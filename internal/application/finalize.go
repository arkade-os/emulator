package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

// SubmitTx signs tx and, if the emulator is the last non-arkd signer, submits
// and finalizes it on arkd.
func (s *service) SubmitTx(ctx context.Context, tx emulator.OffchainTx) (*emulator.OffchainTx, error) {
	var sigsBefore []int
	if tx.ArkTx != nil {
		sigsBefore = make([]int, len(tx.ArkTx.Inputs))
		for i, in := range tx.ArkTx.Inputs {
			sigsBefore[i] = len(in.TaprootScriptSpendSig)
		}
	}

	signed, err := s.Service.SubmitTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	isFinalizer, err := isFinalizerRole(signed.ArkTx, sigsBefore, s.signerPubKeys, s.arkdPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to determine finalizer role: %w", err)
	}

	log.WithField("is_finalizer", isFinalizer).Debug("finalizer role analysis completed")

	if !isFinalizer {
		return signed, nil
	}

	// we must verify that we have all the required checkpoint signatures before submitting to arkd
	// otherwise, finalizing with arkd will fail later
	if err = verifyNonArkdCheckpointSignatures(signed.Checkpoints, s.arkdPubKey); err != nil {
		return nil, fmt.Errorf("failed to verify non-arkd signatures on checkpoints: %w", err)
	}

	encodedCheckpoints := make([]string, 0, len(signed.Checkpoints))
	for i, checkpoint := range signed.Checkpoints {
		encoded, err := checkpoint.B64Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode checkpoint %d: %w", i, err)
		}
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

	arkTx, err := signed.ArkTx.B64Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode ark tx for finalization: %w", err)
	}

	txid, finalArkTx, arkdCheckpointTxs, err := s.arkd.SubmitTx(ctx, arkTx, encodedCheckpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to submit tx on arkd: %w", err)
	}

	// combine arkd checkpoint signatures with the rest of the checkpoint signatures
	arkdCheckpointPSBTs := make(map[string]*psbt.Packet, len(arkdCheckpointTxs))
	for i, checkpoint := range arkdCheckpointTxs {
		p, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		if err != nil {
			return nil, fmt.Errorf("failed to decode arkd checkpoint %d: %w", i, err)
		}
		arkdCheckpointPSBTs[p.UnsignedTx.TxID()] = p
	}

	finalEncodedCheckpoints := make([]string, 0, len(signed.Checkpoints))
	logCheckpoints := make(map[string]any)
	for i, checkpoint := range signed.Checkpoints {
		// arkd's response may not cover our checkpoints
		txid := checkpoint.UnsignedTx.TxID()
		arkdCheckpoint, ok := arkdCheckpointPSBTs[txid]
		if !ok {
			return nil, fmt.Errorf("arkd returned no checkpoint for txid %s", txid)
		}
		if len(arkdCheckpoint.Inputs) == 0 {
			return nil, fmt.Errorf("arkd returned checkpoint %s without inputs", txid)
		}
		if len(checkpoint.Inputs) == 0 {
			return nil, fmt.Errorf("checkpoint %d has no inputs", i)
		}

		checkpoint.Inputs[0].TaprootScriptSpendSig = append(
			checkpoint.Inputs[0].TaprootScriptSpendSig,
			arkdCheckpoint.Inputs[0].TaprootScriptSpendSig...,
		)
		encoded, err := checkpoint.B64Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode final checkpoint %d: %w", i, err)
		}
		logCheckpoints[strconv.Itoa(i)] = encoded
		finalEncodedCheckpoints = append(finalEncodedCheckpoints, encoded)
	}

	log.WithField("txid", txid).WithFields(log.Fields(logCheckpoints)).Info("finalizing tx")

	// TODO: if retry fails, persist retry task in background queue
	if err := s.retryFinalize(ctx, txid, finalEncodedCheckpoints); err != nil {
		return nil, err
	}

	finalArkPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalArkTx), true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode final ark tx: %w", err)
	}

	return &emulator.OffchainTx{
		ArkTx:       finalArkPtx,
		Checkpoints: signed.Checkpoints,
	}, nil
}

func isFinalizerRole(arkPtx *psbt.Packet, sigsBefore []int, signerPubKeys []*btcec.PublicKey, arkdPubKey *btcec.PublicKey) (bool, error) {
	packet, err := arkade.FindEmulatorPacket(arkPtx.UnsignedTx)
	if err != nil {
		return false, fmt.Errorf("failed to parse emulator packet: %w", err)
	}

	acc := newFinalizerAccumulator(arkdPubKey)
	for _, entry := range packet {
		for _, pubKey := range signerPubKeys {
			arkadeScript, err := arkade.ReadArkadeScript(arkPtx, pubKey, entry)
			if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) {
				continue
			}
			if err != nil {
				return false, fmt.Errorf("failed to read arkade script: %w vin=%d", err, entry.Vin)
			}
			input := arkPtx.Inputs[entry.Vin]
			added := input.TaprootScriptSpendSig
			if int(entry.Vin) < len(sigsBefore) {
				added = added[min(sigsBefore[entry.Vin], len(added)):]
			}
			if signedBy(added, arkadeScript.PubKey()) {
				if err := acc.checkScript(entry.Vin, arkadeScript); err != nil {
					return false, err
				}
			}
			break
		}
	}
	return acc.isFinalizer()
}

func signedBy(sigs []*psbt.TaprootScriptSpendSig, pubKey *btcec.PublicKey) bool {
	xOnly := schnorr.SerializePubKey(pubKey)
	for _, sig := range sigs {
		if bytes.Equal(sig.XOnlyPubKey, xOnly) {
			return true
		}
	}
	return false
}

func (s *service) retryFinalize(ctx context.Context, txid string, checkpoints []string) error {
	return retryWithBackoff(ctx, finalizeRetryConfig,
		func() error { return s.arkd.FinalizeTx(ctx, txid, checkpoints) },
		func(attempt int, err error) {
			log.WithField("txid", txid).WithField("attempt", attempt).Errorf("finalizing tx failed: %s", err)
		},
	)
}

type finalizerAccumulator struct {
	arkdPubKeyXonly []byte
	isLastByVin     map[uint16]bool
	vins            []uint16
}

func newFinalizerAccumulator(arkdPubKey *btcec.PublicKey) *finalizerAccumulator {
	arkdPubKeyXonly := schnorr.SerializePubKey(arkdPubKey)
	return &finalizerAccumulator{
		arkdPubKeyXonly: arkdPubKeyXonly,
		isLastByVin:     make(map[uint16]bool),
	}
}

func (a *finalizerAccumulator) checkScript(vin uint16, script *arkade.ArkadeScript) error {
	a.vins = append(a.vins, vin)

	nClosurePubKeys := len(script.ClosurePubKeys())
	tweakedSignerPublicKeyXOnly := schnorr.SerializePubKey(script.PubKey())
	if nClosurePubKeys < 2 {
		// the script should always have a forfeit closure with at least arkd + tweaked key
		return fmt.Errorf("malformed script %x", script.Script())
	}

	lastSigner := script.ClosurePubKeys()[nClosurePubKeys-1]
	lastSignerXOnly := schnorr.SerializePubKey(lastSigner)

	// if arkd is the last signer, check the second-to-last
	if bytes.Equal(lastSignerXOnly, a.arkdPubKeyXonly) {
		lastNonArkdSigner := script.ClosurePubKeys()[nClosurePubKeys-2]
		lastNonArkdSignerXonly := schnorr.SerializePubKey(lastNonArkdSigner)
		a.isLastByVin[vin] = bytes.Equal(lastNonArkdSignerXonly, tweakedSignerPublicKeyXOnly)
		return nil
	}

	a.isLastByVin[vin] = bytes.Equal(lastSignerXOnly, tweakedSignerPublicKeyXOnly)
	return nil
}

func (a *finalizerAccumulator) isFinalizer() (bool, error) {
	if len(a.vins) == 0 {
		return false, nil
	}
	referenceVin := a.vins[0]
	referenceIsLast, ok := a.isLastByVin[referenceVin]
	if !ok {
		return false, fmt.Errorf("missing finalizer state for input %d", referenceVin)
	}
	for _, vin := range a.vins[1:] {
		isLast, ok := a.isLastByVin[vin]
		if !ok {
			return false, fmt.Errorf("missing finalizer state for input %d", vin)
		}
		if isLast != referenceIsLast {
			return false, fmt.Errorf("input %d has a different finalizer", vin)
		}
	}
	return referenceIsLast, nil
}

func verifyNonArkdCheckpointSignatures(checkpoints []*psbt.Packet, arkdPubKey *btcec.PublicKey) error {
	for checkpointIndex, ptx := range checkpoints {
		if len(ptx.Inputs) == 0 || len(ptx.UnsignedTx.TxIn) == 0 {
			return fmt.Errorf("checkpoint %d: missing input 0", checkpointIndex)
		}
		// VerifyTapscriptSigs silently skips inputs without exactly one leaf script
		if len(ptx.Inputs[0].TaprootLeafScript) != 1 {
			return fmt.Errorf(
				"checkpoint %d input 0: missing taproot leaf script (want exactly 1, got %d)",
				checkpointIndex, len(ptx.Inputs[0].TaprootLeafScript),
			)
		}
		prevoutFetcher, err := computePrevoutFetcher(ptx)
		if err != nil {
			return fmt.Errorf("checkpoint %d: %w", checkpointIndex, err)
		}
		// it also skips non-taproot and note inputs without erroring
		verified, err := script.VerifyTapscriptSigs(
			ptx, prevoutFetcher, script.WithSkipPublicKeys(arkdPubKey),
		)
		if err != nil {
			return fmt.Errorf("checkpoint %d: %w", checkpointIndex, err)
		}
		if !slices.Contains(verified, 0) {
			return fmt.Errorf(
				"checkpoint %d input 0: signatures were not verified", checkpointIndex,
			)
		}
	}
	return nil
}

// computePrevoutFetcher is a copy of pkg/emulator's private helper.
func computePrevoutFetcher(ptx *psbt.Packet) (txscript.PrevOutputFetcher, error) {
	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for index, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("witness utxo is nil")
		}

		if len(ptx.UnsignedTx.TxIn) <= index {
			return nil, fmt.Errorf("input index out of range")
		}

		outpoint := ptx.UnsignedTx.TxIn[index].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	return txscript.NewMultiPrevOutFetcher(prevouts), nil
}
