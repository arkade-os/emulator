package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// SubmitTx aims to execute arkade scripts on offchain ark transactions
// execution of the script runs only on ark tx, if valid, the associated checkpoint tx
func (s *service) SubmitTx(ctx context.Context, tx OffchainTx) (*OffchainTx, error) {
	arkPtx := tx.ArkTx

	// index checkpoints by txid for easy lookup while signing ark transaction
	indexedCheckpoints := make(map[string]*psbt.Packet) // txid => checkpoint psbt
	for _, checkpoint := range tx.Checkpoints {
		indexedCheckpoints[checkpoint.UnsignedTx.TxID()] = checkpoint
	}
	// preserve original checkpoint order for deterministic response
	orderedCheckpointTxids := make([]string, 0, len(tx.Checkpoints))
	for _, checkpoint := range tx.Checkpoints {
		orderedCheckpointTxids = append(orderedCheckpointTxids, checkpoint.UnsignedTx.TxID())
	}

	prevOutFetcher, err := prevOutFetcherForArkTx(arkPtx, tx.Checkpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	// Parse IntrospectorPacket from the transaction's OP_RETURN output
	packet, err := arkade.FindIntrospectorPacket(arkPtx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse introspector packet: %w", err)
	}

	if len(packet) == 0 {
		return nil, fmt.Errorf("no introspector packet found in transaction")
	}

	finalizerAcc := newFinalizerAccumulator(s.arkdPubKey)

	var nSigned = 0
	for _, entry := range packet {
		inputIndex := int(entry.Vin)
		matchedSigner, script, err := resolveArkadeScriptSigner(s.signer, s.deprecatedSigners, arkPtx, entry)
		if err != nil {
			// there may be input/entry pairs attributed to a different signer
			if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) && len(arkPtx.Inputs) > 1 {
				continue
			}
			return nil, fmt.Errorf("failed to read arkade script: %w vin=%d", err, inputIndex)
		}

		log.Debugf("executing arkade script: %x", script.Script())
		if err := script.Execute(
			arkPtx.UnsignedTx,
			prevOutFetcher,
			inputIndex,
		); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w vin=%d", err, inputIndex)
		}
		log.Debugf("execution of %x succeeded", script.Script())

		if err := matchedSigner.signInput(arkPtx, inputIndex, script.Hash(), prevOutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		// search for checkpoint
		inputTxid := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.Hash.String()
		checkpointPtx, ok := indexedCheckpoints[inputTxid]
		if !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}

		checkpointPrevoutFetcher, err := computePrevoutFetcher(checkpointPtx)
		if err != nil {
			return nil, fmt.Errorf("failed to create prevout fetcher for checkpoint: %w", err)
		}

		if err := matchedSigner.signInput(checkpointPtx, 0, script.Hash(), checkpointPrevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign checkpoint input %d: %w", inputIndex, err)
		}

		if err = finalizerAcc.checkScript(entry.Vin, script); err != nil {
			return nil, fmt.Errorf("failed to check script for finalizer: %w", err)
		}

		nSigned++
	}

	if nSigned == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}

	signedCheckpointTxs := make([]*psbt.Packet, 0, len(orderedCheckpointTxids))
	for _, txid := range orderedCheckpointTxids {
		signedCheckpointTxs = append(signedCheckpointTxs, indexedCheckpoints[txid])
	}

	isFinalizer, err := finalizerAcc.isFinalizer()
	if err != nil {
		return nil, fmt.Errorf("failed to determine finalizer role: %w", err)
	}

	log.WithField("is_finalizer", isFinalizer).Debug("finalizer role analysis completed")

	if !isFinalizer {
		return &OffchainTx{
			ArkTx:       arkPtx,
			Checkpoints: signedCheckpointTxs,
		}, nil
	}

	// we must verify that we have all the required checkpoint signatures before submitting to arkd
	// otherwise, finalizing with arkd will fail later
	if err = verifyNonArkdCheckpointSignatures(signedCheckpointTxs, s.arkdPubKey); err != nil {
		return nil, fmt.Errorf("failed to verify non-arkd signatures on checkpoints: %w", err)
	}

	encodedCheckpoints := make([]string, 0, len(tx.Checkpoints))
	for i, checkpoint := range tx.Checkpoints {
		encoded, err := checkpoint.B64Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode checkpoint %d: %w", i, err)
		}
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode ark tx for finalization: %w", err)
	}

	txid, finalArkTx, arkdCheckpointTxs, err := s.arkdClient.SubmitTx(ctx, arkTx, encodedCheckpoints)
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

	finalEncodedCheckpoints := make([]string, 0, len(tx.Checkpoints))
	logCheckpoints := make(map[string]any)
	for i, checkpoint := range signedCheckpointTxs {
		checkpoint.Inputs[0].TaprootScriptSpendSig = append(
			checkpoint.Inputs[0].TaprootScriptSpendSig,
			arkdCheckpointPSBTs[checkpoint.UnsignedTx.TxID()].Inputs[0].TaprootScriptSpendSig...,
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

	return &OffchainTx{
		ArkTx:       finalArkPtx,
		Checkpoints: signedCheckpointTxs,
	}, nil
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
		// script.VerifyTapscriptSigs silently skips inputs that do not carry a
		// taproot leaf script, so we must assert its presence here.
		if len(ptx.Inputs[0].TaprootLeafScript) == 0 {
			return fmt.Errorf("checkpoint %d input 0: missing taproot leaf script", checkpointIndex)
		}
		prevoutFetcher, err := computePrevoutFetcher(ptx)
		if err != nil {
			return fmt.Errorf("checkpoint %d: %w", checkpointIndex, err)
		}
		if _, err := script.VerifyTapscriptSigs(
			ptx, prevoutFetcher, script.WithSkipPublicKeys(arkdPubKey),
		); err != nil {
			return fmt.Errorf("checkpoint %d: %w", checkpointIndex, err)
		}
	}
	return nil
}

var finalizeRetryConfig = struct {
	MinAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       float64
}{
	MinAttempts:  10,
	InitialDelay: 1 * time.Second,
	MaxDelay:     10 * time.Second,
	Multiplier:   2.0,
	Jitter:       0.2, // + or - 20% randomness
}

func (s *service) retryFinalize(ctx context.Context, txid string, checkpoints []string) error {
	// copy global to local for this retry run
	retryConfig := finalizeRetryConfig
	backoffDelay := retryConfig.InitialDelay
	attempt := 0

	for {
		attempt++

		if err := s.arkdClient.FinalizeTx(ctx, txid, checkpoints); err == nil {
			return nil
		} else {
			log.WithField("txid", txid).WithField("attempt", attempt).Errorf("finalizing tx failed: %s", err)
		}

		delay := applyJitter(backoffDelay, retryConfig.Jitter)
		backoffDelay = min(retryConfig.MaxDelay, backoffDelay*time.Duration(retryConfig.Multiplier))

		// try a minimum number of times before respecting ctx.Done
		if attempt < retryConfig.MinAttempts {
			time.Sleep(delay)
			continue
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("finalize retry cancelled after attempt %d: %w", attempt, ctx.Err())
		case <-time.After(delay):
		}
	}
}

// applyJitter adds ±jitter randomness to a duration.
// with jitter = 0.2, d get + or - 20%
func applyJitter(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return d
	}
	if jitter >= 1.0 {
		jitter = 0.999
	}

	randomFactor := 2.0*rand.Float64() - 1.0 // [-1, +1] factor
	jitterFactor := 1.0 + jitter*randomFactor
	return time.Duration(float64(d) * jitterFactor)
}
