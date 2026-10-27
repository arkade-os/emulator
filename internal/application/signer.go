// ponytail: superseded by arkd-signer, delete with internal/
package application

import (
	"bytes"
	"context"
	"fmt"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

type signer struct {
	secretKey *btcec.PrivateKey
}

func (s signer) signInput(ptx *psbt.Packet, inputIndex int, tweak []byte, prevoutFetcher txscript.PrevOutputFetcher) error {
	if len(ptx.Inputs) <= inputIndex || len(ptx.UnsignedTx.TxIn) <= inputIndex {
		return fmt.Errorf("input index out of range, cannot sign")
	}

	signingKey := arkade.ComputeArkadeScriptPrivateKey(s.secretKey, tweak)

	input := ptx.Inputs[inputIndex]
	// only sighash types committing to every input and output are safe: any other
	// type lets the requester replace outputs or prevouts the covenant approved
	if input.SighashType != txscript.SigHashDefault && input.SighashType != txscript.SigHashAll {
		return fmt.Errorf("unsupported sighash type 0x%02x, cannot sign", uint32(input.SighashType))
	}

	if input.WitnessUtxo == nil || !txscript.IsPayToTaproot(input.WitnessUtxo.PkScript) {
		return fmt.Errorf("not a taproot input, cannot sign")
	}

	if len(input.TaprootLeafScript) != 1 || input.TaprootLeafScript[0] == nil {
		return fmt.Errorf(
			"expected exactly 1 taproot leaf script, got %d, cannot sign",
			len(input.TaprootLeafScript),
		)
	}

	if err := arkade.VerifyTaprootLeafCommitment(
		input.WitnessUtxo.PkScript, input.TaprootLeafScript[0],
	); err != nil {
		return fmt.Errorf("cannot sign input: %w", err)
	}

	tapLeaf := txscript.NewBaseTapLeaf(input.TaprootLeafScript[0].Script)
	txSigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	signature, err := txscript.RawTxInTapscriptSignature(
		ptx.UnsignedTx, txSigHashes, inputIndex, input.WitnessUtxo.Value,
		input.WitnessUtxo.PkScript, tapLeaf, input.SighashType, signingKey,
	)
	if err != nil {
		return err
	}

	leafHash := tapLeaf.TapHash()

	ptx.Inputs[inputIndex].TaprootScriptSpendSig = append(ptx.Inputs[inputIndex].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		Signature:   signature[:64], // remove the last byte (sig hash type) because signature is already encoded
		XOnlyPubKey: schnorr.SerializePubKey(signingKey.PubKey()),
		LeafHash:    leafHash[:],
		SigHash:     input.SighashType,
	})

	return nil
}

// activeDeprecatedSigners drops the deprecated keys once deprecatedKeysValidUntil has passed.
func (s *service) activeDeprecatedSigners() []signer {
	if s.deprecatedKeysValidUntil != nil && time.Now().After(*s.deprecatedKeysValidUntil) {
		return nil
	}
	return s.deprecatedSigners
}

// signerFor returns the active key named, tweaked by the request script hash, in the request closure.
func (s *service) signerFor(req emulator.SignRequest) (signer, bool) {
	for _, candidate := range append([]signer{s.signer}, s.activeDeprecatedSigners()...) {
		tweaked := schnorr.SerializePubKey(
			arkade.ComputeArkadeScriptPublicKey(candidate.secretKey.PubKey(), req.ScriptHash),
		)
		for _, pubkey := range req.ClosurePubKeys {
			if bytes.Equal(schnorr.SerializePubKey(pubkey), tweaked) {
				return candidate, true
			}
		}
	}
	return signer{}, false
}

// signRequests signs the requests naming one of our keys, skips the ones meant for another emulator, and returns the signed ones.
func (s *service) signRequests(requests []emulator.SignRequest) ([]emulator.SignRequest, error) {
	signed := make([]emulator.SignRequest, 0, len(requests))
	for _, req := range requests {
		matched, ok := s.signerFor(req)
		if !ok {
			continue
		}
		prevoutFetcher, err := computePrevoutFetcher(req.Packet)
		if err != nil {
			return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
		}
		if err := matched.signInput(req.Packet, req.InputIndex, req.ScriptHash, prevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", req.InputIndex, err)
		}
		signed = append(signed, req)
	}
	if len(signed) == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}
	return signed, nil
}

// signFinalization signs forfeit and commitment inputs approved by our intent proof signature; arkd vouches for the commitment tx.
func (s *service) signFinalization(
	ctx context.Context, finalization emulator.BatchFinalization, connectorTree *tree.TxTree,
) (*SignedBatchFinalization, error) {
	requests, err := s.lib.EmulateBatchFinalization(ctx, finalization)
	if err != nil {
		return nil, err
	}
	for _, req := range requests {
		if req.Packet == finalization.CommitmentTx {
			continue
		}
		forfeit, vtxoIndex := req.Packet, req.InputIndex
		var connectorOutput *wire.TxOut
		if len(forfeit.UnsignedTx.TxIn) == 2 {
			connector := forfeit.UnsignedTx.TxIn[vtxoIndex^1].PreviousOutPoint
			connectorOutput = leafOutput(connectorTree, connector)
		}
		// without this the requester can reuse a vtxo input we signed in the past and redirect its value anywhere
		if err := validateForfeitOutputs(
			forfeit, vtxoIndex, forfeit.Inputs[vtxoIndex].WitnessUtxo, connectorOutput, s.arkdForfeitPkScript,
		); err != nil {
			return nil, fmt.Errorf("malformed forfeit %s: %w", forfeit.UnsignedTx.TxID(), err)
		}
	}

	signedRequests, err := s.signRequests(requests)
	if err != nil {
		return nil, err
	}
	signed := &SignedBatchFinalization{Forfeits: make([]*psbt.Packet, 0, len(signedRequests))}
	for _, req := range signedRequests {
		if req.Packet == finalization.CommitmentTx {
			signed.CommitmentTx = finalization.CommitmentTx
			continue
		}
		signed.Forfeits = append(signed.Forfeits, req.Packet)
	}
	return signed, nil
}
