package emulator

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

type OffchainTx struct {
	ArkTx       *psbt.Packet
	Checkpoints []*psbt.Packet
}

// ExpiryOutpoints returns the spent vtxos whose expiry EmulateOffchainTx needs in OffchainData.VtxoExpiries:
// those spent by inputs whose arkade script uses OP_PUSHEXPIRY.
func (t OffchainTx) ExpiryOutpoints() ([]wire.OutPoint, error) {
	if t.ArkTx == nil {
		return nil, fmt.Errorf("missing ark transaction")
	}
	vins, err := pushExpiryVins(t.ArkTx.UnsignedTx)
	if err != nil || len(vins) == 0 {
		return nil, err
	}
	prevOutFetcher, err := prevOutFetcherForArkTx(t.ArkTx, t.Checkpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}
	outpoints := make([]wire.OutPoint, 0, len(vins))
	for _, vin := range vins {
		arkOutpoint := t.ArkTx.UnsignedTx.TxIn[vin].PreviousOutPoint
		prevArkTx := prevOutFetcher.FetchPrevOutArkTx(arkOutpoint)
		if prevArkTx == nil {
			return nil, fmt.Errorf("prevout ark tx not found for input %d", vin)
		}
		outpoints = append(outpoints, wire.OutPoint{
			Hash: prevArkTx.TxHash(), Index: prevOutFetcher.prevOutIdxs[arkOutpoint],
		})
	}
	return outpoints, nil
}

// Intent is an unsigned intent proof and the message it commits to, as the
// scripts read it with OP_INSPECTINTENTMESSAGE. The caller verifies the proof
// commits to Message; the lib never parses it.
type Intent struct {
	Proof   intent.Proof
	Message string
}

// ExpiryOutpoints returns the spent vtxos whose expiry EmulateIntent needs in OffchainData.VtxoExpiries:
// those spent by inputs whose arkade script uses OP_PUSHEXPIRY.
func (i Intent) ExpiryOutpoints() ([]wire.OutPoint, error) {
	ptx := &i.Proof.Packet
	vins, err := pushExpiryVins(ptx.UnsignedTx)
	if err != nil {
		return nil, err
	}
	outpoints := make([]wire.OutPoint, 0, len(vins))
	for _, vin := range vins {
		// input 0 is the message input, it reuses input 1's script
		if vin == 0 {
			continue
		}
		outpoints = append(outpoints, ptx.UnsignedTx.TxIn[vin].PreviousOutPoint)
	}
	return outpoints, nil
}

// OffchainData is the arkd indexer data arkade scripts may need that the
// executor can't derive from the tx itself.
type OffchainData struct {
	// VtxoExpiries maps the vtxos listed by ExpiryOutpoints to their unix
	// expiry, pushed by OP_PUSHEXPIRY.
	VtxoExpiries map[wire.OutPoint]int64
}

type OnchainTx struct {
	Tx *psbt.Packet
}

// BatchFinalization is a batch to sign: the signed intent proofs it settles, its forfeits and commitment tx.
// Intents[i].Message is unused.
type BatchFinalization struct {
	Intents      []Intent
	Forfeits     []*psbt.Packet
	CommitmentTx *psbt.Packet
}

// SignRequest is an input the executed arkade script approved for signing.
// The caller must find its key whose public key, tweaked by ScriptHash via arkade.ComputeArkadeScriptPublicKey, is among ClosurePubKeys, and skip the request otherwise: entries may belong to another emulator.
// The caller must refuse unless the input's SighashType is SigHashDefault or SigHashAll.
// The caller signs with that key tweaked by ScriptHash.
type SignRequest struct {
	Packet         *psbt.Packet
	InputIndex     int
	ScriptHash     []byte
	ClosurePubKeys []*btcec.PublicKey
}

func newSignRequest(ptx *psbt.Packet, inputIndex int, script *arkade.ArkadeScript) (SignRequest, error) {
	if inputIndex < 0 || len(ptx.Inputs) <= inputIndex || len(ptx.UnsignedTx.TxIn) <= inputIndex {
		return SignRequest{}, fmt.Errorf("input index out of range, cannot sign")
	}

	input := ptx.Inputs[inputIndex]
	if input.WitnessUtxo == nil || !txscript.IsPayToTaproot(input.WitnessUtxo.PkScript) {
		return SignRequest{}, fmt.Errorf("not a taproot input, cannot sign")
	}

	if len(input.TaprootLeafScript) != 1 || input.TaprootLeafScript[0] == nil {
		return SignRequest{}, fmt.Errorf(
			"expected exactly 1 taproot leaf script, got %d, cannot sign",
			len(input.TaprootLeafScript),
		)
	}

	if err := arkade.VerifyTaprootLeafCommitment(
		input.WitnessUtxo.PkScript, input.TaprootLeafScript[0],
	); err != nil {
		return SignRequest{}, fmt.Errorf("cannot sign input: %w", err)
	}

	return SignRequest{
		Packet: ptx, InputIndex: inputIndex,
		ScriptHash: script.Hash(), ClosurePubKeys: script.ClosurePubKeys(),
	}, nil
}
