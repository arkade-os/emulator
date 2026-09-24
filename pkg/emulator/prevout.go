package emulator

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// prevOutFetcherForIntent computes and validate prevouts for an intent tx
func prevOutFetcherForIntent(ptx *psbt.Packet) (arkade.ArkPrevOutFetcher, error) {
	baseFetcher, err := computePrevoutFetcher(ptx)
	if err != nil {
		return nil, err
	}

	prevoutTxs, err := decodePrevoutTxsFromField(ptx, arkade.PrevArkTxField)
	if err != nil {
		return nil, err
	}

	prevOutArkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(prevoutTxs))
	prevOutIdxs := make(map[wire.OutPoint]uint32, len(prevoutTxs))
	if len(ptx.Inputs) < 2 {
		return nil, fmt.Errorf("intent proof must have at least 2 inputs")
	}
	// Input 0 is always the BIP322 message input; its output carries zero value
	// and mirrors the first real input script.
	expected := &wire.TxOut{PkScript: ptx.Inputs[1].WitnessUtxo.PkScript}
	if !equalTxOut(ptx.Inputs[0].WitnessUtxo, expected) {
		return nil, fmt.Errorf("intent message input witness utxo is invalid")
	}
	outpoint := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
	prevOutArkTxs[outpoint] = &wire.MsgTx{TxOut: []*wire.TxOut{expected}}
	prevOutIdxs[outpoint] = 0
	for inputIndex := 1; inputIndex < len(ptx.Inputs); inputIndex++ {
		prevTx, ok := prevoutTxs[inputIndex]
		if !ok {
			return nil, fmt.Errorf("missing prevout tx for input %d", inputIndex)
		}
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if err := validatePrevoutTx(inputIndex, prevTx, outpoint.Hash); err != nil {
			return nil, err
		}

		if err := reconcilePrevout(
			inputIndex, prevTx, outpoint.Index, ptx.Inputs[inputIndex].WitnessUtxo,
		); err != nil {
			return nil, err
		}

		prevOutArkTxs[outpoint] = prevTx
		prevOutIdxs[outpoint] = outpoint.Index
	}

	return newMapArkPrevOutFetcher(baseFetcher, prevOutArkTxs, prevOutIdxs), nil
}

// prevOutFetcherForArkTx computes and validate prevouts for an Ark tx using its checkpoints
func prevOutFetcherForArkTx(
	ptx *psbt.Packet, checkpoints []*psbt.Packet,
) (*mapArkPrevOutFetcher, error) {
	baseFetcher, err := computePrevoutFetcher(ptx)
	if err != nil {
		return nil, err
	}

	prevoutTxs, err := decodePrevoutTxsFromField(ptx, arkade.PrevArkTxField)
	if err != nil {
		return nil, err
	}

	checkpointsByTxid := make(map[string]*psbt.Packet, len(checkpoints))
	for _, checkpoint := range checkpoints {
		checkpointsByTxid[checkpoint.UnsignedTx.TxID()] = checkpoint
	}

	prevOutArkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(prevoutTxs))
	prevOutIdxs := make(map[wire.OutPoint]uint32, len(prevoutTxs))
	for inputIndex := range ptx.Inputs {
		prevTx, ok := prevoutTxs[inputIndex]
		if !ok {
			return nil, fmt.Errorf("missing prevout tx for input %d", inputIndex)
		}
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		checkpointTxid := outpoint.Hash.String()
		checkpoint, ok := checkpointsByTxid[checkpointTxid]
		if !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}
		if len(checkpoint.Inputs) == 0 || len(checkpoint.UnsignedTx.TxIn) == 0 {
			return nil, fmt.Errorf("checkpoint has no inputs for input %d", inputIndex)
		}
		if len(checkpoint.Inputs) != 1 || len(checkpoint.UnsignedTx.TxIn) != 1 {
			return nil, fmt.Errorf("checkpoint must have exactly one input for ark input %d", inputIndex)
		}

		// the checkpoint txid is pinned by the ark input outpoint, so its
		// outputs are authenticated and the ark input witness utxo must agree
		if err := reconcilePrevout(
			inputIndex, checkpoint.UnsignedTx, outpoint.Index, ptx.Inputs[inputIndex].WitnessUtxo,
		); err != nil {
			return nil, fmt.Errorf("ark input: %w", err)
		}

		checkpointInputPrevout := checkpoint.UnsignedTx.TxIn[0].PreviousOutPoint
		if err := validatePrevoutTx(inputIndex, prevTx, checkpointInputPrevout.Hash); err != nil {
			return nil, err
		}

		// the prevout tx carried by an ark tx input funds the checkpoint input,
		// not the ark input itself, so it must be reconciled against the
		// checkpoint witness utxo
		if err := reconcilePrevout(
			inputIndex, prevTx, checkpointInputPrevout.Index, checkpoint.Inputs[0].WitnessUtxo,
		); err != nil {
			return nil, err
		}

		prevOutArkTxs[outpoint] = prevTx
		prevOutIdxs[outpoint] = checkpointInputPrevout.Index
	}

	return newMapArkPrevOutFetcher(baseFetcher, prevOutArkTxs, prevOutIdxs), nil
}

// prevOutFetcherForOnchainTx computes and validate prevouts for SubmitOnchainTx
func prevOutFetcherForOnchainTx(ptx *psbt.Packet) (arkade.ArkPrevOutFetcher, error) {
	baseFetcher, err := computePrevoutFetcher(ptx)
	if err != nil {
		return nil, err
	}

	prevoutTxs, err := decodePrevoutTxsFromField(ptx, arkade.PrevoutTxField)
	if err != nil {
		return nil, err
	}

	prevOutTxs := make(map[wire.OutPoint]*wire.MsgTx, len(prevoutTxs))
	prevOutIdxs := make(map[wire.OutPoint]uint32, len(prevoutTxs))
	for inputIndex := range ptx.Inputs {
		prevTx, ok := prevoutTxs[inputIndex]
		if !ok {
			return nil, fmt.Errorf("missing prevout tx for input %d", inputIndex)
		}
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint

		if err := validatePrevoutTx(inputIndex, prevTx, outpoint.Hash); err != nil {
			return nil, err
		}

		if err := reconcilePrevout(
			inputIndex, prevTx, outpoint.Index, ptx.Inputs[inputIndex].WitnessUtxo,
		); err != nil {
			return nil, err
		}

		prevOutTxs[outpoint] = prevTx
		prevOutIdxs[outpoint] = outpoint.Index
	}

	return newMapArkPrevOutFetcher(baseFetcher, prevOutTxs, prevOutIdxs), nil
}

// decodePrevoutTxsFromField decodes prevout transactions from the given psbt field
// arkade.PrevArkTxField is used by offchain transactions
// arkade.PrevoutTxField is used by onchain transactions
func decodePrevoutTxsFromField(
	ptx *psbt.Packet, field txutils.ArkPsbtFieldCoder[wire.MsgTx],
) (map[int]*wire.MsgTx, error) {
	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("malformed psbt")
	}

	prevoutTxs := make(map[int]*wire.MsgTx)

	for inputIndex := range ptx.Inputs {
		fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, field)
		if err != nil {
			return nil, fmt.Errorf("failed to decode prevout tx for input %d: %w", inputIndex, err)
		}

		if len(fields) == 0 {
			continue
		}
		if len(fields) > 1 {
			return nil, fmt.Errorf("multiple prevout tx fields found for input %d", inputIndex)
		}

		prevTx := fields[0]
		prevTxCopy := prevTx
		prevoutTxs[inputIndex] = &prevTxCopy
	}

	return prevoutTxs, nil
}

type mapArkPrevOutFetcher struct {
	txscript.PrevOutputFetcher
	arkTxs      map[wire.OutPoint]*wire.MsgTx
	prevOutIdxs map[wire.OutPoint]uint32
}

func newMapArkPrevOutFetcher(
	base txscript.PrevOutputFetcher,
	arkTxs map[wire.OutPoint]*wire.MsgTx,
	prevOutIdxs map[wire.OutPoint]uint32,
) *mapArkPrevOutFetcher {
	return &mapArkPrevOutFetcher{
		PrevOutputFetcher: base,
		arkTxs:            arkTxs,
		prevOutIdxs:       prevOutIdxs,
	}
}

func (f *mapArkPrevOutFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if f.arkTxs == nil {
		return nil
	}
	return f.arkTxs[op]
}

func (f *mapArkPrevOutFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	prevOut := f.fetchVtxoPrevOut(op)
	if prevOut == nil {
		return nil
	}
	return prevOut.PkScript
}

func (f *mapArkPrevOutFetcher) fetchVtxoPrevOut(op wire.OutPoint) *wire.TxOut {
	if f.arkTxs == nil || f.prevOutIdxs == nil {
		return nil
	}

	idx, foundIdx := f.prevOutIdxs[op]
	arkTx, foundTx := f.arkTxs[op]

	if !foundIdx || !foundTx {
		return nil
	}

	if idx >= uint32(len(arkTx.TxOut)) {
		return nil
	}

	return arkTx.TxOut[idx]
}

func validatePrevoutTx(inputIndex int, prevTx *wire.MsgTx, expectedHash chainhash.Hash) error {
	actualHash := prevTx.TxHash()
	if actualHash != expectedHash {
		return fmt.Errorf(
			"prevout tx hash mismatch for input %d: got %s, expected %s",
			inputIndex, actualHash, expectedHash,
		)
	}

	return nil
}

// reconcilePrevout asserts the witness utxo asserted by the requester matches
// exactly the output it claims to spend on the verified prevout tx.
// The prevout tx only proves it hashes to the spent outpoint, it says nothing
// about the witness utxo: without this check a requester can pair a
// self-consistent prevout tx with a witness utxo declaring any amount and
// script, which is what the VM introspects and what the signature commits to.
func reconcilePrevout(
	inputIndex int, prevTx *wire.MsgTx, outputIndex uint32, witnessUtxo *wire.TxOut,
) error {
	if witnessUtxo == nil {
		return fmt.Errorf("witness utxo is nil for input %d", inputIndex)
	}

	if outputIndex >= uint32(len(prevTx.TxOut)) {
		return fmt.Errorf(
			"prevout tx output index out of range for input %d: index=%d outputs=%d",
			inputIndex, outputIndex, len(prevTx.TxOut),
		)
	}

	prevOut := prevTx.TxOut[outputIndex]
	if prevOut.Value != witnessUtxo.Value {
		return fmt.Errorf(
			"prevout tx value mismatch for input %d: got %d, expected %d",
			inputIndex, witnessUtxo.Value, prevOut.Value,
		)
	}

	if !bytes.Equal(prevOut.PkScript, witnessUtxo.PkScript) {
		return fmt.Errorf(
			"prevout tx script mismatch for input %d: got %x, expected %x",
			inputIndex, witnessUtxo.PkScript, prevOut.PkScript,
		)
	}

	return nil
}

func equalTxOut(a, b *wire.TxOut) bool {
	return a != nil && b != nil && a.Value == b.Value && bytes.Equal(a.PkScript, b.PkScript)
}

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
