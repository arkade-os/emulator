package application

import (
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
	for inputIndex, prevTx := range prevoutTxs {
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if err := validatePrevoutTx(inputIndex, prevTx, outpoint.Hash); err != nil {
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
) (arkade.ArkPrevOutFetcher, error) {
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
	for inputIndex, prevTx := range prevoutTxs {
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		checkpointTxid := outpoint.Hash.String()
		checkpoint, ok := checkpointsByTxid[checkpointTxid]
		if !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}
		if len(checkpoint.UnsignedTx.TxIn) == 0 {
			return nil, fmt.Errorf("checkpoint has no inputs for input %d", inputIndex)
		}

		checkpointInputPrevout := checkpoint.UnsignedTx.TxIn[0].PreviousOutPoint
		if err := validatePrevoutTx(inputIndex, prevTx, checkpointInputPrevout.Hash); err != nil {
			return nil, err
		}

		if checkpointInputPrevout.Index >= uint32(len(prevTx.TxOut)) {
			return nil, fmt.Errorf(
				"prevout tx output index out of range for input %d: index=%d outputs=%d",
				inputIndex, checkpointInputPrevout.Index, len(prevTx.TxOut),
			)
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
	for inputIndex, prevTx := range prevoutTxs {
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint

		if err := validatePrevoutTx(inputIndex, prevTx, outpoint.Hash); err != nil {
			return nil, err
		}

		if outpoint.Index >= uint32(len(prevTx.TxOut)) {
			return nil, fmt.Errorf(
				"prevout tx output index out of range for input %d: index=%d outputs=%d",
				inputIndex, outpoint.Index, len(prevTx.TxOut),
			)
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

	return arkTx.TxOut[idx].PkScript
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
