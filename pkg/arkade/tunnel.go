package arkade

import (
	"bytes"
	"maps"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

const (
	TunnelScriptPubKey = 1 << iota
	TunnelValue
	TunnelAssets
)

const tunnelFlags = TunnelScriptPubKey | TunnelValue | TunnelAssets

func opcodeTunnel(op *opcode, data []byte, vm *Engine) error {
	exceptionCount, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	remaining := int64(vm.dstack.Depth())
	if exceptionCount < 0 || remaining < 2 || int64(exceptionCount) > (remaining-2)/2 {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid asset exception count")
	}

	exceptions := make(map[asset.AssetId]struct{}, int(exceptionCount))
	for range int(exceptionCount) {
		txid, index, err := popAssetID(vm)
		if err != nil {
			return err
		}
		exceptions[asset.AssetId{Txid: txid, Index: index}] = struct{}{}
	}

	flags, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if flags <= 0 || flags&^scriptNum(tunnelFlags) != 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid tunnel flags")
	}
	if flags&TunnelAssets == 0 && len(exceptions) > 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "asset exceptions require asset tunneling")
	}

	outputIndex, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if outputIndex < 0 || int(outputIndex) >= len(vm.tx.TxOut) {
		return scriptError(txscript.ErrInvalidIndex, "output index out of range")
	}
	if flags&(TunnelScriptPubKey|TunnelValue) != 0 && vm.prevOutFetcher == nil {
		return scriptError(txscript.ErrInvalidIndex, "previous output fetcher not set")
	}

	outpoint := vm.tx.TxIn[vm.txIdx].PreviousOutPoint
	output := vm.tx.TxOut[outputIndex]
	if flags&TunnelScriptPubKey != 0 {
		script := vm.prevOutFetcher.FetchVtxoPrevOutPkScript(outpoint)
		if script == nil {
			if prevout := vm.prevOutFetcher.FetchPrevOutput(outpoint); prevout != nil {
				script = prevout.PkScript
			}
			if script == nil {
				return scriptError(txscript.ErrInvalidIndex, "previous output not found")
			}
		}
		if !bytes.Equal(script, output.PkScript) {
			return scriptError(txscript.ErrInvalidStackOperation, "selected output does not preserve source script")
		}
	}
	if flags&TunnelValue != 0 {
		// Value is compared against the directly spent output. When a
		// checkpoint sits in between, validateCheckpoint pins its output value
		// to the VTXO value, so this equals the logical VTXO amount; the script
		// instead always follows the logical VTXO.
		prevout := vm.prevOutFetcher.FetchPrevOutput(outpoint)
		if prevout == nil {
			return scriptError(txscript.ErrInvalidIndex, "previous output not found")
		}
		if prevout.Value != output.Value {
			return scriptError(txscript.ErrInvalidStackOperation, "selected output does not preserve source value")
		}
	}
	if flags&TunnelAssets != 0 {
		if err := tunnelAssets(
			vm.tx.TxHash(), vm.assetPacket, vm.txIdx, int(outputIndex), exceptions,
		); err != nil {
			return err
		}
	}

	vm.dstack.PushBool(true)
	return nil
}

func tunnelAssets(txHash chainhash.Hash, packet asset.Packet, inputIndex, outputIndex int, exceptions map[asset.AssetId]struct{}) error {
	inputAssets := make(map[asset.AssetId]uint64)
	outputAssets := make(map[asset.AssetId]uint64)

	for groupIndex, group := range packet {
		id, err := resolveAssetID(txHash, groupIndex, group)
		if err != nil {
			return err
		}
		if _, excluded := exceptions[id]; excluded {
			continue
		}
		for _, input := range group.Inputs {
			if input.Type == asset.AssetInputTypeLocal && int(input.Vin) == inputIndex {
				inputAssets[id] += input.Amount
			}
		}
		for _, output := range group.Outputs {
			if output.Type == asset.AssetOutputTypeLocal && int(output.Vout) == outputIndex {
				outputAssets[id] += output.Amount
			}
		}
	}

	if !maps.Equal(inputAssets, outputAssets) {
		return scriptError(txscript.ErrInvalidStackOperation, "selected output does not preserve source assets")
	}
	return nil
}
