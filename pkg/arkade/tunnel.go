package arkade

import (
	"bytes"
	"fmt"
	"maps"
	"math"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	TunnelScriptPubKey = 1 << iota
	TunnelValue
	TunnelAssets
	TunnelValueSum
	TunnelAssetsSum
)

const (
	tunnelFlags = TunnelScriptPubKey | TunnelValue | TunnelAssets |
		TunnelValueSum | TunnelAssetsSum
	tunnelAssetFlags = TunnelAssets | TunnelAssetsSum
	tunnelValueFlags = TunnelValue | TunnelValueSum
	tunnelSumFlags   = TunnelValueSum | TunnelAssetsSum
)

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
	if flags&TunnelValue != 0 && flags&TunnelValueSum != 0 {
		return scriptError(
			txscript.ErrInvalidStackOperation, "exact and aggregated value tunneling are exclusive",
		)
	}
	if flags&TunnelAssets != 0 && flags&TunnelAssetsSum != 0 {
		return scriptError(
			txscript.ErrInvalidStackOperation, "exact and aggregated asset tunneling are exclusive",
		)
	}
	if flags&tunnelAssetFlags == 0 && len(exceptions) > 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "asset exceptions require asset tunneling")
	}
	if flags&tunnelSumFlags != 0 && vm.tunnelClaims == nil {
		return scriptError(
			txscript.ErrInvalidStackOperation, "aggregated tunneling unavailable in this context",
		)
	}

	outputIndex, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if outputIndex < 0 || int(outputIndex) >= len(vm.tx.TxOut) {
		return scriptError(txscript.ErrInvalidIndex, "output index out of range")
	}
	if flags&(TunnelScriptPubKey|tunnelValueFlags) != 0 && vm.prevOutFetcher == nil {
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
	if flags&tunnelValueFlags != 0 {
		// Value is compared against the directly spent output. When a
		// checkpoint sits in between, validateCheckpoint pins its output value
		// to the VTXO value, so this equals the logical VTXO amount; the script
		// instead always follows the logical VTXO.
		prevout := vm.prevOutFetcher.FetchPrevOutput(outpoint)
		if prevout == nil {
			return scriptError(txscript.ErrInvalidIndex, "previous output not found")
		}
		if flags&TunnelValue != 0 && prevout.Value != output.Value {
			return scriptError(txscript.ErrInvalidStackOperation, "selected output does not preserve source value")
		}
		if flags&TunnelValueSum != 0 {
			// a negative source value would lower the total the claims demand
			if prevout.Value < 0 {
				return scriptError(txscript.ErrInvalidStackOperation, "negative source value")
			}
			vm.tunnelClaims.recordValue(vm.txIdx, int(outputIndex), prevout.Value)
		}
	}
	if flags&TunnelAssets != 0 {
		if err := tunnelAssets(
			vm.tx.TxHash(), vm.assetPacket, vm.txIdx, int(outputIndex), exceptions,
		); err != nil {
			return err
		}
	}
	if flags&TunnelAssetsSum != 0 {
		txHash := vm.tx.TxHash()
		claimed, err := inputLocalAssets(txHash, vm.assetPacket, vm.txIdx, exceptions)
		if err != nil {
			return err
		}
		available, err := outputLocalAssets(txHash, vm.assetPacket, int(outputIndex), nil)
		if err != nil {
			return err
		}
		vm.tunnelClaims.recordAssets(vm.txIdx, int(outputIndex), claimed, available)
	}

	vm.dstack.PushBool(true)
	return nil
}

func tunnelAssets(
	txHash chainhash.Hash, packet asset.Packet, inputIndex, outputIndex int,
	exceptions map[asset.AssetId]struct{},
) error {
	inputAssets, err := inputLocalAssets(txHash, packet, inputIndex, exceptions)
	if err != nil {
		return err
	}
	outputAssets, err := outputLocalAssets(txHash, packet, outputIndex, exceptions)
	if err != nil {
		return err
	}

	if !maps.EqualFunc(inputAssets, outputAssets, func(a, b BigNum) bool { return a.Cmp(b) == 0 }) {
		return scriptError(txscript.ErrInvalidStackOperation, "selected output does not preserve source assets")
	}
	return nil
}

func inputLocalAssets(
	txHash chainhash.Hash, packet asset.Packet, inputIndex int,
	exceptions map[asset.AssetId]struct{},
) (map[asset.AssetId]BigNum, error) {
	assets := make(map[asset.AssetId]BigNum)
	for groupIndex, group := range packet {
		id, err := resolveAssetID(txHash, groupIndex, group)
		if err != nil {
			return nil, err
		}
		if _, excluded := exceptions[id]; excluded {
			continue
		}
		for _, input := range group.Inputs {
			if input.Type != asset.AssetInputTypeLocal || int(input.Vin) != inputIndex {
				continue
			}
			assets[id] = assets[id].Add(BigNumFromUint64(input.Amount))
		}
	}
	return assets, nil
}

func outputLocalAssets(
	txHash chainhash.Hash, packet asset.Packet, outputIndex int,
	exceptions map[asset.AssetId]struct{},
) (map[asset.AssetId]BigNum, error) {
	assets := make(map[asset.AssetId]BigNum)
	for groupIndex, group := range packet {
		id, err := resolveAssetID(txHash, groupIndex, group)
		if err != nil {
			return nil, err
		}
		if _, excluded := exceptions[id]; excluded {
			continue
		}
		for _, output := range group.Outputs {
			if output.Type != asset.AssetOutputTypeLocal || int(output.Vout) != outputIndex {
				continue
			}
			assets[id] = assets[id].Add(BigNumFromUint64(output.Amount))
		}
	}
	return assets, nil
}

// TunnelClaims collects sum claims for one transaction. Call Verify after script
// execution and MarkPartial if a packet entry was skipped. Concurrent execution
// needs external synchronization.
type TunnelClaims struct {
	value        map[tunnelClaimKey]int64
	assets       map[tunnelClaimKey]map[asset.AssetId]BigNum
	outputAssets map[int]map[asset.AssetId]BigNum
	partial      bool
}

type tunnelClaimKey struct {
	input  int
	output int
}

// NewTunnelClaims returns an accumulator for one transaction's tunnel claims.
func NewTunnelClaims() *TunnelClaims {
	return &TunnelClaims{
		value:        make(map[tunnelClaimKey]int64),
		assets:       make(map[tunnelClaimKey]map[asset.AssetId]BigNum),
		outputAssets: make(map[int]map[asset.AssetId]BigNum),
	}
}

// MarkPartial records that an input which may carry a tunnel claim was not
// executed, making Verify fail closed.
func (c *TunnelClaims) MarkPartial() {
	if c == nil {
		return
	}
	c.partial = true
}

func (c *TunnelClaims) recordValue(input, output int, claimed int64) {
	key := tunnelClaimKey{input: input, output: output}
	if existing, ok := c.value[key]; !ok || claimed > existing {
		c.value[key] = claimed
	}
}

func (c *TunnelClaims) recordAssets(input, output int, claimed, available map[asset.AssetId]BigNum) {
	key := tunnelClaimKey{input: input, output: output}
	existing := c.assets[key]
	if existing == nil {
		existing = make(map[asset.AssetId]BigNum, len(claimed))
		c.assets[key] = existing
	}
	for id, amount := range claimed {
		if amount.Cmp(existing[id]) > 0 {
			existing[id] = amount
		}
	}
	c.outputAssets[output] = available
}

// Verify checks that each selected output covers its accumulated claims.
func (c *TunnelClaims) Verify(tx *wire.MsgTx) error {
	if c == nil {
		return nil
	}
	if len(c.value) == 0 && len(c.assets) == 0 {
		return nil
	}
	if c.partial {
		return fmt.Errorf("incomplete aggregated tunnel claims")
	}

	values := make(map[int]int64, len(c.value))
	for key, claimed := range c.value {
		total, ok := addInt64(values[key.output], claimed)
		if !ok {
			return fmt.Errorf("value claimed on output %d overflows", key.output)
		}
		values[key.output] = total
	}
	for output, total := range values {
		if output >= len(tx.TxOut) {
			return fmt.Errorf("claimed output %d out of range", output)
		}
		if tx.TxOut[output].Value < total {
			return fmt.Errorf(
				"output %d holds %d sats but %d are claimed",
				output, tx.TxOut[output].Value, total,
			)
		}
	}

	totals := make(map[int]map[asset.AssetId]BigNum, len(c.assets))
	for key, claimed := range c.assets {
		perOutput := totals[key.output]
		if perOutput == nil {
			perOutput = make(map[asset.AssetId]BigNum, len(claimed))
			totals[key.output] = perOutput
		}
		for id, amount := range claimed {
			perOutput[id] = perOutput[id].Add(amount)
		}
	}
	for output, perOutput := range totals {
		available := c.outputAssets[output]
		for id, total := range perOutput {
			if available[id].Cmp(total) < 0 {
				return fmt.Errorf(
					"output %d holds %s of asset %s:%d but %s are claimed",
					output, available[id].BigInt(), id.Txid, id.Index, total.BigInt(),
				)
			}
		}
	}

	return nil
}

func addInt64(a, b int64) (int64, bool) {
	if a > math.MaxInt64-b {
		return 0, false
	}
	return a + b, true
}
