package arkade

import (
	"crypto/sha256"
	"math/big"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

// opcodeInspectNumAssetGroups pushes the total number of asset groups in the packet onto the stack.
func opcodeInspectNumAssetGroups(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}
	vm.dstack.PushInt(scriptNum(len(vm.assetPacket)))
	return nil
}

// opcodeInspectAssetGroupAssetId pops a packet group position k and pushes the
// canonical AssetID (asset_txid, asset_gidx) of that group. A fresh issuance
// derives its identity from the current transaction hash and k.
func opcodeInspectAssetGroupAssetId(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	id := resolveAssetID(vm.tx.TxHash(), int(k), vm.assetPacket[int(k)])
	vm.dstack.PushByteArray(id.Txid[:])
	vm.dstack.PushInt(scriptNum(id.Index))
	return nil
}

// opcodeInspectAssetGroupCtrl pops a group index k and pushes a tagged control
// asset reference.
// Found:   pushes txid, index, 1.
// Missing: pushes empty txid, 0, 0.
func opcodeInspectAssetGroupCtrl(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	if group.ControlAsset == nil {
		vm.dstack.PushByteArray(nil)
		vm.dstack.PushInt(0)
		vm.dstack.PushInt(0)
		return nil
	}

	if group.ControlAsset.Type == asset.AssetRefByID {
		vm.dstack.PushByteArray(group.ControlAsset.AssetId.Txid[:])
		vm.dstack.PushInt(scriptNum(group.ControlAsset.AssetId.Index))
		vm.dstack.PushInt(1)
		return nil
	}

	if group.ControlAsset.Type == asset.AssetRefByGroup {
		k := int(group.ControlAsset.GroupIndex)
		if k >= len(vm.assetPacket) {
			return scriptError(txscript.ErrInvalidStackOperation, "control asset group index out of range")
		}
		id := resolveAssetID(vm.tx.TxHash(), k, vm.assetPacket[k])
		vm.dstack.PushByteArray(id.Txid[:])
		vm.dstack.PushInt(scriptNum(id.Index))
		vm.dstack.PushInt(1)
		return nil
	}

	return scriptError(txscript.ErrInvalidStackOperation, "invalid control asset type")
}

// opcodeFindAssetGroupByAssetId pops a canonical AssetID (asset_txid asset_gidx)
// and searches for the packet group whose resolved canonical AssetID matches.
// Found:   pushes the packet group position k, 1.
// Missing: pushes 0, 0.
func opcodeFindAssetGroupByAssetId(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	searchTxid, searchGidx, err := popAssetID(vm)
	if err != nil {
		return err
	}

	txHash := vm.tx.TxHash()
	for k, group := range vm.assetPacket {
		id := resolveAssetID(txHash, k, group)
		if assetIDEqual(id, searchTxid, searchGidx) {
			vm.dstack.PushInt(scriptNum(k))
			vm.dstack.PushInt(1)
			return nil
		}
	}

	vm.dstack.PushInt(0)
	vm.dstack.PushInt(0)
	return nil
}

// opcodeInspectAssetGroupMetadataHash pops a group index k and pushes the Merkle root hash of its metadata.
func opcodeInspectAssetGroupMetadataHash(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	hash, err := computeMetadataMerkleRoot(group.Metadata)
	if err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to compute metadata hash: "+err.Error())
	}
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeInspectAssetGroupNum pops source and group index k, then pushes count(s) based on source:
// source=0: input count, source=1: output count, source=2: both input and output counts.
func opcodeInspectAssetGroupNum(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	source, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	switch source {
	case 0:
		vm.dstack.PushInt(scriptNum(len(group.Inputs)))
	case 1:
		vm.dstack.PushInt(scriptNum(len(group.Outputs)))
	case 2:
		vm.dstack.PushInt(scriptNum(len(group.Inputs)))
		vm.dstack.PushInt(scriptNum(len(group.Outputs)))
	default:
		return scriptError(txscript.ErrInvalidStackOperation, "invalid source value")
	}
	return nil
}

// opcodeInspectAssetGroup pops source, item index j, and group index k, then pushes details of the item.
// source=0: input details (type, [txid if intent], vin, amount), source=1: output details (1, vout, amount).
func opcodeInspectAssetGroup(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	source, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	j, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	switch source {
	case 0:
		if int(j) >= len(group.Inputs) || j < 0 {
			return scriptError(txscript.ErrInvalidStackOperation, "input index out of range")
		}
		input := group.Inputs[int(j)]

		vm.dstack.PushInt(scriptNum(input.Type))
		if input.Type == asset.AssetInputTypeIntent {
			vm.dstack.PushByteArray(input.Txid[:])
		}
		vm.dstack.PushInt(scriptNum(input.Vin))
		if err := vm.dstack.PushBigNum(BigNumFromUint64(input.Amount)); err != nil {
			return err
		}

	case 1:
		if int(j) >= len(group.Outputs) || j < 0 {
			return scriptError(txscript.ErrInvalidStackOperation, "output index out of range")
		}
		output := group.Outputs[int(j)]

		vm.dstack.PushInt(1)
		vm.dstack.PushInt(scriptNum(output.Vout))
		if err := vm.dstack.PushBigNum(BigNumFromUint64(output.Amount)); err != nil {
			return err
		}

	default:
		return scriptError(txscript.ErrInvalidStackOperation, "invalid source value")
	}
	return nil
}

// opcodeInspectAssetGroupSum pops source and group index k, then pushes sum(s) based on source:
// source=0: input sum, source=1: output sum, source=2: both input and output sums.
func opcodeInspectAssetGroupSum(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	source, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	switch source {
	case 0:
		return pushBigIntAsBigNum(vm, safeSumInputs(group.Inputs))
	case 1:
		return pushBigIntAsBigNum(vm, safeSumOutputs(group.Outputs))
	case 2:
		if err := pushBigIntAsBigNum(vm, safeSumInputs(group.Inputs)); err != nil {
			return err
		}
		if err := pushBigIntAsBigNum(vm, safeSumOutputs(group.Outputs)); err != nil {
			return err
		}
	default:
		return scriptError(txscript.ErrInvalidStackOperation, "invalid source value")
	}
	return nil
}

func pushBigIntAsBigNum(vm *Engine, n *big.Int) error {
	return vm.dstack.PushBigNum(BigNum{
		big:    new(big.Int).Set(n),
		useBig: true,
	})
}

// opcodeInspectOutAssetCount pops an output index o and pushes the number of asset entries at that output.
func opcodeInspectOutAssetCount(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	count := 0
	for _, group := range vm.assetPacket {
		for _, output := range group.Outputs {
			if uint32(output.Vout) == uint32(o) {
				count++
			}
		}
	}

	vm.dstack.PushInt(scriptNum(count))
	return nil
}

// opcodeInspectOutAssetAt pops asset index t and output index o, then pushes the
// asset entry as its canonical AssetID (asset_txid asset_gidx) and amount.
func opcodeInspectOutAssetAt(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	t, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if t < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "asset index out of range")
	}

	txHash := vm.tx.TxHash()
	idx := 0

	for k, group := range vm.assetPacket {
		id := resolveAssetID(txHash, k, group)
		for _, output := range group.Outputs {
			if uint32(output.Vout) == uint32(o) {
				if scriptNum(idx) == t {
					vm.dstack.PushByteArray(id.Txid[:])
					vm.dstack.PushInt(scriptNum(id.Index))
					if err := vm.dstack.PushBigNum(BigNumFromUint64(output.Amount)); err != nil {
						return err
					}
					return nil
				}
				idx++
			}
		}
	}

	return scriptError(txscript.ErrInvalidStackOperation, "asset index out of range")
}

// opcodeInspectOutAssetLookup pops a canonical AssetID (asset_txid asset_gidx)
// and an output index o, then looks up the matching asset output amount.
// Found:     pushes the amount as a minimally-encoded BigNum, then 1 (success flag).
// Not found: pushes 0 (BigNum), then 0 (failure flag).
func opcodeInspectOutAssetLookup(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	searchTxid, searchGidx, err := popAssetID(vm)
	if err != nil {
		return err
	}

	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	txHash := vm.tx.TxHash()

	for k, group := range vm.assetPacket {
		id := resolveAssetID(txHash, k, group)
		if !assetIDEqual(id, searchTxid, searchGidx) {
			continue
		}

		for _, output := range group.Outputs {
			if uint32(output.Vout) == uint32(o) {
				if err := vm.dstack.PushBigNum(BigNumFromUint64(output.Amount)); err != nil {
					return err
				}
				vm.dstack.PushInt(1)
				return nil
			}
		}
	}

	if err := vm.dstack.PushBigNum(BigNumFromUint64(0)); err != nil {
		return err
	}
	vm.dstack.PushInt(0)
	return nil
}

// opcodeInspectInAssetCount pops an input index i and pushes the number of asset entries at that input.
func opcodeInspectInAssetCount(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	count := 0
	for _, group := range vm.assetPacket {
		for _, input := range group.Inputs {
			if uint32(input.Vin) == uint32(i) {
				count++
			}
		}
	}

	vm.dstack.PushInt(scriptNum(count))
	return nil
}

// opcodeInspectInAssetAt pops asset index t and input index i, then pushes the
// asset entry as its canonical AssetID (asset_txid asset_gidx) and amount. The
// emitted asset_txid is always the asset's issuance transaction ID, never an
// intent input's intent_txid.
func opcodeInspectInAssetAt(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	t, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if t < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "asset index out of range")
	}

	txHash := vm.tx.TxHash()
	idx := 0

	for k, group := range vm.assetPacket {
		id := resolveAssetID(txHash, k, group)
		for _, input := range group.Inputs {
			if uint32(input.Vin) == uint32(i) {
				if scriptNum(idx) == t {
					vm.dstack.PushByteArray(id.Txid[:])
					vm.dstack.PushInt(scriptNum(id.Index))
					if err := vm.dstack.PushBigNum(BigNumFromUint64(input.Amount)); err != nil {
						return err
					}
					return nil
				}
				idx++
			}
		}
	}

	return scriptError(txscript.ErrInvalidStackOperation, "asset index out of range")
}

// opcodeInspectInAssetLookup pops a canonical AssetID (asset_txid asset_gidx)
// and an input index i, then looks up the matching asset input amount. Matching
// is by canonical AssetID only; an intent input's intent_txid is never accepted
// as a substitute for the issuance asset_txid.
// Found:     pushes the amount as a minimally-encoded BigNum, then 1 (success flag).
// Not found: pushes 0 (BigNum), then 0 (failure flag).
func opcodeInspectInAssetLookup(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	searchTxid, searchGidx, err := popAssetID(vm)
	if err != nil {
		return err
	}

	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	txHash := vm.tx.TxHash()

	for k, group := range vm.assetPacket {
		id := resolveAssetID(txHash, k, group)
		if !assetIDEqual(id, searchTxid, searchGidx) {
			continue
		}

		for _, input := range group.Inputs {
			if uint32(input.Vin) == uint32(i) {
				if err := vm.dstack.PushBigNum(BigNumFromUint64(input.Amount)); err != nil {
					return err
				}
				vm.dstack.PushInt(1)
				return nil
			}
		}
	}

	if err := vm.dstack.PushBigNum(BigNumFromUint64(0)); err != nil {
		return err
	}
	vm.dstack.PushInt(0)
	return nil
}

// computeMetadataMerkleRoot computes the Merkle root hash of the given metadata slice.
func computeMetadataMerkleRoot(metadata []asset.Metadata) (chainhash.Hash, error) {
	if len(metadata) == 0 {
		return chainhash.Hash{}, nil
	}

	hashes := make([]chainhash.Hash, len(metadata))
	for i, md := range metadata {
		serialized, err := md.Serialize()
		if err != nil {
			return chainhash.Hash{}, err
		}
		hashes[i] = sha256.Sum256(serialized)
	}

	for len(hashes) > 1 {
		var nextLevel []chainhash.Hash
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				var combined [64]byte
				copy(combined[:32], hashes[i][:])
				copy(combined[32:], hashes[i+1][:])
				hash := sha256.Sum256(combined[:])
				nextLevel = append(nextLevel, hash)
			} else {
				nextLevel = append(nextLevel, hashes[i])
			}
		}
		hashes = nextLevel
	}

	return hashes[0], nil
}

// safeSumInputs computes the total amount across all inputs using big.Int to avoid overflow.
func safeSumInputs(inputs []asset.AssetInput) *big.Int {
	sum := new(big.Int)
	for _, input := range inputs {
		sum.Add(sum, new(big.Int).SetUint64(input.Amount))
	}
	return sum
}

// safeSumOutputs computes the total amount across all outputs using big.Int to avoid overflow.
func safeSumOutputs(outputs []asset.AssetOutput) *big.Int {
	sum := new(big.Int)
	for _, output := range outputs {
		sum.Add(sum, new(big.Int).SetUint64(output.Amount))
	}
	return sum
}

// maxAssetGroupIndex is the inclusive upper bound for a canonical asset_gidx,
// matching the uint16 Asset V1 field.
const maxAssetGroupIndex = 65535

// resolveAssetID returns the canonical AssetID of the packet group at position k.
// A group with an explicit AssetId is returned as stored; a fresh issuance
// derives its identity from the current transaction hash and its packet
// position. Callers must pass a k already validated to lie in [0, len(packet)),
// so casting it to the uint16 asset_gidx field is always safe.
func resolveAssetID(txHash chainhash.Hash, k int, group asset.AssetGroup) asset.AssetId {
	if group.AssetId != nil {
		return *group.AssetId
	}
	return asset.AssetId{Txid: txHash, Index: uint16(k)}
}

// popAssetID pops and validates a two-item canonical AssetID from the stack. The
// items are, from the top, asset_gidx then asset_txid. asset_txid must be
// exactly 32 bytes and asset_gidx must be a minimally encoded ScriptNum in the
// range [0, 65535]. Any violation is a script error.
func popAssetID(vm *Engine) (chainhash.Hash, uint16, error) {
	var txid chainhash.Hash

	gidx, err := vm.dstack.PopInt()
	if err != nil {
		return txid, 0, err
	}

	txidBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return txid, 0, err
	}

	if len(txidBytes) != 32 {
		return txid, 0, scriptError(txscript.ErrInvalidStackOperation, "invalid asset_txid length")
	}

	if gidx < 0 || gidx > maxAssetGroupIndex {
		return txid, 0, scriptError(txscript.ErrInvalidStackOperation, "asset_gidx out of range")
	}

	copy(txid[:], txidBytes)
	return txid, uint16(gidx), nil
}

// assetIDEqual reports whether a resolved canonical AssetID equals the supplied
// (txid, gidx) pair, comparing the complete pair.
func assetIDEqual(id asset.AssetId, txid chainhash.Hash, gidx uint16) bool {
	return id.Index == gidx && id.Txid.IsEqual(&txid)
}
