package arkade

import (
	"crypto/sha256"
	"encoding/binary"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// fuzzWorldParams is decoded from fuzz bytes to drive the shape of a generated
// transaction world. Fields are named for their semantic role so the struct
// layout is stable across corpus runs.
type fuzzWorldParams struct {
	InputCountSeed       uint8
	OutputCountSeed      uint8
	BasePrevOutIndex     uint32
	BaseSequence         uint32
	BaseInputValue       int64
	BaseOutputValue      int64
	InputScriptTypeSeed  uint8
	OutputScriptTypeSeed uint8
	TxVersionSeed        int32
	LockTimeSeed         uint32
}

// opcodeFuzzWorld bundles a coherent transaction world together with the PSBT
// and signer key that are needed to validate arkade script submissions.
type opcodeFuzzWorld struct {
	world           *opcodeWorld
	ptx             *psbt.Packet
	signerPublicKey *btcec.PublicKey
}

// buildFuzzWorld derives a transaction, prevout set, emulator packet, and
// asset packet that are internally consistent enough for most opcodes to run.
// This intentionally biases toward "valid enough to execute" instead of fully
// unconstrained randomness so the fuzzer spends more time inside opcode logic.
func buildFuzzWorld(data []byte) *opcodeFuzzWorld {
	params := fuzzStructFromBytes[fuzzWorldParams](saltedBytes(data, 0xa0))
	inputCount := int(params.InputCountSeed%fuzzMaxInOutCount) + 1
	outputCount := int(params.OutputCountSeed % fuzzMaxInOutCount)

	txIn := make([]*wire.TxIn, inputCount)
	prevouts := make(map[wire.OutPoint]*wire.TxOut, inputCount)
	arkTxs := make(map[wire.OutPoint]*wire.MsgTx, inputCount)
	prevoutIdxs := make(map[wire.OutPoint]uint32, inputCount)
	scriptByVin := make(map[int][]byte, inputCount)
	execScriptByVin := make(map[int][]byte, inputCount)
	witnessByVin := make(map[int]wire.TxWitness, inputCount)
	entries := make([]EmulatorEntry, 0, inputCount)

	for i := range inputCount {
		h := hashWithSalt(data, byte(i))
		outpoint := wire.OutPoint{Hash: h, Index: params.BasePrevOutIndex + uint32(i)}
		txIn[i] = &wire.TxIn{
			PreviousOutPoint: outpoint,
			Sequence:         params.BaseSequence + uint32(i),
		}

		pkScript := []byte{OP_1, 0x20}
		pkScript = append(pkScript, h[:]...)

		prevouts[outpoint] = &wire.TxOut{
			Value:    params.BaseInputValue + int64(i),
			PkScript: pkScript,
		}

		scriptByVin[i] = []byte{OP_TRUE}
		entryWitness := wire.TxWitness{h[:], h[:16]}
		entries = append(entries, EmulatorEntry{
			Vin:     uint16(i),
			Script:  cloneBytes(scriptByVin[i]),
			Witness: cloneWitness(entryWitness),
		})

		prevPacketType := uint8(2 + h[0]%200)
		prevPayloadLen := int(h[1]%32) + 1
		prevTx := makeOpcodeTxWithExtension(extension.UnknownPacket{
			PacketType: prevPacketType,
			Data:       cloneBytes(h[:prevPayloadLen]),
		})
		prevScript := append([]byte{OP_1, 0x20}, h[:]...)
		prevTx.TxOut = append([]*wire.TxOut{{
			Value:    params.BaseInputValue + int64(i),
			PkScript: prevScript,
		}}, prevTx.TxOut...)
		arkTxs[outpoint] = &prevTx
		prevoutIdxs[outpoint] = 0

		if h[2]&1 == 0 {
			execScript := []byte{OP_TRUE}
			execStack := wire.TxWitness{}
			switch h[3] % 3 {
			case 1:
				execScript = []byte{OP_DUP, OP_DROP, OP_TRUE}
				execStack = wire.TxWitness{[]byte{0x01}}
			case 2:
				execScript = []byte{OP_IF, OP_TRUE, OP_ELSE, OP_TRUE, OP_ENDIF}
				execStack = wire.TxWitness{[]byte{0x01}}
			}

			internalPriv, _ := btcec.PrivKeyFromBytes(saltedBytes(data, byte(0x40+i)))
			leaf := txscript.NewBaseTapLeaf(execScript)
			leafHash := leaf.TapHash()
			outputKey := txscript.ComputeTaprootOutputKey(internalPriv.PubKey(), leafHash[:])
			controlBlock := &txscript.ControlBlock{
				InternalKey:     internalPriv.PubKey(),
				LeafVersion:     txscript.BaseLeafVersion,
				OutputKeyYIsOdd: outputKey.SerializeCompressed()[0] == 0x03,
			}
			controlBytes, err := controlBlock.ToBytes()
			if err != nil {
				return nil
			}
			scriptPubKey, err := txscript.PayToTaprootScript(outputKey)
			if err != nil {
				return nil
			}

			execScriptByVin[i] = scriptPubKey
			witnessByVin[i] = append(cloneWitness(execStack), cloneBytes(execScript), cloneBytes(controlBytes))
		}
	}

	packet, err := NewPacket(entries...)
	if err != nil {
		return nil
	}
	assetPacket := buildFuzzAssetPacket(data, inputCount, outputCount)

	txOut := make([]*wire.TxOut, outputCount)
	for i := range outputCount {
		txOut[i] = &wire.TxOut{
			Value:    params.BaseOutputValue + int64(i),
			PkScript: []byte{OP_TRUE},
		}
	}

	ext := extension.Extension{assetPacket, packet}
	packetOut, err := ext.TxOut()
	if err != nil {
		return nil
	}
	txOut = append(txOut, packetOut)

	tx := wire.MsgTx{
		Version:  params.TxVersionSeed,
		LockTime: params.LockTimeSeed,
		TxIn:     txIn,
		TxOut:    txOut,
	}

	parsedPacket, err := FindEmulatorPacket(&tx)
	if err != nil || len(parsedPacket) == 0 {
		return nil
	}

	ptx, err := psbt.NewFromUnsignedTx(&tx)
	if err != nil {
		return nil
	}

	privKey, _ := btcec.PrivKeyFromBytes(saltedBytes(data, 0x44))
	signerPubKey := privKey.PubKey()

	for _, entry := range parsedPacket {
		vin := int(entry.Vin)
		if vin < 0 || vin >= len(ptx.Inputs) {
			return nil
		}

		tweakedPubKey := ComputeArkadeScriptPublicKey(signerPubKey, ArkadeScriptHash(entry.Script))
		closure := &scriptlib.MultisigClosure{
			PubKeys: []*btcec.PublicKey{tweakedPubKey},
			Type:    scriptlib.MultisigTypeChecksig,
		}
		tapScript, err := closure.Script()
		if err != nil {
			return nil
		}

		ptx.Inputs[vin].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			Script: tapScript,
		}}
	}

	return &opcodeFuzzWorld{
		world: &opcodeWorld{
			tx:              tx,
			prevouts:        prevouts,
			prevFetcher:     newTestArkPrevOutFetcher(txscript.NewMultiPrevOutFetcher(prevouts), arkTxs, prevoutIdxs),
			assetPacket:     assetPacket,
			scriptByVin:     scriptByVin,
			execScriptByVin: execScriptByVin,
			witnessByVin:    witnessByVin,
			packet:          parsedPacket,
		},
		ptx:             ptx,
		signerPublicKey: signerPubKey,
	}
}

// buildMinimalEngineWorld returns the simplest valid opcodeWorld that
// NewEngine will accept: one input, one prevout, no asset/emulator
// packets. It is used by engine fuzzers when buildFuzzWorld returns nil.
func buildMinimalEngineWorld(data []byte) *opcodeWorld {
	h := hashWithSalt(data, 0x01)
	outpoint := wire.OutPoint{Hash: h, Index: 0}
	tx := wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: outpoint}},
		TxOut:   []*wire.TxOut{{Value: 1000, PkScript: []byte{OP_TRUE}}},
	}
	prevouts := map[wire.OutPoint]*wire.TxOut{
		outpoint: {Value: 1000, PkScript: []byte{OP_1, 0x20}},
	}
	return &opcodeWorld{
		tx:          tx,
		prevouts:    prevouts,
		prevFetcher: newTestArkPrevOutFetcher(txscript.NewMultiPrevOutFetcher(prevouts), nil, nil),
	}
}

// setEnginePacketsFromWorld attaches the emulator and asset packets stored
// in world to an already-constructed Engine.
func setEnginePacketsFromWorld(vm *Engine, world *opcodeWorld) {
	vm.SetEmulatorPacket(world.packet)
	if world.assetPacket != nil {
		vm.SetAssetPacket(world.assetPacket)
		return
	}

	ext, err := extension.NewExtensionFromTx(&world.tx)
	if err != nil {
		return
	}
	if packet := ext.GetAssetPacket(); packet != nil {
		vm.SetAssetPacket(packet)
	}
}

// buildFuzzAssetPacket fuzzes asset packet structure while normalizing invalid
// constructions back to a minimal fallback packet. That keeps asset opcodes in
// play even when a particular random shape does not satisfy packet invariants.
func buildFuzzAssetPacket(data []byte, inputCount int, outputCount int) asset.Packet {
	seed := saltedBytes(data, 0xb0)
	groupCount := int(seed[0]%fuzzMaxAssetGroupCount) + 1
	txOutputCount := outputCount + 1
	if txOutputCount <= 0 {
		txOutputCount = 1
	}

	groups := make([]asset.AssetGroup, 0, groupCount)
	seenAssetIDs := make(map[asset.AssetId]struct{}, groupCount)

	for i := range groupCount {
		groupSeed := saltedBytes(data, byte(0xb1+i))
		groups = append(groups, buildFuzzAssetGroup(groupSeed, data, i, groupCount, inputCount, txOutputCount, seenAssetIDs))
	}

	packet, err := asset.NewPacket(groups)
	if err == nil {
		return packet
	}

	fallback, _ := asset.NewPacket([]asset.AssetGroup{fallbackFuzzAssetGroup()})
	return fallback
}

func buildFuzzAssetGroup(
	seed []byte,
	data []byte,
	groupIndex int,
	groupCount int,
	inputCount int,
	txOutputCount int,
	seenAssetIDs map[asset.AssetId]struct{},
) asset.AssetGroup {
	issuance := seed[0]&1 == 0

	var assetID *asset.AssetId
	if !issuance {
		candidate := uniqueFuzzAssetID(data, groupIndex, seenAssetIDs)
		assetID = &candidate
	}

	var controlAsset *asset.AssetRef
	if issuance && seed[1]&1 == 1 {
		if groupCount > 1 && seed[2]&1 == 0 {
			controlAsset = &asset.AssetRef{
				Type:       asset.AssetRefByGroup,
				GroupIndex: uint16(seed[3]) % uint16(groupCount),
			}
		} else {
			controlAsset = &asset.AssetRef{
				Type: asset.AssetRefByID,
				AssetId: asset.AssetId{
					Txid:  nonZeroHashFromSeed(saltedBytes(seed, 0x44)),
					Index: uint16(seed[4]),
				},
			}
		}
	}

	outputCount := int(seed[5] % fuzzMaxAssetItemCount)
	if issuance && outputCount == 0 {
		outputCount = 1
	}
	outputs := make([]asset.AssetOutput, 0, outputCount)
	for i := range outputCount {
		itemSeed := saltedBytes(seed, byte(0x50+i))
		outputs = append(outputs, asset.AssetOutput{
			Type:   asset.AssetOutputTypeLocal,
			Vout:   uint16(binary.LittleEndian.Uint16(itemSeed[:2]) % uint16(txOutputCount)),
			Amount: uint64(binary.LittleEndian.Uint32(itemSeed[2:6])) + 1,
		})
	}

	var inputs []asset.AssetInput
	if !issuance {
		inputItems := int(seed[6] % fuzzMaxAssetItemCount)
		if inputItems == 0 && len(outputs) == 0 {
			inputItems = 1
		}

		inputs = make([]asset.AssetInput, 0, inputItems)
		for i := range inputItems {
			itemSeed := saltedBytes(seed, byte(0x70+i))
			input := asset.AssetInput{
				Type:   asset.AssetInputTypeLocal,
				Vin:    uint16(binary.LittleEndian.Uint16(itemSeed[1:3]) % uint16(inputCount)),
				Amount: uint64(binary.LittleEndian.Uint32(itemSeed[3:7])) + 1,
			}
			if itemSeed[0]&1 == 1 {
				input.Type = asset.AssetInputTypeIntent
				input.Txid = nonZeroHashFromSeed(saltedBytes(itemSeed, 0x71))
			}
			inputs = append(inputs, input)
		}
	}

	metadataCount := int(seed[7] % fuzzMaxMetadataCount)
	metadata := make([]asset.Metadata, 0, metadataCount)
	for i := range metadataCount {
		itemSeed := saltedBytes(seed, byte(0x90+i))
		metadata = append(metadata, asset.Metadata{
			Key:   fuzzMetadataField(itemSeed[0], itemSeed[1:16]),
			Value: fuzzMetadataField(itemSeed[16], itemSeed[17:32]),
		})
	}

	return asset.AssetGroup{
		AssetId:      assetID,
		ControlAsset: controlAsset,
		Inputs:       inputs,
		Outputs:      outputs,
		Metadata:     metadata,
	}
}

func uniqueFuzzAssetID(data []byte, groupIndex int, seen map[asset.AssetId]struct{}) asset.AssetId {
	for attempt := range 16 {
		seed := saltedBytes(data, byte(0xc0+groupIndex+attempt))
		candidate := asset.AssetId{
			Txid:  nonZeroHashFromSeed(seed),
			Index: uint16(binary.LittleEndian.Uint16(seed[:2])),
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		return candidate
	}

	fallback := asset.AssetId{Txid: nonZeroHashFromSeed(saltedBytes(data, byte(0xe0+groupIndex))), Index: uint16(groupIndex)}
	seen[fallback] = struct{}{}
	return fallback
}

func fallbackFuzzAssetGroup() asset.AssetGroup {
	return asset.AssetGroup{
		Outputs: []asset.AssetOutput{{
			Type:   asset.AssetOutputTypeLocal,
			Vout:   0,
			Amount: 1,
		}},
	}
}

func nonZeroHashFromSeed(seed []byte) [32]byte {
	h := hashWithSalt(seed, 0xaa)
	allZero := true
	for _, b := range h {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		h[0] = 1
	}
	return h
}

func fuzzMetadataField(sizeSeed byte, pool []byte) []byte {
	if len(pool) == 0 {
		return []byte{1}
	}
	length := int(sizeSeed%12) + 1
	out := make([]byte, length)
	for i := range length {
		out[i] = pool[i%len(pool)]
		if out[i] == 0 {
			out[i] = 1
		}
	}
	return out
}

// saltedBytes deterministically derives 32 bytes from data and a salt byte.
// Every opcode/engine fuzz case uses a different salt so one raw fuzz input
// drives many independent but reproducible sub-inputs.
func saltedBytes(data []byte, salt byte) []byte {
	b := make([]byte, len(data)+1)
	copy(b, data)
	b[len(data)] = salt
	sum := sha256.Sum256(b)
	return sum[:]
}

// fuzzStructFromBytes populates any struct T from fuzz bytes using the
// go-fuzz-headers consumer, which fills fields in declaration order.
func fuzzStructFromBytes[T any](data []byte) T {
	var params T
	consumer := fuzz.NewConsumer(data)
	_ = consumer.GenerateStruct(&params)
	return params
}

// fuzzStackItems decodes a small number of arbitrary byte slices from fuzz
// data to use as pre-loaded stack items.
func fuzzStackItems(data []byte) [][]byte {
	consumer := fuzz.NewConsumer(data)
	numItems, _ := consumer.GetInt()
	if numItems < 0 {
		numItems = -numItems
	}
	numItems %= 10

	items := make([][]byte, 0, numItems)
	for range numItems {
		item, _ := consumer.GetBytes()
		if len(item) > 520 {
			item = item[:520]
		}
		items = append(items, cloneBytes(item))
	}

	return items
}

// cloneBytes returns a deep copy of b, or nil if b is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	clone := make([]byte, len(b))
	copy(clone, b)
	return clone
}

// clone2DBytes returns a deep copy of a slice of byte slices.
func clone2DBytes(items [][]byte) [][]byte {
	if items == nil {
		return nil
	}

	clone := make([][]byte, len(items))
	for i := range items {
		clone[i] = cloneBytes(items[i])
	}
	return clone
}

// cloneWitness returns a deep copy of a transaction witness stack.
func cloneWitness(w wire.TxWitness) wire.TxWitness {
	if w == nil {
		return nil
	}

	clone := make(wire.TxWitness, len(w))
	for i := range w {
		clone[i] = cloneBytes(w[i])
	}
	return clone
}
