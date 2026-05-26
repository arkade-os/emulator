package arkade

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

const fuzzMaxInOutCount = 200

const (
	fuzzMaxAssetGroupCount = 16
	fuzzMaxAssetItemCount  = 16
	fuzzMaxMetadataCount   = 8

	fuzzSerializedSetupPushLimit = 3
	fuzzSerializedSetupPushSize  = 32
)

type fuzzIndexSource struct {
	IndexSeed uint8
	IndexMode uint8
}

type opcodeFuzzCase struct {
	stackPushes    [][]byte
	altStackPushes [][]byte
	condStack      []int
	txIdx          int
	opcodeData     []byte
}

type fuzzExecutionSource struct {
	TxSeed   uint8
	AltSeed  uint8
	CondSeed uint8
	Mode     uint8
}

type fuzzCaseBuilder interface {
	Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase
}

type defaultCaseBuilder struct{}

func (defaultCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	seed := fuzzStructFromBytes[fuzzExecutionSource](data)
	c := opcodeFuzzCase{
		stackPushes: fuzzStackItems(data),
		txIdx:       0,
	}
	if len(world.world.tx.TxIn) > 0 {
		c.txIdx = int(seed.TxSeed) % len(world.world.tx.TxIn)
	}
	if seed.Mode&1 == 0 {
		c.altStackPushes = fuzzStackItems(saltedBytes(data, seed.AltSeed))
	}
	switch seed.CondSeed % 5 {
	case 1:
		c.condStack = []int{OpCondTrue}
	case 2:
		c.condStack = []int{OpCondFalse}
	case 3:
		c.condStack = []int{OpCondSkip}
	case 4:
		c.condStack = []int{OpCondTrue, []int{OpCondFalse, OpCondSkip}[seed.Mode%2]}
	}
	return c
}

type indexCaseBuilder struct {
	isOut bool
}

func (b indexCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	seed := fuzzStructFromBytes[fuzzIndexSource](data)
	count := len(world.world.tx.TxIn)
	if b.isOut {
		count = len(world.world.tx.TxOut)
	}
	idx := deriveIndex(seed.IndexSeed, seed.IndexMode, count)
	c.stackPushes = [][]byte{scriptNum(idx).Bytes()}
	return c
}

type pushDataCaseBuilder struct {
	opcode byte
}

func (b pushDataCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	payload := buildPushDataPayload(b.opcode, data)
	c.opcodeData = payload
	return c
}

type packetCaseBuilder struct{}

func (packetCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	packetType := scriptNum(int64(data[0]))
	if ext, err := extension.NewExtensionFromTx(&world.world.tx); err == nil && len(ext) > 0 {
		packet := ext[int(data[0])%len(ext)]
		packetType = scriptNum(packet.Type())
		if data[1]&1 == 1 {
			packetType = scriptNum((int64(packet.Type()) + 1) & 0xff)
		}
	}
	c.stackPushes = [][]byte{packetType.Bytes()}
	return c
}

type inputPacketCaseBuilder struct{}

func (inputPacketCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	if len(world.world.tx.TxIn) == 0 {
		c.stackPushes = [][]byte{nil, nil}
		return c
	}
	inputIdx := int(data[0]) % len(world.world.tx.TxIn)
	packetType := scriptNum(int64(data[1]))
	prevTx := world.world.prevFetcher.FetchPrevOutArkTx(world.world.tx.TxIn[inputIdx].PreviousOutPoint)
	if prevTx != nil {
		if ext, err := extension.NewExtensionFromTx(prevTx); err == nil && len(ext) > 0 {
			packet := ext[int(data[1])%len(ext)]
			packetType = scriptNum(packet.Type())
			if data[2]&1 == 1 {
				packetType = scriptNum((int64(packet.Type()) + 1) & 0xff)
			}
		}
	}
	c.stackPushes = [][]byte{packetType.Bytes(), scriptNum(inputIdx).Bytes()}
	return c
}

type assetIDLookupCaseBuilder struct{}

func (assetIDLookupCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	var txid []byte
	groupRef := int64(0)
	if world.world.assetPacket != nil && len(world.world.assetPacket) > 0 {
		groupIdx := int(data[0]) % len(world.world.assetPacket)
		group := world.world.assetPacket[groupIdx]
		groupRef = int64(groupIdx)
		if group.AssetId == nil {
			txHash := world.world.tx.TxHash()
			txid = cloneBytes(txHash[:])
		} else {
			groupRef = int64(group.AssetId.Index)
			txid = cloneBytes(group.AssetId.Txid[:])
		}
		if data[1]&1 == 1 {
			groupRef += int64(len(world.world.assetPacket))
		}
	}
	if len(txid) == 0 {
		txid = make([]byte, 32)
	}
	if data[2]&1 == 1 {
		txid[0] ^= 0xff
	}
	c.stackPushes = [][]byte{txid, scriptNum(groupRef).Bytes()}
	return c
}

type taprootCheckSigCaseBuilder struct{}

func (taprootCheckSigCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	for txIdx := range world.world.execScriptByVin {
		c.txIdx = txIdx
		break
	}
	c.stackPushes = [][]byte{nil, cloneBytes(saltedBytes(data, 0x91))}
	return c
}

// sighashCaseBuilder feeds a wide spread of hashType bytes (valid and invalid)
// into OP_SIGHASH so the fuzzer exercises both the strict validation path and
// the BIP342 digest path.
type sighashCaseBuilder struct{}

func (sighashCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	if len(data) < 2 {
		return c
	}
	for txIdx := range world.world.execScriptByVin {
		c.txIdx = txIdx
		break
	}
	// Mix in some known-valid flags so we don't only test the reject path.
	allowedFlags := []byte{0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83}
	flag := int64(data[0])
	if data[1]&1 == 0 {
		flag = int64(allowedFlags[int(data[0])%len(allowedFlags)])
	}
	c.stackPushes = [][]byte{scriptNum(flag).Bytes()}
	return c
}

type taprootCheckSigAddCaseBuilder struct{}

func (taprootCheckSigAddCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	for txIdx := range world.world.execScriptByVin {
		c.txIdx = txIdx
		break
	}
	c.stackPushes = [][]byte{nil, scriptNum(int64(data[0] % 4)).Bytes(), cloneBytes(saltedBytes(data, 0x92))}
	return c
}

type assetGroupCaseBuilder struct{}

func (assetGroupCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	idx := int64(-1)
	if world.world.assetPacket != nil && len(world.world.assetPacket) > 0 {
		idx = int64(data[0] % uint8(len(world.world.assetPacket)))
		if data[1]&1 == 1 {
			idx = int64(len(world.world.assetPacket) + int(data[0]%4))
		}
	}
	c.stackPushes = [][]byte{scriptNum(idx).Bytes()}
	return c
}

type assetGroupSourceCaseBuilder struct{}

func (assetGroupSourceCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := assetGroupCaseBuilder{}.Build(data, world)
	source := scriptNum(int64(data[2] % 3))
	if data[3]&1 == 1 {
		source = scriptNum(3 + data[2]%3)
	}
	c.stackPushes = append(c.stackPushes, source.Bytes())
	return c
}

type assetGroupItemSourceCaseBuilder struct{}

func (assetGroupItemSourceCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	groupIdx := 0
	if world.world.assetPacket != nil && len(world.world.assetPacket) > 0 {
		groupIdx = int(data[0]) % len(world.world.assetPacket)
	}
	source := int64(data[1] % 2)
	itemIdx := int64(0)
	if world.world.assetPacket != nil && len(world.world.assetPacket) > 0 {
		group := world.world.assetPacket[groupIdx]
		count := len(group.Inputs)
		if source == 1 {
			count = len(group.Outputs)
		}
		if count > 0 {
			itemIdx = int64(data[2] % uint8(count))
		}
		if data[3]&1 == 1 {
			itemIdx = int64(count + int(data[2]%4))
		}
	}
	if data[4]&1 == 1 {
		source = 2
	}
	c.stackPushes = [][]byte{scriptNum(groupIdx).Bytes(), scriptNum(itemIdx).Bytes(), scriptNum(source).Bytes()}
	return c
}

type assetIndexCaseBuilder struct {
	isOut bool
}

func (b assetIndexCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	index := int64(0)
	count := len(world.world.tx.TxIn)
	if b.isOut {
		count = len(world.world.tx.TxOut)
	}
	if count > 0 {
		index = int64(data[0] % uint8(count))
	}
	if data[1]&1 == 1 {
		index = int64(count + int(data[0]%4))
	}
	c.stackPushes = [][]byte{scriptNum(index).Bytes()}
	return c
}

type assetAtCaseBuilder struct {
	isOut bool
}

func (b assetAtCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	index := int64(0)
	assetIdx := int64(0)
	count := len(world.world.tx.TxIn)
	if b.isOut {
		count = len(world.world.tx.TxOut)
	}
	if count > 0 {
		index = int64(data[0] % uint8(count))
	}
	if data[1]&1 == 1 {
		index = int64(count + int(data[0]%4))
	}
	assetIdx = int64(data[2] % 4)
	c.stackPushes = [][]byte{scriptNum(index).Bytes(), scriptNum(assetIdx).Bytes()}
	return c
}

type assetLookupCaseBuilder struct {
	isOut bool
}

func (b assetLookupCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	index := int64(0)
	if b.isOut {
		if len(world.world.tx.TxOut) > 0 {
			index = int64(data[0] % uint8(len(world.world.tx.TxOut)))
		}
	} else if len(world.world.tx.TxIn) > 0 {
		index = int64(data[0] % uint8(len(world.world.tx.TxIn)))
	}

	var txid []byte
	groupIdx := int64(0)
	if world.world.assetPacket != nil && len(world.world.assetPacket) > 0 {
		group := world.world.assetPacket[int(data[1])%len(world.world.assetPacket)]
		groupIdx = int64(int(data[1]) % len(world.world.assetPacket))
		if group.AssetId == nil {
			assetTxid := world.world.tx.TxHash()
			txid = cloneBytes(assetTxid[:])
		} else {
			txid = cloneBytes(group.AssetId.Txid[:])
		}
		if data[2]&1 == 1 {
			groupIdx = int64(len(world.world.assetPacket) + int(data[1]%4))
		}
	}
	if len(txid) == 0 {
		txid = make([]byte, 32)
	}
	if data[3]&1 == 1 {
		txid[0] ^= 0xff
	}
	c.stackPushes = [][]byte{scriptNum(index).Bytes(), txid, scriptNum(groupIdx).Bytes()}
	return c
}

var fuzzCaseBuilders = [256]fuzzCaseBuilder{
	OP_INSPECTINPUTOUTPOINT:          indexCaseBuilder{},
	OP_INSPECTINPUTSEQUENCE:          indexCaseBuilder{},
	OP_INSPECTINPUTSCRIPTPUBKEY:      indexCaseBuilder{},
	OP_INSPECTINPUTVALUE:             indexCaseBuilder{},
	OP_INSPECTOUTPUTVALUE:            indexCaseBuilder{isOut: true},
	OP_INSPECTOUTPUTSCRIPTPUBKEY:     indexCaseBuilder{isOut: true},
	OP_INSPECTINPUTARKADESCRIPTHASH:  indexCaseBuilder{},
	OP_INSPECTINPUTARKADEWITNESSHASH: indexCaseBuilder{},
	OP_INSPECTPACKET:                 packetCaseBuilder{},
	OP_INSPECTINPUTPACKET:            inputPacketCaseBuilder{},
	OP_CODESEPARATOR:                 defaultCaseBuilder{},
	OP_CHECKSIG:                      taprootCheckSigCaseBuilder{},
	OP_CHECKSIGVERIFY:                taprootCheckSigCaseBuilder{},
	OP_CHECKSIGADD:                   taprootCheckSigAddCaseBuilder{},
	OP_SIGHASH:                       sighashCaseBuilder{},
	OP_FINDASSETGROUPBYASSETID:       assetIDLookupCaseBuilder{},
	OP_INSPECTASSETGROUPASSETID:      assetGroupCaseBuilder{},
	OP_INSPECTASSETGROUPCTRL:         assetGroupCaseBuilder{},
	OP_INSPECTASSETGROUPMETADATAHASH: assetGroupCaseBuilder{},
	OP_INSPECTASSETGROUPNUM:          assetGroupSourceCaseBuilder{},
	OP_INSPECTASSETGROUP:             assetGroupItemSourceCaseBuilder{},
	OP_INSPECTASSETGROUPSUM:          assetGroupSourceCaseBuilder{},
	OP_INSPECTOUTASSETCOUNT:          assetIndexCaseBuilder{isOut: true},
	OP_INSPECTOUTASSETAT:             assetAtCaseBuilder{isOut: true},
	OP_INSPECTOUTASSETLOOKUP:         assetLookupCaseBuilder{isOut: true},
	OP_INSPECTINASSETCOUNT:           assetIndexCaseBuilder{},
	OP_INSPECTINASSETAT:              assetAtCaseBuilder{},
	OP_INSPECTINASSETLOOKUP:          assetLookupCaseBuilder{},
	OP_ECADD:                         ecCurveCaseBuilder{coordPushes: 4},
	OP_ECMUL:                         ecCurveCaseBuilder{coordPushes: 3},
	OP_ECPAIRING:                     ecPairingFuzzCaseBuilder{},
}

// ecCurveCaseBuilder seeds the stack with a few BigNum-shaped pushes plus a
// bounded curve_id on top, so the EC opcodes spend most fuzz iterations past
// the initial validation gate.
type ecCurveCaseBuilder struct{ coordPushes int }

func (b ecCurveCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	salted := saltedBytes(data, 0xec)
	items := make([][]byte, 0, b.coordPushes+1)
	for i := range b.coordPushes {
		items = append(items, ecFuzzCoord(salted, byte(i)))
	}
	curveID := scriptNum(int64(salted[0]) % 5) // bias toward 0..2 valid, 3..4 invalid
	items = append(items, curveID.Bytes())
	c.stackPushes = items
	return c
}

// ecPairingFuzzCaseBuilder pushes a count near the maxECPairingCount boundary
// and per-pair coordinates, exercising the variable-arity stack consumption
// in OP_ECPAIRING.
type ecPairingFuzzCaseBuilder struct{}

func (ecPairingFuzzCaseBuilder) Build(data []byte, world *opcodeFuzzWorld) opcodeFuzzCase {
	c := defaultCaseBuilder{}.Build(data, world)
	salted := saltedBytes(data, 0xed)
	// 0..19 covers below, at, and just past maxECPairingCount = 16
	pairCount := int64(salted[0]) % 20
	items := make([][]byte, 0, 6*int(pairCount)+2)
	for i := int64(0); i < pairCount; i++ {
		for j := byte(0); j < 6; j++ {
			items = append(items, ecFuzzCoord(salted, byte(i)*7+j))
		}
	}
	items = append(items, scriptNum(pairCount).Bytes())
	curveID := scriptNum(int64(salted[1]) % 5)
	items = append(items, curveID.Bytes())
	c.stackPushes = items
	return c
}

// ecFuzzCoord builds a random-but-canonical BigNum byte slice from the fuzz
// seed so most fuzz inputs survive minimal-encoding checks and let the opcode
// reach its curve-specific validation paths.
func ecFuzzCoord(seed []byte, salt byte) []byte {
	src := saltedBytes(seed, salt)
	// Length 0..32 bytes covers small, medium, and full-32-byte coordinates.
	length := int(src[0]) % 33
	if length == 0 {
		return nil
	}
	raw := make([]byte, length)
	copy(raw, src[1:])
	// Drop sign bit on the last byte so the BigNum is non-negative
	// most of the time. Coordinates are non-negative in the EC opcodes.
	raw[length-1] &= 0x7f
	canonical := minimallyEncode(raw)
	if canonical == nil {
		return nil
	}
	out := make([]byte, len(canonical))
	copy(out, canonical)
	return out
}

// FuzzOpcodes turns one fuzz input into a coherent transaction world, derives a
// reproducible case for every opcode, and then exercises those cases in three
// complementary ways: isolated execution, stateful/chained execution, and a
// serialized script pass that goes through the tokenizer and Step().
func FuzzOpcodes(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 10 {
			return
		}

		fuzzWorld := buildFuzzWorld(data)
		if fuzzWorld == nil {
			return
		}
		if !validateSubmitTxPreconditions(fuzzWorld) {
			return
		}

		opcodes := shuffledFuzzOpcodes(data)
		cases := buildOpcodeFuzzCases(data, fuzzWorld)

		runFreshOpcodeCases(t, fuzzWorld.world, opcodes, cases)
		runChainedOpcodeCases(t, fuzzWorld.world, opcodes, cases)
		runSerializedOpcodeScriptCases(t, fuzzWorld.world, opcodes, cases)
	})
}

// runFreshOpcodeCases executes each opcode against a fresh VM so failures are
// easy to attribute to a single opcode/case pair.
func runFreshOpcodeCases(t *testing.T, world *opcodeWorld, opcodes []byte, cases [256]opcodeFuzzCase) {
	t.Helper()

	for i, opcode := range opcodes {
		spec := opcodeSpecs[opcode]
		if spec == nil {
			continue
		}

		vm, err := newOpcodeEngine(world, cases[opcode].txIdx)
		require.NoError(t, err)
		setEnginePacketsFromWorld(vm, world)

		// err is used in the chained case only
		_ = executeOpcodeCase(t, vm, spec, cases[opcode], "fresh", i)
	}
}

// runChainedOpcodeCases reuses one VM across many opcodes so fuzzing can expose
// state interaction bugs that do not appear when every opcode starts from a
// clean engine. The VM is reset after an error so later opcodes still get a run.
func runChainedOpcodeCases(t *testing.T, world *opcodeWorld, opcodes []byte, cases [256]opcodeFuzzCase) {
	t.Helper()

	currentTxIdx := 0
	vm, err := newOpcodeEngine(world, currentTxIdx)
	require.NoError(t, err)
	setEnginePacketsFromWorld(vm, world)

	for i, opcode := range opcodes {
		spec := opcodeSpecs[opcode]
		if spec == nil {
			continue
		}
		if cases[opcode].txIdx != currentTxIdx {
			currentTxIdx = cases[opcode].txIdx
			vm, err = newOpcodeEngine(world, currentTxIdx)
			require.NoError(t, err)
			setEnginePacketsFromWorld(vm, world)
		}

		err := executeOpcodeCase(t, vm, spec, cases[opcode], "chained", i)
		if err != nil {
			vm, err = newOpcodeEngine(world, currentTxIdx)
			require.NoError(t, err)
			setEnginePacketsFromWorld(vm, world)
		}
	}
}

// executeOpcodeCase applies the fuzz-generated stack setup, snapshots the VM,
// executes the opcode through engine semantics, and then reuses the opcode spec
// property checker as the oracle. The skipped-branch fast path exists because a
// real engine now treats most opcodes as no-ops while a false conditional branch
// is inactive.
func executeOpcodeCase(t *testing.T, vm *Engine, spec *opcodeSpec, c opcodeFuzzCase, phase string, index int) error {
	t.Helper()

	applyOpcodeFuzzCase(vm, c)
	branchExecuting := vm.isBranchExecuting()
	before := cloneEngineForExpectedResult(vm)
	err := invokeOpcodeWithData(spec.opcode, c.opcodeData, vm)
	if !branchExecuting && !isOpcodeConditional(spec.opcode) && err == nil {
		require.Equal(t, before.GetStack(), vm.GetStack())
		require.Equal(t, before.GetAltStack(), vm.GetAltStack())
		require.Equal(t, before.condStack, vm.condStack)
		return nil
	}

	ctx := opcodeCheckContext{
		before:     before,
		after:      vm,
		opcodeData: c.opcodeData,
		execErr:    err,
		opcode:     spec.opcode,
		opcodeName: opcodeArray[spec.opcode].name,
		phase:      phase,
		order:      index,
	}
	if isAssetOpcode(spec.opcode) {
		assetOpcodeFuzzChecker(t, ctx)
	} else {
		require.NotNil(t, spec.checkProperties)
		failedBefore := t.Failed()
		spec.checkProperties(t, ctx)
		if !failedBefore && t.Failed() {
			t.Logf(
				"fuzz opcode failure: opcode=%s (0x%02x) phase=%s order=%d stack_before=%d stack_after=%d alt_before=%d alt_after=%d opcode_data_len=%d exec_err=%v",
				ctx.opcodeName,
				ctx.opcode,
				ctx.phase,
				ctx.order,
				len(ctx.before.GetStack()),
				len(ctx.after.GetStack()),
				len(ctx.before.GetAltStack()),
				len(ctx.after.GetAltStack()),
				len(ctx.opcodeData),
				ctx.execErr,
			)
		}
	}

	return err
}

// runSerializedOpcodeScriptCases adds an integration-style fuzz pass that packs
// many opcode snippets into real scripts and executes them with Step(). Unlike
// the direct opcode passes above, this exercises tokenizer/dispatch behavior and
// script-level interactions. Errors are expected; the value is broader coverage
// and panic/invariant detection rather than per-script success.
func runSerializedOpcodeScriptCases(t *testing.T, world *opcodeWorld, opcodes []byte, cases [256]opcodeFuzzCase) {
	t.Helper()

	for _, script := range buildSerializedOpcodeScripts(opcodes, cases) {
		vm, err := NewEngine(script, &world.tx, 0, nil, nil, 0, world.prevFetcher)
		require.NoError(t, err)
		setEnginePacketsFromWorld(vm, world)

		for {
			done, err := vm.Step()
			if err != nil || done {
				break
			}
		}
	}
}

func isAssetOpcode(op byte) bool {
	return op >= OP_INSPECTNUMASSETGROUPS && op <= OP_INSPECTINASSETLOOKUP
}

func assetOpcodeFuzzChecker(t *testing.T, c opcodeCheckContext) {
	t.Helper()
	require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
	require.Equal(t, c.before.condStack, c.after.condStack)
	if c.execErr == nil {
		return
	}

	requireScriptErrorCodeIn(t, c.execErr,
		txscript.ErrInvalidStackOperation,
		txscript.ErrNumberTooBig,
		txscript.ErrMinimalData,
	)
}

func applyOpcodeFuzzCase(vm *Engine, c opcodeFuzzCase) {
	if c.condStack == nil {
		vm.condStack = nil
	} else {
		vm.condStack = append(vm.condStack[:0], c.condStack...)
	}
	for _, item := range c.altStackPushes {
		vm.astack.PushByteArray(cloneBytes(item))
	}
	for _, item := range c.stackPushes {
		vm.dstack.PushByteArray(cloneBytes(item))
	}
}

// buildSerializedOpcodeScripts concatenates many opcode snippets into scripts
// that stay under the standard max script size. Splitting large permutations
// into chunks keeps the serialized pass broad without making every input fail at
// construction time.
func buildSerializedOpcodeScripts(opcodes []byte, cases [256]opcodeFuzzCase) [][]byte {
	scripts := make([][]byte, 0, 1)
	current := make([]byte, 0, txscript.MaxScriptSize)

	for _, opcode := range opcodes {
		if opcodeSpecs[opcode] == nil {
			continue
		}

		snippet := serializeOpcodeFuzzSnippet(opcode, cases[opcode])
		if len(snippet) == 0 {
			continue
		}

		if len(current) > 0 && len(current)+len(snippet) > txscript.MaxScriptSize {
			scripts = append(scripts, current)
			current = make([]byte, 0, txscript.MaxScriptSize)
		}

		current = append(current, snippet...)
	}

	if len(current) > 0 {
		scripts = append(scripts, current)
	}

	return scripts
}

// serializeOpcodeFuzzSnippet turns one fuzz case into a small script fragment:
// a bounded number of setup pushes followed by the target opcode encoding. The
// bounds keep serialized scripts compact enough that many different opcodes can
// appear in a single Step()-driven pass.
func serializeOpcodeFuzzSnippet(opcode byte, c opcodeFuzzCase) []byte {
	buf := make([]byte, 0, 128)
	for i, item := range c.stackPushes {
		if i >= fuzzSerializedSetupPushLimit {
			break
		}
		if len(item) > fuzzSerializedSetupPushSize {
			item = item[:fuzzSerializedSetupPushSize]
		}
		buf = appendSerializedPush(buf, item)
	}
	return appendSerializedOpcode(buf, opcode, c.opcodeData)
}

func appendSerializedPush(dst []byte, data []byte) []byte {
	switch {
	case len(data) == 0:
		return append(dst, OP_0)
	case len(data) == 1 && data[0] >= 1 && data[0] <= 16:
		return append(dst, OP_1+data[0]-1)
	case len(data) == 1 && data[0] == 0x81:
		return append(dst, OP_1NEGATE)
	case len(data) <= 75:
		dst = append(dst, byte(len(data)))
		return append(dst, data...)
	case len(data) <= 255:
		dst = append(dst, OP_PUSHDATA1, byte(len(data)))
		return append(dst, data...)
	default:
		var lenBytes [2]byte
		binary.LittleEndian.PutUint16(lenBytes[:], uint16(len(data)))
		dst = append(dst, OP_PUSHDATA2)
		dst = append(dst, lenBytes[:]...)
		return append(dst, data...)
	}
}

func appendSerializedOpcode(dst []byte, opcode byte, data []byte) []byte {
	op := &opcodeArray[opcode]
	if data == nil && op.length > 1 {
		data = make([]byte, op.length-1)
	}

	if opcode >= OP_DATA_1 && opcode <= OP_DATA_75 {
		payload := data
		wantLen := int(opcode)
		if len(payload) > wantLen {
			payload = payload[:wantLen]
		} else if len(payload) < wantLen {
			payload = append(cloneBytes(payload), make([]byte, wantLen-len(payload))...)
		}
		dst = append(dst, opcode)
		return append(dst, payload...)
	}

	switch opcode {
	case OP_PUSHDATA1:
		dst = append(dst, opcode, byte(len(data)))
		return append(dst, data...)
	case OP_PUSHDATA2:
		var lenBytes [2]byte
		binary.LittleEndian.PutUint16(lenBytes[:], uint16(len(data)))
		dst = append(dst, opcode)
		dst = append(dst, lenBytes[:]...)
		return append(dst, data...)
	case OP_PUSHDATA4:
		var lenBytes [4]byte
		binary.LittleEndian.PutUint32(lenBytes[:], uint32(len(data)))
		dst = append(dst, opcode)
		dst = append(dst, lenBytes[:]...)
		return append(dst, data...)
	default:
		return append(dst, opcode)
	}
}

// validateSubmitTxPreconditions filters out worlds that fail for unrelated
// transaction/packet setup reasons before any opcode is exercised. That keeps
// the fuzz signal focused on opcode behavior instead of repeatedly rediscovering
// invalid arkade submission scaffolding.
func validateSubmitTxPreconditions(fuzzWorld *opcodeFuzzWorld) bool {
	if fuzzWorld == nil || fuzzWorld.world == nil {
		return false
	}
	if fuzzWorld.ptx == nil || fuzzWorld.signerPublicKey == nil {
		return false
	}
	if len(fuzzWorld.world.packet) == 0 {
		return false
	}

	for _, entry := range fuzzWorld.world.packet {
		script, err := ReadArkadeScript(fuzzWorld.ptx, fuzzWorld.signerPublicKey, entry)
		if err != nil {
			return false
		}

		vin := int(entry.Vin)
		if vin < 0 || vin >= len(fuzzWorld.world.tx.TxIn) {
			return false
		}

		inputAmount := int64(0)
		if fuzzWorld.world.prevFetcher != nil {
			prevOut := fuzzWorld.world.prevFetcher.FetchPrevOutput(fuzzWorld.world.tx.TxIn[vin].PreviousOutPoint)
			if prevOut != nil {
				inputAmount = prevOut.Value
			}
		}

		_, err = NewEngine(
			script.Script(),
			&fuzzWorld.world.tx,
			vin,
			nil,
			nil,
			inputAmount,
			fuzzWorld.world.prevFetcher,
		)
		if err != nil {
			return false
		}
	}

	return true
}

// buildOpcodeFuzzCases deterministically derives one case per opcode from the
// same top-level fuzz input by salting the bytes with the opcode value. This
// gives broad per-input coverage while keeping failures reproducible.
func buildOpcodeFuzzCases(data []byte, world *opcodeFuzzWorld) [256]opcodeFuzzCase {
	var cases [256]opcodeFuzzCase

	for opcode := range 256 {
		if opcodeSpecs[opcode] == nil {
			continue
		}

		opcodeVal := byte(opcode)
		builder := fuzzCaseBuilders[opcode]
		if builder == nil {
			if isPushDataOpcode(opcodeVal) {
				builder = pushDataCaseBuilder{opcode: opcodeVal}
			} else {
				builder = defaultCaseBuilder{}
			}
		}

		cases[opcode] = builder.Build(saltedBytes(data, opcodeVal), world)
	}

	return cases
}

// shuffledFuzzOpcodes permutes the opcode order deterministically for a given
// input so chained/script passes explore different interaction orders while
// still being reproducible when a crash or assertion fires.
func shuffledFuzzOpcodes(data []byte) []byte {
	opcodes := make([]byte, 0, 256)
	for i := range 256 {
		if opcodeSpecs[i] != nil {
			opcodes = append(opcodes, byte(i))
		}
	}

	seedBytes := saltedBytes(data, 0xfe)
	seed := int64(binary.LittleEndian.Uint64(seedBytes[:8]))
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(opcodes), func(i, j int) {
		opcodes[i], opcodes[j] = opcodes[j], opcodes[i]
	})

	return opcodes
}

func deriveIndex(indexSeed uint8, indexMode uint8, count int) int64 {
	switch indexMode % 4 {
	case 0:
		if count == 0 {
			return 0
		}
		return int64(indexSeed % uint8(count))
	case 1:
		return -1 - int64(indexSeed%32)
	case 2:
		return int64(count) + int64(indexSeed%32)
	default:
		return 1<<31 - int64(indexSeed)
	}
}

func isPushDataOpcode(opcode byte) bool {
	if opcode >= OP_DATA_1 && opcode <= OP_DATA_75 {
		return true
	}

	switch opcode {
	case OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4:
		return true
	default:
		return false
	}
}

func buildPushDataPayload(opcode byte, seed []byte) []byte {
	length := pushDataPayloadLength(opcode, seed)
	if length == 0 {
		return nil
	}

	payload := make([]byte, length)
	for i := range length {
		payload[i] = seed[(i+1)%len(seed)] ^ byte(i)
	}
	return payload
}

func pushDataPayloadLength(opcode byte, seed []byte) int {
	if opcode >= OP_DATA_1 && opcode <= OP_DATA_75 {
		return int(opcode)
	}

	switch opcode {
	case OP_PUSHDATA1:
		return int(seed[0] % 76)
	case OP_PUSHDATA2:
		return int(binary.LittleEndian.Uint16(seed[:2]) % 128)
	case OP_PUSHDATA4:
		return int(binary.LittleEndian.Uint32(seed[:4]) % 196)
	default:
		return 0
	}
}

func cloneEngineForExpectedResult(vm *Engine) *Engine {
	clone := *vm

	txCopy := vm.tx.Copy()
	if txCopy != nil {
		clone.tx = *txCopy
	}

	clone.scripts = clone2DBytes(vm.scripts)
	if vm.condStack == nil {
		clone.condStack = nil
	} else {
		clone.condStack = make([]int, len(vm.condStack))
		copy(clone.condStack, vm.condStack)
	}
	clone.witnessProgram = cloneBytes(vm.witnessProgram)
	clone.dstack = cloneStack(vm.dstack)
	clone.astack = cloneStack(vm.astack)
	clone.introspectorPacket = cloneIntrospectorPacket(vm.introspectorPacket)

	if vm.taprootCtx != nil {
		taprootCtx := *vm.taprootCtx
		taprootCtx.annex = cloneBytes(vm.taprootCtx.annex)
		clone.taprootCtx = &taprootCtx
	}

	return &clone
}

func cloneStack(s stack) stack {
	clone := s
	clone.stk = clone2DBytes(s.stk)
	return clone
}

func cloneIntrospectorPacket(packet IntrospectorPacket) IntrospectorPacket {
	if packet == nil {
		return nil
	}

	clone := make(IntrospectorPacket, len(packet))
	for i, entry := range packet {
		clone[i] = IntrospectorEntry{
			Vin:     entry.Vin,
			Script:  cloneBytes(entry.Script),
			Witness: cloneWitness(entry.Witness),
		}
	}

	return clone
}
