// Package arkade implements a custom Bitcoin Script virtual machine forked from
// btcd/txscript (github.com/btcsuite/btcd v0.24.3).
//
// Key differences from the upstream btcd/txscript engine:
//   - Only taproot/tapscript execution is supported (segwit v0 and legacy are rejected).
//   - All opcodes that btcd disables (OP_CAT, OP_SUBSTR, etc.) are re-enabled for arkade script use.
//   - Custom introspection opcodes are added for transaction input/output inspection,
//     SHA256 streaming, elliptic curve operations, and asset introspection.
//
// When updating btcd dependencies, review upstream txscript changes for security
// patches that may need to be backported to this fork.
package arkade

import (
	"fmt"
	"math"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	// payToTaprootDataSize is the size of the witness program push for
	// taproot spends. This will be the serialized x-coordinate of the
	// top-level taproot output public key.
	payToTaprootDataSize = 32
)

const (
	// blankCodeSepValue is the value of the code separator position in the
	// tapscript sighash when no code separator was found in the script.
	blankCodeSepValue = math.MaxUint32
)

// taprootExecutionCtx houses the special context-specific information we need
// to validate a taproot script spend. This includes the annex, the running sig
// op count tally, and other relevant information.
type taprootExecutionCtx struct {
	annex []byte

	codeSepPos uint32

	tapLeaf     txscript.TapLeaf
	tapLeafHash chainhash.Hash

	sigOpsBudget int32

	mustSucceed bool
}

// sigOpsDelta is both the starting budget for sig ops for tapscript
// verification, as well as the decrease in the total budget when we encounter
// a signature.
const sigOpsDelta = 50

// tallysigOp attempts to decrease the current sig ops budget by sigOpsDelta.
// An error is returned if after subtracting the delta, the budget is below
// zero.
func (t *taprootExecutionCtx) tallysigOp() error {
	t.sigOpsBudget -= sigOpsDelta

	if t.sigOpsBudget < 0 {
		return scriptError(txscript.ErrTaprootMaxSigOps, "")
	}

	return nil
}

// newTaprootExecutionCtx returns a fresh instance of the taproot execution
// context.
func newTaprootExecutionCtx(inputWitnessSize int32) *taprootExecutionCtx {
	return &taprootExecutionCtx{
		codeSepPos:   blankCodeSepValue,
		sigOpsBudget: sigOpsDelta + inputWitnessSize,
	}
}

// Engine is the virtual machine that executes scripts.
type Engine struct {
	// The following fields are set when the engine is created and must not be
	// changed afterwards.  The entries of the signature cache are mutated
	// during execution, however, the cache pointer itself is not changed.
	//
	// tx identifies the transaction that contains the input which in turn
	// contains the signature script being executed.
	//
	// txIdx identifies the input index within the transaction that contains
	// the signature script being executed.
	//
	// version specifies the version of the public key script to execute.
	// Always 0 in this taproot-only engine.
	//
	// sigCache caches the results of signature verifications.  This is useful
	// since transaction scripts are often executed more than once from various
	// contexts (e.g. new block templates, when transactions are first seen
	// prior to being mined, part of full block verification, etc).
	//
	// hashCache caches the midstate of segwit v1 sighashes to optimize
	// worst-case hashing complexity.
	//
	// prevOutFetcher is used to look up all the previous output of
	// taproot transactions, as that information is hashed into the
	// sighash digest for such inputs.
	tx                 wire.MsgTx
	txIdx              int
	version            uint16
	sigCache           *txscript.SigCache
	hashCache          *txscript.TxSigHashes
	prevOutFetcher     ArkPrevOutFetcher
	assetPacket        asset.Packet
	introspectorPacket IntrospectorPacket

	// The following fields handle keeping track of the current execution state
	// of the engine.
	//
	// scripts houses the raw scripts that are executed by the engine.  This
	// includes the signature script as well as the public key script.
	//
	// scriptIdx tracks the index into the scripts array for the current program
	// counter.
	//
	// opcodeIdx tracks the number of the opcode within the current script for
	// the current program counter.  Note that it differs from the actual byte
	// index into the script and is really only used for disassembly purposes.
	//
	// lastCodeSep specifies the position within the current script of the last
	// OP_CODESEPARATOR.
	//
	// tokenizer provides the token stream of the current script being executed
	// and doubles as state tracking for the program counter within the script.
	//
	// dstack is the primary data stack the various opcodes push and pop data
	// to and from during execution.
	//
	// astack is the alternate data stack the various opcodes push and pop data
	// to and from during execution.
	//
	// condStack tracks the conditional execution state with support for
	// multiple nested conditional execution opcodes.
	scripts        [][]byte
	scriptIdx      int
	opcodeIdx      int
	lastCodeSep    int
	tokenizer      ScriptTokenizer
	dstack         stack
	astack         stack
	condStack      []int
	witnessVersion int
	witnessProgram []byte
	inputAmount    int64
	taprootCtx     *taprootExecutionCtx

	// stepCallback is an optional function that will be called every time
	// a step has been performed during script execution.
	//
	// NOTE: This is only meant to be used in debugging, and SHOULD NOT BE
	// USED during regular operation.
	stepCallback func(*StepInfo) error
}

// StepInfo houses the current VM state information that is passed back to the
// stepCallback during script execution.
type StepInfo struct {
	// ScriptIndex is the index of the script currently being executed by
	// the Engine.
	ScriptIndex int

	// OpcodeIndex is the index of the next opcode that will be executed.
	// In case the execution has completed, the opcode index will be
	// incremented beyond the number of the current script's opcodes. This
	// indicates no new script is being executed, and execution is done.
	OpcodeIndex int

	// Stack is the Engine's current content on the stack:
	Stack [][]byte

	// AltStack is the Engine's current content on the alt stack.
	AltStack [][]byte
}

// SetAssetPacket sets the asset packet on the engine for script introspection.
func (vm *Engine) SetAssetPacket(packet asset.Packet) {
	vm.assetPacket = packet
}

// SetIntrospectorPacket sets the introspector packet on the engine for
// cross-input Arkade script/witness introspection.
func (vm *Engine) SetIntrospectorPacket(packet IntrospectorPacket) {
	vm.introspectorPacket = packet
}

// isBranchExecuting returns whether or not the current conditional branch is
// actively executing.  For example, when the data stack has an OP_FALSE on it
// and an OP_IF is encountered, the branch is inactive until an OP_ELSE or
// OP_ENDIF is encountered.  It properly handles nested conditionals.
func (vm *Engine) isBranchExecuting() bool {
	if len(vm.condStack) == 0 {
		return true
	}
	return vm.condStack[len(vm.condStack)-1] == txscript.OpCondTrue
}

// isOpcodeAlwaysIllegal returns whether or not the opcode is always illegal
// when passed over by the program counter even if in a non-executed branch (it
// isn't a coincidence that they are conditionals).
func isOpcodeAlwaysIllegal(opcode byte) bool {
	switch opcode {
	case OP_VERIF:
		return true
	case OP_VERNOTIF:
		return true
	default:
		return false
	}
}

// isOpcodeConditional returns whether or not the opcode is a conditional opcode
// which changes the conditional execution stack when executed.
func isOpcodeConditional(opcode byte) bool {
	switch opcode {
	case OP_IF:
		return true
	case OP_NOTIF:
		return true
	case OP_ELSE:
		return true
	case OP_ENDIF:
		return true
	default:
		return false
	}
}

// checkMinimalDataPush returns whether or not the provided opcode is the
// smallest possible way to represent the given data.  For example, the value 15
// could be pushed with OP_DATA_1 15 (among other variations); however, OP_15 is
// a single opcode that represents the same value and is only a single byte
// versus two bytes.
func checkMinimalDataPush(op *opcode, data []byte) error {
	opcodeVal := op.value
	dataLen := len(data)
	switch {
	case dataLen == 0 && opcodeVal != OP_0:
		str := fmt.Sprintf("zero length data push is encoded with opcode %s "+
			"instead of OP_0", op.name)
		return scriptError(txscript.ErrMinimalData, str)
	case dataLen == 1 && data[0] >= 1 && data[0] <= 16:
		if opcodeVal != OP_1+data[0]-1 {
			// Should have used OP_1 .. OP_16
			str := fmt.Sprintf("data push of the value %d encoded with opcode "+
				"%s instead of OP_%d", data[0], op.name, data[0])
			return scriptError(txscript.ErrMinimalData, str)
		}
	case dataLen == 1 && data[0] == 0x81:
		if opcodeVal != OP_1NEGATE {
			str := fmt.Sprintf("data push of the value -1 encoded with opcode "+
				"%s instead of OP_1NEGATE", op.name)
			return scriptError(txscript.ErrMinimalData, str)
		}
	case dataLen <= 75:
		if int(opcodeVal) != dataLen {
			// Should have used a direct push
			str := fmt.Sprintf("data push of %d bytes encoded with opcode %s "+
				"instead of OP_DATA_%d", dataLen, op.name, dataLen)
			return scriptError(txscript.ErrMinimalData, str)
		}
	case dataLen <= 255:
		if opcodeVal != OP_PUSHDATA1 {
			str := fmt.Sprintf("data push of %d bytes encoded with opcode %s "+
				"instead of OP_PUSHDATA1", dataLen, op.name)
			return scriptError(txscript.ErrMinimalData, str)
		}
	case dataLen <= 65535:
		if opcodeVal != OP_PUSHDATA2 {
			str := fmt.Sprintf("data push of %d bytes encoded with opcode %s "+
				"instead of OP_PUSHDATA2", dataLen, op.name)
			return scriptError(txscript.ErrMinimalData, str)
		}
	}
	return nil
}

// executeOpcode performs execution on the passed opcode.  It takes into account
// whether or not it is hidden by conditionals, but some rules still must be
// tested in this case.
func (vm *Engine) executeOpcode(op *opcode, data []byte) error {
	if isOpcodeAlwaysIllegal(op.value) {
		str := fmt.Sprintf("attempt to execute reserved opcode %s", op.name)
		return scriptError(txscript.ErrReservedOpcode, str)
	}

	// In taproot, we enforce element size limits instead of op count limits.
	if len(data) > txscript.MaxScriptElementSize {
		str := fmt.Sprintf("element size %d exceeds max allowed size %d",
			len(data), txscript.MaxScriptElementSize)
		return scriptError(txscript.ErrElementTooBig, str)
	}

	// Nothing left to do when this is not a conditional opcode and it is
	// not in an executing branch.
	if !vm.isBranchExecuting() && !isOpcodeConditional(op.value) {
		return nil
	}

	// Ensure all executed data push opcodes use the minimal encoding when
	// the minimal data verification flag is set.
	if vm.dstack.verifyMinimalData && vm.isBranchExecuting() && op.value <= OP_PUSHDATA4 {
		if err := checkMinimalDataPush(op, data); err != nil {
			return err
		}
	}

	return op.opfunc(op, data, vm)
}

// checkValidPC returns an error if the current script position is not valid for
// execution.
func (vm *Engine) checkValidPC() error {
	if vm.scriptIdx >= len(vm.scripts) {
		str := fmt.Sprintf("script index %d beyond total scripts %d",
			vm.scriptIdx, len(vm.scripts))
		return scriptError(txscript.ErrInvalidProgramCounter, str)
	}
	return nil
}

// isWitnessVersionActive returns true if a witness program was extracted
// during the initialization of the Engine, and the program's version matches
// the specified version.
func (vm *Engine) isWitnessVersionActive(version uint) bool {
	return vm.witnessProgram != nil && uint(vm.witnessVersion) == version
}

// verifyWitnessProgram validates the stored witness program using the passed
// witness as input.
func (vm *Engine) verifyWitnessProgram(witness wire.TxWitness) error {
	if !vm.isWitnessVersionActive(txscript.TaprootWitnessVersion) ||
		len(vm.witnessProgram) != payToTaprootDataSize {
		return fmt.Errorf("arkscript engine only supports taproot")
	}

	// If there're no stack elements at all, then this is an
	// invalid spend.
	if len(witness) == 0 {
		return scriptError(txscript.ErrWitnessProgramEmpty, "witness "+
			"program empty passed empty witness")
	}

	// At this point, we know taproot is active, so we'll populate
	// the taproot execution context.
	vm.taprootCtx = newTaprootExecutionCtx(
		int32(witness.SerializeSize()),
	)

	// If we can detect the annex, then drop that off the stack,
	// we'll only need it to compute the sighash later.
	if isAnnexedWitness(witness) {
		vm.taprootCtx.annex, _ = extractAnnex(witness)

		// Snip the annex off the end of the witness stack.
		witness = witness[:len(witness)-1]
	}

	// From here, we'll either be validating a normal key spend, or
	// a spend from the tap script leaf using a committed leaf.
	switch {
	// If there's only a single element left on the stack (the
	// signature), then we'll apply the normal top-level schnorr
	// signature verification.
	case len(witness) == 1:
		// As we only have a single element left (after maybe
		// removing the annex), we'll do normal taproot
		// keyspend validation.
		rawSig := witness[0]
		err := txscript.VerifyTaprootKeySpend(
			vm.witnessProgram, rawSig, &vm.tx, vm.txIdx,
			vm.prevOutFetcher, vm.hashCache, vm.sigCache,
		)
		if err != nil {
			return err
		}

		vm.taprootCtx.mustSucceed = true
		return nil

	// Otherwise, we need to attempt full tapscript leaf
	// verification in place.
	default:
		// First, attempt to parse the control block, if this
		// isn't formatted properly, then we'll end execution
		// right here.
		controlBlock, err := txscript.ParseControlBlock(
			witness[len(witness)-1],
		)
		if err != nil {
			return err
		}

		// Now that we know the control block is valid, we'll
		// verify the top-level taproot commitment, which
		// proves that the specified script was committed to in
		// the merkle tree.
		witnessScript := witness[len(witness)-2]
		err = txscript.VerifyTaprootLeafCommitment(
			controlBlock, vm.witnessProgram, witnessScript,
		)
		if err != nil {
			return err
		}

		// Before we proceed with normal execution, check the
		// leaf version of the script, as if the policy flag is
		// active, then we should only allow the base leaf
		// version.
		if controlBlock.LeafVersion != txscript.BaseLeafVersion {
			errStr := fmt.Sprintf("tapscript is attempting "+
				"to use version: %v", controlBlock.LeafVersion)
			return scriptError(
				txscript.ErrDiscourageUpgradeableTaprootVersion, errStr,
			)
		}

		// Now that we know we don't have any op success
		// fields, ensure that the script parses properly.
		err = checkScriptParses(vm.version, witnessScript)
		if err != nil {
			return err
		}

		// Now that we know the script parses, and we have a
		// valid leaf version, we'll save the tap leaf (and its
		// hash) as we need both for signature validation later.
		vm.taprootCtx.tapLeaf = txscript.NewBaseTapLeaf(witnessScript)
		vm.taprootCtx.tapLeafHash = vm.taprootCtx.tapLeaf.TapHash()

		// Otherwise, we'll now "recurse" one level deeper, and
		// set the remaining witness (leaving off the annex and
		// the witness script) as the execution stack, and
		// enter further execution.
		vm.scripts = append(vm.scripts, witnessScript)
		vm.SetStack(witness[:len(witness)-2])
	}

	// In addition to the normal script element size limits, taproot also
	// enforces a limit on the max _starting_ stack size.
	if vm.dstack.Depth() > txscript.MaxStackSize {
		str := fmt.Sprintf("tapscript stack size %d > max allowed %d",
			vm.dstack.Depth(), txscript.MaxStackSize)
		return scriptError(txscript.ErrStackOverflow, str)
	}

	// All elements within the witness stack must not be greater
	// than the maximum bytes which are allowed to be pushed onto
	// the stack.
	for _, witElement := range vm.GetStack() {
		if len(witElement) > txscript.MaxScriptElementSize {
			str := fmt.Sprintf("element size %d exceeds "+
				"max allowed size %d", len(witElement),
				txscript.MaxScriptElementSize)
			return scriptError(txscript.ErrElementTooBig, str)
		}
	}

	return nil
}

// DisasmPC returns the string for the disassembly of the opcode that will be
// next to execute when Step is called.
func (vm *Engine) DisasmPC() (string, error) {
	if err := vm.checkValidPC(); err != nil {
		return "", err
	}

	// Create a copy of the current tokenizer and parse the next opcode in the
	// copy to avoid mutating the current one.
	peekTokenizer := vm.tokenizer
	if !peekTokenizer.Next() {
		// Note that due to the fact that all scripts are checked for parse
		// failures before this code ever runs, there should never be an error
		// here, but check again to be safe in case a refactor breaks that
		// assumption or new script versions are introduced with different
		// semantics.
		if err := peekTokenizer.Err(); err != nil {
			return "", err
		}

		// Note that this should be impossible to hit in practice because the
		// only way it could happen would be for the final opcode of a script to
		// already be parsed without the script index having been updated, which
		// is not the case since stepping the script always increments the
		// script index when parsing and executing the final opcode of a script.
		//
		// However, check again to be safe in case a refactor breaks that
		// assumption or new script versions are introduced with different
		// semantics.
		str := fmt.Sprintf("program counter beyond script index %d (bytes %x)",
			vm.scriptIdx, vm.scripts[vm.scriptIdx])
		return "", scriptError(txscript.ErrInvalidProgramCounter, str)
	}

	var buf strings.Builder
	disasmOpcode(&buf, peekTokenizer.op, peekTokenizer.Data(), false)
	return fmt.Sprintf("%02x:%04x: %s", vm.scriptIdx, vm.opcodeIdx,
		buf.String()), nil
}

// DisasmScript returns the disassembly string for the script at the requested
// offset index.  Index 0 is the signature script and 1 is the public key
// script.
func (vm *Engine) DisasmScript(idx int) (string, error) {
	if idx >= len(vm.scripts) {
		str := fmt.Sprintf("script index %d >= total scripts %d", idx,
			len(vm.scripts))
		return "", scriptError(txscript.ErrInvalidIndex, str)
	}

	var disbuf strings.Builder
	script := vm.scripts[idx]
	tokenizer := MakeScriptTokenizer(vm.version, script)
	var opcodeIdx int
	for tokenizer.Next() {
		disbuf.WriteString(fmt.Sprintf("%02x:%04x: ", idx, opcodeIdx))
		disasmOpcode(&disbuf, tokenizer.op, tokenizer.Data(), false)
		disbuf.WriteByte('\n')
		opcodeIdx++
	}
	return disbuf.String(), tokenizer.Err()
}

// CheckErrorCondition returns nil if the running script has ended and was
// successful, leaving a a true boolean on the stack.  An error otherwise,
// including if the script has not finished.
func (vm *Engine) CheckErrorCondition(finalScript bool) error {
	if vm.taprootCtx != nil && vm.taprootCtx.mustSucceed {
		return nil
	}

	// Check execution is actually done by ensuring the script index is after
	// the final script in the array script.
	if vm.scriptIdx < len(vm.scripts) {
		return scriptError(txscript.ErrScriptUnfinished,
			"error check when script unfinished")
	}

	// The final script must end with exactly one data stack item (taproot
	// always requires a clean stack).
	if finalScript && vm.dstack.Depth() != 1 {
		str := fmt.Sprintf("stack must contain exactly one item (contains %d)",
			vm.dstack.Depth())
		return scriptError(txscript.ErrCleanStack, str)
	} else if vm.dstack.Depth() < 1 {
		return scriptError(txscript.ErrEmptyStack,
			"stack empty at end of script execution")
	}

	v, err := vm.dstack.PopBool()
	if err != nil {
		return err
	}
	if !v {
		return scriptError(txscript.ErrEvalFalse,
			"false stack entry at end of script execution")
	}
	return nil
}

// Step executes the next instruction and moves the program counter to the next
// opcode in the script, or the next script if the current has ended.  Step will
// return true in the case that the last opcode was successfully executed.
//
// The result of calling Step or any other method is undefined if an error is
// returned.
func (vm *Engine) Step() (done bool, err error) {
	// Verify the engine is pointing to a valid program counter.
	if err := vm.checkValidPC(); err != nil {
		return true, err
	}

	// Attempt to parse the next opcode from the current script.
	if !vm.tokenizer.Next() {
		// Note that due to the fact that all scripts are checked for parse
		// failures before this code ever runs, there should never be an error
		// here, but check again to be safe in case a refactor breaks that
		// assumption or new script versions are introduced with different
		// semantics.
		if err := vm.tokenizer.Err(); err != nil {
			return false, err
		}

		str := fmt.Sprintf("attempt to step beyond script index %d (bytes %x)",
			vm.scriptIdx, vm.scripts[vm.scriptIdx])
		return true, scriptError(txscript.ErrInvalidProgramCounter, str)
	}

	// Execute the opcode while taking into account several things such as
	// disabled opcodes, illegal opcodes, maximum allowed operations per script,
	// maximum script element sizes, and conditionals.
	err = vm.executeOpcode(vm.tokenizer.op, vm.tokenizer.Data())
	if err != nil {
		return true, err
	}

	// The number of elements in the combination of the data and alt stacks
	// must not exceed the maximum number of stack elements allowed.
	combinedStackSize := vm.dstack.Depth() + vm.astack.Depth()
	if combinedStackSize > txscript.MaxStackSize {
		str := fmt.Sprintf("combined stack size %d > max allowed %d",
			combinedStackSize, txscript.MaxStackSize)
		return false, scriptError(txscript.ErrStackOverflow, str)
	}

	// Prepare for next instruction.
	vm.opcodeIdx++
	if vm.tokenizer.Done() {
		// Illegal to have a conditional that straddles two scripts.
		if len(vm.condStack) != 0 {
			return false, scriptError(txscript.ErrUnbalancedConditional,
				"end of script reached in conditional execution")
		}

		// Alt stack doesn't persist between scripts.
		_ = vm.astack.DropN(vm.astack.Depth())

		// Reset the opcode index for the next script.
		vm.opcodeIdx = 0

		// Advance to the next script as needed.
		switch {
		case vm.scriptIdx == 1 && vm.witnessProgram != nil:
			vm.scriptIdx++

			witness := vm.tx.TxIn[vm.txIdx].Witness
			if err := vm.verifyWitnessProgram(witness); err != nil {
				return false, err
			}

		default:
			vm.scriptIdx++
		}

		// Skip empty scripts.
		if vm.scriptIdx < len(vm.scripts) && len(vm.scripts[vm.scriptIdx]) == 0 {
			vm.scriptIdx++
		}

		vm.lastCodeSep = 0
		if vm.scriptIdx >= len(vm.scripts) {
			return true, nil
		}

		// Finally, update the current tokenizer used to parse through scripts
		// one opcode at a time to start from the beginning of the new script
		// associated with the program counter.
		vm.tokenizer = MakeScriptTokenizer(vm.version, vm.scripts[vm.scriptIdx])
	}

	return false, nil
}

// copyStack makes a deep copy of the provided slice.
func copyStack(stk [][]byte) [][]byte {
	c := make([][]byte, len(stk))
	for i := range stk {
		c[i] = make([]byte, len(stk[i]))
		copy(c[i][:], stk[i][:])
	}

	return c
}

// Execute will execute all scripts in the script engine and return either nil
// for successful validation or an error if one occurred.
func (vm *Engine) Execute() (err error) {
	// All script versions other than 0 currently execute without issue,
	// making all outputs to them anyone can pay. The version field is always
	// 0 in this taproot-only engine, but this check is retained from upstream
	// btcd as a safety net.
	if vm.version != 0 {
		return nil
	}

	// If the stepCallback is set, we start by making a call back with the
	// initial engine state.
	var stepInfo *StepInfo
	if vm.stepCallback != nil {
		stepInfo = &StepInfo{
			ScriptIndex: vm.scriptIdx,
			OpcodeIndex: vm.opcodeIdx,
			Stack:       copyStack(vm.dstack.stk),
			AltStack:    copyStack(vm.astack.stk),
		}
		err := vm.stepCallback(stepInfo)
		if err != nil {
			return err
		}
	}

	done := false
	for !done {
		done, err = vm.Step()
		if err != nil {
			return err
		}

		if vm.stepCallback != nil {
			scriptIdx := vm.scriptIdx
			opcodeIdx := vm.opcodeIdx

			// In case the execution has completed, we keep the
			// current script index while increasing the opcode
			// index. This is to indicate that no new script is
			// being executed.
			if done {
				scriptIdx = stepInfo.ScriptIndex
				opcodeIdx = stepInfo.OpcodeIndex + 1
			}

			stepInfo = &StepInfo{
				ScriptIndex: scriptIdx,
				OpcodeIndex: opcodeIdx,
				Stack:       copyStack(vm.dstack.stk),
				AltStack:    copyStack(vm.astack.stk),
			}
			err := vm.stepCallback(stepInfo)
			if err != nil {
				return err
			}
		}
	}

	return vm.CheckErrorCondition(true)
}

// getStack returns the contents of stack as a byte array bottom up
func getStack(stack *stack) [][]byte {
	array := make([][]byte, stack.Depth())
	for i := range array {
		// PeekByteArray can't fail due to overflow, already checked
		array[len(array)-i-1], _ = stack.PeekByteArray(int32(i))
	}
	return array
}

// setStack sets the stack to the contents of the array where the last item in
// the array is the top item in the stack.
func setStack(stack *stack, data [][]byte) {
	// This can not error. Only errors are for invalid arguments.
	_ = stack.DropN(stack.Depth())

	for i := range data {
		stack.PushByteArray(data[i])
	}
}

// GetStack returns the contents of the primary stack as an array. where the
// last item in the array is the top of the stack.
func (vm *Engine) GetStack() [][]byte {
	return getStack(&vm.dstack)
}

// SetStack sets the contents of the primary stack to the contents of the
// provided array where the last item in the array will be the top of the stack.
func (vm *Engine) SetStack(data [][]byte) {
	setStack(&vm.dstack, data)
}

// GetAltStack returns the contents of the alternate stack as an array where the
// last item in the array is the top of the stack.
func (vm *Engine) GetAltStack() [][]byte {
	return getStack(&vm.astack)
}

// SetAltStack sets the contents of the alternate stack to the contents of the
// provided array where the last item in the array will be the top of the stack.
func (vm *Engine) SetAltStack(data [][]byte) {
	setStack(&vm.astack, data)
}

// NewEngine returns a new script engine for the provided public key script,
// transaction, and input index. The engine only supports taproot/tapscript
// execution.
func NewEngine(scriptPubKey []byte, tx *wire.MsgTx, txIdx int,
	sigCache *txscript.SigCache, hashCache *txscript.TxSigHashes, inputAmount int64,
	prevOutFetcher ArkPrevOutFetcher) (*Engine, error) {

	const scriptVersion = 0

	// The provided transaction input index must refer to a valid input.
	if txIdx < 0 || txIdx >= len(tx.TxIn) {
		str := fmt.Sprintf("transaction input index %d is negative or "+
			">= %d", txIdx, len(tx.TxIn))
		return nil, scriptError(txscript.ErrInvalidIndex, str)
	}
	scriptSig := tx.TxIn[txIdx].SignatureScript

	// When both the signature script and public key script are empty the result
	// is necessarily an error since the stack would end up being empty which is
	// equivalent to a false top element.  Thus, just return the relevant error
	// now as an optimization.
	if len(scriptSig) == 0 && len(scriptPubKey) == 0 {
		return nil, scriptError(txscript.ErrEvalFalse,
			"false stack entry at end of script execution")
	}

	vm := Engine{
		sigCache:       sigCache,
		hashCache:      hashCache,
		inputAmount:    inputAmount,
		prevOutFetcher: prevOutFetcher,
	}

	// The signature script must only contain data pushes.
	if !txscript.IsPushOnlyScript(scriptSig) {
		return nil, scriptError(txscript.ErrNotPushOnly,
			"signature script is not push only")
	}

	// The engine stores the scripts using a slice.  This allows multiple
	// scripts to be executed in sequence.
	scripts := [][]byte{scriptSig, scriptPubKey}
	for _, scr := range scripts {
		if len(scr) > txscript.MaxScriptSize {
			str := fmt.Sprintf("script size %d is larger than max allowed "+
				"size %d", len(scr), txscript.MaxScriptSize)
			return nil, scriptError(txscript.ErrScriptTooBig, str)
		}

		if err := checkScriptParses(scriptVersion, scr); err != nil {
			return nil, err
		}
	}
	vm.scripts = scripts

	// Advance the program counter to the public key script if the signature
	// script is empty since there is nothing to execute for it in that case.
	if len(scriptSig) == 0 {
		vm.scriptIdx++
	}

	vm.dstack.verifyMinimalData = true
	vm.astack.verifyMinimalData = true

	// Extract the witness program from the public key script.
	if txscript.IsWitnessProgram(vm.scripts[1]) {
		// The scriptSig must be *empty* for all native witness
		// programs, otherwise we introduce malleability.
		if len(scriptSig) != 0 {
			errStr := "native witness program cannot " +
				"also have a signature script"
			return nil, scriptError(txscript.ErrWitnessMalleated, errStr)
		}

		var err error
		vm.witnessVersion, vm.witnessProgram, err = txscript.ExtractWitnessProgramInfo(
			scriptPubKey,
		)
		if err != nil {
			return nil, err
		}
	} else {
		// If we didn't find a witness program, then there MUST NOT
		// be any witness data associated with the input being validated.
		if len(tx.TxIn[txIdx].Witness) != 0 {
			errStr := "non-witness inputs cannot have a witness"
			return nil, scriptError(txscript.ErrWitnessUnexpected, errStr)
		}
	}

	// Setup the current tokenizer used to parse through the script one opcode
	// at a time with the script associated with the program counter.
	vm.tokenizer = MakeScriptTokenizer(scriptVersion, scripts[vm.scriptIdx])

	vm.tx = *tx
	vm.txIdx = txIdx

	return &vm, nil
}

// NewDebugEngine returns a new script engine with a script execution callback set.
// This is useful for debugging script execution.
func NewDebugEngine(scriptPubKey []byte, tx *wire.MsgTx, txIdx int,
	sigCache *txscript.SigCache, hashCache *txscript.TxSigHashes,
	inputAmount int64, prevOutFetcher ArkPrevOutFetcher,
	stepCallback func(*StepInfo) error) (*Engine, error) {

	vm, err := NewEngine(
		scriptPubKey, tx, txIdx, sigCache, hashCache,
		inputAmount, prevOutFetcher,
	)
	if err != nil {
		return nil, err
	}

	vm.stepCallback = stepCallback
	return vm, nil
}

// checkScriptParses returns an error if the provided script fails to parse.
func checkScriptParses(scriptVersion uint16, script []byte) error {
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		// Nothing to do.
	}
	return tokenizer.Err()
}

// isAnnexedWitness returns true if the passed witness has a final push
// that is a witness annex.
func isAnnexedWitness(witness wire.TxWitness) bool {
	if len(witness) < 2 {
		return false
	}

	lastElement := witness[len(witness)-1]
	return len(lastElement) > 0 && lastElement[0] == txscript.TaprootAnnexTag
}

// extractAnnex attempts to extract the annex from the passed witness. If the
// witness doesn't contain an annex, then an error is returned.
func extractAnnex(witness [][]byte) ([]byte, error) {
	if !isAnnexedWitness(witness) {
		return nil, scriptError(txscript.ErrWitnessHasNoAnnex, "")
	}

	lastElement := witness[len(witness)-1]
	return lastElement, nil
}
