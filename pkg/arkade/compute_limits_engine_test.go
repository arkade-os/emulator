package arkade

import (
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func TestChargeOpcodeEnforcesLimit(t *testing.T) {
	vm := limitOnlyOp1(t, 2)

	require.NoError(t, invokeOpcodeWithData(OP_1, nil, vm))
	require.NoError(t, invokeOpcodeWithData(OP_1, nil, vm))
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_1, nil, vm),
		txscript.ErrScriptTooBig)
}

func TestChargeOpcodeIgnoresDeadBranch(t *testing.T) {
	vm := limitOnlyOp1(t, 1)

	// Inside a non-executed conditional branch, executions must not count.
	vm.condStack = []int{OpCondFalse}
	for range 5 {
		require.NoError(t, invokeOpcodeWithData(OP_1, nil, vm))
	}

	// Back in an executing branch the full budget is still available: one
	// charge succeeds, the next exhausts it — proving the dead-branch
	// executions consumed nothing.
	vm.condStack = nil
	require.NoError(t, invokeOpcodeWithData(OP_1, nil, vm))
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_1, nil, vm),
		txscript.ErrScriptTooBig)
}

func TestChargeOpcodeUnlistedIsUnlimited(t *testing.T) {
	// OP_1 has no limit here, so it is never charged.
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = &taprootExecutionCtx{}
	vm.limits = ComputeLimits{OP_ECADD: 0}

	for range 100 {
		require.NoError(t, invokeOpcodeWithData(OP_1, nil, vm))
	}
}

// TestComputeLimitPairingTripsBeforePerCallCap is the acceptance-criterion
// test: a script that repeats OP_ECPAIRING with each call well within the
// per-call pair cap (maxECPairingCount) still fails once OP_ECPAIRING's
// execution limit is exhausted, under the default limits.
func TestComputeLimitPairingTripsBeforePerCallCap(t *testing.T) {
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	)

	// Default OP_ECPAIRING limit is 2. Each call uses a single pair — far below
	// the 16-pair per-call cap — so only the execution limit can stop it.
	for range 2 {
		vm.SetStack(pairingFalseVectors())
		require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
	}
	vm.SetStack(pairingFalseVectors())
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm),
		txscript.ErrScriptTooBig)
}

// TestComputeLimitSigCountsEveryExecution locks in the post-sigops behavior:
// CHECKSIG is counted on every execution, including empty-signature calls that
// BIP-342 used to exempt.
func TestComputeLimitSigCountsEveryExecution(t *testing.T) {
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	)

	// An empty signature short-circuits before any verification; a non-empty
	// pubkey is all opcodeCheckSig requires to reach that path.
	pubkey := make([]byte, 32)
	pushSig := func() { vm.SetStack([][]byte{{}, pubkey}) }

	// Default OP_CHECKSIG limit is 50.
	for range 50 {
		pushSig()
		require.NoError(t, invokeOpcodeWithData(OP_CHECKSIG, nil, vm))
	}
	pushSig()
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_CHECKSIG, nil, vm),
		txscript.ErrScriptTooBig)
}

// TestWithComputeLimitsOverridesDefault verifies the override applies even
// though it runs after the taproot context was created (as it does in
// ArkadeScript.Execute).
func TestWithComputeLimitsOverridesDefault(t *testing.T) {
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	)

	// OP_1 is unlimited by default; the override caps it at 1.
	WithComputeLimits(ComputeLimits{OP_1: 1})(vm)

	require.NoError(t, invokeOpcodeWithData(OP_1, nil, vm))
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_1, nil, vm),
		txscript.ErrScriptTooBig)
}

func TestWithComputeLimitsMergesWithDefaults(t *testing.T) {
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	)

	WithComputeLimits(ComputeLimits{OP_ECPAIRING: 8})(vm)

	pubkey := make([]byte, 32)
	pushSig := func() { vm.SetStack([][]byte{{}, pubkey}) }
	for range 50 {
		pushSig()
		require.NoError(t, invokeOpcodeWithData(OP_CHECKSIG, nil, vm))
	}
	pushSig()
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_CHECKSIG, nil, vm),
		txscript.ErrScriptTooBig)
}

func TestWithExactComputeLimitsCanRemoveDefaultLimit(t *testing.T) {
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	)
	limits := DefaultComputeLimits()
	delete(limits, OP_CHECKSIG)

	WithExactComputeLimits(limits)(vm)

	pubkey := make([]byte, 32)
	for range 100 {
		vm.SetStack([][]byte{{}, pubkey})
		require.NoError(t, invokeOpcodeWithData(OP_CHECKSIG, nil, vm))
	}
}

func TestWithComputeLimitsNilKeepsDefaultLimits(t *testing.T) {
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	)

	WithComputeLimits(nil)(vm)

	pubkey := make([]byte, 32)
	pushSig := func() { vm.SetStack([][]byte{{}, pubkey}) }
	for range 50 {
		pushSig()
		require.NoError(t, invokeOpcodeWithData(OP_CHECKSIG, nil, vm))
	}
	pushSig()
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_CHECKSIG, nil, vm),
		txscript.ErrScriptTooBig)
}

func TestNewEngineDefaultLimitsAreIndependent(t *testing.T) {
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.limits[OP_1] = 0

	next, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	next.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	)

	require.NoError(t, invokeOpcodeWithData(OP_1, nil, next))
}

func TestChargeOpcodeNoTaprootContextIsUnlimited(t *testing.T) {
	// With no tapscript context there is no per-input budget, even for an
	// opcode that would otherwise be limited to zero executions.
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = nil
	vm.limits = ComputeLimits{OP_1: 0}

	require.NoError(t, invokeOpcodeWithData(OP_1, nil, vm))
}

// limitOnlyOp1 builds an engine whose only compute limit is OP_1, with a
// tapscript execution context active so charges take effect.
func limitOnlyOp1(t *testing.T, limit int) *Engine {
	t.Helper()
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = &taprootExecutionCtx{}
	vm.limits = ComputeLimits{OP_1: limit}
	return vm
}
