package arkade

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

// A four-term product has the same shape as a Groth16 pairing equation, but
// these cancelling generator vectors test the VM interface, not a SNARK circuit.
func fourTermPairingStack(t *testing.T) [][]byte {
	t.Helper()
	pair := pairingTrueVectors(t)
	var stack [][]byte
	stack = append(stack, pair[:12]...)
	stack = append(stack, pair[:12]...)
	return append(stack, bnBytesUint(4), bnBytesUint(uint64(CurveAltBN128)))
}

func pairingBudgetEngine(t *testing.T, budget *ComputeBudget) *Engine {
	t.Helper()
	vm, err := newOpcodeEngine(buildOpcodeWorld(), 0)
	require.NoError(t, err)
	vm.taprootCtx = newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	)
	if budget != nil {
		WithComputeBudget(budget)(vm)
	}
	return vm
}

func TestFourTermPairingUsesOneExecutionCharge(t *testing.T) {
	vm := pairingBudgetEngine(t, nil)
	for range 2 {
		vm.SetStack(fourTermPairingStack(t))
		require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
		require.Equal(t, [][]byte{{1}}, vm.GetStack())
	}
	// Two four-term checks fit the default per-input invocation budget. A
	// third fails even though each invocation is below the sixteen-pair cap.
	vm.SetStack(fourTermPairingStack(t))
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm), txscript.ErrScriptTooBig)
}

func TestFourTermPairingSharesRequestBudgetAcrossInputs(t *testing.T) {
	budget := NewComputeBudget()
	perInput := DefaultComputeLimits()[OP_ECPAIRING]
	requestLimit := DefaultAggregateComputeLimits()[OP_ECPAIRING]
	require.Positive(t, perInput)
	require.Equal(t, 0, requestLimit%perInput)

	for range requestLimit / perInput {
		vm := pairingBudgetEngine(t, budget)
		for range perInput {
			vm.SetStack(fourTermPairingStack(t))
			require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
			require.Equal(t, [][]byte{{1}}, vm.GetStack())
		}
	}
	// A fresh input must not reset the request-wide budget.
	vm := pairingBudgetEngine(t, budget)
	vm.SetStack(fourTermPairingStack(t))
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm), txscript.ErrScriptTooBig)
}

func TestFourTermPairingRejectsNonMinimalCoordinateInEveryPosition(t *testing.T) {
	for index := range 24 {
		t.Run(fmt.Sprintf("coordinate_%d", index), func(t *testing.T) {
			stack := fourTermPairingStack(t)
			// Non-minimal encoding of one, irrespective of point membership.
			stack[index] = []byte{1, 0}
			vm := pairingBudgetEngine(t, nil)
			vm.SetStack(stack)
			requireScriptErrorCode(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm), txscript.ErrMinimalData)
		})
	}
}

func TestFourTermPairingDoesNotAcceptNonIdentityProduct(t *testing.T) {
	vm := pairingBudgetEngine(t, nil)
	stack := fourTermPairingStack(t)
	// Replace the second pair's -G1 with +G1, keeping every point valid.
	// The last two terms still cancel, while the first two no longer do.
	stack[7] = append([]byte(nil), stack[1]...)
	vm.SetStack(stack)
	require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
	require.Len(t, vm.GetStack(), 1)
	require.Empty(t, vm.GetStack()[0])
}
