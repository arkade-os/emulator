package arkade

import (
	"math"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestComputeLimitsValidateRejectsNegative(t *testing.T) {
	require.Error(t, ComputeLimits{OP_ECADD: -1}.Validate())
}

func TestComputeLimitsValidateAcceptsDefault(t *testing.T) {
	require.NoError(t, DefaultComputeLimits().Validate())
}

func TestDefaultComputeLimitsCoversHeavyOpcodes(t *testing.T) {
	heavy := []byte{
		OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD,
		OP_CHECKSIGFROMSTACK,
		OP_ECADD, OP_ECMUL, OP_ECPAIRING,
		OP_ECMULSCALARVERIFY, OP_TWEAKVERIFY,
		OP_MODEXP, OP_INSPECTINTENTMESSAGE,
	}
	limits := DefaultComputeLimits()
	for _, op := range heavy {
		_, ok := limits[op]
		require.Truef(t, ok, "opcode %s must have a compute limit", opcodeArray[op].name)
	}
}

func TestDefaultAggregateComputeLimitsScalePerInputCaps(t *testing.T) {
	perInput := DefaultComputeLimits()
	aggregate := DefaultAggregateComputeLimits()

	require.NoError(t, aggregate.Validate())
	require.Len(t, aggregate, len(perInput))
	for op, limit := range perInput {
		require.Equalf(t, limit*requestInputBudget, aggregate[op],
			"aggregate cap for %s must cover %d inputs' worth",
			opcodeArray[op].name, requestInputBudget)
	}
}

func TestAggregateComputeLimitsClampsOverflow(t *testing.T) {
	// A configured limit large enough to overflow when scaled must saturate,
	// never wrap into a negative cap that would reject the first execution.
	aggregate := AggregateComputeLimits(ComputeLimits{OP_ECPAIRING: math.MaxInt})

	require.NoError(t, aggregate.Validate())
	require.Equal(t, math.MaxInt, aggregate[OP_ECPAIRING])
}

// TestComputeBudgetAggregatesAcrossInputs is the acceptance-criterion test for
// the per-request brake: five inputs, each with its own engine and each staying
// within the per-input OP_ECPAIRING cap of 2, must not be able to spend more
// than the request-wide cap between them.
func TestComputeBudgetAggregatesAcrossInputs(t *testing.T) {
	budget := NewComputeBudget()
	aggregate := DefaultAggregateComputeLimits()[OP_ECPAIRING]

	charged := 0
	var lastErr error
	for range 5 {
		// A fresh engine per input, as ArkadeScript.Execute builds one.
		vm := budgetedPairingEngine(t, budget)

		// The per-input limit of 2 is never reached, so only the shared
		// budget can stop the execution.
		for range 2 {
			vm.SetStack(pairingFalseVectors())
			if err := invokeOpcodeWithData(OP_ECPAIRING, nil, vm); err != nil {
				lastErr = err
				continue
			}
			charged++
		}
	}

	require.Equal(t, aggregate, charged,
		"the request must not execute more pairings than the aggregate cap")
	requireScriptErrorCode(t, lastErr, txscript.ErrScriptTooBig)
	require.Contains(t, lastErr.Error(), "request execution limit")
}

// TestComputeBudgetSharedAcrossExecuteCalls exercises the wiring a caller must
// use: one budget created per request and passed to every input's
// ArkadeScript.Execute. The second input's script is identical to the first and
// well within the per-input limits, yet it must fail once the request-wide
// budget is spent.
func TestComputeBudgetSharedAcrossExecuteCalls(t *testing.T) {
	t.Parallel()

	// Each execution runs OP_1 twice and leaves a single truthy item.
	arkadeScript := []byte{OP_1, OP_1, OP_DROP}

	outpoints := []wire.OutPoint{
		{Hash: chainhash.Hash{0xc0}, Index: 0},
		{Hash: chainhash.Hash{0xc1}, Index: 0},
	}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: outpoints[0], Sequence: 0xffffffff},
			{PreviousOutPoint: outpoints[1], Sequence: 0xffffffff},
		},
		TxOut: []*wire.TxOut{{Value: 900, PkScript: []byte{OP_TRUE}}},
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		outpoints[0]: {Value: 1_000, PkScript: []byte{OP_1, 0x20}},
		outpoints[1]: {Value: 1_000, PkScript: []byte{OP_1, 0x20}},
	}
	prevOutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(prevOuts), nil, nil,
	)

	script := &ArkadeScript{
		script:          arkadeScript,
		spendingTapLeaf: txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	}

	// Three OP_1 executions for the whole request: enough for the first input
	// and one more, so the second input runs out mid-script.
	budget := NewComputeBudgetWithLimits(ComputeLimits{OP_1: 3})

	require.NoError(t, script.Execute(
		tx, prevOutFetcher, 0, WithComputeBudget(budget),
	))

	err := script.Execute(tx, prevOutFetcher, 1, WithComputeBudget(budget))
	require.Error(t, err)
	require.Contains(t, err.Error(), "request execution limit")

	// Without a shared budget the same second input succeeds, confirming it is
	// the request-wide accounting — not the input itself — that rejected it.
	require.NoError(t, script.Execute(tx, prevOutFetcher, 1))
}

// TestComputeBudgetAppliesWithoutPerInputLimit proves the two brakes are
// independent: removing the per-input cap for an opcode does not remove its
// request-wide cap.
func TestComputeBudgetAppliesWithoutPerInputLimit(t *testing.T) {
	budget := NewComputeBudgetWithLimits(ComputeLimits{OP_ECPAIRING: 3})

	vm := budgetedPairingEngine(t, budget)
	limits := DefaultComputeLimits()
	delete(limits, OP_ECPAIRING)
	WithExactComputeLimits(limits)(vm)

	for range 3 {
		vm.SetStack(pairingFalseVectors())
		require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
	}
	vm.SetStack(pairingFalseVectors())
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm),
		txscript.ErrScriptTooBig)
}

func TestComputeBudgetUnlistedOpcodeIsUnlimited(t *testing.T) {
	budget := NewComputeBudgetWithLimits(ComputeLimits{OP_ECPAIRING: 0})

	vm := budgetedPairingEngine(t, budget)
	for range 100 {
		require.NoError(t, invokeOpcodeWithData(OP_1, nil, vm))
	}
}

// TestWithoutComputeBudgetInputsStayIndependent documents the behavior callers
// get when they do not share a budget: every input keeps its own per-input
// counters, so the request-wide cost still scales with the number of inputs.
// The aggregate brake only engages once the caller threads one budget through
// every input of the request.
func TestWithoutComputeBudgetInputsStayIndependent(t *testing.T) {
	for range 5 {
		vm := budgetedPairingEngine(t, nil)
		for range 2 {
			vm.SetStack(pairingFalseVectors())
			require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
		}
	}
}

// budgetedPairingEngine builds an engine with a tapscript execution context
// active, optionally sharing the provided request-wide compute budget.
func budgetedPairingEngine(t *testing.T, budget *ComputeBudget) *Engine {
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
