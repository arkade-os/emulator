package arkade

import (
	"math"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestTunnelPreservesSelectedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		flags  int64
		mutate func(*Engine)
		ok     bool
	}{
		{name: "script and value", flags: TunnelScriptPubKey | TunnelValue, ok: true},
		{name: "script only ignores value", flags: TunnelScriptPubKey, mutate: func(vm *Engine) { vm.tx.TxOut[0].Value++ }, ok: true},
		{name: "value only ignores script", flags: TunnelValue, mutate: func(vm *Engine) { vm.tx.TxOut[0].PkScript = []byte{OP_FALSE} }, ok: true},
		{name: "changed script", flags: TunnelScriptPubKey, mutate: func(vm *Engine) { vm.tx.TxOut[0].PkScript = []byte{OP_FALSE} }},
		{name: "changed value", flags: TunnelValue, mutate: func(vm *Engine) { vm.tx.TxOut[0].Value++ }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vm := tunnelTestVM(t)
			if test.mutate != nil {
				test.mutate(vm)
			}
			vm.SetStack(tunnelStack(0, test.flags))
			err := invokeOpcodeWithData(OP_TUNNEL, nil, vm)
			if test.ok {
				require.NoError(t, err)
				require.Equal(t, [][]byte{{1}}, vm.GetStack())
				return
			}
			requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
		})
	}
}

func TestTunnelRejectsInvalidPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		stack [][]byte
		code  txscript.ErrorCode
	}{
		{name: "zero flags", stack: tunnelStack(0, 0), code: txscript.ErrInvalidStackOperation},
		{name: "unknown flags", stack: tunnelStack(0, 32), code: txscript.ErrInvalidStackOperation},
		{name: "exact and aggregated value", stack: tunnelStack(0, TunnelValue|TunnelValueSum), code: txscript.ErrInvalidStackOperation},
		{name: "exact and aggregated assets", stack: tunnelStack(0, TunnelAssets|TunnelAssetsSum), code: txscript.ErrInvalidStackOperation},
		{name: "negative output", stack: tunnelStack(-1, TunnelValue), code: txscript.ErrInvalidIndex},
		{name: "output out of range", stack: tunnelStack(1, TunnelValue), code: txscript.ErrInvalidIndex},
		{name: "missing exception items", stack: [][]byte{nil, scriptNum(TunnelValue).Bytes(), {1}}, code: txscript.ErrInvalidStackOperation},
		{name: "underflow", code: txscript.ErrInvalidStackOperation},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vm := tunnelTestVM(t)
			vm.SetStack(test.stack)
			requireScriptErrorCode(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm), test.code)
		})
	}
}

func TestTunnelUsesDirectPrevoutScript(t *testing.T) {
	t.Parallel()

	vm := tunnelTestVM(t)
	outpoint := vm.tx.TxIn[0].PreviousOutPoint
	base := vm.prevOutFetcher.(*testArkPrevOutFetcher).PrevOutputFetcher
	vm.prevOutFetcher = newTestArkPrevOutFetcher(base, nil, nil)
	vm.tx.TxOut[0].PkScript = base.FetchPrevOutput(outpoint).PkScript
	vm.SetStack(tunnelStack(0, TunnelScriptPubKey))
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
}

func TestTunnelPreservesInputLocalAssets(t *testing.T) {
	t.Parallel()

	id := asset.AssetId{Txid: chainhash.Hash{2}, Index: 3}
	packet := asset.Packet{
		{
			AssetId: &id,
			Inputs: []asset.AssetInput{
				{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7},
				{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 3},
			},
			Outputs: []asset.AssetOutput{
				{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 7},
				{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 8},
			},
		},
		{
			Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 5}},
		},
	}

	tests := []struct {
		name   string
		mutate func(asset.Packet)
		ok     bool
	}{
		{name: "ignores reissuance and issuance elsewhere", ok: true},
		{name: "missing asset", mutate: func(packet asset.Packet) { packet[0].Outputs[0].Vout = 1 }},
		{name: "changed amount", mutate: func(packet asset.Packet) { packet[0].Outputs[0].Amount++ }},
		{name: "asset added to selected output", mutate: func(packet asset.Packet) { packet[1].Outputs[0].Vout = 0 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vm := tunnelTestVM(t)
			vm.tx.TxIn = append(vm.tx.TxIn, wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{3}}, nil, nil))
			vm.tx.TxOut = append(vm.tx.TxOut, wire.NewTxOut(1, []byte{OP_TRUE}))
			vm.assetPacket = cloneTunnelPacket(packet)
			if test.mutate != nil {
				test.mutate(vm.assetPacket)
			}
			vm.SetStack(tunnelStack(0, TunnelAssets))
			err := invokeOpcodeWithData(OP_TUNNEL, nil, vm)
			if test.ok {
				require.NoError(t, err)
				return
			}
			requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
		})
	}
}

func TestTunnelAssetExceptions(t *testing.T) {
	t.Parallel()

	idA := asset.AssetId{Txid: chainhash.Hash{4}, Index: 1}
	idB := asset.AssetId{Txid: chainhash.Hash{5}, Index: 2}
	packet := asset.Packet{
		{
			AssetId: &idA,
			Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7}},
			Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 7}},
		},
		{
			AssetId: &idB,
			Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 9}},
		},
	}

	vm := tunnelTestVM(t)
	vm.assetPacket = packet
	vm.SetStack(tunnelStack(0, TunnelAssets, idA, idB))
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))

	vm = tunnelTestVM(t)
	vm.assetPacket = packet
	vm.SetStack(tunnelStack(0, TunnelAssets, idA))
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm), txscript.ErrInvalidStackOperation)

	vm = tunnelTestVM(t)
	vm.assetPacket = packet
	vm.SetStack(tunnelStack(0, TunnelValue, idA))
	requireScriptErrorCode(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm), txscript.ErrInvalidStackOperation)
}

func TestTunnelTreatsMissingAssetPacketAsEmpty(t *testing.T) {
	t.Parallel()

	vm := tunnelTestVM(t)
	vm.prevOutFetcher = nil
	vm.SetStack(tunnelStack(0, TunnelAssets))
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
}

func tunnelTestVM(t *testing.T) *Engine {
	t.Helper()

	outpoint := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	script := []byte{OP_1, 32, 1}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&outpoint, nil, nil))
	tx.AddTxOut(wire.NewTxOut(10_000, script))

	base := txscript.NewMultiPrevOutFetcher(nil)
	base.AddPrevOut(outpoint, wire.NewTxOut(10_000, []byte{OP_TRUE}))
	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxOut(wire.NewTxOut(10_000, script))

	return &Engine{
		tx:             *tx,
		txIdx:          0,
		prevOutFetcher: newTestArkPrevOutFetcher(base, map[wire.OutPoint]*wire.MsgTx{outpoint: arkTx}, map[wire.OutPoint]uint32{outpoint: 0}),
	}
}

func tunnelStack(outputIndex, flags int64, exceptions ...asset.AssetId) [][]byte {
	stack := [][]byte{scriptNum(outputIndex).Bytes(), scriptNum(flags).Bytes()}
	for _, id := range exceptions {
		stack = append(stack, append([]byte(nil), id.Txid[:]...), scriptNum(id.Index).Bytes())
	}
	return append(stack, scriptNum(len(exceptions)).Bytes())
}

func cloneTunnelPacket(packet asset.Packet) asset.Packet {
	clone := make(asset.Packet, len(packet))
	for i, group := range packet {
		clone[i] = group
		clone[i].Inputs = append([]asset.AssetInput(nil), group.Inputs...)
		clone[i].Outputs = append([]asset.AssetOutput(nil), group.Outputs...)
	}
	return clone
}

func TestTunnelValueSumAggregatesClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		outputValue int64
		ok          bool
	}{
		{name: "exact total", outputValue: 600, ok: true},
		{name: "more than claimed", outputValue: 601, ok: true},
		{name: "one sat short", outputValue: 599},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims := NewTunnelClaims()
			vms := tunnelSumVMs(t, claims, []int64{100, 200, 300}, []int64{test.outputValue, 1_000})

			for _, vm := range vms {
				vm.SetStack(tunnelStack(0, TunnelValueSum))
				require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
				require.Equal(t, [][]byte{{1}}, vm.GetStack())
			}

			err := claims.Verify(&vms[0].tx)
			if test.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "are claimed")
		})
	}
}

func TestTunnelValueSumCountsEachInputOnce(t *testing.T) {
	t.Parallel()

	claims := NewTunnelClaims()
	vms := tunnelSumVMs(t, claims, []int64{100, 200}, []int64{300})

	for _, vm := range vms {
		for range 3 {
			vm.SetStack(tunnelStack(0, TunnelValueSum))
			require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
		}
	}

	require.NoError(t, claims.Verify(&vms[0].tx))
}

func TestTunnelValueSumTracksEachSelectedOutput(t *testing.T) {
	t.Parallel()

	claims := NewTunnelClaims()
	vms := tunnelSumVMs(t, claims, []int64{100, 200}, []int64{100, 199})

	for i, vm := range vms {
		vm.SetStack(tunnelStack(int64(i), TunnelValueSum))
		require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
	}

	require.ErrorContains(t, claims.Verify(&vms[0].tx), "output 1 holds 199 sats but 200 are claimed")
}

func TestTunnelClaimsFailClosedOnPartialView(t *testing.T) {
	t.Parallel()

	claims := NewTunnelClaims()
	vms := tunnelSumVMs(t, claims, []int64{100, 200}, []int64{300})

	vms[0].SetStack(tunnelStack(0, TunnelValueSum))
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vms[0]))

	require.NoError(t, claims.Verify(&vms[0].tx))
	claims.MarkPartial()
	require.ErrorContains(t, claims.Verify(&vms[0].tx), "incomplete aggregated tunnel claims")
}

func TestTunnelClaimsIgnorePartialViewWithoutClaims(t *testing.T) {
	t.Parallel()

	claims := NewTunnelClaims()
	claims.MarkPartial()
	require.NoError(t, claims.Verify(tunnelTestVM(t).tx.Copy()))
}

func TestTunnelSumRequiresClaimsAccumulator(t *testing.T) {
	t.Parallel()

	for _, flags := range []int64{TunnelValueSum, TunnelAssetsSum} {
		vm := tunnelTestVM(t)
		vm.SetStack(tunnelStack(0, flags))
		requireScriptErrorCode(
			t, invokeOpcodeWithData(OP_TUNNEL, nil, vm), txscript.ErrInvalidStackOperation,
		)
	}
}

func TestTunnelValueSumRejectsNegativeSource(t *testing.T) {
	t.Parallel()

	vms := tunnelSumVMs(t, NewTunnelClaims(), []int64{-1}, []int64{100})
	vms[0].SetStack(tunnelStack(0, TunnelValueSum))
	requireScriptErrorCode(
		t, invokeOpcodeWithData(OP_TUNNEL, nil, vms[0]), txscript.ErrInvalidStackOperation,
	)
}

func TestTunnelAssetsSumAggregatesClaims(t *testing.T) {
	t.Parallel()

	id := asset.AssetId{Txid: chainhash.Hash{9}, Index: 1}

	tests := []struct {
		name         string
		outputAmount uint64
		ok           bool
	}{
		{name: "exact total", outputAmount: 10, ok: true},
		{name: "more than claimed", outputAmount: 11, ok: true},
		{name: "one unit short", outputAmount: 9},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims := NewTunnelClaims()
			vms := tunnelSumVMs(t, claims, []int64{100, 200}, []int64{300})
			packet := asset.Packet{
				{
					AssetId: &id,
					Inputs: []asset.AssetInput{
						{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 4},
						{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 6},
					},
					Outputs: []asset.AssetOutput{
						{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: test.outputAmount},
					},
				},
			}

			for _, vm := range vms {
				vm.assetPacket = packet
				vm.SetStack(tunnelStack(0, TunnelAssetsSum))
				require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
			}

			err := claims.Verify(&vms[0].tx)
			if test.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "are claimed")
		})
	}
}

func TestTunnelAssetsSumAboveUint64(t *testing.T) {
	t.Parallel()
	id := asset.AssetId{Txid: chainhash.Hash{9}, Index: 1}
	claims := NewTunnelClaims()
	vms := tunnelSumVMs(t, claims, []int64{100, 200}, []int64{300})
	packet := asset.Packet{{
		AssetId: &id,
		Inputs: []asset.AssetInput{
			{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: math.MaxUint64},
			{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 1},
		},
		Outputs: []asset.AssetOutput{
			{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: math.MaxUint64},
			{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 1},
		},
	}}
	for _, vm := range vms {
		vm.assetPacket = packet
		vm.SetStack(tunnelStack(0, TunnelAssetsSum))
		require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vm))
	}
	require.NoError(t, claims.Verify(&vms[0].tx))
}

func TestTunnelAssetsSumHonoursExceptions(t *testing.T) {
	t.Parallel()

	kept := asset.AssetId{Txid: chainhash.Hash{9}, Index: 1}
	excepted := asset.AssetId{Txid: chainhash.Hash{10}, Index: 2}
	packet := asset.Packet{
		{
			AssetId: &kept,
			Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 4}},
			Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 4}},
		},
		{
			AssetId: &excepted,
			Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7}},
			Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 7}},
		},
	}

	claims := NewTunnelClaims()
	vms := tunnelSumVMs(t, claims, []int64{100}, []int64{100, 100})
	vms[0].assetPacket = packet
	vms[0].SetStack(tunnelStack(0, TunnelAssetsSum, excepted))
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vms[0]))
	require.NoError(t, claims.Verify(&vms[0].tx))

	claims = NewTunnelClaims()
	vms = tunnelSumVMs(t, claims, []int64{100}, []int64{100, 100})
	vms[0].assetPacket = packet
	vms[0].tunnelClaims = claims
	vms[0].SetStack(tunnelStack(0, TunnelAssetsSum))
	require.NoError(t, invokeOpcodeWithData(OP_TUNNEL, nil, vms[0]))
	require.ErrorContains(t, claims.Verify(&vms[0].tx), "but 7 are claimed")
}

func tunnelSumVMs(t *testing.T, claims *TunnelClaims, inputValues, outputValues []int64) []*Engine {
	t.Helper()

	script := []byte{OP_1, 32, 1}
	tx := wire.NewMsgTx(2)
	base := txscript.NewMultiPrevOutFetcher(nil)
	arkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(inputValues))
	idxs := make(map[wire.OutPoint]uint32, len(inputValues))

	for i, value := range inputValues {
		outpoint := wire.OutPoint{Hash: chainhash.Hash{byte(i + 1)}, Index: 0}
		tx.AddTxIn(wire.NewTxIn(&outpoint, nil, nil))
		base.AddPrevOut(outpoint, wire.NewTxOut(value, []byte{OP_TRUE}))
		arkTx := wire.NewMsgTx(2)
		arkTx.AddTxOut(wire.NewTxOut(value, script))
		arkTxs[outpoint] = arkTx
		idxs[outpoint] = 0
	}
	for _, value := range outputValues {
		tx.AddTxOut(wire.NewTxOut(value, script))
	}

	fetcher := newTestArkPrevOutFetcher(base, arkTxs, idxs)
	vms := make([]*Engine, len(inputValues))
	for i := range inputValues {
		vms[i] = &Engine{
			tx:             *tx,
			txIdx:          i,
			prevOutFetcher: fetcher,
			tunnelClaims:   claims,
		}
	}
	return vms
}

func TestTunnelValueSumConsolidatesThroughScript(t *testing.T) {
	t.Parallel()

	values := []int64{100, 200, 300}
	vtxoScript := []byte{OP_TRUE}

	tx := wire.NewMsgTx(2)
	base := txscript.NewMultiPrevOutFetcher(nil)
	arkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(values))
	idxs := make(map[wire.OutPoint]uint32, len(values))
	for i, value := range values {
		outpoint := wire.OutPoint{Hash: chainhash.Hash{byte(i + 1)}, Index: 0}
		tx.AddTxIn(wire.NewTxIn(&outpoint, nil, nil))
		base.AddPrevOut(outpoint, wire.NewTxOut(value, vtxoScript))
		arkTx := wire.NewMsgTx(2)
		arkTx.AddTxOut(wire.NewTxOut(value, vtxoScript))
		arkTxs[outpoint] = arkTx
		idxs[outpoint] = 0
	}
	tx.AddTxOut(wire.NewTxOut(600, vtxoScript))

	consolidate, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddInt64(TunnelScriptPubKey | TunnelValueSum).
		AddInt64(0).
		AddOp(OP_TUNNEL).
		Script()
	require.NoError(t, err)

	fetcher := newTestArkPrevOutFetcher(base, arkTxs, idxs)
	claims := NewTunnelClaims()
	for i, value := range values {
		engine, err := NewEngine(
			consolidate, tx, i, txscript.NewSigCache(100),
			txscript.NewTxSigHashes(tx, base), value, fetcher,
		)
		require.NoError(t, err)
		WithTunnelClaims(claims)(engine)
		require.NoError(t, engine.Execute())
	}
	require.NoError(t, claims.Verify(tx))

	tx.TxOut[0].Value--
	require.ErrorContains(t, claims.Verify(tx), "output 0 holds 599 sats but 600 are claimed")
}
