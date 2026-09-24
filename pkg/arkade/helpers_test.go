package arkade

import (
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// testArkPrevOutFetcher is a test-only implementation of ArkPrevOutFetcher.
type testArkPrevOutFetcher struct {
	txscript.PrevOutputFetcher
	arkTxs      map[wire.OutPoint]*wire.MsgTx
	prevoutIdxs map[wire.OutPoint]uint32
}

func newTestArkPrevOutFetcher(
	base txscript.PrevOutputFetcher,
	arkTxs map[wire.OutPoint]*wire.MsgTx,
	prevoutIdxs map[wire.OutPoint]uint32,
) *testArkPrevOutFetcher {
	return &testArkPrevOutFetcher{
		PrevOutputFetcher: base,
		arkTxs:            arkTxs,
		prevoutIdxs:       prevoutIdxs,
	}
}

func (f *testArkPrevOutFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if f.arkTxs == nil {
		return nil
	}
	return f.arkTxs[op]
}

func (f *testArkPrevOutFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if f.arkTxs == nil || f.prevoutIdxs == nil {
		return nil
	}

	idx, foundIdx := f.prevoutIdxs[op]
	arkTx, foundTx := f.arkTxs[op]

	if !foundIdx || !foundTx {
		return nil
	}

	if idx >= uint32(len(arkTx.TxOut)) {
		return nil
	}

	return arkTx.TxOut[idx].PkScript
}
