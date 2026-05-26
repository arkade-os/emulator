// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package arkade

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestNewOpcodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		valid       bool
		tx          *wire.MsgTx
		txIdx       int
		inputAmount int64
		stack       [][]byte
		errText     string
	}

	type fixture struct {
		name   string
		script *txscript.ScriptBuilder
		cases  []testCase
	}

	outpoint := wire.OutPoint{
		Hash:  chainhash.Hash{},
		Index: 0,
	}

	prevoutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
			outpoint: {
				Value: 1000000000,
				PkScript: []byte{
					OP_1, OP_DATA_32,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
		}), map[wire.OutPoint]*wire.MsgTx{
			outpoint: {
				Version: 1,
				TxOut: []*wire.TxOut{
					{
						Value: 1000000000,
						PkScript: []byte{
							OP_1, OP_DATA_32,
							0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
							0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
							0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
							0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
						},
					},
				},
			}}, map[wire.OutPoint]uint32{outpoint: 0},
	)

	// Pre-compute the expected tx hash for OP_TXID tests
	txForHash := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			},
		},
	}
	expectedTxHash := txForHash.TxHash()

	// A wrong hash to test negative case
	wrongHash := chainhash.Hash{0x01}

	tests := []fixture{
		{
			name:   "OP_MOD",
			script: txscript.NewScriptBuilder().AddOp(OP_4).AddOp(OP_3).AddOp(OP_MOD).AddOp(OP_1).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name:   "OP_DIV",
			script: txscript.NewScriptBuilder().AddOp(OP_DIV).AddOp(OP_3).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x06}, {0x02}},
				},
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x00}, // Divisor of 0 should fail
						{0x01},
					},
				},
			},
		},
		{
			name: "OP_NUM2BIN",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x85}).
				AddInt64(4).
				AddOp(OP_NUM2BIN).
				AddData([]byte{0x05, 0x00, 0x00, 0x80}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_BIN2NUM_feeds_arithmetic",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x05, 0x00, 0x00, 0x00}).
				AddOp(OP_BIN2NUM).
				AddInt64(6).
				AddOp(OP_ADD).
				AddInt64(11).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name:   "OP_MUL",
			script: txscript.NewScriptBuilder().AddOp(OP_MUL).AddOp(OP_6).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x02}, {0x03}}, // 2 * 3 = 6
				},
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x06}, {0x01}}, // 6 * 1 = 6
				},
			},
		},
		{
			name:   "OP_XOR",
			script: txscript.NewScriptBuilder().AddOp(OP_XOR).AddOp(OP_6).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x05}, // 5 (0101)
						{0x03}, // 3 (0011)
						// 5 XOR 3 = 6 (0110)
					},
				},
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x0F}, // 15 (1111)
						{0x09}, // 9  (1001)
						// 15 XOR 9 = 6 (0110)
					},
				},
			},
		},
		{
			name: "OP_CAT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02}).
				AddData([]byte{0x03, 0x04}).
				AddOp(OP_CAT).
				AddData([]byte{0x01, 0x02, 0x03, 0x04}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SUBSTR",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03, 0x04}).
				AddData([]byte{0x01}).
				AddData([]byte{0x02}).
				AddOp(OP_SUBSTR).
				AddData([]byte{0x02, 0x03}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LEFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03}).
				AddData([]byte{0x02}).
				AddOp(OP_LEFT).
				AddData([]byte{0x01, 0x02}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_RIGHT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03}).
				AddData([]byte{0x02}).
				AddOp(OP_RIGHT).
				AddData([]byte{0x02, 0x03}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INVERT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00, 0xFF}).
				AddOp(OP_INVERT).
				AddData([]byte{0xFF, 0x00}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_AND",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x06}). // 0110
				AddData([]byte{0x0C}). // 1100
				AddOp(OP_AND).
				AddData([]byte{0x04}). // 0100
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_OR",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x07}). // 0111
				AddData([]byte{0x05}). // 0101
				AddOp(OP_OR).
				AddData([]byte{0x07}). // 0111
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LSHIFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03}). // 0011
				AddData([]byte{0x01}). // Shift by 1
				AddOp(OP_LSHIFT).
				AddData([]byte{0x06}). // 0110 (shifted left by 1)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_RSHIFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x06}). // 0110
				AddData([]byte{0x01}). // Shift by 1
				AddOp(OP_RSHIFT).
				AddData([]byte{0x03}). // 0011 (shifted right by 1)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTOUTPOINT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}). // success flag
				AddOp(OP_INSPECTINPUTOUTPOINT).
				AddData([]byte{0x00}). // Index
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}). // Hash
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTOUTPOINT invalid negative index",
			script: txscript.NewScriptBuilder().
				AddOp(OP_1NEGATE).
				AddOp(OP_INSPECTINPUTOUTPOINT),
			cases: []testCase{
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
					errText:     "input index cannot be negative",
				},
			},
		},
		{
			name: "OP_INSPECTINPUTVALUE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTVALUE).
				AddData([]byte{0x00, 0xCA, 0x9A, 0x3B}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 1000000000,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTVALUE invalid negative index",
			script: txscript.NewScriptBuilder().
				AddOp(OP_1NEGATE).
				AddOp(OP_INSPECTINPUTVALUE),
			cases: []testCase{
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 1000000000,
					stack:       nil,
					errText:     "input index cannot be negative",
				},
			},
		},
		{
			name: "OP_INSPECTINPUTSCRIPTPUBKEY returns previous ark tx scriptpubkey",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTSCRIPTPUBKEY).
				AddOp(OP_1). // segwit v1
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{ // witness program
					0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
					0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
					0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
					0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTSCRIPTPUBKEY invalid negative index",
			script: txscript.NewScriptBuilder().
				AddOp(OP_1NEGATE).
				AddOp(OP_INSPECTINPUTSCRIPTPUBKEY),
			cases: []testCase{
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
					errText:     "input index cannot be negative",
				},
			},
		},
		{
			name: "OP_INSPECTINPUTSEQUENCE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTSEQUENCE).
				AddData([]byte{0xFF, 0xFF, 0xFF, 0xFF}). // Max sequence number
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
								Sequence: 4294967295,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTSEQUENCE invalid negative index",
			script: txscript.NewScriptBuilder().
				AddOp(OP_1NEGATE).
				AddOp(OP_INSPECTINPUTSEQUENCE),
			cases: []testCase{
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
								Sequence: 4294967295,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
					errText:     "input index cannot be negative",
				},
			},
		},
		{
			name: "OP_PUSHCURRENTINPUTINDEX",
			script: txscript.NewScriptBuilder().
				AddOp(OP_PUSHCURRENTINPUTINDEX).
				AddData([]byte{0x00}). // Input index 0
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTOUTPUTVALUE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTOUTPUTVALUE).
				AddData([]byte{0x00, 0xCA, 0x9A, 0x3B}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						TxOut: []*wire.TxOut{
							{
								Value:    1000000000,
								PkScript: nil,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTOUTPUTVALUE invalid negative index",
			script: txscript.NewScriptBuilder().
				AddOp(OP_1NEGATE).
				AddOp(OP_INSPECTOUTPUTVALUE),
			cases: []testCase{
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						TxOut: []*wire.TxOut{
							{
								Value:    1000000000,
								PkScript: nil,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
					errText:     "output index cannot be negative",
				},
			},
		},
		{
			name: "OP_INSPECTOUTPUTSCRIPTPUBKEY",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY).
				AddOp(OP_1). // Expected scriptPubKey
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						TxOut: []*wire.TxOut{
							{
								Value: 0,
								PkScript: []byte{
									OP_1, OP_DATA_32,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTOUTPUTSCRIPTPUBKEY invalid negative index",
			script: txscript.NewScriptBuilder().
				AddOp(OP_1NEGATE).
				AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY),
			cases: []testCase{
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						TxOut: []*wire.TxOut{
							{
								Value: 0,
								PkScript: []byte{
									OP_1, OP_DATA_32,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
					errText:     "output index cannot be negative",
				},
			},
		},
		{
			name: "OP_INSPECTVERSION",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTVERSION).
				AddData([]byte{0x01, 0x00, 0x00, 0x00}). // Version 1 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTLOCKTIME",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTLOCKTIME).
				AddData([]byte{0x00, 0x00, 0x00, 0x00}). // LockTime 0 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						LockTime: 0,
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTNUMINPUTS",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMINPUTS).
				AddOp(OP_1). // 1 input
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTNUMOUTPUTS",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMOUTPUTS).
				AddData([]byte{0x01}). // 1 output
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						TxOut: []*wire.TxOut{
							{
								Value:    0,
								PkScript: nil,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_TXWEIGHT",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXWEIGHT).
				AddData([]byte{0xCC, 0x00, 0x00, 0x00}). // Expected weight 204 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_CHECKSIGFROMSTACK",
			script: txscript.NewScriptBuilder().
				AddData([]byte{ // signature
					0xE9, 0x07, 0x83, 0x1F, 0x80, 0x84, 0x8D, 0x10,
					0x69, 0xA5, 0x37, 0x1B, 0x40, 0x24, 0x10, 0x36,
					0x4B, 0xDF, 0x1C, 0x5F, 0x83, 0x07, 0xB0, 0x08,
					0x4C, 0x55, 0xF1, 0xCE, 0x2D, 0xCA, 0x82, 0x15,
					0x25, 0xF6, 0x6A, 0x4A, 0x85, 0xEA, 0x8B, 0x71,
					0xE4, 0x82, 0xA7, 0x4F, 0x38, 0x2D, 0x2C, 0xE5,
					0xEB, 0xEE, 0xE8, 0xFD, 0xB2, 0x17, 0x2F, 0x47,
					0x7D, 0xF4, 0x90, 0x0D, 0x31, 0x05, 0x36, 0xC0,
				}).
				AddData([]byte{ // message
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}).
				AddData([]byte{ // public key
					0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
					0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
					0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
					0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9,
				}).
				AddOp(OP_CHECKSIGFROMSTACK),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_TXID",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXID).
				AddData(expectedTxHash[:]).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_TXID_LENGTH",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXID).
				AddOp(OP_SIZE).
				AddOp(OP_NIP).
				AddData([]byte{0x20}). // 32 bytes
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_TXID_WRONG_HASH",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXID).
				AddData(wrongHash[:]).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "SHA256_STREAMING",
			script: txscript.NewScriptBuilder().
				AddData([]byte("Hello")).   // stack = [Hello]
				AddOp(OP_SHA256INITIALIZE). // stack = [shactx(Hello)]
				AddData([]byte(" World")).  // stack = [shactx(Hello), World]
				AddOp(OP_SHA256UPDATE).     // stack = [shactx(Hello+World)]
				AddData([]byte("!")).       // stack = [shactx(Hello+World), !]
				AddOp(OP_SHA256FINALIZE).   // stack = [sha256(Hello+World+!)]
				AddData([]byte{
					0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53,
					0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1, 0xd6, 0x5d,
					0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
					0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
	}

	for _, test := range tests {
		for caseIndex, c := range test.cases {
			t.Run(fmt.Sprintf("%s_%d", test.name, caseIndex), func(tt *testing.T) {
				script, err := test.script.Script()
				if err != nil {
					tt.Errorf("NewEngine failed: %v", err)
				}

				engine, err := NewEngine(
					script,
					c.tx, c.txIdx,
					txscript.NewSigCache(100),
					txscript.NewTxSigHashes(c.tx, prevoutFetcher),
					c.inputAmount,
					prevoutFetcher,
				)
				if err != nil {
					tt.Errorf("NewEngine failed: %v", err)
				}

				if len(c.stack) > 0 {
					engine.SetStack(c.stack)
				}

				err = engine.Execute()
				if c.valid && err != nil {
					tt.Errorf("Execute failed: %v", err)
				}

				if !c.valid && err == nil {
					tt.Errorf("Execute should have failed")
				} else if !c.valid && c.errText != "" && !strings.Contains(err.Error(), c.errText) {
					tt.Errorf("expected error containing %q, got: %v", c.errText, err)
				}
			})
		}
	}
}

func TestMerkleBranchVerify(t *testing.T) {
	t.Parallel()

	prevoutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
			{
				Hash:  chainhash.Hash{},
				Index: 0,
			}: {
				Value: 1000000000,
				PkScript: []byte{
					OP_1, OP_DATA_32,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
		}), nil, nil,
	)

	simpleTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			},
		},
	}

	// --- Helper: sort-and-combine for branch hash ---
	sortedBranchHash := func(branchTag, left, right []byte) []byte {
		combined := make([]byte, 64)
		if bytes.Compare(left, right) < 0 {
			copy(combined[:32], left)
			copy(combined[32:], right)
		} else {
			copy(combined[:32], right)
			copy(combined[32:], left)
		}
		h := chainhash.TaggedHash(branchTag, combined)
		return h[:]
	}

	leafTag := []byte("ArkadeLeaf")
	branchTag := []byte("ArkadeBranch")

	// ---- 2-leaf tree: "hello", "world" ----
	leafA2 := chainhash.TaggedHash(leafTag, []byte("hello"))
	leafB2 := chainhash.TaggedHash(leafTag, []byte("world"))
	root2Leaf := sortedBranchHash(branchTag, leafA2[:], leafB2[:])

	// ---- 4-leaf tree: "alpha", "beta", "gamma", "delta" ----
	hashA := chainhash.TaggedHash(leafTag, []byte("alpha"))
	hashB := chainhash.TaggedHash(leafTag, []byte("beta"))
	hashC := chainhash.TaggedHash(leafTag, []byte("gamma"))
	hashD := chainhash.TaggedHash(leafTag, []byte("delta"))

	hashAB := sortedBranchHash(branchTag, hashA[:], hashB[:])
	hashCD := sortedBranchHash(branchTag, hashC[:], hashD[:])
	rootABCD := sortedBranchHash(branchTag, hashAB, hashCD)

	// Proof for leaf "alpha": [hashB, hashCD]
	proofAlpha := make([]byte, 64)
	copy(proofAlpha[:32], hashB[:])
	copy(proofAlpha[32:], hashCD)

	// Proof for leaf "beta": [hashA, hashCD]
	proofBeta := make([]byte, 64)
	copy(proofBeta[:32], hashA[:])
	copy(proofBeta[32:], hashCD)

	// ---- Single leaf: "only" ----
	singleLeafRoot := chainhash.TaggedHash(leafTag, []byte("only"))

	// ---- Raw hash mode vectors ----
	// Use leafA2 as a pre-computed 32-byte hash, treat it as raw leaf_data
	rawLeafData := leafA2[:]                                              // 32 bytes
	rawSibling := leafB2[:]                                               // 32 bytes
	rawRoot := sortedBranchHash(branchTag, rawLeafData[:], rawSibling[:]) // root in raw mode

	// ---- Proof chaining vectors ----
	// Build a 4-leaf tree but prove via chaining:
	// First call: prove "alpha" in left subtree -> produces hashAB (sub-root)
	// Second call: use hashAB as raw leaf_data with proof=[hashCD] -> produces rootABCD
	chainSubProof := make([]byte, 32)
	copy(chainSubProof, hashB[:]) // proof for alpha in left subtree

	chainUpperProof := make([]byte, 32)
	copy(chainUpperProof, hashCD) // proof for sub-root in full tree

	// --- Helper to build engine and run ---
	runTest := func(tt *testing.T, script []byte, stack [][]byte) error {
		tt.Helper()
		engine, err := NewEngine(
			script,
			simpleTx, 0,
			txscript.NewSigCache(100),
			txscript.NewTxSigHashes(simpleTx, prevoutFetcher),
			0,
			prevoutFetcher,
		)
		if err != nil {
			tt.Fatalf("NewEngine failed: %v", err)
		}
		engine.SetStack(stack)
		return engine.Execute()
	}

	type testCase struct {
		name    string
		valid   bool
		script  func(t *testing.T) []byte
		stack   [][]byte
		errText string // substring expected in error (for invalid cases)
	}

	tests := []testCase{
		// ---- Test 1: valid 2-leaf tree ----
		{
			name:  "valid_2leaf_tree",
			valid: true,
			script: func(t *testing.T) []byte {
				// OP_MERKLEBRANCHVERIFY <expected_root> OP_EQUALVERIFY OP_TRUE
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(root2Leaf).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,         // leaf_tag (bottom)
				branchTag,       // branch_tag
				leafB2[:],       // proof = sibling hash
				[]byte("hello"), // leaf_data (top)
			},
		},
		// ---- Test 2: valid 4-leaf tree ----
		{
			name:  "valid_4leaf_tree",
			valid: true,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rootABCD).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,         // leaf_tag (bottom)
				branchTag,       // branch_tag
				proofAlpha,      // proof = [hashB, hashCD] (64 bytes)
				[]byte("alpha"), // leaf_data (top)
			},
		},
		// ---- Test 3: valid single leaf, empty proof ----
		{
			name:  "valid_single_leaf_empty_proof",
			valid: true,
			script: func(t *testing.T) []byte {
				// Root = tagged_hash(leafTag, "only") since proof is empty
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(singleLeafRoot[:]).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,        // leaf_tag (bottom)
				branchTag,      // branch_tag
				{},             // empty proof
				[]byte("only"), // leaf_data (top)
			},
		},
		// ---- Test 4: valid raw hash mode (empty leaf_tag) ----
		{
			name:  "valid_raw_hash_mode",
			valid: true,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rawRoot).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				{},          // empty leaf_tag -> raw hash mode
				branchTag,   // branch_tag
				rawSibling,  // proof = sibling
				rawLeafData, // leaf_data = 32 bytes (pre-computed hash)
			},
		},
		// ---- Test 5: valid proof chaining ----
		// First OP_MERKLEBRANCHVERIFY: prove "alpha" in left subtree -> pushes hashAB
		// Then set up raw mode args and call again -> pushes rootABCD
		{
			name:  "valid_proof_chaining",
			valid: true,
			script: func(t *testing.T) []byte {
				// Stack before: [leafTag, branchTag, chainSubProof, "alpha"]
				// After 1st MERKLEBRANCHVERIFY: [..., hashAB]
				// Then we push: OP_0 (empty leaf_tag for raw mode), branchTag, chainUpperProof
				// Then: 3 OP_ROLL to bring hashAB to top as leaf_data
				// After 2nd MERKLEBRANCHVERIFY: [..., rootABCD]
				// Then: <rootABCD> OP_EQUALVERIFY OP_TRUE
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddOp(OP_0).
					AddData(branchTag).
					AddData(chainUpperProof).
					AddOp(OP_3).
					AddOp(OP_ROLL).
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rootABCD).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,         // leaf_tag for first call
				branchTag,       // branch_tag for first call
				chainSubProof,   // proof for alpha in left subtree
				[]byte("alpha"), // leaf_data
			},
		},
		// ---- Test 6: valid two leaves same tree, verify roots match ----
		// Prove "alpha" and "beta" in same 4-leaf tree, check roots equal
		{
			name:  "valid_two_leaf_same_tree",
			valid: true,
			script: func(t *testing.T) []byte {
				// Stack before: [leafTag, branchTag, proofAlpha, "alpha"]
				// 1st MERKLEBRANCHVERIFY -> pushes rootABCD (from alpha)
				// Then push items for beta proof inline:
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(leafTag).
					AddData(branchTag).
					AddData(proofBeta).
					AddData([]byte("beta")).
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,         // leaf_tag for first call (bottom)
				branchTag,       // branch_tag for first call
				proofAlpha,      // proof for alpha
				[]byte("alpha"), // leaf_data for first call (top)
			},
		},
		// ---- Test 7: invalid wrong root ----
		{
			name:  "invalid_wrong_root",
			valid: false,
			script: func(t *testing.T) []byte {
				wrongRoot := make([]byte, 32) // all zeros
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(wrongRoot).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,
				branchTag,
				leafB2[:],
				[]byte("hello"),
			},
			errText: "EQUALVERIFY",
		},
		// ---- Test 8: invalid proof not multiple of 32 ----
		{
			name:  "invalid_proof_not_multiple_of_32",
			valid: false,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(root2Leaf).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,
				branchTag,
				make([]byte, 33), // 33 bytes, not multiple of 32
				[]byte("hello"),
			},
			errText: "proof length",
		},
		// ---- Test 9: invalid empty branch_tag ----
		{
			name:  "invalid_empty_branch_tag",
			valid: false,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(root2Leaf).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,
				{}, // empty branch_tag
				leafB2[:],
				[]byte("hello"),
			},
			errText: "branch_tag",
		},
		// ---- Test 10: invalid raw mode leaf not 32 bytes (10 bytes) ----
		{
			name:  "invalid_raw_mode_leaf_not_32_bytes",
			valid: false,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rawRoot).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				{}, // empty leaf_tag -> raw hash mode
				branchTag,
				rawSibling,
				make([]byte, 10), // only 10 bytes, must be 32 in raw mode
			},
			errText: "leaf_data",
		},
		// ---- Test 11: invalid raw mode leaf 31 bytes ----
		{
			name:  "invalid_empty_leaf_tag_nonempty_but_wrong_size",
			valid: false,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rawRoot).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				{}, // empty leaf_tag -> raw hash mode
				branchTag,
				rawSibling,
				make([]byte, 31), // 31 bytes, must be 32 in raw mode
			},
			errText: "leaf_data",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			script := tc.script(tt)

			err := runTest(tt, script, tc.stack)
			if tc.valid && err != nil {
				tt.Errorf("Execute failed: %v", err)
			}
			if !tc.valid && err == nil {
				tt.Errorf("Execute should have failed")
			}
			if !tc.valid && err != nil && tc.errText != "" {
				if !strings.Contains(err.Error(), tc.errText) {
					tt.Errorf("Expected error containing %q, got: %v", tc.errText, err)
				}
			}
		})
	}
}

func TestEmulatorPacketOpcodes(t *testing.T) {
	t.Parallel()

	prevoutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
			{Hash: chainhash.Hash{}, Index: 0}: {Value: 1000, PkScript: []byte{
				OP_1, OP_DATA_32,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}},
			{Hash: chainhash.Hash{}, Index: 1}: {Value: 2000, PkScript: []byte{
				OP_1, OP_DATA_32,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}},
		}), nil, nil,
	)

	twoInputTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 1}},
		},
	}

	scriptA := []byte{OP_TRUE}
	scriptB := []byte{OP_1, OP_1, OP_ADD}
	witnessA := wire.TxWitness{{0xaa, 0xbb}}

	packet, err := NewPacket(
		EmulatorEntry{Vin: 0, Script: scriptA, Witness: witnessA},
		EmulatorEntry{Vin: 1, Script: scriptB, Witness: nil},
	)
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}

	expectedScriptHashA := ArkadeScriptHash(scriptA)
	expectedScriptHashB := ArkadeScriptHash(scriptB)
	var witBuf bytes.Buffer
	_ = psbt.WriteTxWitness(&witBuf, witnessA)
	expectedWitnessHashA := chainhash.TaggedHash(TagArkWitnessHash, witBuf.Bytes())
	zeroHash := make([]byte, 32)

	runEngine := func(t *testing.T, script []byte, tx *wire.MsgTx, pkt EmulatorPacket, stack [][]byte) error {
		t.Helper()
		engine, err := NewEngine(
			script, tx, 0,
			txscript.NewSigCache(100),
			txscript.NewTxSigHashes(tx, prevoutFetcher),
			1000, prevoutFetcher,
		)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		if pkt != nil {
			engine.SetEmulatorPacket(pkt)
		}
		if len(stack) > 0 {
			engine.SetStack(stack)
		}
		return engine.Execute()
	}

	type tc struct {
		name    string
		valid   bool
		script  []byte
		tx      *wire.MsgTx
		pkt     EmulatorPacket
		stack   [][]byte
		errText string
	}

	scriptHashCheck := func(t *testing.T, index byte, expected []byte) []byte {
		t.Helper()
		s, err := txscript.NewScriptBuilder().
			AddOp(index).
			AddOp(OP_INSPECTINPUTARKADESCRIPTHASH).
			AddData(expected).
			AddOp(OP_EQUAL).
			Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	witnessHashCheck := func(t *testing.T, index byte, expected []byte) []byte {
		t.Helper()
		s, err := txscript.NewScriptBuilder().
			AddOp(index).
			AddOp(OP_INSPECTINPUTARKADEWITNESSHASH).
			AddData(expected).
			AddOp(OP_EQUAL).
			Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	buildScript := func(t *testing.T, ops ...byte) []byte {
		t.Helper()
		b := txscript.NewScriptBuilder()
		for _, op := range ops {
			b.AddOp(op)
		}
		s, err := b.Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	tests := []tc{
		{
			name:   "script_hash_own_input",
			valid:  true,
			script: scriptHashCheck(t, OP_0, expectedScriptHashA),
			tx:     twoInputTx,
			pkt:    packet,
		},
		{
			name:   "script_hash_sibling_input",
			valid:  true,
			script: scriptHashCheck(t, OP_1, expectedScriptHashB),
			tx:     twoInputTx,
			pkt:    packet,
		},
		{
			name:  "script_hash_equality_across_inputs",
			valid: true,
			script: func() []byte {
				s, _ := txscript.NewScriptBuilder().
					AddOp(OP_0).AddOp(OP_INSPECTINPUTARKADESCRIPTHASH).
					AddOp(OP_0).AddOp(OP_INSPECTINPUTARKADESCRIPTHASH).
					AddOp(OP_EQUAL).
					Script()
				return s
			}(),
			tx:  twoInputTx,
			pkt: packet,
		},
		{
			name:    "script_hash_no_packet",
			valid:   false,
			script:  buildScript(t, OP_0, OP_INSPECTINPUTARKADESCRIPTHASH),
			tx:      twoInputTx,
			pkt:     nil,
			errText: "no emulator packet",
		},
		{
			name:    "script_hash_out_of_range",
			valid:   false,
			script:  buildScript(t, OP_2, OP_INSPECTINPUTARKADESCRIPTHASH),
			tx:      twoInputTx,
			pkt:     packet,
			errText: "input index out of range",
		},
		{
			name:  "script_hash_missing_entry",
			valid: false,
			script: func() []byte {
				s, _ := txscript.NewScriptBuilder().
					AddOp(OP_0).
					AddOp(OP_INSPECTINPUTARKADESCRIPTHASH).
					Script()
				return s
			}(),
			tx: twoInputTx,
			pkt: EmulatorPacket{
				{Vin: 1, Script: scriptB},
			},
			errText: "no emulator entry for vin 0",
		},
		{
			name:   "witness_hash_non_empty",
			valid:  true,
			script: witnessHashCheck(t, OP_0, expectedWitnessHashA[:]),
			tx:     twoInputTx,
			pkt:    packet,
		},
		{
			name:   "witness_hash_empty_returns_zeros",
			valid:  true,
			script: witnessHashCheck(t, OP_1, zeroHash),
			tx:     twoInputTx,
			pkt:    packet,
		},
		{
			name:    "witness_hash_no_packet",
			valid:   false,
			script:  buildScript(t, OP_0, OP_INSPECTINPUTARKADEWITNESSHASH),
			tx:      twoInputTx,
			pkt:     nil,
			errText: "no emulator packet",
		},
		{
			name:    "witness_hash_out_of_range",
			valid:   false,
			script:  buildScript(t, OP_2, OP_INSPECTINPUTARKADEWITNESSHASH),
			tx:      twoInputTx,
			pkt:     packet,
			errText: "input index out of range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := runEngine(t, tt.script, tt.tx, tt.pkt, tt.stack)
			if tt.valid && err != nil {
				t.Errorf("expected success, got: %v", err)
			}
			if !tt.valid {
				if err == nil {
					t.Error("expected failure, got success")
				} else if tt.errText != "" && !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("expected error containing %q, got: %v", tt.errText, err)
				}
			}
		})
	}
}

// makeTxWithExtension builds a wire.MsgTx that has an OP_RETURN output
// containing an ark extension with the given packets.
func makeTxWithExtension(t *testing.T, packets ...extension.Packet) *wire.MsgTx {
	t.Helper()
	ext := extension.Extension(packets)
	txOut, err := ext.TxOut()
	if err != nil {
		t.Fatalf("Extension.TxOut: %v", err)
	}
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
		},
		TxOut: []*wire.TxOut{txOut},
	}
}

func makeTxWithMalformedExtension(t *testing.T, payload []byte) *wire.MsgTx {
	t.Helper()

	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
		},
		TxOut: []*wire.TxOut{{
			Value:    0,
			PkScript: append([]byte{txscript.OP_RETURN, byte(len(payload))}, payload...),
		}},
	}
}

func TestPacketIntrospectionOpcodes(t *testing.T) {
	t.Parallel()

	prevoutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
			{Hash: chainhash.Hash{}, Index: 0}: {Value: 1000, PkScript: []byte{
				OP_1, OP_DATA_32,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}},
			{Hash: chainhash.Hash{}, Index: 1}: {Value: 2000, PkScript: []byte{
				OP_1, OP_DATA_32,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}},
		}), nil, nil,
	)

	// Custom packet types for testing. We use small values (2, 3) that
	// can be pushed with OP_2, OP_3 opcodes. Type 0 is asset.Packet
	// and type 1 is EmulatorPacket, so 2+ are free.
	const testPacketType = 2
	testPayload := []byte{0xde, 0xad, 0xbe, 0xef}
	testPacket := extension.UnknownPacket{PacketType: testPacketType, Data: testPayload}

	const testPacketType2 = 3
	testPayload2 := []byte{0xca, 0xfe}
	testPacket2 := extension.UnknownPacket{PacketType: testPacketType2, Data: testPayload2}

	const maxPacketType = 255
	maxPayload := []byte{0xff, 0x00, 0xff}
	maxPacket := extension.UnknownPacket{PacketType: maxPacketType, Data: maxPayload}

	// Large packet (> MaxScriptElementSize = 520 bytes) to test that
	// introspection opcodes can push data beyond the normal push limit.
	const largePacketType = 4
	largePayload := bytes.Repeat([]byte{0xab}, 1000)
	largePacket := extension.UnknownPacket{PacketType: largePacketType, Data: largePayload}

	// Transaction with extension containing testPacket.
	txWithPacket := makeTxWithExtension(t, testPacket)

	// Transaction with extension containing two packets.
	txWithTwoPackets := makeTxWithExtension(t, testPacket, testPacket2)

	// Transaction with extension containing max packet type.
	txWithMaxPacket := makeTxWithExtension(t, maxPacket)

	// Transaction with a large packet.
	txWithLargePacket := makeTxWithExtension(t, largePacket)

	// Plain transaction without extension.
	plainTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
		},
	}

	// Malformed extension: magic prefix is present, but packet TLV data is truncated.
	malformedExtensionTx := makeTxWithMalformedExtension(t, []byte{'A', 'R', 'K', testPacketType})

	// Previous ark transaction with extension for OP_INSPECTINPUTPACKET tests.
	prevoutTx := makeTxWithExtension(t, testPacket)
	malformedPrevoutTx := makeTxWithMalformedExtension(t, []byte{'A', 'R', 'K', testPacketType})

	// Two-input transaction for OP_INSPECTINPUTPACKET tests.
	twoInputTx := makeTxWithExtension(t, testPacket)
	twoInputTx.TxIn = append(twoInputTx.TxIn,
		&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 1}},
	)

	// makeArkPrevOutFetcher builds an ArkPrevOutFetcher from a map of input
	// indices to previous ark transactions, using the spending tx's outpoints.
	makeArkPrevOutFetcher := func(tx *wire.MsgTx, byIndex map[int]*wire.MsgTx) ArkPrevOutFetcher {
		var arkTxs map[wire.OutPoint]*wire.MsgTx
		var prevoutIdxs map[wire.OutPoint]uint32
		if byIndex != nil {
			arkTxs = make(map[wire.OutPoint]*wire.MsgTx, len(byIndex))
			prevoutIdxs = make(map[wire.OutPoint]uint32, len(byIndex))
			for idx, prevTx := range byIndex {
				outpoint := tx.TxIn[idx].PreviousOutPoint
				arkTxs[outpoint] = prevTx
				prevoutIdxs[outpoint] = outpoint.Index

			}
		}
		return newTestArkPrevOutFetcher(prevoutFetcher, arkTxs, prevoutIdxs)
	}

	runEngine := func(t *testing.T, script []byte, tx *wire.MsgTx, prevoutTxs map[int]*wire.MsgTx) error {
		t.Helper()
		fetcher := makeArkPrevOutFetcher(tx, prevoutTxs)
		engine, err := NewEngine(
			script, tx, 0,
			txscript.NewSigCache(100),
			txscript.NewTxSigHashes(tx, fetcher),
			1000, fetcher,
		)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		return engine.Execute()
	}

	type tc struct {
		name       string
		valid      bool
		script     []byte
		tx         *wire.MsgTx
		prevoutTxs map[int]*wire.MsgTx
		errText    string
	}

	buildScript := func(t *testing.T, ops ...byte) []byte {
		t.Helper()
		b := txscript.NewScriptBuilder()
		for _, op := range ops {
			b.AddOp(op)
		}
		s, err := b.Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	// Script: <packet_type> OP_INSPECTPACKET OP_1 OP_EQUALVERIFY <expected_data> OP_EQUAL
	// Verifies found flag is 1 and content matches expected data.
	inspectPacketCheck := func(t *testing.T, packetTypeOp byte, expectedData []byte) []byte {
		t.Helper()
		s, err := txscript.NewScriptBuilder().
			AddOp(packetTypeOp). // e.g. OP_2 pushes 2
			AddOp(OP_INSPECTPACKET).
			// stack: [content, 1]
			AddOp(OP_1).
			AddOp(OP_EQUALVERIFY). // verify flag == 1
			AddData(expectedData).
			AddOp(OP_EQUAL). // verify content
			Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	// Script: <packet_type> OP_INSPECTPACKET OP_0 OP_EQUALVERIFY OP_0 OP_EQUAL
	// Verifies the not-found case: flag == 0, content == empty.
	inspectPacketNotFound := func(t *testing.T, packetTypeOp byte) []byte {
		t.Helper()
		s, err := txscript.NewScriptBuilder().
			AddOp(packetTypeOp).
			AddOp(OP_INSPECTPACKET).
			// stack: [<empty>, 0]
			AddOp(OP_0).
			AddOp(OP_EQUALVERIFY). // verify flag == 0
			AddOp(OP_0).
			AddOp(OP_EQUAL). // verify content == empty (OP_0 pushes empty bytes)
			Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	// Script: <packet_type> <input_index> OP_INSPECTINPUTPACKET OP_1 OP_EQUALVERIFY <expected_data> OP_EQUAL
	inspectInputPacketCheck := func(t *testing.T, packetTypeOp, inputIndexOp byte, expectedData []byte) []byte {
		t.Helper()
		s, err := txscript.NewScriptBuilder().
			AddOp(packetTypeOp).
			AddOp(inputIndexOp).
			AddOp(OP_INSPECTINPUTPACKET).
			AddOp(OP_1).
			AddOp(OP_EQUALVERIFY).
			AddData(expectedData).
			AddOp(OP_EQUAL).
			Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	// Script: <packet_type> <input_index> OP_INSPECTINPUTPACKET OP_0 OP_EQUALVERIFY OP_0 OP_EQUAL
	inspectInputPacketNotFound := func(t *testing.T, packetTypeOp, inputIndexOp byte) []byte {
		t.Helper()
		s, err := txscript.NewScriptBuilder().
			AddOp(packetTypeOp).
			AddOp(inputIndexOp).
			AddOp(OP_INSPECTINPUTPACKET).
			// stack: [<empty>, 0]
			AddOp(OP_0).
			AddOp(OP_EQUALVERIFY). // verify flag == 0
			AddOp(OP_0).
			AddOp(OP_EQUAL). // verify content == empty
			Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	tests := []tc{
		// ── OP_INSPECTPACKET ──────────────────────────────────────
		{
			name:   "inspect_packet_found",
			valid:  true,
			script: inspectPacketCheck(t, OP_2, testPayload), // type 2
			tx:     txWithPacket,
		},
		{
			name:   "inspect_packet_type_not_found",
			valid:  true,
			script: inspectPacketNotFound(t, OP_9), // type 9 not in extension
			tx:     txWithPacket,
		},
		{
			name:   "inspect_packet_no_extension",
			valid:  true,
			script: inspectPacketNotFound(t, OP_2),
			tx:     plainTx,
		},
		{
			name:   "inspect_packet_second_type",
			valid:  true,
			script: inspectPacketCheck(t, OP_3, testPayload2), // type 3
			tx:     txWithTwoPackets,
		},
		{
			name:   "inspect_packet_first_of_two",
			valid:  true,
			script: inspectPacketCheck(t, OP_2, testPayload), // type 2
			tx:     txWithTwoPackets,
		},
		{
			name:  "inspect_packet_max_type_value",
			valid: true,
			script: func() []byte {
				s, err := txscript.NewScriptBuilder().
					AddInt64(maxPacketType).
					AddOp(OP_INSPECTPACKET).
					AddOp(OP_1).
					AddOp(OP_EQUALVERIFY).
					AddData(maxPayload).
					AddOp(OP_EQUAL).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			}(),
			tx: txWithMaxPacket,
		},
		{
			name:    "inspect_packet_malformed_extension",
			valid:   false,
			script:  buildScript(t, OP_2, OP_INSPECTPACKET),
			tx:      malformedExtensionTx,
			errText: "failed to parse extension",
		},
		{
			name:    "inspect_packet_empty_stack",
			valid:   false,
			script:  buildScript(t, OP_INSPECTPACKET),
			tx:      txWithPacket,
			errText: "stack",
		},

		// ── OP_INSPECTINPUTPACKET ─────────────────────────────────
		{
			name:       "inspect_input_packet_found",
			valid:      true,
			script:     inspectInputPacketCheck(t, OP_2, OP_0, testPayload),
			tx:         twoInputTx,
			prevoutTxs: map[int]*wire.MsgTx{0: prevoutTx},
		},
		{
			name:       "inspect_input_packet_type_not_found",
			valid:      true,
			script:     inspectInputPacketNotFound(t, OP_9, OP_0),
			tx:         twoInputTx,
			prevoutTxs: map[int]*wire.MsgTx{0: prevoutTx},
		},
		{
			name:       "inspect_input_packet_no_prev_tx_for_input",
			valid:      false,
			script:     buildScript(t, OP_2, OP_1, OP_INSPECTINPUTPACKET),
			tx:         twoInputTx,
			prevoutTxs: map[int]*wire.MsgTx{0: prevoutTx}, // only input 0 has prev tx
			errText:    "prevout tx not available for input",
		},
		{
			name:    "inspect_input_packet_no_prev_ark_txs",
			valid:   false,
			script:  buildScript(t, OP_2, OP_0, OP_INSPECTINPUTPACKET),
			tx:      twoInputTx,
			errText: "prevout tx not available for input",
			// prevoutTxs is nil
		},
		{
			name:       "inspect_input_packet_prev_tx_no_extension",
			valid:      true,
			script:     inspectInputPacketNotFound(t, OP_2, OP_0),
			tx:         twoInputTx,
			prevoutTxs: map[int]*wire.MsgTx{0: plainTx},
		},
		{
			name:       "inspect_input_packet_malformed_prev_tx_extension",
			valid:      false,
			script:     buildScript(t, OP_2, OP_0, OP_INSPECTINPUTPACKET),
			tx:         twoInputTx,
			prevoutTxs: map[int]*wire.MsgTx{0: malformedPrevoutTx},
			errText:    "failed to parse extension",
		},
		{
			name:       "inspect_input_packet_negative_index",
			valid:      false,
			script:     buildScript(t, OP_2, OP_1NEGATE, OP_INSPECTINPUTPACKET),
			tx:         twoInputTx,
			prevoutTxs: map[int]*wire.MsgTx{0: prevoutTx},
			errText:    "input index cannot be negative",
		},
		{
			name:       "inspect_input_packet_index_out_of_range",
			valid:      false,
			script:     buildScript(t, OP_2, OP_5, OP_INSPECTINPUTPACKET),
			tx:         twoInputTx,
			prevoutTxs: map[int]*wire.MsgTx{0: prevoutTx},
			errText:    "input index out of range",
		},
		{
			name:    "inspect_input_packet_empty_stack",
			valid:   false,
			script:  buildScript(t, OP_INSPECTINPUTPACKET),
			tx:      twoInputTx,
			errText: "stack",
		},
		{
			name:    "inspect_input_packet_single_stack_element",
			valid:   false,
			script:  buildScript(t, OP_2, OP_INSPECTINPUTPACKET),
			tx:      twoInputTx,
			errText: "stack",
		},

		// ── Large packet (> 520 byte MaxScriptElementSize) ────────
		{
			name:    "inspect_packet_large_content_rejected",
			valid:   false,
			script:  buildScript(t, OP_4, OP_INSPECTPACKET),
			tx:      txWithLargePacket,
			errText: "packet content size 1000 exceeds max allowed size 520",
		},
		{
			name:       "inspect_input_packet_large_content_rejected",
			valid:      false,
			script:     buildScript(t, OP_4, OP_0, OP_INSPECTINPUTPACKET),
			tx:         twoInputTx,
			prevoutTxs: map[int]*wire.MsgTx{0: txWithLargePacket},
			errText:    "packet content size 1000 exceeds max allowed size 520",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := runEngine(t, tt.script, tt.tx, tt.prevoutTxs)
			if tt.valid && err != nil {
				t.Errorf("expected success, got: %v", err)
			}
			if !tt.valid {
				if err == nil {
					t.Error("expected failure, got success")
				} else if tt.errText != "" && !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("expected error containing %q, got: %v", tt.errText, err)
				}
			}
		})
	}
}

// runTapscriptLeaf wires a witness-script leaf onto a single-input transaction
// and returns the engine ready to execute. The caller owns the pre-signature
// `witnessStack` (anything below the leaf + control block); this helper
// appends the leaf and control block itself.
func runTapscriptLeaf(
	t *testing.T,
	leafScript []byte,
	witnessStack wire.TxWitness,
	prevValue int64,
) *Engine {
	t.Helper()

	// A deterministic internal key keeps tests reproducible.
	internalPriv, _ := btcec.PrivKeyFromBytes([]byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	})

	leaf := txscript.NewBaseTapLeaf(leafScript)
	leafHash := leaf.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(
		internalPriv.PubKey(), leafHash[:],
	)

	controlBlock := &txscript.ControlBlock{
		InternalKey:     internalPriv.PubKey(),
		LeafVersion:     txscript.BaseLeafVersion,
		OutputKeyYIsOdd: outputKey.SerializeCompressed()[0] == 0x03,
	}
	controlBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	prevScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x77}, Index: 0}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: outpoint,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    prevValue - 500,
			PkScript: []byte{OP_TRUE},
		}},
	}

	witness := append(append(wire.TxWitness(nil), witnessStack...),
		leafScript, controlBytes)
	tx.TxIn[0].Witness = witness

	prevouts := map[wire.OutPoint]*wire.TxOut{
		outpoint: {Value: prevValue, PkScript: prevScript},
	}
	fetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(prevouts), nil, nil,
	)

	engine, err := NewEngine(
		prevScript, tx, 0,
		txscript.NewSigCache(32),
		txscript.NewTxSigHashes(tx, fetcher),
		prevValue,
		fetcher,
	)
	require.NoError(t, err)

	return engine
}

// arkadeDigest computes the arkade tapscript sighash for the given tx + input
// without running the engine. It is the single helper used by every digest
// test (round-trip signing, masking properties, BIP342 byte-layout
// equivalence).
func arkadeDigest(
	t *testing.T, tx *wire.MsgTx, txIdx int,
	fetcher ArkPrevOutFetcher, leafScript []byte,
	hashType txscript.SigHashType,
) []byte {
	t.Helper()
	vm := &Engine{
		tx:             *tx,
		txIdx:          txIdx,
		hashCache:      txscript.NewTxSigHashes(tx, fetcher),
		prevOutFetcher: fetcher,
		taprootCtx: newTaprootExecutionCtxForLeaf(
			txscript.NewBaseTapLeaf(leafScript), 0,
		),
	}
	digest, err := computeArkadeSighash(vm, hashType)
	require.NoError(t, err)
	return digest
}

// fetcherFor returns an ArkPrevOutFetcher backed by the given prevout map.
func fetcherFor(prevOuts map[wire.OutPoint]*wire.TxOut) ArkPrevOutFetcher {
	return newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(prevOuts), nil, nil,
	)
}

// TestOpSighashMatchesCheckSigFromStack proves OP_SIGHASH emits the exact
// digest an OP_CHECKSIG-style signature in the arkade VM commits to: the
// script runs OP_SIGHASH for SIGHASH_DEFAULT and verifies a witness-supplied
// Schnorr signature against that digest via OP_CHECKSIGFROMSTACK. The
// signature is produced against the arkade (witness-masked) sighash, not
// BIP342.
func TestOpSighashMatchesCheckSigFromStack(t *testing.T) {
	t.Parallel()

	signingPriv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0xa1}, 32))
	pubKeyX := schnorr.SerializePubKey(signingPriv.PubKey())

	// Stack on entry: [sig, pubkey]. Script:
	//   OP_0 OP_SIGHASH  // [sig, pubkey, sighash]
	//   OP_SWAP          // [sig, sighash, pubkey] — CHECKSIGFROMSTACK's order.
	//   OP_CHECKSIGFROMSTACK
	leafScript, err := txscript.NewScriptBuilder().
		AddOp(OP_0).
		AddOp(OP_SIGHASH).
		AddOp(OP_SWAP).
		AddOp(OP_CHECKSIGFROMSTACK).
		Script()
	require.NoError(t, err)

	engine := runTapscriptLeaf(t, leafScript,
		wire.TxWitness{nil, pubKeyX}, 1_000_000)

	sigHash := arkadeDigest(t, &engine.tx, 0, engine.prevOutFetcher,
		leafScript, txscript.SigHashDefault)
	sig, err := schnorr.Sign(signingPriv, sigHash)
	require.NoError(t, err)
	engine.tx.TxIn[0].Witness[0] = sig.Serialize()

	require.NoError(t, engine.Execute(),
		"OP_SIGHASH digest must equal the arkade sighash a witness signature commits to")
}

// TestOpCheckSigArkadeSighash locks in that OP_CHECKSIG in the arkade VM
// verifies signatures against the arkade (non-standard) tapscript sighash.
// Pre-OP_SIGHASH the verifier built a BIP341 keypath digest, which rejected
// every real tapscript signature.
func TestOpCheckSigArkadeSighash(t *testing.T) {
	t.Parallel()

	signingPriv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0xc1}, 32))
	pubKeyX := schnorr.SerializePubKey(signingPriv.PubKey())

	leafScript, err := txscript.NewScriptBuilder().
		AddData(pubKeyX).
		AddOp(OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	engine := runTapscriptLeaf(t, leafScript,
		wire.TxWitness{nil}, 2_000_000)

	sigHash := arkadeDigest(t, &engine.tx, 0, engine.prevOutFetcher,
		leafScript, txscript.SigHashDefault)
	sig, err := schnorr.Sign(signingPriv, sigHash)
	require.NoError(t, err)
	engine.tx.TxIn[0].Witness[0] = sig.Serialize()

	require.NoError(t, engine.Execute(),
		"OP_CHECKSIG must accept a signature over the arkade sighash")
}

// buildExtensionScript assembles an OP_RETURN script carrying an asset packet
// followed by the given emulator packet. The asset packet co-locates a
// second commitment so masking-property tests can show it remains in the
// digest while the emulator witness blob is dropped.
func buildExtensionScript(t *testing.T, ip EmulatorPacket) []byte {
	t.Helper()
	ap, err := asset.NewPacket([]asset.AssetGroup{fallbackFuzzAssetGroup()})
	require.NoError(t, err)
	script, err := extension.Extension{ap, ip}.Serialize()
	require.NoError(t, err)
	return script
}

// mutateEmulatorEntry locates the emulator packet inside tx's
// extension OP_RETURN, applies fn to its first entry, and rewrites the
// OP_RETURN with the modified packet.
func mutateEmulatorEntry(
	t *testing.T, tx *wire.MsgTx, fn func(*EmulatorEntry),
) {
	t.Helper()
	ip, err := FindEmulatorPacket(tx)
	require.NoError(t, err)
	require.NotNil(t, ip)
	fn(&ip[0])
	for i, out := range tx.TxOut {
		if extension.IsExtension(out.PkScript) {
			tx.TxOut[i].PkScript = buildExtensionScript(t, ip)
			return
		}
	}
	t.Fatal("no extension output found in tx")
}

// buildSighashFixture returns a 1-input tx with one real output and one
// OP_RETURN carrying an asset packet + emulator packet (with non-empty
// witness data), along with its prevout map and the tap leaf script we treat
// as executing.
func buildSighashFixture(t *testing.T) (
	*wire.MsgTx, map[wire.OutPoint]*wire.TxOut, []byte,
) {
	t.Helper()

	leafScript := []byte{OP_TRUE}
	ip, err := NewPacket(EmulatorEntry{
		Vin:    0,
		Script: []byte{OP_INSPECTVERSION, OP_1, OP_EQUAL},
		Witness: wire.TxWitness{
			[]byte("alice-secret"),
			[]byte{0xaa, 0xbb, 0xcc, 0xdd},
		},
	})
	require.NoError(t, err)

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0xa1, 0xa2}, Index: 0}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: outpoint,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{
			{Value: 9000, PkScript: []byte{OP_TRUE}},
			{Value: 0, PkScript: buildExtensionScript(t, ip)},
		},
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		outpoint: {Value: 10_000, PkScript: []byte{OP_TRUE}},
	}
	return tx, prevOuts, leafScript
}

// TestArkadeSighashMasksWitnessBlobs validates the core security property of
// the non-standard digest: emulator witness blobs are masked out, but
// every other byte committed by BIP342 (script bytes, vin, co-located ARK
// packets, non-extension outputs) continues to bind the signature.
func TestArkadeSighashMasksWitnessBlobs(t *testing.T) {
	t.Parallel()

	baseTx, prevOuts, leafScript := buildSighashFixture(t)
	fetcher := fetcherFor(prevOuts)
	const flag = txscript.SigHashAll

	digestOf := func(t *testing.T, tx *wire.MsgTx) []byte {
		t.Helper()
		return arkadeDigest(t, tx, 0, fetcher, leafScript, flag)
	}
	baseDigest := digestOf(t, baseTx)

	t.Run("witness_content_mutation_does_not_change_digest", func(t *testing.T) {
		t.Parallel()
		mutated := baseTx.Copy()
		mutateEmulatorEntry(t, mutated, func(e *EmulatorEntry) {
			e.Witness = wire.TxWitness{
				[]byte("totally-different-content-and-length"),
				[]byte{0xff, 0xff, 0xff},
				[]byte("extra-item"),
			}
		})
		require.Equal(t, baseDigest, digestOf(t, mutated),
			"the arkade sighash must NOT depend on witness blob content or length")
	})

	t.Run("empty_witness_matches_non_empty_witness", func(t *testing.T) {
		t.Parallel()
		mutated := baseTx.Copy()
		mutateEmulatorEntry(t, mutated, func(e *EmulatorEntry) {
			e.Witness = nil
		})
		require.Equal(t, baseDigest, digestOf(t, mutated),
			"masking must produce the same digest for empty and non-empty witnesses")
	})

	t.Run("script_byte_mutation_changes_digest", func(t *testing.T) {
		t.Parallel()
		mutated := baseTx.Copy()
		mutateEmulatorEntry(t, mutated, func(e *EmulatorEntry) {
			e.Script = append([]byte(nil), e.Script...)
			e.Script[0] ^= 0x01
		})
		require.NotEqual(t, baseDigest, digestOf(t, mutated),
			"script bytes must remain committed via sha_outputs")
	})

	t.Run("vin_mutation_changes_digest", func(t *testing.T) {
		t.Parallel()
		// A 2-input tx so vin=0 and vin=1 are both valid Validate() targets.
		twoInputTx, twoInputPrevOuts, _ := buildSighashFixture(t)
		extraOutpoint := wire.OutPoint{Hash: chainhash.Hash{0xb1}, Index: 0}
		twoInputTx.TxIn = append(twoInputTx.TxIn, &wire.TxIn{
			PreviousOutPoint: extraOutpoint,
			Sequence:         0xffffffff,
		})
		twoInputPrevOuts[extraOutpoint] = &wire.TxOut{
			Value: 5_000, PkScript: []byte{OP_TRUE},
		}
		twoInputFetcher := fetcherFor(twoInputPrevOuts)

		digestVin0 := arkadeDigest(t, twoInputTx, 0, twoInputFetcher, leafScript, flag)
		mutateEmulatorEntry(t, twoInputTx, func(e *EmulatorEntry) {
			e.Vin = 1
		})
		digestVin1 := arkadeDigest(t, twoInputTx, 0, twoInputFetcher, leafScript, flag)
		require.NotEqual(t, digestVin0, digestVin1,
			"entry vin must remain committed via sha_outputs")
	})

	t.Run("asset_packet_mutation_changes_digest", func(t *testing.T) {
		t.Parallel()
		mutated := baseTx.Copy()
		ip, err := FindEmulatorPacket(mutated)
		require.NoError(t, err)
		ap, err := asset.NewPacket([]asset.AssetGroup{{
			Outputs: []asset.AssetOutput{{
				Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 99,
			}},
		}})
		require.NoError(t, err)
		newScript, err := extension.Extension{ap, ip}.Serialize()
		require.NoError(t, err)
		mutated.TxOut[1].PkScript = newScript
		require.NotEqual(t, baseDigest, digestOf(t, mutated),
			"co-located asset packet must remain committed via sha_outputs")
	})

	t.Run("non_extension_output_mutation_changes_digest", func(t *testing.T) {
		t.Parallel()
		mutated := baseTx.Copy()
		mutated.TxOut[0].Value++
		require.NotEqual(t, baseDigest, digestOf(t, mutated),
			"non-extension outputs must remain committed via sha_outputs")
	})
}

// TestArkadeSighashSingleMasksExtensionOutput exercises the SIGHASH_SINGLE
// per-output digest branch when the signed input's index maps directly to
// the extension OP_RETURN. In buildArkadeSigMsg the branch
//
//	if maskedIdx == idx { out = masked }
//
// substitutes the witness-masked extension output for the per-output hash;
// TestArkadeSighashMasksWitnessBlobs runs with SIGHASH_ALL (sha_outputs path)
// and TestArkadeSighashByteLayoutMatchesBIP342 covers SIGHASH_SINGLE only at
// idx=0 (the non-extension output). This pins the remaining branch: idx
// landing on the extension OP_RETURN under SIGHASH_SINGLE and its
// ANYONECANPAY variant.
func TestArkadeSighashSingleMasksExtensionOutput(t *testing.T) {
	t.Parallel()

	// 2-input tx with output[1] == the emulator-bearing extension
	// OP_RETURN. Signing input idx=1 with SIGHASH_SINGLE therefore makes
	// the extension output the per-output target.
	build := func(t *testing.T) (*wire.MsgTx, ArkPrevOutFetcher, []byte) {
		t.Helper()
		leafScript := []byte{OP_TRUE}
		ip, err := NewPacket(EmulatorEntry{
			Vin:    0,
			Script: []byte{OP_INSPECTVERSION, OP_1, OP_EQUAL},
			Witness: wire.TxWitness{
				[]byte("alice-secret"),
				[]byte{0xaa, 0xbb, 0xcc, 0xdd},
			},
		})
		require.NoError(t, err)

		op0 := wire.OutPoint{Hash: chainhash.Hash{0xa1}, Index: 0}
		op1 := wire.OutPoint{Hash: chainhash.Hash{0xa2}, Index: 0}
		tx := &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{
				{PreviousOutPoint: op0, Sequence: 0xffffffff},
				{PreviousOutPoint: op1, Sequence: 0xffffffff},
			},
			TxOut: []*wire.TxOut{
				{Value: 9000, PkScript: []byte{OP_TRUE}},
				{Value: 0, PkScript: buildExtensionScript(t, ip)},
			},
		}
		prevOuts := map[wire.OutPoint]*wire.TxOut{
			op0: {Value: 10_000, PkScript: []byte{OP_TRUE}},
			op1: {Value: 5_000, PkScript: []byte{OP_TRUE}},
		}
		return tx, fetcherFor(prevOuts), leafScript
	}

	flags := []struct {
		name string
		flag txscript.SigHashType
	}{
		{"single", txscript.SigHashSingle},
		{"single_anyonecanpay", txscript.SigHashSingle | txscript.SigHashAnyOneCanPay},
	}

	for _, f := range flags {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			baseTx, fetcher, leafScript := build(t)
			const idx = 1
			baseDigest := arkadeDigest(t, baseTx, idx, fetcher, leafScript, f.flag)

			t.Run("witness_mutation_invariant", func(t *testing.T) {
				t.Parallel()
				mutated, _, _ := build(t)
				mutateEmulatorEntry(t, mutated, func(e *EmulatorEntry) {
					e.Witness = wire.TxWitness{
						[]byte("totally-different-witness-content"),
						[]byte{0xff, 0xff, 0xff},
						[]byte("extra-item"),
					}
				})
				require.Equal(t, baseDigest,
					arkadeDigest(t, mutated, idx, fetcher, leafScript, f.flag),
					"SIGHASH_SINGLE per-output mask must drop emulator witness bytes")
			})

			t.Run("script_mutation_changes_digest", func(t *testing.T) {
				t.Parallel()
				mutated, _, _ := build(t)
				mutateEmulatorEntry(t, mutated, func(e *EmulatorEntry) {
					e.Script = append([]byte(nil), e.Script...)
					e.Script[0] ^= 0x01
				})
				require.NotEqual(t, baseDigest,
					arkadeDigest(t, mutated, idx, fetcher, leafScript, f.flag),
					"emulator script bytes must remain committed via per-output hash")
			})

			t.Run("matches_bip342_over_masked_tx", func(t *testing.T) {
				t.Parallel()
				vm := &Engine{
					tx:             *baseTx,
					txIdx:          idx,
					hashCache:      txscript.NewTxSigHashes(baseTx, fetcher),
					prevOutFetcher: fetcher,
					taprootCtx: newTaprootExecutionCtxForLeaf(
						txscript.NewBaseTapLeaf(leafScript), 0,
					),
				}
				arkadeSigMsg, err := buildArkadeSigMsg(vm, f.flag)
				require.NoError(t, err)

				maskedTx := baseTx.Copy()
				masked, maskedIdx, err := maskExtensionOutput(maskedTx)
				require.NoError(t, err)
				require.Equal(t, idx, maskedIdx,
					"sanity: the extension output should sit at the signed idx")
				maskedTx.TxOut[maskedIdx] = masked

				bip342Digest, err := txscript.CalcTapscriptSignaturehash(
					txscript.NewTxSigHashes(maskedTx, fetcher), f.flag,
					maskedTx, idx, fetcher, vm.taprootCtx.tapLeaf,
				)
				require.NoError(t, err)

				arkadeWithBIP342Tag := chainhash.TaggedHash(
					chainhash.TagTapSighash, arkadeSigMsg,
				)
				require.Equal(t, bip342Digest, arkadeWithBIP342Tag[:],
					"SIGHASH_SINGLE byte layout must match BIP342 over the masked tx when idx hits the extension output")
			})
		})
	}
}

// TestArkadeSighashByteLayoutMatchesBIP342 is the strongest correctness check
// on the hand-rolled digest. For every valid sighash flag it computes:
//
//   - arkadeSigMsg = buildArkadeSigMsg(originalTx, flag) — the bytes our code
//     produces before final tagging (witness masking applied internally).
//   - bip342Digest = txscript.CalcTapscriptSignaturehash(maskedTx, flag, …) —
//     btcd's BIP342 digest over the same witness-masked tx, tagged with
//     "TapSighash".
//
// TaggedHash(TapSighash, arkadeSigMsg) MUST equal bip342Digest. Any deviation
// means the differences from BIP342 are NOT only witness-masking + tag.
func TestArkadeSighashByteLayoutMatchesBIP342(t *testing.T) {
	t.Parallel()

	flags := []struct {
		name string
		flag txscript.SigHashType
	}{
		{"default", txscript.SigHashDefault},
		{"all", txscript.SigHashAll},
		{"none", txscript.SigHashNone},
		{"single", txscript.SigHashSingle},
		{"all_anyonecanpay", txscript.SigHashAll | txscript.SigHashAnyOneCanPay},
		{"none_anyonecanpay", txscript.SigHashNone | txscript.SigHashAnyOneCanPay},
		{"single_anyonecanpay", txscript.SigHashSingle | txscript.SigHashAnyOneCanPay},
	}

	for _, f := range flags {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			tx, prevOuts, leafScript := buildSighashFixture(t)
			fetcher := fetcherFor(prevOuts)
			vm := &Engine{
				tx:             *tx,
				txIdx:          0,
				hashCache:      txscript.NewTxSigHashes(tx, fetcher),
				prevOutFetcher: fetcher,
				taprootCtx: newTaprootExecutionCtxForLeaf(
					txscript.NewBaseTapLeaf(leafScript), 0,
				),
			}

			// Our sigMsg over the original tx; masking applied internally.
			arkadeSigMsg, err := buildArkadeSigMsg(vm, f.flag)
			require.NoError(t, err)

			// btcd's BIP342 digest over the masked tx. There is at
			// most one emulator-packet output per tx, so this
			// substitutes the masked replacement at its index (if
			// any) and leaves every other output untouched.
			maskedTx := tx.Copy()
			masked, maskedIdx, err := maskExtensionOutput(maskedTx)
			require.NoError(t, err)
			if maskedIdx >= 0 {
				maskedTx.TxOut[maskedIdx] = masked
			}
			bip342Digest, err := txscript.CalcTapscriptSignaturehash(
				txscript.NewTxSigHashes(maskedTx, fetcher), f.flag,
				maskedTx, 0, fetcher, vm.taprootCtx.tapLeaf,
			)
			require.NoError(t, err)

			arkadeWithBIP342Tag := chainhash.TaggedHash(
				chainhash.TagTapSighash, arkadeSigMsg,
			)
			require.Equal(t, bip342Digest, arkadeWithBIP342Tag[:],
				"byte layout of arkade sigMsg must equal BIP342's over the masked tx")

			// Sanity: re-tagging with the arkade tag MUST yield the
			// production digest.
			productionDigest, err := computeArkadeSighash(vm, f.flag)
			require.NoError(t, err)
			expectedProduction := chainhash.TaggedHash(
				arkadeSighashTag, arkadeSigMsg,
			)
			require.Equal(t, expectedProduction[:], productionDigest,
				"computeArkadeSighash must equal TaggedHash(arkadeSighashTag, buildArkadeSigMsg(...))")
		})
	}
}

func TestArkadeSighashByteLayoutMatchesBIP342WithAnnexAndCodeSep(t *testing.T) {
	t.Parallel()

	tx, prevOuts, _ := buildSighashFixture(t)
	fetcher := fetcherFor(prevOuts)
	leafScript := []byte{OP_TRUE, OP_CODESEPARATOR, OP_TRUE}
	annex := []byte{txscript.TaprootAnnexTag, 0xab, 0xcd}
	const codeSepPos = uint32(1)
	const flag = txscript.SigHashAll
	taprootCtx := newTaprootExecutionCtxForLeaf(
		txscript.NewBaseTapLeaf(leafScript), 0,
	)
	taprootCtx.annex = annex
	taprootCtx.codeSepPos = codeSepPos

	vm := &Engine{
		tx:             *tx,
		txIdx:          0,
		hashCache:      txscript.NewTxSigHashes(tx, fetcher),
		prevOutFetcher: fetcher,
		taprootCtx:     taprootCtx,
	}

	arkadeSigMsg, err := buildArkadeSigMsg(vm, flag)
	require.NoError(t, err)

	maskedTx := tx.Copy()
	masked, maskedIdx, err := maskExtensionOutput(maskedTx)
	require.NoError(t, err)
	if maskedIdx >= 0 {
		maskedTx.TxOut[maskedIdx] = masked
	}
	bip342Digest, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(maskedTx, fetcher), flag,
		maskedTx, 0, fetcher, vm.taprootCtx.tapLeaf,
		txscript.WithAnnex(annex),
		txscript.WithBaseTapscriptVersion(codeSepPos, vm.taprootCtx.tapLeafHash[:]),
	)
	require.NoError(t, err)

	arkadeWithBIP342Tag := chainhash.TaggedHash(
		chainhash.TagTapSighash, arkadeSigMsg,
	)
	require.Equal(t, bip342Digest, arkadeWithBIP342Tag[:],
		"annex and code-separator fields must match BIP342 byte layout")
}

// TestArkadeSighashIsDomainSeparated locks in the BIP-340 tag separation: the
// arkade digest must NOT collide with the BIP342 digest. We use a tx with no
// emulator packet so masking is a no-op — any digest difference is solely
// from the tag.
func TestArkadeSighashIsDomainSeparated(t *testing.T) {
	t.Parallel()

	leafScript := []byte{OP_TRUE}
	outpoint := wire.OutPoint{Hash: chainhash.Hash{0xd1, 0xd2}, Index: 0}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: outpoint,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{Value: 8000, PkScript: []byte{OP_TRUE}}},
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		outpoint: {Value: 10_000, PkScript: []byte{OP_TRUE}},
	}
	fetcher := fetcherFor(prevOuts)
	leaf := txscript.NewBaseTapLeaf(leafScript)

	arkade := arkadeDigest(t, tx, 0, fetcher, leafScript, txscript.SigHashAll)
	bip342, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(tx, fetcher), txscript.SigHashAll,
		tx, 0, fetcher, leaf,
	)
	require.NoError(t, err)
	require.NotEqual(t, bip342, arkade,
		"arkade sighash must use a distinct BIP-340 tag from BIP342 (TapSighash)")
}
