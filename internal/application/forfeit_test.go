package application

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateForfeitOutputs(t *testing.T) {
	vtxo := &wire.TxOut{Value: 100_000, PkScript: []byte{txscript.OP_TRUE}}
	connector := &wire.TxOut{Value: 450, PkScript: []byte{txscript.OP_TRUE}}
	forfeitPkScript := []byte{txscript.OP_TRUE}

	newForfeit := func(t *testing.T) *psbt.Packet {
		t.Helper()

		tx := wire.NewMsgTx(3)
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxOut(&wire.TxOut{
			Value:    vtxo.Value + connector.Value - txutils.ANCHOR_VALUE,
			PkScript: forfeitPkScript,
		})
		tx.AddTxOut(txutils.AnchorOutput())
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		ptx.Inputs[0].WitnessUtxo = vtxo
		ptx.Inputs[1].WitnessUtxo = connector
		return ptx
	}

	require.ErrorContains(t, validateForfeitOutputs(newForfeit(t), 0, nil, connector, forfeitPkScript),
		"missing vtxo prevout for input 0")
	require.ErrorContains(t, validateForfeitOutputs(newForfeit(t), 0, vtxo, nil, forfeitPkScript),
		"missing connector output for input 1")
	require.ErrorContains(t, validateForfeitOutputs(newForfeit(t), 2, vtxo, connector, forfeitPkScript),
		"vtxo input index 2 out of range")
	require.ErrorContains(t, validateForfeitOutputs(newForfeit(t), -1, vtxo, connector, forfeitPkScript),
		"vtxo input index -1 out of range")
	require.ErrorContains(t, validateForfeitOutputs(newForfeit(t), 0, vtxo, connector, nil),
		"missing forfeit script")

	threeInputs := newForfeit(t)
	threeInputs.UnsignedTx.AddTxIn(&wire.TxIn{})
	threeInputs.Inputs = append(threeInputs.Inputs, psbt.PInput{})
	require.ErrorContains(t, validateForfeitOutputs(threeInputs, 0, vtxo, connector, forfeitPkScript),
		"expected 2 inputs, got 3 psbt and 3 tx inputs")

	shortPsbt := newForfeit(t)
	shortPsbt.Inputs = shortPsbt.Inputs[:1]
	require.ErrorContains(t, validateForfeitOutputs(shortPsbt, 1, vtxo, connector, forfeitPkScript),
		"expected 2 inputs, got 1 psbt and 2 tx inputs")

	tests := []struct {
		name    string
		mutate  func(*psbt.Packet)
		wantErr string
	}{
		{name: "valid"},
		{
			name: "missing vtxo witness utxo",
			mutate: func(ptx *psbt.Packet) {
				ptx.Inputs[0].WitnessUtxo = nil
			},
			wantErr: "missing witness utxo for input 0",
		},
		{
			name: "missing connector witness utxo",
			mutate: func(ptx *psbt.Packet) {
				ptx.Inputs[1].WitnessUtxo = nil
			},
			wantErr: "missing witness utxo for input 1",
		},
		{
			name: "vtxo witness utxo mismatch",
			mutate: func(ptx *psbt.Packet) {
				ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: vtxo.Value - 1, PkScript: vtxo.PkScript}
			},
			wantErr: "does not spend the vtxo committed by the intent proof",
		},
		{
			name: "connector witness utxo mismatch",
			mutate: func(ptx *psbt.Packet) {
				ptx.Inputs[1].WitnessUtxo = &wire.TxOut{Value: connector.Value - 1, PkScript: connector.PkScript}
			},
			wantErr: "does not spend the connector output of the tree",
		},
		{
			name: "extra output",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}})
			},
			wantErr: "expected 2 outputs",
		},
		{
			name: "anchor script replaced",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.TxOut[1].PkScript = []byte{txscript.OP_TRUE}
			},
			wantErr: "is not the anchor output",
		},
		{
			name: "wrong anchor value",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.TxOut[1].Value = txutils.ANCHOR_VALUE + 1
			},
			wantErr: "is not the anchor output",
		},
		{
			name: "wrong value",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.TxOut[0].Value--
			},
			wantErr: "output 0 pays",
		},
		{
			name: "payout redirected off the arkd forfeit script",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.TxOut[0].PkScript = []byte{txscript.OP_RETURN}
			},
			wantErr: "output 0 does not pay the arkd forfeit script",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			forfeit := newForfeit(t)
			if tc.mutate != nil {
				tc.mutate(forfeit)
			}

			err := validateForfeitOutputs(forfeit, 0, vtxo, connector, forfeitPkScript)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestLeafOutput(t *testing.T) {
	connectorTx := wire.NewMsgTx(3)
	connectorTx.AddTxIn(&wire.TxIn{})
	connectorTx.AddTxOut(&wire.TxOut{Value: 450, PkScript: []byte{0x52}})
	connectorTx.AddTxOut(txutils.AnchorOutput())

	root, err := psbt.NewFromUnsignedTx(connectorTx)
	require.NoError(t, err)

	connectorTree := &tree.TxTree{Root: root}
	txid := connectorTx.TxHash()

	t.Run("nil tree", func(t *testing.T) {
		require.Nil(t, leafOutput(nil, wire.OutPoint{Hash: txid, Index: 0}))
	})

	t.Run("outpoint not in the tree", func(t *testing.T) {
		require.Nil(t, leafOutput(
			connectorTree, wire.OutPoint{Hash: chainhash.Hash{0xff}, Index: 0},
		))
	})

	t.Run("output index out of range", func(t *testing.T) {
		require.Nil(t, leafOutput(connectorTree, wire.OutPoint{Hash: txid, Index: 5}))
	})

	t.Run("anchor output", func(t *testing.T) {
		require.Nil(t, leafOutput(connectorTree, wire.OutPoint{Hash: txid, Index: 1}))
	})

	t.Run("non-leaf node", func(t *testing.T) {
		parent := &tree.TxTree{Root: root, Children: map[uint32]*tree.TxTree{0: {}}}
		require.Nil(t, leafOutput(parent, wire.OutPoint{Hash: txid, Index: 0}))
	})

	t.Run("leaf output is returned", func(t *testing.T) {
		out := leafOutput(connectorTree, wire.OutPoint{Hash: txid, Index: 0})
		require.Equal(t, connectorTx.TxOut[0], out)
	})
}
