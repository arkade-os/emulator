package application

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// validateForfeitOutputs checks the output side of a forfeit against the two
// prevouts it spends. tree.BuildForfeitTx, which arkd itself replays to accept a
// forfeit, collects the vtxo and the connector into a single output paying
// arkd's forfeit script, followed by the anchor, so the whole output side is
// determined by data the emulator can trust: the intent proof signature commits
// the vtxo prevout, the connector comes from the tree, the destination from GetInfo.
func validateForfeitOutputs(
	forfeit *psbt.Packet, vtxoIndex int, vtxoPrevout, connectorOutput *wire.TxOut,
	forfeitPkScript []byte,
) error {
	if len(forfeit.Inputs) != 2 || len(forfeit.UnsignedTx.TxIn) != 2 {
		return fmt.Errorf(
			"expected 2 inputs, got %d psbt and %d tx inputs",
			len(forfeit.Inputs), len(forfeit.UnsignedTx.TxIn),
		)
	}
	if vtxoIndex != 0 && vtxoIndex != 1 {
		return fmt.Errorf("vtxo input index %d out of range", vtxoIndex)
	}
	if vtxoPrevout == nil {
		return fmt.Errorf("missing vtxo prevout for input %d", vtxoIndex)
	}
	if connectorOutput == nil {
		return fmt.Errorf("missing connector output for input %d", vtxoIndex^1)
	}
	if len(forfeitPkScript) == 0 {
		return fmt.Errorf("missing forfeit script")
	}

	spentVtxo := forfeit.Inputs[vtxoIndex].WitnessUtxo
	if spentVtxo == nil {
		return fmt.Errorf("missing witness utxo for input %d", vtxoIndex)
	}
	if spentVtxo.Value != vtxoPrevout.Value ||
		!bytes.Equal(spentVtxo.PkScript, vtxoPrevout.PkScript) {
		return fmt.Errorf(
			"input %d does not spend the vtxo committed by the intent proof", vtxoIndex,
		)
	}

	connectorIndex := vtxoIndex ^ 1
	spentConnector := forfeit.Inputs[connectorIndex].WitnessUtxo
	if spentConnector == nil {
		return fmt.Errorf("missing witness utxo for input %d", connectorIndex)
	}
	if spentConnector.Value != connectorOutput.Value ||
		!bytes.Equal(spentConnector.PkScript, connectorOutput.PkScript) {
		return fmt.Errorf(
			"input %d does not spend the connector output of the tree", connectorIndex,
		)
	}

	if len(forfeit.UnsignedTx.TxOut) != 2 {
		return fmt.Errorf("expected 2 outputs, got %d", len(forfeit.UnsignedTx.TxOut))
	}

	anchor := forfeit.UnsignedTx.TxOut[1]
	if anchor.Value != txutils.ANCHOR_VALUE ||
		!bytes.Equal(anchor.PkScript, txutils.ANCHOR_PKSCRIPT) {
		return fmt.Errorf("output 1 is not the anchor output")
	}

	expectedValue := vtxoPrevout.Value + connectorOutput.Value - txutils.ANCHOR_VALUE
	if forfeit.UnsignedTx.TxOut[0].Value != expectedValue {
		return fmt.Errorf(
			"output 0 pays %d, expected %d",
			forfeit.UnsignedTx.TxOut[0].Value, expectedValue,
		)
	}
	if !bytes.Equal(forfeit.UnsignedTx.TxOut[0].PkScript, forfeitPkScript) {
		return fmt.Errorf("output 0 does not pay the arkd forfeit script")
	}

	return nil
}

// leafOutput returns the output spent by outpoint if it is a non-anchor output
// of a leaf of the tree, nil otherwise.
func leafOutput(tree *tree.TxTree, outpoint wire.OutPoint) *wire.TxOut {
	if tree == nil {
		return nil
	}

	node := tree.Find(outpoint.Hash.String())
	if node == nil {
		return nil
	}

	if len(node.Children) != 0 {
		// not a leaf
		return nil
	}

	if len(node.Root.UnsignedTx.TxOut) <= int(outpoint.Index) {
		// index out of range
		return nil
	}

	output := node.Root.UnsignedTx.TxOut[outpoint.Index]

	if bytes.Equal(output.PkScript, txutils.ANCHOR_PKSCRIPT) {
		return nil
	}

	return output
}
