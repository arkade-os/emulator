package arkade

// Spike: custom 0x05 state-packet round-trip through the Arkade engine.
//
// Purpose: confirm that a custom extension packet (type 0x05) can be:
//   (a) attached to an Arkade transaction and read back inside an Arkade Script
//       via OP_INSPECTPACKET,
//   (b) read from a PARENT transaction via OP_INSPECTINPUTPACKET,
//   (c) determine how an extension output affects OP_INSPECTNUMOUTPUTS.
//
// Run with: cd pkg/arkade && go test . -run TestPoolStatePacket -v

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// cashuPoolPacketType is the custom packet type byte reserved for the Cashu
// nullifier-pool state.  All values 0x02–0xFE that are not already claimed by
// asset.Packet (0x00) or EmulatorPacket (0x01) are fair game; 0x05 is used
// here so it does not collide with the test values in engine_test.go (0x02–0x04).
const cashuPoolPacketType = 0x05

// poolStatePayload is the 3-byte payload written into the extension.
var poolStatePayload = []byte{0xab, 0xcd, 0xef}

// runPacketEngine is a local helper that mirrors runArkadeScript but accepts a
// caller-supplied *wire.MsgTx (so the caller can attach an extension output)
// and a caller-supplied ArkPrevOutFetcher (so OP_INSPECTINPUTPACKET can
// resolve a parent tx).  It constructs the engine at txIdx=0 and returns the
// Execute() result.
func runPacketEngine(
	t *testing.T,
	script []byte,
	tx *wire.MsgTx,
	fetcher ArkPrevOutFetcher,
) error {
	t.Helper()
	engine, err := NewEngine(
		script, tx, 0,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(tx, fetcher),
		1_000_000,
		fetcher,
	)
	require.NoError(t, err)
	return engine.Execute()
}

// makePrevoutFetcher builds the base prevout fetcher that the engine needs to
// resolve the spending input's scriptPubKey.  The outpoint passed in must match
// tx.TxIn[0].PreviousOutPoint.
func makePrevoutFetcher(outpoint wire.OutPoint) txscript.PrevOutputFetcher {
	return txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		outpoint: {
			Value: 1_000_000,
			PkScript: []byte{
				OP_1, OP_DATA_32,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
	})
}

// TestPoolStatePacketA_CurrentTx verifies that a 0x05 extension packet attached
// to the current transaction is readable via OP_INSPECTPACKET.
//
// Findings:
//   - OP_INSPECTPACKET returns UnknownPacket.Data verbatim (no framing bytes,
//     no type prefix — the raw Data slice is pushed).
//   - When the packet type is not present, OP_INSPECTPACKET pushes (<empty>, 0).
func TestPoolStatePacketA_CurrentTx(t *testing.T) {
	t.Parallel()

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x01}, Index: 0}

	// Build a tx carrying a 0x05 extension output alongside a regular output.
	ext := extension.Extension{
		extension.UnknownPacket{PacketType: cashuPoolPacketType, Data: poolStatePayload},
	}
	extOut, err := ext.TxOut()
	require.NoError(t, err)

	claimantOut := &wire.TxOut{Value: 1_000, PkScript: []byte{OP_TRUE}}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: outpoint}},
		// Two TxOut: one claimant output, one extension output.
		TxOut: []*wire.TxOut{claimantOut, extOut},
	}

	fetcher := newTestArkPrevOutFetcher(makePrevoutFetcher(outpoint), nil, nil)

	t.Run("positive_packet_found", func(t *testing.T) {
		t.Parallel()
		// Script: push type 0x05 → OP_INSPECTPACKET → stack: [Data, 1]
		// Verify flag==1 then data==poolStatePayload.
		script, err := txscript.NewScriptBuilder().
			AddInt64(cashuPoolPacketType).
			AddOp(OP_INSPECTPACKET).
			AddOp(OP_1).
			AddOp(OP_EQUALVERIFY). // flag must be 1 (found)
			AddData(poolStatePayload).
			AddOp(OP_EQUAL). // content must equal the raw payload
			Script()
		require.NoError(t, err)

		err = runPacketEngine(t, script, tx, fetcher)
		// FINDING: OP_INSPECTPACKET returns UnknownPacket.Data verbatim.
		require.NoError(t, err, "0x05 packet round-trip via OP_INSPECTPACKET must pass")
	})

	t.Run("negative_type_not_found", func(t *testing.T) {
		t.Parallel()
		// Query type 0x06 which is not in the extension — expect flag==0 and
		// content==empty.
		script, err := txscript.NewScriptBuilder().
			AddInt64(0x06).
			AddOp(OP_INSPECTPACKET).
			// stack: [<empty>, 0]
			AddOp(OP_0).
			AddOp(OP_EQUALVERIFY). // flag must be 0 (not found)
			AddOp(OP_0).
			AddOp(OP_EQUAL). // content must be empty bytes
			Script()
		require.NoError(t, err)

		err = runPacketEngine(t, script, tx, fetcher)
		require.NoError(t, err, "missing type must push (empty,0)")
	})
}

// TestPoolStatePacketB_InputPacket verifies that OP_INSPECTINPUTPACKET can read
// a 0x05 packet from the PARENT transaction that the current tx spends.
//
// Stack convention for OP_INSPECTINPUTPACKET:
//
//	Push packet_type first, then input_index on top.
//	The opcode pops index first (top), then packetType (second).
//
// Parent tx registration: keyed in arkTxs by the child's input outpoint
// (tx.TxIn[idx].PreviousOutPoint).
//
// Findings:
//   - OP_INSPECTINPUTPACKET works at engine level when the parent tx is
//     registered in the prevout fetcher's arkTxs map.
//   - OP_PUSHCURRENTINPUTINDEX pushes txIdx (0), which selects TxIn[0].
func TestPoolStatePacketB_InputPacket(t *testing.T) {
	t.Parallel()

	// Build the PARENT tx: carries the 0x05 packet.
	ext := extension.Extension{
		extension.UnknownPacket{PacketType: cashuPoolPacketType, Data: poolStatePayload},
	}
	parentExtOut, err := ext.TxOut()
	require.NoError(t, err)
	parentTx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x00}, Index: 0}}},
		TxOut:   []*wire.TxOut{{Value: 1_000, PkScript: []byte{OP_TRUE}}, parentExtOut},
	}

	// Build the CHILD tx: spends parentOutpoint (parentTx output index 0).
	childOutpoint := wire.OutPoint{Hash: chainhash.Hash{0x02}, Index: 0}
	childTx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: childOutpoint}},
		TxOut:   []*wire.TxOut{{Value: 500, PkScript: []byte{OP_TRUE}}},
	}

	// Register the parent tx in the fetcher, keyed by the child's input outpoint.
	base := makePrevoutFetcher(childOutpoint)
	arkTxs := map[wire.OutPoint]*wire.MsgTx{childOutpoint: parentTx}
	prevoutIdxs := map[wire.OutPoint]uint32{childOutpoint: 0}
	fetcher := newTestArkPrevOutFetcher(base, arkTxs, prevoutIdxs)

	t.Run("positive_input_packet_via_pushcurrentinputindex", func(t *testing.T) {
		t.Parallel()
		// Script: push type 0x05, then push current input index (0),
		// then OP_INSPECTINPUTPACKET → stack: [Data, 1].
		script, err := txscript.NewScriptBuilder().
			AddInt64(cashuPoolPacketType).
			AddOp(OP_PUSHCURRENTINPUTINDEX).
			AddOp(OP_INSPECTINPUTPACKET).
			AddOp(OP_1).
			AddOp(OP_EQUALVERIFY). // flag must be 1 (found)
			AddData(poolStatePayload).
			AddOp(OP_EQUAL). // content must equal raw payload
			Script()
		require.NoError(t, err)

		err = runPacketEngine(t, script, childTx, fetcher)
		// FINDING: OP_INSPECTINPUTPACKET resolves parent by looking up
		// tx.TxIn[index].PreviousOutPoint in the fetcher's arkTxs map, then
		// calls findPacketByType on the parent tx.  Data is returned verbatim.
		require.NoError(t, err, "OP_INSPECTINPUTPACKET must read parent 0x05 packet")
	})

	t.Run("negative_type_not_in_parent", func(t *testing.T) {
		t.Parallel()
		// Query type 0x07 which is absent in the parent — expect flag==0.
		script, err := txscript.NewScriptBuilder().
			AddInt64(0x07).
			AddOp(OP_PUSHCURRENTINPUTINDEX).
			AddOp(OP_INSPECTINPUTPACKET).
			AddOp(OP_0).
			AddOp(OP_EQUALVERIFY). // flag must be 0
			AddOp(OP_0).
			AddOp(OP_EQUAL). // content must be empty
			Script()
		require.NoError(t, err)

		err = runPacketEngine(t, script, childTx, fetcher)
		require.NoError(t, err, "missing type in parent must push (empty,0)")
	})
}

// TestPoolStatePacketC_NumOutputs determines empirically how many outputs
// OP_INSPECTNUMOUTPUTS counts when an extension output is present.
//
// Findings:
//   - OP_INSPECTNUMOUTPUTS returns len(tx.TxOut), which INCLUDES the
//     extension output.  A tx with [claimant, pool, extension] has 3 TxOut
//     and OP_INSPECTNUMOUTPUTS pushes 3.
//   - Conclusion: scripts that enforce an exact output count must include the
//     extension output in their count.  For a Cashu pool tx with 2 spendable
//     outputs and 1 extension output, scripts must assert OP_INSPECTNUMOUTPUTS
//     == 3.
func TestPoolStatePacketC_NumOutputs(t *testing.T) {
	t.Parallel()

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x03}, Index: 0}

	ext := extension.Extension{
		extension.UnknownPacket{PacketType: cashuPoolPacketType, Data: poolStatePayload},
	}
	extOut, err := ext.TxOut()
	require.NoError(t, err)

	// Simulate a pool tx: claimant output, pool output, extension output = 3 TxOut.
	claimantOut := &wire.TxOut{Value: 1_000, PkScript: []byte{OP_TRUE}}
	poolOut := &wire.TxOut{Value: 500, PkScript: []byte{OP_TRUE}}

	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: outpoint}},
		TxOut:   []*wire.TxOut{claimantOut, poolOut, extOut},
	}
	fetcher := newTestArkPrevOutFetcher(makePrevoutFetcher(outpoint), nil, nil)

	t.Run("extension_output_counted", func(t *testing.T) {
		t.Parallel()
		// OP_INSPECTNUMOUTPUTS must return 3 (claimant + pool + extension).
		script, err := txscript.NewScriptBuilder().
			AddOp(OP_INSPECTNUMOUTPUTS).
			AddInt64(3).
			AddOp(OP_EQUAL).
			Script()
		require.NoError(t, err)

		err = runPacketEngine(t, script, tx, fetcher)
		// FINDING: extension output IS counted by OP_INSPECTNUMOUTPUTS.
		// Scripts constraining output layout must account for it.
		require.NoError(t, err, "OP_INSPECTNUMOUTPUTS must count extension output (result=3)")
	})

	t.Run("two_outputs_without_extension", func(t *testing.T) {
		t.Parallel()
		// Control: same tx but without the extension output to confirm baseline.
		txNoExt := &wire.MsgTx{
			Version: 1,
			TxIn:    []*wire.TxIn{{PreviousOutPoint: outpoint}},
			TxOut:   []*wire.TxOut{claimantOut, poolOut},
		}
		script, err := txscript.NewScriptBuilder().
			AddOp(OP_INSPECTNUMOUTPUTS).
			AddInt64(2).
			AddOp(OP_EQUAL).
			Script()
		require.NoError(t, err)

		err = runPacketEngine(t, script, txNoExt, fetcher)
		require.NoError(t, err, "without extension, OP_INSPECTNUMOUTPUTS must return 2")
	})
}
