package arkade

import (
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestAssetOpcodes(t *testing.T) {
	t.Parallel()

	// A known txid used for asset IDs in tests.
	assetTxid := chainhash.Hash{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	// A second txid used for intent inputs.
	intentTxid := chainhash.Hash{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}

	// Control asset txid.
	ctrlTxid := chainhash.Hash{
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	// Packet with two groups:
	// Group 0: existing asset (has AssetId), with control asset by ID, 2 local inputs, 1 output
	// Group 1: fresh issuance (nil AssetId), no control asset, no inputs, 1 output
	twoGroupPacket := asset.Packet{
		{
			AssetId: &asset.AssetId{Txid: assetTxid, Index: 3},
			ControlAsset: &asset.AssetRef{
				Type:    asset.AssetRefByID,
				AssetId: asset.AssetId{Txid: ctrlTxid, Index: 7},
			},
			Inputs: []asset.AssetInput{
				{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 500},
				{Type: asset.AssetInputTypeIntent, Vin: 1, Txid: intentTxid, Amount: 300},
			},
			Outputs: []asset.AssetOutput{
				{Vout: 0, Amount: 800},
			},
			Metadata: nil,
		},
		{
			AssetId:      nil, // fresh issuance
			ControlAsset: nil,
			Inputs:       nil,
			Outputs: []asset.AssetOutput{
				{Vout: 0, Amount: 1000},
				{Vout: 1, Amount: 2000},
			},
			Metadata: nil,
		},
	}

	// Packet with control asset by group index.
	ctrlByGroupPacket := asset.Packet{
		{
			AssetId: &asset.AssetId{Txid: assetTxid, Index: 0},
			Inputs:  nil,
			Outputs: []asset.AssetOutput{{Vout: 0, Amount: 100}},
		},
		{
			AssetId: nil, // fresh issuance
			ControlAsset: &asset.AssetRef{
				Type:       asset.AssetRefByGroup,
				GroupIndex: 0,
			},
			Inputs:  nil,
			Outputs: []asset.AssetOutput{{Vout: 1, Amount: 200}},
		},
	}

	// Packet whose control asset references a fresh issuance by packet group
	// index, so its canonical AssetID resolves to (txHash, referenced position).
	ctrlByGroupFreshPacket := asset.Packet{
		{
			AssetId: nil, // fresh issuance at packet position 0
			Outputs: []asset.AssetOutput{{Vout: 0, Amount: 100}},
		},
		{
			AssetId: nil, // fresh issuance whose control references group 0
			ControlAsset: &asset.AssetRef{
				Type:       asset.AssetRefByGroup,
				GroupIndex: 0,
			},
			Outputs: []asset.AssetOutput{{Vout: 1, Amount: 200}},
		},
	}

	// Packet with amounts exceeding the former scriptNum 4-byte limit (2^31-1).
	// Group 0: existing asset, 2 inputs totaling 10B, 1 output of 3B.
	largeAmountPacket := asset.Packet{
		{
			AssetId: &asset.AssetId{Txid: assetTxid, Index: 3},
			Inputs: []asset.AssetInput{
				{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 7_000_000_000},
				{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 3_000_000_000},
			},
			Outputs: []asset.AssetOutput{
				{Vout: 0, Amount: 3_000_000_000},
			},
		},
	}

	maxUint64AmountBytes, err := BigNumFromUint64(math.MaxUint64).Bytes()
	if err != nil {
		t.Fatalf("max uint64 amount bytes: %v", err)
	}
	maxUint64PlusOneBytes, err := (BigNum{
		big:    new(big.Int).Add(new(big.Int).SetUint64(math.MaxUint64), big.NewInt(1)),
		useBig: true,
	}).Bytes()
	if err != nil {
		t.Fatalf("max uint64 plus one amount bytes: %v", err)
	}

	// Packet covering the uint64 amount boundary and a sum above uint64.
	boundaryAmountPacket := asset.Packet{
		{
			AssetId: &asset.AssetId{Txid: assetTxid, Index: 3},
			Inputs: []asset.AssetInput{
				{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: math.MaxUint64},
				{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 1},
			},
			Outputs: []asset.AssetOutput{
				{Vout: 0, Amount: math.MaxUint64},
			},
		},
	}

	// Packet with two groups that share the same asset_txid but have distinct
	// canonical asset_gidx values, at packet positions unrelated to either
	// canonical index. Group 2 is a fresh issuance at a nonzero packet position.
	sameTxidPacket := asset.Packet{
		{
			AssetId: &asset.AssetId{Txid: assetTxid, Index: 10},
			Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 111}},
			Outputs: []asset.AssetOutput{{Vout: 0, Amount: 111}},
		},
		{
			AssetId: &asset.AssetId{Txid: assetTxid, Index: 20},
			Inputs:  []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 1, Amount: 222}},
			Outputs: []asset.AssetOutput{{Vout: 1, Amount: 222}},
		},
		{
			AssetId: nil, // fresh issuance at packet position 2
			Outputs: []asset.AssetOutput{{Vout: 1, Amount: 333}},
		},
	}

	// Packet with metadata.
	md1, _ := asset.NewMetadata("name", "TestToken")
	md2, _ := asset.NewMetadata("symbol", "TT")
	metadataPacket := asset.Packet{
		{
			AssetId:  &asset.AssetId{Txid: assetTxid, Index: 0},
			Inputs:   nil,
			Outputs:  []asset.AssetOutput{{Vout: 0, Amount: 100}},
			Metadata: []asset.Metadata{*md1, *md2},
		},
	}
	// Compute expected metadata hash.
	expectedMetadataHash, _ := computeMetadataMerkleRoot(metadataPacket[0].Metadata)

	prevoutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
			{Hash: chainhash.Hash{}, Index: 0}: {
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
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
		},
		TxOut: []*wire.TxOut{
			{Value: 500, PkScript: nil},
			{Value: 300, PkScript: nil},
		},
	}
	simpleTxHash := simpleTx.TxHash()

	type testCase struct {
		valid       bool
		assetPacket asset.Packet
	}

	type fixture struct {
		name   string
		script *txscript.ScriptBuilder
		cases  []testCase
	}

	tests := []fixture{
		// ========== OP_INSPECTNUMASSETGROUPS ==========
		{
			name: "OP_INSPECTNUMASSETGROUPS",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMASSETGROUPS).
				AddInt64(2).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTNUMASSETGROUPS_no_packet",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMASSETGROUPS),
			cases: []testCase{
				{valid: false, assetPacket: nil},
			},
		},

		// ========== OP_INSPECTASSETGROUPASSETID ==========
		{
			name: "OP_INSPECTASSETGROUPASSETID_existing",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddOp(OP_INSPECTASSETGROUPASSETID).
				AddInt64(3). // expected gidx
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // expected txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPASSETID_fresh_issuance",
			// For fresh issuance (nil AssetId), the opcode pushes the current tx hash and the group index.
			// Verify both components of the derived canonical AssetID exactly.
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group index (fresh issuance)
				AddOp(OP_INSPECTASSETGROUPASSETID).
				AddInt64(1). // expected group index as gidx
				AddOp(OP_EQUALVERIFY).
				AddData(simpleTxHash[:]).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPASSETID_out_of_range",
			script: txscript.NewScriptBuilder().
				AddInt64(5). // out of range
				AddOp(OP_INSPECTASSETGROUPASSETID),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUPCTRL ==========
		{
			name: "OP_INSPECTASSETGROUPCTRL_by_id",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group 0 has control asset by ID
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddOp(OP_1).
				AddOp(OP_EQUALVERIFY).
				AddInt64(7). // expected ctrl gidx
				AddOp(OP_EQUALVERIFY).
				AddData(ctrlTxid[:]). // expected ctrl txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPCTRL_none",
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group 1 has no control asset
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddOp(OP_NOT). // flag=0
				AddOp(OP_VERIFY).
				AddInt64(0). // expected missing index
				AddOp(OP_EQUALVERIFY).
				AddData(nil). // expected missing txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPCTRL_by_group_index",
			// Group 1 has control asset referencing group 0 (which has AssetId).
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group 1
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddOp(OP_1).
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // expected ctrl gidx (group 0's AssetId.Index)
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // expected ctrl txid (group 0's AssetId.Txid)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: ctrlByGroupPacket},
			},
		},

		// ========== OP_FINDASSETGROUPBYASSETID ==========
		{
			name: "OP_FINDASSETGROUPBYASSETID_found",
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]). // txid to search
				AddInt64(3).           // gidx to search
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_1).
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // expected group index
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_FINDASSETGROUPBYASSETID_not_found",
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]). // txid to search
				AddInt64(99).          // wrong gidx
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_NOT). // flag=0
				AddOp(OP_VERIFY).
				AddInt64(0). // expected missing index
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUPMETADATAHASH ==========
		{
			name: "OP_INSPECTASSETGROUPMETADATAHASH",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddOp(OP_INSPECTASSETGROUPMETADATAHASH).
				AddData(expectedMetadataHash[:]). // expected hash
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: metadataPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPMETADATAHASH_empty",
			// Empty metadata should produce zero hash.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddOp(OP_INSPECTASSETGROUPMETADATAHASH).
				AddData(make([]byte, 32)). // zero hash
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUPNUM ==========
		{
			name: "OP_INSPECTASSETGROUPNUM_inputs",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // source=0 (inputs)
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddInt64(2). // 2 inputs in group 0
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPNUM_outputs",
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group index
				AddInt64(1). // source=1 (outputs)
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddInt64(2). // 2 outputs in group 1
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPNUM_both",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(2). // source=2 (both)
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddInt64(1). // output count
				AddOp(OP_EQUALVERIFY).
				AddInt64(2). // input count
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPNUM_invalid_source",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(3). // invalid source
				AddOp(OP_INSPECTASSETGROUPNUM),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUP (input details) ==========
		{
			name: "OP_INSPECTASSETGROUP_local_input",
			// Group 0, input 0 is local: type=1, vin=0, amount=500
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // item index
				AddInt64(0). // source=0 (input)
				AddOp(OP_INSPECTASSETGROUP).
				AddInt64(500). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // vin
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // type (local)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUP_intent_input",
			// Group 0, input 1 is intent: type=2, txid, vin=1, amount=300
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(1). // item index
				AddInt64(0). // source=0 (input)
				AddOp(OP_INSPECTASSETGROUP).
				AddInt64(300). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // vin
				AddOp(OP_EQUALVERIFY).
				AddData(intentTxid[:]). // txid (only for intent inputs)
				AddOp(OP_EQUALVERIFY).
				AddInt64(2). // type (intent)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUP_output",
			// Group 0, output 0: type=1, vout=0, amount=800
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // item index
				AddInt64(1). // source=1 (output)
				AddOp(OP_INSPECTASSETGROUP).
				AddInt64(800). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // vout
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // type (always 1 for outputs)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUP_input_out_of_range",
			script: txscript.NewScriptBuilder().
				AddInt64(0).  // group index
				AddInt64(10). // out of range item index
				AddInt64(0).  // source=0 (input)
				AddOp(OP_INSPECTASSETGROUP),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUP_invalid_source",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // item index
				AddInt64(5). // invalid source
				AddOp(OP_INSPECTASSETGROUP),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUPSUM ==========
		{
			name: "OP_INSPECTASSETGROUPSUM_inputs",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // source=0 (inputs)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(800). // 500 + 300
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPSUM_outputs",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(1). // source=1 (outputs)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(800). // single output of 800
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPSUM_both",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(2). // source=2 (both)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(800). // output sum
				AddOp(OP_EQUALVERIFY).
				AddInt64(800). // input sum
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPSUM_outputs_group1",
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group 1
				AddInt64(1). // source=1 (outputs)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(3000). // 1000 + 2000
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPSUM_invalid_source",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(3). // invalid source
				AddOp(OP_INSPECTASSETGROUPSUM),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTOUTASSETCOUNT ==========
		{
			name: "OP_INSPECTOUTASSETCOUNT_output0",
			// Output 0 has assets from both group 0 (800) and group 1 (1000) => 2 entries.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // output index
				AddOp(OP_INSPECTOUTASSETCOUNT).
				AddInt64(2).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTOUTASSETCOUNT_output1",
			// Output 1 has assets from group 1 only (2000) => 1 entry.
			script: txscript.NewScriptBuilder().
				AddInt64(1). // output index
				AddOp(OP_INSPECTOUTASSETCOUNT).
				AddInt64(1).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTOUTASSETCOUNT_no_assets",
			// Output 99 has no asset entries.
			script: txscript.NewScriptBuilder().
				AddInt64(99). // output index with no assets
				AddOp(OP_INSPECTOUTASSETCOUNT).
				AddInt64(0).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTOUTASSETAT ==========
		{
			name: "OP_INSPECTOUTASSETAT_output0_first",
			// Output 0, asset 0: from group 0 (existing asset).
			// Emits the canonical asset_gidx (3), not the packet position (0).
			script: txscript.NewScriptBuilder().
				AddInt64(0). // output index
				AddInt64(0). // asset index
				AddOp(OP_INSPECTOUTASSETAT).
				AddInt64(800). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(3). // canonical asset_gidx (issuance index)
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // asset_txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTOUTASSETAT_out_of_range",
			script: txscript.NewScriptBuilder().
				AddInt64(0).  // output index
				AddInt64(99). // out of range asset index
				AddOp(OP_INSPECTOUTASSETAT),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTOUTASSETLOOKUP ==========
		{
			name: "OP_INSPECTOUTASSETLOOKUP_found",
			script: txscript.NewScriptBuilder().
				AddInt64(0).           // output index
				AddData(assetTxid[:]). // asset_txid
				AddInt64(3).           // canonical asset_gidx
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_1). // verify success flag
				AddOp(OP_EQUALVERIFY).
				AddInt64(800). // expected amount
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTOUTASSETLOOKUP_not_found",
			// Canonical AssetID (assetTxid, 3) exists but its only output is at
			// vout 0, so a lookup at output 1 returns absent.
			script: txscript.NewScriptBuilder().
				AddInt64(1).           // output 1
				AddData(assetTxid[:]). // asset_txid
				AddInt64(3).           // canonical asset_gidx
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_NOT). // flag=0 → NOT → true
				AddOp(OP_VERIFY).
				AddInt64(0). // expected dummy 0
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTINASSETCOUNT ==========
		{
			name: "OP_INSPECTINASSETCOUNT_input0",
			// Input 0 has 1 asset entry (group 0, local input at vin=0).
			script: txscript.NewScriptBuilder().
				AddInt64(0). // input index
				AddOp(OP_INSPECTINASSETCOUNT).
				AddInt64(1).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETCOUNT_input1",
			// Input 1 has 1 asset entry (group 0, intent input at vin=1).
			script: txscript.NewScriptBuilder().
				AddInt64(1). // input index
				AddOp(OP_INSPECTINASSETCOUNT).
				AddInt64(1).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETCOUNT_no_assets",
			script: txscript.NewScriptBuilder().
				AddInt64(99). // input with no assets
				AddOp(OP_INSPECTINASSETCOUNT).
				AddInt64(0).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTINASSETAT ==========
		{
			name: "OP_INSPECTINASSETAT_local",
			// Input 0, asset 0: local input from group 0.
			// Emits the canonical AssetID (asset_txid, asset_gidx=3).
			script: txscript.NewScriptBuilder().
				AddInt64(0). // input index
				AddInt64(0). // asset index
				AddOp(OP_INSPECTINASSETAT).
				AddInt64(500). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(3). // canonical asset_gidx
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // asset_txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETAT_intent",
			// Input 1, asset 0: intent input from group 0.
			// Emits the canonical issuance AssetID, never the intent_txid.
			script: txscript.NewScriptBuilder().
				AddInt64(1). // input index
				AddInt64(0). // asset index
				AddOp(OP_INSPECTINASSETAT).
				AddInt64(300). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(3). // canonical asset_gidx
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // canonical asset_txid (not intent_txid)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETAT_out_of_range",
			script: txscript.NewScriptBuilder().
				AddInt64(0).  // input index
				AddInt64(99). // out of range asset index
				AddOp(OP_INSPECTINASSETAT),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTINASSETLOOKUP ==========
		{
			name: "OP_INSPECTINASSETLOOKUP_local_found",
			// Lookup local input: input 0, canonical AssetID => 500.
			script: txscript.NewScriptBuilder().
				AddInt64(0).           // input index
				AddData(assetTxid[:]). // asset_txid
				AddInt64(3).           // canonical asset_gidx
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddOp(OP_1). // verify success flag
				AddOp(OP_EQUALVERIFY).
				AddInt64(500). // expected amount
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETLOOKUP_intent_found",
			// Lookup intent input by its canonical AssetID => 300.
			script: txscript.NewScriptBuilder().
				AddInt64(1).           // input index
				AddData(assetTxid[:]). // canonical asset_txid (not intent_txid)
				AddInt64(3).           // canonical asset_gidx
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddOp(OP_1). // verify success flag
				AddOp(OP_EQUALVERIFY).
				AddInt64(300). // expected amount
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETLOOKUP_intent_txid_rejected",
			// Supplying the intent_txid instead of the canonical asset_txid
			// must not match: returns absent.
			script: txscript.NewScriptBuilder().
				AddInt64(1).            // input index
				AddData(intentTxid[:]). // intent_txid, not a valid AssetID
				AddInt64(3).            // correct canonical asset_gidx
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddOp(OP_NOT). // flag=0 → NOT → true
				AddOp(OP_VERIFY).
				AddInt64(0). // expected dummy 0
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETLOOKUP_not_found",
			script: txscript.NewScriptBuilder().
				AddInt64(0).           // input index
				AddData(assetTxid[:]). // asset_txid
				AddInt64(5).           // wrong canonical asset_gidx
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddOp(OP_NOT). // flag=0 → NOT → true
				AddOp(OP_VERIFY).
				AddInt64(0). // expected dummy 0
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "large_amount_group_output_read",
			// 3 billion > 2^31-1: would have failed with ErrNumberTooBig under scriptNum.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // item index
				AddInt64(1). // source=1 (output)
				AddOp(OP_INSPECTASSETGROUP).
				AddInt64(3_000_000_000). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // vout
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // type
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: largeAmountPacket},
			},
		},
		{
			name: "large_amount_group_input_read",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // item index
				AddInt64(0). // source=0 (input)
				AddOp(OP_INSPECTASSETGROUP).
				AddInt64(7_000_000_000). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // vin
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // type (local)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: largeAmountPacket},
			},
		},
		{
			name: "large_amount_sum",
			// Sum of 7B + 3B = 10B, well above 2^32.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(2). // source=2 (both)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(3_000_000_000). // output sum
				AddOp(OP_EQUALVERIFY).
				AddInt64(10_000_000_000). // input sum: 7B + 3B
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: largeAmountPacket},
			},
		},
		{
			name: "boundary_amount_sum",
			// MaxUint64 is a legal individual amount, and BigNum sums may
			// exceed uint64 when multiple amounts are aggregated.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(2). // source=2 (both)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddData(maxUint64AmountBytes). // output sum
				AddOp(OP_EQUALVERIFY).
				AddData(maxUint64PlusOneBytes). // input sum: MaxUint64 + 1
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: boundaryAmountPacket},
			},
		},
		{
			name: "large_amount_add",
			// Verify pushed large amount feeds directly into OP_ADD.
			script: txscript.NewScriptBuilder().
				AddInt64(0).                    // group index
				AddInt64(0).                    // source=0 (inputs)
				AddOp(OP_INSPECTASSETGROUPSUM). // pushes 10B
				AddInt64(500_000_000).          // 0.5B
				AddOp(OP_ADD).                  // 10B + 0.5B
				AddInt64(10_500_000_000).       // expected sum
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: largeAmountPacket},
			},
		},
		{
			name: "large_amount_comparison",
			// Verify pushed large amount works with OP_GREATERTHANOREQUAL.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // output index
				AddInt64(0). // asset index
				AddOp(OP_INSPECTOUTASSETAT).
				AddInt64(2_000_000_000).      // threshold
				AddOp(OP_GREATERTHANOREQUAL). // 3B >= 2B → true
				AddOp(OP_VERIFY).
				AddInt64(3). // canonical asset_gidx
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // asset_txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: largeAmountPacket},
			},
		},
		{
			name: "large_amount_lookup_found",
			// Lookup with large amount returns amount.
			script: txscript.NewScriptBuilder().
				AddInt64(0).           // output index
				AddData(assetTxid[:]). // asset_txid
				AddInt64(3).           // canonical asset_gidx
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_1). // verify success flag
				AddOp(OP_EQUALVERIFY).
				AddInt64(3_000_000_000). // expected amount
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: largeAmountPacket},
			},
		},

		// ========== Canonical AssetID: same txid, distinct canonical gidx ==========
		{
			name: "canonical_find_first_of_shared_txid",
			// (assetTxid, 10) resolves to packet position 0.
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]).
				AddInt64(10).
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_1).
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // packet position k
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_find_second_of_shared_txid",
			// (assetTxid, 20) resolves to packet position 1.
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]).
				AddInt64(20).
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_1).
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // packet position k
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_out_at_emits_canonical_gidx",
			// Output 1's first entry belongs to packet group 1 with canonical gidx 20.
			script: txscript.NewScriptBuilder().
				AddInt64(1). // output index
				AddInt64(0). // asset index
				AddOp(OP_INSPECTOUTASSETAT).
				AddInt64(222). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(20). // canonical asset_gidx (not packet position 1)
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_out_lookup_wrong_gidx_absent",
			// Output 0 carries (assetTxid, 10), not (assetTxid, 20).
			script: txscript.NewScriptBuilder().
				AddInt64(0). // output index
				AddData(assetTxid[:]).
				AddInt64(20). // canonical asset_gidx of the other group
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_NOT).
				AddOp(OP_VERIFY).
				AddInt64(0).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_out_lookup_wrong_txid_absent",
			// Right canonical gidx, wrong issuance txid.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // output index
				AddData(ctrlTxid[:]).
				AddInt64(10).
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_NOT).
				AddOp(OP_VERIFY).
				AddInt64(0).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_out_lookup_wrong_output_absent",
			// Valid AssetID (assetTxid, 10) but requested at output 99.
			script: txscript.NewScriptBuilder().
				AddInt64(99). // output index
				AddData(assetTxid[:]).
				AddInt64(10).
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_NOT).
				AddOp(OP_VERIFY).
				AddInt64(0).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},

		// ========== Fresh issuance at nonzero packet position ==========
		{
			name: "canonical_fresh_issuance_group_resolution_round_trip",
			// k OP_INSPECTASSETGROUPASSETID => txHash k ; feeding it back into
			// OP_FINDASSETGROUPBYASSETID recovers the same packet position.
			script: txscript.NewScriptBuilder().
				AddInt64(2). // packet position of the fresh issuance
				AddOp(OP_INSPECTASSETGROUPASSETID).
				// stack: asset_txid asset_gidx
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_1).
				AddOp(OP_EQUALVERIFY).
				AddInt64(2). // recovered packet position k
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_fresh_issuance_output_round_trip",
			// OUTASSETAT emits the fresh issuance's canonical ID; that ID is
			// directly consumable by OUTASSETLOOKUP at the same output.
			script: txscript.NewScriptBuilder().
				AddInt64(1). // output index
				AddInt64(1). // second asset entry is the fresh issuance
				AddOp(OP_INSPECTOUTASSETAT).
				// stack: asset_txid asset_gidx amount
				AddInt64(333).
				AddOp(OP_EQUALVERIFY).
				// stack: asset_txid asset_gidx ; build "o asset_txid asset_gidx".
				AddInt64(1).
				AddOp(OP_ROT).
				AddOp(OP_ROT).
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_1).
				AddOp(OP_EQUALVERIFY).
				AddInt64(333).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},

		// ========== Canonical AssetID operand validation ==========
		{
			name: "canonical_find_negative_gidx_error",
			// OP_2DROP OP_TRUE makes the non-error path succeed, so failure can
			// only come from operand validation rejecting the negative gidx.
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]).
				AddInt64(-1).
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_2DROP).
				AddOp(OP_TRUE),
			cases: []testCase{
				{valid: false, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_find_gidx_too_large_error",
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]).
				AddInt64(65536). // exceeds uint16 ceiling
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_2DROP).
				AddOp(OP_TRUE),
			cases: []testCase{
				{valid: false, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_find_gidx_max_ok",
			// 65535 is in range; a well-formed but absent AssetID returns 0 0.
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]).
				AddInt64(65535).
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_NOT).
				AddOp(OP_VERIFY).
				AddInt64(0).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_find_gidx_oversized_error",
			// A 5-byte ScriptNum exceeds the 4-byte numeric limit.
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]).
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00}).
				AddOp(OP_FINDASSETGROUPBYASSETID),
			cases: []testCase{
				{valid: false, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_find_gidx_non_minimal_error",
			// 10 with a redundant trailing zero byte is non-minimal.
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]).
				AddData([]byte{0x0a, 0x00}).
				AddOp(OP_FINDASSETGROUPBYASSETID),
			cases: []testCase{
				{valid: false, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_find_txid_wrong_length_error",
			script: txscript.NewScriptBuilder().
				AddData(make([]byte, 31)). // not 32 bytes
				AddInt64(10).
				AddOp(OP_FINDASSETGROUPBYASSETID),
			cases: []testCase{
				{valid: false, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_out_lookup_gidx_too_large_error",
			script: txscript.NewScriptBuilder().
				AddInt64(5). // output index
				AddData(assetTxid[:]).
				AddInt64(65536).
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_2DROP).
				AddOp(OP_TRUE),
			cases: []testCase{
				{valid: false, assetPacket: sameTxidPacket},
			},
		},
		{
			name: "canonical_in_lookup_txid_wrong_length_error",
			script: txscript.NewScriptBuilder().
				AddInt64(5).               // input index
				AddData(make([]byte, 33)). // not 32 bytes
				AddInt64(10).
				AddOp(OP_INSPECTINASSETLOOKUP),
			cases: []testCase{
				{valid: false, assetPacket: sameTxidPacket},
			},
		},

		// ========== Control asset canonical resolution ==========
		{
			name: "canonical_ctrl_by_group_fresh_issuance",
			// Group 1's control references group 0 by packet index; group 0 is a
			// fresh issuance, so the control AssetID resolves to (txHash, 0).
			script: txscript.NewScriptBuilder().
				AddInt64(1).
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddOp(OP_1).
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // canonical asset_gidx of the referenced fresh issuance
				AddOp(OP_EQUALVERIFY).
				AddData(simpleTxHash[:]).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: ctrlByGroupFreshPacket},
			},
		},
	}

	for _, test := range tests {
		for caseIndex, c := range test.cases {
			t.Run(fmt.Sprintf("%s_%d", test.name, caseIndex), func(tt *testing.T) {
				script, err := test.script.Script()
				if err != nil {
					tt.Fatalf("Script build failed: %v", err)
				}

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

				if c.assetPacket != nil {
					engine.SetAssetPacket(c.assetPacket)
				}

				err = engine.Execute()
				if c.valid && err != nil {
					tt.Errorf("Execute failed: %v", err)
				}
				if !c.valid && err == nil {
					tt.Errorf("Execute should have failed")
				}
			})
		}
	}
}
