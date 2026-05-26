package test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/emulator/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Packet type 2 for contract state (0=assets, 1=emulator).
const statePacketType = 2

// Fixed state payload carried by the main contract across spends.
var fixedStatePayload = uint64LE(0xdeadbeef)

// TestContractIdWithAssetIdentity exercises the contract identity pattern:
//   - A main contract carries a unique asset (contract ID) and fixed state.
//     It enforces output continuation (same script, asset forwarded, state preserved).
//   - A reader contract is co-spent with the main contract, verifies the main
//     contract's asset identity via OP_INSPECTINASSETLOOKUP, and reads the state
//     from the current transaction's packet.
func TestContractIdWithAssetIdentity(t *testing.T) {
	ctx := t.Context()

	alice, aliceWallet, alicePubKey, grpcClient := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcClient.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 50000)

	emulatorClient, emulatorPubKey, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	infos, err := grpcClient.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)
	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	// Recipient for the reader's value after the co-spend.
	recipientKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	recipientPkScript, err := txscript.PayToTaprootScript(recipientKey.PubKey())
	require.NoError(t, err)

	encodeCheckpoints := func(checkpoints []*psbt.Packet) []string {
		encodedCheckpoints := make([]string, 0, len(checkpoints))
		for _, checkpoint := range checkpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}
		return encodedCheckpoints
	}

	submitWithArkd := func(candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, candidateTx, 0)

		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		signedTx, err := aliceWallet.SignTransaction(ctx, explorer, encodedTx)
		require.NoError(t, err)

		txid, _, signedCheckpoints, err := grpcClient.SubmitTx(ctx, signedTx, encodeCheckpoints(checkpoints))
		require.NoError(t, err)
		require.NotEmpty(t, txid)
		require.NotEmpty(t, signedCheckpoints)

		finalCheckpoints := make([]string, 0, len(signedCheckpoints))
		for _, checkpoint := range signedCheckpoints {
			signedCheckpoint, err := aliceWallet.SignTransaction(ctx, explorer, checkpoint)
			require.NoError(t, err)
			finalCheckpoints = append(finalCheckpoints, signedCheckpoint)
		}

		require.NoError(t, grpcClient.FinalizeTx(ctx, txid, finalCheckpoints))

		waitForVtxos()
	}

	submitWithEmulator := func(candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, candidateTx, 0)

		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		_, _, err = emulatorClient.SubmitTx(ctx, encodedTx, encodeCheckpoints(checkpoints))
		require.NoError(t, err)

		waitForVtxos()
	}

	// =========================================================================
	// Phase 1: Compile the main contract.
	// =========================================================================

	mainArkadeScript := mainContractArkadeScript(t)
	mainVtxoScript := createArkadeOnlyVtxoScript(
		aliceAddr.Signer,
		emulatorPubKey,
		arkade.ArkadeScriptHash(mainArkadeScript),
	)
	mainTapscript := onlyForfeitScript(t, mainVtxoScript)
	mainPkScript := p2trScriptForVtxoScript(t, mainVtxoScript)

	// =========================================================================
	// Phase 2: Bootstrap the main contract directly from Alice's wallet UTXO.
	// =========================================================================

	exitDelayType := arklib.LocktimeTypeBlock
	if infos.UnilateralExitDelay >= 512 {
		exitDelayType = arklib.LocktimeTypeSecond
	}
	fundingVtxoScript := script.NewDefaultVtxoScript(
		alicePubKey,
		aliceAddr.Signer,
		arklib.RelativeLocktime{
			Type:  exitDelayType,
			Value: uint32(infos.UnilateralExitDelay),
		},
	)
	fundingTapscript := onlyForfeitScript(t, *fundingVtxoScript)
	fundingTapKey, _, err := fundingVtxoScript.TapTree()
	require.NoError(t, err)

	fundingPkScript, err := script.P2TRScript(fundingTapKey)
	require.NoError(t, err)
	spendableVtxos, _, err := alice.ListVtxos(ctx)
	require.NoError(t, err)

	var fundingVtxo types.Vtxo
	for _, vtxo := range spendableVtxos {
		if vtxo.Script == hex.EncodeToString(fundingPkScript) {
			fundingVtxo = vtxo
			break
		}
	}
	require.NotEmpty(t, fundingVtxo.Txid)

	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingVtxo.Txid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	fundingOutputIndex, fundingOutput := findTaprootOutput(t, fundingPtx.UnsignedTx, fundingTapKey)
	require.Equal(t, fundingVtxo.VOut, fundingOutputIndex)
	require.Equal(t, int64(fundingVtxo.Amount), fundingOutput.Value)

	fundingInput := vtxoInputFromScriptOutput(
		t,
		fundingPtx.UnsignedTx,
		fundingOutputIndex,
		*fundingVtxoScript,
		fundingTapscript,
	)

	const mainContractValue = int64(20000)
	changeValue := fundingOutput.Value - mainContractValue
	require.Positive(t, changeValue)

	// Build the bootstrap tx: Alice's wallet UTXO -> main contract UTXO + Alice change.
	bootstrapTx, bootstrapCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{fundingInput},
		[]*wire.TxOut{
			{Value: mainContractValue, PkScript: mainPkScript},
			{Value: changeValue, PkScript: fundingPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	// Genesis asset issuance: 1 unit at output 0.
	issuancePacket := createIssuanceAssetPacket(t, 0, 1)
	addAssetPacketToTx(t, bootstrapTx, issuancePacket)

	// State packet with fixed payload.
	addStatePacket(t, bootstrapTx, fixedStatePayload)

	submitWithArkd(bootstrapTx, bootstrapCheckpoints)

	// =========================================================================
	// Phase 3: Compile the reader contract (needs the asset genesis tx hash).
	// =========================================================================

	bootstrapTxHash := bootstrapTx.UnsignedTx.TxHash()

	readerArkadeScript := readerContractArkadeScript(t, bootstrapTxHash)
	readerVtxoScript := createArkadeOnlyVtxoScript(
		aliceAddr.Signer,
		emulatorPubKey,
		arkade.ArkadeScriptHash(readerArkadeScript),
	)
	readerTapscript := onlyForfeitScript(t, readerVtxoScript)
	readerTapKey, _, err := readerVtxoScript.TapTree()
	require.NoError(t, err)

	// =========================================================================
	// Phase 4: Fund the reader UTXO.
	// =========================================================================

	readerAddress := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: readerTapKey,
		Signer:     aliceAddr.Signer,
	}
	readerAddr, err := readerAddress.EncodeV0()
	require.NoError(t, err)

	readerTxid, err := alice.SendOffChain(
		ctx,
		[]types.Receiver{{To: readerAddr, Amount: 10000}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, readerTxid)

	readerTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{readerTxid})
	require.NoError(t, err)
	require.Len(t, readerTxs.Txs, 1)

	readerPtx, err := psbt.NewFromRawBytes(strings.NewReader(readerTxs.Txs[0]), true)
	require.NoError(t, err)

	readerOutputIndex, _ := findTaprootOutput(t, readerPtx.UnsignedTx, readerTapKey)
	readerInput := vtxoInputFromScriptOutput(
		t,
		readerPtx.UnsignedTx,
		readerOutputIndex,
		readerVtxoScript,
		readerTapscript,
	)

	// =========================================================================
	// Phase 5: Co-spend main + reader.
	// =========================================================================

	// Build the main contract input from the bootstrap tx output.
	mainInput := vtxoInputFromScriptOutput(
		t,
		bootstrapTx.UnsignedTx,
		0,
		mainVtxoScript,
		mainTapscript,
	)

	coSpendTx, coSpendCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{mainInput, readerInput},
		[]*wire.TxOut{
			{Value: mainInput.Amount, PkScript: mainPkScript},
			{Value: readerInput.Amount, PkScript: recipientPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	// Transfer asset packet: forward the asset from input 0 to output 0.
	transferPacket := createTransferAssetPacket(t, bootstrapTxHash, 0, 0, 0, 1)
	addAssetPacketToTx(t, coSpendTx, transferPacket)

	// State packet with the same fixed payload.
	addStatePacket(t, coSpendTx, fixedStatePayload)

	// Emulator packet for both inputs.
	addEmulatorPacket(t, coSpendTx, []arkade.EmulatorEntry{
		{Vin: 0, Script: mainArkadeScript},
		{Vin: 1, Script: readerArkadeScript},
	})

	// The main contract needs the bootstrap tx for OP_INSPECTINPUTPACKET.
	require.NoError(t, txutils.SetArkPsbtField(coSpendTx, 0, arkade.PrevArkTxField, *bootstrapTx.UnsignedTx))

	require.NoError(t, executeArkadeScripts(t, coSpendTx, coSpendCheckpoints, emulatorPubKey))
	submitWithEmulator(coSpendTx, coSpendCheckpoints)
}

// mainContractArkadeScript builds the recursive main contract script. It verifies:
//   - Discovers own asset ID at runtime via OP_INSPECTASSETGROUPASSETID
//   - Current input carries the group-0 contract ID asset with amount 1
//   - Contract ID asset is forwarded to output 0 with amount 1
//   - Current input and output 0 each carry exactly one asset
//   - Previous state packet exists (OP_INSPECTINPUTPACKET)
//   - Current state packet preserves the previous payload (OP_INSPECTPACKET)
//   - Output 0 scriptpubkey == input scriptpubkey (continuation)
//   - Value is preserved
func mainContractArkadeScript(t *testing.T) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		// Verify this input carries exactly one asset.
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINASSETCOUNT).
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY).

		// Discover the group-0 asset ID and verify this input carries it.
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddInt64(0). // group index for OP_INSPECTASSETGROUPASSETID
		AddOp(arkade.OP_INSPECTASSETGROUPASSETID).
		AddOp(arkade.OP_INSPECTINASSETLOOKUP).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // found flag == 1
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY). // amount == 1

		// Verify the same group-0 asset is forwarded to output 0.
		AddInt64(0). // output index for OP_INSPECTOUTASSETLOOKUP
		AddInt64(0). // group index for OP_INSPECTASSETGROUPASSETID
		AddOp(arkade.OP_INSPECTASSETGROUPASSETID).
		AddOp(arkade.OP_INSPECTOUTASSETLOOKUP).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // found flag == 1
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY). // amount == 1

		// Verify output 0 carries no other assets.
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTASSETCOUNT).
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY).

		// Read previous state payload and keep it on the stack.
		AddInt64(statePacketType).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).

		// Verify current state preserves the previous payload.
		AddInt64(statePacketType).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_EQUALVERIFY).

		// Verify output continuation: output 0 scriptpubkey == input scriptpubkey.
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_EQUALVERIFY).

		// Verify value preserved (final check leaves result on stack).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

// readerContractArkadeScript builds the reader contract script. It verifies:
//   - Input 0 carries the expected asset via OP_INSPECTINASSETLOOKUP
//   - Current transaction's state packet matches the fixed payload
func readerContractArkadeScript(t *testing.T, mainAssetTxid chainhash.Hash) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		// Verify main contract asset at input 0.
		AddInt64(0).               // input index
		AddData(mainAssetTxid[:]). // asset txid (genesis tx hash)
		AddInt64(0).               // group index in current packet
		AddOp(arkade.OP_INSPECTINASSETLOOKUP).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // found flag == 1
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY). // amount == 1

		// Read and verify state from current transaction packet.
		AddInt64(statePacketType).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(fixedStatePayload).
		AddOp(arkade.OP_EQUAL). // final check
		Script()
	require.NoError(t, err)

	return arkadeScript
}

func addStatePacket(t *testing.T, ptx *psbt.Packet, payload []byte) {
	t.Helper()

	addExtensionPacket(t, ptx, extension.UnknownPacket{
		PacketType: statePacketType,
		Data:       payload,
	})
}
