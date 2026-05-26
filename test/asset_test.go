package test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/emulator/pkg/arkade"
	emulatorclient "github.com/ArkLabsHQ/emulator/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestOffchainTxWithAsset tests an offchain transaction with asset introspection opcodes.
// The test creates a simple asset packet with one asset group (issuance) and verifies
// that the arkade script can correctly inspect the asset using the introspection opcodes.
func TestOffchainTxWithAsset(t *testing.T) {
	ctx := t.Context()
	alice, grpcAlice := setupArkSDK(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	const (
		sendAmount  = 10000
		assetAmount = 1000
	)

	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice, sendAmount)

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	assetPacket := createIssuanceAssetPacket(t, 0, assetAmount)
	// Asset packet at index 0, P2A at index 1
	arkadeScript := createArkadeScriptWithAssetIntrospection(t, alicePkScript, assetAmount)
	emulatorClient, publicKey, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	vtxoScript := createVtxoScriptWithArkadeScript(bobPubKey, aliceAddr.Signer, publicKey, arkade.ArkadeScriptHash(arkadeScript))

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	bobAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     aliceAddr.Signer,
	}

	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(arkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	bobAddrStr, err := bobAddr.EncodeV0()
	require.NoError(t, err)

	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	indexerSvc := setupIndexer(t)

	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTx)
	require.Len(t, fundingTx.Txs, 1)

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	var bobOutput *wire.TxOut
	var bobOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(bobAddr.VtxoTapKey)) {
			bobOutput = out
			bobOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, bobOutput)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	// Build transaction with asset packet
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				Outpoint: &wire.OutPoint{
					Hash:  redeemPtx.UnsignedTx.TxHash(),
					Index: bobOutputIndex,
				},
				Tapscript:          tapscript,
				Amount:             bobOutput.Value,
				RevealedTapscripts: []string{hex.EncodeToString(arkadeTapscript)},
			},
		},
		[]*wire.TxOut{
			{
				Value:    bobOutput.Value,
				PkScript: alicePkScript,
			},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addAssetPacketToTx(t, validTx, assetPacket)

	// Add the emulator packet with the arkade script for input 0
	addEmulatorPacket(t, validTx, []arkade.EmulatorEntry{
		{Vin: 0, Script: arkadeScript},
	})

	encodedValidTx, err := validTx.B64Encode()
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(
		ctx,
		explorer,
		encodedValidTx,
	)
	require.NoError(t, err)

	encodedValidCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, checkpoint := range validCheckpoints {
		encoded, err := checkpoint.B64Encode()
		require.NoError(t, err)

		signed, err := bobWallet.SignTransaction(
			ctx,
			explorer,
			encoded,
		)
		require.NoError(t, err)

		encodedValidCheckpoints = append(encodedValidCheckpoints, signed)
	}

	waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, validTx, 0)

	// Submit to emulator - should succeed as the asset introspection opcodes will validate correctly
	_, _, err = emulatorClient.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)

	waitForVtxos()
}

// TestSettlementWithAsset tests the settlement flow with an asset packet in the intent.
// First mints the asset via an offchain tx, then settles the resulting VTXO with a transfer packet.
func TestSettlementWithAsset(t *testing.T) {
	ctx := t.Context()
	alice, grpcClient := setupArkSDK(t)
	t.Cleanup(func() {
		grpcClient.Close()
	})

	const (
		sendAmount  = 10000
		assetAmount = 1000
	)

	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice, sendAmount)
	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	emulatorClient, publicKey, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	// =========================================================================
	// Phase 1: Create settle and mint contract addresses
	// =========================================================================

	// Settle arkade script: checks output goes to Alice, 1 asset group, sum = assetAmount
	settleArkadeScript := createArkadeScriptWithAssetIntrospection(t, alicePkScript, assetAmount)
	settleVtxoScript := createVtxoScriptWithArkadeAndCSV(bobPubKey, aliceAddr.Signer, publicKey, arkade.ArkadeScriptHash(settleArkadeScript))
	settleContractTapKey, settleContractTapTree, err := settleVtxoScript.TapTree()
	require.NoError(t, err)

	settleContractPkScript, err := script.P2TRScript(settleContractTapKey)
	require.NoError(t, err)

	// Mint arkade script: checks output goes to settle contract, 1 asset group, sum = assetAmount
	mintArkadeScript := createArkadeScriptWithAssetIntrospection(t, settleContractPkScript, assetAmount)
	mintVtxoScript := createVtxoScriptWithArkadeScript(bobPubKey, aliceAddr.Signer, publicKey, arkade.ArkadeScriptHash(mintArkadeScript))
	mintContractTapKey, mintContractTapTree, err := mintVtxoScript.TapTree()
	require.NoError(t, err)

	mintContractAddress := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: mintContractTapKey,
		Signer:     aliceAddr.Signer,
	}

	mintClosure := mintVtxoScript.ForfeitClosures()[0]
	mintArkadeTapscript, err := mintClosure.Script()
	require.NoError(t, err)

	mintMerkleProof, err := mintContractTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(mintArkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	mintCtrlBlock, err := txscript.ParseControlBlock(mintMerkleProof.ControlBlock)
	require.NoError(t, err)

	mintTapscript := &waddrmgr.Tapscript{
		ControlBlock:   mintCtrlBlock,
		RevealedScript: mintMerkleProof.Script,
	}

	// =========================================================================
	// Phase 2: Mint asset via offchain tx
	// =========================================================================

	mintContractAddressStr, err := mintContractAddress.EncodeV0()
	require.NoError(t, err)

	// Alice sends to the mint contract address
	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: mintContractAddressStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	indexerSvc := setupIndexer(t)

	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTx)
	require.Len(t, fundingTx.Txs, 1)

	mintInputPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	var mintVtxoOutput *wire.TxOut
	var mintVtxoOutputIndex uint32
	for i, out := range mintInputPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(mintContractAddress.VtxoTapKey)) {
			mintVtxoOutput = out
			mintVtxoOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, mintVtxoOutput)

	infos, err := grpcClient.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	// Build mint offchain tx: input = mint VTXO, output = settle contract address
	mintTx, mintCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				Outpoint: &wire.OutPoint{
					Hash:  mintInputPtx.UnsignedTx.TxHash(),
					Index: mintVtxoOutputIndex,
				},
				Tapscript:          mintTapscript,
				Amount:             mintVtxoOutput.Value,
				RevealedTapscripts: []string{hex.EncodeToString(mintArkadeTapscript)},
			},
		},
		[]*wire.TxOut{
			{
				Value:    mintVtxoOutput.Value,
				PkScript: settleContractPkScript,
			},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	// Add issuance asset packet to the mint tx
	issuancePacket := createIssuanceAssetPacket(t, 0, assetAmount)
	addAssetPacketToTx(t, mintTx, issuancePacket)

	// Add the emulator packet with the mint arkade script for input 0
	addEmulatorPacket(t, mintTx, []arkade.EmulatorEntry{
		{Vin: 0, Script: mintArkadeScript},
	})

	encodedMintTx, err := mintTx.B64Encode()
	require.NoError(t, err)

	signedMintTx, err := bobWallet.SignTransaction(ctx, explorer, encodedMintTx)
	require.NoError(t, err)

	encodedMintCheckpoints := make([]string, 0, len(mintCheckpoints))
	for _, checkpoint := range mintCheckpoints {
		encoded, err := checkpoint.B64Encode()
		require.NoError(t, err)

		signed, err := bobWallet.SignTransaction(ctx, explorer, encoded)
		require.NoError(t, err)
		encodedMintCheckpoints = append(encodedMintCheckpoints, signed)
	}

	waitForMintVtxo := watchForPreconfirmedVtxos(t, indexerSvc, mintTx, 0)

	// Submit mint tx to emulator
	_, _, err = emulatorClient.SubmitTx(ctx, signedMintTx, encodedMintCheckpoints)
	require.NoError(t, err)

	waitForMintVtxo()

	// =========================================================================
	// Phase 3: Settle the VTXO with a transfer asset packet
	// =========================================================================

	// Retrieve the mint tx to find the settle VTXO
	mintResult, err := indexerSvc.GetVirtualTxs(ctx, []string{mintTx.UnsignedTx.TxID()})
	require.NoError(t, err)
	require.NotEmpty(t, mintResult)
	require.Len(t, mintResult.Txs, 1)

	mintResultPtx, err := psbt.NewFromRawBytes(strings.NewReader(mintResult.Txs[0]), true)
	require.NoError(t, err)

	var settleVtxoOutput *wire.TxOut
	var settleVtxoOutputIndex uint32
	for i, out := range mintResultPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(settleContractTapKey)) {
			settleVtxoOutput = out
			settleVtxoOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, settleVtxoOutput)

	// Build the settlement intent
	settleClosure := settleVtxoScript.ForfeitClosures()[0]
	settleArkadeTapscript, err := settleClosure.Script()
	require.NoError(t, err)

	settleMerkleProof, err := settleContractTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(settleArkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	settleCtrlBlock, err := txscript.ParseControlBlock(settleMerkleProof.ControlBlock)
	require.NoError(t, err)

	randomKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	treeSignerSession := tree.NewTreeSignerSession(randomKey)

	message, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		OnchainOutputIndexes: nil,
		ExpireAt:             0,
		ValidAt:              0,
		CosignersPublicKeys:  []string{treeSignerSession.GetPublicKey()},
	}.Encode()
	require.NoError(t, err)

	intentProof, err := intent.New(
		message,
		[]intent.Input{
			{
				OutPoint: &wire.OutPoint{
					Hash:  mintResultPtx.UnsignedTx.TxHash(),
					Index: settleVtxoOutputIndex,
				},
				Sequence:    wire.MaxTxInSequenceNum,
				WitnessUtxo: settleVtxoOutput,
			},
		},
		[]*wire.TxOut{
			{
				Value:    settleVtxoOutput.Value,
				PkScript: alicePkScript,
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, intentProof)

	// Add TRANSFER asset packet (not issuance!) referencing the minted asset
	mintTxHash := mintResultPtx.UnsignedTx.TxHash()
	transferPacket := createTransferAssetPacket(t, mintTxHash, 0, 1, 0, uint64(assetAmount))
	transferExt := extension.Extension{transferPacket}
	transferPacketOut, err := transferExt.TxOut()
	require.NoError(t, err)
	intentProof.UnsignedTx.AddTxOut(transferPacketOut)
	intentProof.Outputs = append(intentProof.Outputs, psbt.POutput{})

	settleTapscripts, err := settleVtxoScript.Encode()
	require.NoError(t, err)
	taptreeField, err := txutils.VtxoTaprootTreeField.Encode(settleTapscripts)
	require.NoError(t, err)

	settleCtrlBlockBytes, err := settleCtrlBlock.ToBytes()
	require.NoError(t, err)

	tapLeafScript := []*psbt.TaprootTapLeafScript{
		{
			LeafVersion:  txscript.BaseLeafVersion,
			ControlBlock: settleCtrlBlockBytes,
			Script:       settleMerkleProof.Script,
		},
	}
	intentProof.Inputs[0].TaprootLeafScript = tapLeafScript
	intentProof.Inputs[1].TaprootLeafScript = tapLeafScript
	intentProof.Inputs[0].Unknowns = append(intentProof.Inputs[0].Unknowns, taptreeField)
	intentProof.Inputs[1].Unknowns = append(intentProof.Inputs[1].Unknowns, taptreeField)

	intentPtx := &intentProof.Packet
	addEmulatorPacket(t, intentPtx, []arkade.EmulatorEntry{
		{Vin: 1, Script: settleArkadeScript},
	})

	encodedIntentProof, err := intentPtx.B64Encode()
	require.NoError(t, err)

	signedIntentProof, err := bobWallet.SignTransaction(ctx, explorer, encodedIntentProof)
	require.NoError(t, err)
	require.NotEqual(t, signedIntentProof, encodedIntentProof)

	// Submit intent to emulator (validates the settle arkade script with transfer packet)
	approvedIntentProof, err := emulatorClient.SubmitIntent(ctx, emulatorclient.Intent{
		Proof:   signedIntentProof,
		Message: message,
	})
	require.NoError(t, err)

	signedIntent := emulatorclient.Intent{
		Proof:   approvedIntentProof,
		Message: message,
	}

	intentId, err := grpcClient.RegisterIntent(ctx, signedIntent.Proof, signedIntent.Message)
	require.NoError(t, err)

	vtxo := client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: mintResultPtx.UnsignedTx.TxHash().String(),
				VOut: settleVtxoOutputIndex,
			},
			Script: hex.EncodeToString(settleArkadeTapscript),
			Amount: uint64(settleVtxoOutput.Value),
		},
		Tapscripts: settleTapscripts,
	}

	emulatorBatchHandler := &delegateBatchEventsHandler{
		intentId:       intentId,
		intent:         signedIntent,
		vtxosToForfeit: []client.TapscriptsVtxo{vtxo},
		signerSession:  treeSignerSession,
		emulatorClient: emulatorClient,
		wallet:         bobWallet,
		client:         grpcClient,
	}

	topics := arksdk.GetEventStreamTopics([]types.Outpoint{vtxo.Outpoint}, []tree.SignerSession{treeSignerSession})
	eventStream, stop, err := grpcClient.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(func() {
		stop()
	})

	commitmentTxid, err := arksdk.JoinBatchSession(ctx, eventStream, emulatorBatchHandler)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
}

// addAssetPacketToTx adds the asset packet to the transaction as an OP_RETURN output (before the last output, which is the P2A)
func addAssetPacketToTx(t *testing.T, tx *psbt.Packet, assetPacket asset.Packet) {
	ext := extension.Extension{assetPacket}
	assetPacketOut, err := ext.TxOut()
	require.NoError(t, err)
	p2aOutputIndex := len(tx.UnsignedTx.TxOut) - 1
	p2aOutput := tx.UnsignedTx.TxOut[p2aOutputIndex]
	tx.UnsignedTx.TxOut[p2aOutputIndex] = assetPacketOut
	tx.UnsignedTx.AddTxOut(p2aOutput)
	tx.Outputs = append(tx.Outputs, psbt.POutput{})
}
