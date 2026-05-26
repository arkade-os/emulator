package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func TestDeprecatedKeySigning(t *testing.T) {
	ctx := t.Context()

	emulatorClient, _, _ := setupEmulatorClient(t, ctx)

	info, err := emulatorClient.GetInfo(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, info.DeprecatedSignerPublicKeys)

	deprecatedPubKeyBytes, err := hex.DecodeString(
		info.DeprecatedSignerPublicKeys[len(info.DeprecatedSignerPublicKeys)-1],
	)
	require.NoError(t, err)
	deprecatedPubKey, err := btcec.ParsePubKey(deprecatedPubKeyBytes)
	require.NoError(t, err)

	t.Run("SubmitTx signs offchain transaction", func(t *testing.T) {
		runSubmitTxWithDeprecatedKey(t, ctx, emulatorClient, deprecatedPubKey)
	})

	t.Run("SubmitIntent and SubmitFinalization complete batch", func(t *testing.T) {
		runSubmitIntentFinalizationWithDeprecatedKey(t, ctx, emulatorClient, deprecatedPubKey)
	})

	t.Run("SubmitOnchainTx signs onchain PSBT", func(t *testing.T) {
		runSubmitOnchainWithDeprecatedKey(t, ctx, emulatorClient, deprecatedPubKey)
	})
}

func runSubmitTxWithDeprecatedKey(
	t *testing.T,
	ctx context.Context,
	emulatorClient emulatorclient.TransportClient,
	deprecatedPubKey *btcec.PublicKey,
) {
	t.Helper()

	alice, grpcAlice := setupArkSDK(t)
	t.Cleanup(func() { grpcAlice.Close() })
	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice, 10_000)
	indexerSvc := setupIndexer(t)
	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)
	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(alicePkScript[2:]).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey, aliceAddr.Signer, deprecatedPubKey, arkade.ArkadeScriptHash(arkadeScript),
	)
	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	closure := vtxoScript.ForfeitClosures()[0]
	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)
	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(arkadeTapscript).TapHash())
	require.NoError(t, err)
	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)
	tapscript := &waddrmgr.Tapscript{ControlBlock: ctrlBlock, RevealedScript: merkleProof.Script}

	contractAddress := arklib.Address{HRP: "tark", VtxoTapKey: vtxoTapKey, Signer: aliceAddr.Signer}
	contractAddressStr, err := contractAddress.EncodeV0()
	require.NoError(t, err)

	txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: contractAddressStr, Amount: 10_000}})
	require.NoError(t, err)
	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	tx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{{
			Outpoint:  &wire.OutPoint{Hash: redeemPtx.UnsignedTx.TxHash(), Index: 0},
			Tapscript: tapscript,
			Amount:    10_000,
			RevealedTapscripts: []string{
				hex.EncodeToString(arkadeTapscript),
			},
		}},
		[]*wire.TxOut{{Value: 10_000, PkScript: alicePkScript}},
		checkpointScriptBytes,
	)
	require.NoError(t, err)
	addEmulatorPacket(t, tx, []arkade.EmulatorEntry{{Vin: 0, Script: arkadeScript}})

	encodedTx, err := tx.B64Encode()
	require.NoError(t, err)
	signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
	require.NoError(t, err)
	signedCheckpoints := make([]string, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		encoded, err := checkpoint.B64Encode()
		require.NoError(t, err)
		signed, err := bobWallet.SignTransaction(ctx, explorer, encoded)
		require.NoError(t, err)
		signedCheckpoints = append(signedCheckpoints, signed)
	}

	waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, tx, 0)
	_, _, err = emulatorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
	require.NoError(t, err)
	waitForVtxos()
}

func runSubmitIntentFinalizationWithDeprecatedKey(
	t *testing.T,
	ctx context.Context,
	emulatorClient emulatorclient.TransportClient,
	deprecatedPubKey *btcec.PublicKey,
) {
	t.Helper()

	alice, aliceWallet, alicePubKey, grpcClient := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcClient.Close() })
	aliceAddr := fundAndSettleAlice(t, ctx, alice, 100_000)
	indexerSvc := setupIndexer(t)
	explorerSvc, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	delegateArkadeScript := enforceSelfSend(t)
	delegateVtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					aliceAddr.Signer,
					arkade.ComputeArkadeScriptPublicKey(
						deprecatedPubKey,
						arkade.ArkadeScriptHash(delegateArkadeScript),
					),
				},
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{alicePubKey}},
				Locktime: arklib.RelativeLocktime{
					Type:  arklib.LocktimeTypeSecond,
					Value: delegateExitDelay,
				},
			},
		},
	}
	delegateTapscript := onlyForfeitScript(t, delegateVtxoScript)
	delegatePkScript := p2trScriptForVtxoScript(t, delegateVtxoScript)
	delegateRevealedTapscripts, err := delegateVtxoScript.Encode()
	require.NoError(t, err)
	delegateInput, fundingTx := fundDelegate(
		t, ctx, alice, indexerSvc, aliceAddr.Signer, delegateVtxoScript, delegateAmount,
	)

	cosignerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerSession := tree.NewTreeSignerSession(cosignerKey)
	message, err := intent.RegisterMessage{
		BaseMessage:         intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		CosignersPublicKeys: []string{signerSession.GetPublicKey()},
	}.Encode()
	require.NoError(t, err)

	proof, err := intent.New(
		message,
		[]intent.Input{{
			OutPoint: delegateInput.Outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    delegateAmount,
				PkScript: delegatePkScript,
			},
		}},
		[]*wire.TxOut{{Value: delegateAmount, PkScript: delegatePkScript}},
	)
	require.NoError(t, err)
	ctrlBlockBytes, err := delegateInput.Tapscript.ControlBlock.ToBytes()
	require.NoError(t, err)
	tapLeafScript := []*psbt.TaprootTapLeafScript{{
		LeafVersion:  txscript.BaseLeafVersion,
		ControlBlock: ctrlBlockBytes,
		Script:       delegateTapscript,
	}}
	taptreeField, err := txutils.VtxoTaprootTreeField.Encode(delegateRevealedTapscripts)
	require.NoError(t, err)
	proof.Inputs[0].TaprootLeafScript = tapLeafScript
	proof.Inputs[1].TaprootLeafScript = tapLeafScript
	proof.Inputs[0].Unknowns = append(proof.Inputs[0].Unknowns, taptreeField)
	proof.Inputs[1].Unknowns = append(proof.Inputs[1].Unknowns, taptreeField)

	intentPtx := &proof.Packet
	addEmulatorPacket(t, intentPtx, []arkade.EmulatorEntry{{Vin: 1, Script: delegateArkadeScript}})
	require.NoError(t, txutils.SetArkPsbtField(intentPtx, 1, arkade.PrevArkTxField, *fundingTx))
	require.NoError(t, executeArkadeScripts(t, intentPtx, nil, deprecatedPubKey))
	encodedProof, err := intentPtx.B64Encode()
	require.NoError(t, err)

	approvedProof, err := emulatorClient.SubmitIntent(ctx, emulatorclient.Intent{
		Proof:   encodedProof,
		Message: message,
	})
	require.NoError(t, err)
	signedIntent := emulatorclient.Intent{Proof: approvedProof, Message: message}
	intentID, err := grpcClient.RegisterIntent(ctx, signedIntent.Proof, signedIntent.Message)
	require.NoError(t, err)

	vtxo := client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: delegateInput.Outpoint.Hash.String(),
				VOut: delegateInput.Outpoint.Index,
			},
			Script: hex.EncodeToString(delegateTapscript),
			Amount: uint64(delegateAmount),
		},
		Tapscripts: delegateRevealedTapscripts,
	}
	batchHandler := &delegateBatchEventsHandler{
		intentId:       intentID,
		intent:         signedIntent,
		vtxosToForfeit: []client.TapscriptsVtxo{vtxo},
		signerSession:  signerSession,
		emulatorClient: emulatorClient,
		wallet:         aliceWallet,
		client:         grpcClient,
		explorer:       explorerSvc,
	}
	topics := arksdk.GetEventStreamTopics([]types.Outpoint{vtxo.Outpoint}, []tree.SignerSession{signerSession})
	eventStream, stop, err := grpcClient.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(stop)
	commitmentTxid, err := arksdk.JoinBatchSession(
		ctx, eventStream, &capturingBatchEventsHandler{delegateBatchEventsHandler: batchHandler},
	)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
}

func runSubmitOnchainWithDeprecatedKey(
	t *testing.T,
	ctx context.Context,
	emulatorClient emulatorclient.TransportClient,
	deprecatedPubKey *btcec.PublicKey,
) {
	t.Helper()

	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	aliceKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	const (
		fundingAmount int64 = 1_000_000
		feeAmount     int64 = 500
		spendAmount         = fundingAmount - feeAmount
	)
	bobPkScript, err := txscript.PayToTaprootScript(bobPubKey)
	require.NoError(t, err)
	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(bobPkScript[2:]).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(spendAmount).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)
	arkadeScriptHash := arkade.ArkadeScriptHash(arkadeScript)
	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey, aliceKey.PubKey(), deprecatedPubKey, arkadeScriptHash,
	)
	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	closure := vtxoScript.ForfeitClosures()[0]
	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)
	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(arkadeTapscript).TapHash())
	require.NoError(t, err)

	tapAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(vtxoTapKey), getRegtestParams(t))
	require.NoError(t, err)
	_, err = runCommand("nigiri", "faucet", tapAddr.EncodeAddress(), "0.01")
	require.NoError(t, err)
	explorerSvc, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)
	fundingUtxo := waitForUtxo(t, explorerSvc, tapAddr.EncodeAddress(), 60*time.Second)
	_, err = runCommand("nigiri", "rpc", "-generate", "1")
	require.NoError(t, err)
	rawFundingHex, err := explorerSvc.GetTxHex(fundingUtxo.Txid)
	require.NoError(t, err)
	rawFundingBytes, err := hex.DecodeString(rawFundingHex)
	require.NoError(t, err)
	rawFundingTx := wire.NewMsgTx(wire.TxVersion)
	require.NoError(t, rawFundingTx.Deserialize(bytes.NewReader(rawFundingBytes)))
	contractPkScript, err := script.P2TRScript(vtxoTapKey)
	require.NoError(t, err)

	var fundingOutput *wire.TxOut
	var fundingVout uint32
	for i, out := range rawFundingTx.TxOut {
		if bytes.Equal(out.PkScript, contractPkScript) {
			fundingOutput = out
			fundingVout = uint32(i)
			break
		}
	}
	require.NotNil(t, fundingOutput)
	require.Equal(t, uint32(fundingUtxo.Vout), fundingVout)
	fundingTxid, err := chainhash.NewHashFromStr(fundingUtxo.Txid)
	require.NoError(t, err)
	ptx := buildOnchainSpendPtx(
		t, *fundingTxid, fundingVout, fundingOutput,
		&wire.TxOut{Value: spendAmount, PkScript: bobPkScript},
		merkleProof, rawFundingTx, arkadeScript,
	)
	encoded, err := ptx.B64Encode()
	require.NoError(t, err)
	bobSigned, err := bobWallet.SignTransaction(ctx, explorerSvc, encoded)
	require.NoError(t, err)
	fullySigned, err := emulatorClient.SubmitOnchainTx(ctx, bobSigned)
	require.NoError(t, err)
	require.NotEqual(t, bobSigned, fullySigned)
	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(fullySigned), true)
	require.NoError(t, err)

	deprecatedTweaked := arkade.ComputeArkadeScriptPublicKey(deprecatedPubKey, arkadeScriptHash)
	wantKeys := map[string]struct{}{
		hex.EncodeToString(schnorr.SerializePubKey(bobPubKey)):         {},
		hex.EncodeToString(schnorr.SerializePubKey(deprecatedTweaked)): {},
	}
	for _, sig := range signedPtx.Inputs[0].TaprootScriptSpendSig {
		delete(wantKeys, hex.EncodeToString(sig.XOnlyPubKey))
	}
	require.Empty(t, wantKeys)
}
