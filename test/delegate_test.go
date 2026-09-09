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
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	mempoolexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

const (
	delegateAmount    = int64(10_000)
	delegateExitDelay = uint32(512)
)

// TestCovenantDelegate exercises a non-interactive refresh of a VTXO through
// the Ark batch settlement process, with no user signature required.
//
// The VTXO is owned by a 2-of-2 multisig (arkd signer + emulator-tweaked
// key) with an extra CSV exit leaf for the user. The emulator only signs
// once the arkade covenant on the spending tx passes.
//
// Self-send arkade script — enforces output[i-1] preserves the spent VTXO's
// pkScript and value, and gates the spend to register intents only with strict
// cosigner verification.
// Witness stack: [].
//
//	OP_PUSHEXPIRY 1024 OP_SUB OP_CHECKTIMEVERIFY          # within 1024 seconds of expiry
//	"type" OP_INSPECTINTENTMESSAGE OP_VERIFY "register" OP_EQUALVERIFY  # type == "register"
//	"onchain_output_indexes" OP_INSPECTINTENTMESSAGE OP_VERIFY "[]" OP_EQUALVERIFY  # no onchain outputs
//	"cosigners_public_keys.0" OP_INSPECTINTENTMESSAGE OP_VERIFY <pubkey> OP_EQUALVERIFY  # cosigner[0] == delegate key
//	"cosigners_public_keys.1" OP_INSPECTINTENTMESSAGE OP_NOT OP_VERIFY OP_DROP  # no second cosigner
//	OP_PUSHCURRENTINPUTINDEX OP_1SUB OP_7 OP_0 OP_TUNNEL  # output i-1, script+value+assets flags, no exceptions
//
// Delegate path — MultisigClosure [server, emulator_tweaked]. Any solver
// can trigger the refresh; the covenant acts in the user's place.
// Exit path — CSVMultisigClosure for the user. Unilateral exit remains
// available if the emulator or arkd refuse to cooperate.
//
// The intent-message gate blocks off-chain Ark txs: without it a solver
// could spend the delegate VTXO via SubmitTx in a self-send loop, burning
// fees without ever refreshing the VTXO through a batch.
//
// Under the hood, the VTXO closures are :
// Delegate: Server + Emulator
// Exit: User + CSV
func TestCovenantDelegate(t *testing.T) {
	ctx := t.Context()

	alice, aliceWallet, alicePubKey, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	emulatorClient, emulatorPubKey, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 100_000)

	indexerSvc := setupIndexer(t)

	explorerSvc, err := mempoolexplorer.NewExplorer(
		"http://localhost:3000", arklib.BitcoinRegTest,
	)
	require.NoError(t, err)

	// solver-owned cosigner, drives Musig2 on behalf of the absent user.
	// Generated before the covenant script so its pubkey can be pinned in it.
	cosignerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerSession := tree.NewTreeSignerSession(cosignerKey)
	delegateSignerPubkeyHex := signerSession.GetPublicKey()

	// covenant: spending is allowed near expiry if output[0] preserves the spent VTXO
	// with additional checks on intent message fields
	delegateArkadeScript, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHEXPIRY).
		AddInt64(1024).
		AddOp(arkade.OP_SUB).
		AddOp(arkade.OP_CHECKTIMEVERIFY).
		// Check intent message type == "register"
		AddData([]byte("type")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).
		AddData([]byte(intent.IntentMessageTypeRegister)).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check onchain_output_indexes == "[]"
		AddData([]byte("onchain_output_indexes")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).
		AddData([]byte("[]")).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check cosigners_public_keys.0 == delegate's vtxotree signer pubkey
		AddData([]byte("cosigners_public_keys.0")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).
		AddData([]byte(delegateSignerPubkeyHex)).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check cosigners_public_keys.1 does not exist (only one cosigner allowed)
		AddData([]byte("cosigners_public_keys.1")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_NOT).
		AddOp(txscript.OP_VERIFY).
		AddOp(txscript.OP_DROP).
		// Tunnel: output i-1, script+value+assets flags, no asset exceptions
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_1SUB).
		AddInt64(arkade.TunnelScriptPubKey | arkade.TunnelValue | arkade.TunnelAssets).
		AddInt64(0).
		AddOp(arkade.OP_TUNNEL).
		Script()
	require.NoError(t, err)

	// delegate VTXO: [server, emulator_tweaked] for refresh, [alice]+CSV for exit
	delegateVtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					aliceAddr.Signer,
					arkade.ComputeArkadeScriptPublicKey(
						emulatorPubKey,
						arkade.ArkadeScriptHash(delegateArkadeScript),
					),
				},
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{alicePubKey},
				},
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

	// fund the delegate VTXO from Alice's wallet
	delegateInput, fundingTx := fundDelegate(
		t, ctx, alice, indexerSvc,
		aliceAddr.Signer, delegateVtxoScript, delegateAmount,
	)

	buildIntent := func(outputs []*wire.TxOut) (*psbt.Packet, string) {
		t.Helper()

		message, err := intent.RegisterMessage{
			BaseMessage: intent.BaseMessage{
				Type: intent.IntentMessageTypeRegister,
			},
			// non-nil so it encodes as "[]" (nil marshals to null, a covenant miss)
			OnchainOutputIndexes: []int{},
			CosignersPublicKeys:  []string{delegateSignerPubkeyHex},
		}.Encode()
		require.NoError(t, err)

		intentProof, err := intent.New(
			message,
			[]intent.Input{{
				OutPoint: delegateInput.Outpoint,
				Sequence: wire.MaxTxInSequenceNum,
				WitnessUtxo: &wire.TxOut{
					Value:    delegateAmount,
					PkScript: delegatePkScript,
				},
			}},
			outputs,
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

		// input 0 (BIP322 message) shares the VTXO pkScript, so the same tapscript applies
		intentProof.Inputs[0].TaprootLeafScript = tapLeafScript
		intentProof.Inputs[1].TaprootLeafScript = tapLeafScript
		intentProof.Inputs[0].Unknowns = append(intentProof.Inputs[0].Unknowns, taptreeField)
		intentProof.Inputs[1].Unknowns = append(intentProof.Inputs[1].Unknowns, taptreeField)

		intentPtx := &intentProof.Packet
		addEmulatorPacket(t, intentPtx, []arkade.EmulatorEntry{
			{Vin: 1, Script: delegateArkadeScript},
		})
		// required by OP_TUNNEL on input 1
		require.NoError(t, txutils.SetArkPsbtField(
			intentPtx, 1, arkade.PrevArkTxField, *fundingTx,
		))

		return intentPtx, message
	}

	submitIntentAndExpectFailure := func(outputs []*wire.TxOut) {
		t.Helper()

		ptx, msg := buildIntent(outputs)
		encoded, err := ptx.B64Encode()
		require.NoError(t, err)

		_, err = emulatorClient.SubmitIntent(ctx, emulatorclient.Intent{
			Proof:   encoded,
			Message: msg,
		})
		require.Error(t, err)
	}

	// Invalid: output pkScript does not match the delegate VTXO
	submitIntentAndExpectFailure([]*wire.TxOut{
		{Value: delegateAmount, PkScript: randomP2TRScript(t)},
	})

	// Invalid: output value does not match the delegate VTXO
	submitIntentAndExpectFailure([]*wire.TxOut{
		{Value: delegateAmount - 1, PkScript: delegatePkScript},
	})

	// Invalid: off-chain Ark tx rejected by the intent-message gate
	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	offchainPtx, offchainCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{delegateInput},
		[]*wire.TxOut{{Value: delegateAmount, PkScript: delegatePkScript}},
		checkpointScriptBytes,
	)
	require.NoError(t, err)
	addEmulatorPacket(t, offchainPtx, []arkade.EmulatorEntry{
		{Vin: 0, Script: delegateArkadeScript},
	})

	encodedOffchain, err := offchainPtx.B64Encode()
	require.NoError(t, err)
	_, _, err = emulatorClient.SubmitTx(
		ctx, encodedOffchain, encodeCheckpoints(t, offchainCheckpoints),
	)
	require.Error(t, err)

	// Valid: self-send intent proof, output preserves pkScript and value
	validPtx, validMessage := buildIntent([]*wire.TxOut{
		{Value: delegateAmount, PkScript: delegatePkScript},
	})
	encodedValidProof, err := validPtx.B64Encode()
	require.NoError(t, err)

	approvedProof, err := emulatorClient.SubmitIntent(ctx, emulatorclient.Intent{
		Proof:   encodedValidProof,
		Message: validMessage,
	})
	require.NoError(t, err)

	signedIntent := emulatorclient.Intent{
		Proof:   approvedProof,
		Message: validMessage,
	}

	intentId, err := grpcAlice.RegisterIntent(ctx, signedIntent.Proof, signedIntent.Message)
	require.NoError(t, err)

	vtxo := types.VtxoWithTapTree{
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

	handler := &delegateBatchEventsHandler{
		intentId:       intentId,
		intent:         signedIntent,
		vtxosToForfeit: []types.VtxoWithTapTree{vtxo},
		signerSession:  signerSession,
		emulatorClient: emulatorClient,
		wallet:         aliceWallet,
		client:         grpcAlice,
		explorer:       explorerSvc,
	}

	topics := clientlib.GetEventStreamTopics(
		[]types.Outpoint{vtxo.Outpoint},
		[]tree.SignerSession{signerSession},
	)
	eventStream, stop, err := grpcAlice.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(stop)

	capturing := &capturingBatchEventsHandler{delegateBatchEventsHandler: handler}
	commitmentTxid, _, _, _, _, err := clientlib.JoinBatchSession(ctx, eventStream, capturing)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
	require.NotNil(t, capturing.vtxoTree)

	// batch produced a leaf at the same delegate pkScript and value
	refreshedOutpoint := findLeafOutpoint(t, capturing.vtxoTree, delegatePkScript, delegateAmount)

	// refreshed VTXO is a batch leaf (not preconfirmed)
	require.Eventually(t, func() bool {
		resp, err := indexerSvc.GetVtxos(ctx, indexer.WithOutpoints([]types.Outpoint{refreshedOutpoint}))
		if err != nil || resp == nil || len(resp.Vtxos) != 1 {
			return false
		}
		v := resp.Vtxos[0]
		return !v.Preconfirmed && !v.Spent
	}, 10*time.Second, 200*time.Millisecond, "refreshed delegate VTXO not found or preconfirmed")
}

// enforceSelfSend builds an arkade script that asserts the output paired with
// the current input (intent proof input i, whose input 0 is the BIP322
// message, maps to output i-1) has the same pkScript and value, and that the
// spending tx is an intent proof (v2). Binding the output to the input index
// stops two equal delegate VTXOs from both being "preserved" by one output.
// Witness stack: [].
func enforceSelfSend(t *testing.T) []byte {
	t.Helper()

	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_INSPECTVERSION).
		AddInt64(2).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_1SUB).
		AddInt64(arkade.TunnelScriptPubKey | arkade.TunnelValue).
		AddInt64(0).
		AddOp(arkade.OP_TUNNEL).
		Script()
	require.NoError(t, err)

	return s
}

// fundDelegate locks amount sats into a VTXO with the given script and returns
// the spend input for its forfeit leaf plus the funding ark tx (needed by
// OP_TUNNEL via arkade.PrevArkTxField).
func fundDelegate(
	t *testing.T,
	ctx context.Context,
	alice arksdk.Wallet,
	indexerSvc indexer.Indexer,
	serverSigner *btcec.PublicKey,
	delegateVtxoScript script.TapscriptsVtxoScript,
	amount int64,
) (offchain.VtxoInput, *wire.MsgTx) {
	t.Helper()

	tapKey, _, err := delegateVtxoScript.TapTree()
	require.NoError(t, err)

	addr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: tapKey,
		Signer:     serverSigner,
	}
	addrStr, err := addr.EncodeV0()
	require.NoError(t, err)

	fundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{
		{To: addrStr, Amount: uint64(amount)},
	})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxid)

	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	tapscript := onlyForfeitScript(t, delegateVtxoScript)
	vout, output := findTaprootOutput(t, fundingPtx.UnsignedTx, tapKey)
	require.Equal(t, amount, output.Value)

	return vtxoInputFromScriptOutput(
		t, fundingPtx.UnsignedTx, vout, delegateVtxoScript, tapscript,
	), fundingPtx.UnsignedTx
}

// findLeafOutpoint returns the outpoint of the vtxo tree leaf output matching
// the given pkScript and value.
func findLeafOutpoint(
	t *testing.T, vtxoTree *tree.TxTree, pkScript []byte, value int64,
) types.Outpoint {
	t.Helper()

	for _, leaf := range vtxoTree.Leaves() {
		for vout, out := range leaf.UnsignedTx.TxOut {
			if out.Value == value && bytes.Equal(out.PkScript, pkScript) {
				return types.Outpoint{
					Txid: leaf.UnsignedTx.TxID(),
					VOut: uint32(vout),
				}
			}
		}
	}

	require.FailNow(t, "leaf output not found")
	return types.Outpoint{}
}
