package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ArkLabsHQ/emulator/pkg/arkade"
	emulatorclient "github.com/ArkLabsHQ/emulator/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
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
// Self-send arkade script — enforces output[0] preserves the spent VTXO's
// pkScript and value, and gates the spend to intent-proof txs only (v2).
// Witness stack: [].
//
//	OP_INSPECTVERSION <0x02000000> OP_EQUALVERIFY  # intent proof only (v2, not v3)
//	OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY
//	OP_1 OP_EQUALVERIFY                            # force taproot
//	OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTSCRIPTPUBKEY
//	OP_1 OP_EQUALVERIFY                            # force taproot
//	OP_EQUALVERIFY                                 # programs equal
//	OP_0 OP_INSPECTOUTPUTVALUE
//	OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE
//	OP_EQUAL                                       # values equal
//
// Delegate path — MultisigClosure [server, emulator_tweaked]. Any solver
// can trigger the refresh; the covenant acts in the user's place.
// Exit path — CSVMultisigClosure for the user. Unilateral exit remains
// available if the emulator or arkd refuse to cooperate.
//
// The v=2 version gate blocks off-chain Ark txs (v=3): without it a solver
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

	// covenant: output[0] preserves the spent VTXO (same pkScript and value)
	delegateArkadeScript := enforceSelfSend(t)

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

	// solver-owned cosigner, drives Musig2 on behalf of the absent user
	cosignerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerSession := tree.NewTreeSignerSession(cosignerKey)

	buildIntent := func(outputs []*wire.TxOut) (*psbt.Packet, string) {
		t.Helper()

		message, err := intent.RegisterMessage{
			BaseMessage: intent.BaseMessage{
				Type: intent.IntentMessageTypeRegister,
			},
			CosignersPublicKeys: []string{signerSession.GetPublicKey()},
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
		// required by OP_INSPECTINPUTSCRIPTPUBKEY on input 1
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

	// Invalid: off-chain Ark tx (v3) rejected by the version gate
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
	require.NoError(t, executeArkadeScripts(t, validPtx, nil, emulatorPubKey))

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

	handler := &delegateBatchEventsHandler{
		intentId:       intentId,
		intent:         signedIntent,
		vtxosToForfeit: []client.TapscriptsVtxo{vtxo},
		signerSession:  signerSession,
		emulatorClient: emulatorClient,
		wallet:         aliceWallet,
		client:         grpcAlice,
		explorer:       explorerSvc,
	}

	topics := arksdk.GetEventStreamTopics(
		[]types.Outpoint{vtxo.Outpoint},
		[]tree.SignerSession{signerSession},
	)
	eventStream, stop, err := grpcAlice.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(stop)

	capturing := &capturingBatchEventsHandler{delegateBatchEventsHandler: handler}
	commitmentTxid, err := arksdk.JoinBatchSession(ctx, eventStream, capturing)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
	require.NotNil(t, capturing.vtxoTree)

	// batch produced a leaf at the same delegate pkScript and value
	refreshedOutpoint := findLeafOutpoint(t, capturing.vtxoTree, delegatePkScript, delegateAmount)

	// refreshed VTXO is a batch leaf (not preconfirmed)
	require.Eventually(t, func() bool {
		req := indexer.GetVtxosRequestOption{}
		if err := req.WithOutpoints([]types.Outpoint{refreshedOutpoint}); err != nil {
			return false
		}
		resp, err := indexerSvc.GetVtxos(ctx, req)
		if err != nil || resp == nil || len(resp.Vtxos) != 1 {
			return false
		}
		v := resp.Vtxos[0]
		return !v.Preconfirmed && !v.Spent
	}, 10*time.Second, 200*time.Millisecond, "refreshed delegate VTXO not found or preconfirmed")
}

// enforceSelfSend builds an arkade script that asserts output[0] has the same
// pkScript and value as the current input, and that the spending tx is an
// intent proof (v2). Witness stack: [].
func enforceSelfSend(t *testing.T) []byte {
	t.Helper()

	s, err := txscript.NewScriptBuilder().
		// OP_INSPECTVERSION pushes tx.Version as 4-byte LE, compared against raw bytes
		AddOp(arkade.OP_INSPECTVERSION).
		AddData([]byte{0x02, 0x00, 0x00, 0x00}).
		AddOp(arkade.OP_EQUALVERIFY).
		// output[0] witness program == input[self] witness program
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // segwit v1
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // segwit v1
		AddOp(arkade.OP_EQUALVERIFY).
		// output[0] value == input[self] value
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return s
}

// fundDelegate locks amount sats into a VTXO with the given script and returns
// the spend input for its forfeit leaf plus the funding ark tx (needed by
// OP_INSPECTINPUTSCRIPTPUBKEY via arkade.PrevArkTxField).
func fundDelegate(
	t *testing.T,
	ctx context.Context,
	alice arksdk.ArkClient,
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
