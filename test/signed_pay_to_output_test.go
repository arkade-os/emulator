package test

import (
	"encoding/hex"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/emulator/pkg/arkade"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestSignedPayToOutput(t *testing.T) {
	ctx := t.Context()

	alice, grpcAlice := setupArkSDK(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice, 50_000)

	emulatorClient, emulatorPubKey, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)

	explorerSvc, err := mempoolexplorer.NewExplorer(
		"http://localhost:3000", arklib.BitcoinRegTest,
	)
	require.NoError(t, err)

	authorizerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	receiverKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	receiverPkScript, err := txscript.PayToTaprootScript(receiverKey.PubKey())
	require.NoError(t, err)

	const contractAmount = int64(10_000)
	arkadeScript := signedPayToOutputScript(
		t, authorizerKey.PubKey(), receiverPkScript, contractAmount,
	)
	contractVtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey,
		aliceAddr.Signer,
		emulatorPubKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)
	contractTapscript := onlyForfeitScript(t, contractVtxoScript)
	contractInput := fund(
		t, ctx, alice, indexerSvc,
		aliceAddr.Signer, contractVtxoScript, contractAmount,
	)

	buildSpend := func(witness wire.TxWitness) (*psbt.Packet, []*psbt.Packet) {
		t.Helper()

		ptx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{contractInput},
			[]*wire.TxOut{{Value: contractAmount, PkScript: receiverPkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)

		addEmulatorPacket(t, ptx, []arkade.EmulatorEntry{
			{Vin: 0, Script: arkadeScript, Witness: witness},
		})

		return ptx, checkpoints
	}

	t.Run("missing_authorization_signature", func(t *testing.T) {
		ptx, checkpoints := buildSpend(wire.TxWitness{nil})

		err := executeArkadeScripts(t, ptx, checkpoints, emulatorPubKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "OP_CHECKSIGVERIFY")

		encodedTx, err := ptx.B64Encode()
		require.NoError(t, err)

		signedTx, err := bobWallet.SignTransaction(ctx, explorerSvc, encodedTx)
		require.NoError(t, err)

		signedCheckpoints := make([]string, 0, len(checkpoints))
		for _, checkpoint := range checkpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)

			signed, err := bobWallet.SignTransaction(ctx, explorerSvc, encoded)
			require.NoError(t, err)
			signedCheckpoints = append(signedCheckpoints, signed)
		}

		_, _, err = emulatorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	})

	t.Run("valid_authorization_signature", func(t *testing.T) {
		ptx, checkpoints := buildSpend(wire.TxWitness{nil})
		authSig := signArkadeInput(
			t, ptx, 0, authorizerKey, txscript.NewBaseTapLeaf(contractTapscript),
		)
		replaceEmulatorPacket(t, ptx, []arkade.EmulatorEntry{
			{Vin: 0, Script: arkadeScript, Witness: wire.TxWitness{authSig}},
		})

		require.NoError(t, executeArkadeScripts(t, ptx, checkpoints, emulatorPubKey))

		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, ptx, 0)

		encodedTx, err := ptx.B64Encode()
		require.NoError(t, err)

		signedTx, err := bobWallet.SignTransaction(ctx, explorerSvc, encodedTx)
		require.NoError(t, err)

		signedCheckpoints := make([]string, 0, len(checkpoints))
		for _, checkpoint := range checkpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)

			signed, err := bobWallet.SignTransaction(ctx, explorerSvc, encoded)
			require.NoError(t, err)
			signedCheckpoints = append(signedCheckpoints, signed)
		}

		signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(signedTx), true)
		require.NoError(t, err)
		require.NoError(t, executeArkadeScripts(
			t, signedPtx, checkpoints, emulatorPubKey,
		))

		_, _, err = emulatorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
		require.NoError(t, err)

		waitForVtxos()
	})
}

func signedPayToOutputScript(
	t *testing.T,
	authorizerPubKey *btcec.PublicKey,
	receiverPkScript []byte,
	amount int64,
) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(authorizerPubKey)).
		AddOp(arkade.OP_CHECKSIGVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(receiverPkScript[2:]).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(amount).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

func replaceEmulatorPacket(
	t *testing.T,
	ptx *psbt.Packet,
	entries []arkade.EmulatorEntry,
) {
	t.Helper()

	packet, err := arkade.NewPacket(entries...)
	require.NoError(t, err)

	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)

	for i, out := range ptx.UnsignedTx.TxOut {
		if extension.IsExtension(out.PkScript) {
			ptx.UnsignedTx.TxOut[i] = txOut
			return
		}
	}

	require.FailNow(t, "emulator packet output not found")
}

func signArkadeInput(
	t *testing.T,
	ptx *psbt.Packet,
	inputIndex int,
	signingKey *btcec.PrivateKey,
	tapLeaf txscript.TapLeaf,
) []byte {
	t.Helper()

	prevouts := make(map[wire.OutPoint]*wire.TxOut, len(ptx.Inputs))
	for i, input := range ptx.Inputs {
		prevouts[ptx.UnsignedTx.TxIn[i].PreviousOutPoint] = input.WitnessUtxo
	}

	prevOutFetcher := &testArkPrevOutFetcher{
		PrevOutputFetcher: txscript.NewMultiPrevOutFetcher(prevouts),
	}
	sighashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevOutFetcher)
	message, err := arkade.CalcArkadeScriptSignatureHash(
		sighashes, txscript.SigHashDefault, ptx.UnsignedTx,
		inputIndex, prevOutFetcher, tapLeaf, arkade.BlankCodeSepValue,
	)
	require.NoError(t, err)

	sig, err := schnorr.Sign(signingKey, message)
	require.NoError(t, err)
	return sig.Serialize()
}
