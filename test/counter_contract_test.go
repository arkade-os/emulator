package test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Packet types 0 and 1 are reserved for assets and emulator entries.
const counterPacketType = 2

func TestCounterContractWithPacketIntrospection(t *testing.T) {
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

	counterArkadeScript := counterContractArkadeScript(t)
	counterVtxoScript := createArkadeOnlyVtxoScript(
		aliceAddr.Signer,
		emulatorPubKey,
		arkade.ArkadeScriptHash(counterArkadeScript),
	)
	counterTapscript := onlyForfeitScript(t, counterVtxoScript)
	counterPkScript := p2trScriptForVtxoScript(t, counterVtxoScript)

	submitAndFinalize := func(candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, candidateTx, 0)

		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		_, _, err = emulatorClient.SubmitTx(
			ctx, encodedTx, encodeCheckpoints(t, checkpoints),
		)
		require.NoError(t, err)

		waitForVtxos()
	}

	submitExpectEmulatorFailure := func(candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		_, _, err = emulatorClient.SubmitTx(ctx, encodedTx, encodeCheckpoints(t, checkpoints))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	deployTx := deployCounterFromWallet(
		t,
		ctx,
		alice,
		aliceWallet,
		grpcClient,
		indexerSvc,
		alicePubKey,
		aliceAddr.Signer,
		uint32(infos.UnilateralExitDelay),
		counterPkScript,
		checkpointScriptBytes,
	)

	firstCounterInput := vtxoInputFromScriptOutput(
		t,
		deployTx.UnsignedTx,
		0,
		counterVtxoScript,
		counterTapscript,
	)

	invalidUnlockTx, invalidUnlockCheckpoints := buildCounterUnlockTx(
		t,
		firstCounterInput,
		counterPkScript,
		checkpointScriptBytes,
		counterArkadeScript,
		deployTx.UnsignedTx,
		0,
	)
	require.Error(t, executeArkadeScripts(t, invalidUnlockTx, invalidUnlockCheckpoints, emulatorPubKey))
	submitExpectEmulatorFailure(invalidUnlockTx, invalidUnlockCheckpoints)

	firstUnlockTx, firstUnlockCheckpoints := buildCounterUnlockTx(
		t,
		firstCounterInput,
		counterPkScript,
		checkpointScriptBytes,
		counterArkadeScript,
		deployTx.UnsignedTx,
		1,
	)
	requireCounterPacket(t, firstUnlockTx.UnsignedTx, 1)
	require.NoError(t, executeArkadeScripts(t, firstUnlockTx, firstUnlockCheckpoints, emulatorPubKey))
	submitAndFinalize(firstUnlockTx, firstUnlockCheckpoints)

	secondUnlockTx, secondUnlockCheckpoints := buildCounterUnlockTx(
		t,
		offchain.VtxoInput{
			Outpoint: &wire.OutPoint{
				Hash:  firstUnlockTx.UnsignedTx.TxHash(),
				Index: 0,
			},
			Tapscript:          firstCounterInput.Tapscript,
			Amount:             firstCounterInput.Amount,
			RevealedTapscripts: firstCounterInput.RevealedTapscripts,
		},
		counterPkScript,
		checkpointScriptBytes,
		counterArkadeScript,
		firstUnlockTx.UnsignedTx,
		2,
	)
	requireCounterPacket(t, secondUnlockTx.UnsignedTx, 2)
	require.NoError(t, executeArkadeScripts(t, secondUnlockTx, secondUnlockCheckpoints, emulatorPubKey))
	submitAndFinalize(secondUnlockTx, secondUnlockCheckpoints)
}

func deployCounterFromWallet(
	t *testing.T,
	ctx context.Context,
	alice arksdk.ArkClient,
	aliceWallet wallet.WalletService,
	grpcClient client.TransportClient,
	indexerSvc indexer.Indexer,
	alicePubKey *btcec.PublicKey,
	serverSigner *btcec.PublicKey,
	unilateralExitDelay uint32,
	counterPkScript []byte,
	checkpointScriptBytes []byte,
) *psbt.Packet {
	t.Helper()

	const counterContractValue = int64(20000)
	deployTx, deployCheckpoints := buildWalletFundedTx(
		t,
		ctx,
		alice,
		indexerSvc,
		alicePubKey,
		serverSigner,
		unilateralExitDelay,
		[]*wire.TxOut{
			{Value: counterContractValue, PkScript: counterPkScript},
		},
		checkpointScriptBytes,
	)
	addCounterPacket(t, deployTx, 0)
	requireCounterPacket(t, deployTx.UnsignedTx, 0)

	waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, deployTx, 0)
	submitWithArkd(t, ctx, deployTx, deployCheckpoints, aliceWallet, grpcClient)
	waitForVtxos()

	return deployTx
}

func counterContractArkadeScript(t *testing.T) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(counterPacketType).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).
		AddOp(arkade.OP_ADD).
		AddInt64(counterPacketType).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

func buildCounterUnlockTx(
	t *testing.T,
	input offchain.VtxoInput,
	nextPkScript []byte,
	checkpointScriptBytes []byte,
	arkadeScript []byte,
	prevArkTx *wire.MsgTx,
	counterValue uint64,
) (*psbt.Packet, []*psbt.Packet) {
	t.Helper()

	counterTx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{input},
		[]*wire.TxOut{{Value: input.Amount, PkScript: nextPkScript}},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addCounterPacket(t, counterTx, counterValue)
	addEmulatorPacket(t, counterTx, []arkade.EmulatorEntry{
		{Vin: 0, Script: arkadeScript},
	})
	require.NoError(t, txutils.SetArkPsbtField(counterTx, 0, arkade.PrevArkTxField, *prevArkTx))

	return counterTx, checkpoints
}

func addCounterPacket(t *testing.T, ptx *psbt.Packet, value uint64) {
	t.Helper()

	addExtensionPacket(t, ptx, extension.UnknownPacket{
		PacketType: counterPacketType,
		Data:       counterPacketPayload(t, value),
	})
}

func counterPacketPayload(t *testing.T, value uint64) []byte {
	t.Helper()

	// The extension packet format cannot represent an empty data field, while
	// zero minimally encodes as empty. Store the test counter offset by one so
	// every payload remains a canonical BigNum and can feed OP_ADD directly.
	payload, err := arkade.BigNumFromUint64(value + 1).Bytes()
	require.NoError(t, err)
	return payload
}

func requireCounterPacket(t *testing.T, tx *wire.MsgTx, want uint64) {
	t.Helper()

	ext, err := extension.NewExtensionFromTx(tx)
	require.NoError(t, err)

	for _, packet := range ext {
		if packet.Type() != counterPacketType {
			continue
		}
		data, err := packet.Serialize()
		require.NoError(t, err)
		require.Equal(t, counterPacketPayload(t, want), data)
		return
	}

	require.FailNow(t, "counter packet not found")
}
