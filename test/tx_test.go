package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	introspectorclient "github.com/ArkLabsHQ/introspector/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/indexer"
	grpcindexer "github.com/arkade-os/go-sdk/indexer/grpc"
	"github.com/arkade-os/go-sdk/store"
	inmemorystoreconfig "github.com/arkade-os/go-sdk/store/inmemory"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet"
	singlekeywallet "github.com/arkade-os/go-sdk/wallet/singlekey"
	inmemorystore "github.com/arkade-os/go-sdk/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestMain(m *testing.M) {
	if err := generateBlock(); err != nil {
		log.Fatalf("error generating block: %s", err)
	}

	err := setupServerWalletAndCLI()
	if err != nil && !errors.Is(err, ErrAlreadySetup) {
		log.Fatalf("error setting up server wallet and CLI: %s", err)
	}
	time.Sleep(1 * time.Second)

	code := m.Run()
	os.Exit(code)
}

// TestSubmitOffchain tests sending funds to an arkade script closure
// alice onboard funds and send to an arkade script closure using introspection opcodes
// then 2 offchain transactions are attempted:
// 1. offchain with the wrong outputs : test if it fails
// 2. offchain with the correct outputs : test if it succeeds
func TestSubmitOffchain(t *testing.T) {
	ctx := t.Context()
	alice, grpcAlice := setupArkSDK(t)
	_, offchainAddr, _, err := alice.Receive(ctx)
	require.NoError(t, err)
	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)
	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)
	mustPayAliceScript, err := txscript.NewScriptBuilder().
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(alicePkScript[2:]).AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	altIntroWallet, _, altIntroPubKey := setupWallet(t, ctx)
	introspectorClient, introspectorPublicKey, _ := setupIntrospectorClient(t, ctx)
	indexerSvc := setupIndexer(t)
	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	bobPaysAliceContract := createVtxoScriptWithArkadeScript(bobPubKey, aliceAddr.Signer, introspectorPublicKey, arkade.ArkadeScriptHash(mustPayAliceScript))
	vtxoTapKey, vtxoTapTree, err := bobPaysAliceContract.TapTree()
	require.NoError(t, err)
	closure := bobPaysAliceContract.ForfeitClosures()[0]
	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)
	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(arkadeTapscript).TapHash())
	require.NoError(t, err)
	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)
	bobPaysAliceTapscript := &waddrmgr.Tapscript{ControlBlock: ctrlBlock, RevealedScript: merkleProof.Script}

	bobPaysAliceContractAddr := arklib.Address{HRP: "tark", VtxoTapKey: vtxoTapKey, Signer: aliceAddr.Signer}
	bobPaysAliceContractAddrStr, err := bobPaysAliceContractAddr.EncodeV0()
	require.NoError(t, err)

	// Alternative arkade script for multi-input tests
	arkadeScriptB, err := txscript.NewScriptBuilder().AddOp(arkade.OP_1).Script()
	require.NoError(t, err)

	// Foreign script using alternative introspector
	foreignScript := createVtxoScriptWithArkadeScript(bobPubKey, aliceAddr.Signer, altIntroPubKey, arkade.ArkadeScriptHash(mustPayAliceScript))

	// Current script (same as bobPaysAliceContract but recreated for consistency in multi-input patterns)
	currentScript := createVtxoScriptWithArkadeScript(bobPubKey, aliceAddr.Signer, introspectorPublicKey, arkade.ArkadeScriptHash(mustPayAliceScript))

	// Multisig script for not_finalizer_on_all_owned_inputs pattern
	multisigScriptNotFinalizer := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					arkade.ComputeArkadeScriptPublicKey(introspectorPublicKey, arkade.ArkadeScriptHash(mustPayAliceScript)),
					bobPubKey, aliceAddr.Signer,
				},
			},
		},
	}
	multisigTapKeyNotFinalizer, _, err := multisigScriptNotFinalizer.TapTree()
	require.NoError(t, err)
	multisigClosureNotFinalizer := multisigScriptNotFinalizer.ForfeitClosures()[0]
	multisigTapscriptBytesNotFinalizer, err := multisigClosureNotFinalizer.Script()
	require.NoError(t, err)

	// Multisig script for mixed_introspector_entries_success pattern
	multisigScriptMixed := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					// we don't tweak the key for easier signing
					altIntroPubKey,
					bobPubKey,
					aliceAddr.Signer,
				},
			},
		},
	}
	multisigTapKeyMixed, _, err := multisigScriptMixed.TapTree()
	require.NoError(t, err)
	multisigClosureMixed := multisigScriptMixed.ForfeitClosures()[0]
	multisigTapscriptBytesMixed, err := multisigClosureMixed.Script()
	require.NoError(t, err)

	// VTXO script variants for multi-input tests
	vtxoScriptA := createVtxoScriptWithArkadeScript(bobPubKey, aliceAddr.Signer, introspectorPublicKey, arkade.ArkadeScriptHash(mustPayAliceScript))
	vtxoScriptB := createVtxoScriptWithArkadeScript(bobPubKey, aliceAddr.Signer, introspectorPublicKey, arkade.ArkadeScriptHash(arkadeScriptB))
	tapKeyA, _, err := vtxoScriptA.TapTree()
	require.NoError(t, err)
	tapKeyB, _, err := vtxoScriptB.TapTree()
	require.NoError(t, err)

	assertSubmitError := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	t.Run("single_input_invalid_script", func(t *testing.T) {
		fundAndSettleAlice(t, ctx, alice, 10000)

		txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: bobPaysAliceContractAddrStr, Amount: 10000}})
		require.NoError(t, err)

		fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
		require.NoError(t, err)
		redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
		require.NoError(t, err)

		infos, err := grpcAlice.GetInfo(ctx)
		require.NoError(t, err)
		checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
		require.NoError(t, err)

		invalidTx, invalidCheckpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{
				{
					Outpoint: &wire.OutPoint{
						Hash:  redeemPtx.UnsignedTx.TxHash(),
						Index: 0,
					},
					Tapscript: bobPaysAliceTapscript,
					Amount:    10000,
					RevealedTapscripts: []string{
						hex.EncodeToString(arkadeTapscript),
					},
				},
			},
			[]*wire.TxOut{
				{
					Value: 10000,
					// not paying alice
					PkScript: []byte{0x6a},
				},
			},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addIntrospectorPacket(t, invalidTx, []arkade.IntrospectorEntry{{Vin: 0, Script: mustPayAliceScript}})

		encodedInvalidTx, err := invalidTx.B64Encode()
		require.NoError(t, err)
		signedInvalidTx, err := bobWallet.SignTransaction(ctx, explorer, encodedInvalidTx)
		require.NoError(t, err)
		signedInvalidCheckpoints := make([]string, 0, len(invalidCheckpoints))
		for _, checkpoint := range invalidCheckpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			signed, err := bobWallet.SignTransaction(ctx, explorer, encoded)
			require.NoError(t, err)
			signedInvalidCheckpoints = append(signedInvalidCheckpoints, signed)
		}

		_, _, err = introspectorClient.SubmitTx(ctx, signedInvalidTx, signedInvalidCheckpoints)
		assertSubmitError(t, err)
	})

	t.Run("single_input_missing_checkpoint_signature", func(t *testing.T) {
		fundAndSettleAlice(t, ctx, alice, 10000)

		txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: bobPaysAliceContractAddrStr, Amount: 10000}})
		require.NoError(t, err)

		fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
		require.NoError(t, err)
		redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
		require.NoError(t, err)

		infos, err := grpcAlice.GetInfo(ctx)
		require.NoError(t, err)
		checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
		require.NoError(t, err)

		validTx, validCheckpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{
				{
					Outpoint: &wire.OutPoint{
						Hash:  redeemPtx.UnsignedTx.TxHash(),
						Index: 0,
					},
					Tapscript: bobPaysAliceTapscript,
					Amount:    10000,
					RevealedTapscripts: []string{
						hex.EncodeToString(arkadeTapscript),
					},
				},
			},
			[]*wire.TxOut{
				{
					Value:    10000,
					PkScript: alicePkScript,
				},
			},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{{Vin: 0, Script: mustPayAliceScript}})
		encodedValidTx, err := validTx.B64Encode()
		require.NoError(t, err)
		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedValidTx)
		require.NoError(t, err)
		encodedValidCheckpoints := make([]string, 0, len(validCheckpoints))
		// no signatures addded
		for _, checkpoint := range validCheckpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			encodedValidCheckpoints = append(encodedValidCheckpoints, encoded)
		}
		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
		assertSubmitError(t, err)
	})

	t.Run("single_input_success", func(t *testing.T) {
		fundAndSettleAlice(t, ctx, alice, 10000)

		txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: bobPaysAliceContractAddrStr, Amount: 10000}})
		require.NoError(t, err)

		fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
		require.NoError(t, err)
		redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
		require.NoError(t, err)

		infos, err := grpcAlice.GetInfo(ctx)
		require.NoError(t, err)
		checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
		require.NoError(t, err)

		validTx, validCheckpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{
				{
					Outpoint: &wire.OutPoint{
						Hash:  redeemPtx.UnsignedTx.TxHash(),
						Index: 0,
					},
					Tapscript: bobPaysAliceTapscript,
					Amount:    10000,
					RevealedTapscripts: []string{
						hex.EncodeToString(arkadeTapscript),
					},
				},
			},
			[]*wire.TxOut{
				{
					Value:    10000,
					PkScript: alicePkScript,
				},
			},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{{Vin: 0, Script: mustPayAliceScript}})
		encodedValidTx, err := validTx.B64Encode()
		require.NoError(t, err)
		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedValidTx)
		require.NoError(t, err)
		signedValidCheckpoints := make([]string, 0, len(validCheckpoints))
		for _, checkpoint := range validCheckpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			signed, err := bobWallet.SignTransaction(ctx, explorer, encoded)
			require.NoError(t, err)
			signedValidCheckpoints = append(signedValidCheckpoints, signed)
		}
		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, validTx, 0)
		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, signedValidCheckpoints)
		require.NoError(t, err)
		waitForVtxos()
	})

	t.Run("multi_input_same_introspector_success", func(t *testing.T) {
		fundAndSettleAlice(t, ctx, alice, 20000)
		addrA := arklib.Address{HRP: "tark", VtxoTapKey: tapKeyA, Signer: aliceAddr.Signer}
		addrB := arklib.Address{HRP: "tark", VtxoTapKey: tapKeyB, Signer: aliceAddr.Signer}
		addrAStr, err := addrA.EncodeV0()
		require.NoError(t, err)
		addrBStr, err := addrB.EncodeV0()
		require.NoError(t, err)
		txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: addrAStr, Amount: 10000}, {To: addrBStr, Amount: 10000}})
		require.NoError(t, err)
		fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
		require.NoError(t, err)
		redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
		require.NoError(t, err)
		idxA, outA := findTaprootOutput(t, redeemPtx.UnsignedTx, tapKeyA)
		idxB, outB := findTaprootOutput(t, redeemPtx.UnsignedTx, tapKeyB)
		closureA := vtxoScriptA.ForfeitClosures()[0]
		closureB := vtxoScriptB.ForfeitClosures()[0]
		tapscriptABytes, err := closureA.Script()
		require.NoError(t, err)
		tapscriptBBytes, err := closureB.Script()
		require.NoError(t, err)
		inputA := vtxoInputFromScriptOutput(t, redeemPtx.UnsignedTx, idxA, vtxoScriptA, tapscriptABytes)
		inputB := vtxoInputFromScriptOutput(t, redeemPtx.UnsignedTx, idxB, vtxoScriptB, tapscriptBBytes)
		_ = outA
		_ = outB
		infos, err := grpcAlice.GetInfo(ctx)
		require.NoError(t, err)
		checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
		require.NoError(t, err)
		validTx, validCheckpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{inputA, inputB},
			[]*wire.TxOut{{Value: inputA.Amount + inputB.Amount, PkScript: alicePkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{{Vin: 0, Script: mustPayAliceScript}, {Vin: 1, Script: arkadeScriptB}})
		encodedValidTx, err := validTx.B64Encode()
		require.NoError(t, err)
		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedValidTx)
		require.NoError(t, err)
		signedCheckpoints := make([]string, 0, len(validCheckpoints))
		for _, checkpoint := range validCheckpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			signed, err := bobWallet.SignTransaction(ctx, explorer, encoded)
			require.NoError(t, err)
			signedCheckpoints = append(signedCheckpoints, signed)
		}
		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, validTx, 0)
		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
		require.NoError(t, err)
		waitForVtxos()
	})

	t.Run("not_finalizer_on_all_owned_inputs", func(t *testing.T) {
		fundAndSettleAlice(t, ctx, alice, 20000)
		vtxoScriptB := multisigScriptNotFinalizer
		tapKeyB := multisigTapKeyNotFinalizer
		addrA := arklib.Address{HRP: "tark", VtxoTapKey: tapKeyA, Signer: aliceAddr.Signer}
		addrB := arklib.Address{HRP: "tark", VtxoTapKey: tapKeyB, Signer: aliceAddr.Signer}
		addrAStr, err := addrA.EncodeV0()
		require.NoError(t, err)
		addrBStr, err := addrB.EncodeV0()
		require.NoError(t, err)
		txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: addrAStr, Amount: 10000}, {To: addrBStr, Amount: 10000}})
		require.NoError(t, err)
		fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
		require.NoError(t, err)
		redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
		require.NoError(t, err)
		idxA, _ := findTaprootOutput(t, redeemPtx.UnsignedTx, tapKeyA)
		idxB, _ := findTaprootOutput(t, redeemPtx.UnsignedTx, tapKeyB)
		closureA := vtxoScriptA.ForfeitClosures()[0]
		tapscriptABytes, err := closureA.Script()
		require.NoError(t, err)
		tapscriptBBytes := multisigTapscriptBytesNotFinalizer
		inputA := vtxoInputFromScriptOutput(t, redeemPtx.UnsignedTx, idxA, vtxoScriptA, tapscriptABytes)
		inputB := vtxoInputFromScriptOutput(t, redeemPtx.UnsignedTx, idxB, vtxoScriptB, tapscriptBBytes)
		infos, err := grpcAlice.GetInfo(ctx)
		require.NoError(t, err)
		checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
		require.NoError(t, err)
		candidateTx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{inputA, inputB},
			[]*wire.TxOut{{Value: inputA.Amount + inputB.Amount, PkScript: alicePkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{{Vin: 0, Script: mustPayAliceScript}, {Vin: 1, Script: mustPayAliceScript}})
		encodedTx, err := candidateTx.B64Encode()
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
		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
		assertSubmitError(t, err)
	})

	t.Run("mixed_introspector_entries_missing_required_signature", func(t *testing.T) {
		fundAndSettleAlice(t, ctx, alice, 20000)
		tapKeyA, _, err := currentScript.TapTree()
		require.NoError(t, err)
		tapKeyB, _, err := foreignScript.TapTree()
		require.NoError(t, err)
		addrA := arklib.Address{HRP: "tark", VtxoTapKey: tapKeyA, Signer: aliceAddr.Signer}
		addrB := arklib.Address{HRP: "tark", VtxoTapKey: tapKeyB, Signer: aliceAddr.Signer}
		addrAStr, err := addrA.EncodeV0()
		require.NoError(t, err)
		addrBStr, err := addrB.EncodeV0()
		require.NoError(t, err)
		txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: addrAStr, Amount: 10000}, {To: addrBStr, Amount: 10000}})
		require.NoError(t, err)
		fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
		require.NoError(t, err)
		redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
		require.NoError(t, err)
		idxA, _ := findTaprootOutput(t, redeemPtx.UnsignedTx, tapKeyA)
		idxB, _ := findTaprootOutput(t, redeemPtx.UnsignedTx, tapKeyB)
		closureA := currentScript.ForfeitClosures()[0]
		closureB := foreignScript.ForfeitClosures()[0]
		tapscriptABytes, err := closureA.Script()
		require.NoError(t, err)
		tapscriptBBytes, err := closureB.Script()
		require.NoError(t, err)
		inputA := vtxoInputFromScriptOutput(t, redeemPtx.UnsignedTx, idxA, currentScript, tapscriptABytes)
		inputB := vtxoInputFromScriptOutput(t, redeemPtx.UnsignedTx, idxB, foreignScript, tapscriptBBytes)
		infos, err := grpcAlice.GetInfo(ctx)
		require.NoError(t, err)
		checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
		require.NoError(t, err)
		candidateTx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{inputA, inputB},
			[]*wire.TxOut{{Value: inputA.Amount + inputB.Amount, PkScript: alicePkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{{Vin: 0, Script: mustPayAliceScript}, {Vin: 1, Script: mustPayAliceScript}})
		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)
		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
		require.NoError(t, err)
		signedCheckpoints := make([]string, 0, len(checkpoints))
		for i, checkpoint := range checkpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			if i == 0 {
				signed, err := bobWallet.SignTransaction(ctx, explorer, encoded)
				require.NoError(t, err)
				signedCheckpoints = append(signedCheckpoints, signed)
			} else {
				signedCheckpoints = append(signedCheckpoints, encoded)
			}
		}
		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
		assertSubmitError(t, err)
	})

	t.Run("mixed_introspector_entries_success", func(t *testing.T) {
		fundAndSettleAlice(t, ctx, alice, 20000)
		foreignScript := multisigScriptMixed
		tapKeyA, _, err := currentScript.TapTree()
		require.NoError(t, err)
		tapKeyB := multisigTapKeyMixed
		addrA := arklib.Address{HRP: "tark", VtxoTapKey: tapKeyA, Signer: aliceAddr.Signer}
		addrB := arklib.Address{HRP: "tark", VtxoTapKey: tapKeyB, Signer: aliceAddr.Signer}
		addrAStr, err := addrA.EncodeV0()
		require.NoError(t, err)
		addrBStr, err := addrB.EncodeV0()
		require.NoError(t, err)
		txid, err := alice.SendOffChain(ctx, []types.Receiver{{To: addrAStr, Amount: 10000}, {To: addrBStr, Amount: 10000}})
		require.NoError(t, err)
		fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
		require.NoError(t, err)
		redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
		require.NoError(t, err)
		idxA, _ := findTaprootOutput(t, redeemPtx.UnsignedTx, tapKeyA)
		idxB, _ := findTaprootOutput(t, redeemPtx.UnsignedTx, tapKeyB)
		closureA := currentScript.ForfeitClosures()[0]
		tapscriptABytes, err := closureA.Script()
		require.NoError(t, err)
		tapscriptBBytes := multisigTapscriptBytesMixed
		inputA := vtxoInputFromScriptOutput(t, redeemPtx.UnsignedTx, idxA, currentScript, tapscriptABytes)
		inputB := vtxoInputFromScriptOutput(t, redeemPtx.UnsignedTx, idxB, foreignScript, tapscriptBBytes)
		infos, err := grpcAlice.GetInfo(ctx)
		require.NoError(t, err)
		checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
		require.NoError(t, err)
		candidateTx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{inputA, inputB},
			[]*wire.TxOut{{Value: inputA.Amount + inputB.Amount, PkScript: alicePkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{{Vin: 0, Script: mustPayAliceScript}, {Vin: 1, Script: mustPayAliceScript}})
		encodedTx, err := candidateTx.B64Encode()
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
		// foriegn introspector must sign input checkpoint 1 and tx
		introBSigned, err := altIntroWallet.SignTransaction(ctx, explorer, signedCheckpoints[1])
		require.NoError(t, err)
		signedCheckpoints[1] = introBSigned
		signedTx, err = altIntroWallet.SignTransaction(ctx, explorer, signedTx)
		require.NoError(t, err)
		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, candidateTx, 0)
		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, signedCheckpoints)
		require.NoError(t, err)
		waitForVtxos()
	})
}

func TestSettlement(t *testing.T) {
	ctx := t.Context()
	alice, grpcClient := setupArkSDK(t)
	t.Cleanup(func() {
		grpcClient.Close()
	})

	const (
		sendAmount = 10000
	)

	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice, sendAmount)

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	// script verifying that the spending tx includes an output going to alice's address
	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(alicePkScript[2:]). // only witness program is pushed
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	// create the client
	introspectorClient, publicKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	vtxoScript := createVtxoScriptWithArkadeAndCSV(bobPubKey, aliceAddr.Signer, publicKey, arkade.ArkadeScriptHash(arkadeScript))

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	contractAddress := arklib.Address{
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

	contractAddressStr, err := contractAddress.EncodeV0()
	require.NoError(t, err)

	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: contractAddressStr, Amount: sendAmount}},
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

	var contractOutput *wire.TxOut
	var contractOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(contractAddress.VtxoTapKey)) {
			contractOutput = out
			contractOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, contractOutput)

	// create the intent

	randomKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	treeSignerSession := tree.NewTreeSignerSession(randomKey)
	require.NoError(t, err)

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

	intent, err := intent.New(
		message,
		[]intent.Input{
			{
				OutPoint: &wire.OutPoint{
					Hash:  redeemPtx.UnsignedTx.TxHash(),
					Index: contractOutputIndex,
				},
				Sequence:    wire.MaxTxInSequenceNum,
				WitnessUtxo: contractOutput,
			},
		},
		[]*wire.TxOut{
			{
				Value:    contractOutput.Value,
				PkScript: alicePkScript,
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, intent)
	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)
	taptreeField, err := txutils.VtxoTaprootTreeField.Encode(tapscripts)
	require.NoError(t, err)

	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	tapLeafScript := []*psbt.TaprootTapLeafScript{
		{
			LeafVersion:  txscript.BaseLeafVersion,
			ControlBlock: ctrlBlockBytes,
			Script:       merkleProof.Script,
		},
	}
	intent.Inputs[0].TaprootLeafScript = tapLeafScript
	intent.Inputs[1].TaprootLeafScript = tapLeafScript
	intent.Inputs[0].Unknowns = append(intent.Inputs[0].Unknowns, taptreeField)
	intent.Inputs[1].Unknowns = append(intent.Inputs[1].Unknowns, taptreeField)

	intentPtx := &intent.Packet
	addIntrospectorPacket(t, intentPtx, []arkade.IntrospectorEntry{
		{Vin: 1, Script: arkadeScript},
	})

	encodedIntentProof, err := intentPtx.B64Encode()
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	signedIntentProof, err := bobWallet.SignTransaction(ctx, explorer, encodedIntentProof)
	require.NoError(t, err)
	require.NotEqual(t, signedIntentProof, encodedIntentProof)

	// SubmitIntent make the introspector execute the arkade script on the intent tx
	// if valid, it will sign the intent and return it
	approvedIntentProof, err := introspectorClient.SubmitIntent(ctx, introspectorclient.Intent{
		Proof:   signedIntentProof,
		Message: message,
	})
	require.NoError(t, err)

	signedIntent := introspectorclient.Intent{
		Proof:   approvedIntentProof,
		Message: message,
	}

	intentId, err := grpcClient.RegisterIntent(ctx, signedIntent.Proof, signedIntent.Message)
	require.NoError(t, err)

	vtxo := client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: redeemPtx.UnsignedTx.TxHash().String(),
				VOut: contractOutputIndex,
			},
			Script: hex.EncodeToString(arkadeTapscript),
			Amount: uint64(contractOutput.Value),
		},
		Tapscripts: tapscripts,
	}

	introspectorBatchHandler := &delegateBatchEventsHandler{
		intentId:           intentId,
		intent:             signedIntent,
		vtxosToForfeit:     []client.TapscriptsVtxo{vtxo},
		signerSession:      treeSignerSession,
		introspectorClient: introspectorClient,
		wallet:             bobWallet,
		client:             grpcClient,
	}

	topics := arksdk.GetEventStreamTopics([]types.Outpoint{vtxo.Outpoint}, []tree.SignerSession{treeSignerSession})
	eventStream, stop, err := grpcClient.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(func() {
		stop()
	})

	commitmentTxid, err := arksdk.JoinBatchSession(ctx, eventStream, introspectorBatchHandler)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
}

func TestBoarding(t *testing.T) {
	ctx := t.Context()
	alice, grpcClient := setupArkSDK(t)
	t.Cleanup(func() {
		grpcClient.Close()
	})

	bobPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	configStore, err := inmemorystoreconfig.NewConfigStore()
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)

	bobWallet, err := singlekeywallet.NewBitcoinWallet(
		configStore,
		walletStore,
	)
	require.NoError(t, err)

	_, err = bobWallet.Create(ctx, password, hex.EncodeToString(bobPrivKey.Serialize()))
	require.NoError(t, err)

	_, err = bobWallet.Unlock(ctx, password)
	require.NoError(t, err)

	bobPubKey := bobPrivKey.PubKey()

	_, offchainAddr, _, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	// script verifying that the spending tx includes an output going to alice's address
	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(alicePkScript[2:]). // only witness program is pushed
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	// create the client
	conn, err := grpc.NewClient("localhost:7073", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	introspectorClient := introspectorclient.NewGRPCClient(conn)

	introspectorInfo, err := introspectorClient.GetInfo(ctx)
	require.NoError(t, err)
	require.NotNil(t, introspectorInfo)

	publicKeyBytes, err := hex.DecodeString(introspectorInfo.SignerPublicKey)
	require.NoError(t, err)
	publicKey, err := btcec.ParsePubKey(publicKeyBytes)
	require.NoError(t, err)

	arkadeKey := arkade.ComputeArkadeScriptPublicKey(
		publicKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	arkInfos, err := grpcClient.GetInfo(ctx)
	require.NoError(t, err)

	boardingExitDelay := getBatchExpiryLocktime(uint32(arkInfos.BoardingExitDelay))

	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{bobPubKey, aliceAddr.Signer, arkadeKey},
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{bobPubKey},
				},
				Locktime: boardingExitDelay,
			},
		},
	}

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(arkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	// compute the P2TR bitcoin address for the contract
	contractBtcAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	// faucet the contract address with onchain funds
	faucetOutput, err := runCommand("nigiri", "faucet", contractBtcAddr.EncodeAddress())
	require.NoError(t, err)

	faucetTxid := strings.TrimSpace(strings.TrimPrefix(faucetOutput, "txId:"))

	time.Sleep(5 * time.Second)

	// get the raw transaction to find the contract output
	rawTxHex, err := runCommand("nigiri", "rpc", "getrawtransaction", faucetTxid)
	require.NoError(t, err)

	rawTxBytes, err := hex.DecodeString(strings.TrimSpace(rawTxHex))
	require.NoError(t, err)

	faucetMsgTx := wire.NewMsgTx(wire.TxVersion)
	err = faucetMsgTx.Deserialize(bytes.NewReader(rawTxBytes))
	require.NoError(t, err)

	contractPkScript, err := script.P2TRScript(vtxoTapKey)
	require.NoError(t, err)

	var contractOutput *wire.TxOut
	var contractOutputIndex uint32
	for i, out := range faucetMsgTx.TxOut {
		if bytes.Equal(out.PkScript, contractPkScript) {
			contractOutput = out
			contractOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, contractOutput)

	// create the intent

	randomKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	treeSignerSession := tree.NewTreeSignerSession(randomKey)
	require.NoError(t, err)

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

	intent, err := intent.New(
		message,
		[]intent.Input{
			{
				OutPoint: &wire.OutPoint{
					Hash:  faucetMsgTx.TxHash(),
					Index: contractOutputIndex,
				},
				Sequence:    wire.MaxTxInSequenceNum,
				WitnessUtxo: contractOutput,
			},
		},
		[]*wire.TxOut{
			{
				Value:    contractOutput.Value,
				PkScript: alicePkScript,
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, intent)
	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)
	taptreeField, err := txutils.VtxoTaprootTreeField.Encode(tapscripts)
	require.NoError(t, err)

	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	tapLeafScript := []*psbt.TaprootTapLeafScript{
		{
			LeafVersion:  txscript.BaseLeafVersion,
			ControlBlock: ctrlBlockBytes,
			Script:       merkleProof.Script,
		},
	}
	intent.Inputs[0].TaprootLeafScript = tapLeafScript
	intent.Inputs[1].TaprootLeafScript = tapLeafScript
	intent.Inputs[0].Unknowns = append(intent.Inputs[0].Unknowns, taptreeField)
	intent.Inputs[1].Unknowns = append(intent.Inputs[1].Unknowns, taptreeField)

	intentPtx := &intent.Packet
	addIntrospectorPacket(t, intentPtx, []arkade.IntrospectorEntry{
		{Vin: 1, Script: arkadeScript},
	})

	encodedIntentProof, err := intentPtx.B64Encode()
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	signedIntentProof, err := bobWallet.SignTransaction(ctx, explorer, encodedIntentProof)
	require.NoError(t, err)
	require.NotEqual(t, signedIntentProof, encodedIntentProof)

	// SubmitIntent make the introspector execute the arkade script on the intent tx
	// if valid, it will sign the intent and return it
	approvedIntentProof, err := introspectorClient.SubmitIntent(ctx, introspectorclient.Intent{
		Proof:   signedIntentProof,
		Message: message,
	})
	require.NoError(t, err)

	signedIntent := introspectorclient.Intent{
		Proof:   approvedIntentProof,
		Message: message,
	}

	intentId, err := grpcClient.RegisterIntent(ctx, signedIntent.Proof, signedIntent.Message)
	require.NoError(t, err)

	vtxo := client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: faucetMsgTx.TxHash().String(),
				VOut: contractOutputIndex,
			},
			Script: hex.EncodeToString(arkadeTapscript),
			Amount: uint64(contractOutput.Value),
		},
		Tapscripts: tapscripts,
	}

	introspectorBatchHandler := &boardingBatchEventsHandler{
		delegateBatchEventsHandler: &delegateBatchEventsHandler{
			intentId:           intentId,
			intent:             signedIntent,
			signerSession:      treeSignerSession,
			introspectorClient: introspectorClient,
			wallet:             bobWallet,
			client:             grpcClient,
			explorer:           explorer,
		},
		boardingVtxo: vtxo,
	}

	topics := arksdk.GetEventStreamTopics([]types.Outpoint{vtxo.Outpoint}, []tree.SignerSession{treeSignerSession})
	eventStream, stop, err := grpcClient.GetEventStream(ctx, topics)
	require.NoError(t, err)
	t.Cleanup(func() {
		stop()
	})

	commitmentTxid, err := arksdk.JoinBatchSession(ctx, eventStream, introspectorBatchHandler)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)
}

func TestIntrospectorRejectsInvalidArkadeScript(t *testing.T) {
	ctx := t.Context()
	alice, grpcAlice := setupArkSDK(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	const (
		sendAmount = 10000
	)

	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	aliceAddr := fundAndSettleAlice(t, ctx, alice, sendAmount)

	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	// script verifying that the witness contains 2 numbers that sum to 10
	arkadeScript, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_ADD).
		AddInt64(10).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	// create the client
	introspectorClient, introspectorPublicKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	vtxoScript := createVtxoScriptWithArkadeScript(bobPubKey, aliceAddr.Signer, introspectorPublicKey, arkade.ArkadeScriptHash(arkadeScript))

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

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	invalidArkadeScript, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_1).
		Script()
	require.NoError(t, err)

	testCases := []struct {
		name     string
		contains string
		entry    arkade.IntrospectorEntry
		mutateTx func(*testing.T, *psbt.Packet)
	}{
		{
			name:     "malformed witness",
			contains: "EOF",
			entry: arkade.IntrospectorEntry{
				Vin:     0,
				Script:  arkadeScript,
				Witness: wire.TxWitness{uint64LE(6), {0, 0, 0, 0, 0, 0, 0, 4}},
			},
			mutateTx: func(t *testing.T, ptx *psbt.Packet) {
				t.Helper()
				// the introspector packet should be the penultimate output (before P2A)
				require.GreaterOrEqual(t, len(ptx.UnsignedTx.TxOut), 2)
				idx := len(ptx.UnsignedTx.TxOut) - 2
				pkScript := ptx.UnsignedTx.TxOut[idx].PkScript
				// increment the last witness element varint to cause EOF
				ptx.UnsignedTx.TxOut[idx].PkScript[len(pkScript)-9] = pkScript[len(pkScript)-9] + 1
			},
		},
		{
			name:     "script hash mismatch",
			contains: "tweaked arkade script public key not found in tapscript",
			entry: arkade.IntrospectorEntry{
				Vin:    0,
				Script: invalidArkadeScript,
			},
		},
		{
			name:     "missing taproot leaf script",
			contains: "input does not specify any TaprootLeafScript",
			entry: arkade.IntrospectorEntry{
				Vin:    0,
				Script: arkadeScript,
			},
			mutateTx: func(t *testing.T, ptx *psbt.Packet) {
				t.Helper()
				require.NotEmpty(t, ptx.Inputs)
				ptx.Inputs[0].TaprootLeafScript = nil
			},
		},
		{
			name:     "non-multisig tapscript",
			contains: "failed to decode tapscript",
			entry: arkade.IntrospectorEntry{
				Vin:    0,
				Script: arkadeScript,
			},
			mutateTx: func(t *testing.T, ptx *psbt.Packet) {
				t.Helper()
				require.NotEmpty(t, ptx.Inputs)
				require.NotEmpty(t, ptx.Inputs[0].TaprootLeafScript)
				require.NotNil(t, ptx.Inputs[0].TaprootLeafScript[0])
				ptx.Inputs[0].TaprootLeafScript[0].Script = []byte{txscript.OP_TRUE}
			},
		},
		{
			name:     "malformed tapscript decode",
			contains: "failed to decode tapscript",
			entry: arkade.IntrospectorEntry{
				Vin:    0,
				Script: arkadeScript,
			},
			mutateTx: func(t *testing.T, ptx *psbt.Packet) {
				t.Helper()
				require.NotEmpty(t, ptx.Inputs)
				require.NotEmpty(t, ptx.Inputs[0].TaprootLeafScript)
				require.NotNil(t, ptx.Inputs[0].TaprootLeafScript[0])
				ptx.Inputs[0].TaprootLeafScript[0].Script = nil
			},
		},
		{
			name:     "input index out of range",
			contains: "input index out of range",
			entry: arkade.IntrospectorEntry{
				Vin:    1,
				Script: arkadeScript,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			invalidTx, invalidCheckpoints, err := offchain.BuildTxs(
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

			addIntrospectorPacket(t, invalidTx, []arkade.IntrospectorEntry{tc.entry})

			if tc.mutateTx != nil {
				tc.mutateTx(t, invalidTx)
			}

			// confirm the packet is malformed for the reason stated in the testcase
			packet, err := arkade.FindIntrospectorPacket(invalidTx.UnsignedTx)
			if err != nil {
				require.Contains(t, err.Error(), tc.contains)
			} else {
				require.NotNil(t, packet)
				require.Len(t, packet, 1)

				entry := packet[0]
				_, err = arkade.ReadArkadeScript(invalidTx, introspectorPublicKey, entry)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.contains)
			}

			encodedInvalidTx, err := invalidTx.B64Encode()
			require.NoError(t, err)

			signedInvalidTx, err := bobWallet.SignTransaction(
				ctx,
				explorer,
				encodedInvalidTx,
			)
			require.NoError(t, err)

			encodedInvalidCheckpoints := make([]string, 0, len(invalidCheckpoints))
			for _, checkpoint := range invalidCheckpoints {
				encoded, err := checkpoint.B64Encode()
				require.NoError(t, err)
				encodedInvalidCheckpoints = append(encodedInvalidCheckpoints, encoded)
			}

			_, _, err = introspectorClient.SubmitTx(ctx, signedInvalidTx, encodedInvalidCheckpoints)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to process transaction")
		})
	}
}

const password = "password"

func setupIndexer(t *testing.T) indexer.Indexer {
	svc, err := grpcindexer.NewClient("localhost:7070")
	require.NoError(t, err)
	return svc
}

func setupArkSDKwithPublicKey(
	t *testing.T,
) (arksdk.ArkClient, wallet.WalletService, *btcec.PublicKey, client.TransportClient) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.InMemoryStore,
		AppDataStoreType: types.KVStore,
	})
	require.NoError(t, err)

	client, err := arksdk.NewArkClient(appDataStore)
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)
	require.NotNil(t, walletStore)

	wallet, err := singlekeywallet.NewBitcoinWallet(appDataStore.ConfigStore(), walletStore)
	require.NoError(t, err)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privkeyHex := hex.EncodeToString(privkey.Serialize())

	err = client.InitWithWallet(t.Context(), arksdk.InitWithWalletArgs{
		Wallet:     wallet,
		ClientType: arksdk.GrpcClient,
		ServerUrl:  "localhost:7070",
		Password:   password,
		Seed:       privkeyHex,
	})
	require.NoError(t, err)

	err = client.Unlock(t.Context(), password)
	require.NoError(t, err)

	grpcClient, err := grpcclient.NewClient("localhost:7070")
	require.NoError(t, err)

	return client, wallet, privkey.PubKey(), grpcClient
}

func setupArkSDK(t *testing.T) (arksdk.ArkClient, client.TransportClient) {
	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	return alice, grpcAlice
}

func runCommand(name string, arg ...string) (string, error) {
	errb := new(strings.Builder)
	cmd := exec.Command(name, arg...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}
	output := new(strings.Builder)
	errorb := new(strings.Builder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(output, stdout); err != nil {
			fmt.Fprintf(errb, "error reading stdout: %s", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(errorb, stderr); err != nil {
			fmt.Fprintf(errb, "error reading stderr: %s", err)
		}
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if errMsg := errorb.String(); len(errMsg) > 0 {
			return "", fmt.Errorf("%s", errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf("%s", outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf("%s", errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func generateBlock() error {
	_, err := runCommand("nigiri", "rpc", "--generate", "1")
	return err
}

var ErrAlreadySetup = errors.New("already setup")

func setupServerWalletAndCLI() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	// skip if already setup
	resp, err := http.NewRequest("GET", "http://localhost:7070/v1/info", nil)
	if resp.Response != nil && err == nil {
		return ErrAlreadySetup
	}

	req, err := http.NewRequest("GET", "http://localhost:7071/v1/admin/wallet/seed", nil)
	if err != nil {
		return fmt.Errorf("failed to prepare generate seed request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")

	seedResp, err := adminHttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to generate seed: %s", err)
	}

	var seed struct {
		Seed string `json:"seed"`
	}

	if err := json.NewDecoder(seedResp.Body).Decode(&seed); err != nil {
		return fmt.Errorf("failed to parse response: %s", err)
	}

	reqBody := bytes.NewReader(
		[]byte(fmt.Sprintf(`{"seed": "%s", "password": "%s"}`, seed.Seed, password)),
	)
	req, err = http.NewRequest("POST", "http://localhost:7071/v1/admin/wallet/create", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet create request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to create wallet: %s", err)
	}

	reqBody = bytes.NewReader([]byte(fmt.Sprintf(`{"password": "%s"}`, password)))
	req, err = http.NewRequest("POST", "http://localhost:7071/v1/admin/wallet/unlock", reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare wallet unlock request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	if _, err := adminHttpClient.Do(req); err != nil {
		return fmt.Errorf("failed to unlock wallet: %s", err)
	}

	var status struct {
		Initialized bool `json:"initialized"`
		Unlocked    bool `json:"unlocked"`
		Synced      bool `json:"synced"`
	}
	for {
		time.Sleep(time.Second)

		req, err := http.NewRequest("GET", "http://localhost:7071/v1/admin/wallet/status", nil)
		if err != nil {
			return fmt.Errorf("failed to prepare status request: %s", err)
		}
		resp, err := adminHttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get status: %s", err)
		}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return fmt.Errorf("failed to parse status response: %s", err)
		}
		if status.Initialized && status.Unlocked && status.Synced {
			break
		}
	}

	var addr struct {
		Address string `json:"address"`
	}
	for addr.Address == "" {
		time.Sleep(time.Second)

		req, err = http.NewRequest("GET", "http://localhost:7071/v1/admin/wallet/address", nil)
		if err != nil {
			return fmt.Errorf("failed to prepare new address request: %s", err)
		}
		req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")

		resp, err := adminHttpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get new address: %s", err)
		}

		if err := json.NewDecoder(resp.Body).Decode(&addr); err != nil {
			return fmt.Errorf("failed to parse response: %s", err)
		}
	}

	const numberOfFaucet = 15 // must cover the liquidity needed for all tests

	for i := 0; i < numberOfFaucet; i++ {
		_, err = runCommand("nigiri", "faucet", addr.Address)
		if err != nil {
			return fmt.Errorf("failed to fund wallet: %s", err)
		}
	}

	time.Sleep(5 * time.Second)

	if _, err := runArkCommand(
		"init", "--server-url", "localhost:7070", "--password", password,
		"--explorer", "http://chopsticks:3000",
	); err != nil {
		return fmt.Errorf("error initializing ark config: %s", err)
	}

	// wait for introspector to come up
	for {
		time.Sleep(time.Second)

		conn, err := grpc.NewClient("localhost:7073", grpc.WithTransportCredentials(insecure.NewCredentials()))

		if err != nil {
			continue
		}

		introspectorClient := introspectorclient.NewGRPCClient(conn)

		if _, err := introspectorClient.GetInfo(context.Background()); err == nil {
			break
		}
	}

	return nil
}

func runArkCommand(arg ...string) (string, error) {
	args := append([]string{"ark"}, arg...)
	return runDockerExec("arkd", args...)
}

func runDockerExec(container string, arg ...string) (string, error) {
	args := append([]string{"exec", "-t", container}, arg...)
	out, err := runCommand("docker", args...)
	if err != nil {
		return "", err
	}
	idx := strings.Index(out, "{")
	if idx == -1 {
		return out, nil
	}
	return out[idx:], nil
}
