package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ArkLabsHQ/emulator/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/go-sdk/explorer"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestSubmitOnchainTx funds an arkade-tweaked P2TR address directly via
// `nigiri faucet`, then spends it via a plain Bitcoin transaction where the
// emulator co-signs after running the embedded arkade script.
func TestSubmitOnchainTx(t *testing.T) {
	ctx := context.Background()

	// --- Setup Bob & emulator ---
	bobWallet, _, bobPubKey := setupWallet(t, ctx)
	emulatorClient, emulatorPubKey, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() { _ = conn.Close() })

	// Reuse aliceSigner role with a fresh random pubkey (not used for signing).
	aliceKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	aliceSigner := aliceKey.PubKey()

	const (
		fundingAmount int64 = 1_000_000 // 0.01 BTC
		feeAmount     int64 = 500
		spendAmount         = fundingAmount - feeAmount
	)

	// --- Bob's destination P2TR output ---
	bobPkScript, err := txscript.PayToTaprootScript(bobPubKey)
	require.NoError(t, err)

	// --- Build arkade script: output 0 pays Bob exactly spendAmount ---
	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // taproot version
		AddData(bobPkScript[2:]).     // witness program
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(spendAmount).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	arkadeScriptHash := arkade.ArkadeScriptHash(arkadeScript)

	// --- VTXO-shaped tapscript with the arkade closure ---
	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey, aliceSigner, emulatorPubKey, arkadeScriptHash,
	)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]
	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(arkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	// --- Derive regtest P2TR address for the tweaked taproot key ---
	regtestParams := getRegtestParams(t)
	tapAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey), regtestParams,
	)
	require.NoError(t, err)
	tapAddrStr := tapAddr.EncodeAddress()

	// --- Fund the address via nigiri ---
	_, err = runCommand("nigiri", "faucet", tapAddrStr, "0.01")
	require.NoError(t, err)

	explorerSvc, err := mempoolexplorer.NewExplorer(
		"http://localhost:3000", arklib.BitcoinRegTest,
	)
	require.NoError(t, err)

	// --- Poll for UTXO and fetch raw funding tx ---
	fundingUtxo := waitForUtxo(t, explorerSvc, tapAddrStr, 60*time.Second)

	// Mine a block so the funding tx is confirmed.
	_, err = runCommand("nigiri", "rpc", "-generate", "1")
	require.NoError(t, err)

	rawFundingHex, err := explorerSvc.GetTxHex(fundingUtxo.Txid)
	require.NoError(t, err)

	rawFundingBytes, err := hex.DecodeString(rawFundingHex)
	require.NoError(t, err)

	rawFundingTx := wire.NewMsgTx(wire.TxVersion)
	require.NoError(t, rawFundingTx.Deserialize(bytes.NewReader(rawFundingBytes)))

	// Sanity: resolve correct output index by comparing pkscript.
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

	t.Run("valid", func(t *testing.T) {
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

		finalPtx, err := psbt.NewFromRawBytes(strings.NewReader(fullySigned), true)
		require.NoError(t, err)

		require.GreaterOrEqual(
			t, len(finalPtx.Inputs[0].TaprootScriptSpendSig), 2,
			"expected at least 2 signatures (Bob + emulator)",
		)

		// Add alice's signature to complete the 3-of-3 multisig.
		leaf := txscript.NewBaseTapLeaf(arkadeTapscript)
		prevoutFetcher := txscript.NewCannedPrevOutputFetcher(
			fundingOutput.PkScript, fundingOutput.Value,
		)
		sigHashes := txscript.NewTxSigHashes(finalPtx.UnsignedTx, prevoutFetcher)
		aliceSig, err := txscript.RawTxInTapscriptSignature(
			finalPtx.UnsignedTx, sigHashes, 0,
			fundingOutput.Value, fundingOutput.PkScript,
			leaf, txscript.SigHashDefault, aliceKey,
		)
		require.NoError(t, err)

		// finalize and broadcast
		closureIface, err := script.DecodeClosure(arkadeTapscript)
		require.NoError(t, err)

		sigs := map[string][]byte{
			hex.EncodeToString(schnorr.SerializePubKey(aliceKey.PubKey())): aliceSig[:64],
		}
		for _, s := range finalPtx.Inputs[0].TaprootScriptSpendSig {
			sigs[hex.EncodeToString(s.XOnlyPubKey)] = s.Signature
		}

		witness, err := closureIface.Witness(merkleProof.ControlBlock, sigs)
		require.NoError(t, err)

		var witnessBuf bytes.Buffer
		require.NoError(t, psbt.WriteTxWitness(&witnessBuf, witness))
		finalPtx.Inputs[0].FinalScriptWitness = witnessBuf.Bytes()
		finalPtx.Inputs[0].TaprootScriptSpendSig = nil
		finalPtx.Inputs[0].TaprootLeafScript = nil

		extractedTx, err := psbt.Extract(finalPtx)
		require.NoError(t, err)

		var rawBuf bytes.Buffer
		require.NoError(t, extractedTx.Serialize(&rawBuf))

		txid, err := explorerSvc.Broadcast(hex.EncodeToString(rawBuf.Bytes()))
		require.NoError(t, err)
		require.NotEmpty(t, txid)
	})

	t.Run("no emulator packet", func(t *testing.T) {
		ptx := buildOnchainSpendPtx(
			t, *fundingTxid, fundingVout, fundingOutput,
			&wire.TxOut{Value: spendAmount, PkScript: bobPkScript},
			merkleProof, rawFundingTx, nil, // no arkade script → no OP_RETURN
		)

		encoded, err := ptx.B64Encode()
		require.NoError(t, err)

		bobSigned, err := bobWallet.SignTransaction(ctx, explorerSvc, encoded)
		require.NoError(t, err)

		_, err = emulatorClient.SubmitOnchainTx(ctx, bobSigned)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process onchain tx")
	})

	t.Run("PrevoutTxField wrong txid", func(t *testing.T) {
		// Build a bogus tx (different from the real funding tx).
		bogusTx := wire.NewMsgTx(wire.TxVersion)
		bogusTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x6a}})

		ptx := buildOnchainSpendPtxCustomPrevout(
			t, *fundingTxid, fundingVout, fundingOutput,
			&wire.TxOut{Value: spendAmount, PkScript: bobPkScript},
			merkleProof, bogusTx, arkadeScript,
		)

		encoded, err := ptx.B64Encode()
		require.NoError(t, err)

		bobSigned, err := bobWallet.SignTransaction(ctx, explorerSvc, encoded)
		require.NoError(t, err)

		_, err = emulatorClient.SubmitOnchainTx(ctx, bobSigned)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process onchain tx")
	})

	t.Run("arkade script fails", func(t *testing.T) {
		// Output value off by one — arkade script requires exactly spendAmount.
		ptx := buildOnchainSpendPtx(
			t, *fundingTxid, fundingVout, fundingOutput,
			&wire.TxOut{Value: spendAmount - 1, PkScript: bobPkScript},
			merkleProof, rawFundingTx, arkadeScript,
		)

		encoded, err := ptx.B64Encode()
		require.NoError(t, err)

		bobSigned, err := bobWallet.SignTransaction(ctx, explorerSvc, encoded)
		require.NoError(t, err)

		_, err = emulatorClient.SubmitOnchainTx(ctx, bobSigned)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process onchain tx")
	})

	t.Run("rejects tapscript containing arkd pubkey", func(t *testing.T) {
		// Pull arkd's signer pubkey from the running server.
		_, grpcAlice := setupArkSDK(t)
		defer grpcAlice.Close()
		arkInfo, err := grpcAlice.GetInfo(ctx)
		require.NoError(t, err)
		arkdPubBytes, err := hex.DecodeString(arkInfo.SignerPubKey)
		require.NoError(t, err)
		arkdPubKey, err := btcec.ParsePubKey(arkdPubBytes)
		require.NoError(t, err)

		// VTXO script including arkd's pubkey — this is exactly the shape
		// SubmitOnchainTx must refuse.
		vtxoWithArkd := createVtxoScriptWithArkadeScript(
			bobPubKey, arkdPubKey, emulatorPubKey, arkadeScriptHash,
		)
		_, vtxoWithArkdTapTree, err := vtxoWithArkd.TapTree()
		require.NoError(t, err)
		arkdTapscript, err := vtxoWithArkd.ForfeitClosures()[0].Script()
		require.NoError(t, err)
		arkdMerkleProof, err := vtxoWithArkdTapTree.GetTaprootMerkleProof(
			txscript.NewBaseTapLeaf(arkdTapscript).TapHash(),
		)
		require.NoError(t, err)

		// The reject check runs before script execution and signing, so we
		// can reuse the already-funded outpoint's WitnessUtxo value; the
		// on-wire tapscript metadata is what matters for the check.
		ptx := buildOnchainSpendPtx(
			t, *fundingTxid, fundingVout, fundingOutput,
			&wire.TxOut{Value: spendAmount, PkScript: bobPkScript},
			arkdMerkleProof, rawFundingTx, arkadeScript,
		)

		encoded, err := ptx.B64Encode()
		require.NoError(t, err)

		_, err = emulatorClient.SubmitOnchainTx(ctx, encoded)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process onchain tx")
	})

	// VTXO whose exit leaf is a CSVMultisigClosure containing the emulator's arkade-tweaked key.
	// Post-unroll, the owner can continue the covenant execution onchain.
	t.Run("CSV exit closure", func(t *testing.T) {
		const csvBlocks uint32 = 3

		csvLocktime := arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeBlock, Value: csvBlocks,
		}
		exitScript := createVtxoScriptWithArkadeExitClosure(
			bobPubKey, aliceSigner, emulatorPubKey, arkadeScriptHash, csvLocktime,
		)
		exitTapKey, exitTapTree, err := exitScript.TapTree()
		require.NoError(t, err)

		// Merkle proof for the CSV exit leaf (second closure).
		csvLeafScript, err := exitScript.Closures[1].Script()
		require.NoError(t, err)
		exitMerkleProof, err := exitTapTree.GetTaprootMerkleProof(
			txscript.NewBaseTapLeaf(csvLeafScript).TapHash(),
		)
		require.NoError(t, err)

		// Fund the exit-shaped tapscript address (simulates a fully
		// unrolled VTXO sitting onchain under this tapscript).
		exitAddr, err := btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(exitTapKey), regtestParams,
		)
		require.NoError(t, err)
		exitAddrStr := exitAddr.EncodeAddress()

		_, err = runCommand("nigiri", "faucet", exitAddrStr, "0.01")
		require.NoError(t, err)

		exitUtxo := waitForUtxo(t, explorerSvc, exitAddrStr, 60*time.Second)

		// Mine CSV + 1 blocks so the relative locktime is satisfied.
		for i := uint32(0); i < csvBlocks+1; i++ {
			_, err = runCommand("nigiri", "rpc", "-generate", "1")
			require.NoError(t, err)
		}

		exitRawHex, err := explorerSvc.GetTxHex(exitUtxo.Txid)
		require.NoError(t, err)
		exitRawBytes, err := hex.DecodeString(exitRawHex)
		require.NoError(t, err)
		exitRawTx := wire.NewMsgTx(wire.TxVersion)
		require.NoError(t, exitRawTx.Deserialize(bytes.NewReader(exitRawBytes)))

		exitContractPkScript, err := script.P2TRScript(exitTapKey)
		require.NoError(t, err)

		var exitOutput *wire.TxOut
		var exitVout uint32
		for i, out := range exitRawTx.TxOut {
			if bytes.Equal(out.PkScript, exitContractPkScript) {
				exitOutput = out
				exitVout = uint32(i)
				break
			}
		}
		require.NotNil(t, exitOutput)

		exitTxid, err := chainhash.NewHashFromStr(exitUtxo.Txid)
		require.NoError(t, err)

		// Build the spending PSBT with the CSV sequence set.
		unsigned := wire.NewMsgTx(wire.TxVersion)
		unsigned.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: *exitTxid, Index: exitVout},
			Sequence:         csvBlocks, // BIP-68 block-based CSV
		})
		unsigned.AddTxOut(&wire.TxOut{Value: spendAmount, PkScript: bobPkScript})

		ptx, err := psbt.NewFromUnsignedTx(unsigned)
		require.NoError(t, err)

		ptx.Inputs[0].WitnessUtxo = exitOutput
		ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: exitMerkleProof.ControlBlock,
			Script:       exitMerkleProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}}
		require.NoError(t, txutils.SetArkPsbtField(
			ptx, 0, arkade.PrevoutTxField, *exitRawTx,
		))
		addEmulatorPacket(t, ptx, []arkade.EmulatorEntry{
			{Vin: 0, Script: arkadeScript},
		})

		encoded, err := ptx.B64Encode()
		require.NoError(t, err)

		bobSigned, err := bobWallet.SignTransaction(ctx, explorerSvc, encoded)
		require.NoError(t, err)

		fullySigned, err := emulatorClient.SubmitOnchainTx(ctx, bobSigned)
		require.NoError(t, err)

		signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(fullySigned), true)
		require.NoError(t, err)

		emulatorTweaked := arkade.ComputeArkadeScriptPublicKey(
			emulatorPubKey, arkadeScriptHash,
		)
		wantKeys := map[string]struct{}{
			hex.EncodeToString(schnorr.SerializePubKey(bobPubKey)):       {},
			hex.EncodeToString(schnorr.SerializePubKey(emulatorTweaked)): {},
		}
		for _, sig := range signedPtx.Inputs[0].TaprootScriptSpendSig {
			delete(wantKeys, hex.EncodeToString(sig.XOnlyPubKey))
		}
		require.Empty(t, wantKeys)
	})
}

// buildOnchainSpendPtx builds a one-in / one-out PSBT that spends the funding
// outpoint and sends to the given output. It wires WitnessUtxo,
// TaprootLeafScript, PrevoutTxField, and (if arkadeScript != nil) an
// emulator OP_RETURN packet.
func buildOnchainSpendPtx(
	t *testing.T,
	fundingTxid chainhash.Hash,
	fundingVout uint32,
	fundingOutput *wire.TxOut,
	spendOutput *wire.TxOut,
	merkleProof *arklib.TaprootMerkleProof,
	rawFundingTx *wire.MsgTx,
	arkadeScript []byte,
) *psbt.Packet {
	return buildOnchainSpendPtxCustomPrevout(
		t, fundingTxid, fundingVout, fundingOutput, spendOutput,
		merkleProof, rawFundingTx, arkadeScript,
	)
}

func buildOnchainSpendPtxCustomPrevout(
	t *testing.T,
	fundingTxid chainhash.Hash,
	fundingVout uint32,
	fundingOutput *wire.TxOut,
	spendOutput *wire.TxOut,
	merkleProof *arklib.TaprootMerkleProof,
	prevoutTx *wire.MsgTx,
	arkadeScript []byte,
) *psbt.Packet {
	t.Helper()

	unsigned := wire.NewMsgTx(wire.TxVersion)
	unsigned.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: fundingTxid, Index: fundingVout},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	unsigned.AddTxOut(spendOutput)

	ptx, err := psbt.NewFromUnsignedTx(unsigned)
	require.NoError(t, err)

	ptx.Inputs[0].WitnessUtxo = fundingOutput
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: merkleProof.ControlBlock,
			Script:       merkleProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		},
	}

	require.NoError(t, txutils.SetArkPsbtField(
		ptx, 0, arkade.PrevoutTxField, *prevoutTx,
	))

	if arkadeScript != nil {
		addEmulatorPacket(t, ptx, []arkade.EmulatorEntry{
			{Vin: 0, Script: arkadeScript},
		})
	}

	return ptx
}

// getRegtestParams returns btcd chain params for regtest with bech32 HRP "bcrt".
func getRegtestParams(t *testing.T) *chaincfg.Params {
	t.Helper()
	params := chaincfg.RegressionNetParams
	params.Bech32HRPSegwit = "bcrt"
	return &params
}

// waitForUtxo polls the explorer until at least one UTXO appears at the
// given address, then returns it. Fails the test on timeout.
func waitForUtxo(
	t *testing.T, explorerSvc explorer.Explorer, addr string, timeout time.Duration,
) explorer.Utxo {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		utxos, err := explorerSvc.GetUtxos(addr)
		if err == nil && len(utxos) > 0 {
			return utxos[0]
		}
		time.Sleep(1 * time.Second)
	}

	t.Fatalf("timed out waiting for UTXO at %s", addr)
	return explorer.Utxo{}
}
