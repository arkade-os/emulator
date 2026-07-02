package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Requires the dockerized regtest stack; run through make integrationtest.
func TestCSFSNativeP256Multischeme(t *testing.T) {
	ctx := t.Context()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
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

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	message := []byte("oracle price=42000")

	digest := sha256.Sum256(message)

	comp := csfsMultischemeCompressedKey(t, priv)
	sig := csfsMultischemeCompactSig(t, priv, digest[:])

	arkadeScript := csfsMultischemeVerifyScript(t, comp)
	arkadeScriptHash := arkade.ArkadeScriptHash(arkadeScript)

	vtxoScript := createArkadeOnlyVtxoScript(aliceAddr.Signer, emulatorPubKey, arkadeScriptHash)

	const contractAmount = int64(10_000)
	validInput := fund(t, ctx, alice, indexerSvc, aliceAddr.Signer, vtxoScript, contractAmount)
	invalidInput := fund(t, ctx, alice, indexerSvc, aliceAddr.Signer, vtxoScript, contractAmount)

	validWitness := wire.TxWitness{sig, message}

	receiverPkScript := randomP2TR(t)

	buildSpend := func(input offchain.VtxoInput, w wire.TxWitness) (*psbt.Packet, []*psbt.Packet) {
		spendTx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{input},
			[]*wire.TxOut{{Value: contractAmount, PkScript: receiverPkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addEmulatorPacket(t, spendTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: arkadeScript, Witness: w},
		})
		return spendTx, checkpoints
	}

	t.Run("valid_signature_accepted", func(t *testing.T) {
		spendTx, checkpoints := buildSpend(validInput, validWitness)

		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, spendTx, 0)

		encoded, err := spendTx.B64Encode()
		require.NoError(t, err)

		_, _, err = emulatorClient.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
		require.NoError(t, err)
		waitForVtxos()
	})

	t.Run("tampered_signature_rejected", func(t *testing.T) {
		bad := append([]byte{}, sig...)
		bad[0] ^= 0x01

		spendTx, checkpoints := buildSpend(invalidInput, wire.TxWitness{bad, message})
		encoded, err := spendTx.B64Encode()
		require.NoError(t, err)

		_, _, err = emulatorClient.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	})
}

func csfsMultischemeVerifyScript(t *testing.T, comp []byte) []byte {
	t.Helper()
	// OP_SHA256 turns the witness message into the digest checked by CSFS.
	out, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_SHA256).
		AddData(append([]byte{0x11}, comp...)).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).
		Script()
	require.NoError(t, err)
	return out
}

func csfsMultischemeCompressedKey(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	enc, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	require.Len(t, enc, 65)
	x := new(big.Int).SetBytes(enc[1:33])
	y := new(big.Int).SetBytes(enc[33:65])
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

func csfsMultischemeCompactSig(t *testing.T, priv *ecdsa.PrivateKey, hash []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	require.NoError(t, err)
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s = new(big.Int).Sub(n, s)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}
