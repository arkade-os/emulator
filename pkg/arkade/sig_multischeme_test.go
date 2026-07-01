package arkade

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// checkSigLeafECDSA builds `<pubkey> OP_CHECKSIG` and runs it with sig as the
// sole witness item, returning the engine's Execute error.
func checkSigLeafECDSA(t *testing.T, extendedPubKey []byte,
	signCompact func(digest []byte) []byte) error {
	t.Helper()

	leaf, err := txscript.NewScriptBuilder().
		AddData(extendedPubKey).
		AddOp(OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	engine := runTapscriptLeaf(t, leaf, wire.TxWitness{nil}, 2_000_000)
	digest := arkadeDigest(t, &engine.tx, 0, engine.prevOutFetcher,
		leaf, txscript.SigHashDefault)
	engine.tx.TxIn[0].Witness[0] = signCompact(digest)
	return engine.Execute()
}

func TestOpCheckSigECDSASecp256k1(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	pk := append([]byte{0x10}, priv.PubKey().SerializeCompressed()...)
	err := checkSigLeafECDSA(t, pk, func(d []byte) []byte {
		return ecdsaK1Compact(t, priv, d)
	})
	require.NoError(t, err)
}

func TestOpCheckSigECDSASecp256r1(t *testing.T) {
	t.Parallel()
	priv, comp := r1CompressedPubKey(t)
	pk := append([]byte{0x11}, comp...)
	err := checkSigLeafECDSA(t, pk, func(d []byte) []byte {
		return ecdsaR1Compact(t, priv, d)
	})
	require.NoError(t, err)
}

func TestOpCheckSigECDSAWrongKeyRejected(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	other, _ := btcec.NewPrivateKey()
	pk := append([]byte{0x10}, priv.PubKey().SerializeCompressed()...)
	err := checkSigLeafECDSA(t, pk, func(d []byte) []byte {
		return ecdsaK1Compact(t, other, d) // signed by the wrong key
	})
	require.Error(t, err)
}

// verifies the explicit sighash-type byte path still works for ECDSA: a
// 65-byte sig (64 core + 0x01 SIGHASH_ALL) over the SIGHASH_ALL digest.
func TestOpCheckSigECDSAExplicitSighashByte(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	pk := append([]byte{0x10}, priv.PubKey().SerializeCompressed()...)

	leaf, err := txscript.NewScriptBuilder().AddData(pk).AddOp(OP_CHECKSIG).Script()
	require.NoError(t, err)
	engine := runTapscriptLeaf(t, leaf, wire.TxWitness{nil}, 2_000_000)
	digest := arkadeDigest(t, &engine.tx, 0, engine.prevOutFetcher,
		leaf, txscript.SigHashAll)
	engine.tx.TxIn[0].Witness[0] = append(
		ecdsaK1Compact(t, priv, digest), byte(txscript.SigHashAll))
	require.NoError(t, engine.Execute())
}

// csfsLeaf pushes the 3 CSFS inputs from the witness and runs
// `OP_CHECKSIGFROMSTACK`. Witness order (top on right): [sig, msg, pubkey].
func csfsLeaf(t *testing.T, pubKey, msg, sig []byte) error {
	t.Helper()
	leaf, err := txscript.NewScriptBuilder().AddOp(OP_CHECKSIGFROMSTACK).Script()
	require.NoError(t, err)
	// Engine expects witness pushed so that pop order is pubkey, msg, sig.
	engine := runTapscriptLeaf(t, leaf, wire.TxWitness{sig, msg, pubKey}, 1_000_000)
	return engine.Execute()
}

func TestCSFSECDSASecp256r1(t *testing.T) {
	t.Parallel()
	priv, comp := r1CompressedPubKey(t)
	pk := append([]byte{0x11}, comp...)

	// The script author owns hashing: here msg is already the 32-byte digest.
	digest := bytes.Repeat([]byte{0x5a}, 32)
	sig := ecdsaR1Compact(t, priv, digest)

	require.NoError(t, csfsLeaf(t, pk, digest, sig))

	bad := append([]byte{}, sig...)
	bad[10] ^= 0x01
	require.Error(t, csfsLeaf(t, pk, digest, bad))
}

func TestCSFSECDSASecp256k1(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	pk := append([]byte{0x10}, priv.PubKey().SerializeCompressed()...)
	digest := bytes.Repeat([]byte{0x33}, 32)
	sig := ecdsaK1Compact(t, priv, digest)
	require.NoError(t, csfsLeaf(t, pk, digest, sig))
}

// Backwards compat: legacy 32-byte Schnorr CSFS still verifies.
func TestCSFSSchnorrLegacyStillWorks(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	xonly := schnorr.SerializePubKey(priv.PubKey())
	msg := bytes.Repeat([]byte{0x22}, 32)
	sig, err := schnorr.Sign(priv, msg)
	require.NoError(t, err)
	require.NoError(t, csfsLeaf(t, xonly, msg, sig.Serialize()))
}

// TestCSFSNativeP256InScriptSha256 exercises the WebAuthn-shaped flow:
// the script hashes the witness message with OP_SHA256 in-script, then
// OP_CHECKSIGFROMSTACK verifies a native P-256 ECDSA signature over that
// digest. No EC-arithmetic opcodes are needed.
func TestCSFSNativeP256InScriptSha256(t *testing.T) {
	t.Parallel()

	priv, comp := r1CompressedPubKey(t)
	message := []byte("oracle price=42000")
	digest := sha256.Sum256(message)
	sig := ecdsaR1Compact(t, priv, digest[:])

	// Script: hash the witness message in-script, then verify a native P-256
	// ECDSA sig over that digest. Stack before CSFS: [sig, sha256(message), pubkey].
	leaf, err := txscript.NewScriptBuilder().
		AddOp(OP_SHA256).
		AddData(append([]byte{0x11}, comp...)).
		AddOp(OP_CHECKSIGFROMSTACK).
		Script()
	require.NoError(t, err)

	run := func(w wire.TxWitness) error {
		return runTapscriptLeaf(t, leaf, w, 1_000_000).Execute()
	}
	// Witness supplies [signature, message]; OP_SHA256 replaces message with its digest.
	require.NoError(t, run(wire.TxWitness{sig, message}))

	bad := append([]byte{}, sig...)
	bad[0] ^= 0x01
	require.Error(t, run(wire.TxWitness{bad, message}))
}
