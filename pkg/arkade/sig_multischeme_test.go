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

func TestOpCheckSigECDSASecp256r1(t *testing.T) {
	t.Parallel()
	priv, comp := r1CompressedPubKey(t)
	pk := append([]byte{extPubKeyECDSASecp256r1}, comp...)
	err := checkSigLeafECDSA(t, pk, func(d []byte) []byte {
		return ecdsaR1Compact(t, priv, d)
	})
	require.NoError(t, err)
}

func TestOpCheckSigECDSAWrongKeyRejected(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	other, _ := btcec.NewPrivateKey()
	pk := append([]byte{extPubKeyECDSASecp256k1}, priv.PubKey().SerializeCompressed()...)
	err := checkSigLeafECDSA(t, pk, func(d []byte) []byte {
		return ecdsaK1Compact(t, other, d)
	})
	require.Error(t, err)
}

func TestOpCheckSigECDSAExplicitSighashByte(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	pk := append([]byte{extPubKeyECDSASecp256k1}, priv.PubKey().SerializeCompressed()...)

	leaf, err := txscript.NewScriptBuilder().AddData(pk).AddOp(OP_CHECKSIG).Script()
	require.NoError(t, err)
	engine := runTapscriptLeaf(t, leaf, wire.TxWitness{nil}, 2_000_000)
	digest := arkadeDigest(t, &engine.tx, 0, engine.prevOutFetcher,
		leaf, txscript.SigHashAll)
	engine.tx.TxIn[0].Witness[0] = append(
		ecdsaK1Compact(t, priv, digest), byte(txscript.SigHashAll))
	require.NoError(t, engine.Execute())
}

func TestCSFSECDSASecp256k1(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	pk := append([]byte{extPubKeyECDSASecp256k1}, priv.PubKey().SerializeCompressed()...)
	digest := bytes.Repeat([]byte{0x33}, 32)
	sig := ecdsaK1Compact(t, priv, digest)
	require.NoError(t, csfsLeaf(t, pk, digest, sig))
}

func TestCSFSECDSARejectsNonDigestMessage(t *testing.T) {
	t.Parallel()
	priv, comp := r1CompressedPubKey(t)
	pk := append([]byte{extPubKeyECDSASecp256r1}, comp...)
	digest := bytes.Repeat([]byte{0x44}, 32)
	sig := ecdsaR1Compact(t, priv, digest)
	require.Error(t, csfsLeaf(t, pk, append(digest, 0x00), sig))
}

func TestCSFSSchnorrLegacyStillWorks(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	xonly := schnorr.SerializePubKey(priv.PubKey())
	msg := bytes.Repeat([]byte{0x22}, 32)
	sig, err := schnorr.Sign(priv, msg)
	require.NoError(t, err)
	require.NoError(t, csfsLeaf(t, xonly, msg, sig.Serialize()))
}

func TestCSFSNativeP256InScriptSha256(t *testing.T) {
	t.Parallel()

	priv, comp := r1CompressedPubKey(t)
	message := []byte("oracle price=42000")
	digest := sha256.Sum256(message)
	sig := ecdsaR1Compact(t, priv, digest[:])

	// Script hashes the witness message before native P-256 verification.
	leaf, err := txscript.NewScriptBuilder().
		AddOp(OP_SHA256).
		AddData(append([]byte{extPubKeyECDSASecp256r1}, comp...)).
		AddOp(OP_CHECKSIGFROMSTACK).
		Script()
	require.NoError(t, err)

	run := func(w wire.TxWitness) error {
		return runTapscriptLeaf(t, leaf, w, 1_000_000).Execute()
	}
	require.NoError(t, run(wire.TxWitness{sig, message}))

	bad := append([]byte{}, sig...)
	bad[0] ^= 0x01
	require.Error(t, run(wire.TxWitness{bad, message}))
}

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

func csfsLeaf(t *testing.T, pubKey, msg, sig []byte) error {
	t.Helper()
	leaf, err := txscript.NewScriptBuilder().AddOp(OP_CHECKSIGFROMSTACK).Script()
	require.NoError(t, err)
	// Initial stack order is bottom-to-top; CSFS pops pubkey, msg, sig.
	engine := runTapscriptLeaf(t, leaf, wire.TxWitness{sig, msg, pubKey}, 1_000_000)
	return engine.Execute()
}
