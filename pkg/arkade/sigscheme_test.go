package arkade

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestParseSchemePubKey(t *testing.T) {
	t.Parallel()

	k1Priv, _ := btcec.NewPrivateKey()
	xonly := schnorr.SerializePubKey(k1Priv.PubKey())
	k1Comp := k1Priv.PubKey().SerializeCompressed()
	_, r1Comp := r1CompressedPubKey(t)

	t.Run("legacy_32B_is_schnorr_secp256k1", func(t *testing.T) {
		got, err := parseSchemePubKey(xonly)
		require.NoError(t, err)
		require.Equal(t, schemeSchnorrSecp256k1, got.scheme)
		require.NotNil(t, got.secpPub)
	})

	t.Run("prefix_0x10_is_ecdsa_secp256k1", func(t *testing.T) {
		got, err := parseSchemePubKey(append([]byte{extPubKeyECDSASecp256k1}, k1Comp...))
		require.NoError(t, err)
		require.Equal(t, schemeECDSASecp256k1, got.scheme)
		require.NotNil(t, got.secpPub)
	})

	t.Run("prefix_0x11_is_ecdsa_secp256r1", func(t *testing.T) {
		got, err := parseSchemePubKey(append([]byte{extPubKeyECDSASecp256r1}, r1Comp...))
		require.NoError(t, err)
		require.Equal(t, schemeECDSASecp256r1, got.scheme)
		require.NotNil(t, got.nistPub)
	})

	t.Run("empty_is_pubkey_empty_error", func(t *testing.T) {
		_, err := parseSchemePubKey(nil)
		requireScriptErrorCode(t, err, txscript.ErrTaprootPubkeyIsEmpty)
	})

	t.Run("reserved_schnorr_extended_discouraged", func(t *testing.T) {
		_, err := parseSchemePubKey(append([]byte{0x00}, xonly...))
		requireScriptErrorCode(t, err, txscript.ErrDiscourageUpgradeablePubKeyType)
	})

	t.Run("unknown_prefix_discouraged", func(t *testing.T) {
		_, err := parseSchemePubKey(append([]byte{0x20}, k1Comp...))
		requireScriptErrorCode(t, err, txscript.ErrDiscourageUpgradeablePubKeyType)
	})

	t.Run("wrong_length_key_discouraged", func(t *testing.T) {
		_, err := parseSchemePubKey(append([]byte{extPubKeyECDSASecp256k1}, k1Comp[:20]...))
		requireScriptErrorCode(t, err, txscript.ErrDiscourageUpgradeablePubKeyType)
	})

	t.Run("off_curve_r1_rejected", func(t *testing.T) {
		xBytes := make([]byte, 32)
		for i := range xBytes {
			xBytes[i] = 0xff
		}
		bad := append([]byte{0x11, 0x02}, xBytes...)
		_, err := parseSchemePubKey(bad)
		requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
	})
}

func TestSchemeKeyVerify(t *testing.T) {
	t.Parallel()

	msg := bytes.Repeat([]byte{0x9f}, 32)

	t.Run("ecdsa_secp256k1_roundtrip", func(t *testing.T) {
		priv, _ := btcec.NewPrivateKey()
		k, err := parseSchemePubKey(append([]byte{extPubKeyECDSASecp256k1}, priv.PubKey().SerializeCompressed()...))
		require.NoError(t, err)
		sig := ecdsaK1Compact(t, priv, msg)
		require.True(t, k.verify(msg, sig))

		sig[63] ^= 0x01
		require.False(t, k.verify(msg, sig))
	})

	t.Run("ecdsa_secp256r1_roundtrip", func(t *testing.T) {
		priv, comp := r1CompressedPubKey(t)
		k, err := parseSchemePubKey(append([]byte{extPubKeyECDSASecp256r1}, comp...))
		require.NoError(t, err)
		sig := ecdsaR1Compact(t, priv, msg)
		require.True(t, k.verify(msg, sig))

		sig[0] ^= 0x01
		require.False(t, k.verify(msg, sig))
	})

	t.Run("high_s_rejected_r1", func(t *testing.T) {
		priv, comp := r1CompressedPubKey(t)
		k, err := parseSchemePubKey(append([]byte{extPubKeyECDSASecp256r1}, comp...))
		require.NoError(t, err)
		sig := ecdsaR1Compact(t, priv, msg)
		n := elliptic.P256().Params().N
		s := new(big.Int).SetBytes(sig[32:])
		// n-s is still ECDSA-valid but non-canonical.
		new(big.Int).Sub(n, s).FillBytes(sig[32:])
		require.False(t, k.verify(msg, sig))
	})

	t.Run("ecdsa_secp256k1_rejects_non_digest_message", func(t *testing.T) {
		priv, _ := btcec.NewPrivateKey()
		k, err := parseSchemePubKey(append([]byte{extPubKeyECDSASecp256k1}, priv.PubKey().SerializeCompressed()...))
		require.NoError(t, err)
		sig := ecdsaK1Compact(t, priv, msg)
		require.False(t, k.verify(append(bytes.Clone(msg), 0x00), sig))
	})

	t.Run("ecdsa_secp256r1_rejects_non_digest_message", func(t *testing.T) {
		priv, comp := r1CompressedPubKey(t)
		k, err := parseSchemePubKey(append([]byte{extPubKeyECDSASecp256r1}, comp...))
		require.NoError(t, err)
		sig := ecdsaR1Compact(t, priv, msg)
		require.False(t, k.verify(append(bytes.Clone(msg), 0x00), sig))
	})
}

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

func r1CompressedPubKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enc, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	x := new(big.Int).SetBytes(enc[1:33])
	y := new(big.Int).SetBytes(enc[33:65])
	return priv, elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

func ecdsaK1Compact(t *testing.T, priv *btcec.PrivateKey, hash []byte) []byte {
	t.Helper()
	sig := btcecdsa.Sign(priv, hash)
	r := sig.R()
	s := sig.S()
	rb := r.Bytes()
	sb := s.Bytes()
	return append(rb[:], sb[:]...)
}

func ecdsaR1Compact(t *testing.T, priv *ecdsa.PrivateKey, hash []byte) []byte {
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
