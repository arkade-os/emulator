package arkade

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// r1CompressedPubKey returns a random secp256r1 public key as 33-byte SEC1
// compressed bytes, plus the private key for signing in later tests.
func r1CompressedPubKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enc, err := priv.PublicKey.Bytes() // 0x04 || X(32) || Y(32)
	require.NoError(t, err)
	x := new(big.Int).SetBytes(enc[1:33])
	y := new(big.Int).SetBytes(enc[33:65])
	return priv, elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

func TestParseSchemePubKey(t *testing.T) {
	t.Parallel()

	k1Priv, _ := btcec.NewPrivateKey()
	xonly := schnorr.SerializePubKey(k1Priv.PubKey())  // 32B
	k1Comp := k1Priv.PubKey().SerializeCompressed()     // 33B
	_, r1Comp := r1CompressedPubKey(t)                  // 33B

	t.Run("legacy_32B_is_schnorr_secp256k1", func(t *testing.T) {
		got, err := parseSchemePubKey(xonly)
		require.NoError(t, err)
		require.Equal(t, algoSchnorr, got.algo)
		require.Equal(t, CurveSecp256k1, got.curve)
		require.NotNil(t, got.secpPub)
	})

	t.Run("prefix_0x10_is_ecdsa_secp256k1", func(t *testing.T) {
		got, err := parseSchemePubKey(append([]byte{0x10}, k1Comp...))
		require.NoError(t, err)
		require.Equal(t, algoECDSA, got.algo)
		require.Equal(t, CurveSecp256k1, got.curve)
		require.NotNil(t, got.secpPub)
	})

	t.Run("prefix_0x11_is_ecdsa_secp256r1", func(t *testing.T) {
		got, err := parseSchemePubKey(append([]byte{0x11}, r1Comp...))
		require.NoError(t, err)
		require.Equal(t, algoECDSA, got.algo)
		require.Equal(t, CurveSecp256r1, got.curve)
		require.NotNil(t, got.nistPub)
	})

	t.Run("empty_is_pubkey_empty_error", func(t *testing.T) {
		_, err := parseSchemePubKey(nil)
		requireScriptErrorCode(t, err, txscript.ErrTaprootPubkeyIsEmpty)
	})

	t.Run("reserved_schnorr_extended_discouraged", func(t *testing.T) {
		_, err := parseSchemePubKey(append([]byte{0x00}, xonly...)) // 0x00 || 32B
		requireScriptErrorCode(t, err, txscript.ErrDiscourageUpgradeablePubKeyType)
	})

	t.Run("unknown_prefix_discouraged", func(t *testing.T) {
		_, err := parseSchemePubKey(append([]byte{0x20}, k1Comp...))
		requireScriptErrorCode(t, err, txscript.ErrDiscourageUpgradeablePubKeyType)
	})

	t.Run("wrong_length_key_discouraged", func(t *testing.T) {
		_, err := parseSchemePubKey(append([]byte{0x10}, k1Comp[:20]...))
		requireScriptErrorCode(t, err, txscript.ErrDiscourageUpgradeablePubKeyType)
	})

	t.Run("off_curve_r1_rejected", func(t *testing.T) {
		// x = 2^256-1 > P-256 field prime, no valid point exists.
		xBytes := make([]byte, 32)
		for i := range xBytes {
			xBytes[i] = 0xff
		}
		bad := append([]byte{0x11, 0x02}, xBytes...)
		_, err := parseSchemePubKey(bad)
		requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
	})
}

// ecdsaK1Compact signs hash with a secp256k1 key and returns 64-byte r||s.
// btcec normalizes to low-s, so the result is canonical by construction.
func ecdsaK1Compact(t *testing.T, priv *btcec.PrivateKey, hash []byte) []byte {
	t.Helper()
	sig := btcecdsa.Sign(priv, hash)
	r := sig.R()
	s := sig.S()
	rb := r.Bytes()
	sb := s.Bytes()
	return append(rb[:], sb[:]...)
}

// ecdsaR1Compact signs hash with a secp256r1 key, normalizes to low-s, and
// returns 64-byte r||s (each big-endian, left-padded to 32 bytes).
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

func TestSchemeKeyVerify(t *testing.T) {
	t.Parallel()

	msg := bytes.Repeat([]byte{0x9f}, 32) // a 32-byte digest

	t.Run("ecdsa_secp256k1_roundtrip", func(t *testing.T) {
		priv, _ := btcec.NewPrivateKey()
		k, err := parseSchemePubKey(append([]byte{0x10}, priv.PubKey().SerializeCompressed()...))
		require.NoError(t, err)
		sig := ecdsaK1Compact(t, priv, msg)
		require.True(t, k.verify(msg, sig))

		sig[63] ^= 0x01 // tamper s
		require.False(t, k.verify(msg, sig))
	})

	t.Run("ecdsa_secp256r1_roundtrip", func(t *testing.T) {
		priv, comp := r1CompressedPubKey(t)
		k, err := parseSchemePubKey(append([]byte{0x11}, comp...))
		require.NoError(t, err)
		sig := ecdsaR1Compact(t, priv, msg)
		require.True(t, k.verify(msg, sig))

		sig[0] ^= 0x01 // tamper r
		require.False(t, k.verify(msg, sig))
	})

	t.Run("high_s_rejected_r1", func(t *testing.T) {
		priv, comp := r1CompressedPubKey(t)
		k, err := parseSchemePubKey(append([]byte{0x11}, comp...))
		require.NoError(t, err)
		sig := ecdsaR1Compact(t, priv, msg)
		// Flip s to its high-s counterpart n-s: still a valid ECDSA sig, but
		// non-canonical and must be rejected.
		n := elliptic.P256().Params().N
		s := new(big.Int).SetBytes(sig[32:])
		high := new(big.Int).Sub(n, s)
		high.FillBytes(sig[32:])
		require.False(t, k.verify(msg, sig))
	})

	t.Run("cross_curve_bytes_rejected", func(t *testing.T) {
		// X = 2^256-1 exceeds the P-256 field prime — no valid point exists.
		// Verifies that bytes not on P-256 are rejected under the r1 prefix.
		offCurve := make([]byte, 33)
		offCurve[0] = 0x02
		for i := 1; i < 33; i++ {
			offCurve[i] = 0xff
		}
		_, err := parseSchemePubKey(append([]byte{0x11}, offCurve...))
		requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
	})

	t.Run("wrong_sig_length_rejected", func(t *testing.T) {
		priv, _ := btcec.NewPrivateKey()
		k, err := parseSchemePubKey(append([]byte{0x10}, priv.PubKey().SerializeCompressed()...))
		require.NoError(t, err)
		require.False(t, k.verify(msg, make([]byte, 70)))
	})
}
