package arkade

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
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
	return priv, elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
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
