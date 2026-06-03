package cashupool

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestProofDLEQ(t *testing.T) {
	t.Parallel()

	t.Run("round_trip", func(t *testing.T) {
		t.Parallel()
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		A := k.PubKey()

		secret := GrindSecret("dleq", 4)
		Y, _ := HashToCurve(secret)

		r, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		C := Sign(k, Y)
		e, s := ProveProofDLEQ(k, Y, C, r)

		require.True(t, VerifyProofDLEQ(A, Y, C, r, e, s), "valid proof must verify")
	})

	t.Run("tampered_s_fails", func(t *testing.T) {
		t.Parallel()
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		A := k.PubKey()

		secret := GrindSecret("dleq-s", 4)
		Y, _ := HashToCurve(secret)

		r, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		C := Sign(k, Y)
		e, s := ProveProofDLEQ(k, Y, C, r)

		bad := new(btcec.ModNScalar).Set(s)
		bad.Add(new(btcec.ModNScalar).SetInt(1))
		require.False(t, VerifyProofDLEQ(A, Y, C, r, e, bad), "tampered s must not verify")
	})

	t.Run("tampered_e_fails", func(t *testing.T) {
		t.Parallel()
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		A := k.PubKey()

		secret := GrindSecret("dleq-e", 4)
		Y, _ := HashToCurve(secret)

		r, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		C := Sign(k, Y)
		e, s := ProveProofDLEQ(k, Y, C, r)

		badE := new(btcec.ModNScalar).Set(e)
		badE.Add(new(btcec.ModNScalar).SetInt(1))
		require.False(t, VerifyProofDLEQ(A, Y, C, r, badE, s), "tampered e must not verify")
	})

	t.Run("wrong_key_fails", func(t *testing.T) {
		t.Parallel()
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		k2, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		A2 := k2.PubKey()

		secret := GrindSecret("dleq-wk", 4)
		Y, _ := HashToCurve(secret)

		r, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		C := Sign(k, Y)
		e, s := ProveProofDLEQ(k, Y, C, r)

		require.False(t, VerifyProofDLEQ(A2, Y, C, r, e, s), "wrong mint key must not verify")
	})

	t.Run("wrong_r_fails", func(t *testing.T) {
		t.Parallel()
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		A := k.PubKey()

		secret := GrindSecret("dleq-wr", 4)
		Y, _ := HashToCurve(secret)

		r, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		r2, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		C := Sign(k, Y)
		e, s := ProveProofDLEQ(k, Y, C, r)

		require.False(t, VerifyProofDLEQ(A, Y, C, r2, e, s), "wrong blinding factor must not verify")
	})

	t.Run("determinism", func(t *testing.T) {
		t.Parallel()
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		secret := GrindSecret("dleq-det", 4)
		Y, _ := HashToCurve(secret)

		r, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		C := Sign(k, Y)
		e1, s1 := ProveProofDLEQ(k, Y, C, r)
		e2, s2 := ProveProofDLEQ(k, Y, C, r)

		require.True(t, e1.Equals(e2), "ProveProofDLEQ must be deterministic: e differs")
		require.True(t, s1.Equals(s2), "ProveProofDLEQ must be deterministic: s differs")
	})
}
