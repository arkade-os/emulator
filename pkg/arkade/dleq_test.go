package arkade

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestDLEQProof exercises a Cashu/BDHKE-style DLEQ (Discrete Log Equality)
// proof. Bob proves that the same secret a links A = a*G and C' = a*B' without
// revealing a:
//
//	Bob:   r random; R1 = r*G; R2 = r*B'; e = hash(R1,R2,A,C'); s = r + e*a
//	Alice: R1 = s*G - e*A; R2 = s*B' - e*C'; accept iff e == hash(R1,R2,A,C')
func TestDLEQProof(t *testing.T) {
	// a is Bob's secret (the signing key), A = a*G is public.
	a := mustPrivKeyFromSeed(t, "dleq-secret-a")
	A := a.PubKey()

	// B' is Alice's blinded message (any point); b is its discrete log here
	// only so the test can construct a well-formed B'.
	b := mustPrivKeyFromSeed(t, "dleq-blinded-b")
	bPub := b.PubKey()

	// C' = a*B' is Bob's signature over the blinded message.
	cPrime := scalarMultPub(&a.Key, bPub)

	t.Run("valid proof verifies", func(t *testing.T) {
		e, s := dleqProve(t, a, bPub, cPrime)
		require.True(t, dleqVerify(e, s, A, bPub, cPrime))
	})

	t.Run("wrong A fails", func(t *testing.T) {
		e, s := dleqProve(t, a, bPub, cPrime)
		wrongA := mustPrivKeyFromSeed(t, "dleq-wrong-a").PubKey()
		require.False(t, dleqVerify(e, s, wrongA, bPub, cPrime))
	})

	t.Run("wrong C' (different secret) fails", func(t *testing.T) {
		e, s := dleqProve(t, a, bPub, cPrime)
		other := mustPrivKeyFromSeed(t, "dleq-other-secret")
		wrongCPrime := scalarMultPub(&other.Key, bPub)
		require.False(t, dleqVerify(e, s, A, bPub, wrongCPrime))
	})

	t.Run("tampered s fails", func(t *testing.T) {
		e, s := dleqProve(t, a, bPub, cPrime)
		tampered := new(btcec.ModNScalar).Set(s)
		tampered.Add(new(btcec.ModNScalar).SetInt(1))
		require.False(t, dleqVerify(e, tampered, A, bPub, cPrime))
	})

	t.Run("tampered e fails", func(t *testing.T) {
		e, s := dleqProve(t, a, bPub, cPrime)
		tampered := new(btcec.ModNScalar).Set(e)
		tampered.Add(new(btcec.ModNScalar).SetInt(1))
		require.False(t, dleqVerify(tampered, s, A, bPub, cPrime))
	})
}

func mustPrivKeyFromSeed(t *testing.T, seed string) *btcec.PrivateKey {
	t.Helper()
	digest := sha256.Sum256([]byte(seed))
	priv, _ := btcec.PrivKeyFromBytes(digest[:])
	return priv
}

// dleqProve is Bob's side of the proof. It picks a nonce r (derived
// deterministically here so the test is reproducible), then returns the
// challenge e and response s proving that a links A = a*G and cPrime = a*B'.
func dleqProve(t *testing.T, a *btcec.PrivateKey, bPub, cPrime *btcec.PublicKey) (e, s *btcec.ModNScalar) {
	t.Helper()

	// Deterministic nonce r = H(a || B' || C'); any uniformly random scalar
	// works, but a fixed derivation keeps failures reproducible.
	h := sha256.New()
	aBytes := a.Key.Bytes()
	h.Write(aBytes[:])
	h.Write(bPub.SerializeCompressed())
	h.Write(cPrime.SerializeCompressed())
	var nonce [32]byte
	copy(nonce[:], h.Sum(nil))
	r := new(btcec.ModNScalar)
	r.SetBytes(&nonce)

	A := a.PubKey()
	R1 := scalarBaseMult(r)      // r*G
	R2 := scalarMultPub(r, bPub) // r*B'
	e = dleqChallenge(R1, R2, A, cPrime)

	// s = r + e*a
	ea := new(btcec.ModNScalar).Mul2(e, &a.Key)
	s = new(btcec.ModNScalar).Add2(r, ea)
	return e, s
}

// dleqVerify is Alice's side. It recomputes R1 = s*G - e*A and
// R2 = s*B' - e*C', then checks the challenge matches.
func dleqVerify(e, s *btcec.ModNScalar, A, bPub, cPrime *btcec.PublicKey) bool {
	negE := new(btcec.ModNScalar).Set(e)
	negE.Negate()

	// R1 = s*G - e*A = s*G + (-e)*A
	R1 := pointAdd(scalarBaseMult(s), scalarMultPub(negE, A))
	// R2 = s*B' - e*C' = s*B' + (-e)*C'
	R2 := pointAdd(scalarMultPub(s, bPub), scalarMultPub(negE, cPrime))

	expected := dleqChallenge(R1, R2, A, cPrime)
	return expected.Equals(e)
}

// dleqChallenge computes e = H(R1 || R2 || A || C') as a scalar.
func dleqChallenge(R1, R2, A, cPrime *btcec.PublicKey) *btcec.ModNScalar {
	h := sha256.New()
	h.Write(R1.SerializeCompressed())
	h.Write(R2.SerializeCompressed())
	h.Write(A.SerializeCompressed())
	h.Write(cPrime.SerializeCompressed())
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	e := new(btcec.ModNScalar)
	e.SetBytes(&digest)
	return e
}

// scalarBaseMult returns scalar*G.
func scalarBaseMult(scalar *btcec.ModNScalar) *btcec.PublicKey {
	var result btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(scalar, &result)
	result.ToAffine()
	return btcec.NewPublicKey(&result.X, &result.Y)
}

// scalarMultPub returns scalar*point.
func scalarMultPub(scalar *btcec.ModNScalar, point *btcec.PublicKey) *btcec.PublicKey {
	var p, result btcec.JacobianPoint
	point.AsJacobian(&p)
	btcec.ScalarMultNonConst(scalar, &p, &result)
	result.ToAffine()
	return btcec.NewPublicKey(&result.X, &result.Y)
}

// pointAdd returns a + b.
func pointAdd(a, b *btcec.PublicKey) *btcec.PublicKey {
	var pa, pb, result btcec.JacobianPoint
	a.AsJacobian(&pa)
	b.AsJacobian(&pb)
	btcec.AddNonConst(&pa, &pb, &result)
	result.ToAffine()
	return btcec.NewPublicKey(&result.X, &result.Y)
}
