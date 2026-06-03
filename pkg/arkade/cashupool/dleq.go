package cashupool

import (
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// --- EC helpers ---

func baseMul(k *btcec.ModNScalar) *btcec.PublicKey {
	var r btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(k, &r)
	r.ToAffine()
	return btcec.NewPublicKey(&r.X, &r.Y)
}

func mul(k *btcec.ModNScalar, p *btcec.PublicKey) *btcec.PublicKey {
	var pj, r btcec.JacobianPoint
	p.AsJacobian(&pj)
	btcec.ScalarMultNonConst(k, &pj, &r)
	r.ToAffine()
	return btcec.NewPublicKey(&r.X, &r.Y)
}

func add(a, b *btcec.PublicKey) *btcec.PublicKey {
	var aj, bj, r btcec.JacobianPoint
	a.AsJacobian(&aj)
	b.AsJacobian(&bj)
	btcec.AddNonConst(&aj, &bj, &r)
	r.ToAffine()
	return btcec.NewPublicKey(&r.X, &r.Y)
}

// challenge computes e = SHA256(U(R1)||U(R2)||U(A)||U(Cp)) as a big-endian
// scalar mod n. MUST match the in-script verifier byte-for-byte.
//
// Points are fed as uncompressed (65 bytes: 0x04 || X32 || Y32).
func challenge(R1, R2, A, Cp *btcec.PublicKey) *btcec.ModNScalar {
	pre := make([]byte, 0, 65*4)
	pre = append(pre, R1.SerializeUncompressed()...)
	pre = append(pre, R2.SerializeUncompressed()...)
	pre = append(pre, A.SerializeUncompressed()...)
	pre = append(pre, Cp.SerializeUncompressed()...)
	d := sha256.Sum256(pre)
	h := new(big.Int).SetBytes(d[:]) // big-endian
	h.Mod(h, btcec.S256().N)
	var sc btcec.ModNScalar
	var b [32]byte
	h.FillBytes(b[:])
	sc.SetBytes(&b)
	return &sc
}

// Sign is the mint's BDHKE signature C = k*Y.
func Sign(k *btcec.PrivateKey, Y *btcec.PublicKey) *btcec.PublicKey { return mul(&k.Key, Y) }

// ProveProofDLEQ produces a NUT-12 proof DLEQ (e, s) for token C=k*Y under
// mint key A=k*G, given the wallet blinding factor r.
//
//	B' = Y + r*G ; C' = C + r*A
//	p (nonce) = deterministic scalar ; R1 = p*G ; R2 = p*B'
//	e = challenge(R1,R2,A,C') ; s = p + e*k
//
// The nonce p is derived deterministically as
// SHA256("cashupool-dleq-nonce" || k || Y || C) to avoid nonce reuse.
func ProveProofDLEQ(k *btcec.PrivateKey, Y, C *btcec.PublicKey, r *btcec.PrivateKey) (e, s *btcec.ModNScalar) {
	A := k.PubKey()
	Bp := add(Y, baseMul(&r.Key))
	Cp := add(C, mul(&r.Key, A))

	// Deterministic nonce p = SHA256("cashupool-dleq-nonce" || k || Y || C).
	hh := sha256.New()
	hh.Write([]byte("cashupool-dleq-nonce"))
	kb := k.Key.Bytes()
	hh.Write(kb[:])
	hh.Write(Y.SerializeCompressed())
	hh.Write(C.SerializeCompressed())
	var pb [32]byte
	copy(pb[:], hh.Sum(nil))
	p := new(btcec.ModNScalar)
	p.SetBytes(&pb)

	R1 := baseMul(p)
	R2 := mul(p, Bp)
	e = challenge(R1, R2, A, Cp)

	// s = p + e*k
	ek := new(btcec.ModNScalar).Mul2(e, &k.Key)
	s = new(btcec.ModNScalar).Add2(p, ek)
	return e, s
}

// VerifyProofDLEQ checks a NUT-12 proof DLEQ. r is the revealed blinding
// factor (the claim reveals r so the verifier can reconstruct B' and C').
//
//	B' = Y + r*G ; C' = C + r*A
//	R1 = s*G - e*A ; R2 = s*B' - e*C'
//	accept iff challenge(R1,R2,A,C') == e
func VerifyProofDLEQ(A, Y, C *btcec.PublicKey, r *btcec.PrivateKey, e, s *btcec.ModNScalar) bool {
	Bp := add(Y, baseMul(&r.Key))
	Cp := add(C, mul(&r.Key, A))

	negE := new(btcec.ModNScalar).Set(e)
	negE.Negate()

	R1 := add(baseMul(s), mul(negE, A))
	R2 := add(mul(s, Bp), mul(negE, Cp))

	return challenge(R1, R2, A, Cp).Equals(e)
}
