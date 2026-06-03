package arkade

import (
	"math/big"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade/cashupool"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// TestProofDLEQScript verifies a NUT-12 r-blinded proof DLEQ entirely inside an
// Arkade Script, matching cashupool.ProveProofDLEQ / VerifyProofDLEQ
// byte-for-byte. This is the in-script counterpart of the off-chain reference in
// pkg/arkade/cashupool/dleq.go.
//
// The wallet (spender) reveals the blinding factor r so the verifier can
// reconstruct B' and C'. The script:
//
//	B' = Y + r*G ; C' = C + r*A
//	R1 = s*G + (n-e)*A ; R2 = s*B' + (n-e)*C'
//	e' = bigendian(SHA256(U(R1)||U(R2)||U(A)||U(C'))) mod n ; assert e' == e
//
// Conventions that DIFFER from dleq_script_test.go:
//   - Points are hashed in SEC1 UNCOMPRESSED form (0x04 || be32(X) || be32(Y)).
//   - The challenge digest is read BIG-endian (OP_REVERSEBYTES before the 0x00
//     pad + OP_BIN2NUM), matching new(big.Int).SetBytes(d) mod n off-chain.
//   - B' and C' are reconstructed in-script from the revealed r.
func TestProofDLEQScript(t *testing.T) {
	t.Parallel()

	n := btcec.S256().N

	// Public instance: mint key A = k*G.
	k := mustPrivKeyFromSeed(t, "cashu-mint")
	A := k.PubKey()

	// Token point Y = HashToCurve(secret); signature C = k*Y.
	secret := cashupool.GrindSecret("dleqs", 4)
	Y, _ := cashupool.HashToCurve(secret)
	C := cashupool.Sign(k, Y)

	// Wallet blinding factor r.
	r := mustPrivKeyFromSeed(t, "cashu-r")

	// Off-chain proof (e, s).
	e, s := cashupool.ProveProofDLEQ(k, Y, C, r)
	require.True(t, cashupool.VerifyProofDLEQ(A, Y, C, r, e, s),
		"off-chain proof must verify before testing the script")

	eBig := scalarToBig(e)
	sBig := scalarToBig(s)
	require.NotEqual(t, 0, eBig.Sign(), "e must be non-zero so (n-e) is a valid scalar")
	require.NotEqual(t, 0, sBig.Sign(), "s must be non-zero")

	rBig := scalarToBig(&r.Key)
	Yx, Yy := pubCoords(Y)
	Cx, Cy := pubCoords(C)

	script := buildProofDLEQVerifyScript(A, n)

	// Witness order (bottom -> top): r, Yx, Yy, Cx, Cy, e, s.
	validWitness := [][]byte{
		encodeBig(rBig),
		encodeBig(Yx), encodeBig(Yy),
		encodeBig(Cx), encodeBig(Cy),
		encodeBig(eBig), encodeBig(sBig),
	}

	witnessWith := func(rb, eb, sb *big.Int) [][]byte {
		return [][]byte{
			encodeBig(rb),
			encodeBig(Yx), encodeBig(Yy),
			encodeBig(Cx), encodeBig(Cy),
			encodeBig(eb), encodeBig(sb),
		}
	}

	t.Run("valid proof verifies", func(t *testing.T) {
		require.NoError(t, runArkadeScript(t, script, validWitness))
	})

	t.Run("tampered s fails", func(t *testing.T) {
		badS := new(big.Int).Mod(new(big.Int).Add(sBig, big.NewInt(1)), n)
		require.Error(t, runArkadeScript(t, script, witnessWith(rBig, eBig, badS)))
	})

	t.Run("tampered e fails", func(t *testing.T) {
		badE := new(big.Int).Mod(new(big.Int).Add(eBig, big.NewInt(1)), n)
		require.Error(t, runArkadeScript(t, script, witnessWith(rBig, badE, sBig)))
	})

	t.Run("wrong mint key fails", func(t *testing.T) {
		// Script commits to a different A2, but the witness proves against A.
		k2 := mustPrivKeyFromSeed(t, "cashu-mint-other")
		script2 := buildProofDLEQVerifyScript(k2.PubKey(), n)
		require.Error(t, runArkadeScript(t, script2, validWitness))
	})

	t.Run("wrong r fails", func(t *testing.T) {
		r2 := mustPrivKeyFromSeed(t, "cashu-r-other")
		require.Error(t, runArkadeScript(t, script, witnessWith(scalarToBig(&r2.Key), eBig, sBig)))
	})
}

// buildProofDLEQVerifyScript assembles the inline NUT-12 proof-DLEQ verifier for
// the public mint key A = k*G and group order n. The spender's witness, bottom
// to top, is: r, Yx, Yy, Cx, Cy, e, s.
//
// The builder tracks the runtime stack depth so OP_PICK offsets for the re-used
// witness scalars (r, e, s) and the derived (n-e) are always correct.
func buildProofDLEQVerifyScript(A *btcec.PublicKey, n *big.Int) []byte {
	bld := txscript.NewScriptBuilder()

	// depth models the data stack at runtime, starting with the seven witness
	// items [r, Yx, Yy, Cx, Cy, e, s] pushed by SetStack.
	depth := 7

	data := func(v []byte) { bld.AddData(v); depth++ }
	i64 := func(v int64) { bld.AddInt64(v); depth++ }
	op := func(o byte, delta int) { bld.AddOp(o); depth += delta }

	// Immutable base item indices (counted from the bottom of the stack). The
	// first seven are the witness; n-e, B' and C' are appended as base items so
	// they can be re-picked without recomputation.
	const (
		idxR   = 0
		idxYx  = 1
		idxYy  = 2
		idxCx  = 3
		idxCy  = 4
		idxE   = 5
		idxS   = 6
		idxNE  = 7  // n - e
		idxBpx = 8  // B'.x
		idxBpy = 9  // B'.y
		idxCpx = 10 // C'.x
		idxCpy = 11 // C'.y
	)

	// pick copies the immutable base item at baseIdx to the top. Net effect: +1.
	pick := func(baseIdx int) {
		i64(int64(depth - 1 - baseIdx))
		op(OP_PICK, 0)
	}

	// scalarMul leaves k*(px,py) as affine (x, y) on top for a BAKED point p,
	// where k is the base scalar at kIdx. Stack: [...] -> [... x y].
	scalarMul := func(p *btcec.PublicKey, kIdx int) {
		px, py := pubCoords(p)
		data(encodeBig(px))
		data(encodeBig(py))
		pick(kIdx)
		op(OP_0, 1)      // curve id 0 = secp256k1
		op(OP_ECMUL, -2) // pops x,y,k,curve; pushes x,y
	}

	// scalarMulXY leaves k*(px,py) as affine (x, y) on top for a RUNTIME point
	// whose coords are base items at xIdx, yIdx. k is the base scalar at kIdx.
	scalarMulXY := func(xIdx, yIdx, kIdx int) {
		pick(xIdx)
		pick(yIdx)
		pick(kIdx)
		op(OP_0, 1)      // curve id 0 = secp256k1
		op(OP_ECMUL, -2) // pops x,y,k,curve; pushes x,y
	}

	// ecAdd combines the two affine points on top. [... x1 y1 x2 y2] -> [... x3 y3].
	ecAdd := func() {
		op(OP_0, 1)
		op(OP_ECADD, -3) // pops x1,y1,x2,y2,curve; pushes x3,y3
	}

	// be32 turns a curve-coordinate number on top into its 32-byte big-endian
	// fixed-width encoding. [... v] -> [... be32(v)]. Reuses the
	// NUM2BIN(33)->REVERSEBYTES->RIGHT(32) trick to drop the sign byte.
	be32 := func() {
		i64(33)                // v 33
		op(OP_NUM2BIN, -1)     // le33(v)
		op(OP_REVERSEBYTES, 0) // be33(v) == 0x00 || be32(v)
		i64(32)                // be33(v) 32
		op(OP_RIGHT, -1)       // be32(v)
	}

	// serializeUncompressed turns the affine point on top into its 65-byte SEC1
	// uncompressed encoding 0x04 || be32(x) || be32(y). [... x y] -> [... U(P)].
	serializeUncompressed := func() {
		// Stack: x y
		be32()         // x be32(y)
		op(OP_SWAP, 0) // be32(y) x
		be32()         // be32(y) be32(x)
		op(OP_4, 1)    // be32(y) be32(x) 0x04  (OP_4 pushes the single byte 0x04)
		op(OP_SWAP, 0) // be32(y) 0x04 be32(x)
		op(OP_CAT, -1) // be32(y) 0x04||be32(x)
		op(OP_SWAP, 0) // 0x04||be32(x) be32(y)
		op(OP_CAT, -1) // 0x04||be32(x)||be32(y)
	}

	G := scalarBaseMultPoint()

	// --- n - e (base item idxNE) ---
	data(encodeBig(n))
	pick(idxE)     // copy e
	op(OP_SUB, -1) // n - e

	// --- B' = Y + r*G (leaves Bpx Bpy as base items idxBpx, idxBpy) ---
	scalarMul(G, idxR) // r*G
	pick(idxYx)
	pick(idxYy)
	ecAdd() // B' = (r*G) + Y

	// --- C' = C + r*A (leaves Cpx Cpy as base items idxCpx, idxCpy) ---
	scalarMul(A, idxR) // r*A
	pick(idxCx)
	pick(idxCy)
	ecAdd() // C' = (r*A) + C

	// --- R1 = s*G + (n-e)*A, serialize and park on the alt stack ---
	scalarMul(G, idxS)  // s*G
	scalarMul(A, idxNE) // (n-e)*A
	ecAdd()             // R1
	serializeUncompressed()
	op(OP_TOALTSTACK, -1) // alt: [U(R1)]

	// --- R2 = s*B' + (n-e)*C', append U(R2) to the alt-stacked preimage ---
	scalarMulXY(idxBpx, idxBpy, idxS)  // s*B'
	scalarMulXY(idxCpx, idxCpy, idxNE) // (n-e)*C'
	ecAdd()                            // R2
	serializeUncompressed()
	op(OP_FROMALTSTACK, 1) // U(R2) U(R1)
	op(OP_SWAP, 0)         // U(R1) U(R2)
	op(OP_CAT, -1)         // U(R1)||U(R2)
	op(OP_TOALTSTACK, -1)  // alt: [acc]

	// --- append U(A) ---
	ax, ay := pubCoords(A)
	data(encodeBig(ax))
	data(encodeBig(ay))
	serializeUncompressed()
	op(OP_FROMALTSTACK, 1)
	op(OP_SWAP, 0)
	op(OP_CAT, -1)
	op(OP_TOALTSTACK, -1)

	// --- append U(C'): build the full preimage on the main stack ---
	pick(idxCpx)
	pick(idxCpy)
	serializeUncompressed()
	op(OP_FROMALTSTACK, 1)
	op(OP_SWAP, 0)
	op(OP_CAT, -1) // preimage = U(R1)||U(R2)||U(A)||U(C')

	// --- e' = bigendian(SHA256(preimage)) mod n ---
	op(OP_SHA256, 0)       // 32-byte digest
	op(OP_REVERSEBYTES, 0) // reverse so big-endian magnitude reads LE for BIN2NUM
	op(OP_0, 1)            // 0
	op(OP_1, 1)            // 0 1
	op(OP_NUM2BIN, -1)     // 0x00 byte
	op(OP_CAT, -1)         // reversed-digest||0x00 (positive little-endian)
	op(OP_BIN2NUM, 0)      // H (big-endian value of the digest)
	data(encodeBig(n))     // H n
	op(OP_MOD, -1)         // e' = H mod n

	// --- assert e' == e, then clean up the 12 base items and leave success ---
	pick(idxE)
	op(OP_NUMEQUALVERIFY, -2)
	// Drop the 12 immutable base items: r,Yx,Yy,Cx,Cy,e,s,n-e,Bpx,Bpy,Cpx,Cpy.
	for i := 0; i < 6; i++ {
		op(OP_2DROP, -2)
	}
	op(OP_1, 1) // success

	script, err := bld.Script()
	if err != nil {
		panic(err)
	}
	return script
}

// scalarBaseMultPoint returns the secp256k1 generator G as a *btcec.PublicKey.
func scalarBaseMultPoint() *btcec.PublicKey {
	one := new(btcec.ModNScalar)
	one.SetInt(1)
	return scalarBaseMult(one)
}
