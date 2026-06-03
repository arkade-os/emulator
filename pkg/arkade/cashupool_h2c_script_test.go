package arkade

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade/cashupool"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// This file verifies Cashu NUT-00 hash_to_curve entirely inside an Arkade
// Script, mirroring the off-chain reference in
// github.com/arkade-os/emulator/pkg/arkade/cashupool.
//
// NUT-00 hash_to_curve:
//
//	DOMAIN = "Secp256k1_HashToCurve_Cashu_"
//	msg    = SHA256(DOMAIN || secret)
//	for c = 0, 1, 2, …:
//	    cand_c = SHA256(msg || uint32_le(c))   // 32-byte big-endian SEC1 x
//	    if cand_c is a valid secp256k1 x-coordinate: point exists at counter c
//
// The first counter c whose cand_c is a valid x-coordinate "wins"; the point
// is the even-Y lift of cand_c (0x02 prefix).
//
// In script we read each 32-byte big-endian digest as a non-negative Arkade
// number with the digest-to-number trick from dleq_script_test.go: reverse the
// bytes (big-endian -> little-endian of the same value), append a 0x00 byte so
// the high bit is never read as a sign bit, then OP_BIN2NUM.
//
// A counter is a residue (point exists) iff v = x³ + 7 is a quadratic residue
// mod p, tested via the Euler criterion: legendre = v^((p-1)/2) mod p, which is
// 1 for a residue and p-1 for a non-residue. The winning counter additionally
// has its full point verified: the witness supplies the big-endian Y, and the
// script asserts Y is even, x < p, y < p, and y² ≡ x³ + 7 (mod p).

// h2cDomain is the NUT-00 hash_to_curve domain tag, identical to
// cashupool.DomainSeparator.
var h2cDomain = []byte("Secp256k1_HashToCurve_Cashu_")

// h2cFieldP returns the secp256k1 field modulus p.
func h2cFieldP() *big.Int {
	return new(big.Int).Set(btcec.S256().P)
}

// h2cCounterLE returns the 4-byte little-endian encoding of counter c, exactly
// as NUT-00 appends it to msg before SHA256.
func h2cCounterLE(c uint32) []byte {
	return []byte{byte(c), byte(c >> 8), byte(c >> 16), byte(c >> 24)}
}

// h2cWitnessY returns the 32-byte big-endian Y coordinate of the hash_to_curve
// point for secret, as the script's witness expects it.
func h2cWitnessY(point *btcec.PublicKey) []byte {
	u := point.SerializeUncompressed() // 0x04 || be32(x) || be32(y)
	return u[33:65]
}

// h2cBuilder wraps a txscript.ScriptBuilder with the depth-tracked emit helpers
// used throughout the in-script crypto tests. depth models the runtime data
// stack so OP_PICK offsets stay correct.
type h2cBuilder struct {
	bld   *txscript.ScriptBuilder
	depth int
}

func newH2CBuilder(initialDepth int) *h2cBuilder {
	return &h2cBuilder{bld: txscript.NewScriptBuilder(), depth: initialDepth}
}

func (b *h2cBuilder) data(v []byte)        { b.bld.AddData(v); b.depth++ }
func (b *h2cBuilder) i64(v int64)          { b.bld.AddInt64(v); b.depth++ }
func (b *h2cBuilder) op(o byte, delta int) { b.bld.AddOp(o); b.depth += delta }

// pick copies the item at absolute stack index baseIdx (0 = bottom) to the top.
func (b *h2cBuilder) pick(baseIdx int) {
	b.i64(int64(b.depth - 1 - baseIdx))
	b.op(OP_PICK, 0)
}

func (b *h2cBuilder) script() []byte {
	s, err := b.bld.Script()
	if err != nil {
		panic(err)
	}
	return s
}

// appendZeroByte synthesizes a single 0x00 byte on top of the stack and
// concatenates it onto the byte string below it. Minimal-push forbids a literal
// 0x00 data push, so the byte is built via OP_0 OP_1 OP_NUM2BIN.
//
// Stack: [... bytes] -> [... bytes||0x00]
func (b *h2cBuilder) appendZeroByte() {
	b.op(OP_0, 1)        // bytes 0
	b.op(OP_1, 1)        // bytes 0 1
	b.op(OP_NUM2BIN, -1) // bytes 0x00
	b.op(OP_CAT, -1)     // bytes||0x00
}

// digestToNum converts the 32-byte big-endian digest on top of the stack to a
// non-negative Arkade number: reverse to little-endian, append 0x00, BIN2NUM.
//
// Stack: [... be32] -> [... num]
func (b *h2cBuilder) digestToNum() {
	b.op(OP_REVERSEBYTES, 0) // little-endian of the same magnitude
	b.appendZeroByte()       // force non-negative
	b.op(OP_BIN2NUM, 0)      // integer
}

// modP reduces the top item modulo p. Stack: [... a] -> [... a mod p]
func (b *h2cBuilder) modP(p *big.Int) {
	b.data(encodeBig(p))
	b.op(OP_MOD, -1)
}

// rhsCurve computes (x³ + 7) mod p for the x_int currently at absolute stack
// index xIdx, leaving the result on top. Every intermediate stays reduced.
//
// Stack: [...] -> [... (x³+7) mod p]
func (b *h2cBuilder) rhsCurve(xIdx int, p *big.Int) {
	b.pick(xIdx)     // x
	b.pick(xIdx)     // x x
	b.op(OP_MUL, -1) // x²
	b.modP(p)        // x² mod p
	b.pick(xIdx)     // (x² mod p) x
	b.op(OP_MUL, -1) // x³ (reduced * x)
	b.modP(p)        // x³ mod p
	b.data(encodeBig(big.NewInt(7)))
	b.op(OP_ADD, -1) // x³+7
	b.modP(p)        // (x³+7) mod p
}

// buildH2CScriptC0 builds the Stage A script that assumes the winning counter is
// 0. Witness layout (bottom -> top): [secret, y].
//
//	cand_0 = SHA256(SHA256(DOMAIN||secret) || 0x00000000)
//	x_int  = digestToNum(cand_0)
//	y_int  = digestToNum(y)
//	assert y_int even, x_int < p, y_int < p, and
//	       y_int² ≡ x_int³ + 7 (mod p)
//	leave OP_1
func buildH2CScriptC0() []byte {
	p := h2cFieldP()

	// Witness: [secret(idx0), y(idx1)].
	b := newH2CBuilder(2)

	// --- x_int = digestToNum(SHA256(SHA256(DOMAIN||secret) || ctr0)) ---
	b.data(h2cDomain) // secret y DOMAIN
	b.pick(0)         // secret y DOMAIN secret
	b.op(OP_CAT, -1)  // secret y (DOMAIN||secret)
	b.op(OP_SHA256, 0)
	b.data(h2cCounterLE(0)) // secret y msg ctr0
	b.op(OP_CAT, -1)        // secret y (msg||ctr0)
	b.op(OP_SHA256, 0)      // secret y cand_0
	b.digestToNum()         // secret y x_int  (x_int at idx2)

	// --- y_int = digestToNum(y) ---
	b.pick(1)       // secret y x_int y
	b.digestToNum() // secret y x_int y_int  (y_int at idx3)

	// assert x_int < p and y_int < p (operands fit the EC field).
	b.pick(2) // ... x_int
	b.data(encodeBig(p))
	b.op(OP_LESSTHAN, -1)
	b.op(OP_VERIFY, -1)
	b.pick(3) // ... y_int
	b.data(encodeBig(p))
	b.op(OP_LESSTHAN, -1)
	b.op(OP_VERIFY, -1)

	// assert y_int is even (NUT-00 picks the even-Y lift).
	b.pick(3)     // ... y_int
	b.op(OP_2, 1) // ... y_int 2
	b.op(OP_MOD, -1)
	b.op(OP_0NOTEQUAL, 0) // 1 if odd, 0 if even
	b.op(OP_NOT, 0)       // 1 if even
	b.op(OP_VERIFY, -1)

	// on-curve: y_int² mod p == (x_int³ + 7) mod p.
	b.pick(3)        // ... y_int
	b.pick(3)        // ... y_int y_int
	b.op(OP_MUL, -1) // y_int²
	b.modP(p)        // y_int² mod p
	b.rhsCurve(2, p) // ... lhs rhs
	b.op(OP_NUMEQUALVERIFY, -2)

	// Clean up the four base items and leave success.
	b.op(OP_2DROP, -2) // drop x_int, y_int
	b.op(OP_2DROP, -2) // drop secret, y
	b.op(OP_1, 1)

	return b.script()
}

func TestH2CScriptC0(t *testing.T) {
	t.Parallel()

	secret := cashupool.GrindSecret("h2c-c0", 0)
	point, c := cashupool.HashToCurve(secret)
	require.Equal(t, uint32(0), c, "GrindSecret must yield a counter-0 secret")

	script := buildH2CScriptC0()
	y := h2cWitnessY(point)

	t.Run("valid counter-0 witness verifies", func(t *testing.T) {
		require.NoError(t, runArkadeScript(t, script, [][]byte{secret, y}))
	})

	t.Run("tampered y fails", func(t *testing.T) {
		badY := make([]byte, len(y))
		copy(badY, y)
		badY[0] ^= 0x01
		require.Error(t, runArkadeScript(t, script, [][]byte{secret, badY}))
	})
}

// h2cMsgFromSecret pushes msg = SHA256(DOMAIN||secret) for the secret at
// absolute stack index secretIdx, leaving msg on top.
//
// Stack: [...] -> [... msg]
func (b *h2cBuilder) h2cMsgFromSecret(secretIdx int) {
	b.data(h2cDomain) // ... DOMAIN
	b.pick(secretIdx) // ... DOMAIN secret
	b.op(OP_CAT, -1)  // ... (DOMAIN||secret)
	b.op(OP_SHA256, 0)
}

// candXFromMsg computes x_int = digestToNum(SHA256(msg || ctr_c)) for the msg
// at absolute stack index msgIdx and the loop constant counter c, leaving x_int
// on top. msg is left untouched on the stack.
//
// Stack: [...] -> [... x_int]
func (b *h2cBuilder) candXFromMsg(msgIdx int, c uint32) {
	b.pick(msgIdx)          // ... msg
	b.data(h2cCounterLE(c)) // ... msg ctr_c
	b.op(OP_CAT, -1)        // ... (msg||ctr_c)
	b.op(OP_SHA256, 0)      // ... cand_c
	b.digestToNum()         // ... x_int
}

// legendreForCounter computes legendre_c = ((x_c³+7) mod p)^((p-1)/2) mod p for
// the loop constant counter c and the msg at absolute index msgIdx, leaving only
// legendre_c on top (the intermediate candidate x is dropped). For a residue
// (a point exists at this counter) legendre_c == 1; for a non-residue it is p-1.
//
// Stack: [...] -> [... legendre_c]
func (b *h2cBuilder) legendreForCounter(msgIdx int, c uint32, p, pMinus1Over2 *big.Int) {
	b.candXFromMsg(msgIdx, c) // ... x_c
	xIdx := b.depth - 1
	b.rhsCurve(xIdx, p) // ... x_c v=(x_c³+7) mod p   (base)
	b.data(encodeBig(pMinus1Over2))
	b.data(encodeBig(p))
	b.op(OP_MODEXP, -2) // ... x_c legendre_c   (pops base, exp, modulus)
	// drop x_c from beneath legendre_c.
	b.op(OP_SWAP, 0) // ... legendre_c x_c
	b.op(OP_DROP, -1)
}

// buildH2CScript builds the Stage B script that verifies hash_to_curve over a
// bounded counter range 0..K-1, enforcing that the witness winning counter cU
// is the *first* counter whose candidate x is a quadratic residue.
//
// Witness layout (bottom -> top): [secret, cU, y].
//
// For each loop constant c in 0..K-1 the script computes legendre_c and, driven
// by comparing c to cU with OP_LESSTHAN / OP_NUMEQUAL and OP_IF/OP_ELSE/OP_ENDIF:
//   - c < cU  : assert legendre_c == p-1 (every earlier counter is a non-residue)
//   - c == cU : assert legendre_c == 1   (the winning counter is a residue)
//   - c > cU  : no constraint (drop legendre_c)
//
// After the loop the winning point is bound to the witness: cand_cU is recomputed
// from the witness cU, and y is checked even, < p and on-curve against x_cU.
func buildH2CScript(k uint32) []byte {
	p := h2cFieldP()
	pMinus1Over2 := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))

	// Witness: [secret(idx0), cU(idx1), y(idx2)].
	const (
		secretIdx = 0
		cUIdx     = 1
		yIdx      = 2
	)
	b := newH2CBuilder(3)

	// msg = SHA256(DOMAIN||secret), kept as a base item at absolute index 3.
	b.h2cMsgFromSecret(secretIdx)
	const msgIdx = 3

	// --- bounded first-valid loop over counters 0..k-1 ---
	for c := uint32(0); c < k; c++ {
		// legendre_c on top (depth grows by 1 vs. loop-start).
		b.legendreForCounter(msgIdx, c, p, pMinus1Over2)

		// depthWithLegendre is the runtime depth with legendre_c on top; every
		// branch below consumes exactly legendre_c, so the post-ENDIF depth is
		// depthWithLegendre-1 on every path. We restore b.depth to that value
		// after emitting the (multi-branch) conditional.
		depthWithLegendre := b.depth

		// c < cU ?
		b.i64(int64(c))
		b.pick(cUIdx)
		b.op(OP_LESSTHAN, -1)
		b.op(OP_IF, -1)
		{
			// earlier counter: must be a non-residue (legendre == p-1).
			b.data(encodeBig(pMinus1))
			b.op(OP_NUMEQUALVERIFY, -2)
		}
		b.op(OP_ELSE, 0)
		{
			// reset builder depth to the start of this branch: legendre_c is
			// still on the stack (the OP_IF condition was already consumed).
			b.depth = depthWithLegendre
			// c == cU ?
			b.i64(int64(c))
			b.pick(cUIdx)
			b.op(OP_NUMEQUAL, -1)
			b.op(OP_IF, -1)
			{
				// winning counter: must be a residue (legendre == 1).
				b.op(OP_1, 1)
				b.op(OP_NUMEQUALVERIFY, -2)
			}
			b.op(OP_ELSE, 0)
			{
				// later counter: no constraint, drop legendre_c.
				b.depth = depthWithLegendre
				b.op(OP_DROP, -1)
			}
			b.op(OP_ENDIF, 0)
		}
		b.op(OP_ENDIF, 0)

		// Normalise depth: all paths removed exactly legendre_c.
		b.depth = depthWithLegendre - 1
	}

	// --- bind the winning point to the witness y ---
	// x_cU = digestToNum(SHA256(msg || ctr_cU)), using the witness cU.
	b.pick(msgIdx)        // ... msg
	b.pick(cUIdx)         // ... msg cU
	b.i64(4)              // ... msg cU 4
	b.op(OP_NUM2BIN, -1)  // ... msg ctr_cU (4-byte LE of cU)
	b.op(OP_CAT, -1)      // ... (msg||ctr_cU)
	b.op(OP_SHA256, 0)    // ... cand_cU
	b.digestToNum()       // ... x_cU
	xCUIdx := b.depth - 1 // absolute index of x_cU

	// y_int = digestToNum(y).
	b.pick(yIdx)    // ... x_cU y
	b.digestToNum() // ... x_cU y_int
	yIntIdx := b.depth - 1

	// assert x_cU < p and y_int < p.
	b.pick(xCUIdx)
	b.data(encodeBig(p))
	b.op(OP_LESSTHAN, -1)
	b.op(OP_VERIFY, -1)
	b.pick(yIntIdx)
	b.data(encodeBig(p))
	b.op(OP_LESSTHAN, -1)
	b.op(OP_VERIFY, -1)

	// assert y_int even.
	b.pick(yIntIdx)
	b.op(OP_2, 1)
	b.op(OP_MOD, -1)
	b.op(OP_0NOTEQUAL, 0)
	b.op(OP_NOT, 0)
	b.op(OP_VERIFY, -1)

	// on-curve: y_int² mod p == (x_cU³ + 7) mod p.
	b.pick(yIntIdx)
	b.pick(yIntIdx)
	b.op(OP_MUL, -1)
	b.modP(p)
	b.rhsCurve(xCUIdx, p)
	b.op(OP_NUMEQUALVERIFY, -2)

	// Clean up: drop x_cU, y_int, msg, and the three witness items, leave OP_1.
	b.op(OP_2DROP, -2) // x_cU, y_int
	b.op(OP_2DROP, -2) // msg, y
	b.op(OP_2DROP, -2) // cU, secret
	b.op(OP_1, 1)

	return b.script()
}

func TestH2CScript(t *testing.T) {
	t.Parallel()

	const k = 4
	script := buildH2CScript(k)

	// Vector 1: a counter-0 secret.
	secret0 := cashupool.GrindSecret("h2c-b0", 0)
	point0, c0 := cashupool.HashToCurve(secret0)
	require.Equal(t, uint32(0), c0)
	y0 := h2cWitnessY(point0)

	// Vector 2: a secret whose winning counter is >= 1 and < k.
	var secret1 []byte
	var c1 uint32
	var point1 *btcec.PublicKey
	for i := 0; ; i++ {
		s := []byte(fmt.Sprintf("h2c-b1-%d", i))
		pt, c := cashupool.HashToCurve(s)
		if c >= 1 && c < k {
			secret1, c1, point1 = s, c, pt
			break
		}
	}
	y1 := h2cWitnessY(point1)

	cBytes := func(c uint32) []byte { return encodeBig(big.NewInt(int64(c))) }

	t.Run("counter-0 vector verifies", func(t *testing.T) {
		require.NoError(t, runArkadeScript(t, script, [][]byte{secret0, cBytes(c0), y0}))
	})

	t.Run("counter>=1 vector verifies", func(t *testing.T) {
		require.NoError(t, runArkadeScript(t, script, [][]byte{secret1, cBytes(c1), y1}))
	})

	t.Run("wrong y fails", func(t *testing.T) {
		badY := make([]byte, len(y1))
		copy(badY, y1)
		badY[0] ^= 0x01
		require.Error(t, runArkadeScript(t, script, [][]byte{secret1, cBytes(c1), badY}))
	})

	t.Run("cU one less than true fails", func(t *testing.T) {
		// cU = c1-1 is an earlier (non-residue) counter wrongly claimed as the
		// winner; the c==cU branch asserts a residue and fails.
		require.GreaterOrEqual(t, c1, uint32(1))
		require.Error(t, runArkadeScript(t, script, [][]byte{secret1, cBytes(c1 - 1), y1}))
	})

	t.Run("cU larger than true fails", func(t *testing.T) {
		// cU = c1+1 (still < k) skips the true residue c1; at c==c1 (< cU) the
		// loop asserts a non-residue and fails.
		require.Less(t, c1+1, uint32(k))
		require.Error(t, runArkadeScript(t, script, [][]byte{secret1, cBytes(c1 + 1), y1}))
	})
}
