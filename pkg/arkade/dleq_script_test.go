package arkade

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestDLEQScript verifies a Cashu/BDHKE-style DLEQ (Discrete Log Equality)
// proof entirely inside an Arkade Script, exercising the elliptic-curve
// opcodes (OP_ECMUL/OP_ECADD), byte-surgery opcodes (OP_NUM2BIN/OP_BIN2NUM/
// OP_REVERSEBYTES/OP_RIGHT/OP_CAT) and OP_SHA256/OP_MOD together.
//
// Bob proves the same secret a links A = a*G and C' = a*B' without revealing a:
//
//	Bob:   r random; R1 = r*G; R2 = r*B'; e = H(R1,R2,A,C'); s = r + e*a → (e, s)
//	Alice: R1 = s*G - e*A; R2 = s*B' - e*C'; accept iff e == H(R1,R2,A,C')
//
// Here Alice is the script. The public instance (G, A, B', C') is baked into
// the locking script; the spender supplies the proof (e, s) as the witness.
//
// Conventions chosen so the script and the off-chain prover agree exactly:
//   - Points are hashed in SEC1 compressed form (0x02/0x03 || big-endian X),
//     which the script reconstructs from the affine (x, y) coordinates that the
//     EC opcodes operate on.
//   - The challenge digest is read as a little-endian unsigned integer (Arkade
//     numbers are sign-magnitude little-endian); a 0x00 byte is appended before
//     OP_BIN2NUM so the 256-bit digest is never interpreted as negative.
//   - Point subtraction is done as s*G + (n-e)*A, since (n-e)*A == -e*A and
//     there is no point-negation opcode.
func TestDLEQScript(t *testing.T) {
	t.Parallel()

	n := btcec.S256().N

	// Public DLEQ instance.
	a := mustPrivKeyFromSeed(t, "dleq-script-secret-a")  // Bob's secret
	b := mustPrivKeyFromSeed(t, "dleq-script-blinded-b") // gives a well-formed B'
	r := mustPrivKeyFromSeed(t, "dleq-script-nonce-r")   // proof nonce

	one := new(btcec.ModNScalar)
	one.SetInt(1)
	G := scalarBaseMult(one)

	A := a.PubKey()                 // A  = a*G
	Bp := b.PubKey()                // B' = b*G (any point)
	Cp := scalarMultPub(&a.Key, Bp) // C' = a*B'
	R1 := scalarBaseMult(&r.Key)    // R1 = r*G
	R2 := scalarMultPub(&r.Key, Bp) // R2 = r*B'

	// e = H(R1 || R2 || A || C') mod n, with the digest read little-endian to
	// match the script's OP_BIN2NUM. s = r + e*a mod n.
	e := dleqScriptChallenge(R1, R2, A, Cp, n)
	require.NotEqual(t, 0, e.Sign(), "challenge e must be non-zero so (n-e) is a valid scalar")

	aBig := scalarToBig(&a.Key)
	rBig := scalarToBig(&r.Key)
	s := new(big.Int).Mod(new(big.Int).Add(rBig, new(big.Int).Mul(e, aBig)), n)
	require.NotEqual(t, 0, s.Sign(), "response s must be non-zero")

	script := buildDLEQVerifyScript(G, A, Bp, Cp, n)

	// The witness is the proof (e, s): bottom-of-stack e, top-of-stack s.
	validWitness := [][]byte{encodeBig(e), encodeBig(s)}

	t.Run("valid proof verifies", func(t *testing.T) {
		require.NoError(t, runArkadeScript(t, script, validWitness))
	})

	t.Run("tampered s fails", func(t *testing.T) {
		badS := new(big.Int).Mod(new(big.Int).Add(s, big.NewInt(1)), n)
		require.Error(t, runArkadeScript(t, script, [][]byte{encodeBig(e), encodeBig(badS)}))
	})

	t.Run("tampered e fails", func(t *testing.T) {
		badE := new(big.Int).Mod(new(big.Int).Add(e, big.NewInt(1)), n)
		require.Error(t, runArkadeScript(t, script, [][]byte{encodeBig(badE), encodeBig(s)}))
	})

	t.Run("proof for a different secret fails", func(t *testing.T) {
		// A valid (e2, s2) for a different secret a2 must not satisfy the
		// script, whose public instance still commits to A = a*G, C' = a*B'.
		a2 := mustPrivKeyFromSeed(t, "dleq-script-other-secret")
		C2 := scalarMultPub(&a2.Key, Bp)
		e2 := dleqScriptChallenge(R1, R2, a2.PubKey(), C2, n)
		s2 := new(big.Int).Mod(
			new(big.Int).Add(rBig, new(big.Int).Mul(e2, scalarToBig(&a2.Key))), n)
		require.Error(t, runArkadeScript(t, script, [][]byte{encodeBig(e2), encodeBig(s2)}))
	})
}

// buildDLEQVerifyScript assembles the inline DLEQ verification script for the
// public instance (G, A, B', C') and group order n. The spender's witness is
// the proof (e, s) with e at the bottom of the stack and s on top.
//
// The builder tracks the runtime stack depth as it emits opcodes so that
// OP_PICK offsets for the re-used scalars (e, s, n-e) are always correct.
func buildDLEQVerifyScript(G, A, Bp, Cp *btcec.PublicKey, n *big.Int) []byte {
	bld := txscript.NewScriptBuilder()

	// depth models the data stack at runtime, starting with the two witness
	// items [e, s] already pushed by SetStack.
	depth := 2

	data := func(v []byte) { bld.AddData(v); depth++ }
	i64 := func(v int64) { bld.AddInt64(v); depth++ }
	op := func(o byte, delta int) { bld.AddOp(o); depth += delta }

	// pick copies the immutable base item at baseIdx (0 = e, 1 = s, 2 = n-e)
	// to the top of the stack. Net stack effect: +1.
	pick := func(baseIdx int) {
		i64(int64(depth - 1 - baseIdx))
		op(OP_PICK, 0)
	}

	// scalarMul leaves k*(px,py) as affine (x, y) on top, where k is the base
	// scalar at kIdx. Stack: [...] -> [... x y].
	scalarMul := func(p *btcec.PublicKey, kIdx int) {
		px, py := pubCoords(p)
		data(encodeBig(px))
		data(encodeBig(py))
		pick(kIdx)
		op(OP_0, 1)      // curve id 0 = secp256k1
		op(OP_ECMUL, -2) // pops x,y,k,curve; pushes x,y
	}

	// ecAdd combines the two affine points on top. [... x1 y1 x2 y2] -> [... x3 y3].
	ecAdd := func() {
		op(OP_0, 1)
		op(OP_ECADD, -3) // pops x1,y1,x2,y2,curve; pushes x3,y3
	}

	// serializeCompressed turns the affine point on top into its 33-byte SEC1
	// compressed encoding. [... x y] -> [... 0x02|0x03 || be32(x)].
	serializeCompressed := func() {
		op(OP_DUP, 1)          // x y y
		op(OP_2, 1)            // x y y 2
		op(OP_MOD, -1)         // x y (y%2)
		op(OP_2, 1)            // x y (y%2) 2
		op(OP_ADD, -1)         // x y prefixNum (2=even, 3=odd)
		op(OP_1, 1)            // x y prefixNum 1
		op(OP_NUM2BIN, -1)     // x y prefixByte
		op(OP_SWAP, 0)         // x prefixByte y
		op(OP_DROP, -1)        // x prefixByte
		op(OP_SWAP, 0)         // prefixByte x
		i64(33)                // prefixByte x 33
		op(OP_NUM2BIN, -1)     // prefixByte le33(x)
		op(OP_REVERSEBYTES, 0) // prefixByte be33(x) == 0x00||be32(x)
		i64(32)                // prefixByte be33(x) 32
		op(OP_RIGHT, -1)       // prefixByte be32(x)
		op(OP_CAT, -1)         // compressed point
	}

	// --- n - e (kept as base item index 2, reused for both -e*A and -e*C') ---
	data(encodeBig(n))
	pick(0)        // copy e
	op(OP_SUB, -1) // n - e

	// --- R1 = s*G + (n-e)*A, push compressed(R1) to the alt stack ---
	scalarMul(G, 1) // s*G
	scalarMul(A, 2) // (n-e)*A
	ecAdd()         // R1
	serializeCompressed()
	op(OP_TOALTSTACK, -1) // alt: [c(R1)]

	// --- R2 = s*B' + (n-e)*C', accumulate c(R1)||c(R2) on the alt stack ---
	scalarMul(Bp, 1) // s*B'
	scalarMul(Cp, 2) // (n-e)*C'
	ecAdd()          // R2
	serializeCompressed()
	op(OP_FROMALTSTACK, 1) // c(R2) c(R1)
	op(OP_SWAP, 0)         // c(R1) c(R2)
	op(OP_CAT, -1)         // c(R1)||c(R2)
	op(OP_TOALTSTACK, -1)  // alt: [acc]

	// --- append compressed(A) ---
	ax, ay := pubCoords(A)
	data(encodeBig(ax))
	data(encodeBig(ay))
	serializeCompressed()
	op(OP_FROMALTSTACK, 1)
	op(OP_SWAP, 0)
	op(OP_CAT, -1)
	op(OP_TOALTSTACK, -1)

	// --- append compressed(C'): leaves the full preimage on the main stack ---
	cx, cy := pubCoords(Cp)
	data(encodeBig(cx))
	data(encodeBig(cy))
	serializeCompressed()
	op(OP_FROMALTSTACK, 1)
	op(OP_SWAP, 0)
	op(OP_CAT, -1) // preimage = c(R1)||c(R2)||c(A)||c(C')

	// --- e' = H(preimage) mod n, read little-endian and forced non-negative ---
	op(OP_SHA256, 0)   // 32-byte digest
	op(OP_0, 1)        // 0
	op(OP_1, 1)        // 0 1
	op(OP_NUM2BIN, -1) // 0x00 byte
	op(OP_CAT, -1)     // digest||0x00 (positive little-endian)
	op(OP_BIN2NUM, 0)  // H
	data(encodeBig(n)) // H n
	op(OP_MOD, -1)     // e' = H mod n

	// --- assert e' == e, then leave a single truthy item ---
	pick(0) // copy e
	op(OP_NUMEQUALVERIFY, -2)
	op(OP_2DROP, -2) // drop n-e, s
	op(OP_DROP, -1)  // drop e
	op(OP_1, 1)      // success

	script, err := bld.Script()
	if err != nil {
		panic(err)
	}
	return script
}

// runArkadeScript executes script with the given witness as the initial data
// stack and returns the engine result.
func runArkadeScript(t *testing.T, script []byte, witness [][]byte) error {
	t.Helper()

	outpoint := wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}
	prevoutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
			outpoint: {
				Value: 1_000_000_000,
				PkScript: []byte{
					OP_1, OP_DATA_32,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
		}), nil, nil,
	)

	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: outpoint}},
	}

	engine, err := NewEngine(
		script, tx, 0,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(tx, prevoutFetcher),
		0,
		prevoutFetcher,
	)
	require.NoError(t, err)

	if len(witness) > 0 {
		engine.SetStack(witness)
	}
	return engine.Execute()
}

// dleqScriptChallenge computes e = H(R1||R2||A||C') mod n exactly as the script
// does: SHA256 over the SEC1 compressed points, with the digest interpreted as
// a little-endian unsigned integer.
func dleqScriptChallenge(R1, R2, A, Cp *btcec.PublicKey, n *big.Int) *big.Int {
	pre := make([]byte, 0, 33*4)
	pre = append(pre, R1.SerializeCompressed()...)
	pre = append(pre, R2.SerializeCompressed()...)
	pre = append(pre, A.SerializeCompressed()...)
	pre = append(pre, Cp.SerializeCompressed()...)

	digest := sha256.Sum256(pre)

	// The script appends a 0x00 byte and runs OP_BIN2NUM, reading the bytes as
	// sign-magnitude little-endian. Reverse to big-endian to load the same
	// magnitude into a big.Int.
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = digest[31-i]
	}
	h := new(big.Int).SetBytes(be)
	return new(big.Int).Mod(h, n)
}

// pubCoords returns the affine (x, y) coordinates of a public key as big.Ints.
func pubCoords(p *btcec.PublicKey) (x, y *big.Int) {
	u := p.SerializeUncompressed() // 0x04 || be32(x) || be32(y)
	return new(big.Int).SetBytes(u[1:33]), new(big.Int).SetBytes(u[33:65])
}

// scalarToBig converts a secp256k1 scalar to a big.Int.
func scalarToBig(s *btcec.ModNScalar) *big.Int {
	b := s.Bytes()
	return new(big.Int).SetBytes(b[:])
}
