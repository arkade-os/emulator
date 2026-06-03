package arkade

// Phase 5: the FULL Cashu nullifier-pool ClaimScript.
//
// This file composes the four already-built in-script phases — packet/state
// continuity, NUT-00 hash_to_curve, NUT-12 r-blinded DLEQ, and the IMT
// non-membership + insert — into one Arkade Script, plus a recursive-covenant
// and value check, and exercises the whole thing through the engine over a
// crafted current+parent transaction.
//
// The off-chain reference (github.com/arkade-os/emulator/pkg/arkade/cashupool)
// is the source of truth for every value; the script re-derives each one and
// asserts equality, so a real Cashu token must be accepted and every tampered
// negative must be rejected.
//
// Run with: cd pkg/arkade && go test . -run TestClaimScript -v

import (
	"math/big"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/emulator/pkg/arkade/cashupool"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Claim-model constants.
const (
	claimDenomSat   = 1000   // Dsat: fixed per-claim payout to the claimant.
	claimPoolValue  = 100000 // V: value locked in the spent pool input.
	claimTreeDepth  = 16     // IMT depth (matches imtD in the IMT script test).
	claimMaxCounter = 4      // bounded hash_to_curve counter range (K).
)

// claimBuilder is a depth-tracked Arkade Script builder for the full claim. It
// mirrors the per-phase builders: depth models the runtime data stack so that
// OP_PICK offsets into the immutable base region are always correct.
type claimBuilder struct {
	bld   *txscript.ScriptBuilder
	depth int
}

func (b *claimBuilder) data(v []byte)        { b.bld.AddData(v); b.depth++ }
func (b *claimBuilder) i64(v int64)          { b.bld.AddInt64(v); b.depth++ }
func (b *claimBuilder) op(o byte, delta int) { b.bld.AddOp(o); b.depth += delta }
func (b *claimBuilder) rawOp(o byte)         { b.bld.AddOp(o) }

// pick copies the immutable base item at absolute index baseIdx to the top.
func (b *claimBuilder) pick(baseIdx int) {
	b.i64(int64(b.depth - 1 - baseIdx))
	b.op(OP_PICK, 0)
}

func (b *claimBuilder) script() []byte {
	s, err := b.bld.Script()
	if err != nil {
		panic(err)
	}
	return s
}

// be32FromIdx leaves the 32-byte big-endian encoding of the witness number at
// baseIdx on top. Stack: [...] -> [... be32(num)].
func (b *claimBuilder) be32FromIdx(baseIdx int) {
	b.pick(baseIdx)
	b.be32Top()
}

// be32Top turns the number on top into its 32-byte big-endian fixed-width
// encoding. Stack: [... v] -> [... be32(v)].
func (b *claimBuilder) be32Top() {
	b.i64(33)
	b.op(OP_NUM2BIN, -1)
	b.op(OP_REVERSEBYTES, 0)
	b.i64(32)
	b.op(OP_RIGHT, -1)
}

// appendZeroByte concatenates a single 0x00 byte onto the byte string on top.
// Stack: [... bytes] -> [... bytes||0x00].
func (b *claimBuilder) appendZeroByte() {
	b.op(OP_0, 1)
	b.op(OP_1, 1)
	b.op(OP_NUM2BIN, -1)
	b.op(OP_CAT, -1)
}

// digestToNum converts the 32-byte big-endian digest on top to a non-negative
// Arkade number. Stack: [... be32] -> [... num].
func (b *claimBuilder) digestToNum() {
	b.op(OP_REVERSEBYTES, 0)
	b.appendZeroByte()
	b.op(OP_BIN2NUM, 0)
}

// modP reduces the top item modulo p. Stack: [... a] -> [... a mod p].
func (b *claimBuilder) modP(p *big.Int) {
	b.data(encodeBig(p))
	b.op(OP_MOD, -1)
}

// rhsCurve computes (x³ + 7) mod p for the x_int at absolute index xIdx,
// leaving the result on top. Stack: [...] -> [... (x³+7) mod p].
func (b *claimBuilder) rhsCurve(xIdx int, p *big.Int) {
	b.pick(xIdx)
	b.pick(xIdx)
	b.op(OP_MUL, -1)
	b.modP(p)
	b.pick(xIdx)
	b.op(OP_MUL, -1)
	b.modP(p)
	b.data(encodeBig(big.NewInt(7)))
	b.op(OP_ADD, -1)
	b.modP(p)
}

// serializeUncompressed turns the affine point on top into its 65-byte SEC1
// uncompressed encoding 0x04 || be32(x) || be32(y). Stack: [... x y] -> [... U(P)].
func (b *claimBuilder) serializeUncompressed() {
	b.be32Top()      // x be32(y)
	b.op(OP_SWAP, 0) // be32(y) x
	b.be32Top()      // be32(y) be32(x)
	b.op(OP_4, 1)    // be32(y) be32(x) 0x04
	b.op(OP_SWAP, 0) // be32(y) 0x04 be32(x)
	b.op(OP_CAT, -1) // be32(y) 0x04||be32(x)
	b.op(OP_SWAP, 0) // 0x04||be32(x) be32(y)
	b.op(OP_CAT, -1) // 0x04||be32(x)||be32(y)
}

// scalarMulBaked leaves k*p as affine (x, y) on top for a BAKED point p, where
// k is the base scalar at kIdx. Stack: [...] -> [... x y].
func (b *claimBuilder) scalarMulBaked(p *btcec.PublicKey, kIdx int) {
	px, py := pubCoords(p)
	b.data(encodeBig(px))
	b.data(encodeBig(py))
	b.pick(kIdx)
	b.op(OP_0, 1)
	b.op(OP_ECMUL, -2)
}

// scalarMulXY leaves k*(px,py) on top for a RUNTIME point whose coords are base
// items at xIdx, yIdx; k is the base scalar at kIdx. Stack: [...] -> [... x y].
func (b *claimBuilder) scalarMulXY(xIdx, yIdx, kIdx int) {
	b.pick(xIdx)
	b.pick(yIdx)
	b.pick(kIdx)
	b.op(OP_0, 1)
	b.op(OP_ECMUL, -2)
}

// ecAdd combines the two affine points on top. [... x1 y1 x2 y2] -> [... x3 y3].
func (b *claimBuilder) ecAdd() {
	b.op(OP_0, 1)
	b.op(OP_ECADD, -3)
}

// Witness layout (bottom -> top), with D = claimTreeDepth. See buildClaimScript.
const (
	wSecret  = 0
	wCU      = 1
	wYx      = 2
	wYy      = 3
	wR       = 4
	wCx      = 5
	wCy      = 6
	wE       = 7
	wS       = 8
	wLowVal  = 9
	wLowNext = 10
	wLowIdx  = 11
	wLowPath = 12 // lowPath[i] at wLowPath+i
)

// buildClaimScript assembles the full ClaimScript.
//
// Witness layout (bottom -> top), with D = d:
//
//	idx 0 : secret
//	idx 1 : cU                (hash_to_curve winning counter)
//	idx 2 : Yx                (token point x; also the nullifier nf)
//	idx 3 : Yy                (token point y)
//	idx 4 : r                 (revealed DLEQ blinding factor)
//	idx 5 : Cx
//	idx 6 : Cy
//	idx 7 : e
//	idx 8 : s
//	idx 9 : low.Value
//	idx 10: low.Next
//	idx 11: lowIdx
//	idx 12 .. 12+D-1     : lowPath[0..D-1]
//	idx 12+D .. 12+2D-1  : szSibs[0..D-1]
//
// Phase 1 reads prevRoot, newRoot and appendIdx from the 0x05 packets and
// appends them as immutable base items above the witness:
//
//	idx 12+2D     : prevRoot   (32 bytes)
//	idx 12+2D+1   : newRoot    (32 bytes)
//	idx 12+2D+2   : appendIdx  (number, = parent size)
func buildClaimScript(A *btcec.PublicKey, dsat int64, packetType int64, d int, kCounters uint32) []byte {
	p := h2cFieldP()
	n := btcec.S256().N
	pMinus1Over2 := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))

	wSzSibs := wLowPath + d
	witnessLen := wSzSibs + d

	b := &claimBuilder{bld: txscript.NewScriptBuilder(), depth: witnessLen}

	// Base indices for the packet-derived items appended by Phase 1.
	idxPrevRoot := witnessLen
	idxNewRoot := witnessLen + 1
	idxAppendIdx := witnessLen + 2

	// ---------------------------------------------------------------------
	// Phase 1: read state from the 0x05 packets and assert continuity.
	// On exit the stack has gained exactly three base items in order:
	//   [... prevRoot newRoot appendIdx].
	// ---------------------------------------------------------------------

	// this PoolState = OP_INSPECTPACKET(packetType) -> [data, flag].
	b.i64(packetType)
	b.op(OP_INSPECTPACKET, 1) // pops type; pushes data then flag (net +1)
	b.op(OP_1, 1)
	b.op(OP_EQUALVERIFY, -2) // flag must be 1 (present); leaves [... data]

	// thisData on top. Extract prevRoot, newRoot, thisSize.
	b.op(OP_DUP, 1) // data data
	b.i64(0)
	b.i64(32)
	b.op(OP_SUBSTR, -2) // data prevRoot   (data[0:32])
	b.op(OP_SWAP, 0)    // prevRoot data
	b.op(OP_DUP, 1)     // prevRoot data data
	b.i64(32)
	b.i64(32)
	b.op(OP_SUBSTR, -2) // prevRoot data newRoot   (data[32:64])
	b.op(OP_SWAP, 0)    // prevRoot newRoot data
	b.i64(64)
	b.i64(4)
	b.op(OP_SUBSTR, -2) // prevRoot newRoot sizeBytes   (data[64:68])
	b.op(OP_BIN2NUM, 0) // prevRoot newRoot thisSize

	// parent PoolState = OP_INSPECTINPUTPACKET(packetType, currentInputIndex).
	b.i64(packetType)
	b.op(OP_PUSHCURRENTINPUTINDEX, 1)
	b.op(OP_INSPECTINPUTPACKET, 0) // pops type,index; pushes data then flag (net 0)
	b.op(OP_1, 1)
	b.op(OP_EQUALVERIFY, -2) // flag must be 1; leaves [... prevRoot newRoot thisSize pdata]

	// parentNewRoot = pdata[32:64]; assert prevRoot == parentNewRoot.
	b.op(OP_DUP, 1) // ... pdata pdata
	b.i64(32)
	b.i64(32)
	b.op(OP_SUBSTR, -2) // ... pdata parentNewRoot
	// prevRoot is 5 items below the top (prevRoot newRoot thisSize pdata parentNewRoot).
	b.op(OP_4, 1)            // ... pdata parentNewRoot 4
	b.op(OP_PICK, 0)         // ... pdata parentNewRoot prevRoot
	b.op(OP_EQUALVERIFY, -2) // assert; leaves [... prevRoot newRoot thisSize pdata]

	// parentSize = BIN2NUM(pdata[64:68]); assert thisSize == parentSize + 1.
	b.i64(64)
	b.i64(4)
	b.op(OP_SUBSTR, -2) // ... thisSize parentSize(bytes)
	b.op(OP_BIN2NUM, 0) // ... thisSize parentSize
	// appendIdx = parentSize (kept below); also need thisSize == parentSize+1.
	b.op(OP_DUP, 1)  // ... thisSize parentSize parentSize
	b.op(OP_1, 1)    // ... thisSize parentSize parentSize 1
	b.op(OP_ADD, -1) // ... thisSize parentSize (parentSize+1)
	// compare to thisSize (3 below top): thisSize parentSize sum.
	b.op(OP_2, 1)               // ... thisSize parentSize sum 2
	b.op(OP_PICK, 0)            // ... thisSize parentSize sum thisSize
	b.op(OP_NUMEQUALVERIFY, -2) // assert sum == thisSize; leaves [... thisSize parentSize]
	// Drop thisSize from under parentSize, leaving appendIdx (=parentSize) on top.
	b.op(OP_SWAP, 0)  // ... parentSize thisSize
	b.op(OP_DROP, -1) // ... parentSize  (== appendIdx)
	// Stack now: prevRoot newRoot appendIdx  (the three Phase-1 base items).

	// ---------------------------------------------------------------------
	// Phase 2: hash_to_curve. Prove HashToCurve(secret).x == Yx and that
	// (Yx, Yy) is the even-Y on-curve point, over the bounded counter range.
	// All work is consumed; net 0 to the base region.
	// ---------------------------------------------------------------------

	// msg = SHA256(DOMAIN || secret), parked on the alt stack so it survives the
	// loop without occupying a shifting main-stack slot.
	b.data(h2cDomain)
	b.pick(wSecret)
	b.op(OP_CAT, -1)
	b.op(OP_SHA256, 0)      // ... msg
	b.op(OP_TOALTSTACK, -1) // alt: [msg]

	// Bounded first-valid loop over counters 0..k-1. legendreFromAlt pushes
	// legendre_c using msg from the alt stack (restoring it each time).
	legendreForCounter := func(c uint32) {
		// recover msg, compute cand_c, restore msg.
		b.op(OP_FROMALTSTACK, 1) // ... msg
		b.op(OP_DUP, 1)          // ... msg msg
		b.op(OP_TOALTSTACK, -1)  // ... msg ; alt: [msg]
		b.data(h2cCounterLE(c))  // ... msg ctr_c
		b.op(OP_CAT, -1)         // ... (msg||ctr_c)
		b.op(OP_SHA256, 0)       // ... cand_c
		b.digestToNum()          // ... x_c
		xIdx := b.depth - 1
		b.rhsCurve(xIdx, p) // ... x_c v
		b.data(encodeBig(pMinus1Over2))
		b.data(encodeBig(p))
		b.op(OP_MODEXP, -2) // ... x_c legendre_c
		b.op(OP_SWAP, 0)    // ... legendre_c x_c
		b.op(OP_DROP, -1)   // ... legendre_c
	}

	for c := uint32(0); c < kCounters; c++ {
		legendreForCounter(c)
		depthWithLegendre := b.depth
		b.i64(int64(c))
		b.pick(wCU)
		b.op(OP_LESSTHAN, -1)
		b.op(OP_IF, -1)
		{
			b.data(encodeBig(pMinus1))
			b.op(OP_NUMEQUALVERIFY, -2)
		}
		b.op(OP_ELSE, 0)
		{
			b.depth = depthWithLegendre
			b.i64(int64(c))
			b.pick(wCU)
			b.op(OP_NUMEQUAL, -1)
			b.op(OP_IF, -1)
			{
				b.op(OP_1, 1)
				b.op(OP_NUMEQUALVERIFY, -2)
			}
			b.op(OP_ELSE, 0)
			{
				b.depth = depthWithLegendre
				b.op(OP_DROP, -1)
			}
			b.op(OP_ENDIF, 0)
		}
		b.op(OP_ENDIF, 0)
		b.depth = depthWithLegendre - 1
	}

	// Bind the winning point to the witness (Yx, Yy):
	// x_cU = digestToNum(SHA256(msg || ctr_cU)); assert == Yx.
	b.op(OP_FROMALTSTACK, 1) // ... msg
	b.pick(wCU)              // ... msg cU
	b.i64(4)
	b.op(OP_NUM2BIN, -1) // ... msg ctr_cU
	b.op(OP_CAT, -1)     // ... (msg||ctr_cU)
	b.op(OP_SHA256, 0)
	b.digestToNum() // ... x_cU
	b.pick(wYx)
	b.op(OP_NUMEQUALVERIFY, -2) // assert x_cU == Yx; stack back to base region

	// Assert (Yx, Yy) on-curve and Yy even (NUT-00 even-Y lift).
	b.pick(wYy)
	b.op(OP_2, 1)
	b.op(OP_MOD, -1)
	b.op(OP_0NOTEQUAL, 0)
	b.op(OP_NOT, 0)
	b.op(OP_VERIFY, -1) // Yy even

	b.pick(wYx)
	b.data(encodeBig(p))
	b.op(OP_LESSTHAN, -1)
	b.op(OP_VERIFY, -1) // Yx < p
	b.pick(wYy)
	b.data(encodeBig(p))
	b.op(OP_LESSTHAN, -1)
	b.op(OP_VERIFY, -1) // Yy < p

	b.pick(wYy)
	b.pick(wYy)
	b.op(OP_MUL, -1)
	b.modP(p)
	b.rhsCurve(wYx, p)
	b.op(OP_NUMEQUALVERIFY, -2) // Yy² == Yx³+7 (mod p)

	// ---------------------------------------------------------------------
	// Phase 3: NUT-12 r-blinded DLEQ. Y = (Yx, Yy) from witness; A baked.
	// B' = Y + r*G ; C' = C + r*A
	// R1 = s*G + (n-e)*A ; R2 = s*B' + (n-e)*C'
	// e' = bigendian(SHA256(U(R1)||U(R2)||U(A)||U(C'))) mod n ; assert e' == e.
	// (n-e), B', C' are appended as temporary base items above the Phase-1
	// items, then dropped at the end of this phase, restoring the base region.
	// ---------------------------------------------------------------------

	idxNE := b.depth // n - e
	idxBpx := b.depth + 1
	idxBpy := b.depth + 2
	idxCpx := b.depth + 3
	idxCpy := b.depth + 4

	// n - e
	b.data(encodeBig(n))
	b.pick(wE)
	b.op(OP_SUB, -1) // ... (n-e)

	// B' = Y + r*G
	G := scalarBaseMultPoint()
	b.scalarMulBaked(G, wR) // r*G
	b.pick(wYx)
	b.pick(wYy)
	b.ecAdd() // B' = (r*G)+Y -> Bpx Bpy

	// C' = C + r*A
	b.scalarMulBaked(A, wR) // r*A
	b.pick(wCx)
	b.pick(wCy)
	b.ecAdd() // C' = (r*A)+C -> Cpx Cpy

	// R1 = s*G + (n-e)*A ; serialize and park on alt stack.
	b.scalarMulBaked(G, wS)
	b.scalarMulBaked(A, idxNE)
	b.ecAdd()
	b.serializeUncompressed()
	b.op(OP_TOALTSTACK, -1) // alt: [U(R1)]

	// R2 = s*B' + (n-e)*C' ; append U(R2).
	b.scalarMulXY(idxBpx, idxBpy, wS)
	b.scalarMulXY(idxCpx, idxCpy, idxNE)
	b.ecAdd()
	b.serializeUncompressed()
	b.op(OP_FROMALTSTACK, 1)
	b.op(OP_SWAP, 0)
	b.op(OP_CAT, -1)
	b.op(OP_TOALTSTACK, -1) // alt: [U(R1)||U(R2)]

	// append U(A)
	ax, ay := pubCoords(A)
	b.data(encodeBig(ax))
	b.data(encodeBig(ay))
	b.serializeUncompressed()
	b.op(OP_FROMALTSTACK, 1)
	b.op(OP_SWAP, 0)
	b.op(OP_CAT, -1)
	b.op(OP_TOALTSTACK, -1)

	// append U(C')
	b.pick(idxCpx)
	b.pick(idxCpy)
	b.serializeUncompressed()
	b.op(OP_FROMALTSTACK, 1)
	b.op(OP_SWAP, 0)
	b.op(OP_CAT, -1) // preimage

	// e' = bigendian(SHA256(preimage)) mod n
	b.op(OP_SHA256, 0)
	b.op(OP_REVERSEBYTES, 0)
	b.op(OP_0, 1)
	b.op(OP_1, 1)
	b.op(OP_NUM2BIN, -1)
	b.op(OP_CAT, -1)
	b.op(OP_BIN2NUM, 0)
	b.data(encodeBig(n))
	b.op(OP_MOD, -1) // e'
	b.pick(wE)
	b.op(OP_NUMEQUALVERIFY, -2) // assert e' == e

	// Drop the five DLEQ temporaries (n-e, Bpx, Bpy, Cpx, Cpy), restoring base.
	b.op(OP_2DROP, -2)
	b.op(OP_2DROP, -2)
	b.op(OP_DROP, -1)

	// ---------------------------------------------------------------------
	// Phase 4: IMT non-membership + coupled insert. k = nf = Yx (witness).
	// prevRoot/newRoot/appendIdx from Phase 1. Uses imtRecomputeRoot.
	// All work is consumed; net 0 to the base region.
	// ---------------------------------------------------------------------

	emptyLeaf := cashupool.EmptyLeafHash()

	// Non-membership: recompute root from low leaf and assert == prevRoot.
	b.be32FromIdx(wLowVal)
	b.be32FromIdx(wLowNext)
	b.op(OP_CAT, -1)
	b.op(OP_SHA256, 0) // lowLeafHash
	imtRecomputeRoot(d, wLowIdx, wLowPath, b.op, b.rawOp, b.i64, b.pick)
	b.pick(idxPrevRoot)
	b.op(OP_EQUALVERIFY, -2)

	// Range check: low.Value < k AND (low.Next == 0 OR k < low.Next), k = Yx.
	b.pick(wLowVal)
	b.pick(wYx)
	b.op(OP_LESSTHAN, -1)
	b.pick(wLowNext)
	b.op(OP_0, 1)
	b.op(OP_NUMEQUAL, -1)
	b.pick(wYx)
	b.pick(wLowNext)
	b.op(OP_LESSTHAN, -1)
	b.op(OP_BOOLOR, -1)
	b.op(OP_BOOLAND, -1)
	b.op(OP_VERIFY, -1)

	// Insert step 1: lowPrimeHash = SHA256(be32(low.Value)||be32(k)); root1.
	b.be32FromIdx(wLowVal)
	b.be32FromIdx(wYx)
	b.op(OP_CAT, -1)
	b.op(OP_SHA256, 0)
	imtRecomputeRoot(d, wLowIdx, wLowPath, b.op, b.rawOp, b.i64, b.pick)
	b.op(OP_TOALTSTACK, -1) // alt: [root1]

	// Insert step 2: recompute(EMPTY, appendIdx, szSibs) == root1.
	b.data(emptyLeaf)
	imtRecomputeRoot(d, idxAppendIdx, wSzSibs, b.op, b.rawOp, b.i64, b.pick)
	b.op(OP_FROMALTSTACK, 1) // ... rootEmpty root1
	b.op(OP_DUP, 1)
	b.op(OP_TOALTSTACK, -1) // alt: [root1]
	b.op(OP_EQUALVERIFY, -2)

	// Insert step 3: newLeafHash = SHA256(be32(k)||be32(low.Next)); == newRoot.
	b.be32FromIdx(wYx)
	b.be32FromIdx(wLowNext)
	b.op(OP_CAT, -1)
	b.op(OP_SHA256, 0)
	imtRecomputeRoot(d, idxAppendIdx, wSzSibs, b.op, b.rawOp, b.i64, b.pick)
	b.pick(idxNewRoot)
	b.op(OP_EQUALVERIFY, -2)

	// Drop the cached root1.
	b.op(OP_FROMALTSTACK, 1)
	b.op(OP_DROP, -1)

	// ---------------------------------------------------------------------
	// Phase 5: covenant + value.
	//   OP_INSPECTNUMOUTPUTS == 3
	//   OP_INSPECTOUTPUTVALUE(0) == Dsat
	//   OP_INSPECTOUTPUTSCRIPTPUBKEY(1) == input scriptPubKey (recursive, v1)
	//   OP_INSPECTOUTPUTVALUE(1) == INSPECTINPUTVALUE - Dsat
	// ---------------------------------------------------------------------

	// numOutputs == 3 (claimant, pool, extension).
	b.op(OP_INSPECTNUMOUTPUTS, 1)
	b.i64(3)
	b.op(OP_NUMEQUALVERIFY, -2)

	// outputValue(0) == Dsat.
	b.i64(0)
	b.op(OP_INSPECTOUTPUTVALUE, 0)
	b.i64(dsat)
	b.op(OP_NUMEQUALVERIFY, -2)

	// outputScriptPubKey(1) == inputScriptPubKey (segwit v1, compare programs).
	b.i64(1)
	b.op(OP_INSPECTOUTPUTSCRIPTPUBKEY, 1) // pops index; pushes program then version (net +1)
	b.op(OP_1, 1)
	b.op(OP_EQUALVERIFY, -2) // version must be segwit v1; leaves [... outProg]
	b.op(OP_PUSHCURRENTINPUTINDEX, 1)
	b.op(OP_INSPECTINPUTSCRIPTPUBKEY, 1) // pops index; pushes program then version (net +1)
	b.op(OP_1, 1)
	b.op(OP_EQUALVERIFY, -2) // version must be segwit v1; leaves [... outProg inProg]
	b.op(OP_EQUALVERIFY, -2) // outProg == inProg

	// outputValue(1) == inputValue - Dsat.
	b.i64(1)
	b.op(OP_INSPECTOUTPUTVALUE, 0) // outVal1
	b.op(OP_PUSHCURRENTINPUTINDEX, 1)
	b.op(OP_INSPECTINPUTVALUE, 0) // outVal1 inVal
	b.i64(dsat)
	b.op(OP_SUB, -1) // outVal1 (inVal-Dsat)
	b.op(OP_NUMEQUALVERIFY, -2)

	// All checks passed; clear the witness + Phase-1 base items so the engine
	// sees a single truthy result.
	for b.depth >= 2 {
		b.op(OP_2DROP, -2)
	}
	for b.depth >= 1 {
		b.op(OP_DROP, -1)
	}
	b.op(OP_1, 1) // success

	return b.script()
}

// claimWitness assembles the witness stack in the exact order buildClaimScript
// picks: [secret, cU, Yx, Yy, r, Cx, Cy, e, s, low.Value, low.Next, lowIdx,
// lowPath[0..D-1], szSibs[0..D-1]].
func claimWitness(
	secret []byte, cU uint32,
	Yx, Yy, r, Cx, Cy, e, s *big.Int,
	low cashupool.Leaf, lowIdx uint32, lowPath [][]byte, szSibs [][]byte,
) [][]byte {
	w := make([][]byte, 0, 12+len(lowPath)+len(szSibs))
	w = append(w, secret)
	w = append(w, encodeBig(new(big.Int).SetUint64(uint64(cU))))
	w = append(w, encodeBig(Yx), encodeBig(Yy))
	w = append(w, encodeBig(r), encodeBig(Cx), encodeBig(Cy))
	w = append(w, encodeBig(e), encodeBig(s))
	w = append(w, encodeBig(low.Value), encodeBig(low.Next))
	w = append(w, encodeBig(new(big.Int).SetUint64(uint64(lowIdx))))
	for _, sib := range lowPath {
		w = append(w, sib)
	}
	for _, sib := range szSibs {
		w = append(w, sib)
	}
	return w
}

// ClaimEnv holds the persistent state of a Cashu nullifier pool plus the baked
// mint key and the segwit-v1 pool program (the recursive-covenant target).
type ClaimEnv struct {
	t          *testing.T
	k          *btcec.PrivateKey // mint private key
	A          *btcec.PublicKey  // mint public key A = k*G
	tree       *cashupool.IMT    // off-chain nullifier tree
	poolPk     []byte            // segwit-v1 pool scriptPubKey
	script     []byte            // the full ClaimScript
	parentRoot []byte            // current pool root (NewRoot of the latest tx)
	parentSize uint32            // current pool size
}

// newClaimEnv builds a fresh pool: mint key, genesis IMT, the ClaimScript, and a
// genesis parent PoolState {PrevRoot: zero32, NewRoot: tree.Root(), Size: 1}.
func newClaimEnv(t *testing.T) *ClaimEnv {
	t.Helper()
	k := mustPrivKeyFromSeed(t, "cashu-pool-mint")
	tree := cashupool.NewIMT(claimTreeDepth)

	// A deterministic 32-byte segwit-v1 program for the pool.
	prog := make([]byte, 32)
	for i := range prog {
		prog[i] = byte(0x10 + i)
	}
	poolPk := append([]byte{OP_1, OP_DATA_32}, prog...)

	return &ClaimEnv{
		t:          t,
		k:          k,
		A:          k.PubKey(),
		tree:       tree,
		poolPk:     poolPk,
		script:     buildClaimScript(k.PubKey(), claimDenomSat, cashuPoolPacketType, claimTreeDepth, claimMaxCounter),
		parentRoot: append([]byte(nil), tree.Root()...),
		parentSize: tree.Size(),
	}
}

// claimArtifacts bundles everything needed to run one claim through the engine.
type claimArtifacts struct {
	tx       *wire.MsgTx
	fetcher  ArkPrevOutFetcher
	witness  [][]byte
	prevRoot []byte
	newRoot  []byte
	thisSize uint32

	// Token + IMT proof pieces, captured so a follow-up double-spend can replay
	// the same (now stale) non-membership proof against the advanced pool state.
	secret  []byte
	cU      uint32
	Yx, Yy  *big.Int
	r       *big.Int
	Cx, Cy  *big.Int
	e, s    *big.Int
	low     cashupool.Leaf
	lowIdx  uint32
	lowPath [][]byte
	szSibs  [][]byte
}

// prepareClaim performs the off-chain Cashu work for claiming token `secret`,
// mutates the pool tree by inserting the nullifier, and crafts the current +
// parent transactions (with 0x05 PoolState packets) plus the witness.
func (env *ClaimEnv) prepareClaim(secret []byte) claimArtifacts {
	t := env.t
	t.Helper()

	// Cashu token: Y = HashToCurve(secret); nf = Y.x; C = k*Y.
	Y, cU := cashupool.HashToCurve(secret)
	require.Less(t, cU, uint32(claimMaxCounter), "secret must grind within the bounded counter range")
	C := cashupool.Sign(env.k, Y)
	Yx, Yy := pubCoords(Y)
	Cx, Cy := pubCoords(C)
	nf := new(big.Int).Set(Yx)

	// NUT-12 r-blinded DLEQ proof.
	r := mustPrivKeyFromSeed(t, "cashu-claim-r-"+string(secret))
	e, s := cashupool.ProveProofDLEQ(env.k, Y, C, r)
	require.True(t, cashupool.VerifyProofDLEQ(env.A, Y, C, r, e, s),
		"off-chain DLEQ must verify before running the script")

	// IMT non-membership + insert (mutates the off-chain tree).
	low, lowIdx, lowPath := env.tree.NonMembership(nf)
	prevRoot := append([]byte(nil), env.tree.Root()...)
	_, newRoot, szSibs, appendIdx := env.tree.Insert(nf, low, lowIdx, lowPath)
	require.Equal(t, env.parentSize, appendIdx, "append index must equal parent size")
	require.Equal(t, env.parentRoot, prevRoot, "this.PrevRoot must equal parent.NewRoot")

	thisSize := env.parentSize + 1

	rBig := scalarToBig(&r.Key)
	eBig := scalarToBig(e)
	sBig := scalarToBig(s)

	witness := claimWitness(secret, cU, Yx, Yy, rBig, Cx, Cy, eBig, sBig, low, lowIdx, lowPath, szSibs)

	// Parent state = env's current view (the latest committed pool state).
	parentNewRoot := append([]byte(nil), env.parentRoot...)
	parentSize := env.parentSize

	a := claimArtifacts{
		witness:  witness,
		prevRoot: prevRoot,
		newRoot:  newRoot,
		thisSize: thisSize,
		secret:   secret,
		cU:       cU,
		Yx:       Yx, Yy: Yy,
		r:  rBig,
		Cx: Cx, Cy: Cy,
		e: eBig, s: sBig,
		low:     low,
		lowIdx:  lowIdx,
		lowPath: lowPath,
		szSibs:  szSibs,
	}
	a.tx, a.fetcher = env.craftClaimTx(parentNewRoot, parentSize, prevRoot, newRoot, thisSize)

	// Advance the env's view to this tx's state for any chained claim.
	env.parentRoot = append([]byte(nil), newRoot...)
	env.parentSize = thisSize

	return a
}

// craftClaimTx builds the current claim tx (claimant, pool, ext outputs) and the
// prevout fetcher, with a parent tx carrying parentNewRoot/parentSize in a 0x05
// packet. The current tx's 0x05 packet carries {prevRoot, newRoot, thisSize}.
func (env *ClaimEnv) craftClaimTx(
	parentNewRoot []byte, parentSize uint32,
	prevRoot, newRoot []byte, thisSize uint32,
) (*wire.MsgTx, ArkPrevOutFetcher) {
	t := env.t

	// Parent tx: carries the parent PoolState in a 0x05 extension; its output[0]
	// is the segwit-v1 pool program (so the recursive covenant binds output[1]).
	parentState := cashupool.PoolState{
		PrevRoot: env.genesisPrevRoot(),
		NewRoot:  append([]byte(nil), parentNewRoot...),
		Size:     parentSize,
	}
	parentTx := env.buildExtTx(env.poolPk, claimPoolValue, parentState)

	inputOutpoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}

	thisExtOut := mustExtTxOut(t, cashupool.PoolState{
		PrevRoot: append([]byte(nil), prevRoot...),
		NewRoot:  append([]byte(nil), newRoot...),
		Size:     thisSize,
	})

	claimantPk := append([]byte{OP_1, OP_DATA_32}, make([]byte, 32)...)
	tx := &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: inputOutpoint}},
		TxOut: []*wire.TxOut{
			{Value: claimDenomSat, PkScript: claimantPk},
			{Value: claimPoolValue - claimDenomSat, PkScript: env.poolPk},
			thisExtOut,
		},
	}

	base := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		inputOutpoint: {Value: claimPoolValue, PkScript: env.poolPk},
	})
	fetcher := newTestArkPrevOutFetcher(
		base,
		map[wire.OutPoint]*wire.MsgTx{inputOutpoint: parentTx},
		map[wire.OutPoint]uint32{inputOutpoint: 0},
	)
	return tx, fetcher
}

// genesisPrevRoot returns the all-zero 32-byte root used as the genesis
// PrevRoot of the very first pool state.
func (env *ClaimEnv) genesisPrevRoot() []byte { return make([]byte, 32) }

// buildExtTx builds a parent-style tx whose output[0] carries `value` under
// pkScript and which holds `state` in a 0x05 extension output.
func (env *ClaimEnv) buildExtTx(pkScript []byte, value int64, state cashupool.PoolState) *wire.MsgTx {
	extOut := mustExtTxOut(env.t, state)
	return &wire.MsgTx{
		Version: 1,
		TxIn:    []*wire.TxIn{{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x00}, Index: 0}}},
		TxOut:   []*wire.TxOut{{Value: value, PkScript: pkScript}, extOut},
	}
}

// mustExtTxOut builds a 0x05 extension output carrying the serialized PoolState.
func mustExtTxOut(t *testing.T, state cashupool.PoolState) *wire.TxOut {
	t.Helper()
	ext := extension.Extension{
		extension.UnknownPacket{PacketType: cashuPoolPacketType, Data: state.Serialize()},
	}
	out, err := ext.TxOut()
	require.NoError(t, err)
	return out
}

// runClaim executes the ClaimScript over the prepared artifacts.
func (env *ClaimEnv) runClaim(a claimArtifacts) error {
	engine, err := NewEngine(
		env.script, a.tx, 0,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(a.tx, a.fetcher),
		1_000_000,
		a.fetcher,
	)
	require.NoError(env.t, err)
	engine.SetStack(a.witness)
	return engine.Execute()
}

func TestClaimScript(t *testing.T) {
	t.Parallel()

	// claimSecret grinds a secret whose hash_to_curve counter is within K.
	claimSecret := func(tag string) []byte {
		return cashupool.GrindSecret(tag, claimMaxCounter-1)
	}

	t.Run("valid claim", func(t *testing.T) {
		env := newClaimEnv(t)
		a := env.prepareClaim(claimSecret("claim-valid"))
		require.NoError(t, env.runClaim(a))
	})
}
