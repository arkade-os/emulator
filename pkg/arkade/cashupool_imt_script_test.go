package arkade

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade/cashupool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// This file verifies an Indexed Merkle Tree (IMT) non-membership proof entirely
// inside an Arkade Script, mirroring the off-chain reference in
// github.com/arkade-os/emulator/pkg/arkade/cashupool (imt.go).
//
// The on-chain core is a positional Merkle walk that recomputes a root from a
// 32-byte leaf hash, a leaf index, and D sibling hashes. It matches
// cashupool.RecomputeRoot byte-for-byte: the walk is LSB-first and at level i,
//
//	bit == 0  =>  current is LEFT  child:  SHA256(cur || sib)
//	bit == 1  =>  current is RIGHT child:  SHA256(sib || cur)
//
// where bit is the i-th least-significant bit of the leaf index. Leaf hashes
// are SHA256(be32(Value) || be32(Next)); the 32-byte big-endian encoding of a
// script number is produced with NUM2BIN(33) -> REVERSEBYTES -> RIGHT(32).
//
// imtD is the fixed tree depth used throughout the in-script tests.
const imtD = 16

// imtKFromTag returns a 256-bit nullifier value derived from a tag, used as the
// IMT key k. It is the SHA256 of the tag interpreted as a big-endian unsigned
// integer, which is non-zero with overwhelming probability.
func imtKFromTag(tag string) *big.Int {
	d := sha256.Sum256([]byte(tag))
	return new(big.Int).SetBytes(d[:])
}

// imtRecomputeRoot emits opcodes that recompute a Merkle root by walking D
// levels LSB-first, matching cashupool.RecomputeRoot exactly.
//
// On entry the 32-byte leafHash is on top of the data stack; the leaf index is
// the immutable witness item at base position idxBaseIdx, and the D sibling
// hashes are the immutable witness items at base positions sibBaseIdx+0 ..
// sibBaseIdx+D-1 (sib level 0 first). On exit the recomputed 32-byte root is on
// top of the data stack and all working values have been cleaned up.
//
// The running index is kept on the alt stack across each level so that the main
// stack inside the OP_IF/OP_ELSE branches contains exactly [cur sib], keeping
// both branches stack-balanced (each leaves a single concatenated preimage).
func imtRecomputeRoot(
	d int,
	idxBaseIdx, sibBaseIdx int,
	op func(byte, int),
	rawOp func(byte),
	i64 func(int64),
	pick func(int),
) {
	// Seed the running index on the alt stack from a copy of the witness index.
	pick(idxBaseIdx)      // [... leafHash idxCopy]
	op(OP_TOALTSTACK, -1) // [... leafHash]; alt: [idxWork]

	for i := 0; i < d; i++ {
		// Recover the running index, derive (bit, next) and re-stash next.
		op(OP_FROMALTSTACK, 1) // [... cur idxWork]
		op(OP_DUP, 1)          // [... cur idxWork idxWork]
		op(OP_2, 1)            // [... cur idxWork idxWork 2]
		op(OP_DIV, -1)         // [... cur idxWork next]
		op(OP_TOALTSTACK, -1)  // [... cur idxWork]; alt: [next]
		op(OP_2, 1)            // [... cur idxWork 2]
		op(OP_MOD, -1)         // [... cur bit]

		// Fetch the level-i sibling and arrange [cur sib bit] for the branch.
		pick(sibBaseIdx + i) // [... cur bit sib]
		op(OP_SWAP, 0)       // [... cur sib bit]

		// Both branches consume bit and turn [cur sib] into one preimage, so
		// the whole conditional has a single net effect of -2 (pop bit, then
		// the branch that runs concatenates two items into one). Only the IF
		// path is counted in depth; the ELSE path is emitted raw so the two
		// arms are not double-counted.
		op(OP_IF, -2) // net of the conditional: pops bit, branch nets -1
		// bit == 1: current is the RIGHT child -> SHA256(sib || cur).
		rawOp(OP_SWAP) // [... sib cur]
		rawOp(OP_CAT)  // [... sib||cur]
		rawOp(OP_ELSE)
		// bit == 0: current is the LEFT child -> SHA256(cur || sib).
		rawOp(OP_CAT) // [... cur||sib]
		rawOp(OP_ENDIF)
		op(OP_SHA256, 0) // [... newCur]
	}

	// Discard the exhausted running index (0 after D divisions).
	op(OP_FROMALTSTACK, 1) // [... cur idxWork]
	op(OP_DROP, -1)        // [... cur]
}

// buildIMTNonMembershipScript builds a locking script that verifies a
// non-membership proof for a key k against the baked prevRoot.
//
// Witness layout (bottom of stack first):
//
//	[ low.Value, low.Next, lowIdx, lowPath[0..D-1], k ]
func buildIMTNonMembershipScript(d int, prevRoot []byte) []byte {
	bld := txscript.NewScriptBuilder()

	// Witness base positions.
	const (
		lowValIdx  = 0
		lowNextIdx = 1
		lowIdxIdx  = 2
		lowPathIdx = 3 // lowPath[i] at lowPathIdx+i
	)
	kIdx := lowPathIdx + d

	depth := kIdx + 1 // number of witness items pushed by SetStack

	data := func(v []byte) { bld.AddData(v); depth++ }
	i64 := func(v int64) { bld.AddInt64(v); depth++ }
	op := func(o byte, delta int) { bld.AddOp(o); depth += delta }
	rawOp := func(o byte) { bld.AddOp(o) }

	pick := func(baseIdx int) {
		i64(int64(depth - 1 - baseIdx))
		op(OP_PICK, 0)
	}

	// be32 leaves the 32-byte big-endian encoding of the witness number at
	// baseIdx on top of the stack.
	be32 := func(baseIdx int) {
		pick(baseIdx)          // [... num]
		i64(33)                // [... num 33]
		op(OP_NUM2BIN, -1)     // [... le33(num)]
		op(OP_REVERSEBYTES, 0) // [... be33(num) == 0x00||be32(num)]
		i64(32)                // [... be33 32]
		op(OP_RIGHT, -1)       // [... be32(num)]
	}

	emitNonMembership := func() {
		// 1. lowLeafHash = SHA256(be32(low.Value) || be32(low.Next)).
		be32(lowValIdx)  // [... be32(low.Value)]
		be32(lowNextIdx) // [... be32(low.Value) be32(low.Next)]
		op(OP_CAT, -1)   // [... le64]
		op(OP_SHA256, 0) // [... lowLeafHash]

		// 2. recompute the root from the low leaf and assert == prevRoot.
		imtRecomputeRoot(d, lowIdxIdx, lowPathIdx, op, rawOp, i64, pick)
		data(prevRoot)         // [... root prevRoot]
		op(OP_EQUALVERIFY, -2) // assert equal

		// 3. range check: low.Value < k AND (low.Next == 0 OR k < low.Next).
		pick(lowValIdx)     // [... low.Value]
		pick(kIdx)          // [... low.Value k]
		op(OP_LESSTHAN, -1) // [... (low.Value<k)]

		pick(lowNextIdx)    // [... lt low.Next]
		op(OP_0, 1)         // [... lt low.Next 0]
		op(OP_NUMEQUAL, -1) // [... lt (low.Next==0)]

		pick(kIdx)          // [... lt isInf k]
		pick(lowNextIdx)    // [... lt isInf k low.Next]
		op(OP_LESSTHAN, -1) // [... lt isInf (k<low.Next)]

		op(OP_BOOLOR, -1)  // [... lt (isInf OR k<low.Next)]
		op(OP_BOOLAND, -1) // [... (low.Value<k AND bracket)]
		op(OP_VERIFY, -1)  // assert range holds
	}

	emitNonMembership()

	// All checks passed; clear the witness items so the engine sees a single
	// truthy result.
	for depth >= 2 {
		op(OP_2DROP, -2)
	}
	for depth >= 1 {
		op(OP_DROP, -1)
	}
	op(OP_1, 1) // success

	script, err := bld.Script()
	if err != nil {
		panic(err)
	}
	return script
}

// imtNonMembershipWitness builds the witness stack for the non-membership
// script: [ low.Value, low.Next, lowIdx, lowPath[0..D-1], k ].
func imtNonMembershipWitness(low cashupool.Leaf, lowIdx uint32, lowPath [][]byte, k *big.Int) [][]byte {
	w := make([][]byte, 0, 3+len(lowPath)+1)
	w = append(w, encodeBig(low.Value))
	w = append(w, encodeBig(low.Next))
	w = append(w, encodeBig(new(big.Int).SetUint64(uint64(lowIdx))))
	for _, s := range lowPath {
		w = append(w, s)
	}
	w = append(w, encodeBig(k))
	return w
}

func TestIMTNonMembershipScript(t *testing.T) {
	t.Parallel()

	t.Run("valid non-membership against genesis", func(t *testing.T) {
		tree := cashupool.NewIMT(imtD)
		k := imtKFromTag("imt-a")
		low, lowIdx, lowPath := tree.NonMembership(k)

		// Sanity: the in-script root must match the off-chain reference.
		root := cashupool.RecomputeRoot(imtD, lowIdx, low.Hash(), lowPath)
		require.Equal(t, tree.Root(), root)

		script := buildIMTNonMembershipScript(imtD, tree.Root())
		w := imtNonMembershipWitness(low, lowIdx, lowPath, k)
		require.NoError(t, runArkadeScript(t, script, w))
	})

	t.Run("valid non-membership with occupied predecessor", func(t *testing.T) {
		tree := cashupool.NewIMT(imtD)
		// Insert a couple of leaves so the predecessor is a real leaf.
		for _, tag := range []string{"imt-seed-1", "imt-seed-2"} {
			kk := imtKFromTag(tag)
			low, lowIdx, lowPath := tree.NonMembership(kk)
			tree.Insert(kk, low, lowIdx, lowPath)
		}
		k := imtKFromTag("imt-a")
		low, lowIdx, lowPath := tree.NonMembership(k)

		script := buildIMTNonMembershipScript(imtD, tree.Root())
		w := imtNonMembershipWitness(low, lowIdx, lowPath, k)
		require.NoError(t, runArkadeScript(t, script, w))
	})

	t.Run("tampered lowPath sibling fails", func(t *testing.T) {
		tree := cashupool.NewIMT(imtD)
		k := imtKFromTag("imt-a")
		low, lowIdx, lowPath := tree.NonMembership(k)

		bad := make([][]byte, len(lowPath))
		copy(bad, lowPath)
		tampered := append([]byte(nil), bad[0]...)
		tampered[0] ^= 0x01
		bad[0] = tampered

		script := buildIMTNonMembershipScript(imtD, tree.Root())
		w := imtNonMembershipWitness(low, lowIdx, bad, k)
		require.Error(t, runArkadeScript(t, script, w))
	})

	t.Run("k outside proven low range fails", func(t *testing.T) {
		// Insert two leaves, prove non-membership of a key k1, then reuse that
		// low proof for a key k2 that is NOT bracketed by low (k2 < low.Value).
		tree := cashupool.NewIMT(imtD)
		seeds := []string{"imt-seed-1", "imt-seed-2"}
		for _, tag := range seeds {
			kk := imtKFromTag(tag)
			low, lowIdx, lowPath := tree.NonMembership(kk)
			tree.Insert(kk, low, lowIdx, lowPath)
		}

		// Find a high key whose low predecessor is an occupied (non-sentinel)
		// leaf, so that a key smaller than low.Value is outside its range.
		var low cashupool.Leaf
		var lowIdx uint32
		var lowPath [][]byte
		for _, tag := range []string{"imt-hi-1", "imt-hi-2", "imt-hi-3", "imt-hi-4"} {
			k1 := imtKFromTag(tag)
			low, lowIdx, lowPath = tree.NonMembership(k1)
			if low.Value.Sign() != 0 {
				break
			}
		}
		require.NotZero(t, low.Value.Sign(), "need an occupied predecessor")

		// k2 < low.Value: not bracketed by low, so the range check must fail.
		k2 := new(big.Int).Sub(low.Value, big.NewInt(1))

		script := buildIMTNonMembershipScript(imtD, tree.Root())
		w := imtNonMembershipWitness(low, lowIdx, lowPath, k2)
		require.Error(t, runArkadeScript(t, script, w))
	})
}
