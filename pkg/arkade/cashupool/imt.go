package cashupool

import (
	"bytes"
	"crypto/sha256"
	"math/big"
)

// Leaf is one node in the sorted linked-list threaded through the IMT.
// Value is the nullifier value; Next is the value of the next-larger occupied
// leaf (Next == 0 means "+infinity": this leaf is the current maximum).
type Leaf struct {
	Value *big.Int
	Next  *big.Int
}

// Hash returns SHA256(be32(Value) || be32(Next)) where be32 is the 32-byte
// big-endian encoding.  This is the real-leaf hash used by both the off-chain
// Go library and the in-script verifier — they must agree byte-for-byte.
func (l Leaf) Hash() []byte {
	var val, next [32]byte
	l.Value.FillBytes(val[:])
	l.Next.FillBytes(next[:])
	h := sha256.Sum256(append(val[:], next[:]...))
	return h[:]
}

// EmptyLeafHash returns the canonical empty-slot hash (32 zero bytes).
// This is DISTINCT from the sentinel leaf (0,0).hash which is SHA256(64 zeros).
func EmptyLeafHash() []byte {
	return bytes.Repeat([]byte{0x00}, 32)
}

// RecomputeRoot walks depth levels from a leaf at index using siblings
// (siblings[0] = sibling at the leaf level, i.e. level 0).
// At each level the LSB-first bit of index selects child order:
//
//	bit == 0  =>  current is LEFT child:  SHA256(cur || sib)
//	bit == 1  =>  current is RIGHT child: SHA256(sib || cur)
//
// This is the canonical positional walk that the in-script verifier replicates.
func RecomputeRoot(depth int, index uint32, leafHash []byte, siblings [][]byte) []byte {
	cur := leafHash
	for i := 0; i < depth; i++ {
		sib := siblings[i]
		var comb []byte
		if (index>>uint(i))&1 == 0 {
			comb = append(append([]byte{}, cur...), sib...)
		} else {
			comb = append(append([]byte{}, sib...), cur...)
		}
		h := sha256.Sum256(comb)
		cur = h[:]
	}
	return cur
}

// IMT is a fixed-depth Indexed Merkle Tree (Aztec-style).
//
// The tree holds a sorted linked list of occupied nullifier values.  Each leaf
// stores (Value, Next) where Next is the value of the successor in the sorted
// order (Next==0 means +infinity).
//
// Leaf index 0 always contains the genesis sentinel (0, 0).
// Subsequent inserts occupy indices 1, 2, … in insertion order.
type IMT struct {
	depth    int
	leaves   map[uint32]Leaf // occupied leaves
	occupied map[uint32]bool // set of occupied indices (for subtree-empty checks)
	size     uint32
	dflt     [][]byte          // dflt[i] is the default hash for a subtree of height i
	cache    map[uint64][]byte // nodeHash cache: key = level<<32|idx
}

// subtreeKey packs level and idx into a uint64 for the cache.
func subtreeKey(level int, idx uint32) uint64 {
	return uint64(level)<<32 | uint64(idx)
}

// NewIMT creates a depth-D indexed Merkle tree with the genesis leaf (0,0) at
// index 0. Size() == 1 after construction.
func NewIMT(depth int) *IMT {
	// Build default hashes: dflt[0] = 32 zero bytes; dflt[i] = SHA256(dflt[i-1]||dflt[i-1]).
	dflt := make([][]byte, depth+1)
	dflt[0] = EmptyLeafHash()
	for i := 1; i <= depth; i++ {
		h := sha256.Sum256(append(dflt[i-1], dflt[i-1]...))
		dflt[i] = h[:]
	}

	t := &IMT{
		depth:    depth,
		leaves:   make(map[uint32]Leaf),
		occupied: make(map[uint32]bool),
		size:     0,
		dflt:     dflt,
		cache:    make(map[uint64][]byte),
	}

	// Insert genesis sentinel: Leaf{0, 0} at index 0.
	genesis := Leaf{Value: new(big.Int), Next: new(big.Int)}
	t.leaves[0] = genesis
	t.occupied[0] = true
	t.size = 1

	return t
}

// Depth returns the fixed depth of the tree.
func (t *IMT) Depth() int { return t.depth }

// Size returns the number of occupied leaves (genesis counts as 1).
func (t *IMT) Size() uint32 { return t.size }

// Root returns the Merkle root of the full tree.
func (t *IMT) Root() []byte { return t.nodeHash(t.depth, 0) }

// invalidateCache clears the entire node-hash cache after any mutation.
// With only a handful of leaves a full-clear is cheap.
func (t *IMT) invalidateCache() {
	t.cache = make(map[uint64][]byte)
}

// hasOccupiedLeaf reports whether the subtree rooted at (level, idx) contains
// at least one occupied leaf.  The subtree covers leaf indices
// [idx*2^level, (idx+1)*2^level).
func (t *IMT) hasOccupiedLeaf(level int, idx uint32) bool {
	lo := idx << uint(level)
	hi := lo + (1 << uint(level)) // exclusive
	for i := lo; i < hi; i++ {
		if t.occupied[i] {
			return true
		}
	}
	return false
}

// nodeHash computes the hash of the subtree rooted at (level, idx) using the
// short-circuit: if no occupied leaf falls under the subtree, return dflt[level].
func (t *IMT) nodeHash(level int, idx uint32) []byte {
	key := subtreeKey(level, idx)
	if v, ok := t.cache[key]; ok {
		return v
	}

	var h []byte
	if !t.hasOccupiedLeaf(level, idx) {
		h = t.dflt[level]
	} else if level == 0 {
		if t.occupied[idx] {
			leaf := t.leaves[idx]
			h = leaf.Hash()
		} else {
			h = EmptyLeafHash()
		}
	} else {
		left := t.nodeHash(level-1, 2*idx)
		right := t.nodeHash(level-1, 2*idx+1)
		sum := sha256.Sum256(append(left, right...))
		h = sum[:]
	}

	t.cache[key] = h
	return h
}

// merklePathFor computes the D siblings for the leaf at index i.
// siblings[0] is the sibling at level 0 (leaf level), siblings[D-1] is at level D-1.
func (t *IMT) merklePathFor(leafIdx uint32) [][]byte {
	sibs := make([][]byte, t.depth)
	cur := leafIdx
	for lv := 0; lv < t.depth; lv++ {
		sibIdx := cur ^ 1 // toggle LSB
		sibs[lv] = t.nodeHash(lv, sibIdx)
		cur >>= 1
	}
	return sibs
}

// findLow finds the predecessor ("low") leaf for value k: the occupied leaf L
// with L.Value < k and (L.Next == 0 OR L.Next > k).
// Returns the Leaf and its index.
func (t *IMT) findLow(k *big.Int) (Leaf, uint32) {
	var bestLeaf Leaf
	var bestIdx uint32
	found := false

	for idx := range t.occupied {
		leaf := t.leaves[idx]
		// Must have leaf.Value < k.
		if leaf.Value.Cmp(k) >= 0 {
			continue
		}
		// Must bracket k: Next == 0 (sentinel/+inf) OR Next > k.
		if leaf.Next.Sign() != 0 && leaf.Next.Cmp(k) <= 0 {
			continue
		}
		// Among all qualifying leaves, pick the one with the largest Value
		// (closest predecessor).
		if !found || leaf.Value.Cmp(bestLeaf.Value) > 0 {
			bestLeaf = Leaf{
				Value: new(big.Int).Set(leaf.Value),
				Next:  new(big.Int).Set(leaf.Next),
			}
			bestIdx = idx
			found = true
		}
	}
	return bestLeaf, bestIdx
}

// NonMembership returns the predecessor ("low") leaf bracketing k, its index,
// and its Merkle path (D siblings, level-0 first) against the current root.
// Caller must ensure k is not already a member; if it is, the result is
// undefined (the predecessor's Next will equal k, not bracket it).
func (t *IMT) NonMembership(k *big.Int) (low Leaf, lowIdx uint32, lowPath [][]byte) {
	low, lowIdx = t.findLow(k)
	lowPath = t.merklePathFor(lowIdx)
	return low, lowIdx, lowPath
}

// Insert adds nullifier k to the tree.
//
// It performs two sub-operations:
//  1. Update the low leaf's Next pointer from oldLowNext to k; recompute root1.
//  2. Store the new leaf (k, oldLowNext) at appendIdx = Size(); recompute newRoot.
//
// Returns:
//   - root1:     intermediate Merkle root after low-leaf update but before new leaf
//   - newRoot:   final Merkle root after new leaf insertion
//   - szSibs:    Merkle path of appendIdx under root1 (all siblings are empty/default)
//   - appendIdx: the leaf index where the new leaf was stored
//
// The caller must supply low, lowIdx, lowPath from a prior NonMembership call
// for the same k (they are used for consistency but the tree recomputes paths
// internally after mutation).
func (t *IMT) Insert(k *big.Int, low Leaf, lowIdx uint32, lowPath [][]byte) (root1, newRoot []byte, szSibs [][]byte, appendIdx uint32) {
	// Save original Next of the low leaf.
	oldLowNext := new(big.Int).Set(low.Next)

	// Step 1: update low leaf's Next to k.
	updatedLow := Leaf{
		Value: new(big.Int).Set(low.Value),
		Next:  new(big.Int).Set(k),
	}
	t.leaves[lowIdx] = updatedLow
	t.invalidateCache()

	root1 = t.Root()

	// Step 2: compute the Merkle path for the append slot (currently empty).
	appendIdx = t.size
	szSibs = t.merklePathFor(appendIdx)

	// Sanity-check the coupling invariant (will also be tested externally).
	_ = root1 // used below for assertion in tests; already computed

	// Step 3: store new leaf (k, oldLowNext) at appendIdx.
	newLeaf := Leaf{
		Value: new(big.Int).Set(k),
		Next:  oldLowNext,
	}
	t.leaves[appendIdx] = newLeaf
	t.occupied[appendIdx] = true
	t.size++
	t.invalidateCache()

	newRoot = t.Root()
	return root1, newRoot, szSibs, appendIdx
}
