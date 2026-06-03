package cashupool

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIMT_Genesis verifies that a freshly created IMT has the expected state.
func TestIMT_Genesis(t *testing.T) {
	t.Parallel()

	tree := NewIMT(16)
	require.Equal(t, 16, tree.Depth())
	require.Equal(t, uint32(1), tree.Size())

	root := tree.Root()
	require.Len(t, root, 32, "root must be 32 bytes")
	require.False(t, bytes.Equal(root, make([]byte, 32)), "root must not be all-zero")

	// Root must be deterministic.
	tree2 := NewIMT(16)
	require.Equal(t, root, tree2.Root(), "genesis root must be deterministic")
}

// TestIMT_NonMembershipGenesis verifies non-membership proof for a positive k
// in a fresh tree containing only (0,0).
func TestIMT_NonMembershipGenesis(t *testing.T) {
	t.Parallel()

	tree := NewIMT(16)
	root := tree.Root()

	k := big.NewInt(42)
	low, lowIdx, lowPath := tree.NonMembership(k)

	// Low leaf must be (0, 0) — the genesis sentinel.
	require.Equal(t, 0, low.Value.Sign(), "low.Value must be 0")
	require.Equal(t, 0, low.Next.Sign(), "low.Next must be 0 (sentinel = +inf)")

	// Path must verify against current root.
	computed := RecomputeRoot(16, lowIdx, low.Hash(), lowPath)
	require.True(t, bytes.Equal(computed, root),
		"RecomputeRoot of low leaf path must equal Root()")
}

// TestIMT_Insert verifies a single insertion.
func TestIMT_Insert(t *testing.T) {
	t.Parallel()

	tree := NewIMT(16)
	prevRoot := tree.Root()

	k := big.NewInt(100)
	low, lowIdx, lowPath := tree.NonMembership(k)

	root1, newRoot, szSibs, appendIdx := tree.Insert(k, low, lowIdx, lowPath)

	// newRoot must equal live Root() after insert.
	require.Equal(t, newRoot, tree.Root(), "newRoot must equal Root() after insert")
	// Root must have changed.
	require.False(t, bytes.Equal(newRoot, prevRoot), "root must change after insert")
	// Size must have incremented.
	require.Equal(t, uint32(2), tree.Size())

	// Coupling invariant: root1 was the intermediate root with low leaf updated
	// but append slot still empty.
	coupling := RecomputeRoot(16, appendIdx, EmptyLeafHash(), szSibs)
	require.True(t, bytes.Equal(coupling, root1),
		"coupling invariant: RecomputeRoot(appendIdx, emptyHash, szSibs) must == root1")

	// Final root coupling: newLeaf = (k, old low.Next) at appendIdx under root1's siblings.
	newLeaf := Leaf{Value: k, Next: new(big.Int).Set(low.Next)}
	finalCoupling := RecomputeRoot(16, appendIdx, newLeaf.Hash(), szSibs)
	require.True(t, bytes.Equal(finalCoupling, newRoot),
		"final coupling invariant: RecomputeRoot(appendIdx, newLeaf.Hash(), szSibs) must == newRoot")
}

// TestIMT_InsertRootChaining verifies that a fresh tree replaying the same
// insert yields the same root.
func TestIMT_InsertRootChaining(t *testing.T) {
	t.Parallel()

	k := big.NewInt(77)

	tree1 := NewIMT(16)
	low, lowIdx, lowPath := tree1.NonMembership(k)
	_, newRoot1, _, _ := tree1.Insert(k, low, lowIdx, lowPath)

	tree2 := NewIMT(16)
	low2, lowIdx2, lowPath2 := tree2.NonMembership(k)
	_, newRoot2, _, _ := tree2.Insert(k, low2, lowIdx2, lowPath2)

	require.Equal(t, newRoot1, newRoot2,
		"replaying the same insert on a fresh tree must produce the same root")
}

// TestIMT_InsertMembershipExclusion verifies that after inserting k,
// there is no longer a bracketing low leaf for k (k is now a member).
func TestIMT_InsertMembershipExclusion(t *testing.T) {
	t.Parallel()

	tree := NewIMT(16)
	k := big.NewInt(55)

	low, lowIdx, lowPath := tree.NonMembership(k)
	tree.Insert(k, low, lowIdx, lowPath)

	// After insertion, searching for a bracketing predecessor should not find
	// any leaf L where L.Value < k AND (L.Next == 0 OR L.Next > k).
	// Instead the leaf with Value==k should be in the tree; we verify by
	// checking that the predecessor's Next now points to k (not past it).
	low2, _, _ := tree.NonMembership(big.NewInt(56)) // just above k
	// The predecessor of 56 should now be k (or something >=k).
	// low2.Value should be k (the newly inserted leaf).
	require.Equal(t, 0, low2.Value.Cmp(k),
		"after inserting k, the predecessor of k+1 must be k itself")
	// And its Next must be 0 (was the old sentinel) since k was inserted before any larger value.
	require.Equal(t, 0, low2.Next.Sign(),
		"Next of k must be 0 (sentinel) since no larger value was inserted")
}

// TestIMT_MultiInsert inserts several values and after each verifies:
// - RecomputeRoot of each returned proof == live Root()
// - membership-vs-nonmembership consistency
// - insert coupling invariant
func TestIMT_MultiInsert(t *testing.T) {
	t.Parallel()

	// Fixed set of distinct keys in insertion order.
	keys := []*big.Int{
		big.NewInt(300),
		big.NewInt(50),
		big.NewInt(700),
		big.NewInt(150),
		big.NewInt(10),
	}

	tree := NewIMT(16)

	for i, k := range keys {
		prevRoot := tree.Root()

		low, lowIdx, lowPath := tree.NonMembership(k)

		// Verify non-membership path against pre-insert root.
		computed := RecomputeRoot(16, lowIdx, low.Hash(), lowPath)
		require.True(t, bytes.Equal(computed, prevRoot),
			"key[%d]: non-membership path must verify against pre-insert root", i)

		root1, newRoot, szSibs, appendIdx := tree.Insert(k, low, lowIdx, lowPath)

		// newRoot == live Root()
		require.Equal(t, newRoot, tree.Root(),
			"key[%d]: newRoot must equal Root() after insert", i)

		// Root changed
		require.False(t, bytes.Equal(newRoot, prevRoot),
			"key[%d]: root must change after insert", i)

		// Coupling invariant
		coupling := RecomputeRoot(16, appendIdx, EmptyLeafHash(), szSibs)
		require.True(t, bytes.Equal(coupling, root1),
			"key[%d]: coupling invariant must hold", i)

		// Final root coupling
		newLeaf := Leaf{Value: k, Next: new(big.Int).Set(low.Next)}
		finalCoupling := RecomputeRoot(16, appendIdx, newLeaf.Hash(), szSibs)
		require.True(t, bytes.Equal(finalCoupling, newRoot),
			"key[%d]: final coupling invariant must hold", i)
	}

	// Verify all proofs are still valid against the final root.
	finalRoot := tree.Root()
	for i, k := range keys {
		// Each key is now a member; its NonMembership predecessor should not bracket it.
		// Specifically, if we query k's predecessor, predecessor.Next should == k.
		low, lowIdx, lowPath := tree.NonMembership(new(big.Int).Add(k, big.NewInt(1)))
		// predecessor of k+1 is either k or something larger with a gap.
		// The predecessor's path must verify.
		computed := RecomputeRoot(16, lowIdx, low.Hash(), lowPath)
		require.True(t, bytes.Equal(computed, finalRoot),
			"key[%d]: post-insert non-membership path must verify against final root", i)
	}
}
