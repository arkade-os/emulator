package cashupool

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHashToCurve exercises the Cashu NUT-00 hash_to_curve primitive.
func TestHashToCurve(t *testing.T) {
	t.Parallel()

	t.Run("determinism", func(t *testing.T) {
		t.Parallel()
		secret := []byte("test-secret")
		Y1, c1 := HashToCurve(secret)
		Y2, c2 := HashToCurve(secret)
		require.Equal(t, c1, c2, "counter must be stable across calls")
		require.Equal(
			t,
			Y1.SerializeCompressed(),
			Y2.SerializeCompressed(),
			"point must be stable across calls",
		)
	})

	t.Run("even_y", func(t *testing.T) {
		t.Parallel()
		// NUT-00 lift_x always selects the even-Y solution (0x02 prefix).
		Y, _ := HashToCurve([]byte("even-y-check"))
		compressed := Y.SerializeCompressed()
		require.Equal(t, byte(0x02), compressed[0], "compressed point must have 0x02 prefix (even Y)")
	})

	t.Run("on_curve", func(t *testing.T) {
		t.Parallel()
		Y, _ := HashToCurve([]byte("on-curve-check"))
		require.True(t, Y.IsOnCurve(), "returned point must lie on secp256k1")
	})

	t.Run("different_secrets_give_different_points", func(t *testing.T) {
		t.Parallel()
		Y1, _ := HashToCurve([]byte("secret-alpha"))
		Y2, _ := HashToCurve([]byte("secret-beta"))
		require.NotEqual(
			t,
			Y1.SerializeCompressed(),
			Y2.SerializeCompressed(),
			"distinct secrets must produce distinct points",
		)
	})

	t.Run("grind_counter_zero", func(t *testing.T) {
		t.Parallel()
		secret := GrindSecret("x", 0)
		_, c := HashToCurve(secret)
		require.Equal(t, uint32(0), c, "GrindSecret(\"x\", 0) must yield a secret with counter == 0")
	})

	t.Run("grind_counter_bounded", func(t *testing.T) {
		t.Parallel()
		secret := GrindSecret("y", 3)
		_, c := HashToCurve(secret)
		require.LessOrEqual(t, c, uint32(3), "GrindSecret(\"y\", 3) must yield a secret with counter <= 3")
	})
}
