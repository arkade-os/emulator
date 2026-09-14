package config

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRetry covers this package's copy of the backoff helper. pkg/emulator keeps
// an identical unexported copy (see retry.go), and the two must stay in sync, so
// the behavior both callers rely on is pinned here rather than left to the
// library's own tests.
func TestRetry(t *testing.T) {
	t.Run("succeeds without retrying", func(t *testing.T) {
		calls := 0
		err := retryWithBackoff(t.Context(), retryConfig{}, func() error {
			calls++
			return nil
		}, nil)
		require.NoError(t, err)
		require.Equal(t, 1, calls)
	})

	t.Run("reports every failed attempt", func(t *testing.T) {
		cfg := retryConfig{
			MinAttempts:  3,
			InitialDelay: time.Millisecond,
			MaxDelay:     time.Millisecond,
			Multiplier:   1,
		}
		calls := 0
		var reported []int
		err := retryWithBackoff(t.Context(), cfg,
			func() error {
				calls++
				if calls < 3 {
					return fmt.Errorf("attempt %d", calls)
				}
				return nil
			},
			func(attempt int, _ error) { reported = append(reported, attempt) },
		)
		require.NoError(t, err)
		require.Equal(t, 3, calls)
		require.Equal(t, []int{1, 2}, reported)
	})

	t.Run("runs MinAttempts before respecting ctx", func(t *testing.T) {
		// MaxDelay must be set: min(cfg.MaxDelay, ...) clamps every delay to zero
		// when it is left at the zero value, and the resulting time.After(0) then
		// races the cancelled ctx in the select, letting a fourth attempt through.
		cfg := retryConfig{
			MinAttempts:  3,
			InitialDelay: 50 * time.Millisecond,
			MaxDelay:     50 * time.Millisecond,
			Multiplier:   1,
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		calls := 0
		err := retryWithBackoff(ctx, cfg, func() error {
			calls++
			return fmt.Errorf("boom")
		}, nil)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 3, calls)
	})

	t.Run("arkd connect config gives up on the first cancelled attempt", func(t *testing.T) {
		// arkdConnectRetryConfig sets MinAttempts 0, so a cancelled ctx must stop
		// the arkd-readiness loop right away instead of sleeping through a minimum
		// attempt count while the process is shutting down.
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		calls := 0
		err := retryWithBackoff(ctx, arkdConnectRetryConfig, func() error {
			calls++
			return fmt.Errorf("arkd not ready")
		}, nil)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 1, calls)
	})

	t.Run("grows the delay by a fractional multiplier", func(t *testing.T) {
		// time.Duration(cfg.Multiplier) truncates 1.5 to 1 and holds the delay
		// flat, so assert the growth really compounds: sleeps of 100ms then 150ms
		// cannot finish sooner than 250ms, while the truncating form takes 200ms.
		cfg := retryConfig{
			MinAttempts:  3,
			InitialDelay: 100 * time.Millisecond,
			MaxDelay:     time.Minute,
			Multiplier:   1.5,
		}
		calls := 0
		start := time.Now()
		err := retryWithBackoff(t.Context(), cfg, func() error {
			calls++
			if calls < 3 {
				return fmt.Errorf("attempt %d", calls)
			}
			return nil
		}, nil)
		require.NoError(t, err)
		require.Equal(t, 3, calls)
		require.GreaterOrEqual(t, time.Since(start), 250*time.Millisecond)
	})

	t.Run("clamps the delay to MaxDelay", func(t *testing.T) {
		// the multiplier would take the second delay to a full second without the
		// clamp, so three attempts must still finish well inside it.
		cfg := retryConfig{
			MinAttempts:  4,
			InitialDelay: 10 * time.Millisecond,
			MaxDelay:     15 * time.Millisecond,
			Multiplier:   100,
		}
		calls := 0
		start := time.Now()
		err := retryWithBackoff(t.Context(), cfg, func() error {
			calls++
			if calls < 4 {
				return fmt.Errorf("attempt %d", calls)
			}
			return nil
		}, nil)
		require.NoError(t, err)
		require.Equal(t, 4, calls)
		require.Less(t, time.Since(start), time.Second)
	})

	t.Run("jitter", func(t *testing.T) {
		t.Run("zero or negative leaves the duration unchanged", func(t *testing.T) {
			require.Equal(t, time.Second, applyJitter(time.Second, 0))
			require.Equal(t, time.Second, applyJitter(time.Second, -0.5))
		})
		t.Run("stays within the requested fraction", func(t *testing.T) {
			for range 100 {
				got := applyJitter(time.Second, 0.2)
				require.GreaterOrEqual(t, got, 800*time.Millisecond)
				require.LessOrEqual(t, got, 1200*time.Millisecond)
			}
		})
		t.Run("a fraction at or above one stays positive", func(t *testing.T) {
			// jitter is clamped to 0.999, so the delay never reaches zero and the
			// retry loop cannot spin without sleeping.
			for range 100 {
				got := applyJitter(time.Second, 5)
				require.Positive(t, got)
				require.LessOrEqual(t, got, 2*time.Second)
			}
		})
	})
}
