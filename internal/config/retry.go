package config

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// retryConfig/retryWithBackoff are a deliberate copy of the unexported helper
// in pkg/emulator (tx.go). That package is a separate module shipped as a
// library, so exporting its retry helper would make generic backoff plumbing
// part of the library's public API. Keeping a private copy here lets the
// library keep it unexported. The two callers also use different configs
// (arkd-connect vs finalize backoff), so they share only an implementation.

// retryConfig tunes retryWithBackoff: how many attempts ignore ctx
// cancellation, the initial/maximum delay, the growth multiplier, and the
// jitter fraction.
type retryConfig struct {
	MinAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       float64
}

// retryWithBackoff runs op until it succeeds, backing off between attempts with
// jitter. The first cfg.MinAttempts run regardless of ctx; after that a
// cancelled ctx aborts the loop. onErr, if set, is called after each failure.
func retryWithBackoff(
	ctx context.Context, cfg retryConfig, op func() error, onErr func(attempt int, err error),
) error {
	backoffDelay := cfg.InitialDelay
	for attempt := 1; ; attempt++ {
		err := op()
		if err == nil {
			return nil
		}
		if onErr != nil {
			onErr(attempt, err)
		}

		delay := applyJitter(backoffDelay, cfg.Jitter)
		backoffDelay = min(cfg.MaxDelay, backoffDelay*time.Duration(cfg.Multiplier))

		// try a minimum number of times before respecting ctx.Done
		if attempt < cfg.MinAttempts {
			time.Sleep(delay)
			continue
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled after attempt %d: %w", attempt, ctx.Err())
		case <-time.After(delay):
		}
	}
}

// applyJitter adds ±jitter randomness to a duration.
// with jitter = 0.2, d get + or - 20%
func applyJitter(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return d
	}
	if jitter >= 1.0 {
		jitter = 0.999
	}

	randomFactor := 2.0*rand.Float64() - 1.0 // [-1, +1] factor
	jitterFactor := 1.0 + jitter*randomFactor
	return time.Duration(float64(d) * jitterFactor)
}
