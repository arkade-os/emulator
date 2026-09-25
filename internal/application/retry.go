package application

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

var arkdConnectRetryConfig = retryConfig{
	MinAttempts:  0,
	InitialDelay: 1 * time.Second,
	MaxDelay:     45 * time.Second,
	Multiplier:   2.0,
	Jitter:       0.2,
}

var finalizeRetryConfig = retryConfig{
	MinAttempts: 10,
	// absolute caps, enforced even when the caller passes a context without
	// deadline, so the signer can never be wedged by an unresponsive arkd
	MaxAttempts:  15,
	MaxElapsed:   2 * time.Minute,
	InitialDelay: 1 * time.Second,
	MaxDelay:     10 * time.Second,
	Multiplier:   2.0,
	Jitter:       0.2, // + or - 20% randomness
}

var indexerRetryConfig = finalizeRetryConfig

type retryConfig struct {
	MinAttempts  int
	MaxAttempts  int
	MaxElapsed   time.Duration
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       float64
}

// retryWithBackoff retries op with jittered backoff; the first MinAttempts
// ignore ctx cancellation.
func retryWithBackoff(
	ctx context.Context, cfg retryConfig, op func() error, onErr func(attempt int, err error),
) error {
	backoffDelay := cfg.InitialDelay
	deadline := time.Now().Add(cfg.MaxElapsed)
	for attempt := 1; ; attempt++ {
		err := op()
		if err == nil {
			return nil
		}
		if onErr != nil {
			onErr(attempt, err)
		}

		// absolute bounds, independent of the caller supplied context, so the
		// loop always returns even when ctx has no deadline
		if cfg.MaxAttempts > 0 && attempt >= cfg.MaxAttempts {
			return fmt.Errorf("retry exhausted after attempt %d: %w", attempt, err)
		}

		delay := applyJitter(backoffDelay, cfg.Jitter)
		// float math: time.Duration(1.5) would truncate to 1
		backoffDelay = min(cfg.MaxDelay, time.Duration(float64(backoffDelay)*cfg.Multiplier))

		if cfg.MaxElapsed > 0 && !time.Now().Add(delay).Before(deadline) {
			return fmt.Errorf("retry budget exhausted after attempt %d: %w", attempt, err)
		}

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
