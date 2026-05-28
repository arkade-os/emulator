package arkade

import "fmt"

// ComputeLimits maps an opcode to the maximum number of times it may execute
// during a single input's script evaluation. Opcodes absent from the map are
// unlimited, matching tapscript's lack of an op-count limit for the cheap
// opcodes whose per-call cost is negligible.
type ComputeLimits map[byte]int

// Validate reports whether every configured limit is non-negative.
func (c ComputeLimits) Validate() error {
	for op, limit := range c {
		if limit < 0 {
			return fmt.Errorf("compute limit for %s is negative: %d",
				opcodeArray[op].name, limit)
		}
	}
	return nil
}

// DefaultComputeLimits returns the canonical per-input execution caps for the
// heavy opcodes. It returns a fresh map so callers may modify their copy
// without affecting the engine default.
//
// Limits are calibrated from the issue #81 benchmark table (Apple Silicon,
// single-threaded) to bound worst-case per-input CPU well below the
// multi-second cases an unbounded script could reach.
func DefaultComputeLimits() ComputeLimits {
	return ComputeLimits{
		// Schnorr-class signature verification, ~84 µs each.
		OP_CHECKSIG:          50,
		OP_CHECKSIGVERIFY:    50,
		OP_CHECKSIGADD:       50,
		OP_CHECKSIGFROMSTACK: 50,
		// Elliptic-curve point operations.
		OP_ECADD:             1000, // ~3.7 µs
		OP_ECMUL:             50,   // ~84 µs
		OP_ECMULSCALARVERIFY: 50,   // ~84 µs
		OP_TWEAKVERIFY:       50,   // ~84 µs
		OP_ECPAIRING:         2,    // ~2.04 ms at the 16-pair cap
		OP_MODEXP:            64,   // ~60 µs at the 64-byte operand cap
	}
}

// defaultComputeLimits is the shared, read-only default applied by NewEngine to
// every engine that does not override it via WithComputeLimits.
var defaultComputeLimits = DefaultComputeLimits()
