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
func DefaultComputeLimits() ComputeLimits {
	// Aggregate-cost note: this table is deliberately a simple per-opcode
	// lookup, not a grouped or weighted budget. If every listed opcode is pushed
	// to its independent cap, the measured heavy-opcode aggregate is ~37 ms per
	// input on an Apple M4 Pro. That is looser than the ~24 ms grouped design,
	// but keeps the policy easy to read, configure, and reason about for now.
	return ComputeLimits{
		// Signature verification opcodes. Each execution may perform Schnorr
		// (secp256k1, ~84 µs), secp256k1 ECDSA (same two-scalar-mult class),
		// or P-256 ECDSA (~51 µs, measured on Apple M4 Pro — Go's native P-256
		// assembly). The ~84 µs Schnorr class bounds per-op cost; 50 × ~84 µs
		// ≈ 4.2 ms per opcode stays within the ~37 ms/input budget.
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

func cloneComputeLimits(c ComputeLimits) ComputeLimits {
	if c == nil {
		return nil
	}
	clone := make(ComputeLimits, len(c))
	for op, limit := range c {
		clone[op] = limit
	}
	return clone
}
