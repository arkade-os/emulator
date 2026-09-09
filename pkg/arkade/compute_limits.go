package arkade

import (
	"fmt"
	"math"
	"sync"

	"github.com/btcsuite/btcd/txscript"
)

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
	// to its independent cap, the measured heavy-opcode aggregate is ~41 ms per
	// input on an Apple M4 Pro. That is looser than the ~24 ms grouped design,
	// but keeps the policy easy to read, configure, and reason about for now.
	return ComputeLimits{
		// Schnorr-class signature verification, ~84 µs each.
		OP_CHECKSIG:          50,
		OP_CHECKSIGVERIFY:    50,
		OP_CHECKSIGADD:       50,
		OP_CHECKSIGFROMSTACK: 50,
		// Elliptic-curve point operations.
		OP_ECADD:                1000, // ~3.7 µs
		OP_ECMUL:                50,   // ~84 µs
		OP_ECMULSCALARVERIFY:    50,   // ~84 µs
		OP_TWEAKVERIFY:          50,   // ~84 µs
		OP_ECPAIRING:            2,    // ~2.04 ms at the 16-pair cap
		OP_MODEXP:               64,   // ~60 µs at the 64-byte operand cap
		OP_INSPECTINTENTMESSAGE: 16,   // ~266 µs at the 1 MiB request ceiling
	}
}

// requestInputBudget is how many inputs' worth of per-input limits a single
// request may spend in aggregate. The per-input caps reset for every input, so
// without a request-wide budget an attacker multiplies the cost of the heavy
// opcodes by the number of inputs it supplies, each input individually within
// its limits. Four inputs' worth bounds the measured heavy-opcode aggregate of
// a whole request at ~165 ms on an Apple M4 Pro while leaving ample headroom
// for legitimate multi-input transactions, whose inputs each spend a small
// fraction of the per-input caps.
const requestInputBudget = 4

// AggregateComputeLimits returns the per-request caps matching the per-input
// caps in c, that is c scaled by requestInputBudget. Callers running with
// configured per-input limits should derive their request budget from the same
// table so that a single input can never exhaust the request.
func AggregateComputeLimits(c ComputeLimits) ComputeLimits {
	limits := cloneComputeLimits(c)
	for op, limit := range limits {
		// A configured limit may be arbitrarily large; never wrap around.
		if limit > math.MaxInt/requestInputBudget {
			limits[op] = math.MaxInt
			continue
		}
		limits[op] = limit * requestInputBudget
	}
	return limits
}

// DefaultAggregateComputeLimits returns the canonical per-request execution
// caps: the per-input caps of DefaultComputeLimits scaled by
// requestInputBudget. It returns a fresh map so callers may modify their copy
// without affecting the engine default.
func DefaultAggregateComputeLimits() ComputeLimits {
	return AggregateComputeLimits(DefaultComputeLimits())
}

// ComputeBudget is the request-wide compute brake. Unlike the per-input
// ComputeLimits, which reset with every input's engine, a ComputeBudget is
// shared by the engines of every input of a single request (all the inputs of
// one PSBT), so the total work an attacker can force does not grow with the
// number of inputs it supplies.
//
// A budget is created per request and passed to each execution with
// WithComputeBudget. It is safe for concurrent use.
type ComputeBudget struct {
	mtx      sync.Mutex
	limits   ComputeLimits
	opCounts map[byte]int
}

// NewComputeBudget returns a request-wide budget carrying the canonical
// aggregate caps of DefaultAggregateComputeLimits.
func NewComputeBudget() *ComputeBudget {
	return NewComputeBudgetWithLimits(DefaultAggregateComputeLimits())
}

// NewComputeBudgetWithLimits returns a request-wide budget with exactly the
// caps in c. Opcodes absent from c are unlimited in aggregate.
func NewComputeBudgetWithLimits(c ComputeLimits) *ComputeBudget {
	return &ComputeBudget{
		limits:   cloneComputeLimits(c),
		opCounts: make(map[byte]int),
	}
}

// WithComputeBudget shares the request-wide compute budget with this execution.
// The same budget must be passed to every input of the request for the
// aggregate cap to hold. A nil budget means no aggregate accounting.
func WithComputeBudget(b *ComputeBudget) ExecuteOption {
	return func(engine *Engine) {
		engine.budget = b
	}
}

// charge counts one execution of op against the request-wide budget and returns
// an error once op exceeds its aggregate limit. A nil budget, and opcodes with
// no aggregate limit, are never charged.
func (b *ComputeBudget) charge(op byte) error {
	if b == nil {
		return nil
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	limit, ok := b.limits[op]
	if !ok {
		return nil
	}
	if b.opCounts == nil {
		b.opCounts = make(map[byte]int)
	}
	b.opCounts[op]++
	if b.opCounts[op] > limit {
		return scriptError(txscript.ErrScriptTooBig,
			fmt.Sprintf("opcode %s exceeded request execution limit of %d",
				opcodeArray[op].name, limit))
	}
	return nil
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
