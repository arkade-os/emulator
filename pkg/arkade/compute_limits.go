package arkade

import "fmt"

// OpcodeGroup is a named set of opcodes that share a single per-input
// execution-count limit. Each time any member opcode executes, the group's
// remaining count is decremented; execution fails once a group would go below
// zero.
type OpcodeGroup struct {
	Name    string
	Opcodes []byte
	Limit   int
}

// ComputeLimits is the declarative compute brake: a set of opcode groups, each
// with its own per-input execution-count cap. Opcodes that belong to no group
// are unlimited, matching tapscript's lack of an op-count limit for the cheap
// opcodes whose per-call cost is negligible.
type ComputeLimits struct {
	Groups []OpcodeGroup
}

// compiledComputeLimits is the hot-path form of a ComputeLimits: a constant-time
// opcode→group lookup plus per-group metadata addressed by group index.
type compiledComputeLimits struct {
	groupOf [256]int // opcode byte -> group index, -1 if ungrouped
	limits  []int    // per-group execution-count limit
	names   []string // per-group name, for error messages
}

// Validate reports whether the configuration is well formed: every limit must
// be non-negative and no opcode may appear in more than one group.
func (c ComputeLimits) Validate() error {
	var seen [256]bool
	for _, g := range c.Groups {
		if g.Limit < 0 {
			return fmt.Errorf("compute limits: group %q has negative limit %d",
				g.Name, g.Limit)
		}
		for _, op := range g.Opcodes {
			if seen[op] {
				return fmt.Errorf("compute limits: opcode 0x%02x appears in "+
					"more than one group", op)
			}
			seen[op] = true
		}
	}
	return nil
}

// compile builds the lookup form. It panics on an invalid configuration: a
// malformed ComputeLimits is always a programmer error, never runtime input.
// Use Validate to check a configuration without panicking.
func (c ComputeLimits) compile() *compiledComputeLimits {
	if err := c.Validate(); err != nil {
		panic(err)
	}
	cl := &compiledComputeLimits{
		limits: make([]int, len(c.Groups)),
		names:  make([]string, len(c.Groups)),
	}
	for i := range cl.groupOf {
		cl.groupOf[i] = -1
	}
	for gi, g := range c.Groups {
		cl.limits[gi] = g.Limit
		cl.names[gi] = g.Name
		for _, op := range g.Opcodes {
			cl.groupOf[op] = gi
		}
	}
	return cl
}

// DefaultComputeLimits returns the canonical per-input compute brake. It is a
// function rather than an exported variable so the production policy cannot be
// mutated through a shared slice-backed global: each call builds fresh slices,
// so callers may freely modify the returned value (e.g. to relax a limit for an
// experiment) without affecting the engine default.
//
// Limits are calibrated from the issue #81 benchmark table (Apple Silicon,
// single-threaded) so the worst-case per-input CPU summed across all groups —
// Σ(limit × worst-call-cost) — is roughly 20-25 ms, well below the multi-second
// adversarial cases an unbounded script could reach.
func DefaultComputeLimits() ComputeLimits {
	return ComputeLimits{Groups: []OpcodeGroup{
		// Schnorr verify ≈ 84 µs/call; 50 → ≈ 4.2 ms.
		{Name: "sig", Limit: 50, Opcodes: []byte{
			OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD,
		}},
		// ≈ 3.7 µs/call; 1000 → ≈ 3.7 ms.
		{Name: "ec-add", Limit: 1000, Opcodes: []byte{OP_ECADD}},
		// ≈ 84 µs/call; 50 → ≈ 4.2 ms.
		{Name: "ec-scalarmul", Limit: 50, Opcodes: []byte{
			OP_ECMUL, OP_ECMULSCALARVERIFY, OP_TWEAKVERIFY,
		}},
		// CHECKSIGFROMSTACK ≈ 84 µs/call; 50 → ≈ 4.2 ms.
		{Name: "ec-sig", Limit: 50, Opcodes: []byte{OP_CHECKSIGFROMSTACK}},
		// ≈ 2.04 ms/call at the 16-pair cap; 2 → ≈ 4.1 ms.
		{Name: "ec-pairing", Limit: 2, Opcodes: []byte{OP_ECPAIRING}},
		// ≈ 60 µs/call at the 64-byte operand cap; 64 → ≈ 3.8 ms.
		{Name: "modexp", Limit: 64, Opcodes: []byte{OP_MODEXP}},
	}}
}

// defaultCompiledLimits is the compiled canonical brake, built once at package
// init and shared read-only by every engine that does not override it via
// WithComputeLimits.
var defaultCompiledLimits = DefaultComputeLimits().compile()
