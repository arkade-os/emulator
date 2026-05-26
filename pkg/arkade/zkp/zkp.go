// Package zkp provides SNARK verification primitives used by OP_VERIFY_ZKP.
//
// The opcode dispatches to a registered Verifier based on a 1-byte zkp_type
// pulled from the script stack. This package owns the Type enum, the Verifier
// interface, and the dispatch registry. Concrete verifiers (Groth16, PLONK,
// future trustless variants) live in sibling files and register themselves at
// init time.
package zkp

import (
	"errors"
	"fmt"
)

// Type identifies a SNARK proof system. Allocated values match the type
// registry documented in `docs/specs/2026-05-01-arkade-asset-pool-v0-zkp.md`
// §1.2 and the introspector#77 issue body.
type Type byte

const (
	// TypeGroth16 — Groth16 over BLS12-381. Per-circuit trusted setup.
	// Smallest proofs (~200 B), fastest verification (3 pairings).
	TypeGroth16 Type = 0x01
	// TypePLONK — PLONK over BLS12-381 with KZG commitments. Universal
	// updatable trusted setup (one ceremony serves all circuits up to its
	// constraint cap). ~500 B proofs, ~5 pairings to verify.
	TypePLONK Type = 0x02
	// 0x03+ reserved for future systems (Halo 2, Plonky2, STARKs, Binius).
	// Currently out of scope: their proof sizes exceed practical witness
	// budgets (>10 KB) for current target use cases.
)

// String returns a human-readable name for the type. Used in error messages
// and disassembly output.
func (t Type) String() string {
	switch t {
	case TypeGroth16:
		return "Groth16"
	case TypePLONK:
		return "PLONK"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", byte(t))
	}
}

// Verifier verifies a single proof of the system it represents. Implementations
// must be deterministic, panic-free, and return a non-nil error on any
// validation failure (including malformed input).
//
// The byte arguments are passed verbatim from the script stack; each
// implementation owns the deserialization format. The canonical format used by
// the bundled Groth16 and PLONK verifiers is `gnark`'s standard binary
// marshaling — see groth16.go and plonk.go for the exact framing.
type Verifier interface {
	// Verify checks that proof is valid for vk and publicInputs. It returns
	// nil on success and a descriptive error on any failure (malformed
	// inputs, soundness rejection, unsupported variant, etc.).
	Verify(vk, publicInputs, proof []byte) error
}

// ErrUnknownType is returned when Verify is called with a Type that has no
// registered implementation. Distinct from a verifier returning an error
// during Verify — this means the dispatch table itself doesn't recognize the
// requested system.
var ErrUnknownType = errors.New("zkp: unknown or unregistered zkp_type")

// registry maps each registered Type to its Verifier. Populated at init time
// by sibling files (groth16.go, plonk.go).
var registry = map[Type]Verifier{}

// Register adds a Verifier for the given Type. Subsequent calls for the same
// Type replace the prior registration. Concrete verifier files call this from
// their init() to register themselves; tests may also override registrations
// to inject mocks.
func Register(t Type, v Verifier) {
	registry[t] = v
}

// Lookup returns the registered Verifier for t, or ErrUnknownType if none.
// Exposed so callers (e.g., the opcode handler) can distinguish "no verifier
// available" from "verifier rejected the proof."
func Lookup(t Type) (Verifier, error) {
	v, ok := registry[t]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownType, t)
	}
	return v, nil
}

// Verify dispatches to the registered Verifier for t and runs verification.
// Returns ErrUnknownType (or a wrap of it) if t isn't registered, otherwise
// returns whatever the Verifier returns (nil on success).
func Verify(t Type, vk, publicInputs, proof []byte) error {
	v, err := Lookup(t)
	if err != nil {
		return err
	}
	return v.Verify(vk, publicInputs, proof)
}

// IsRegistered reports whether t has a registered Verifier. Useful for
// configuration introspection (e.g., "what proof systems does this binary
// support?") without forcing a verification call.
func IsRegistered(t Type) bool {
	_, ok := registry[t]
	return ok
}
