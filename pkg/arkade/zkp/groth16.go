// Groth16 verifier (BLS12-381) using consensys/gnark.
//
// Wire format (matches gnark's standard binary marshaling):
//   - vk: groth16.VerifyingKey.WriteTo bytes (BLS12-381 form)
//   - publicInputs: witness.Witness.WriteTo bytes for the public-only witness
//   - proof: groth16.Proof.WriteTo bytes (BLS12-381 form)
//
// This is a thin adapter around gnark; soundness, side-channel resistance, and
// curve correctness are the library's responsibility.
package zkp

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

type groth16Verifier struct{}

// Verify checks a Groth16 proof on BLS12-381.
func (groth16Verifier) Verify(vkBytes, publicInputsBytes, proofBytes []byte) error {
	if len(vkBytes) == 0 {
		return fmt.Errorf("groth16: empty verifying key")
	}
	if len(proofBytes) == 0 {
		return fmt.Errorf("groth16: empty proof")
	}

	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return fmt.Errorf("groth16: parse vk: %w", err)
	}

	proof := groth16.NewProof(ecc.BLS12_381)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("groth16: parse proof: %w", err)
	}

	pubW, err := witness.New(ecc.BLS12_381.ScalarField())
	if err != nil {
		return fmt.Errorf("groth16: init witness: %w", err)
	}
	if _, err := pubW.ReadFrom(bytes.NewReader(publicInputsBytes)); err != nil {
		return fmt.Errorf("groth16: parse public inputs: %w", err)
	}

	if err := groth16.Verify(proof, vk, pubW); err != nil {
		return fmt.Errorf("groth16: verify failed: %w", err)
	}
	return nil
}

func init() {
	Register(TypeGroth16, groth16Verifier{})
}
