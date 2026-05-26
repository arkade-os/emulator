// PLONK verifier (BLS12-381 + KZG) using consensys/gnark.
//
// Wire format (matches gnark's standard binary marshaling):
//   - vk: plonk.VerifyingKey.WriteTo bytes (BLS12-381 form)
//   - publicInputs: witness.Witness.WriteTo bytes for the public-only witness
//   - proof: plonk.Proof.WriteTo bytes (BLS12-381 form)
package zkp

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
)

type plonkVerifier struct{}

// Verify checks a PLONK proof on BLS12-381 with KZG commitments.
func (plonkVerifier) Verify(vkBytes, publicInputsBytes, proofBytes []byte) error {
	if len(vkBytes) == 0 {
		return fmt.Errorf("plonk: empty verifying key")
	}
	if len(proofBytes) == 0 {
		return fmt.Errorf("plonk: empty proof")
	}

	vk := plonk.NewVerifyingKey(ecc.BLS12_381)
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return fmt.Errorf("plonk: parse vk: %w", err)
	}

	proof := plonk.NewProof(ecc.BLS12_381)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("plonk: parse proof: %w", err)
	}

	pubW, err := witness.New(ecc.BLS12_381.ScalarField())
	if err != nil {
		return fmt.Errorf("plonk: init witness: %w", err)
	}
	if _, err := pubW.ReadFrom(bytes.NewReader(publicInputsBytes)); err != nil {
		return fmt.Errorf("plonk: parse public inputs: %w", err)
	}

	if err := plonk.Verify(proof, vk, pubW); err != nil {
		return fmt.Errorf("plonk: verify failed: %w", err)
	}
	return nil
}

func init() {
	Register(TypePLONK, plonkVerifier{})
}
