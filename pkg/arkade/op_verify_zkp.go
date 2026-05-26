package arkade

import (
	"github.com/ArkLabsHQ/introspector/pkg/arkade/zkp"
	"github.com/btcsuite/btcd/txscript"
)

// opcodeVerifyZkp implements OP_VERIFY_ZKP. It verifies a SNARK proof drawn
// from the script stack using a registered Verifier (see pkg/arkade/zkp).
//
// Stack expectation (top to bottom):
//
//	zkp_type:u8     identifies the proof system (zkp.Type)
//	proof           variable-length, system-specific binary
//	publicInputs    variable-length, system-specific binary (gnark witness format
//	                for the bundled Groth16/PLONK verifiers)
//	vk              variable-length verifying key, pushed earlier in the script
//	                body (committing the circuit identity to the tapleaf hash)
//
// On success the opcode pushes 1; on any failure (unknown zkp_type, malformed
// inputs, soundness rejection) it returns a script error. Callers typically
// follow it with OP_VERIFY to fail the script on rejection.
func opcodeVerifyZkp(op *opcode, data []byte, vm *Engine) error {
	zkpTypeBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(zkpTypeBytes) != 1 {
		return scriptError(txscript.ErrInvalidStackOperation,
			"OP_VERIFY_ZKP: zkp_type must be exactly 1 byte")
	}
	zkpType := zkp.Type(zkpTypeBytes[0])

	proof, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	publicInputs, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	vk, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	if err := zkp.Verify(zkpType, vk, publicInputs, proof); err != nil {
		return scriptError(txscript.ErrNullFail, err.Error())
	}

	vm.dstack.PushInt(1)
	return nil
}
