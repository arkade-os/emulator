package arkade

import (
	"bytes"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade/zkp"
	"github.com/btcsuite/btcd/txscript"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
)

// squareCircuit proves: I know X such that X*X == Y, where Y is public.
// Mirrors the circuit used in pkg/arkade/zkp/zkp_test.go so the round-trip
// vectors produced here exercise the same prover/verifier pair via the opcode
// dispatch.
type squareOpCircuit struct {
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",public"`
}

func (c *squareOpCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

// generateGroth16Vectors returns serialized (vk, public_inputs, proof) for a
// known-good Groth16 proof of 3*3 == 9.
func generateGroth16Vectors(t *testing.T) (vk, pub, proof []byte) {
	t.Helper()
	var c squareOpCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &c)
	require.NoError(t, err)
	pk, vkObj, err := groth16.Setup(ccs)
	require.NoError(t, err)
	w, err := frontend.NewWitness(&squareOpCircuit{X: 3, Y: 9}, ecc.BLS12_381.ScalarField())
	require.NoError(t, err)
	pubW, err := w.Public()
	require.NoError(t, err)
	proofObj, err := groth16.Prove(ccs, pk, w)
	require.NoError(t, err)

	var vkBuf, pubBuf, pBuf bytes.Buffer
	_, err = vkObj.WriteTo(&vkBuf)
	require.NoError(t, err)
	_, err = pubW.WriteTo(&pubBuf)
	require.NoError(t, err)
	_, err = proofObj.WriteTo(&pBuf)
	require.NoError(t, err)
	return vkBuf.Bytes(), pubBuf.Bytes(), pBuf.Bytes()
}

// generatePlonkVectors returns serialized (vk, public_inputs, proof) for a
// known-good PLONK proof of 4*4 == 16. Uses an unsafe in-test KZG SRS — never
// suitable for production deployments, which must use a public ceremony's SRS.
func generatePlonkVectors(t *testing.T) (vk, pub, proof []byte) {
	t.Helper()
	var c squareOpCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &c)
	require.NoError(t, err)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	require.NoError(t, err)
	pk, vkObj, err := plonk.Setup(ccs, srs, srsLagrange)
	require.NoError(t, err)
	w, err := frontend.NewWitness(&squareOpCircuit{X: 4, Y: 16}, ecc.BLS12_381.ScalarField())
	require.NoError(t, err)
	pubW, err := w.Public()
	require.NoError(t, err)
	proofObj, err := plonk.Prove(ccs, pk, w)
	require.NoError(t, err)

	var vkBuf, pubBuf, pBuf bytes.Buffer
	_, err = vkObj.WriteTo(&vkBuf)
	require.NoError(t, err)
	_, err = pubW.WriteTo(&pubBuf)
	require.NoError(t, err)
	_, err = proofObj.WriteTo(&pBuf)
	require.NoError(t, err)
	return vkBuf.Bytes(), pubBuf.Bytes(), pBuf.Bytes()
}

// runVerifyZkp drives the opcode handler directly against a fresh engine with
// the four required stack items. Returns the engine post-execution and the
// handler error (if any).
func runVerifyZkp(t *testing.T, vk, pub, proof []byte, zkpType zkp.Type) (*Engine, error) {
	t.Helper()
	vm := &Engine{}
	// Push order is bottom-to-top: vk, public_inputs, proof, zkp_type.
	vm.dstack.PushByteArray(vk)
	vm.dstack.PushByteArray(pub)
	vm.dstack.PushByteArray(proof)
	vm.dstack.PushByteArray([]byte{byte(zkpType)})
	err := opcodeVerifyZkp(nil, nil, vm)
	return vm, err
}

func TestOpVerifyZkpGroth16Success(t *testing.T) {
	vk, pub, proof := generateGroth16Vectors(t)
	vm, err := runVerifyZkp(t, vk, pub, proof, zkp.TypeGroth16)
	require.NoError(t, err)

	// Handler pushes 1 on success.
	top, err := vm.dstack.PopInt()
	require.NoError(t, err)
	require.Equal(t, int64(1), int64(top))
}

func TestOpVerifyZkpPlonkSuccess(t *testing.T) {
	vk, pub, proof := generatePlonkVectors(t)
	vm, err := runVerifyZkp(t, vk, pub, proof, zkp.TypePLONK)
	require.NoError(t, err)

	top, err := vm.dstack.PopInt()
	require.NoError(t, err)
	require.Equal(t, int64(1), int64(top))
}

func TestOpVerifyZkpRejectsTamperedProof(t *testing.T) {
	vk, pub, proof := generateGroth16Vectors(t)
	tampered := append([]byte(nil), proof...)
	tampered[0] ^= 0x01
	_, err := runVerifyZkp(t, vk, pub, tampered, zkp.TypeGroth16)
	require.Error(t, err)
}

func TestOpVerifyZkpRejectsUnknownType(t *testing.T) {
	vk, pub, proof := generateGroth16Vectors(t)
	_, err := runVerifyZkp(t, vk, pub, proof, zkp.Type(0xff))
	require.Error(t, err)
}

func TestOpVerifyZkpRejectsBadTypeLength(t *testing.T) {
	vk, pub, proof := generateGroth16Vectors(t)
	vm := &Engine{}
	vm.dstack.PushByteArray(vk)
	vm.dstack.PushByteArray(pub)
	vm.dstack.PushByteArray(proof)
	// Push 2 bytes instead of 1 for zkp_type.
	vm.dstack.PushByteArray([]byte{0x01, 0x00})
	err := opcodeVerifyZkp(nil, nil, vm)
	require.Error(t, err)
	// Should be a script error, not a panic.
	var serr txscript.Error
	require.ErrorAs(t, err, &serr)
	require.Equal(t, txscript.ErrInvalidStackOperation, serr.ErrorCode)
}
