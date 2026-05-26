package zkp

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/test/unsafekzg"
)

// squareCircuit proves: I know X such that X*X == Y, where Y is public.
type squareCircuit struct {
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",public"`
}

func (c *squareCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

func TestTypeString(t *testing.T) {
	if TypeGroth16.String() != "Groth16" {
		t.Fatalf("Groth16 stringer wrong: %s", TypeGroth16)
	}
	if TypePLONK.String() != "PLONK" {
		t.Fatalf("PLONK stringer wrong: %s", TypePLONK)
	}
	if Type(0xff).String() != "Unknown(0xff)" {
		t.Fatalf("Unknown stringer wrong: %s", Type(0xff))
	}
}

func TestRegistry(t *testing.T) {
	if !IsRegistered(TypeGroth16) {
		t.Fatal("Groth16 not registered")
	}
	if !IsRegistered(TypePLONK) {
		t.Fatal("PLONK not registered")
	}
	if IsRegistered(Type(0xff)) {
		t.Fatal("0xff should not be registered")
	}
	if err := Verify(Type(0xff), nil, nil, nil); err == nil {
		t.Fatal("expected ErrUnknownType")
	}
}

func TestGroth16RoundTrip(t *testing.T) {
	// Compile circuit, run setup, prove, marshal, then verify via the
	// dispatch path. This is a real end-to-end test — no precomputed
	// fixtures, just gnark proving and our verifier accepting.
	var c squareCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	assignment := &squareCircuit{X: 5, Y: 25}
	w, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pubW, err := w.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	var pBuf, vkBuf, pubBuf bytes.Buffer
	if _, err := proof.WriteTo(&pBuf); err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	if _, err := vk.WriteTo(&vkBuf); err != nil {
		t.Fatalf("marshal vk: %v", err)
	}
	if _, err := pubW.WriteTo(&pubBuf); err != nil {
		t.Fatalf("marshal pubW: %v", err)
	}

	// Honest proof verifies.
	if err := Verify(TypeGroth16, vkBuf.Bytes(), pubBuf.Bytes(), pBuf.Bytes()); err != nil {
		t.Fatalf("expected verify success, got: %v", err)
	}

	// Tampered proof rejects.
	tampered := append([]byte(nil), pBuf.Bytes()...)
	tampered[0] ^= 0x01
	if err := Verify(TypeGroth16, vkBuf.Bytes(), pubBuf.Bytes(), tampered); err == nil {
		t.Fatal("expected tampered proof to fail")
	}

	// Wrong public input rejects.
	wrongAssignment := &squareCircuit{X: 5, Y: 26} // 5*5 != 26
	wrongW, _ := frontend.NewWitness(wrongAssignment, ecc.BLS12_381.ScalarField())
	wrongPubW, _ := wrongW.Public()
	var wrongBuf bytes.Buffer
	wrongPubW.WriteTo(&wrongBuf)
	if err := Verify(TypeGroth16, vkBuf.Bytes(), wrongBuf.Bytes(), pBuf.Bytes()); err == nil {
		t.Fatal("expected wrong-input proof to fail")
	}
}

func TestPLONKRoundTrip(t *testing.T) {
	var c squareCircuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// PLONK needs a KZG SRS. unsafekzg generates one in-test (NOT for
	// production use; production must use a public ceremony's SRS).
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("srs: %v", err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	assignment := &squareCircuit{X: 7, Y: 49}
	w, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	pubW, err := w.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	proof, err := plonk.Prove(ccs, pk, w)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	var pBuf, vkBuf, pubBuf bytes.Buffer
	if _, err := proof.WriteTo(&pBuf); err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	if _, err := vk.WriteTo(&vkBuf); err != nil {
		t.Fatalf("marshal vk: %v", err)
	}
	if _, err := pubW.WriteTo(&pubBuf); err != nil {
		t.Fatalf("marshal pubW: %v", err)
	}

	if err := Verify(TypePLONK, vkBuf.Bytes(), pubBuf.Bytes(), pBuf.Bytes()); err != nil {
		t.Fatalf("expected verify success, got: %v", err)
	}

	// Tampered proof rejects.
	tampered := append([]byte(nil), pBuf.Bytes()...)
	tampered[0] ^= 0x01
	if err := Verify(TypePLONK, vkBuf.Bytes(), pubBuf.Bytes(), tampered); err == nil {
		t.Fatal("expected tampered proof to fail")
	}
}

// Compile-time assertion that we're using the BLS12-381 KZG package — pulls
// it into the import graph so go.mod tooling resolves it correctly. (gnark
// loads it lazily otherwise, which can confuse `go mod tidy` in some cases.)
var _ = kzg_bls12381.SRS{}
