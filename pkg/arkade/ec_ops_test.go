package arkade

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	gnarkbn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	gnarkbn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	gnarkbn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gnarksecp256k1 "github.com/consensys/gnark-crypto/ecc/secp256k1"
	gnarksecp256k1fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	gnarksecp256k1fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/stretchr/testify/require"
)

// bnBytes returns the canonical Arkade BigNum encoding of v. It panics on
// values that cannot be encoded (oversized); callers in tests pass sane
// in-range values.
func bnBytes(v *big.Int) []byte {
	b, err := (BigNum{big: v, useBig: true}).Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

func bnBytesUint(v uint64) []byte {
	return bnBytes(new(big.Int).SetUint64(v))
}

func bigInt(s string, base int) *big.Int {
	v, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("bad bigint literal: " + s)
	}
	return v
}

// Curve generators and helpers.

func secp256k1Gen() (x, y *big.Int) {
	var g gnarksecp256k1.G1Affine
	_, gAff := gnarksecp256k1.Generators()
	g.Set(&gAff)
	var bx, by big.Int
	g.X.BigInt(&bx)
	g.Y.BigInt(&by)
	return &bx, &by
}

func secp256k1Double(x, y *big.Int) (*big.Int, *big.Int) {
	var p, r gnarksecp256k1.G1Affine
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
	r.Double(&p)
	var bx, by big.Int
	r.X.BigInt(&bx)
	r.Y.BigInt(&by)
	return &bx, &by
}

func secp256k1NegY(y *big.Int) *big.Int {
	mod := gnarksecp256k1fp.Modulus()
	return new(big.Int).Mod(new(big.Int).Neg(y), mod)
}

func secp256r1Gen() (x, y *big.Int) {
	p := elliptic.P256().Params()
	return new(big.Int).Set(p.Gx), new(big.Int).Set(p.Gy)
}

func secp256r1Double(x, y *big.Int) (*big.Int, *big.Int) {
	return elliptic.P256().Double(x, y)
}

func secp256r1NegY(y *big.Int) *big.Int {
	p := elliptic.P256().Params().P
	return new(big.Int).Mod(new(big.Int).Neg(y), p)
}

func bn254G1Gen() (x, y *big.Int) {
	_, _, g1Aff, _ := gnarkbn254.Generators()
	var bx, by big.Int
	g1Aff.X.BigInt(&bx)
	g1Aff.Y.BigInt(&by)
	return &bx, &by
}

func bn254G1Double(x, y *big.Int) (*big.Int, *big.Int) {
	var p, r gnarkbn254.G1Affine
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
	r.Double(&p)
	var bx, by big.Int
	r.X.BigInt(&bx)
	r.Y.BigInt(&by)
	return &bx, &by
}

func bn254G1NegY(y *big.Int) *big.Int {
	mod := gnarkbn254fp.Modulus()
	return new(big.Int).Mod(new(big.Int).Neg(y), mod)
}

func bn254G2Gen() (xC0, xC1, yC0, yC1 *big.Int) {
	_, _, _, g2Aff := gnarkbn254.Generators()
	var xa0, xa1, ya0, ya1 big.Int
	g2Aff.X.A0.BigInt(&xa0)
	g2Aff.X.A1.BigInt(&xa1)
	g2Aff.Y.A0.BigInt(&ya0)
	g2Aff.Y.A1.BigInt(&ya1)
	return &xa0, &xa1, &ya0, &ya1
}

// nonSubgroupG2 produces a deterministic G2 point that is on the alt_bn128
// twist curve but NOT in the r-subgroup. We rely on MapToCurve2: it returns
// a curve point but does NOT clear the cofactor, so the result is overwhelmingly
// likely to be off-subgroup. The function panics if the chosen seed lands in
// the subgroup so a test author can pick a different seed.
func nonSubgroupG2(t *testing.T) (xC0, xC1, yC0, yC1 *big.Int) {
	t.Helper()
	var seed gnarkbn254.G2Affine
	seed.X.A0.SetUint64(1)
	seed.X.A1.SetUint64(0)
	p := gnarkbn254.MapToCurve2(&seed.X)
	require.True(t, p.IsOnCurve(), "MapToCurve2 should land on curve")
	require.False(t, p.IsInSubGroup(), "test seed unexpectedly landed in r-subgroup; pick a new seed")
	var xa0, xa1, ya0, ya1 big.Int
	p.X.A0.BigInt(&xa0)
	p.X.A1.BigInt(&xa1)
	p.Y.A0.BigInt(&ya0)
	p.Y.A1.BigInt(&ya1)
	return &xa0, &xa1, &ya0, &ya1
}

// requireCanonicalBigNums checks that every byte slice on top of `after`'s
// stack is a minimally encoded BigNum. We round-trip through
// BigNumFromBytes — which itself rejects non-minimal encodings — and assert
// that the canonical re-encoding equals the original bytes.
func requireCanonicalBigNums(t *testing.T, items [][]byte) {
	t.Helper()
	for i, b := range items {
		n, err := BigNumFromBytes(b)
		require.NoErrorf(t, err, "stack item %d is not a valid BigNum: %v", i, err)
		out, err := n.Bytes()
		require.NoErrorf(t, err, "stack item %d failed to re-encode: %v", i, err)
		require.Equalf(t, b, out, "stack item %d is not canonically encoded", i)
	}
}

// ecPropertyChecker returns a checker that:
//   - asserts alt-stack and cond-stack are untouched;
//   - if an error occurred, asserts the error code is one of the documented
//     consensus codes;
//   - if no error, asserts the stack delta is exactly outputs - inputs and
//     that all newly pushed items are canonical BigNums.
func ecPropertyChecker(inputs, outputs int) opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)
		if c.execErr != nil {
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrMinimalData,
				txscript.ErrNumberTooBig,
			)
			return
		}
		beforeStack := c.before.GetStack()
		afterStack := c.after.GetStack()
		require.GreaterOrEqual(t, len(beforeStack), inputs, "not enough inputs on stack before opcode")
		require.Equal(t, len(beforeStack)-inputs+outputs, len(afterStack))
		// New pushes are the last `outputs` items.
		requireCanonicalBigNums(t, afterStack[len(afterStack)-outputs:])
	}
}

// ecAddSpec builds the OP_ECADD opcodeSpec with the spec's test matrix.
func ecAddSpec() *opcodeSpec {
	// Common values reused across vectors.
	g1x, g1y := secp256k1Gen()
	g1x2, g1y2 := secp256k1Double(g1x, g1y)
	g1negY := secp256k1NegY(g1y)

	p1x, p1y := secp256r1Gen()
	p1x2, p1y2 := secp256r1Double(p1x, p1y)
	p1negY := secp256r1NegY(p1y)

	bnGx, bnGy := bn254G1Gen()
	bnG2x, bnG2y := bn254G1Double(bnGx, bnGy)
	bnGnegY := bn254G1NegY(bnGy)

	var zero []byte

	pSecp256k1 := gnarksecp256k1fp.Modulus()
	pP256 := elliptic.P256().Params().P
	pBN254 := gnarkbn254fp.Modulus()

	return &opcodeSpec{
		opcode:          OP_ECADD,
		checkProperties: ecPropertyChecker(5, 2),
		validVectors: []opcodeVector{
			{
				name: "secp256k1_G_plus_G",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					bnBytes(g1x), bnBytes(g1y),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{bnBytes(g1x2), bnBytes(g1y2)},
			},
			{
				name: "secp256k1_G_plus_negG_is_infinity",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					bnBytes(g1x), bnBytes(g1negY),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "secp256k1_infinity_plus_G_is_G",
				inputStack: [][]byte{
					zero, zero,
					bnBytes(g1x), bnBytes(g1y),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{bnBytes(g1x), bnBytes(g1y)},
			},
			{
				name: "secp256k1_infinity_plus_infinity",
				inputStack: [][]byte{
					zero, zero,
					zero, zero,
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "secp256r1_G_plus_G",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					bnBytes(p1x), bnBytes(p1y),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{bnBytes(p1x2), bnBytes(p1y2)},
			},
			{
				name: "secp256r1_G_plus_negG_is_infinity",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					bnBytes(p1x), bnBytes(p1negY),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "secp256r1_infinity_plus_infinity",
				inputStack: [][]byte{
					zero, zero,
					zero, zero,
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "secp256r1_infinity_plus_G_is_G",
				inputStack: [][]byte{
					zero, zero,
					bnBytes(p1x), bnBytes(p1y),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{bnBytes(p1x), bnBytes(p1y)},
			},
			{
				name: "alt_bn128_G_plus_G",
				inputStack: [][]byte{
					bnBytes(bnGx), bnBytes(bnGy),
					bnBytes(bnGx), bnBytes(bnGy),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedStack: [][]byte{bnBytes(bnG2x), bnBytes(bnG2y)},
			},
			{
				name: "alt_bn128_G_plus_negG_is_infinity",
				inputStack: [][]byte{
					bnBytes(bnGx), bnBytes(bnGy),
					bnBytes(bnGx), bnBytes(bnGnegY),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedStack: [][]byte{zero, zero},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name:          "missing_curve_id",
				inputStack:    [][]byte{zero, zero, zero, zero},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "unsupported_curve_id",
				inputStack: [][]byte{
					zero, zero, zero, zero,
					bnBytesUint(99),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "negative_curve_id",
				inputStack: [][]byte{
					zero, zero, zero, zero,
					{0x81}, // -1
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "negative_coordinate",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					{0x81}, // -1 as x2
					bnBytes(g1y),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "out_of_field_coordinate",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					bnBytes(pSecp256k1), bnBytes(g1y),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "off_curve_secp256k1",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					bnBytesUint(1), bnBytesUint(1), // (1, 1) not on curve
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "off_curve_secp256r1",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					bnBytesUint(1), bnBytesUint(1),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "off_curve_alt_bn128",
				inputStack: [][]byte{
					bnBytes(bnGx), bnBytes(bnGy),
					bnBytesUint(1), bnBytesUint(1),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "non_minimal_coordinate",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					{0x05, 0x00}, // non-minimal encoding of 5
					bnBytes(g1y),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrMinimalData,
			},
			{
				name: "p256_out_of_field",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					bnBytes(pP256), bnBytes(p1y),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "bn254_out_of_field",
				inputStack: [][]byte{
					bnBytes(bnGx), bnBytes(bnGy),
					bnBytes(pBN254), bnBytes(bnGy),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
		},
	}
}

// ecMulSpec builds the OP_ECMUL opcodeSpec.
func ecMulSpec() *opcodeSpec {
	g1x, g1y := secp256k1Gen()
	g1x2, g1y2 := secp256k1Double(g1x, g1y)

	p1x, p1y := secp256r1Gen()
	p1x2, p1y2 := secp256r1Double(p1x, p1y)

	bnGx, bnGy := bn254G1Gen()
	bnG2x, bnG2y := bn254G1Double(bnGx, bnGy)

	nSecp256k1 := gnarksecp256k1fr.Modulus()
	nP256 := elliptic.P256().Params().N
	nBN254 := gnarkbn254fr.Modulus()
	pSecp256k1 := gnarksecp256k1fp.Modulus()

	// (order - 1) * G = -G. Last valid scalar — confirms the boundary
	// check on the scalar is `<` and not `<=`.
	one := big.NewInt(1)
	nSecp256k1Minus1 := new(big.Int).Sub(nSecp256k1, one)
	nP256Minus1 := new(big.Int).Sub(nP256, one)
	nBN254Minus1 := new(big.Int).Sub(nBN254, one)
	g1negY := secp256k1NegY(g1y)
	p1negY := secp256r1NegY(p1y)
	bnGnegY := bn254G1NegY(bnGy)

	var zero []byte

	return &opcodeSpec{
		opcode:          OP_ECMUL,
		checkProperties: ecPropertyChecker(4, 2),
		validVectors: []opcodeVector{
			{
				name: "secp256k1_k_zero_is_infinity",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					zero,
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "secp256k1_k_one",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					bnBytesUint(1),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{bnBytes(g1x), bnBytes(g1y)},
			},
			{
				name: "secp256k1_k_two",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					bnBytesUint(2),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{bnBytes(g1x2), bnBytes(g1y2)},
			},
			{
				name: "secp256k1_infinity_times_anything",
				inputStack: [][]byte{
					zero, zero,
					bnBytesUint(42),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "secp256k1_k_eq_order_minus_one_is_negG",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					bnBytes(nSecp256k1Minus1),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedStack: [][]byte{bnBytes(g1x), bnBytes(g1negY)},
			},
			{
				name: "secp256r1_k_one",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					bnBytesUint(1),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{bnBytes(p1x), bnBytes(p1y)},
			},
			{
				name: "secp256r1_k_two",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					bnBytesUint(2),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{bnBytes(p1x2), bnBytes(p1y2)},
			},
			{
				name: "secp256r1_k_zero",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					zero,
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "secp256r1_infinity_times_anything",
				inputStack: [][]byte{
					zero, zero,
					bnBytesUint(42),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "secp256r1_k_eq_order_minus_one_is_negG",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					bnBytes(nP256Minus1),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedStack: [][]byte{bnBytes(p1x), bnBytes(p1negY)},
			},
			{
				name: "alt_bn128_k_two",
				inputStack: [][]byte{
					bnBytes(bnGx), bnBytes(bnGy),
					bnBytesUint(2),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedStack: [][]byte{bnBytes(bnG2x), bnBytes(bnG2y)},
			},
			{
				name: "alt_bn128_k_zero",
				inputStack: [][]byte{
					bnBytes(bnGx), bnBytes(bnGy),
					zero,
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedStack: [][]byte{zero, zero},
			},
			{
				name: "alt_bn128_k_eq_order_minus_one_is_negG",
				inputStack: [][]byte{
					bnBytes(bnGx), bnBytes(bnGy),
					bnBytes(nBN254Minus1),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedStack: [][]byte{bnBytes(bnGx), bnBytes(bnGnegY)},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "unsupported_curve_id",
				inputStack: [][]byte{
					zero, zero, zero, bnBytesUint(99),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "scalar_equal_to_group_order_secp256k1",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					bnBytes(nSecp256k1),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "scalar_equal_to_group_order_secp256r1",
				inputStack: [][]byte{
					bnBytes(p1x), bnBytes(p1y),
					bnBytes(nP256),
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "scalar_equal_to_group_order_alt_bn128",
				inputStack: [][]byte{
					bnBytes(bnGx), bnBytes(bnGy),
					bnBytes(nBN254),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "negative_scalar",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					{0x81}, // -1
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "off_curve_secp256k1",
				inputStack: [][]byte{
					bnBytesUint(1), bnBytesUint(1),
					bnBytesUint(1),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "out_of_field_coordinate",
				inputStack: [][]byte{
					bnBytes(pSecp256k1), bnBytes(g1y),
					bnBytesUint(1),
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "non_minimal_scalar",
				inputStack: [][]byte{
					bnBytes(g1x), bnBytes(g1y),
					{0x05, 0x00},
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrMinimalData,
			},
		},
	}
}

// pairingTrueVectors returns a stack that encodes a valid pairing-product
// check evaluating to true: e(G1, G2) * e(-G1, G2) == 1.
func pairingTrueVectors(t *testing.T) [][]byte {
	t.Helper()
	g1x, g1y := bn254G1Gen()
	negY := bn254G1NegY(g1y)
	g2xC0, g2xC1, g2yC0, g2yC1 := bn254G2Gen()
	// Stack layout for each pair (bottom -> top):
	//   g1_x g1_y g2_x_c1 g2_x_c0 g2_y_c1 g2_y_c0
	pair := func(x, y *big.Int) [][]byte {
		return [][]byte{
			bnBytes(x), bnBytes(y),
			bnBytes(g2xC1), bnBytes(g2xC0),
			bnBytes(g2yC1), bnBytes(g2yC0),
		}
	}
	var out [][]byte
	out = append(out, pair(g1x, g1y)...)
	out = append(out, pair(g1x, negY)...)
	out = append(out, bnBytesUint(2), bnBytesUint(uint64(CurveAltBN128)))
	return out
}

func pairingFalseVectors() [][]byte {
	g1x, g1y := bn254G1Gen()
	g2xC0, g2xC1, g2yC0, g2yC1 := bn254G2Gen()
	stack := [][]byte{
		bnBytes(g1x), bnBytes(g1y),
		bnBytes(g2xC1), bnBytes(g2xC0),
		bnBytes(g2yC1), bnBytes(g2yC0),
		bnBytesUint(1), bnBytesUint(uint64(CurveAltBN128)),
	}
	return stack
}

func TestECPairingTrueValid(t *testing.T) {
	// Sanity check that the chosen vectors do form a valid e(G,G2)*e(-G,G2)=1.
	world := buildOpcodeWorld()
	vm, err := newOpcodeEngine(world, 0)
	require.NoError(t, err)
	vm.SetStack(pairingTrueVectors(t))
	require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
	require.Equal(t, [][]byte{{0x01}}, vm.GetStack())
}

func TestECPairingFalseValid(t *testing.T) {
	world := buildOpcodeWorld()
	vm, err := newOpcodeEngine(world, 0)
	require.NoError(t, err)
	vm.SetStack(pairingFalseVectors())
	require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
	require.Equal(t, [][]byte{nil}, vm.GetStack())
}

// pairingPropertyChecker is a relaxed version that does not require the
// pushed boolean to round-trip through BigNumFromBytes — true is `{0x01}`,
// false is `nil`, both consensus-canonical bool encodings.
func pairingPropertyChecker() opcodePropertyChecker {
	return func(t *testing.T, c opcodeCheckContext) {
		t.Helper()
		require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
		require.Equal(t, c.before.condStack, c.after.condStack)
		if c.execErr != nil {
			requireScriptErrorCodeIn(t, c.execErr,
				txscript.ErrInvalidStackOperation,
				txscript.ErrMinimalData,
				txscript.ErrNumberTooBig,
			)
			return
		}
		// On success, the after-stack must have grown by exactly one item
		// (a bool), and that item must be either `{0x01}` (true) or `{}` (false).
		afterStack := c.after.GetStack()
		require.NotEmpty(t, afterStack)
		top := afterStack[len(afterStack)-1]
		require.True(t, len(top) == 0 || (len(top) == 1 && top[0] == 0x01),
			"OP_ECPAIRING pushed a non-canonical bool %x", top)
	}
}

// ecPairingSpec builds the OP_ECPAIRING opcodeSpec.
func ecPairingSpec() *opcodeSpec {
	var zero []byte

	return &opcodeSpec{
		opcode:          OP_ECPAIRING,
		checkProperties: pairingPropertyChecker(),
		validVectors: []opcodeVector{
			{
				name: "empty_set_returns_true",
				inputStack: [][]byte{
					zero, // pair_count = 0
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedStack: [][]byte{{0x01}},
			},
		},
		invalidVectors: []opcodeVector{
			{
				name:          "underflow",
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "unsupported_curve_id",
				inputStack: [][]byte{
					zero,
					bnBytesUint(99),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "unsupported_pairing_curve_secp256k1",
				inputStack: [][]byte{
					zero,
					bnBytesUint(uint64(CurveSecp256k1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "unsupported_pairing_curve_secp256r1",
				inputStack: [][]byte{
					zero,
					bnBytesUint(uint64(CurveSecp256r1)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "negative_pair_count",
				inputStack: [][]byte{
					{0x81}, // -1
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "pair_count_exceeds_max",
				inputStack: [][]byte{
					bnBytesUint(uint64(maxECPairingCount + 1)),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "pair_count_underflow",
				inputStack: [][]byte{
					// Claim 1 pair but provide no coords.
					bnBytesUint(1),
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedError: txscript.ErrInvalidStackOperation,
			},
			{
				name: "non_minimal_pair_count",
				inputStack: [][]byte{
					{0x01, 0x00},
					bnBytesUint(uint64(CurveAltBN128)),
				},
				expectedError: txscript.ErrMinimalData,
			},
		},
	}
}

// TestECPairingOffCurveG1 verifies that an off-curve G1 input fails execution.
func TestECPairingOffCurveG1(t *testing.T) {
	g2xC0, g2xC1, g2yC0, g2yC1 := bn254G2Gen()
	stack := [][]byte{
		// G1 = (1, 1), not on curve
		bnBytesUint(1), bnBytesUint(1),
		bnBytes(g2xC1), bnBytes(g2xC0),
		bnBytes(g2yC1), bnBytes(g2yC0),
		bnBytesUint(1), bnBytesUint(uint64(CurveAltBN128)),
	}
	world := buildOpcodeWorld()
	vm, err := newOpcodeEngine(world, 0)
	require.NoError(t, err)
	vm.SetStack(stack)
	err = invokeOpcodeWithData(OP_ECPAIRING, nil, vm)
	requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
}

// TestECPairingOffCurveG2 verifies that an on-field but off-curve G2 input
// fails execution. We construct an Fp2 element that we know is on the twist
// (via MapToCurve2), then perturb its X coordinate so it leaves the curve.
func TestECPairingOffCurveG2(t *testing.T) {
	g1x, g1y := bn254G1Gen()
	g2xC0, g2xC1, _, g2yC1 := bn254G2Gen()
	// Use the real G2 X but a y that does not satisfy the curve equation.
	// Setting yC0 = 0 in general breaks y² = x³ + b' for the generator.
	stack := [][]byte{
		bnBytes(g1x), bnBytes(g1y),
		bnBytes(g2xC1), bnBytes(g2xC0),
		bnBytes(g2yC1), []byte{}, // yC0 := 0
		bnBytesUint(1), bnBytesUint(uint64(CurveAltBN128)),
	}
	world := buildOpcodeWorld()
	vm, err := newOpcodeEngine(world, 0)
	require.NoError(t, err)
	vm.SetStack(stack)
	err = invokeOpcodeWithData(OP_ECPAIRING, nil, vm)
	requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
}

// TestECPairingG2NotInSubgroup verifies that a G2 point on the twist but
// outside the r-subgroup fails execution.
func TestECPairingG2NotInSubgroup(t *testing.T) {
	g1x, g1y := bn254G1Gen()
	xc0, xc1, yc0, yc1 := nonSubgroupG2(t)
	stack := [][]byte{
		bnBytes(g1x), bnBytes(g1y),
		bnBytes(xc1), bnBytes(xc0),
		bnBytes(yc1), bnBytes(yc0),
		bnBytesUint(1), bnBytesUint(uint64(CurveAltBN128)),
	}
	world := buildOpcodeWorld()
	vm, err := newOpcodeEngine(world, 0)
	require.NoError(t, err)
	vm.SetStack(stack)
	err = invokeOpcodeWithData(OP_ECPAIRING, nil, vm)
	requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
}

// TestECPairingOutOfFieldCoordinate covers the field-modulus boundary for
// pairing coordinates on G1.
func TestECPairingOutOfFieldCoordinate(t *testing.T) {
	g1y := func() *big.Int { _, y := bn254G1Gen(); return y }()
	g2xC0, g2xC1, g2yC0, g2yC1 := bn254G2Gen()
	mod := gnarkbn254fp.Modulus()
	stack := [][]byte{
		bnBytes(mod), bnBytes(g1y),
		bnBytes(g2xC1), bnBytes(g2xC0),
		bnBytes(g2yC1), bnBytes(g2yC0),
		bnBytesUint(1), bnBytesUint(uint64(CurveAltBN128)),
	}
	world := buildOpcodeWorld()
	vm, err := newOpcodeEngine(world, 0)
	require.NoError(t, err)
	vm.SetStack(stack)
	err = invokeOpcodeWithData(OP_ECPAIRING, nil, vm)
	requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
}

// TestECPairingOutOfFieldG2Coordinate covers the field-modulus boundary for
// each of the four G2 Fp2 components.
func TestECPairingOutOfFieldG2Coordinate(t *testing.T) {
	g1x, g1y := bn254G1Gen()
	g2xC0, g2xC1, g2yC0, g2yC1 := bn254G2Gen()
	mod := gnarkbn254fp.Modulus()
	cases := []struct {
		name                       string
		xC0, xC1, yC0, yC1 *big.Int
	}{
		{"g2_x_c0_eq_mod", mod, g2xC1, g2yC0, g2yC1},
		{"g2_x_c1_eq_mod", g2xC0, mod, g2yC0, g2yC1},
		{"g2_y_c0_eq_mod", g2xC0, g2xC1, mod, g2yC1},
		{"g2_y_c1_eq_mod", g2xC0, g2xC1, g2yC0, mod},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stack := [][]byte{
				bnBytes(g1x), bnBytes(g1y),
				bnBytes(tc.xC1), bnBytes(tc.xC0),
				bnBytes(tc.yC1), bnBytes(tc.yC0),
				bnBytesUint(1), bnBytesUint(uint64(CurveAltBN128)),
			}
			world := buildOpcodeWorld()
			vm, err := newOpcodeEngine(world, 0)
			require.NoError(t, err)
			vm.SetStack(stack)
			err = invokeOpcodeWithData(OP_ECPAIRING, nil, vm)
			requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
		})
	}
}

// TestECPairingNegativeG2Coordinate confirms a negative BigNum in any G2
// component fails execution.
func TestECPairingNegativeG2Coordinate(t *testing.T) {
	g1x, g1y := bn254G1Gen()
	g2xC0, g2xC1, g2yC0, g2yC1 := bn254G2Gen()
	negOne := []byte{0x81} // canonical minimal encoding of -1
	cases := []struct {
		name string
		xC0, xC1, yC0, yC1 []byte
	}{
		{"g2_x_c0_negative", negOne, bnBytes(g2xC1), bnBytes(g2yC0), bnBytes(g2yC1)},
		{"g2_x_c1_negative", bnBytes(g2xC0), negOne, bnBytes(g2yC0), bnBytes(g2yC1)},
		{"g2_y_c0_negative", bnBytes(g2xC0), bnBytes(g2xC1), negOne, bnBytes(g2yC1)},
		{"g2_y_c1_negative", bnBytes(g2xC0), bnBytes(g2xC1), bnBytes(g2yC0), negOne},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stack := [][]byte{
				bnBytes(g1x), bnBytes(g1y),
				tc.xC1, tc.xC0,
				tc.yC1, tc.yC0,
				bnBytesUint(1), bnBytesUint(uint64(CurveAltBN128)),
			}
			world := buildOpcodeWorld()
			vm, err := newOpcodeEngine(world, 0)
			require.NoError(t, err)
			vm.SetStack(stack)
			err = invokeOpcodeWithData(OP_ECPAIRING, nil, vm)
			requireScriptErrorCode(t, err, txscript.ErrInvalidStackOperation)
		})
	}
}

// TestECPairingPairCountAtMax verifies that pair_count == maxECPairingCount
// is accepted. Confirms the bound is `>` and not `>=`. The bundle of 16
// pairs is 8 copies of {(G, G2), (-G, G2)} so the product is the identity
// in GT and the opcode returns true.
func TestECPairingPairCountAtMax(t *testing.T) {
	g1x, g1y := bn254G1Gen()
	negY := bn254G1NegY(g1y)
	g2xC0, g2xC1, g2yC0, g2yC1 := bn254G2Gen()
	pair := func(x, y *big.Int) [][]byte {
		return [][]byte{
			bnBytes(x), bnBytes(y),
			bnBytes(g2xC1), bnBytes(g2xC0),
			bnBytes(g2yC1), bnBytes(g2yC0),
		}
	}
	var stack [][]byte
	for i := 0; i < maxECPairingCount/2; i++ {
		stack = append(stack, pair(g1x, g1y)...)
		stack = append(stack, pair(g1x, negY)...)
	}
	stack = append(stack,
		bnBytesUint(uint64(maxECPairingCount)),
		bnBytesUint(uint64(CurveAltBN128)),
	)

	world := buildOpcodeWorld()
	vm, err := newOpcodeEngine(world, 0)
	require.NoError(t, err)
	vm.SetStack(stack)
	require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
	require.Equal(t, [][]byte{{0x01}}, vm.GetStack())
}

// TestECPairingG2InfinityIsIdentity verifies that pairs containing the G2
// point at infinity contribute the identity to the product, so a single
// pair (P, 0_G2) produces a true result.
func TestECPairingG2InfinityIsIdentity(t *testing.T) {
	g1x, g1y := bn254G1Gen()
	z := []byte(nil)
	stack := [][]byte{
		bnBytes(g1x), bnBytes(g1y),
		z, z, // G2 x: c1=0, c0=0
		z, z, // G2 y: c1=0, c0=0
		bnBytesUint(1), bnBytesUint(uint64(CurveAltBN128)),
	}
	world := buildOpcodeWorld()
	vm, err := newOpcodeEngine(world, 0)
	require.NoError(t, err)
	vm.SetStack(stack)
	require.NoError(t, invokeOpcodeWithData(OP_ECPAIRING, nil, vm))
	require.Equal(t, [][]byte{{0x01}}, vm.GetStack())
}
