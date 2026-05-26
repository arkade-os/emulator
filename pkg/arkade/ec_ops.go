package arkade

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	gnarkbn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	gnarkbn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	gnarkbn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gnarksecp256k1 "github.com/consensys/gnark-crypto/ecc/secp256k1"
	gnarksecp256k1fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	gnarksecp256k1fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"

	"github.com/btcsuite/btcd/txscript"
)

// Curve identifiers consumed by OP_ECADD, OP_ECMUL, and OP_ECPAIRING. Curve
// IDs are pushed on the stack as Arkade BigNums.
const (
	CurveSecp256k1 int64 = 0
	CurveSecp256r1 int64 = 1
	CurveAltBN128  int64 = 2
)

// maxECPairingCount is the maximum number of (G1, G2) pairs OP_ECPAIRING
// will process in a single call. Arkade Script has no gas model, so the
// CPU cost of a pairing-product check must be bounded deterministically.
const maxECPairingCount = 16

// alt_bn128 (G1, G2, pairing) and secp256k1 (G1) use gnark-crypto v0.19.2.
// secp256r1 / NIST P-256 is not in gnark-crypto, so it uses Go's standard
// crypto/elliptic.P256() — itself backed by crypto/internal/nistec and used
// in crypto/tls, crypto/ecdsa, and crypto/ecdh.

type curveMeta struct {
	id              int64
	name            string
	fieldModulus    *big.Int
	groupOrder      *big.Int
	supportsPairing bool
}

var curveByID = map[int64]*curveMeta{
	CurveSecp256k1: {
		id:           CurveSecp256k1,
		name:         "secp256k1",
		fieldModulus: gnarksecp256k1fp.Modulus(),
		groupOrder:   gnarksecp256k1fr.Modulus(),
	},
	CurveSecp256r1: {
		id:           CurveSecp256r1,
		name:         "secp256r1",
		fieldModulus: new(big.Int).Set(elliptic.P256().Params().P),
		groupOrder:   new(big.Int).Set(elliptic.P256().Params().N),
	},
	CurveAltBN128: {
		id:              CurveAltBN128,
		name:            "alt_bn128",
		fieldModulus:    gnarkbn254fp.Modulus(),
		groupOrder:      gnarkbn254fr.Modulus(),
		supportsPairing: true,
	},
}

// ecPair is one (G1, G2) input to an EIP-197-style pairing-product check
// on alt_bn128. G1 coordinates are field elements; G2 coordinates are Fp2
// elements represented as (c0, c1) per gnark's E2 layout.
type ecPair struct {
	g1X, g1Y                   *big.Int
	g2XC0, g2XC1, g2YC0, g2YC1 *big.Int
}

var (
	errECPointOffCurve   = errors.New("point not on curve")
	errECG2NotInSubgroup = errors.New("G2 point not in r-subgroup")
)

// popCurveID pops the top stack item and resolves it to a known curve.
// Negative IDs, non-int64 IDs, and unknown IDs all fail script execution.
func popCurveID(vm *Engine) (*curveMeta, error) {
	n, err := vm.dstack.PopBigNum()
	if err != nil {
		return nil, err
	}
	if n.Sign() < 0 {
		return nil, scriptError(txscript.ErrInvalidStackOperation,
			"negative curve id")
	}
	bi := n.BigInt()
	if !bi.IsInt64() {
		return nil, scriptError(txscript.ErrInvalidStackOperation,
			"curve id out of range")
	}
	id := bi.Int64()
	meta, ok := curveByID[id]
	if !ok {
		return nil, scriptError(txscript.ErrInvalidStackOperation,
			fmt.Sprintf("unsupported curve id %d", id))
	}
	return meta, nil
}

// popInFieldElement pops a BigNum and enforces 0 ≤ n < modulus.
// The descriptive `what` is included in error messages for failure mode
// disambiguation in tests and debugging.
func popInFieldElement(vm *Engine, modulus *big.Int, what string) (*big.Int, error) {
	n, err := vm.dstack.PopBigNum()
	if err != nil {
		return nil, err
	}
	if n.Sign() < 0 {
		return nil, scriptError(txscript.ErrInvalidStackOperation,
			fmt.Sprintf("negative %s", what))
	}
	bi := n.BigInt()
	if bi.Cmp(modulus) >= 0 {
		return nil, scriptError(txscript.ErrInvalidStackOperation,
			fmt.Sprintf("%s not less than field modulus", what))
	}
	return bi, nil
}

// popInGroupScalar pops a BigNum and enforces 0 ≤ k < order.
func popInGroupScalar(vm *Engine, order *big.Int) (*big.Int, error) {
	n, err := vm.dstack.PopBigNum()
	if err != nil {
		return nil, err
	}
	if n.Sign() < 0 {
		return nil, scriptError(txscript.ErrInvalidStackOperation,
			"negative scalar")
	}
	bi := n.BigInt()
	if bi.Cmp(order) >= 0 {
		return nil, scriptError(txscript.ErrInvalidStackOperation,
			"scalar not less than group order")
	}
	return bi, nil
}

// pushECCoord pushes a non-negative big.Int as a canonical Arkade BigNum.
func pushECCoord(vm *Engine, v *big.Int) error {
	return vm.dstack.PushBigNum(BigNum{big: v, useBig: true})
}

// pushECPoint pushes (x, y) as two BigNums, x first.
func pushECPoint(vm *Engine, x, y *big.Int) error {
	if err := pushECCoord(vm, x); err != nil {
		return err
	}
	return pushECCoord(vm, y)
}

// opcodeECAdd implements OP_ECADD.
// Stack transformation: [... x1 y1 x2 y2 curve_id] -> [... x3 y3]
func opcodeECAdd(op *opcode, _ []byte, vm *Engine) error {
	meta, err := popCurveID(vm)
	if err != nil {
		return err
	}

	y2, err := popInFieldElement(vm, meta.fieldModulus, "y2")
	if err != nil {
		return err
	}
	x2, err := popInFieldElement(vm, meta.fieldModulus, "x2")
	if err != nil {
		return err
	}
	y1, err := popInFieldElement(vm, meta.fieldModulus, "y1")
	if err != nil {
		return err
	}
	x1, err := popInFieldElement(vm, meta.fieldModulus, "x1")
	if err != nil {
		return err
	}

	rx, ry, err := ecAdd(meta.id, x1, y1, x2, y2)
	if err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, err.Error())
	}
	return pushECPoint(vm, rx, ry)
}

// opcodeECMul implements OP_ECMUL.
// Stack transformation: [... x y k curve_id] -> [... x2 y2]
func opcodeECMul(op *opcode, _ []byte, vm *Engine) error {
	meta, err := popCurveID(vm)
	if err != nil {
		return err
	}

	k, err := popInGroupScalar(vm, meta.groupOrder)
	if err != nil {
		return err
	}
	y, err := popInFieldElement(vm, meta.fieldModulus, "y")
	if err != nil {
		return err
	}
	x, err := popInFieldElement(vm, meta.fieldModulus, "x")
	if err != nil {
		return err
	}

	rx, ry, err := ecMul(meta.id, x, y, k)
	if err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, err.Error())
	}
	return pushECPoint(vm, rx, ry)
}

// opcodeECPairing implements OP_ECPAIRING.
// Stack transformation:
//
//	[... (g1_x g1_y g2_x_c1 g2_x_c0 g2_y_c1 g2_y_c0)... pair_count curve_id]
//	  -> [... bool]
func opcodeECPairing(op *opcode, _ []byte, vm *Engine) error {
	meta, err := popCurveID(vm)
	if err != nil {
		return err
	}
	if !meta.supportsPairing {
		return scriptError(txscript.ErrInvalidStackOperation,
			fmt.Sprintf("curve %s does not support pairing", meta.name))
	}

	countBN, err := vm.dstack.PopBigNum()
	if err != nil {
		return err
	}
	if countBN.Sign() < 0 {
		return scriptError(txscript.ErrInvalidStackOperation,
			"negative pair_count")
	}
	countBI := countBN.BigInt()
	if !countBI.IsInt64() {
		return scriptError(txscript.ErrInvalidStackOperation,
			"pair_count out of range")
	}
	count := countBI.Int64()
	if count > maxECPairingCount {
		return scriptError(txscript.ErrInvalidStackOperation,
			fmt.Sprintf("pair_count %d exceeds max %d", count, maxECPairingCount))
	}

	pairs := make([]ecPair, count)
	// For each pair the stack layout (bottom -> top) is
	//   g1_x g1_y g2_x_c1 g2_x_c0 g2_y_c1 g2_y_c0.
	// Pop from the top so the last pair on the stack is filled first.
	for i := int(count) - 1; i >= 0; i-- {
		yC0, err := popInFieldElement(vm, meta.fieldModulus, "g2_y_c0")
		if err != nil {
			return err
		}
		yC1, err := popInFieldElement(vm, meta.fieldModulus, "g2_y_c1")
		if err != nil {
			return err
		}
		xC0, err := popInFieldElement(vm, meta.fieldModulus, "g2_x_c0")
		if err != nil {
			return err
		}
		xC1, err := popInFieldElement(vm, meta.fieldModulus, "g2_x_c1")
		if err != nil {
			return err
		}
		g1Y, err := popInFieldElement(vm, meta.fieldModulus, "g1_y")
		if err != nil {
			return err
		}
		g1X, err := popInFieldElement(vm, meta.fieldModulus, "g1_x")
		if err != nil {
			return err
		}
		pairs[i] = ecPair{
			g1X:   g1X,
			g1Y:   g1Y,
			g2XC0: xC0,
			g2XC1: xC1,
			g2YC0: yC0,
			g2YC1: yC1,
		}
	}

	ok, err := bn254PairingCheck(pairs)
	if err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, err.Error())
	}
	vm.dstack.PushBool(ok)
	return nil
}

// ecAdd dispatches OP_ECADD to the right backend.
func ecAdd(curveID int64, x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int, error) {
	switch curveID {
	case CurveSecp256k1:
		return ecAddSecp256k1(x1, y1, x2, y2)
	case CurveSecp256r1:
		return ecAddSecp256r1(x1, y1, x2, y2)
	case CurveAltBN128:
		return ecAddBN254G1(x1, y1, x2, y2)
	default:
		return nil, nil, fmt.Errorf("unsupported curve id %d", curveID)
	}
}

// ecMul dispatches OP_ECMUL to the right backend.
func ecMul(curveID int64, x, y, k *big.Int) (*big.Int, *big.Int, error) {
	switch curveID {
	case CurveSecp256k1:
		return ecMulSecp256k1(x, y, k)
	case CurveSecp256r1:
		return ecMulSecp256r1(x, y, k)
	case CurveAltBN128:
		return ecMulBN254G1(x, y, k)
	default:
		return nil, nil, fmt.Errorf("unsupported curve id %d", curveID)
	}
}

// secp256k1 — gnark-crypto.

// ecAddSecp256k1 adds two affine secp256k1 points. (0, 0) denotes the point
// at infinity. Returns (0, 0) when the geometric sum is infinity.
func ecAddSecp256k1(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int, error) {
	var p1, p2, r gnarksecp256k1.G1Affine
	setSecp256k1Affine(&p1, x1, y1)
	setSecp256k1Affine(&p2, x2, y2)
	if !p1.IsOnCurve() {
		return nil, nil, errECPointOffCurve
	}
	if !p2.IsOnCurve() {
		return nil, nil, errECPointOffCurve
	}
	r.Add(&p1, &p2)
	rx, ry := secp256k1AffineCoords(&r)
	return rx, ry, nil
}

// ecMulSecp256k1 returns k * P on secp256k1. P=(0,0) denotes infinity. k=0
// returns infinity. The caller must enforce 0 ≤ k < group order.
func ecMulSecp256k1(x, y, k *big.Int) (*big.Int, *big.Int, error) {
	var p, r gnarksecp256k1.G1Affine
	setSecp256k1Affine(&p, x, y)
	if !p.IsOnCurve() {
		return nil, nil, errECPointOffCurve
	}
	r.ScalarMultiplication(&p, k)
	rx, ry := secp256k1AffineCoords(&r)
	return rx, ry, nil
}

func setSecp256k1Affine(p *gnarksecp256k1.G1Affine, x, y *big.Int) {
	if x.Sign() == 0 && y.Sign() == 0 {
		p.X.SetZero()
		p.Y.SetZero()
		return
	}
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
}

func secp256k1AffineCoords(p *gnarksecp256k1.G1Affine) (*big.Int, *big.Int) {
	if p.IsInfinity() {
		return new(big.Int), new(big.Int)
	}
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return &x, &y
}

// alt_bn128 G1 — gnark-crypto.

// ecAddBN254G1 adds two affine alt_bn128 G1 points. Same infinity convention
// as ecAddSecp256k1.
func ecAddBN254G1(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int, error) {
	var p1, p2, r gnarkbn254.G1Affine
	setBN254G1Affine(&p1, x1, y1)
	setBN254G1Affine(&p2, x2, y2)
	if !p1.IsOnCurve() {
		return nil, nil, errECPointOffCurve
	}
	if !p2.IsOnCurve() {
		return nil, nil, errECPointOffCurve
	}
	r.Add(&p1, &p2)
	rx, ry := bn254G1AffineCoords(&r)
	return rx, ry, nil
}

// ecMulBN254G1 returns k * P on alt_bn128 G1.
func ecMulBN254G1(x, y, k *big.Int) (*big.Int, *big.Int, error) {
	var p, r gnarkbn254.G1Affine
	setBN254G1Affine(&p, x, y)
	if !p.IsOnCurve() {
		return nil, nil, errECPointOffCurve
	}
	r.ScalarMultiplication(&p, k)
	rx, ry := bn254G1AffineCoords(&r)
	return rx, ry, nil
}

func setBN254G1Affine(p *gnarkbn254.G1Affine, x, y *big.Int) {
	if x.Sign() == 0 && y.Sign() == 0 {
		p.X.SetZero()
		p.Y.SetZero()
		return
	}
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
}

func bn254G1AffineCoords(p *gnarkbn254.G1Affine) (*big.Int, *big.Int) {
	if p.IsInfinity() {
		return new(big.Int), new(big.Int)
	}
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return &x, &y
}

// alt_bn128 pairing — gnark-crypto.

// bn254PairingCheck returns whether the product of pairings is the identity
// in GT. Validates G1 on-curve and G2 on-curve + in-subgroup before invoking
// gnark's PairingCheck. An empty input set returns true to match EIP-197.
func bn254PairingCheck(pairs []ecPair) (bool, error) {
	if len(pairs) == 0 {
		return true, nil
	}
	g1s := make([]gnarkbn254.G1Affine, len(pairs))
	g2s := make([]gnarkbn254.G2Affine, len(pairs))
	for i, p := range pairs {
		setBN254G1Affine(&g1s[i], p.g1X, p.g1Y)
		setBN254G2Affine(&g2s[i], p.g2XC0, p.g2XC1, p.g2YC0, p.g2YC1)
		if !g1s[i].IsOnCurve() {
			return false, errECPointOffCurve
		}
		if !g2s[i].IsOnCurve() {
			return false, errECPointOffCurve
		}
		// BN254 G1 has cofactor 1, so on-curve implies in-subgroup. G2
		// requires an explicit subgroup test for security per EIP-197.
		if !g2s[i].IsInSubGroup() {
			return false, errECG2NotInSubgroup
		}
	}
	return gnarkbn254.PairingCheck(g1s, g2s)
}

func setBN254G2Affine(p *gnarkbn254.G2Affine, xC0, xC1, yC0, yC1 *big.Int) {
	if xC0.Sign() == 0 && xC1.Sign() == 0 && yC0.Sign() == 0 && yC1.Sign() == 0 {
		p.X.A0.SetZero()
		p.X.A1.SetZero()
		p.Y.A0.SetZero()
		p.Y.A1.SetZero()
		return
	}
	p.X.A0.SetBigInt(xC0)
	p.X.A1.SetBigInt(xC1)
	p.Y.A0.SetBigInt(yC0)
	p.Y.A1.SetBigInt(yC1)
}

// secp256r1 / NIST P-256 — Go standard library.

// crypto/elliptic's Curve.IsOnCurve, Curve.Add, and Curve.ScalarMult are
// marked deprecated because the higher-level packages crypto/ecdh and
// crypto/ecdsa cover most consumers. We need the raw point arithmetic for
// the EC opcodes, so the deprecation is intentionally suppressed below.

// ecAddSecp256r1 adds two affine P-256 points. Validates on-curve manually
// because crypto/elliptic.P256().IsOnCurve rejects (0, 0) — the spec uses
// that pair as the wire representation of the point at infinity.
func ecAddSecp256r1(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int, error) {
	inf1 := x1.Sign() == 0 && y1.Sign() == 0
	inf2 := x2.Sign() == 0 && y2.Sign() == 0
	curve := elliptic.P256()
	if !inf1 && !curve.IsOnCurve(x1, y1) { //nolint:staticcheck
		return nil, nil, errECPointOffCurve
	}
	if !inf2 && !curve.IsOnCurve(x2, y2) { //nolint:staticcheck
		return nil, nil, errECPointOffCurve
	}
	switch {
	case inf1 && inf2:
		return new(big.Int), new(big.Int), nil
	case inf1:
		return new(big.Int).Set(x2), new(big.Int).Set(y2), nil
	case inf2:
		return new(big.Int).Set(x1), new(big.Int).Set(y1), nil
	}
	rx, ry := curve.Add(x1, y1, x2, y2) //nolint:staticcheck
	return rx, ry, nil
}

// ecMulSecp256r1 returns k * P on P-256. P=(0,0) and k=0 both produce
// infinity. The caller must enforce 0 ≤ k < group order.
func ecMulSecp256r1(x, y, k *big.Int) (*big.Int, *big.Int, error) {
	curve := elliptic.P256()
	inf := x.Sign() == 0 && y.Sign() == 0
	if !inf && !curve.IsOnCurve(x, y) { //nolint:staticcheck
		return nil, nil, errECPointOffCurve
	}
	if inf || k.Sign() == 0 {
		return new(big.Int), new(big.Int), nil
	}
	rx, ry := curve.ScalarMult(x, y, k.Bytes()) //nolint:staticcheck
	return rx, ry, nil
}
