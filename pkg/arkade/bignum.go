package arkade

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/btcsuite/btcd/txscript"
)

// maxBigNumLen is the largest permitted byte-length of a minimally-encoded
// BigNum operand or result. Equal to txscript.MaxScriptElementSize.
const maxBigNumLen = txscript.MaxScriptElementSize

// int64ByteCap is the largest byte length whose minimal sign-magnitude LE
// encoding is guaranteed to fit in int64. 9+ bytes require the big.Int path.
const int64ByteCap = 8

var (
	ErrBigNumDivisionByZero     = errors.New("division by zero")
	ErrBigNumModuloByZero       = errors.New("modulo by zero")
	ErrBigNumModulusNotPositive = errors.New("modulus must be positive")
	ErrBigNumNegativeExponent   = errors.New("negative exponent")
)

// BigNum is the unified numeric type used by the arkade VM. It is a tagged
// union: when useBig is false the value lives in small (fast path). When
// useBig is true the value lives in big (arbitrary precision). Promotion
// from small → big is one-way; an arithmetic result that fits in int64
// after having been produced on the big path is NOT demoted.
type BigNum struct {
	small  int64
	big    *big.Int
	useBig bool
}

// Bytes returns the minimal sign-magnitude little-endian encoding of n.
// If the encoding would exceed maxBigNumLen, an ErrNumberTooBig is returned.
func (n BigNum) Bytes() ([]byte, error) {
	var out []byte
	if !n.useBig {
		out = encodeInt64(n.small)
	} else {
		out = encodeBig(n.big)
	}
	if len(out) > maxBigNumLen {
		return nil, scriptError(txscript.ErrNumberTooBig,
			fmt.Sprintf("BigNum result encoded as %d bytes exceeds max allowed of %d",
				len(out), maxBigNumLen))
	}
	return out, nil
}

// FixedBytes returns n encoded as exactly size bytes in sign-magnitude
// little-endian form. It pads with zero bytes between the magnitude and sign
// bit, and fails if the minimally encoded value cannot fit in size bytes.
func (n BigNum) FixedBytes(size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("negative fixed size %d", size)
	}

	encoded, err := n.Bytes()
	if err != nil {
		return nil, err
	}
	if len(encoded) > size {
		return nil, fmt.Errorf("number needs %d bytes, size=%d", len(encoded), size)
	}

	out := make([]byte, size)
	if len(encoded) == 0 {
		return out, nil
	}

	sign := encoded[len(encoded)-1] & 0x80
	magnitude := append([]byte(nil), encoded...)
	magnitude[len(magnitude)-1] &= 0x7f
	if magnitude[len(magnitude)-1] == 0 {
		magnitude = magnitude[:len(magnitude)-1]
	}

	copy(out, magnitude)
	out[len(out)-1] |= sign
	return out, nil
}

// IsZero reports whether n equals zero.
func (n BigNum) IsZero() bool {
	if !n.useBig {
		return n.small == 0
	}
	return n.big.Sign() == 0
}

// Sign returns -1, 0, or +1.
func (n BigNum) Sign() int {
	if n.useBig {
		return n.big.Sign()
	}
	return cmp.Compare(n.small, int64(0))
}

// BigInt returns n as a fresh *big.Int. The returned value is independent of
// n's internal state; callers may mutate it freely.
func (n BigNum) BigInt() *big.Int {
	if n.useBig {
		return new(big.Int).Set(n.big)
	}
	return big.NewInt(n.small)
}

// Cmp reports -1/0/+1 comparing n and m.
func (n BigNum) Cmp(m BigNum) int {
	if n.useBig || m.useBig {
		return n.BigInt().Cmp(m.BigInt())
	}
	return cmp.Compare(n.small, m.small)
}

// Add returns n + m. Promotes to big on int64 overflow.
func (n BigNum) Add(m BigNum) BigNum {
	if !n.useBig && !m.useBig {
		r := n.small + m.small
		// Detect signed overflow for n.small + m.small.
		//
		// In two's complement, overflow occurs iff both operands have the
		// same sign and the result has the opposite sign. Each XOR below has
		// its sign bit set when r differs in sign from that operand. If both
		// sign bits are set, the AND is negative, so the sum overflowed.
		//
		// Example:
		//   n = 01111111...11111111 (MaxInt64)
		//   m = 00000000...00000001
		//   r = 10000000...00000000 (wrapped MinInt64)
		//
		//   r ^ n = 11111111...11111111
		//   r ^ m = 10000000...00000001
		//   AND   = 10000000...00000001 (negative => overflow)
		if (r^n.small)&(r^m.small) >= 0 {
			return BigNum{small: r}
		}
	}
	return BigNum{big: new(big.Int).Add(n.BigInt(), m.BigInt()), useBig: true}
}

// Sub returns n - m. Promotes to big on int64 overflow.
func (n BigNum) Sub(m BigNum) BigNum {
	if !n.useBig && !m.useBig {
		r := n.small - m.small
		// Detect signed overflow for n.small - m.small.
		//
		// Subtraction overflows iff the operands have opposite signs and the
		// result has the opposite sign from n.small. The first XOR checks the
		// operand signs; the second checks whether r changed sign from n.
		//
		// Example:
		//   n = 10000000...00000000 (MinInt64)
		//   m = 00000000...00000001
		//   r = 01111111...11111111 (wrapped MaxInt64)
		//
		//   n ^ m = 10000000...00000001
		//   n ^ r = 11111111...11111111
		//   AND   = 10000000...00000001 (negative => overflow)
		if (n.small^m.small)&(n.small^r) >= 0 {
			return BigNum{small: r}
		}
	}
	return BigNum{big: new(big.Int).Sub(n.BigInt(), m.BigInt()), useBig: true}
}

// Mul returns n * m. Promotes to big on int64 overflow.
func (n BigNum) Mul(m BigNum) BigNum {
	if !n.useBig && !m.useBig {
		if n.small == 0 || m.small == 0 {
			return BigNum{small: 0}
		}
		r := n.small * m.small
		if r/n.small == m.small {
			return BigNum{small: r}
		}
	}
	return BigNum{big: new(big.Int).Mul(n.BigInt(), m.BigInt()), useBig: true}
}

// Div returns truncated n / m. Promotes only on int64 min / -1 overflow.
func (n BigNum) Div(m BigNum) (BigNum, error) {
	if m.IsZero() {
		return BigNum{}, ErrBigNumDivisionByZero
	}
	if !n.useBig && !m.useBig {
		if n.small != math.MinInt64 || m.small != -1 {
			return BigNum{small: n.small / m.small}, nil
		}
	}
	return BigNum{big: new(big.Int).Quo(n.BigInt(), m.BigInt()), useBig: true}, nil
}

// Mod returns truncated n % m (sign follows dividend).
func (n BigNum) Mod(m BigNum) (BigNum, error) {
	if m.IsZero() {
		return BigNum{}, ErrBigNumModuloByZero
	}
	if !n.useBig && !m.useBig {
		if n.small != math.MinInt64 || m.small != -1 {
			return BigNum{small: n.small % m.small}, nil
		}
	}
	return BigNum{big: new(big.Int).Rem(n.BigInt(), m.BigInt()), useBig: true}, nil
}

// Modexp returns n^exp mod modulus in the canonical range [0, modulus).
// Returns ErrBigNumModulusNotPositive if modulus <= 0.
// Returns ErrBigNumNegativeExponent if exp is negative.
//
// The result is always carried on the big.Int path; no demotion to the
// int64 fast path is performed (consistent with the file-level policy).
func (n BigNum) Modexp(exp, modulus BigNum) (BigNum, error) {
	if modulus.Sign() <= 0 {
		return BigNum{}, ErrBigNumModulusNotPositive
	}
	if exp.Sign() < 0 {
		return BigNum{}, ErrBigNumNegativeExponent
	}
	res := new(big.Int).Exp(n.BigInt(), exp.BigInt(), modulus.BigInt())
	return BigNum{big: res, useBig: true}, nil
}

// Negate returns -n. Promotes on int64 min.
func (n BigNum) Negate() BigNum {
	if !n.useBig {
		if n.small != math.MinInt64 {
			return BigNum{small: -n.small}
		}
	}
	return BigNum{big: new(big.Int).Neg(n.BigInt()), useBig: true}
}

// Abs returns |n|. Promotes on int64 min.
func (n BigNum) Abs() BigNum {
	if !n.useBig {
		if n.small >= 0 {
			return n
		}
		if n.small != math.MinInt64 {
			return BigNum{small: -n.small}
		}
	}
	return BigNum{big: new(big.Int).Abs(n.BigInt()), useBig: true}
}

// Lshift returns n << shift. Fails if the minimal encoding of the result
// would exceed maxBigNumLen bytes.
func (n BigNum) Lshift(shift uint) (BigNum, error) {
	if n.IsZero() {
		return n, nil
	}
	// Early fail: an n > 0 shifted by more than maxBigNumLen*8 bits cannot fit.
	if shift > uint(maxBigNumLen*8) {
		return BigNum{}, scriptError(txscript.ErrNumberTooBig,
			fmt.Sprintf("LSHIFT result would exceed %d bytes", maxBigNumLen))
	}
	res := new(big.Int).Lsh(n.BigInt(), shift)
	out := BigNum{big: res, useBig: true}
	if _, err := out.Bytes(); err != nil {
		return BigNum{}, err
	}
	return out, nil
}

// Rshift returns n >> shift with arithmetic semantics:
//   - rounds toward negative infinity (e.g., -7 >> 1 == -4, -1 >> any == -1)
//   - shifting a positive value by more than its bit-width yields 0
//   - shifting a negative value by more than its bit-width yields -1
func (n BigNum) Rshift(shift uint) BigNum {
	if n.IsZero() {
		return n
	}
	// big.Int.Rsh operates on two's-complement representation and rounds
	// toward negative infinity for negative values, matching our spec.
	res := new(big.Int).Rsh(n.BigInt(), shift)
	return BigNum{big: res, useBig: true}
}

// BigNumFromInt64 constructs a BigNum on the int64 fast path.
func BigNumFromInt64(v int64) BigNum {
	return BigNum{small: v}
}

// BigNumFromUint64 constructs a BigNum from an unsigned 64-bit value. Values
// up to math.MaxInt64 use the int64 fast path; larger values promote to big.
func BigNumFromUint64(v uint64) BigNum {
	if v <= math.MaxInt64 {
		return BigNum{small: int64(v)}
	}
	return BigNum{big: new(big.Int).SetUint64(v), useBig: true}
}

// BigNumFromBytes decodes a sign-magnitude little-endian byte slice into a
// BigNum. Inputs longer than maxBigNumLen bytes are rejected with
// ErrNumberTooBig. Non-minimal encodings (including negative zero [0x80])
// are rejected with ErrMinimalData.
//
// Values with len(v) ≤ 8 land on the int64 fast path; ≥ 9 bytes land on the
// big.Int path.
func BigNumFromBytes(v []byte) (BigNum, error) {
	if len(v) > maxBigNumLen {
		return BigNum{}, scriptError(txscript.ErrNumberTooBig,
			fmt.Sprintf("numeric value encoded as %x is %d bytes which exceeds the max allowed of %d",
				v, len(v), maxBigNumLen))
	}
	if err := checkMinimalDataEncoding(v); err != nil {
		return BigNum{}, err
	}
	if len(v) == 0 {
		return BigNum{}, nil
	}
	if len(v) <= int64ByteCap {
		return decodeInt64(v), nil
	}
	return decodeBig(v), nil
}

// minimallyEncode returns the minimal sign-magnitude LE encoding of the
// byte slice v (interpreting v as sign-magnitude LE). It strips trailing
// zero-bytes while preserving the sign bit, and normalises negative zero
// ([0x80], [0x00, 0x00, 0x80], etc.) to the empty slice.
func minimallyEncode(v []byte) []byte {
	if len(v) == 0 {
		return []byte{}
	}
	out := append([]byte(nil), v...)
	sign := out[len(out)-1] & 0x80
	// Clear sign bit from MSB so we can detect an all-zero magnitude.
	out[len(out)-1] &= 0x7f
	out = bytes.TrimRight(out, "\x00")
	if len(out) == 0 {
		return []byte{}
	}
	// If new MSB's high bit is set, we need a sign-extension byte.
	if out[len(out)-1]&0x80 != 0 {
		out = append(out, sign) // sign byte is either 0x00 (positive) or 0x80 (negative)
	} else if sign != 0 {
		out[len(out)-1] |= sign
	}
	return out
}

// decodeInt64 parses up to 8 bytes of sign-magnitude LE into int64.
// Pre: 0 ≤ len(v) ≤ 8.
func decodeInt64(v []byte) BigNum {
	if len(v) == 0 {
		return BigNum{}
	}

	var result int64
	for i, b := range v {
		result |= int64(b) << uint(8*i)
	}
	// Strip sign bit from most significant byte and apply sign.
	if v[len(v)-1]&0x80 != 0 {
		result &= ^(int64(0x80) << uint(8*(len(v)-1)))
		return BigNum{small: -result}
	}
	return BigNum{small: result}
}

// decodeBig parses ≥ 9 bytes of sign-magnitude LE into a *big.Int.
// Pre: len(v) ≥ 9.
func decodeBig(v []byte) BigNum {
	msb := v[len(v)-1]
	negative := msb&0x80 != 0
	mag := make([]byte, len(v))
	copy(mag, v)
	mag[len(mag)-1] = msb & 0x7f
	// Reverse to big-endian for big.Int.SetBytes.
	slices.Reverse(mag)
	b := new(big.Int).SetBytes(mag)
	if negative {
		b.Neg(b)
	}
	return BigNum{big: b, useBig: true}
}

// encodeInt64 reproduces the legacy scriptNum.Bytes() algorithm for int64.
func encodeInt64(v int64) []byte {
	if v == 0 {
		return nil
	}
	neg := v < 0
	var mag uint64
	if neg {
		// Avoid overflowing when v == math.MinInt64.
		mag = uint64(-(v + 1)) + 1
	} else {
		mag = uint64(v)
	}
	result := make([]byte, 0, 9)
	for mag > 0 {
		result = append(result, byte(mag&0xff))
		mag >>= 8
	}
	if result[len(result)-1]&0x80 != 0 {
		extra := byte(0x00)
		if neg {
			extra = 0x80
		}
		result = append(result, extra)
	} else if neg {
		result[len(result)-1] |= 0x80
	}
	return result
}

// encodeBig serialises a *big.Int as minimal sign-magnitude LE.
func encodeBig(v *big.Int) []byte {
	if v.Sign() == 0 {
		return nil
	}
	le := new(big.Int).Abs(v).Bytes() // big-endian magnitude
	slices.Reverse(le)
	neg := v.Sign() < 0
	if le[len(le)-1]&0x80 != 0 {
		extra := byte(0x00)
		if neg {
			extra = 0x80
		}
		le = append(le, extra)
	} else if neg {
		le[len(le)-1] |= 0x80
	}
	return le
}
