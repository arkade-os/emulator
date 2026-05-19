package arkade

import (
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func TestBigNumFromBytesDecoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serialized []byte
		wantInt64  int64 // meaningful only when wantUseBig == false
		wantUseBig bool
		wantBigHex string // hex of absolute magnitude; sign encoded in wantSign
		wantSign   int    // -1, 0, 1 (big.Int.Sign())
	}{
		{"zero empty", nil, 0, false, "", 0},
		{"one", []byte{0x01}, 1, false, "", 0},
		{"neg one", []byte{0x81}, -1, false, "", 0},
		{"127", []byte{0x7f}, 127, false, "", 0},
		{"128", []byte{0x80, 0x00}, 128, false, "", 0},
		{"neg 128", []byte{0x80, 0x80}, -128, false, "", 0},
		// int64 boundary (max positive and min negative that fit in 8
		// minimally-encoded bytes)
		{"int64 max 8 bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, math.MaxInt64, false, "", 0},
		{"int64 min plus one 8 bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MinInt64 + 1, false, "", 0},
		// 9 bytes → big path. 2^63 has magnitude requiring 9 bytes
		// (sign-extension byte).
		{"2^63 as 9 bytes", nil, 0, true, "8000000000000000", 1},
		{"-2^63 as 9 bytes", nil, 0, true, "8000000000000000", -1},
	}

	// Encode the 9-byte fixtures properly.
	twoPow63 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00}
	negTwoPow63 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80}

	for i := range tests {
		if tests[i].name == "2^63 as 9 bytes" {
			tests[i].serialized = twoPow63
		}
		if tests[i].name == "-2^63 as 9 bytes" {
			tests[i].serialized = negTwoPow63
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BigNumFromBytes(tc.serialized)
			require.NoError(t, err)
			require.Equal(t, tc.wantUseBig, got.useBig)
			if !tc.wantUseBig {
				require.Equal(t, tc.wantInt64, got.small)
				return
			}
			require.NotNil(t, got.big)
			wantMag, _ := new(big.Int).SetString(tc.wantBigHex, 16)
			gotMag := new(big.Int).Abs(got.big)
			require.Zero(t, gotMag.Cmp(wantMag), "big magnitude = %s, want %s", gotMag.Text(16), tc.wantBigHex)
			require.Equal(t, tc.wantSign, got.big.Sign())
		})
	}
}

func TestBigNumFromBytesRejectsOversized(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, maxBigNumLen+1)
	_, err := BigNumFromBytes(oversized)
	require.Error(t, err, "expected error for %d-byte operand", maxBigNumLen+1)
	require.True(t, isScriptError(err, txscript.ErrNumberTooBig), "want ErrNumberTooBig, got %v", err)
}

func TestBigNumFromBytesRejectsNonMinimal(t *testing.T) {
	t.Parallel()
	// Non-minimal: [0x01, 0x00] should be [0x01].
	_, err := BigNumFromBytes([]byte{0x01, 0x00})
	require.True(t, isScriptError(err, txscript.ErrMinimalData), "want ErrMinimalData, got %v", err)
	// Negative zero is not minimal.
	_, err = BigNumFromBytes([]byte{0x80})
	require.True(t, isScriptError(err, txscript.ErrMinimalData), "want ErrMinimalData for negative zero, got %v", err)
}

// isScriptError reports whether err is a txscript.Error with the given code.
func isScriptError(err error, code txscript.ErrorCode) bool {
	if err == nil {
		return false
	}
	asErr, ok := err.(txscript.Error)
	if !ok {
		return false
	}
	return asErr.ErrorCode == code
}

func TestBigNumBytesEncoding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  BigNum
		want []byte
	}{
		{"zero int64", BigNumFromInt64(0), nil},
		{"one", BigNumFromInt64(1), []byte{0x01}},
		{"neg one", BigNumFromInt64(-1), []byte{0x81}},
		{"127", BigNumFromInt64(127), []byte{0x7f}},
		{"128", BigNumFromInt64(128), []byte{0x80, 0x00}},
		{"neg 128", BigNumFromInt64(-128), []byte{0x80, 0x80}},
		{"255", BigNumFromInt64(255), []byte{0xff, 0x00}},
		{"neg 255", BigNumFromInt64(-255), []byte{0xff, 0x80}},
		{"int64 max", BigNumFromInt64(math.MaxInt64), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}},
		{"int64 min plus one", BigNumFromInt64(math.MinInt64 + 1), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.src.Bytes()
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestBigNumFixedBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		src        BigNum
		size       int
		want       []byte
		shouldFail bool
	}{
		{"5 as 4 bytes", BigNumFromInt64(5), 4, []byte{0x05, 0x00, 0x00, 0x00}, false},
		{"-5 as 4 bytes", BigNumFromInt64(-5), 4, []byte{0x05, 0x00, 0x00, 0x80}, false},
		{"-5 as 1 byte", BigNumFromInt64(-5), 1, []byte{0x85}, false},
		{"0 as 4 bytes", BigNumFromInt64(0), 4, []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"0 as 0 bytes", BigNumFromInt64(0), 0, []byte{}, false},
		{"128 as 2 bytes", BigNumFromInt64(128), 2, []byte{0x80, 0x00}, false},
		{"-128 as 2 bytes", BigNumFromInt64(-128), 2, []byte{0x80, 0x80}, false},
		{"255 as 1 byte fails", BigNumFromInt64(255), 1, nil, true},
		{"128 as 1 byte fails", BigNumFromInt64(128), 1, nil, true},
		{"negative size fails", BigNumFromInt64(0), -1, nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.src.FixedBytes(tc.size)
			if tc.shouldFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDecodeInt64AcceptsEmptyZero(t *testing.T) {
	t.Parallel()

	got := decodeInt64(encodeInt64(0))
	require.False(t, got.useBig, "decodeInt64(encodeInt64(0)) = %+v, want zero on int64 path", got)
	require.Zero(t, got.small)
}

func TestInt64EncodingRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []int64{
		math.MinInt64,
		math.MinInt64 + 1,
		-1,
		0,
		1,
		math.MaxInt64,
	}
	for _, want := range tests {
		t.Run(fmt.Sprintf("%d", want), func(t *testing.T) {
			got, err := BigNumFromBytes(encodeInt64(want))
			require.NoError(t, err)
			require.Zero(t, got.BigInt().Cmp(big.NewInt(want)), "roundtrip = %s, want %d", got.BigInt(), want)
		})
	}
}

func TestBigIntEncodingRoundTrip(t *testing.T) {
	t.Parallel()

	maxInt64PlusOne := new(big.Int).SetUint64(math.MaxInt64 + 1)
	minInt64MinusOne := new(big.Int).Neg(new(big.Int).SetUint64(math.MaxInt64 + 2))
	maxUint64PlusOne := new(big.Int).Add(new(big.Int).SetUint64(math.MaxUint64), big.NewInt(1))

	max520ByteMagnitude := new(big.Int).Lsh(big.NewInt(1), uint(maxBigNumLen*8-2))
	negMax520ByteMagnitude := new(big.Int).Neg(new(big.Int).Set(max520ByteMagnitude))

	tests := []struct {
		name string
		want *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"max int64", big.NewInt(math.MaxInt64)},
		{"max int64 plus one", maxInt64PlusOne},
		{"min int64", big.NewInt(math.MinInt64)},
		{"min int64 minus one", minInt64MinusOne},
		{"max uint64", new(big.Int).SetUint64(math.MaxUint64)},
		{"max uint64 plus one", maxUint64PlusOne},
		{"max 520-byte positive", max520ByteMagnitude},
		{"max 520-byte negative", negMax520ByteMagnitude},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := BigNum{big: new(big.Int).Set(tc.want), useBig: true}
			encoded, err := src.Bytes()
			require.NoError(t, err)
			got, err := BigNumFromBytes(encoded)
			require.NoError(t, err)
			require.Zero(t, got.BigInt().Cmp(tc.want), "roundtrip = %s, want %s", got.BigInt(), tc.want)
		})
	}
}

func TestBigNumBytesBigPath(t *testing.T) {
	t.Parallel()
	// 2^63 as big.Int → minimal sign-magnitude LE is 9 bytes: magnitude plus
	// 0x00 sign ext.
	n := BigNum{big: new(big.Int).SetUint64(math.MaxInt64 + 1), useBig: true}
	got, err := n.Bytes()
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00}, got)
	// -(2^63)
	neg := BigNum{big: new(big.Int).Neg(new(big.Int).SetUint64(math.MaxInt64 + 1)), useBig: true}
	got, err = neg.Bytes()
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80}, got)
}

func TestBigNumBytesExceedsLimit(t *testing.T) {
	t.Parallel()
	// Construct a magnitude of 1 << (520*8) which requires 521 bytes as
	// sign-magnitude LE.
	magnitude := new(big.Int).Lsh(big.NewInt(1), 520*8)
	n := BigNum{big: magnitude, useBig: true}
	_, err := n.Bytes()
	require.True(t, isScriptError(err, txscript.ErrNumberTooBig), "want ErrNumberTooBig, got %v", err)
}

func TestBigNumFromUint64(t *testing.T) {
	t.Parallel()
	// Values that fit in int64 positive range use int64 path.
	n := BigNumFromUint64(12345)
	require.False(t, n.useBig, "small uint64 should be on int64 path")
	require.Equal(t, int64(12345), n.small)
	// Value at int64 max still uses the int64 path.
	n = BigNumFromUint64(math.MaxInt64)
	require.False(t, n.useBig, "max int64 should be on int64 path")
	require.Equal(t, int64(math.MaxInt64), n.small)
	// Value just above int64 max must use big path.
	n = BigNumFromUint64(math.MaxInt64 + 1)
	require.True(t, n.useBig, "max int64 plus one must use big path")
	want := new(big.Int).SetUint64(math.MaxInt64 + 1)
	require.Zero(t, n.big.Cmp(want), "big = %s, want %s", n.big, want)
	// Value at uint64 max (> int64 max) must use big path.
	n = BigNumFromUint64(math.MaxUint64)
	require.True(t, n.useBig, "max uint64 must use big path")
	want = new(big.Int).SetUint64(math.MaxUint64)
	require.Zero(t, n.big.Cmp(want), "big = %s, want %s", n.big, want)
}

func TestBigNumAddFastPath(t *testing.T) {
	t.Parallel()
	a := BigNumFromInt64(2)
	b := BigNumFromInt64(3)
	got := a.Add(b)
	require.False(t, got.useBig)
	require.Equal(t, int64(5), got.small)
}

func TestBigNumAddOverflowPromotes(t *testing.T) {
	t.Parallel()
	a := BigNumFromInt64(math.MaxInt64)
	b := BigNumFromInt64(1)
	got := a.Add(b)
	require.True(t, got.useBig, "expected promotion to big, got %+v", got)
	want := new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1))
	require.Zero(t, got.big.Cmp(want), "got %s, want %s", got.big, want)
}

func TestBigNumSubOverflowPromotes(t *testing.T) {
	t.Parallel()
	a := BigNumFromInt64(math.MinInt64)
	b := BigNumFromInt64(1)
	got := a.Sub(b)
	require.True(t, got.useBig, "expected promotion, got %+v", got)
}

func TestBigNumMulFastPathAndOverflow(t *testing.T) {
	t.Parallel()
	got := BigNumFromInt64(1_000_000).Mul(BigNumFromInt64(1_000_000))
	require.False(t, got.useBig)
	require.Equal(t, int64(1_000_000_000_000), got.small)
	big1 := BigNumFromInt64(1 << 32)
	got = big1.Mul(big1) // 2^64, overflows int64
	require.True(t, got.useBig, "expected promotion for 2^32 * 2^32, got %+v", got)
	want := new(big.Int).Lsh(big.NewInt(1), 64)
	require.Zero(t, got.big.Cmp(want), "got %s, want 2^64", got.big)
}

func TestBigNumDivAndModSignSemantics(t *testing.T) {
	t.Parallel()
	// Truncated division: sign of remainder follows dividend.
	q, err := BigNumFromInt64(-7).Div(BigNumFromInt64(2))
	require.NoError(t, err)
	r, err := BigNumFromInt64(-7).Mod(BigNumFromInt64(2))
	require.NoError(t, err)
	require.Equal(t, int64(-3), q.small)
	require.Equal(t, int64(-1), r.small)
	// 7 / -2 = -3 (truncated), 7 % -2 = 1.
	q, err = BigNumFromInt64(7).Div(BigNumFromInt64(-2))
	require.NoError(t, err)
	r, err = BigNumFromInt64(7).Mod(BigNumFromInt64(-2))
	require.NoError(t, err)
	require.Equal(t, int64(-3), q.small)
	require.Equal(t, int64(1), r.small)
}

func TestBigNumDivAndModByZero(t *testing.T) {
	t.Parallel()

	_, err := BigNumFromInt64(7).Div(BigNumFromInt64(0))
	require.ErrorIs(t, err, ErrBigNumDivisionByZero)

	_, err = BigNumFromInt64(7).Mod(BigNumFromInt64(0))
	require.ErrorIs(t, err, ErrBigNumModuloByZero)
}

func TestBigNumNegateOverflowPromotes(t *testing.T) {
	t.Parallel()
	a := BigNumFromInt64(math.MinInt64)
	got := a.Negate()
	require.True(t, got.useBig, "expected promotion, got %+v", got)
	want := new(big.Int).Neg(big.NewInt(math.MinInt64))
	require.Zero(t, got.big.Cmp(want), "got %s, want %s", got.big, want)
}

func TestBigNumAbs(t *testing.T) {
	t.Parallel()
	require.Equal(t, int64(5), BigNumFromInt64(-5).Abs().small)
	// abs of int64 min must promote.
	got := BigNumFromInt64(math.MinInt64).Abs()
	require.True(t, got.useBig, "abs(int64 min) must promote")
}

func TestBigNumLshift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, shift, want int64
	}{
		{1, 0, 1},
		{1, 8, 256},
		{-1, 8, -256},
		{5, 1, 10},
		{-5, 1, -10},
		{0, 100, 0},
	}
	for _, tc := range tests {
		got, err := BigNumFromInt64(tc.in).Lshift(uint(tc.shift))
		require.NoError(t, err, "Lshift(%d, %d)", tc.in, tc.shift)
		if got.useBig {
			require.Zero(t, got.BigInt().Cmp(big.NewInt(tc.want)),
				"Lshift(%d, %d) big = %s, want %d", tc.in, tc.shift, got.big, tc.want)
			continue
		}
		require.Equal(t, tc.want, got.small,
			"Lshift(%d, %d) small = %d, want %d", tc.in, tc.shift, got.small, tc.want)
	}
}

func TestBigNumLshiftExceeds520Bytes(t *testing.T) {
	t.Parallel()
	// Shifting a non-zero value by enough to exceed 520*8 = 4160 bits
	// produces a magnitude that can't fit in 520 bytes.
	_, err := BigNumFromInt64(1).Lshift(4161)
	require.True(t, isScriptError(err, txscript.ErrNumberTooBig), "want ErrNumberTooBig, got %v", err)
}

func TestBigNumRshiftArithmetic(t *testing.T) {
	t.Parallel()
	// Arithmetic shift: rounds toward negative infinity for negatives.
	tests := []struct {
		in, shift, want int64
	}{
		{7, 1, 3},
		{-7, 1, -4}, // -4 (floor(-3.5) = -4)
		{-1, 1, -1}, // -1 >> any = -1
		{-1, 100, -1},
		{8, 3, 1},
		{-8, 3, -1},
		{-9, 3, -2}, // floor(-1.125) = -2
		{0, 10, 0},
	}
	for _, tc := range tests {
		got := BigNumFromInt64(tc.in).Rshift(uint(tc.shift))
		require.Zero(t, got.BigInt().Cmp(big.NewInt(tc.want)),
			"Rshift(%d, %d) = %s, want %d", tc.in, tc.shift, got.BigInt(), tc.want)
	}
}

func TestMinimallyEncode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want []byte
	}{
		{nil, nil},
		{[]byte{}, nil},
		{[]byte{0x05, 0x00, 0x00, 0x00}, []byte{0x05}},
		{[]byte{0x00, 0x00, 0x00, 0x80}, nil},          // negative zero → zero
		{[]byte{0x05, 0x00, 0x00, 0x80}, []byte{0x85}}, // -5 padded
		{[]byte{0x05}, []byte{0x05}},                   // already minimal
		{[]byte{0x80, 0x00}, []byte{0x80, 0x00}},       // 128 needs sign-ext byte
		{[]byte{0x80, 0x00, 0x00}, []byte{0x80, 0x00}}, // 128 with extra padding
		{[]byte{0x00, 0x80}, nil},                      // -0 two-byte → zero
	}
	for i, tc := range tests {
		got := minimallyEncode(tc.in)
		want := tc.want
		if want == nil {
			want = []byte{}
		}
		require.Equal(t, want, got, "case %d: minimallyEncode(%x)", i, tc.in)
	}
}

func TestBigNumModexp(t *testing.T) {
	t.Parallel()

	t.Run("small", func(t *testing.T) {
		got, err := BigNumFromInt64(2).Modexp(
			BigNumFromInt64(10),
			BigNumFromInt64(1000),
		)
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(24).Cmp(got))
	})

	t.Run("exp_zero_nonzero_base", func(t *testing.T) {
		got, err := BigNumFromInt64(5).Modexp(
			BigNumFromInt64(0),
			BigNumFromInt64(7),
		)
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(1).Cmp(got))
	})

	t.Run("exp_zero_base_zero", func(t *testing.T) {
		got, err := BigNumFromInt64(0).Modexp(
			BigNumFromInt64(0),
			BigNumFromInt64(7),
		)
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(1).Cmp(got))
	})

	t.Run("base_zero_exp_positive", func(t *testing.T) {
		got, err := BigNumFromInt64(0).Modexp(
			BigNumFromInt64(5),
			BigNumFromInt64(7),
		)
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(0).Cmp(got))
	})

	t.Run("modulus_one", func(t *testing.T) {
		got, err := BigNumFromInt64(123456789).Modexp(
			BigNumFromInt64(42),
			BigNumFromInt64(1),
		)
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(0).Cmp(got))
	})

	t.Run("negative_base_reduces_canonically", func(t *testing.T) {
		got, err := BigNumFromInt64(-3).Modexp(
			BigNumFromInt64(2),
			BigNumFromInt64(5),
		)
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(4).Cmp(got))

		got, err = BigNumFromInt64(-2).Modexp(
			BigNumFromInt64(3),
			BigNumFromInt64(5),
		)
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(2).Cmp(got))
	})

	t.Run("fermat_inverse", func(t *testing.T) {
		inv, err := BigNumFromInt64(3).Modexp(
			BigNumFromInt64(5),
			BigNumFromInt64(7),
		)
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(5).Cmp(inv))

		product, err := BigNumFromInt64(3).Mul(inv).Mod(BigNumFromInt64(7))
		require.NoError(t, err)
		require.Zero(t, BigNumFromInt64(1).Cmp(product))
	})

	t.Run("rsa_sized_matches_bigint", func(t *testing.T) {
		p, ok := new(big.Int).SetString(
			"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
			16,
		)
		require.True(t, ok)
		base := mustBigNumFromBigInt(big.NewInt(65537))
		exp := mustBigNumFromBigInt(new(big.Int).Sub(p, big.NewInt(2)))
		mod := mustBigNumFromBigInt(p)

		got, err := base.Modexp(exp, mod)
		require.NoError(t, err)

		want := new(big.Int).Exp(big.NewInt(65537), new(big.Int).Sub(p, big.NewInt(2)), p)
		require.Equal(t, 0, want.Cmp(got.BigInt()))
	})

	t.Run("modulus_zero_rejected", func(t *testing.T) {
		_, err := BigNumFromInt64(2).Modexp(
			BigNumFromInt64(3),
			BigNumFromInt64(0),
		)
		require.ErrorIs(t, err, ErrBigNumModulusNotPositive)
	})

	t.Run("modulus_negative_rejected", func(t *testing.T) {
		_, err := BigNumFromInt64(2).Modexp(
			BigNumFromInt64(3),
			BigNumFromInt64(-7),
		)
		require.ErrorIs(t, err, ErrBigNumModulusNotPositive)
	})

	t.Run("negative_exponent_rejected", func(t *testing.T) {
		_, err := BigNumFromInt64(2).Modexp(
			BigNumFromInt64(-1),
			BigNumFromInt64(7),
		)
		require.ErrorIs(t, err, ErrBigNumNegativeExponent)
	})
}
