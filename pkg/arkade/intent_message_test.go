package arkade

import (
	"bytes"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func TestSimpleIntentMessagePath(t *testing.T) {
	for _, path := range []string{"type", "nested.value", "items.0", "items.1048575", "a_b", "_meta"} {
		require.True(t, isSimpleIntentMessagePath(path), path)
	}
	for _, path := range []string{
		"", ".type", "type.", "a..b", "*", "items.#", "@this", "items.#(type)",
		"a|b", "Type", "1field", "items.00", "items.1048576",
		"items.18446744073709551616",
	} {
		require.False(t, isSimpleIntentMessagePath(path), path)
	}
}

func TestParseJSONInteger(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		integer bool
	}{
		{raw: "1", want: "1", integer: true},
		{raw: "-0", want: "0", integer: true},
		{raw: "1.0", want: "1", integer: true},
		{raw: "1e3", want: "1000", integer: true},
		{raw: "10e-1", want: "1", integer: true},
		{raw: "1.5e1", want: "15", integer: true},
		{raw: "1e-1", integer: false},
		{raw: "1.5", integer: false},
		{raw: "1e-9223372036854775808", integer: false},
		{raw: "1e-999999999", integer: false},
	}

	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			t.Parallel()
			got, integer, err := parseJSONInteger(test.raw)
			require.NoError(t, err)
			require.Equal(t, test.integer, integer)
			if integer {
				require.Equal(t, test.want, got.String())
			}
		})
	}

	_, _, err := parseJSONInteger("1e999999999")
	requireScriptErrorCode(t, err, txscript.ErrNumberTooBig)

	_, _, err = parseJSONInteger(strings.Repeat("9", maxBigNumDecimalDigitCount+1))
	requireScriptErrorCode(t, err, txscript.ErrNumberTooBig)
}

func BenchmarkInspectIntentMessage1MiB(b *testing.B) {
	prefix := []byte(`{"padding":"`)
	suffix := []byte(`","type":"register"}`)
	message := append(prefix, bytes.Repeat([]byte{'a'}, maxIntentMessageSize-len(prefix)-len(suffix))...)
	message = append(message, suffix...)
	vm := &Engine{intentMessage: message}

	b.ReportAllocs()
	b.SetBytes(int64(len(message)))
	for b.Loop() {
		vm.SetStack([][]byte{[]byte("type")})
		if err := opcodeInspectIntentMessage(nil, nil, vm); err != nil {
			b.Fatal(err)
		}
	}
}

func inspectIntentMessagePropertyChecker(t *testing.T, c opcodeCheckContext) {
	t.Helper()
	require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
	require.Equal(t, c.before.condStack, c.after.condStack)

	beforeDepth := len(c.before.GetStack())
	afterDepth := len(c.after.GetStack())
	if c.execErr != nil {
		requireScriptErrorCodeIn(t, c.execErr,
			txscript.ErrInvalidStackOperation,
			txscript.ErrNumberTooBig,
			txscript.ErrElementTooBig,
		)
		require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
		return
	}

	require.Equal(t, beforeDepth+1, afterDepth)
	flag := c.after.GetStack()[afterDepth-1]
	require.True(t, bytes.Equal(flag, nil) || bytes.Equal(flag, []byte{1}))
	require.LessOrEqual(t, len(c.after.GetStack()[afterDepth-2]), txscript.MaxScriptElementSize)
}
