package arkade

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssembleScript(t *testing.T) {
	t.Parallel()

	txid := strings.Repeat("aa", 32)
	push76 := strings.Repeat("cd", 76)
	push300 := strings.Repeat("ef", 300)

	tests := []struct {
		name string
		asm  string
		want string
	}{
		{name: "empty"},
		{
			name: "standard opcodes and hex push",
			asm:  "OP_DUP OP_HASH160 aabbccdd OP_EQUALVERIFY",
			want: "76a904aabbccdd88",
		},
		{
			name: "opcodes without prefix",
			asm:  "DUP HASH160",
			want: "76a9",
		},
		{
			name: "small integer aliases",
			asm:  "OP_0 OP_1 OP_16 OP_TRUE OP_FALSE OP_1NEGATE",
			want: "00516051004f",
		},
		{
			name: "arkade opcodes",
			asm:  "OP_INSPECTPACKET INSPECTINASSETLOOKUP",
			want: "f4f2",
		},
		{
			name: "pushdata1",
			asm:  push76,
			want: "4c4c" + push76,
		},
		{
			name: "op_data",
			asm:  "OP_DATA_32 " + txid,
			want: "20" + push76,
		},
		{
			name: "pushdata2",
			asm:  push300,
			want: "4d2c01" + push300,
		},
		{
			name: "reader contract",
			asm:  "OP_0 " + txid + " OP_0 OP_INSPECTINASSETLOOKUP OP_1 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY OP_2 OP_INSPECTPACKET OP_1 OP_EQUALVERIFY efbeadde00000000 OP_EQUAL",
			want: "0020" + txid + "00f25188518852f4518808efbeadde0000000087",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := AssembleScript(test.asm)
			require.NoError(t, err)
			require.Equal(t, test.want, hex.EncodeToString(got))
		})
	}
}

func TestAssembleScriptRejectsInvalidToken(t *testing.T) {
	t.Parallel()

	for _, asm := range []string{"abc", "NOTAREALOPCODE"} {
		t.Run(asm, func(t *testing.T) {
			t.Parallel()

			_, err := AssembleScript(asm)
			require.Error(t, err)
		})
	}
}
