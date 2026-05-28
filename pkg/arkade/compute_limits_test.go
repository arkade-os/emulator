package arkade

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeLimitsCompileLookup(t *testing.T) {
	c := ComputeLimits{Groups: []OpcodeGroup{
		{Name: "first", Limit: 3, Opcodes: []byte{OP_ECADD, OP_ECMUL}},
		{Name: "second", Limit: 7, Opcodes: []byte{OP_MODEXP}},
	}}
	compiled := c.compile()

	require.Equal(t, 0, compiled.groupOf[OP_ECADD])
	require.Equal(t, 0, compiled.groupOf[OP_ECMUL])
	require.Equal(t, 1, compiled.groupOf[OP_MODEXP])
	// Ungrouped opcodes map to -1.
	require.Equal(t, -1, compiled.groupOf[OP_DUP])

	require.Equal(t, []int{3, 7}, compiled.limits)
	require.Equal(t, []string{"first", "second"}, compiled.names)
}

func TestComputeLimitsValidateRejectsDuplicateOpcode(t *testing.T) {
	c := ComputeLimits{Groups: []OpcodeGroup{
		{Name: "a", Limit: 1, Opcodes: []byte{OP_ECADD}},
		{Name: "b", Limit: 1, Opcodes: []byte{OP_ECADD}},
	}}
	require.Error(t, c.Validate())
}

func TestComputeLimitsValidateRejectsNegativeLimit(t *testing.T) {
	c := ComputeLimits{Groups: []OpcodeGroup{
		{Name: "a", Limit: -1, Opcodes: []byte{OP_ECADD}},
	}}
	require.Error(t, c.Validate())
}

func TestComputeLimitsValidateAcceptsWellFormed(t *testing.T) {
	require.NoError(t, DefaultComputeLimits().Validate())
}

func TestComputeLimitsCompilePanicsOnInvalid(t *testing.T) {
	c := ComputeLimits{Groups: []OpcodeGroup{
		{Name: "a", Limit: 1, Opcodes: []byte{OP_ECADD}},
		{Name: "b", Limit: 1, Opcodes: []byte{OP_ECADD}},
	}}
	require.Panics(t, func() { _ = c.compile() })
}

func TestDefaultComputeLimitsIsIndependentCopy(t *testing.T) {
	c1 := DefaultComputeLimits()
	c1.Groups[0].Limit = 99999
	c1.Groups[0].Opcodes[0] = OP_NOP

	c2 := DefaultComputeLimits()
	require.NotEqual(t, 99999, c2.Groups[0].Limit,
		"mutating a returned copy must not affect later calls")
	require.NotEqual(t, byte(OP_NOP), c2.Groups[0].Opcodes[0],
		"opcode slices must be deep-copied")
}

func TestDefaultCompiledLimitsCoversHeavyOpcodes(t *testing.T) {
	heavy := []byte{
		OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD,
		OP_CHECKSIGFROMSTACK,
		OP_ECADD, OP_ECMUL, OP_ECPAIRING,
		OP_ECMULSCALARVERIFY, OP_TWEAKVERIFY,
		OP_MODEXP,
	}
	for _, op := range heavy {
		require.GreaterOrEqualf(t, defaultCompiledLimits.groupOf[op], 0,
			"opcode 0x%02x must belong to a compute-limit group", op)
	}
}
