package arkade

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeLimitsValidateRejectsNegative(t *testing.T) {
	require.Error(t, ComputeLimits{OP_ECADD: -1}.Validate())
}

func TestComputeLimitsValidateAcceptsDefault(t *testing.T) {
	require.NoError(t, DefaultComputeLimits().Validate())
}

func TestDefaultComputeLimitsCoversHeavyOpcodes(t *testing.T) {
	heavy := []byte{
		OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD,
		OP_CHECKSIGFROMSTACK,
		OP_ECADD, OP_ECMUL, OP_ECPAIRING,
		OP_ECMULSCALARVERIFY, OP_TWEAKVERIFY,
		OP_MODEXP,
	}
	limits := DefaultComputeLimits()
	for _, op := range heavy {
		_, ok := limits[op]
		require.Truef(t, ok, "opcode %s must have a compute limit", opcodeArray[op].name)
	}
}
