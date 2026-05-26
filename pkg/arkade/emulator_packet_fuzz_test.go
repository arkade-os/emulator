package arkade

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func FuzzDeserializeEmulatorPacket(f *testing.F) {
	fix := readFixtures(f)

	for _, tc := range fix.Valid {
		data, err := hex.DecodeString(tc.Encoded)
		require.NoError(f, err)
		f.Add(data)
	}

	for _, tc := range fix.Invalid {
		if tc.Encoded == "" {
			continue
		}
		data, err := hex.DecodeString(tc.Encoded)
		require.NoError(f, err)
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := DeserializeEmulatorPacket(data)
		if err != nil {
			return
		}

		reencoded, err := packet.Serialize()
		require.NoError(t, err)

		_, err = DeserializeEmulatorPacket(reencoded)
		require.NoError(t, err)
	})
}
