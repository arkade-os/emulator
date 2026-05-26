package arkade

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestEmulatorPacket(t *testing.T) {
	fix := readFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				expected, err := hex.DecodeString(f.Encoded)
				require.NoError(t, err)

				data, err := f.Packet.Serialize()
				require.NoError(t, err)
				require.Equal(t, expected, data)

				got, err := DeserializeEmulatorPacket(data)
				require.NoError(t, err)
				require.Len(t, got, len(f.Packet))

				for i := range f.Packet {
					require.Equal(t, f.Packet[i].Vin, got[i].Vin)
					require.Equal(t, f.Packet[i].Script, got[i].Script)
					require.Len(t, got[i].Witness, len(f.Packet[i].Witness))
					for j := range f.Packet[i].Witness {
						require.Equal(t, f.Packet[i].Witness[j], got[i].Witness[j])
					}
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fix.Invalid {
			t.Run(f.Name, func(t *testing.T) {
				if f.HasEntries {
					_, err := NewPacket(f.Entries...)
					require.Error(t, err)
				}
				if f.Encoded != "" {
					data, err := hex.DecodeString(f.Encoded)
					require.NoError(t, err)
					_, err = DeserializeEmulatorPacket(data)
					require.Error(t, err)
				}
			})
		}
	})

	t.Run("entry count exceeds max", func(t *testing.T) {
		entries := make([]EmulatorEntry, MaxEntryCount+1)
		for i := range entries {
			entries[i] = EmulatorEntry{
				Vin:    uint16(i),
				Script: []byte{0x01},
			}
		}

		_, err := NewPacket(entries...)
		require.EqualError(t, err, "max emulator entry count exceeded, max=1000 got=1001")
	})
}

type validFixture struct {
	Name    string         `json:"name"`
	Encoded string         `json:"encoded"`
	Packet  EmulatorPacket `json:"-"`
}

type invalidFixture struct {
	Name       string          `json:"name"`
	Encoded    string          `json:"encoded"`
	HasEntries bool            `json:"-"`
	Entries    []EmulatorEntry `json:"-"`
}

type fixtures struct {
	Valid   []validFixture
	Invalid []invalidFixture
}

type rawEntry struct {
	Vin     uint16   `json:"vin"`
	Script  string   `json:"script"`
	Witness []string `json:"witness"`
}

func decodeEntries(raw []rawEntry) []EmulatorEntry {
	entries := make([]EmulatorEntry, len(raw))
	for j, e := range raw {
		script, _ := hex.DecodeString(e.Script)
		witness := make(wire.TxWitness, len(e.Witness))
		for k, w := range e.Witness {
			witness[k], _ = hex.DecodeString(w)
		}
		entries[j] = EmulatorEntry{
			Vin:     e.Vin,
			Script:  script,
			Witness: witness,
		}
	}
	return entries
}

func readFixtures(t testing.TB) fixtures {
	t.Helper()
	raw, err := os.ReadFile("testdata/emulator_packet.json")
	require.NoError(t, err)

	var rawFixtures struct {
		Valid []struct {
			Name    string     `json:"name"`
			Encoded string     `json:"encoded"`
			Entries []rawEntry `json:"entries"`
		} `json:"valid"`
		Invalid []struct {
			Name    string      `json:"name"`
			Encoded string      `json:"encoded"`
			Entries *[]rawEntry `json:"entries"`
		} `json:"invalid"`
	}
	require.NoError(t, json.Unmarshal(raw, &rawFixtures))

	var fix fixtures
	for _, rf := range rawFixtures.Valid {
		entries := decodeEntries(rf.Entries)
		packet, err := NewPacket(entries...)
		require.NoError(t, err)
		fix.Valid = append(fix.Valid, validFixture{
			Name:    rf.Name,
			Encoded: rf.Encoded,
			Packet:  packet,
		})
	}
	for _, rf := range rawFixtures.Invalid {
		inv := invalidFixture{
			Name:    rf.Name,
			Encoded: rf.Encoded,
		}
		if rf.Entries != nil {
			inv.HasEntries = true
			inv.Entries = decodeEntries(*rf.Entries)
		}
		fix.Invalid = append(fix.Invalid, inv)
	}
	return fix
}
