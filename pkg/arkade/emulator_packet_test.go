package arkade

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire/v2"
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

// buildBigWitnessPacket serializes a packet of entryCount entries, each
// carrying itemCount witness items of itemLen bytes. Every entry stays within
// the per-entry MaxScriptLength / MaxWitnessLength caps (and every item within
// the 10_000-byte per-item cap txutils.ReadTxWitness enforces), so only an
// aggregate budget can reject the result.
func buildBigWitnessPacket(t *testing.T, entryCount, itemCount, itemLen int) []byte {
	t.Helper()
	entries := make([]EmulatorEntry, entryCount)
	for i := range entries {
		witness := make(wire.TxWitness, itemCount)
		for j := range witness {
			witness[j] = make([]byte, itemLen)
		}
		entries[i] = EmulatorEntry{
			Vin:     uint16(i),
			Script:  []byte{0x51},
			Witness: witness,
		}
	}
	packet := EmulatorPacket(entries)
	data, err := packet.Serialize()
	require.NoError(t, err)
	return data
}

// TestEmulatorPacketAggregateSize covers the aggregate allocation budget:
// per-entry caps alone let a single OP_RETURN payload drive ~1 GB of
// allocation, and a declared length is honoured before the input is known to
// hold that many bytes.
func TestEmulatorPacketAggregateSize(t *testing.T) {
	t.Run("per-entry caps alone allow an absurd aggregate", func(t *testing.T) {
		// What the per-entry caps permit on their own, with no total budget.
		worstCase := MaxEntryCount * (MaxScriptLength + MaxWitnessLength)
		require.Greater(t, worstCase, 1_000_000_000,
			"per-entry caps alone allow >1GB from one packet")

		// The total budget must cut that down to the size of one maximal entry.
		require.Equal(t, MaxScriptLength+MaxWitnessLength, MaxTotalEntrySize)
	})

	t.Run("aggregate over budget is rejected", func(t *testing.T) {
		// Two entries, each individually legal, together well over budget.
		data := buildBigWitnessPacket(t, 2, 100, 9_000)
		require.Greater(t, len(data), MaxTotalEntrySize)

		_, err := DeserializeEmulatorPacket(data)
		require.ErrorContains(t, err, "max emulator total entry size exceeded")
	})

	t.Run("aggregate within budget is accepted", func(t *testing.T) {
		data := buildBigWitnessPacket(t, 2, 50, 4_000)
		require.LessOrEqual(t, len(data), MaxTotalEntrySize)

		packet, err := DeserializeEmulatorPacket(data)
		require.NoError(t, err)
		require.Len(t, packet, 2)
	})

	t.Run("declared witness length is not allocated before it is read", func(t *testing.T) {
		// entry_count=1, vin=0, script_len=1, script=OP_TRUE,
		// witness_len=1_000_000 — and then the payload simply ends.
		var payload bytes.Buffer
		require.NoError(t, wire.WriteVarInt(&payload, 0, 1))
		require.NoError(t, binary.Write(&payload, binary.LittleEndian, uint16(0)))
		require.NoError(t, wire.WriteVarInt(&payload, 0, 1))
		payload.WriteByte(0x51)
		require.NoError(t, wire.WriteVarInt(&payload, 0, MaxWitnessLength))
		data := payload.Bytes()
		require.Less(t, len(data), 32, "attack payload is tiny")

		const iterations = 200
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for range iterations {
			_, err := DeserializeEmulatorPacket(data)
			require.Error(t, err)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)

		allocated := after.TotalAlloc - before.TotalAlloc
		// Unfixed, each call allocates MaxWitnessLength bytes up front:
		// ~200MB total from ~4KB of attacker input.
		require.Less(t, allocated, uint64(iterations*MaxWitnessLength/10),
			"declared witness length must not be allocated before the input is known to hold it")
	})
}

// TestEmulatorPacketVinValidation covers rejection of duplicate vin values and
// of vin values that do not address an input of the spending transaction.
func TestEmulatorPacketVinValidation(t *testing.T) {
	t.Run("duplicate vin is rejected", func(t *testing.T) {
		packet := EmulatorPacket{
			{Vin: 3, Script: []byte{0x51}},
			{Vin: 3, Script: []byte{0x52}},
		}
		data, err := packet.Serialize()
		require.NoError(t, err)

		_, err = DeserializeEmulatorPacket(data)
		require.ErrorContains(t, err, "duplicate vin 3")
	})

	t.Run("vin out of range for the tx is rejected", func(t *testing.T) {
		packet := EmulatorPacket{{Vin: 5, Script: []byte{0x51}}}
		out, err := extension.Extension{packet}.TxOut()
		require.NoError(t, err)

		tx := &wire.MsgTx{
			Version: 3,
			TxIn:    []*wire.TxIn{{}, {}},
			TxOut:   []*wire.TxOut{out},
		}

		_, err = FindEmulatorPacket(tx)
		require.ErrorContains(t, err, "vin 5 out of range")
	})

	t.Run("vin within range for the tx is accepted", func(t *testing.T) {
		packet := EmulatorPacket{{Vin: 1, Script: []byte{0x51}}}
		out, err := extension.Extension{packet}.TxOut()
		require.NoError(t, err)

		tx := &wire.MsgTx{
			Version: 3,
			TxIn:    []*wire.TxIn{{}, {}},
			TxOut:   []*wire.TxOut{out},
		}

		got, err := FindEmulatorPacket(tx)
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, uint16(1), got[0].Vin)
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
