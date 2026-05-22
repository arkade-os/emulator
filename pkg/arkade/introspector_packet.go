package arkade

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

const (
	// PacketType is the extension type for the Introspector Packet.
	PacketType = 0x01
	// MaxEntryCount is the maximum number of entries allowed in one packet.
	MaxEntryCount = 1_000
	// MaxScriptLength is the maximum script size per entry.
	MaxScriptLength = 10_000
	// MaxWitnessLength is the maximum serialized witness size per entry.
	MaxWitnessLength = 1_000_000
)

// IntrospectorEntry represents a single entry in the Introspector Packet.
type IntrospectorEntry struct {
	Vin     uint16         // Transaction input index (u16 LE)
	Script  []byte         // Arkade Script bytecode
	Witness wire.TxWitness // Script witness stack items
}

// IntrospectorPacket is a set of IntrospectorEntry items encoded as a TLV
// record inside an ARK extension OP_RETURN output.
type IntrospectorPacket []IntrospectorEntry

// NewPacket creates a validated IntrospectorPacket from the given entries.
func NewPacket(entries ...IntrospectorEntry) (IntrospectorPacket, error) {
	p := IntrospectorPacket(entries)
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// Validate checks that the packet is not empty and has no duplicate vin values.
func (p IntrospectorPacket) Validate() error {
	if len(p) == 0 {
		return fmt.Errorf("empty packet")
	}
	if len(p) > MaxEntryCount {
		return fmt.Errorf("max introspector entry count exceeded, max=%d got=%d", MaxEntryCount, len(p))
	}
	seen := make(map[uint16]bool, len(p))
	for i, entry := range p {
		if len(entry.Script) == 0 {
			return fmt.Errorf("empty script at entry %d", i)
		}
		if seen[entry.Vin] {
			return fmt.Errorf("duplicate vin %d at entry %d", entry.Vin, i)
		}
		seen[entry.Vin] = true
	}
	return nil
}

// Type returns the TLV type byte for the Introspector Packet,
// implementing the extension.Packet interface.
func (p IntrospectorPacket) Type() uint8 {
	return PacketType
}

// Serialize serializes the IntrospectorPacket to bytes.
func (p IntrospectorPacket) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	// Write entry count as varint
	if err := wire.WriteVarInt(&buf, 0, uint64(len(p))); err != nil {
		return nil, fmt.Errorf("failed to write entry count: %w", err)
	}

	for i, entry := range p {
		// Write vin as u16 LE
		if err := binary.Write(&buf, binary.LittleEndian, entry.Vin); err != nil {
			return nil, fmt.Errorf("failed to write vin for entry %d: %w", i, err)
		}

		// Write script_len + script
		if err := wire.WriteVarInt(&buf, 0, uint64(len(entry.Script))); err != nil {
			return nil, fmt.Errorf("failed to write script_len for entry %d: %w", i, err)
		}
		if _, err := buf.Write(entry.Script); err != nil {
			return nil, fmt.Errorf("failed to write script for entry %d: %w", i, err)
		}

		// Write witness (serialized as wire format, length-prefixed)
		var witBuf bytes.Buffer
		if err := psbt.WriteTxWitness(&witBuf, entry.Witness); err != nil {
			return nil, fmt.Errorf("failed to serialize witness for entry %d: %w", i, err)
		}
		if err := wire.WriteVarInt(&buf, 0, uint64(witBuf.Len())); err != nil {
			return nil, fmt.Errorf("failed to write witness_len for entry %d: %w", i, err)
		}
		if _, err := buf.Write(witBuf.Bytes()); err != nil {
			return nil, fmt.Errorf("failed to write witness for entry %d: %w", i, err)
		}
	}

	return buf.Bytes(), nil
}

// serializeIntrospectorPacketMasked is like Serialize, but omits the witness
// blob of every entry entirely (witness_len = 0, no witness bytes). It is the
// encoding used inside the non-standard arkade tapscript sighash, where
// witness data must be excluded from the digest so scripts can be pre-signed
// without committing to runtime witness arguments. The masked encoding is
// never broadcast — it exists only to feed sha_outputs in the digest pipeline.
func serializeIntrospectorPacketMasked(p IntrospectorPacket) ([]byte, error) {
	var buf bytes.Buffer

	if err := wire.WriteVarInt(&buf, 0, uint64(len(p))); err != nil {
		return nil, fmt.Errorf("failed to write entry count: %w", err)
	}

	for i, entry := range p {
		if err := binary.Write(&buf, binary.LittleEndian, entry.Vin); err != nil {
			return nil, fmt.Errorf("failed to write vin for entry %d: %w", i, err)
		}
		if err := wire.WriteVarInt(&buf, 0, uint64(len(entry.Script))); err != nil {
			return nil, fmt.Errorf("failed to write script_len for entry %d: %w", i, err)
		}
		if _, err := buf.Write(entry.Script); err != nil {
			return nil, fmt.Errorf("failed to write script for entry %d: %w", i, err)
		}
		// Mask: witness_len = 0, no witness bytes.
		if err := wire.WriteVarInt(&buf, 0, 0); err != nil {
			return nil, fmt.Errorf("failed to write masked witness_len for entry %d: %w", i, err)
		}
	}

	return buf.Bytes(), nil
}

// DeserializeIntrospectorPacket deserializes an IntrospectorPacket from bytes.
func DeserializeIntrospectorPacket(data []byte) (IntrospectorPacket, error) {
	r := bytes.NewReader(data)

	entryCount, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read entry count: %w", err)
	}
	if entryCount > MaxEntryCount {
		return nil, fmt.Errorf("max introspector entry count exceeded, max=%d got=%d", MaxEntryCount, entryCount)
	}

	entries := make([]IntrospectorEntry, 0, entryCount)
	for i := range entryCount {
		var entry IntrospectorEntry

		// Read vin (u16 LE)
		if err := binary.Read(r, binary.LittleEndian, &entry.Vin); err != nil {
			return nil, fmt.Errorf("failed to read vin for entry %d: %w", i, err)
		}

		// Read script
		scriptLen, err := wire.ReadVarInt(r, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to read script_len for entry %d: %w", i, err)
		}
		if scriptLen > MaxScriptLength {
			return nil, fmt.Errorf("max introspector script length exceeded, max=%d got=%d", MaxScriptLength, scriptLen)
		}
		entry.Script = make([]byte, scriptLen)
		if _, err := io.ReadFull(r, entry.Script); err != nil {
			return nil, fmt.Errorf("failed to read script for entry %d: %w", i, err)
		}

		// Read witness (raw bytes, then decode to TxWitness)
		witnessLen, err := wire.ReadVarInt(r, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to read witness_len for entry %d: %w", i, err)
		}
		if witnessLen > MaxWitnessLength {
			return nil, fmt.Errorf("max introspector witness length exceeded, max=%d got=%d", MaxWitnessLength, witnessLen)
		}
		witnessBytes := make([]byte, witnessLen)
		if _, err := io.ReadFull(r, witnessBytes); err != nil {
			return nil, fmt.Errorf("failed to read witness for entry %d: %w", i, err)
		}
		if len(witnessBytes) > 0 {
			entry.Witness, err = txutils.ReadTxWitness(witnessBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to decode witness for entry %d: %w", i, err)
			}
		}

		entries = append(entries, entry)
	}

	if r.Len() != 0 {
		return nil, fmt.Errorf("unexpected %d trailing bytes", r.Len())
	}

	return NewPacket(entries...)
}

// FindIntrospectorPacket scans a transaction's outputs for an OP_RETURN
// containing an ARK TLV stream with an Introspector Packet (Type 0x01).
// Returns the parsed packet, or nil if no packet is found.
func FindIntrospectorPacket(tx *wire.MsgTx) (IntrospectorPacket, error) {
	ext, err := extension.NewExtensionFromTx(tx)
	if err != nil {
		if errors.Is(err, extension.ErrExtensionNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to parse extension: %w", err)
	}
	for _, pkt := range ext {
		if pkt.Type() != PacketType {
			continue
		}
		unknownPacket, ok := pkt.(extension.UnknownPacket)
		if !ok {
			continue
		}

		return DeserializeIntrospectorPacket(unknownPacket.Data)
	}
	return nil, nil
}
