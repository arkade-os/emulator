package cashupool

import (
	"encoding/binary"
	"fmt"
)

// Byte-layout constants for the 68-byte on-chain pool-state packet.
// The layout is fixed so that an in-script OP_SUBSTR can pull fields at known
// offsets without any parsing logic.
const (
	PoolStateSize = 68 // total wire size in bytes

	OffPrevRoot = 0  // bytes [0:32]  — previous IMT root
	OffNewRoot  = 32 // bytes [32:64] — new IMT root after this tx's insert
	OffSize     = 64 // bytes [64:68] — occupied-leaf count (u32 LE)
)

// PoolState is the decoded form of the 68-byte pool-state packet carried in a
// custom 0x05 extension packet and read in-script via OP_INSPECTPACKET.
type PoolState struct {
	PrevRoot []byte // 32 bytes — previous IMT root
	NewRoot  []byte // 32 bytes — new IMT root after this tx's insert
	Size     uint32 // occupied-leaf count after this tx's insert
}

// Serialize returns prev_root(32) || new_root(32) || size_le(4).
// It panics if PrevRoot or NewRoot is not exactly 32 bytes (programmer error).
func (s PoolState) Serialize() []byte {
	if len(s.PrevRoot) != 32 {
		panic(fmt.Sprintf("cashupool: PoolState.PrevRoot must be 32 bytes, got %d", len(s.PrevRoot)))
	}
	if len(s.NewRoot) != 32 {
		panic(fmt.Sprintf("cashupool: PoolState.NewRoot must be 32 bytes, got %d", len(s.NewRoot)))
	}

	b := make([]byte, PoolStateSize)
	copy(b[OffPrevRoot:OffNewRoot], s.PrevRoot)
	copy(b[OffNewRoot:OffSize], s.NewRoot)
	binary.LittleEndian.PutUint32(b[OffSize:PoolStateSize], s.Size)
	return b
}

// ParsePoolState decodes a 68-byte payload into a PoolState.
// It returns an error if the payload length is not exactly PoolStateSize.
func ParsePoolState(b []byte) (PoolState, error) {
	if len(b) != PoolStateSize {
		return PoolState{}, fmt.Errorf("cashupool: ParsePoolState requires %d bytes, got %d", PoolStateSize, len(b))
	}

	prevRoot := make([]byte, 32)
	newRoot := make([]byte, 32)
	copy(prevRoot, b[OffPrevRoot:OffNewRoot])
	copy(newRoot, b[OffNewRoot:OffSize])
	size := binary.LittleEndian.Uint32(b[OffSize:PoolStateSize])

	return PoolState{
		PrevRoot: prevRoot,
		NewRoot:  newRoot,
		Size:     size,
	}, nil
}
