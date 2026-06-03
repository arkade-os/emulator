package cashupool

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPoolState_RoundTrip(t *testing.T) {
	t.Parallel()

	prevRoot := make([]byte, 32)
	newRoot := make([]byte, 32)
	for i := range prevRoot {
		prevRoot[i] = byte(i + 1)
	}
	for i := range newRoot {
		newRoot[i] = byte(i + 0x80)
	}

	s := PoolState{
		PrevRoot: prevRoot,
		NewRoot:  newRoot,
		Size:     7,
	}

	b := s.Serialize()
	require.Len(t, b, PoolStateSize, "serialized length must be 68 bytes")

	got, err := ParsePoolState(b)
	require.NoError(t, err)
	require.Equal(t, s, got)
}

func TestPoolState_WrongLength(t *testing.T) {
	t.Parallel()

	_, err := ParsePoolState(make([]byte, 67))
	require.Error(t, err, "67 bytes should fail")

	_, err = ParsePoolState(make([]byte, 69))
	require.Error(t, err, "69 bytes should fail")
}

func TestPoolState_FieldOffsets(t *testing.T) {
	t.Parallel()

	prevRoot := make([]byte, 32)
	newRoot := make([]byte, 32)
	for i := range prevRoot {
		prevRoot[i] = byte(i + 1)
	}
	for i := range newRoot {
		newRoot[i] = byte(i + 0x40)
	}

	s := PoolState{
		PrevRoot: prevRoot,
		NewRoot:  newRoot,
		Size:     0xDEADBEEF,
	}

	b := s.Serialize()

	require.Equal(t, prevRoot, b[OffPrevRoot:OffNewRoot], "PrevRoot bytes at expected offset")
	require.Equal(t, newRoot, b[OffNewRoot:OffSize], "NewRoot bytes at expected offset")
	require.Equal(t, uint32(0xDEADBEEF), binary.LittleEndian.Uint32(b[OffSize:PoolStateSize]), "Size LE at expected offset")
}
