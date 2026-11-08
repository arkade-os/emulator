package arkade

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestPrevArkTxField(t *testing.T) {
	t.Run("encode and decode", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(1)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx.TxHash()

		err := txutils.SetArkPsbtField(ptx, 0, PrevArkTxField, *prevTx)
		require.NoError(t, err)

		fields, err := txutils.GetArkPsbtFields(ptx, 0, PrevArkTxField)
		require.NoError(t, err)
		require.Len(t, fields, 1)
		require.Equal(t, prevTx.TxHash(), fields[0].TxHash())
	})
}

func TestPrevoutTxField(t *testing.T) {
	t.Run("encode and decode", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		prevTx := newTestPrevoutTx(2)
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = prevTx.TxHash()

		err := txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *prevTx)
		require.NoError(t, err)

		fields, err := txutils.GetArkPsbtFields(ptx, 0, PrevoutTxField)
		require.NoError(t, err)
		require.Len(t, fields, 1)
		require.Equal(t, prevTx.TxHash(), fields[0].TxHash())
	})

	t.Run("does not collide with PrevArkTxField", func(t *testing.T) {
		ptx := newTestPSBT(t, 1)
		arkTx := newTestPrevoutTx(1)
		outTx := newTestPrevoutTx(2)

		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, PrevArkTxField, *arkTx))
		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, PrevoutTxField, *outTx))

		arkFields, err := txutils.GetArkPsbtFields(ptx, 0, PrevArkTxField)
		require.NoError(t, err)
		require.Len(t, arkFields, 1)
		require.Equal(t, arkTx.TxHash(), arkFields[0].TxHash())

		outFields, err := txutils.GetArkPsbtFields(ptx, 0, PrevoutTxField)
		require.NoError(t, err)
		require.Len(t, outFields, 1)
		require.Equal(t, outTx.TxHash(), outFields[0].TxHash())
	})
}

// TestPrevoutTxFieldRejectsOversizedValue proves the prevout tx coders bound the
// blob they hand to Deserialize, so an attacker cannot drive unbounded parse
// work and allocation before any other validation runs.
func TestPrevoutTxFieldRejectsOversizedValue(t *testing.T) {
	coders := map[string]struct {
		keyData []byte
		coder   txutils.ArkPsbtFieldCoder[wire.MsgTx]
	}{
		"prevarktx": {ArkFieldPrevArkTx, PrevArkTxField},
		"prevouttx": {ArkFieldPrevoutTx, PrevoutTxField},
	}

	for name, c := range coders {
		t.Run(name, func(t *testing.T) {
			t.Run("oversized value is rejected", func(t *testing.T) {
				unknown := &psbt.Unknown{
					Key:   makeArkPsbtKey(c.keyData),
					Value: make([]byte, MaxPrevoutTxLength+1),
				}

				_, err := c.coder.Decode(unknown)
				require.ErrorContains(t, err, "max prevout tx length exceeded")
			})

			t.Run("value at the cap is still parsed", func(t *testing.T) {
				prevTx := newTestPrevoutTx(3)

				unknown, err := c.coder.Encode(*prevTx)
				require.NoError(t, err)
				require.LessOrEqual(t, len(unknown.Value), MaxPrevoutTxLength)

				decoded, err := c.coder.Decode(unknown)
				require.NoError(t, err)
				require.Equal(t, prevTx.TxHash(), decoded.TxHash())
			})
		})
	}
}

func newTestPSBT(t *testing.T, numInputs int) *psbt.Packet {
	t.Helper()

	ptx, err := psbt.New(nil, nil, 2, 0, nil)
	require.NoError(t, err)

	ptx.UnsignedTx.TxIn = make([]*wire.TxIn, 0, numInputs)
	ptx.Inputs = make([]psbt.PInput, 0, numInputs)

	for i := 0; i < numInputs; i++ {
		ptx.UnsignedTx.TxIn = append(ptx.UnsignedTx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: uint32(i),
			},
		})
		ptx.Inputs = append(ptx.Inputs, psbt.PInput{})
	}

	return ptx
}

func newTestPrevoutTx(tag byte) *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{tag},
			Index: 0,
		},
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    int64(tag) + 1,
		PkScript: []byte{txscript.OP_TRUE},
	})
	return tx
}
