package arkade

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// MaxPrevoutTxLength is the maximum serialized size of a prevout transaction
// carried by a psbt field. The value is attacker controlled and reaches
// wire.MsgTx.Deserialize before any other validation, so it must be bounded to
// cap parse work and allocation.
const MaxPrevoutTxLength = 1_000_000

// decodePrevoutTx deserializes a bounded prevout transaction from a psbt field.
func decodePrevoutTx(value []byte) (*wire.MsgTx, error) {
	if len(value) > MaxPrevoutTxLength {
		return nil, fmt.Errorf(
			"max prevout tx length exceeded, max=%d got=%d", MaxPrevoutTxLength, len(value),
		)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(value)); err != nil {
		return nil, err
	}

	return tx, nil
}

var (
	ArkFieldPrevArkTx                                       = []byte("prevarktx")
	PrevArkTxField    txutils.ArkPsbtFieldCoder[wire.MsgTx] = arkPsbtFieldCoderPrevArkTx{}
)

type arkPsbtFieldCoderPrevArkTx struct{}

func (c arkPsbtFieldCoderPrevArkTx) Encode(tx wire.MsgTx) (*psbt.Unknown, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}

	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkFieldPrevArkTx),
		Value: buf.Bytes(),
	}, nil
}

func (c arkPsbtFieldCoderPrevArkTx) Decode(unknown *psbt.Unknown) (*wire.MsgTx, error) {
	if !containsArkPsbtKey(unknown, ArkFieldPrevArkTx) {
		return nil, nil
	}

	return decodePrevoutTx(unknown.Value)
}

var (
	ArkFieldPrevoutTx                                       = []byte("prevouttx")
	PrevoutTxField    txutils.ArkPsbtFieldCoder[wire.MsgTx] = arkPsbtFieldCoderPrevoutTx{}
)

type arkPsbtFieldCoderPrevoutTx struct{}

func (c arkPsbtFieldCoderPrevoutTx) Encode(tx wire.MsgTx) (*psbt.Unknown, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}

	return &psbt.Unknown{
		Key:   makeArkPsbtKey(ArkFieldPrevoutTx),
		Value: buf.Bytes(),
	}, nil
}

func (c arkPsbtFieldCoderPrevoutTx) Decode(unknown *psbt.Unknown) (*wire.MsgTx, error) {
	if !containsArkPsbtKey(unknown, ArkFieldPrevoutTx) {
		return nil, nil
	}

	return decodePrevoutTx(unknown.Value)
}

func makeArkPsbtKey(keyData []byte) []byte {
	return append([]byte{txutils.ArkPsbtFieldKeyType}, keyData...)
}

// Keep key matching strict here even though arkd's transitional decoder is
// currently looser. This field is newly introduced, so requiring the canonical
// [0xde]["prevarktx"] key prevents accidental matches against unrelated
// unknowns and makes malformed producer behavior fail closed.
func containsArkPsbtKey(unknownField *psbt.Unknown, keyFieldName []byte) bool {
	if len(unknownField.Key) == 0 {
		return false
	}

	return bytes.Equal(unknownField.Key, makeArkPsbtKey(keyFieldName))
}
