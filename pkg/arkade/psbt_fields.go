package arkade

import (
	"bytes"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

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

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(unknown.Value)); err != nil {
		return nil, err
	}

	return tx, nil
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

	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(unknown.Value)); err != nil {
		return nil, err
	}

	return tx, nil
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
