package handlers

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestParseIntent(t *testing.T) {
	proof := newProofB64(t)
	future := time.Now().Add(time.Hour).Unix()

	base := func(tp intent.IntentMessageType) intent.BaseMessage {
		return intent.BaseMessage{Type: tp}
	}

	tests := []struct {
		name     string
		proof    string
		message  string
		wantType interface{} // expected concrete type behind Intent.Message
		wantErr  string
	}{
		{
			name:     "register",
			proof:    proof,
			message:  encodeMsg(t, intent.RegisterMessage{BaseMessage: base(intent.IntentMessageTypeRegister), ExpireAt: future}),
			wantType: &intent.RegisterMessage{},
		},
		{
			name:     "estimate-fee",
			proof:    proof,
			message:  encodeMsg(t, intent.EstimateIntentFeeMessage{BaseMessage: base(intent.IntentMessageTypeEstimateFee), ExpireAt: future}),
			wantType: &intent.EstimateIntentFeeMessage{},
		},
		{
			name:     "delete",
			proof:    proof,
			message:  encodeMsg(t, intent.DeleteMessage{BaseMessage: base(intent.IntentMessageTypeDelete), ExpireAt: future}),
			wantType: &intent.DeleteMessage{},
		},
		{
			name:     "get-pending-tx",
			proof:    proof,
			message:  encodeMsg(t, intent.GetPendingTxMessage{BaseMessage: base(intent.IntentMessageTypeGetPendingTx), ExpireAt: future}),
			wantType: &intent.GetPendingTxMessage{},
		},
		{
			name:     "get-intent",
			proof:    proof,
			message:  encodeMsg(t, intent.GetIntentMessage{BaseMessage: base(intent.IntentMessageTypeGetIntent), ExpireAt: future}),
			wantType: &intent.GetIntentMessage{},
		},
		{
			name:     "get-data",
			proof:    proof,
			message:  encodeMsg(t, intent.GetDataMessage{BaseMessage: base(intent.IntentMessageTypeGetData), ExpireAt: future}),
			wantType: &intent.GetDataMessage{},
		},
		{
			name:    "missing proof",
			proof:   "",
			message: encodeMsg(t, intent.DeleteMessage{BaseMessage: base(intent.IntentMessageTypeDelete)}),
			wantErr: "missing proof",
		},
		{
			name:    "missing message",
			proof:   proof,
			message: "",
			wantErr: "missing message",
		},
		{
			name:    "invalid proof",
			proof:   "not-a-psbt",
			message: encodeMsg(t, intent.DeleteMessage{BaseMessage: base(intent.IntentMessageTypeDelete)}),
			wantErr: "invalid proof",
		},
		{
			name:    "unsupported type",
			proof:   proof,
			message: `{"type":"bogus"}`,
			wantErr: "unsupported intent message type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseIntent(&emulatorv1.Intent{Proof: tc.proof, Message: tc.message})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Nil(t, result)
				return
			}
			require.NoError(t, err)
			require.IsType(t, tc.wantType, result.Message)
		})
	}
}

func encodeMsg(t *testing.T, m interface{ Encode() (string, error) }) string {
	t.Helper()
	s, err := m.Encode()
	require.NoError(t, err)
	return s
}

func newProofB64(t *testing.T) string {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}}) // OP_TRUE
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	encoded, err := ptx.B64Encode()
	require.NoError(t, err)
	return encoded
}
