package application

import (
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateIntentMessageCommitment(t *testing.T) {
	message := &intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		ExpireAt:    time.Now().Add(time.Hour).Unix(),
	}
	encoded, err := message.Encode()
	require.NoError(t, err)

	proof, err := intent.New(encoded, []intent.Input{{
		OutPoint:    &wire.OutPoint{Index: 1},
		WitnessUtxo: &wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}},
	}}, nil)
	require.NoError(t, err)

	request := emulator.Intent{Proof: *proof, Message: encoded}
	require.NoError(t, validateIntentMessageCommitment(request))

	// a proof bound to non-canonical bytes fails the outpoint comparison
	request.Message = " " + encoded
	require.ErrorContains(t, validateIntentMessageCommitment(request), "synthetic message input")
	request.Message = strings.Replace(encoded, `"expire_at":`, `"expire_at":1,"expire_at":`, 1)
	require.ErrorContains(t, validateIntentMessageCommitment(request), "synthetic message input")

	request.Message = encoded
	request.Proof.UnsignedTx.TxIn[0].PreviousOutPoint.Hash[0] ^= 0xff
	require.ErrorContains(t, validateIntentMessageCommitment(request), "synthetic message input")
}
