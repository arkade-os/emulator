package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/internal/application"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

// parseIntent decodes the proof and intent message. The emulator takes every
// intent type through one endpoint, so it sniffs `BaseMessage.Type` then decodes
// the matching concrete struct.
func parseIntent(fromProto *emulatorv1.Intent) (*application.Intent, error) {
	proof := fromProto.GetProof()
	message := fromProto.GetMessage()

	if len(proof) <= 0 {
		return nil, fmt.Errorf("missing proof")
	}
	if len(message) <= 0 {
		return nil, fmt.Errorf("missing message")
	}

	proofPsbt, err := psbt.NewFromRawBytes(strings.NewReader(proof), true)
	if err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}

	// peek at the envelope to read the type
	var base intent.BaseMessage
	if err := json.Unmarshal([]byte(message), &base); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	// pick the concrete struct for that type
	var decoded application.IntentMessage
	switch base.Type {
	case intent.IntentMessageTypeRegister:
		decoded = &intent.RegisterMessage{}
	case intent.IntentMessageTypeEstimateFee:
		decoded = &intent.EstimateIntentFeeMessage{}
	case intent.IntentMessageTypeDelete:
		decoded = &intent.DeleteMessage{}
	case intent.IntentMessageTypeGetPendingTx:
		decoded = &intent.GetPendingTxMessage{}
	case intent.IntentMessageTypeGetIntent:
		decoded = &intent.GetIntentMessage{}
	case intent.IntentMessageTypeGetData:
		decoded = &intent.GetDataMessage{}
	default:
		return nil, fmt.Errorf("unsupported intent message type: %s", base.Type)
	}

	if err := decoded.Decode(message); err != nil {
		return nil, fmt.Errorf("invalid %s message: %w", base.Type, err)
	}

	return &application.Intent{
		Proof:   intent.Proof{Packet: *proofPsbt},
		Message: decoded,
	}, nil
}
