package application

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/stretchr/testify/require"
)

func TestValidateMessage(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour).Unix()
	future := now.Add(time.Hour).Unix()

	tests := []struct {
		name    string
		message IntentMessage
		wantErr string // "" means the message is accepted
	}{
		// every type is accepted inside a valid window
		{"register valid", &intent.RegisterMessage{ValidAt: past, ExpireAt: future}, ""},
		{"estimate-fee valid", &intent.EstimateIntentFeeMessage{ValidAt: past, ExpireAt: future}, ""},
		{"delete valid", &intent.DeleteMessage{ExpireAt: future}, ""},
		{"get-pending-tx valid", &intent.GetPendingTxMessage{ExpireAt: future}, ""},
		{"get-intent valid", &intent.GetIntentMessage{ExpireAt: future}, ""},
		{"get-data valid", &intent.GetDataMessage{ExpireAt: future}, ""},

		// zero timestamps mean "no bound" -> always valid
		{"delete no expiry", &intent.DeleteMessage{}, ""},

		// expired (ExpireAt in the past)
		{"register expired", &intent.RegisterMessage{ExpireAt: past}, "expired"},
		{"delete expired", &intent.DeleteMessage{ExpireAt: past}, "expired"},

		// not valid yet (only register/estimate-fee carry ValidAt)
		{"register not valid yet", &intent.RegisterMessage{ValidAt: future}, "not valid yet"},
		{"estimate-fee not valid yet", &intent.EstimateIntentFeeMessage{ValidAt: future}, "not valid yet"},

		// a message type the switch doesn't handle
		{"unsupported type", unknownMessage{}, "unsupported intent message type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMessage(tc.message)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// unknownMessage satisfies IntentMessage but is not one of the six arkd types,
// so it exercises validateMessage's default branch.
type unknownMessage struct{}

func (unknownMessage) Encode() (string, error) { return "", nil }
func (unknownMessage) Decode(string) error     { return nil }
