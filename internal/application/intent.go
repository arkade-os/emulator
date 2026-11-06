package application

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/emulator/pkg/emulator"
)

// validateIntentMessageCommitment checks that the proof's synthetic message
// input (index 0) was derived from request.Message. Since the message is the
// canonical re-encoding of the decoded one, a client that signed a
// non-canonical encoding fails the outpoint comparison here.
func validateIntentMessageCommitment(request emulator.Intent) error {
	ptx := &request.Proof.Packet
	if len(ptx.UnsignedTx.TxIn) < 2 || len(ptx.Inputs) < 2 || ptx.Inputs[1].WitnessUtxo == nil {
		return fmt.Errorf("proof is missing its first ownership input witness utxo")
	}
	firstInput := ptx.UnsignedTx.TxIn[1]
	expected, err := intent.New(request.Message, []intent.Input{{
		OutPoint:    &firstInput.PreviousOutPoint,
		Sequence:    firstInput.Sequence,
		WitnessUtxo: ptx.Inputs[1].WitnessUtxo,
	}}, nil)
	if err != nil {
		return err
	}
	if ptx.UnsignedTx.TxIn[0].PreviousOutPoint != expected.UnsignedTx.TxIn[0].PreviousOutPoint {
		return fmt.Errorf("synthetic message input does not match the supplied message")
	}
	return nil
}
