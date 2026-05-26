package application

import (
	"context"
	"fmt"
	"time"

	"github.com/ArkLabsHQ/emulator/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// SubmitIntent aims to execute arkade scripts on unsigned intent proof
// it must be used before registration of the intent
func (s *service) SubmitIntent(ctx context.Context, intent Intent) (*psbt.Packet, error) {
	if err := validateRegisterMessage(intent.Message); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	ptx := &intent.Proof.Packet

	prevOutFetcher, err := prevOutFetcherForIntent(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	// Parse EmulatorPacket from the transaction's OP_RETURN output
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse emulator packet: %w", err)
	}

	if len(packet) == 0 {
		return nil, fmt.Errorf("no emulator packet found in transaction")
	}

	for _, entry := range packet {
		inputIndex := int(entry.Vin)

		if inputIndex == 0 {
			// in intent proof, input index 0 is the message input
			// the signature script equals to the input 1 script
			// so we can skip it and handle it later if input index 1 is an arkade script
			continue
		}

		matchedSigner, script, err := resolveArkadeScriptSigner(s.signer, s.deprecatedSigners, ptx, entry)
		if err != nil {
			// skip if the input is not a valid arkade script
			continue
		}

		if err := script.Execute(
			ptx.UnsignedTx,
			prevOutFetcher,
			inputIndex,
		); err != nil {
			log.WithError(err).WithField("input_index", inputIndex).Error("arkade script execution failed")
			return nil, fmt.Errorf("failed to execute arkade script at input %d: %w", inputIndex, err)
		}

		if err := matchedSigner.signInput(ptx, inputIndex, script.Hash(), prevOutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		// if input index 1 is valid and signed, we can also sign the intent message input (index 0)
		if inputIndex == 1 {
			if err := matchedSigner.signInput(ptx, 0, script.Hash(), prevOutFetcher); err != nil {
				return nil, fmt.Errorf("failed to sign fake message input: %w", err)
			}
		}
	}

	return ptx, nil
}

func validateRegisterMessage(message intent.RegisterMessage) error {
	now := time.Now()
	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if expireAt.Before(now) {
			return fmt.Errorf("intent message expired")
		}
	}

	if message.ValidAt > 0 {
		validAt := time.Unix(message.ValidAt, 0)
		if validAt.After(now) {
			return fmt.Errorf("intent message not valid yet")
		}
	}

	return nil
}
