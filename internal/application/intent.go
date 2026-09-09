package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// SubmitIntent aims to execute arkade scripts on unsigned intent proof
// it must be used before registration of the intent
func (s *service) SubmitIntent(ctx context.Context, intent Intent) (*psbt.Packet, error) {
	if err := validateMessage(intent.Message); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}
	encodedMessage, err := intent.Message.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode intent message: %w", err)
	}
	if err := validateIntentMessageCommitment(intent, encodedMessage); err != nil {
		return nil, fmt.Errorf("intent message is not committed by the proof: %w", err)
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

	budget := arkade.NewComputeBudgetWithLimits(arkade.AggregateComputeLimits(s.computeLimits))

	var nSigned = 0
	for _, entry := range packet {
		inputIndex := int(entry.Vin)

		if inputIndex == 0 {
			// in intent proof, input index 0 is the message input
			// the signature script equals to the input 1 script
			// so we can skip it and handle it later if input index 1 is an arkade script
			continue
		}

		matchedSigner, script, err := resolveArkadeScriptSigner(s.signer, s.activeDeprecatedSigners(), ptx, entry)
		if err != nil {
			// there may be input/entry pairs attributed to a different signer
			if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) && len(ptx.Inputs) > 1 {
				continue
			}
			return nil, fmt.Errorf("failed to read arkade script: %w vin=%d", err, inputIndex)
		}

		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		expiry, err := s.expiryForScript(
			ctx, script.Script(), outpoint.Hash.String(), outpoint.Index,
		)
		if err != nil {
			return nil, err
		}

		if err := script.Execute(
			ptx.UnsignedTx,
			prevOutFetcher,
			inputIndex,
			arkade.WithIntentMessage(encodedMessage),
			arkade.WithExactComputeLimits(s.computeLimits),
			arkade.WithComputeBudget(budget),
			arkade.WithExpiry(expiry),
		); err != nil {
			log.WithError(err).WithField("input_index", inputIndex).Error("arkade script execution failed")
			return nil, fmt.Errorf("failed to execute arkade script at input %d: %w", inputIndex, err)
		}

		if err := matchedSigner.signInput(ptx, inputIndex, script.Hash(), prevOutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		// if input index 1 is valid and signed, we can also sign the intent message input (index 0)
		if inputIndex == 1 {
			// the message input is signed with input 1's script hash, so it must
			// really carry input 1's script: the vm never executes input 0 on its
			// own, nothing else would bind the signature to the executed script
			if !bytes.Equal(
				ptx.Inputs[0].WitnessUtxo.PkScript, ptx.Inputs[1].WitnessUtxo.PkScript,
			) {
				return nil, fmt.Errorf("message input script does not match input 1 script")
			}

			if err := matchedSigner.signInput(ptx, 0, script.Hash(), prevOutFetcher); err != nil {
				return nil, fmt.Errorf("failed to sign fake message input: %w", err)
			}
		}

		nSigned++
	}

	if nSigned == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}

	return ptx, nil
}

func (s *service) expiryForScript(
	ctx context.Context, script []byte, txid string, vout uint32,
) (int64, error) {
	tokenizer := arkade.MakeScriptTokenizer(0, script)
	needsExpiry := false
	for tokenizer.Next() {
		needsExpiry = needsExpiry || tokenizer.Opcode() == arkade.OP_PUSHEXPIRY
	}
	if err := tokenizer.Err(); err != nil {
		return 0, err
	}
	if !needsExpiry {
		return 0, nil
	}

	response, err := s.indexerClient.GetVtxos(
		withClientVersion(ctx, s.clientVersion),
		indexer.WithOutpoints([]types.Outpoint{{Txid: txid, VOut: vout}}),
	)
	if err != nil {
		return 0, err
	}
	if response != nil {
		for _, vtxo := range response.Vtxos {
			if vtxo.Txid != txid || vtxo.VOut != vout {
				continue
			}
			expiresAt := vtxo.ExpiresAt.Unix()
			if expiresAt <= 0 {
				return 0, fmt.Errorf("vtxo %s:%d has no expiry", txid, vout)
			}
			return expiresAt, nil
		}
	}
	return 0, fmt.Errorf("vtxo %s:%d not found", txid, vout)
}

// validateIntentMessageCommitment checks that the proof's synthetic message
// input (index 0) was derived from encodedMessage. Since encodedMessage is the
// server-side canonical re-encoding of the decoded message, a client that
// signed a non-canonical encoding fails the outpoint comparison here.
func validateIntentMessageCommitment(request Intent, encodedMessage string) error {
	ptx := &request.Proof.Packet
	if len(ptx.UnsignedTx.TxIn) < 2 || len(ptx.Inputs) < 2 || ptx.Inputs[1].WitnessUtxo == nil {
		return fmt.Errorf("proof is missing its first ownership input witness utxo")
	}
	firstInput := ptx.UnsignedTx.TxIn[1]
	expected, err := intent.New(encodedMessage, []intent.Input{{
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

// validateMessage checks intent admission policy and the proof's validity window.
func validateMessage(message IntentMessage) error {
	var validAt, expireAt int64
	switch m := message.(type) {
	case *intent.RegisterMessage:
		if len(m.OnchainOutputIndexes) > 0 {
			return fmt.Errorf("onchain outputs are not supported")
		}
		validAt, expireAt = m.ValidAt, m.ExpireAt
	case *intent.EstimateIntentFeeMessage:
		validAt, expireAt = m.ValidAt, m.ExpireAt
	case *intent.DeleteMessage:
		expireAt = m.ExpireAt
	case *intent.GetPendingTxMessage:
		expireAt = m.ExpireAt
	case *intent.GetIntentMessage:
		expireAt = m.ExpireAt
	case *intent.GetDataMessage:
		expireAt = m.ExpireAt
	default:
		return fmt.Errorf("unsupported intent message type")
	}

	now := time.Now()
	if expireAt > 0 && time.Unix(expireAt, 0).Before(now) {
		return fmt.Errorf("intent message expired")
	}
	if validAt > 0 && time.Unix(validAt, 0).After(now) {
		return fmt.Errorf("intent message not valid yet")
	}

	return nil
}
