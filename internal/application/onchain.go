package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// SubmitOnchainTx executes arkade scripts on a plain Bitcoin PSBT and signs
// every input whose tapscript closure contains the introspector's tweaked
// key.
// Rejects any input whose tapscript closure also contains the arkd signer
// pubkey: those inputs must go through SubmitTx so that the offchain
// checks (checkpoints, forfeit flow) are enforced. Accepting them here
// would be a path to bypass those checks.
func (s *service) SubmitOnchainTx(ctx context.Context, tx OnchainTx) (*psbt.Packet, error) {
	ptx := tx.Tx

	prevOutFetcher, err := prevOutFetcherForOnchainTx(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	packet, err := arkade.FindIntrospectorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse introspector packet: %w", err)
	}
	if len(packet) == 0 {
		return nil, fmt.Errorf("no introspector packet found in transaction")
	}

	nSigned := 0

	for _, entry := range packet {
		inputIndex := int(entry.Vin)

		matchedSigner, script, err := resolveArkadeScriptSigner(s.signer, s.deprecatedSigners, ptx, entry)
		if err != nil {
			if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) && len(ptx.Inputs) > 1 {
				continue
			}
			return nil, fmt.Errorf("failed to read arkade script: %w vin=%d", err, inputIndex)
		}

		if containsPubKey(script.ClosurePubKeys(), s.arkdPubKey) {
			return nil, fmt.Errorf(
				"tapscript on input #%d contains arkd signer pubkey: can't be used onchain",
				inputIndex,
			)
		}

		log.Debugf("executing arkade script: %x", script.Script())
		if err := script.Execute(ptx.UnsignedTx, prevOutFetcher, inputIndex); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w vin=%d", err, inputIndex)
		}
		log.Debugf("execution of %x succeeded", script.Script())

		if err := matchedSigner.signInput(ptx, inputIndex, script.Hash(), prevOutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		nSigned++
	}

	if nSigned == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}

	return ptx, nil
}

func containsPubKey(pubkeys []*btcec.PublicKey, target *btcec.PublicKey) bool {
	if target == nil {
		return false
	}
	want := schnorr.SerializePubKey(target)
	for _, pk := range pubkeys {
		if pk == nil {
			continue
		}
		if bytes.Equal(schnorr.SerializePubKey(pk), want) {
			return true
		}
	}
	return false
}
