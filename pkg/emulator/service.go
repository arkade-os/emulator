// Package emulator executes ArkadeScript on Ark transactions.
package emulator

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
)

type Service interface {
	EmulateOffchainTx(context.Context, OffchainTx, OffchainData) ([]SignRequest, error)
	EmulateIntent(context.Context, Intent, OffchainData) ([]SignRequest, error)
	EmulateOnchainTx(context.Context, OnchainTx) ([]SignRequest, error)
	EmulateBatchFinalization(context.Context, BatchFinalization) ([]SignRequest, error)
}

type service struct {
	computeLimits arkade.ComputeLimits
}

func New(computeLimits arkade.ComputeLimits) Service {
	return &service{computeLimits}
}

// EmulateOffchainTx runs every emulator packet script on the ark tx and returns, per entry, the ark input and checkpoint input to sign.
func (s *service) EmulateOffchainTx(
	ctx context.Context, tx OffchainTx, data OffchainData,
) ([]SignRequest, error) {
	arkPtx := tx.ArkTx

	scripts, err := packetScripts(arkPtx)
	if err != nil {
		return nil, err
	}
	if len(scripts) == 0 {
		return nil, nil
	}

	indexedCheckpoints, err := indexCheckpoints(arkPtx, tx.Checkpoints)
	if err != nil {
		return nil, err
	}

	prevOutFetcher, err := prevOutFetcherForArkTx(arkPtx, tx.Checkpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	opts := s.executeOptions()

	requests := make([]SignRequest, 0, 2*len(scripts))
	for _, rs := range scripts {
		inputIndex, script := rs.vin, rs.script
		inputTxid := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.Hash.String()
		checkpointPtx := indexedCheckpoints[inputTxid]
		arkOutpoint := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if err := validateCheckpoint(
			arkPtx, inputIndex, checkpointPtx, prevOutFetcher.fetchVtxoPrevOut(arkOutpoint), script.TapLeaf(),
		); err != nil {
			return nil, fmt.Errorf("invalid checkpoint for input %d: %w", inputIndex, err)
		}
		prevArkTx := prevOutFetcher.FetchPrevOutArkTx(arkOutpoint)
		if prevArkTx == nil {
			return nil, fmt.Errorf("prevout ark tx not found for input %d", inputIndex)
		}
		vtxoOutpoint := wire.OutPoint{
			Hash: prevArkTx.TxHash(), Index: prevOutFetcher.prevOutIdxs[arkOutpoint],
		}
		expiry, err := expiryForScript(script.Script(), vtxoOutpoint, data.VtxoExpiries)
		if err != nil {
			return nil, err
		}

		log.Debugf("executing arkade script: %x", script.Script())
		if err := script.Execute(
			arkPtx.UnsignedTx,
			prevOutFetcher,
			inputIndex,
			append(opts, arkade.WithExpiry(expiry))...,
		); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w vin=%d", err, inputIndex)
		}
		log.Debugf("execution of %x succeeded", script.Script())

		arkReq, err := newSignRequest(arkPtx, inputIndex, script)
		if err != nil {
			return nil, fmt.Errorf("cannot request signature for input %d: %w", inputIndex, err)
		}
		cpReq, err := newSignRequest(checkpointPtx, 0, script)
		if err != nil {
			return nil, fmt.Errorf("cannot request signature for checkpoint input %d: %w", inputIndex, err)
		}
		requests = append(requests, arkReq, cpReq)
	}
	return requests, nil
}

// EmulateOnchainTx runs every emulator packet script on a plain Bitcoin PSBT and returns one request per entry.
func (s *service) EmulateOnchainTx(ctx context.Context, tx OnchainTx) ([]SignRequest, error) {
	ptx := tx.Tx

	scripts, err := packetScripts(ptx)
	if err != nil {
		return nil, err
	}
	if len(scripts) == 0 {
		return nil, nil
	}

	prevOutFetcher, err := prevOutFetcherForOnchainTx(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	opts := s.executeOptions()

	requests := make([]SignRequest, 0, len(scripts))
	for _, rs := range scripts {
		inputIndex, script := rs.vin, rs.script
		log.Debugf("executing arkade script: %x", script.Script())
		if err := script.Execute(
			ptx.UnsignedTx,
			prevOutFetcher,
			inputIndex,
			opts...,
		); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w vin=%d", err, inputIndex)
		}
		log.Debugf("execution of %x succeeded", script.Script())

		req, err := newSignRequest(ptx, inputIndex, script)
		if err != nil {
			return nil, fmt.Errorf("cannot request signature for input %d: %w", inputIndex, err)
		}
		requests = append(requests, req)
	}
	return requests, nil
}

// EmulateIntent runs every emulator packet script on an unsigned intent proof, before its registration.
func (s *service) EmulateIntent(
	ctx context.Context, intent Intent, data OffchainData,
) ([]SignRequest, error) {
	ptx := &intent.Proof.Packet

	scripts, err := packetScripts(ptx)
	if err != nil {
		return nil, err
	}
	if len(scripts) == 0 {
		return nil, nil
	}

	prevOutFetcher, err := prevOutFetcherForIntent(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	// input 0 is approved through input 1, whose script it carries
	scripts = slices.DeleteFunc(scripts, func(rs packetScript) bool { return rs.vin == 0 })
	if len(scripts) == 0 {
		return nil, fmt.Errorf("no input to execute")
	}

	opts := s.executeOptions()

	requests := make([]SignRequest, 0, len(scripts)+1)
	for _, rs := range scripts {
		inputIndex, script := rs.vin, rs.script
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		expiry, err := expiryForScript(script.Script(), outpoint, data.VtxoExpiries)
		if err != nil {
			return nil, err
		}

		if err := script.Execute(
			ptx.UnsignedTx,
			prevOutFetcher,
			inputIndex,
			append(opts, arkade.WithIntentMessage(intent.Message), arkade.WithExpiry(expiry))...,
		); err != nil {
			log.WithError(err).WithField("input_index", inputIndex).Error("arkade script execution failed")
			return nil, fmt.Errorf("failed to execute arkade script at input %d: %w", inputIndex, err)
		}

		req, err := newSignRequest(ptx, inputIndex, script)
		if err != nil {
			return nil, fmt.Errorf("cannot request signature for input %d: %w", inputIndex, err)
		}
		requests = append(requests, req)

		// if input index 1 is valid, the intent message input (index 0) is approved with it
		if inputIndex == 1 {
			// the message input is signed with input 1's script hash, so it must
			// really carry input 1's script: the vm never executes input 0 on its
			// own, nothing else would bind the signature to the executed script
			if !bytes.Equal(
				ptx.Inputs[0].WitnessUtxo.PkScript, ptx.Inputs[1].WitnessUtxo.PkScript,
			) {
				return nil, fmt.Errorf("message input script does not match input 1 script")
			}

			msgReq, err := newSignRequest(ptx, 0, script)
			if err != nil {
				return nil, fmt.Errorf("cannot request signature for message input: %w", err)
			}
			requests = append(requests, msgReq)
		}
	}
	return requests, nil
}

// EmulateBatchFinalization executes no script: the intents were executed at registration.
// It returns one request per forfeit or commitment input spending a vtxo approved
// by a signed proof input, whose ClosurePubKeys are the keys that signed the proof.
// A forfeit spending no approved vtxo gets no request.
func (s *service) EmulateBatchFinalization(
	ctx context.Context, finalization BatchFinalization,
) ([]SignRequest, error) {
	approved := make(map[wire.OutPoint]approvedInput)
	for i := range finalization.Intents {
		inputs, err := approvedInputs(&finalization.Intents[i].Proof.Packet)
		if err != nil {
			return nil, fmt.Errorf("intent %d: %w", i, err)
		}
		for outpoint, input := range inputs {
			approved[outpoint] = input
		}
	}
	if len(approved) == 0 {
		return nil, nil
	}

	txs := finalization.Forfeits
	if finalization.CommitmentTx != nil {
		txs = append(slices.Clone(txs), finalization.CommitmentTx)
	}
	requests := make([]SignRequest, 0, len(approved))
	for _, ptx := range txs {
		for inputIndex, input := range ptx.UnsignedTx.TxIn {
			outpoint := input.PreviousOutPoint
			a, ok := approved[outpoint]
			if !ok {
				continue
			}
			if err := a.validateInput(ptx, inputIndex, outpoint); err != nil {
				return nil, fmt.Errorf("tx %s: %w", ptx.UnsignedTx.TxID(), err)
			}
			req, err := newSignRequest(ptx, inputIndex, a.script)
			if err != nil {
				return nil, fmt.Errorf("tx %s: cannot request signature for input %d: %w", ptx.UnsignedTx.TxID(), inputIndex, err)
			}
			req.ClosurePubKeys = a.signers
			requests = append(requests, req)
			// a vtxo is forfeited once
			delete(approved, outpoint)
		}
	}
	return requests, nil
}


func (s *service) executeOptions() []arkade.ExecuteOption {
	budget := arkade.NewComputeBudgetWithLimits(arkade.AggregateComputeLimits(s.computeLimits))
	return []arkade.ExecuteOption{
		arkade.WithExactComputeLimits(s.computeLimits),
		arkade.WithComputeBudget(budget),
	}
}
