package emulator

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

// SubmitTx aims to execute arkade scripts on offchain ark transactions
// execution of the script runs only on ark tx, if valid, the associated checkpoint tx
// tx is signed in place, even on error: do not reuse it across calls.
func (s *service) SubmitTx(ctx context.Context, tx OffchainTx) (*OffchainTx, error) {
	arkPtx := tx.ArkTx

	indexedCheckpoints, err := indexCheckpoints(arkPtx, tx.Checkpoints)
	if err != nil {
		return nil, err
	}

	prevOutFetcher, err := prevOutFetcherForArkTx(arkPtx, tx.Checkpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	// Parse EmulatorPacket from the transaction's OP_RETURN output
	packet, err := arkade.FindEmulatorPacket(arkPtx.UnsignedTx)
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
		matchedSigner, script, err := resolveArkadeScriptSigner(s.signer, s.activeDeprecatedSigners(), arkPtx, entry)
		if err != nil {
			// there may be input/entry pairs attributed to a different signer
			if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) && len(arkPtx.Inputs) > 1 {
				continue
			}
			return nil, fmt.Errorf("failed to read arkade script: %w vin=%d", err, inputIndex)
		}

		inputTxid := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint.Hash.String()
		checkpointPtx := indexedCheckpoints[inputTxid]
		arkOutpoint := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if err := validateCheckpoint(arkPtx, inputIndex, checkpointPtx, prevOutFetcher.fetchVtxoPrevOut(arkOutpoint), script.TapLeaf()); err != nil {
			return nil, fmt.Errorf("invalid checkpoint for input %d: %w", inputIndex, err)
		}
		prevArkTx := prevOutFetcher.FetchPrevOutArkTx(arkOutpoint)
		if prevArkTx == nil {
			return nil, fmt.Errorf("prevout ark tx not found for input %d", inputIndex)
		}
		expiry, err := s.expiryForScript(
			ctx, script.Script(), prevArkTx.TxHash().String(),
			prevOutFetcher.prevOutIdxs[arkOutpoint],
		)
		if err != nil {
			return nil, err
		}

		log.Debugf("executing arkade script: %x", script.Script())
		if err := script.Execute(
			arkPtx.UnsignedTx,
			prevOutFetcher,
			inputIndex,
			arkade.WithExactComputeLimits(s.computeLimits),
			arkade.WithComputeBudget(budget),
			arkade.WithExpiry(expiry),
		); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w vin=%d", err, inputIndex)
		}
		log.Debugf("execution of %x succeeded", script.Script())

		if err := matchedSigner.signInput(arkPtx, inputIndex, script.Hash(), prevOutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		checkpointPrevoutFetcher, err := computePrevoutFetcher(checkpointPtx)
		if err != nil {
			return nil, fmt.Errorf("failed to create prevout fetcher for checkpoint: %w", err)
		}

		if err := matchedSigner.signInput(checkpointPtx, 0, script.Hash(), checkpointPrevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign checkpoint input %d: %w", inputIndex, err)
		}

		nSigned++
	}

	if nSigned == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}

	return &OffchainTx{
		ArkTx:       arkPtx,
		Checkpoints: tx.Checkpoints,
	}, nil
}

func indexCheckpoints(arkPtx *psbt.Packet, checkpoints []*psbt.Packet) (map[string]*psbt.Packet, error) {
	if arkPtx == nil || arkPtx.UnsignedTx == nil {
		return nil, fmt.Errorf("missing ark transaction")
	}
	if len(checkpoints) != len(arkPtx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("expected %d checkpoints, got %d", len(arkPtx.UnsignedTx.TxIn), len(checkpoints))
	}

	indexed := make(map[string]*psbt.Packet, len(checkpoints))
	for i, checkpoint := range checkpoints {
		if checkpoint == nil || checkpoint.UnsignedTx == nil {
			return nil, fmt.Errorf("checkpoint %d is missing its transaction", i)
		}
		txid := checkpoint.UnsignedTx.TxID()
		if _, exists := indexed[txid]; exists {
			return nil, fmt.Errorf("duplicate checkpoint %s", txid)
		}
		indexed[txid] = checkpoint
	}

	used := make(map[string]struct{}, len(arkPtx.UnsignedTx.TxIn))
	for inputIndex, input := range arkPtx.UnsignedTx.TxIn {
		txid := input.PreviousOutPoint.Hash.String()
		if _, ok := indexed[txid]; !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}
		if _, exists := used[txid]; exists {
			return nil, fmt.Errorf("checkpoint %s is associated with multiple ark inputs", txid)
		}
		used[txid] = struct{}{}
	}

	return indexed, nil
}

func validateCheckpoint(
	arkPtx *psbt.Packet, inputIndex int, checkpoint *psbt.Packet,
	previousOutput *wire.TxOut, expectedLeaf txscript.TapLeaf,
) error {
	if inputIndex < 0 || inputIndex >= len(arkPtx.Inputs) || inputIndex >= len(arkPtx.UnsignedTx.TxIn) {
		return fmt.Errorf("ark input index out of range")
	}
	if checkpoint == nil || checkpoint.UnsignedTx == nil || len(checkpoint.Inputs) != 1 || len(checkpoint.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("checkpoint must have exactly one input")
	}
	if len(checkpoint.UnsignedTx.TxOut) != 2 {
		return fmt.Errorf("checkpoint must have one vtxo output and one anchor output")
	}

	arkOutpoint := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
	if arkOutpoint.Hash != checkpoint.UnsignedTx.TxHash() {
		return fmt.Errorf("ark input does not spend checkpoint")
	}
	if arkOutpoint.Index != 0 {
		return fmt.Errorf("ark input must spend checkpoint output 0")
	}
	if !equalTxOut(arkPtx.Inputs[inputIndex].WitnessUtxo, checkpoint.UnsignedTx.TxOut[arkOutpoint.Index]) {
		return fmt.Errorf("checkpoint output does not match ark input witness utxo")
	}
	if !equalTxOut(checkpoint.UnsignedTx.TxOut[1], txutils.AnchorOutput()) {
		return fmt.Errorf("checkpoint anchor output is invalid")
	}

	if previousOutput == nil {
		return fmt.Errorf("missing authenticated previous ark output")
	}
	if !equalTxOut(checkpoint.Inputs[0].WitnessUtxo, previousOutput) {
		return fmt.Errorf("checkpoint input witness utxo does not match previous ark transaction")
	}
	if checkpoint.UnsignedTx.TxOut[0].Value != previousOutput.Value {
		return fmt.Errorf("checkpoint vtxo output value does not match its input")
	}

	if err := validateTaprootLeaf(arkPtx.Inputs[inputIndex], expectedLeaf); err != nil {
		return fmt.Errorf("ark input tapleaf: %w", err)
	}
	if err := validateTaprootLeaf(checkpoint.Inputs[0], expectedLeaf); err != nil {
		return fmt.Errorf("checkpoint tapleaf: %w", err)
	}

	return nil
}

func validateTaprootLeaf(input psbt.PInput, expectedLeaf txscript.TapLeaf) error {
	if input.WitnessUtxo == nil || !txscript.IsPayToTaproot(input.WitnessUtxo.PkScript) {
		return fmt.Errorf("witness utxo is not taproot")
	}
	if len(input.TaprootLeafScript) == 0 || input.TaprootLeafScript[0] == nil {
		return fmt.Errorf("missing taproot leaf script")
	}

	leaf := input.TaprootLeafScript[0]
	controlBlock, err := txscript.ParseControlBlock(leaf.ControlBlock)
	if err != nil {
		return fmt.Errorf("invalid control block: %w", err)
	}
	if controlBlock.LeafVersion != leaf.LeafVersion {
		return fmt.Errorf("control block leaf version does not match taproot leaf script")
	}
	if txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash() != expectedLeaf.TapHash() {
		return fmt.Errorf("tapleaf does not match ark input")
	}
	if err := txscript.VerifyTaprootLeafCommitment(controlBlock, input.WitnessUtxo.PkScript[2:], leaf.Script); err != nil {
		return fmt.Errorf("tapleaf is not committed by witness utxo: %w", err)
	}

	return nil
}

// Keep the retry helper in sync with internal/application/retry.go.
type retryConfig struct {
	MinAttempts  int
	MaxAttempts  int
	MaxElapsed   time.Duration
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       float64
}

// retryWithBackoff retries op with jittered backoff; the first MinAttempts
// ignore ctx cancellation.
func retryWithBackoff(
	ctx context.Context, cfg retryConfig, op func() error, onErr func(attempt int, err error),
) error {
	backoffDelay := cfg.InitialDelay
	deadline := time.Now().Add(cfg.MaxElapsed)
	for attempt := 1; ; attempt++ {
		err := op()
		if err == nil {
			return nil
		}
		if onErr != nil {
			onErr(attempt, err)
		}

		// absolute bounds, independent of the caller supplied context, so the
		// loop always returns even when ctx has no deadline
		if cfg.MaxAttempts > 0 && attempt >= cfg.MaxAttempts {
			return fmt.Errorf("retry exhausted after attempt %d: %w", attempt, err)
		}

		delay := applyJitter(backoffDelay, cfg.Jitter)
		// float math: time.Duration(1.5) would truncate to 1
		backoffDelay = min(cfg.MaxDelay, time.Duration(float64(backoffDelay)*cfg.Multiplier))

		if cfg.MaxElapsed > 0 && !time.Now().Add(delay).Before(deadline) {
			return fmt.Errorf("retry budget exhausted after attempt %d: %w", attempt, err)
		}

		// try a minimum number of times before respecting ctx.Done
		if attempt < cfg.MinAttempts {
			time.Sleep(delay)
			continue
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled after attempt %d: %w", attempt, ctx.Err())
		case <-time.After(delay):
		}
	}
}

// applyJitter adds ±jitter randomness to a duration.
// with jitter = 0.2, d get + or - 20%
func applyJitter(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return d
	}
	if jitter >= 1.0 {
		jitter = 0.999
	}

	randomFactor := 2.0*rand.Float64() - 1.0 // [-1, +1] factor
	jitterFactor := 1.0 + jitter*randomFactor
	return time.Duration(float64(d) * jitterFactor)
}
