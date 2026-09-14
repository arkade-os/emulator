package emulator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

// SubmitTx aims to execute arkade scripts on offchain ark transactions
// execution of the script runs only on ark tx, if valid, the associated checkpoint tx
//
// tx is signed in place: the returned OffchainTx aliases the caller's ArkTx and
// checkpoint packets (except the ark tx replaced by arkd's finalized one), so an
// OffchainTx must not be reused across calls. The in-place signing persists when
// SubmitTx returns an error, so a failed OffchainTx must not be re-submitted:
// signatures are appended, not replaced.
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

	finalizerAcc := newFinalizerAccumulator(s.arkdPubKey)

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

		if err = finalizerAcc.checkScript(entry.Vin, script); err != nil {
			return nil, err
		}

		nSigned++
	}

	if nSigned == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}

	signedCheckpointTxs := tx.Checkpoints

	isFinalizer, err := finalizerAcc.isFinalizer()
	if err != nil {
		return nil, fmt.Errorf("failed to determine finalizer role: %w", err)
	}

	log.WithField("is_finalizer", isFinalizer).Debug("finalizer role analysis completed")

	if !isFinalizer {
		return &OffchainTx{
			ArkTx:       arkPtx,
			Checkpoints: signedCheckpointTxs,
		}, nil
	}

	// we must verify that we have all the required checkpoint signatures before submitting to arkd
	// otherwise, finalizing with arkd will fail later. this runs in signing-only mode too:
	// the caller forwards our signature to arkd, so an incomplete set fails there instead.
	if err = verifyNonArkdCheckpointSignatures(signedCheckpointTxs, s.arkdPubKey); err != nil {
		return nil, fmt.Errorf("failed to verify non-arkd signatures on checkpoints: %w", err)
	}

	// signing-only: hand the verified signed set back, the caller does the arkd round-trip
	if s.finalizer == nil {
		return &OffchainTx{
			ArkTx:       arkPtx,
			Checkpoints: signedCheckpointTxs,
		}, nil
	}

	encodedCheckpoints := make([]string, 0, len(tx.Checkpoints))
	for i, checkpoint := range tx.Checkpoints {
		encoded, err := checkpoint.B64Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode checkpoint %d: %w", i, err)
		}
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode ark tx for finalization: %w", err)
	}

	txid, finalArkTx, arkdCheckpointTxs, err := s.finalizer.SubmitTx(ctx, arkTx, encodedCheckpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to submit tx on arkd: %w", err)
	}

	// combine arkd checkpoint signatures with the rest of the checkpoint signatures
	arkdCheckpointPSBTs := make(map[string]*psbt.Packet, len(arkdCheckpointTxs))
	for i, checkpoint := range arkdCheckpointTxs {
		p, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		if err != nil {
			return nil, fmt.Errorf("failed to decode arkd checkpoint %d: %w", i, err)
		}
		arkdCheckpointPSBTs[p.UnsignedTx.TxID()] = p
	}

	finalEncodedCheckpoints := make([]string, 0, len(tx.Checkpoints))
	logCheckpoints := make(map[string]any)
	for i, checkpoint := range signedCheckpointTxs {
		// Finalizer is a public interface, so do not trust the returned set to
		// cover ours: a missing or malformed entry must be an error, not a panic.
		txid := checkpoint.UnsignedTx.TxID()
		arkdCheckpoint, ok := arkdCheckpointPSBTs[txid]
		if !ok {
			return nil, fmt.Errorf("finalizer returned no checkpoint for txid %s", txid)
		}
		if len(arkdCheckpoint.Inputs) == 0 {
			return nil, fmt.Errorf("finalizer returned checkpoint %s without inputs", txid)
		}
		if len(checkpoint.Inputs) == 0 {
			return nil, fmt.Errorf("checkpoint %d has no inputs", i)
		}

		checkpoint.Inputs[0].TaprootScriptSpendSig = append(
			checkpoint.Inputs[0].TaprootScriptSpendSig,
			arkdCheckpoint.Inputs[0].TaprootScriptSpendSig...,
		)
		encoded, err := checkpoint.B64Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode final checkpoint %d: %w", i, err)
		}
		logCheckpoints[strconv.Itoa(i)] = encoded
		finalEncodedCheckpoints = append(finalEncodedCheckpoints, encoded)
	}

	log.WithField("txid", txid).WithFields(log.Fields(logCheckpoints)).Info("finalizing tx")

	// TODO: if retry fails, persist retry task in background queue
	if err := s.retryFinalize(ctx, txid, finalEncodedCheckpoints); err != nil {
		return nil, err
	}

	finalArkPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalArkTx), true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode final ark tx: %w", err)
	}

	return &OffchainTx{
		ArkTx:       finalArkPtx,
		Checkpoints: signedCheckpointTxs,
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

func (s *service) retryFinalize(ctx context.Context, txid string, checkpoints []string) error {
	// unreachable: SubmitTx returns before this in signing-only mode. Asserted so
	// the contract is explicit rather than a nil deref if that guard ever moves.
	if s.finalizer == nil {
		return fmt.Errorf("cannot finalize tx %s: service has no finalizer", txid)
	}
	return retryWithBackoff(ctx, finalizeRetryConfig,
		func() error { return s.finalizer.FinalizeTx(ctx, txid, checkpoints) },
		func(attempt int, err error) {
			log.WithField("txid", txid).WithField("attempt", attempt).Errorf("finalizing tx failed: %s", err)
		},
	)
}

type finalizerAccumulator struct {
	arkdPubKeyXonly []byte
	isLastByVin     map[uint16]bool
	vins            []uint16
}

func newFinalizerAccumulator(arkdPubKey *btcec.PublicKey) *finalizerAccumulator {
	arkdPubKeyXonly := schnorr.SerializePubKey(arkdPubKey)
	return &finalizerAccumulator{
		arkdPubKeyXonly: arkdPubKeyXonly,
		isLastByVin:     make(map[uint16]bool),
	}
}

func (a *finalizerAccumulator) checkScript(vin uint16, script *arkade.ArkadeScript) error {
	a.vins = append(a.vins, vin)

	nClosurePubKeys := len(script.ClosurePubKeys())
	tweakedSignerPublicKeyXOnly := schnorr.SerializePubKey(script.PubKey())
	if nClosurePubKeys < 2 {
		// the script should always have a forfeit closure with at least arkd + tweaked key
		return fmt.Errorf("malformed script %x", script.Script())
	}

	lastSigner := script.ClosurePubKeys()[nClosurePubKeys-1]
	lastSignerXOnly := schnorr.SerializePubKey(lastSigner)

	// if arkd is the last signer, check the second-to-last
	if bytes.Equal(lastSignerXOnly, a.arkdPubKeyXonly) {
		lastNonArkdSigner := script.ClosurePubKeys()[nClosurePubKeys-2]
		lastNonArkdSignerXonly := schnorr.SerializePubKey(lastNonArkdSigner)
		a.isLastByVin[vin] = bytes.Equal(lastNonArkdSignerXonly, tweakedSignerPublicKeyXOnly)
		return nil
	}

	a.isLastByVin[vin] = bytes.Equal(lastSignerXOnly, tweakedSignerPublicKeyXOnly)
	return nil
}

func (a *finalizerAccumulator) isFinalizer() (bool, error) {
	if len(a.vins) == 0 {
		return false, nil
	}
	referenceVin := a.vins[0]
	referenceIsLast, ok := a.isLastByVin[referenceVin]
	if !ok {
		return false, fmt.Errorf("missing finalizer state for input %d", referenceVin)
	}
	for _, vin := range a.vins[1:] {
		isLast, ok := a.isLastByVin[vin]
		if !ok {
			return false, fmt.Errorf("missing finalizer state for input %d", vin)
		}
		if isLast != referenceIsLast {
			return false, fmt.Errorf("input %d has a different finalizer", vin)
		}
	}
	return referenceIsLast, nil
}

func verifyNonArkdCheckpointSignatures(checkpoints []*psbt.Packet, arkdPubKey *btcec.PublicKey) error {
	for checkpointIndex, ptx := range checkpoints {
		if len(ptx.Inputs) == 0 || len(ptx.UnsignedTx.TxIn) == 0 {
			return fmt.Errorf("checkpoint %d: missing input 0", checkpointIndex)
		}
		// script.VerifyTapscriptSigs silently skips inputs that do not carry
		// exactly one taproot leaf script, so we must assert that count here.
		if len(ptx.Inputs[0].TaprootLeafScript) != 1 {
			return fmt.Errorf(
				"checkpoint %d input 0: missing taproot leaf script (want exactly 1, got %d)",
				checkpointIndex, len(ptx.Inputs[0].TaprootLeafScript),
			)
		}
		prevoutFetcher, err := computePrevoutFetcher(ptx)
		if err != nil {
			return fmt.Errorf("checkpoint %d: %w", checkpointIndex, err)
		}
		// script.VerifyTapscriptSigs also skips an input whose prevout is not a
		// taproot output and one carrying a note closure, both without erroring, so
		// a nil error alone does not mean input 0 was checked. Require it in the
		// verified set instead.
		verified, err := script.VerifyTapscriptSigs(
			ptx, prevoutFetcher, script.WithSkipPublicKeys(arkdPubKey),
		)
		if err != nil {
			return fmt.Errorf("checkpoint %d: %w", checkpointIndex, err)
		}
		if !slices.Contains(verified, 0) {
			return fmt.Errorf(
				"checkpoint %d input 0: signatures were not verified", checkpointIndex,
			)
		}
	}
	return nil
}

// internal/config/retry.go keeps a private copy of retryConfig/retryWithBackoff
// so this library need not export them. The two are behavior-identical by
// design: any fix to retryWithBackoff/applyJitter here must land there too.

// retryConfig tunes retryWithBackoff: how many attempts ignore ctx
// cancellation, the initial/maximum delay, the growth multiplier, and the
// jitter fraction.
type retryConfig struct {
	MinAttempts  int
	MaxAttempts  int
	MaxElapsed   time.Duration
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       float64
}

var finalizeRetryConfig = retryConfig{
	MinAttempts: 10,
	// absolute caps, enforced even when the caller passes a context without
	// deadline, so the signer can never be wedged by an unresponsive arkd
	MaxAttempts:  15,
	MaxElapsed:   2 * time.Minute,
	InitialDelay: 1 * time.Second,
	MaxDelay:     10 * time.Second,
	Multiplier:   2.0,
	Jitter:       0.2, // + or - 20% randomness
}

// retryWithBackoff runs op until it succeeds, backing off between attempts with
// jitter. The first cfg.MinAttempts run regardless of ctx; after that a
// cancelled ctx aborts the loop. onErr, if set, is called after each failure.
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
		// scale in float64: time.Duration(cfg.Multiplier) truncates 1.5 to 1
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
