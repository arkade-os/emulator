// Package application wraps the pkg/emulator signer with arkd submit/finalize.
package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

type arkdClient interface {
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (arkTxid, finalArkTx string, signedCheckpointTxs []string, err error)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
	Close()
}

// Service is the emulator signer backed by arkd: it fetches the offchain data
// the signer needs itself. Close releases the arkd clients.
type Service interface {
	GetInfo(context.Context) (*emulator.Info, error)
	SubmitTx(context.Context, emulator.OffchainTx) (*emulator.OffchainTx, error)
	SubmitIntent(context.Context, emulator.Intent) (*psbt.Packet, error)
	SubmitFinalization(context.Context, emulator.BatchFinalization) (*emulator.SignedBatchFinalization, error)
	SubmitOnchainTx(context.Context, emulator.OnchainTx) (*psbt.Packet, error)
	Close()
}

type service struct {
	emulator.Service
	arkd          arkdClient
	indexer       clientlib.Indexer
	arkdPubKey    *btcec.PublicKey
	signerPubKeys []*btcec.PublicKey
}

// New connects to arkd and builds the emulator service.
func New(
	ctx context.Context, version string,
	secretKey *btcec.PrivateKey, deprecatedKeys []*btcec.PrivateKey, deprecatedKeysValidUntil *time.Time,
	arkdURL, arkdIndexerURL string, computeLimits arkade.ComputeLimits,
) (Service, error) {
	clientVersion := "emulator/" + version

	arkd, err := grpcclient.NewClient(arkdURL, clientVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to create arkd client: %w", err)
	}
	indexerClient, err := grpcindexer.NewClient(arkdIndexerURL)
	if err != nil {
		arkd.Close()
		return nil, fmt.Errorf("failed to create arkd indexer client: %w", err)
	}
	// close both clients unless the service takes ownership
	handedOff := false
	defer func() {
		if !handedOff {
			arkd.Close()
			indexerClient.Close()
		}
	}()

	var info *clientlib.Info
	// arkd may still be booting when the emulator starts, retry if it fails.
	err = retryWithBackoff(
		ctx, arkdConnectRetryConfig,
		func() error {
			var e error
			info, e = arkd.GetInfo(ctx)
			return e
		},
		func(attempt int, e error) {
			log.WithField("attempt", attempt).Warnf("arkd not ready: %s", e)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch arkd info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("arkd info is required")
	}
	if info.SignerPubKey == "" {
		return nil, fmt.Errorf("arkd info does not include signer pubkey")
	}
	pk, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid arkd signer pubkey: %w", err)
	}
	arkdPubKey, err := btcec.ParsePubKey(pk)
	if err != nil {
		return nil, fmt.Errorf("invalid arkd signer pubkey: %w", err)
	}

	lib, err := emulator.New(
		secretKey, deprecatedKeys, deprecatedKeysValidUntil, arkdPubKey, computeLimits,
	)
	if err != nil {
		return nil, err
	}
	handedOff = true

	signerPubKeys := []*btcec.PublicKey{secretKey.PubKey()}
	for _, k := range deprecatedKeys {
		signerPubKeys = append(signerPubKeys, k.PubKey())
	}
	return &service{
		Service:       lib,
		arkd:          arkd,
		indexer:       versionedIndexer{indexerClient, clientVersion},
		arkdPubKey:    arkdPubKey,
		signerPubKeys: signerPubKeys,
	}, nil
}

// SubmitTx executes and signs arkade script for offchain tx
// it directly submits to arkd in order to prevent griefing attacks where a malicious signer retain the tx in the "pending" state
func (s *service) SubmitTx(ctx context.Context, tx emulator.OffchainTx) (*emulator.OffchainTx, error) {
	var sigsBefore []int
	if tx.ArkTx != nil {
		sigsBefore = make([]int, len(tx.ArkTx.Inputs))
		for i, in := range tx.ArkTx.Inputs {
			sigsBefore[i] = len(in.TaprootScriptSpendSig)
		}
	}

	outpoints, err := tx.RequiredVtxos()
	if err != nil {
		return nil, err
	}
	data, err := s.fetchOffchainData(ctx, outpoints)
	if err != nil {
		return nil, err
	}

	signed, err := s.Service.SubmitTx(ctx, tx, data)
	if err != nil {
		return nil, err
	}

	isFinalizer, err := isFinalizerRole(signed.ArkTx, sigsBefore, s.signerPubKeys, s.arkdPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to determine finalizer role: %w", err)
	}

	log.WithField("is_finalizer", isFinalizer).Debug("finalizer role analysis completed")

	if !isFinalizer {
		return signed, nil
	}

	// we must verify that we have all the required checkpoint signatures before submitting to arkd
	// otherwise, finalizing with arkd will fail later
	if err = verifyNonArkdCheckpointSignatures(signed.Checkpoints, s.arkdPubKey); err != nil {
		return nil, fmt.Errorf("failed to verify non-arkd signatures on checkpoints: %w", err)
	}

	encodedCheckpoints := make([]string, 0, len(signed.Checkpoints))
	for i, checkpoint := range signed.Checkpoints {
		encoded, err := checkpoint.B64Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode checkpoint %d: %w", i, err)
		}
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

	arkTx, err := signed.ArkTx.B64Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode ark tx for finalization: %w", err)
	}

	txid, finalArkTx, arkdCheckpointTxs, err := s.arkd.SubmitTx(ctx, arkTx, encodedCheckpoints)
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

	finalEncodedCheckpoints := make([]string, 0, len(signed.Checkpoints))
	logCheckpoints := make(map[string]any)
	for i, checkpoint := range signed.Checkpoints {
		// arkd's response may not cover our checkpoints
		txid := checkpoint.UnsignedTx.TxID()
		arkdCheckpoint, ok := arkdCheckpointPSBTs[txid]
		if !ok {
			return nil, fmt.Errorf("arkd returned no checkpoint for txid %s", txid)
		}
		if len(arkdCheckpoint.Inputs) == 0 {
			return nil, fmt.Errorf("arkd returned checkpoint %s without inputs", txid)
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

	return &emulator.OffchainTx{
		ArkTx:       finalArkPtx,
		Checkpoints: signed.Checkpoints,
	}, nil
}

// SubmitIntent executes and signs arkade script for intent tx
func (s *service) SubmitIntent(ctx context.Context, intent emulator.Intent) (*psbt.Packet, error) {
	outpoints, err := intent.RequiredVtxos()
	if err != nil {
		return nil, err
	}
	data, err := s.fetchOffchainData(ctx, outpoints)
	if err != nil {
		return nil, err
	}
	return s.Service.SubmitIntent(ctx, intent, data)
}

// SubmitFinalization executes and sign arkade script for batch session finalization phase
func (s *service) SubmitFinalization(
	ctx context.Context, finalization emulator.BatchFinalization,
) (*emulator.SignedBatchFinalization, error) {
	if finalization.CommitmentTx == nil {
		return nil, fmt.Errorf("commitment tx is required")
	}
	commitmentTxid := finalization.CommitmentTx.UnsignedTx.TxID()
	err := retryWithBackoff(ctx, indexerRetryConfig,
		func() error {
			_, err := s.indexer.GetCommitmentTx(ctx, commitmentTxid)
			return err
		}, nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"commitment tx %s not known to arkd indexer: %w", commitmentTxid, err,
		)
	}
	return s.Service.SubmitFinalization(ctx, finalization)
}

func (s *service) Close() {
	s.indexer.Close()
	s.arkd.Close()
}

// versionedIndexer adds the x-sdk-version header to indexer calls.
type versionedIndexer struct {
	clientlib.Indexer
	version string
}

func (v versionedIndexer) ctx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-sdk-version", v.version)
}

func (v versionedIndexer) GetVtxos(ctx context.Context, opts ...clientlib.GetVtxosOption) (*clientlib.VtxosResponse, error) {
	return v.Indexer.GetVtxos(v.ctx(ctx), opts...)
}

func (v versionedIndexer) GetCommitmentTx(ctx context.Context, txid string) (*clientlib.CommitmentTx, error) {
	return v.Indexer.GetCommitmentTx(v.ctx(ctx), txid)
}
