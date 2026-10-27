// Package application signs what pkg/emulator executes, submitting to arkd.
package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

type arkdClient interface {
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (arkTxid, finalArkTx string, signedCheckpointTxs []string, err error)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
	Close()
}

type Info struct {
	SignerPublicKey            string
	DeprecatedSignerPublicKeys []string
}

type SignedBatchFinalization struct {
	Forfeits     []*psbt.Packet
	CommitmentTx *psbt.Packet
}

// Service is the emulator signer backed by arkd: it fetches the offchain data
// the signer needs itself. Close releases the arkd clients.
type Service interface {
	GetInfo(context.Context) (*Info, error)
	SubmitTx(context.Context, emulator.OffchainTx) (*emulator.OffchainTx, error)
	SubmitIntent(context.Context, emulator.Intent) (*psbt.Packet, error)
	SubmitFinalization(context.Context, emulator.BatchFinalization, *tree.TxTree) (*SignedBatchFinalization, error)
	SubmitOnchainTx(context.Context, emulator.OnchainTx) (*psbt.Packet, error)
	Close()
}

type service struct {
	lib                      emulator.Service
	signer                   signer
	deprecatedSigners        []signer
	deprecatedKeysValidUntil *time.Time
	arkdForfeitPkScript      []byte
	arkd                     arkdClient
	indexer                  clientlib.Indexer
	arkdPubKey               *btcec.PublicKey
	signerPubKeys            []*btcec.PublicKey
}

// New connects to arkd and builds the emulator service.
func New(
	ctx context.Context, version string,
	secretKey *btcec.PrivateKey, deprecatedKeys []*btcec.PrivateKey, deprecatedKeysValidUntil *time.Time,
	arkdURL, arkdIndexerURL string, computeLimits arkade.ComputeLimits,
) (Service, error) {
	if secretKey == nil {
		return nil, fmt.Errorf("current signer key is required")
	}
	deprecatedSigners := make([]signer, 0, len(deprecatedKeys))
	for i, deprecatedKey := range deprecatedKeys {
		if deprecatedKey == nil {
			return nil, fmt.Errorf("deprecated signer key #%d is required", i)
		}
		deprecatedSigners = append(deprecatedSigners, signer{deprecatedKey})
	}

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

	network := clientlib.ToBitcoinNetwork(clientlib.NetworkFromString(info.Network))
	forfeitAddr, err := arklib.DecodeBitcoinAddress(info.ForfeitAddress, &network)
	if err != nil {
		return nil, fmt.Errorf("invalid arkd forfeit address: %w", err)
	}
	forfeitPkScript, err := txscript.PayToAddrScript(forfeitAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to build arkd forfeit script: %w", err)
	}

	lib := emulator.New(computeLimits)
	handedOff = true

	signerPubKeys := []*btcec.PublicKey{secretKey.PubKey()}
	for _, k := range deprecatedKeys {
		signerPubKeys = append(signerPubKeys, k.PubKey())
	}
	return &service{
		lib:                      lib,
		signer:                   signer{secretKey},
		deprecatedSigners:        deprecatedSigners,
		deprecatedKeysValidUntil: deprecatedKeysValidUntil,
		arkdForfeitPkScript:      forfeitPkScript,
		arkd:                     arkd,
		indexer:                  versionedIndexer{indexerClient, clientVersion},
		arkdPubKey:               arkdPubKey,
		signerPubKeys:            signerPubKeys,
	}, nil
}

func (s *service) GetInfo(context.Context) (*Info, error) {
	deprecated := make([]string, 0, len(s.deprecatedSigners))
	for _, d := range s.deprecatedSigners {
		deprecated = append(deprecated, hex.EncodeToString(d.secretKey.PubKey().SerializeCompressed()))
	}
	return &Info{
		SignerPublicKey:            hex.EncodeToString(s.signer.secretKey.PubKey().SerializeCompressed()),
		DeprecatedSignerPublicKeys: deprecated,
	}, nil
}

// signTx executes and signs the arkade script inputs of tx in place, even on error: do not reuse it across calls.
func (s *service) signTx(ctx context.Context, tx emulator.OffchainTx, data emulator.OffchainData) (*emulator.OffchainTx, error) {
	requests, err := s.lib.EmulateOffchainTx(ctx, tx, data)
	if err != nil {
		return nil, err
	}
	if _, err := s.signRequests(requests); err != nil {
		return nil, err
	}
	return &emulator.OffchainTx{ArkTx: tx.ArkTx, Checkpoints: tx.Checkpoints}, nil
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

	outpoints, err := tx.ExpiryOutpoints()
	if err != nil {
		return nil, err
	}
	data, err := s.fetchOffchainData(ctx, outpoints)
	if err != nil {
		return nil, err
	}

	signed, err := s.signTx(ctx, tx, data)
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

	arkdTxid, finalArkTx, arkdCheckpointTxs, err := s.arkd.SubmitTx(ctx, arkTx, encodedCheckpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to submit tx on arkd: %w", err)
	}

	// arkd must countersign the ark tx we executed the arkade script against, not another one
	arkTxid := signed.ArkTx.UnsignedTx.TxID()
	if arkdTxid != arkTxid {
		return nil, fmt.Errorf("arkd returned txid %s, expected %s", arkdTxid, arkTxid)
	}
	finalArkPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalArkTx), true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode final ark tx: %w", err)
	}
	if finalTxid := finalArkPtx.UnsignedTx.TxID(); finalTxid != arkTxid {
		return nil, fmt.Errorf("arkd returned ark tx %s, expected %s", finalTxid, arkTxid)
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
	finalizedOnSubmit := len(signed.Checkpoints) > 0
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

		// arkd >= v0.9.22 finalizes inside the submit call when the checkpoint it
		// receives is already signed, and then rejects any FinalizeTx attempt
		if !carriesTapscriptSigs(
			arkdCheckpoint.Inputs[0].TaprootScriptSpendSig,
			checkpoint.Inputs[0].TaprootScriptSpendSig,
		) {
			finalizedOnSubmit = false
		}

		checkpoint.Inputs[0].TaprootScriptSpendSig = mergeTapscriptSigs(
			checkpoint.Inputs[0].TaprootScriptSpendSig,
			arkdCheckpoint.Inputs[0].TaprootScriptSpendSig,
		)
		encoded, err := checkpoint.B64Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode final checkpoint %d: %w", i, err)
		}
		logCheckpoints[strconv.Itoa(i)] = encoded
		finalEncodedCheckpoints = append(finalEncodedCheckpoints, encoded)
	}

	if finalizedOnSubmit {
		log.WithField("txid", arkTxid).Info("arkd finalized the tx on submit")
	} else {
		log.WithField("txid", arkTxid).WithFields(log.Fields(logCheckpoints)).Info("finalizing tx")

		// TODO: if retry fails, persist retry task in background queue
		if err := s.retryFinalize(ctx, arkTxid, finalEncodedCheckpoints); err != nil {
			return nil, err
		}
	}

	return &emulator.OffchainTx{
		ArkTx:       finalArkPtx,
		Checkpoints: signed.Checkpoints,
	}, nil
}

// SubmitIntent executes and signs arkade script for intent tx
func (s *service) SubmitIntent(ctx context.Context, intent emulator.Intent) (*psbt.Packet, error) {
	if err := validateIntentMessageCommitment(intent); err != nil {
		return nil, fmt.Errorf("intent message is not committed by the proof: %w", err)
	}
	outpoints, err := intent.ExpiryOutpoints()
	if err != nil {
		return nil, err
	}
	data, err := s.fetchOffchainData(ctx, outpoints)
	if err != nil {
		return nil, err
	}
	requests, err := s.lib.EmulateIntent(ctx, intent, data)
	if err != nil {
		return nil, err
	}
	if _, err := s.signRequests(requests); err != nil {
		return nil, err
	}
	return requests[0].Packet, nil
}

// SubmitOnchainTx executes and signs arkade script for a plain Bitcoin PSBT
func (s *service) SubmitOnchainTx(ctx context.Context, tx emulator.OnchainTx) (*psbt.Packet, error) {
	requests, err := s.lib.EmulateOnchainTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if _, err := s.signRequests(requests); err != nil {
		return nil, err
	}
	return tx.Tx, nil
}

// SubmitFinalization executes and sign arkade script for batch session finalization phase
func (s *service) SubmitFinalization(
	ctx context.Context, finalization emulator.BatchFinalization, connectorTree *tree.TxTree,
) (*SignedBatchFinalization, error) {
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
	return s.signFinalization(ctx, finalization, connectorTree)
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
