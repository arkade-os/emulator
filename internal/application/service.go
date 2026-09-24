// Package application wraps the pkg/emulator signer with arkd submit/finalize.
package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

type arkdClient interface {
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (arkTxid, finalArkTx string, signedCheckpointTxs []string, err error)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
	Close()
}

type service struct {
	emulator.Service
	arkd          arkdClient
	arkdPubKey    *btcec.PublicKey
	signerPubKeys []*btcec.PublicKey
}

// New connects to arkd and builds the emulator service.
func New(
	ctx context.Context, version string,
	secretKey *btcec.PrivateKey, deprecatedKeys []*btcec.PrivateKey, deprecatedKeysValidUntil *time.Time,
	arkdURL, arkdIndexerURL string, computeLimits arkade.ComputeLimits,
) (emulator.Service, error) {
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

	var info *client.Info
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
		ctx, secretKey, deprecatedKeys, deprecatedKeysValidUntil, arkdPubKey,
		versionedIndexer{indexerClient, clientVersion}, computeLimits,
	)
	if err != nil {
		return nil, err
	}
	svc, err := newService(lib, arkd, arkdPubKey)
	if err != nil {
		// lib owns the indexer
		handedOff = true
		lib.Close()
		arkd.Close()
		return nil, err
	}
	handedOff = true
	return svc, nil
}

func newService(lib emulator.Service, arkd arkdClient, arkdPubKey *btcec.PublicKey) (*service, error) {
	info, err := lib.GetInfo(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read signer info: %w", err)
	}
	signerPubKeys := make([]*btcec.PublicKey, 0, 1+len(info.DeprecatedSignerPublicKeys))
	for _, k := range append([]string{info.SignerPublicKey}, info.DeprecatedSignerPublicKeys...) {
		raw, err := hex.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("invalid signer pubkey %q: %w", k, err)
		}
		pubKey, err := btcec.ParsePubKey(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid signer pubkey %q: %w", k, err)
		}
		signerPubKeys = append(signerPubKeys, pubKey)
	}
	return &service{
		Service:       lib,
		arkd:          arkd,
		arkdPubKey:    arkdPubKey,
		signerPubKeys: signerPubKeys,
	}, nil
}

func (s *service) Close() {
	s.Service.Close()
	s.arkd.Close()
}

// versionedIndexer adds the x-sdk-version header to indexer calls.
type versionedIndexer struct {
	indexer.Indexer
	version string
}

func (v versionedIndexer) ctx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-sdk-version", v.version)
}

func (v versionedIndexer) GetVtxos(ctx context.Context, opts ...indexer.GetVtxosOption) (*indexer.VtxosResponse, error) {
	return v.Indexer.GetVtxos(v.ctx(ctx), opts...)
}

func (v versionedIndexer) GetCommitmentTx(ctx context.Context, txid string) (*indexer.CommitmentTx, error) {
	return v.Indexer.GetCommitmentTx(v.ctx(ctx), txid)
}
