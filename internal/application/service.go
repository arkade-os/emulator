package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

type Info struct {
	SignerPublicKey            string
	DeprecatedSignerPublicKeys []string
}

type OffchainTx struct {
	ArkTx       *psbt.Packet
	Checkpoints []*psbt.Packet
}

// IntentMessage is the common surface of every arkd intent message type;
// Encode/Decode are the only methods all six share.
type IntentMessage interface {
	Encode() (string, error)
	Decode(string) error
}

type Intent struct {
	Proof   intent.Proof
	Message IntentMessage
}

type BatchFinalization struct {
	Intent        Intent
	Forfeits      []*psbt.Packet
	ConnectorTree *tree.TxTree
	CommitmentTx  *psbt.Packet
}

type SignedBatchFinalization struct {
	Forfeits     []*psbt.Packet
	CommitmentTx *psbt.Packet
}

type OnchainTx struct {
	Tx *psbt.Packet
}

type Service interface {
	GetInfo(context.Context) (*Info, error)
	SubmitTx(context.Context, OffchainTx) (*OffchainTx, error)
	SubmitIntent(context.Context, Intent) (*psbt.Packet, error)
	SubmitFinalization(context.Context, BatchFinalization) (*SignedBatchFinalization, error)
	SubmitOnchainTx(context.Context, OnchainTx) (*psbt.Packet, error)
	Close()
}

type service struct {
	signer                   signer
	deprecatedSigners        []signer
	deprecatedKeysValidUntil *time.Time
	publicKey                string
	deprecatedPublicKeys     []string
	arkdClient               client.Client
	arkdPubKey               *btcec.PublicKey
	indexerClient            indexer.Indexer
	computeLimits            arkade.ComputeLimits
	clientVersion            string
}

// activeDeprecatedSigners returns the deprecated signers usable for the
// current request. A requester steers which key signs by choosing which
// tweaked key appears in the tapscript it submits, so deprecated keys carry
// indefinite signing authority unless bounded here. When
// deprecatedKeysValidUntil is set and has passed, deprecated keys stop being
// honored for both fresh signing (resolveArkadeScriptSigner) and
// finalization (getSignedInputAssociations) alike: a VTXO whose covenant
// still names a deprecated key must be spent before the cutover, or it can no
// longer be finalized by this emulator. A nil cutoff (the default, unset via
// config) preserves today's unbounded behavior.
func (s *service) activeDeprecatedSigners() []signer {
	if s.deprecatedKeysValidUntil != nil && time.Now().After(*s.deprecatedKeysValidUntil) {
		return nil
	}
	return s.deprecatedSigners
}

func New(ctx context.Context, version string, secretKey *btcec.PrivateKey, deprecatedKeys []*btcec.PrivateKey, deprecatedKeysValidUntil *time.Time, arkdURL, arkdIndexerURL string, computeLimits arkade.ComputeLimits) (Service, error) {
	if secretKey == nil {
		return nil, fmt.Errorf("current signer key is required")
	}

	clientVersion := xSdkVersionValue(version)

	arkdClient, err := grpcclient.NewClient(arkdURL, clientVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to create arkd client: %w", err)
	}

	indexerClient, err := grpcindexer.NewClient(arkdIndexerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create arkd indexer client: %w", err)
	}

	publicKey := hex.EncodeToString(secretKey.PubKey().SerializeCompressed())
	deprecatedSigners := make([]signer, 0, len(deprecatedKeys))
	deprecatedPublicKeys := make([]string, 0, len(deprecatedKeys))
	for i, deprecatedKey := range deprecatedKeys {
		if deprecatedKey == nil {
			return nil, fmt.Errorf("deprecated signer key #%d is required", i)
		}
		deprecatedSigners = append(deprecatedSigners, signer{deprecatedKey})
		deprecatedPublicKeys = append(deprecatedPublicKeys, hex.EncodeToString(deprecatedKey.PubKey().SerializeCompressed()))
	}

	var arkdInfo *client.Info

	// arkd may still be booting when the emulator starts, retry if it fails.
	err = retryWithBackoff(
		ctx, arkdConnectRetryConfig,
		func() error {
			var e error
			arkdInfo, e = arkdClient.GetInfo(withClientVersion(ctx, clientVersion))
			return e
		},
		func(attempt int, e error) {
			log.WithField("attempt", attempt).Warnf("arkd not ready: %s", e)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch arkd info: %w", err)
	}
	if arkdInfo == nil {
		return nil, fmt.Errorf("arkd info is required")
	}
	if arkdInfo.SignerPubKey == "" {
		return nil, fmt.Errorf("arkd info does not include signer pubkey")
	}

	decodedKey, err := hex.DecodeString(arkdInfo.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode arkd signer pubkey: %w", err)
	}

	arkdPubKey, err := btcec.ParsePubKey(decodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse arkd signer pubkey: %w", err)
	}

	return &service{
		signer:                   signer{secretKey},
		deprecatedSigners:        deprecatedSigners,
		deprecatedKeysValidUntil: deprecatedKeysValidUntil,
		publicKey:                publicKey,
		deprecatedPublicKeys:     deprecatedPublicKeys,
		arkdClient:               arkdClient,
		arkdPubKey:               arkdPubKey,
		indexerClient:            indexerClient,
		computeLimits:            computeLimits,
		clientVersion:            clientVersion,
	}, nil
}

func (s *service) Close() {
	s.arkdClient.Close()
	s.indexerClient.Close()
}

func (s *service) GetInfo(ctx context.Context) (*Info, error) {
	return &Info{
		SignerPublicKey:            s.publicKey,
		DeprecatedSignerPublicKeys: append([]string(nil), s.deprecatedPublicKeys...),
	}, nil
}

var arkdConnectRetryConfig = retryConfig{
	MinAttempts:  0,
	InitialDelay: 1 * time.Second,
	MaxDelay:     45 * time.Second,
	Multiplier:   2.0,
	Jitter:       0.2,
}

func xSdkVersionValue(version string) string {
	return "emulator/" + version
}

func withClientVersion(ctx context.Context, clientVersion string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-sdk-version", clientVersion)
}
