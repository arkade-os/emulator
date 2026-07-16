package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/go-sdk/client"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
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
	signer               signer
	deprecatedSigners    []signer
	publicKey            string
	deprecatedPublicKeys []string
	arkdClient           client.TransportClient
	arkdPubKey           *btcec.PublicKey
	computeLimits        arkade.ComputeLimits
}

func New(ctx context.Context, secretKey *btcec.PrivateKey, deprecatedKeys []*btcec.PrivateKey, arkdURL string, computeLimits arkade.ComputeLimits) (Service, error) {
	if secretKey == nil {
		return nil, fmt.Errorf("current signer key is required")
	}

	arkdClient, err := grpcclient.NewClient(arkdURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create arkd client: %w", err)
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
			arkdInfo, e = arkdClient.GetInfo(ctx)
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
		signer:               signer{secretKey},
		deprecatedSigners:    deprecatedSigners,
		publicKey:            publicKey,
		deprecatedPublicKeys: deprecatedPublicKeys,
		arkdClient:           arkdClient,
		arkdPubKey:           arkdPubKey,
		computeLimits:        computeLimits,
	}, nil
}

func (s *service) Close() {
	s.arkdClient.Close()
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
