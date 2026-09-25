// Package emulator executes ArkadeScript and signs Ark transactions.
package emulator

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
)

// Indexer is the subset of the arkd indexer client used by Service.
type Indexer interface {
	GetVtxos(ctx context.Context, opts ...clientlib.GetVtxosOption) (*clientlib.VtxosResponse, error)
	GetCommitmentTx(ctx context.Context, txid string) (*clientlib.CommitmentTx, error)
}

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
	indexerClient            Indexer
	arkdPubKey               *btcec.PublicKey
	computeLimits            arkade.ComputeLimits
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

// New builds a signing Service. It owns indexerClient and closes it on Close.
func New(
	secretKey *btcec.PrivateKey, deprecatedKeys []*btcec.PrivateKey, deprecatedKeysValidUntil *time.Time,
	arkdPubKey *btcec.PublicKey, indexerClient Indexer,
	computeLimits arkade.ComputeLimits,
) (Service, error) {
	if secretKey == nil {
		return nil, fmt.Errorf("current signer key is required")
	}

	if arkdPubKey == nil {
		return nil, fmt.Errorf("arkd public key is required")
	}

	if indexerClient == nil {
		return nil, fmt.Errorf("arkd indexer is required")
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

	return &service{
		signer:                   signer{secretKey},
		deprecatedSigners:        deprecatedSigners,
		deprecatedKeysValidUntil: deprecatedKeysValidUntil,
		publicKey:                publicKey,
		deprecatedPublicKeys:     deprecatedPublicKeys,
		indexerClient:            indexerClient,
		arkdPubKey:               arkdPubKey,
		computeLimits:            computeLimits,
	}, nil
}

func (s *service) Close() {
	// client-lib's Close() returns nothing, so it is not an io.Closer.
	if closer, ok := s.indexerClient.(interface{ Close() }); ok {
		closer.Close()
	}
}

func (s *service) GetInfo(ctx context.Context) (*Info, error) {
	return &Info{
		SignerPublicKey:            s.publicKey,
		DeprecatedSignerPublicKeys: append([]string(nil), s.deprecatedPublicKeys...),
	}, nil
}
