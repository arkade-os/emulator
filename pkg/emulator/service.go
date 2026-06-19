package emulator

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

// Finalizer is the subset of the go-sdk TransportClient used for the finalizer
// role in SubmitTx. It is satisfied structurally by go-sdk's grpc client.
type Finalizer interface {
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (arkTxid, finalArkTx string, signedCheckpointTxs []string, err error)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
}

type Info struct {
	SignerPublicKey            string
	DeprecatedSignerPublicKeys []string
}

type OffchainTx struct {
	ArkTx       *psbt.Packet
	Checkpoints []*psbt.Packet
}

type Intent struct {
	Proof   intent.Proof
	Message intent.RegisterMessage
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
	finalizer            Finalizer
	arkdPubKey           *btcec.PublicKey
	computeLimits        arkade.ComputeLimits
}

func New(_ context.Context, secretKey *btcec.PrivateKey, deprecatedKeys []*btcec.PrivateKey, arkdPubKey *btcec.PublicKey, finalizer Finalizer, computeLimits arkade.ComputeLimits) (Service, error) {
	if secretKey == nil {
		return nil, fmt.Errorf("current signer key is required")
	}

	if arkdPubKey == nil {
		return nil, fmt.Errorf("arkd public key is required")
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
		signer:               signer{secretKey},
		deprecatedSigners:    deprecatedSigners,
		publicKey:            publicKey,
		deprecatedPublicKeys: deprecatedPublicKeys,
		finalizer:            finalizer,
		arkdPubKey:           arkdPubKey,
		computeLimits:        computeLimits,
	}, nil
}

func (s *service) Close() {
	if closer, ok := s.finalizer.(io.Closer); ok {
		closer.Close()
	}
}

func (s *service) GetInfo(ctx context.Context) (*Info, error) {
	return &Info{
		SignerPublicKey:            s.publicKey,
		DeprecatedSignerPublicKeys: append([]string(nil), s.deprecatedPublicKeys...),
	}, nil
}
