// Package emulator executes ArkadeScript on offchain and onchain Ark
// transactions and signs the resulting inputs. A Service signs autonomously;
// the arkd round-trip that submits and finalizes a signed tx is supplied by an
// injectable Finalizer, which may be nil for signing-only use. Build one with
// New.
package emulator

import (
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

// Finalizer is the subset of the client-lib Client used for the finalizer
// role in SubmitTx. It is satisfied structurally by client-lib's grpc client.
type Finalizer interface {
	SubmitTx(ctx context.Context, signedArkTx string, checkpointTxs []string) (arkTxid, finalArkTx string, signedCheckpointTxs []string, err error)
	FinalizeTx(ctx context.Context, arkTxid string, finalCheckpointTxs []string) error
}

// Indexer is the subset of the client-lib Indexer the Service queries: vtxo
// expiry for OP_PUSHEXPIRY scripts and commitment tx existence before signing a
// batch finalization. It is satisfied structurally by client-lib's grpc indexer.
type Indexer interface {
	GetVtxos(ctx context.Context, opts ...indexer.GetVtxosOption) (*indexer.VtxosResponse, error)
	GetCommitmentTx(ctx context.Context, txid string) (*indexer.CommitmentTx, error)
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
	// SubmitTx signs the given tx in place: the returned OffchainTx aliases the
	// caller's ArkTx and checkpoint packets, except the ark tx when a Finalizer
	// replaces it with arkd's finalized one. The in-place signatures persist even
	// when SubmitTx returns an error and are appended rather than replaced, so an
	// OffchainTx must not be reused or re-submitted across calls.
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
	finalizer                Finalizer
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
// longer be finalized by this emulator. A nil cutoff preserves the unbounded
// behavior.
func (s *service) activeDeprecatedSigners() []signer {
	if s.deprecatedKeysValidUntil != nil && time.Now().After(*s.deprecatedKeysValidUntil) {
		return nil
	}
	return s.deprecatedSigners
}

// isTypedNil reports whether v is a non-nil interface holding a nil value of a
// nilable kind. Such a value passes a `!= nil` check but is almost always a
// caller bug, and panics on any method that dereferences the receiver.
func isTypedNil(v any) bool {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map,
		reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}

// New builds a signing Service. secretKey is the current arkade-signing key and
// arkdPubKey is the arkd signer key. Both are required. deprecatedKeys may be
// nil; deprecatedKeysValidUntil optionally bounds how long they keep signing
// authority (see activeDeprecatedSigners).
//
// finalizer may be nil: with a nil finalizer the Service runs signing-only, so
// SubmitTx signs and returns without any arkd round-trip. Pass a non-nil
// Finalizer (e.g. client-lib's grpc client) to also submit and finalize on arkd.
//
// indexerClient may be nil, but SubmitIntent on an OP_PUSHEXPIRY script and
// SubmitFinalization then fail, since both need arkd's indexer.
//
// The Service owns finalizer and indexerClient: Close closes each one that has
// a Close method with no results, so do not pass a client whose lifecycle you
// manage elsewhere. A typed nil (e.g. a nil *grpcClient wrapped in the
// interface) is rejected here rather than left to panic on its nil receiver.
//
// The context is currently unused; it is accepted for forward compatibility.
// Note the standalone emulator's arkd-connect retry lives in
// internal/config/retry.go, not here.
func New(
	_ context.Context,
	secretKey *btcec.PrivateKey, deprecatedKeys []*btcec.PrivateKey, deprecatedKeysValidUntil *time.Time,
	arkdPubKey *btcec.PublicKey, finalizer Finalizer, indexerClient Indexer,
	computeLimits arkade.ComputeLimits,
) (Service, error) {
	if secretKey == nil {
		return nil, fmt.Errorf("current signer key is required")
	}

	if arkdPubKey == nil {
		return nil, fmt.Errorf("arkd public key is required")
	}

	if isTypedNil(finalizer) {
		return nil, fmt.Errorf("finalizer is a typed nil, pass an untyped nil for signing-only mode")
	}

	if isTypedNil(indexerClient) {
		return nil, fmt.Errorf("indexer is a typed nil, pass an untyped nil to run without one")
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
		finalizer:                finalizer,
		indexerClient:            indexerClient,
		arkdPubKey:               arkdPubKey,
		computeLimits:            computeLimits,
	}, nil
}

func (s *service) Close() {
	// client-lib's clients expose Close() with no return value, so they do not
	// satisfy io.Closer; assert the actual signature instead.
	for _, c := range []any{s.finalizer, s.indexerClient} {
		if closer, ok := c.(interface{ Close() }); ok {
			closer.Close()
		}
	}
}

func (s *service) GetInfo(ctx context.Context) (*Info, error) {
	return &Info{
		SignerPublicKey:            s.publicKey,
		DeprecatedSignerPublicKeys: append([]string(nil), s.deprecatedPublicKeys...),
	}, nil
}
