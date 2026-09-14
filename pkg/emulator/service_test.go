package emulator

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("nil signer key", func(t *testing.T) {
		_, err := New(context.Background(), nil, nil, nil, arkdKey.PubKey(), nil, nil, arkade.ComputeLimits{})
		require.ErrorContains(t, err, "current signer key is required")
	})

	t.Run("nil arkd pubkey", func(t *testing.T) {
		_, err := New(context.Background(), signerKey, nil, nil, nil, nil, nil, arkade.ComputeLimits{})
		require.ErrorContains(t, err, "arkd public key is required")
	})

	t.Run("signing-only (nil finalizer)", func(t *testing.T) {
		svc, err := New(context.Background(), signerKey, nil, nil, arkdKey.PubKey(), nil, nil, arkade.ComputeLimits{})
		require.NoError(t, err)
		require.NotNil(t, svc)
		// Close must be a no-op, not a panic, when the finalizer is nil.
		require.NotPanics(t, svc.Close)
	})

	t.Run("typed nil finalizer", func(t *testing.T) {
		// a nil *countingFinalizer wrapped in the interface is non-nil to a
		// `!= nil` check, so New must reject it rather than let SubmitTx or
		// Close panic on the nil receiver later.
		var typedNil *countingFinalizer
		svc, err := New(context.Background(), signerKey, nil, nil, arkdKey.PubKey(), typedNil, nil, arkade.ComputeLimits{})
		require.ErrorContains(t, err, "typed nil")
		require.Nil(t, svc)
	})

	t.Run("finalizer is accepted and owned", func(t *testing.T) {
		// the guard must not reject a live finalizer, and the Service owns it:
		// Close forwards to the finalizer's own Close.
		fin := &countingFinalizer{}
		svc, err := New(context.Background(), signerKey, nil, nil, arkdKey.PubKey(), fin, nil, arkade.ComputeLimits{})
		require.NoError(t, err)
		require.NotNil(t, svc)

		svc.Close()
		require.Equal(t, 1, fin.closeCalls)
	})
}

func TestGetInfo(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	deprecatedKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	svc, err := New(
		context.Background(), signerKey, []*btcec.PrivateKey{deprecatedKey}, nil,
		arkdKey.PubKey(), nil, nil, arkade.ComputeLimits{},
	)
	require.NoError(t, err)

	info, err := svc.GetInfo(context.Background())
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(signerKey.PubKey().SerializeCompressed()), info.SignerPublicKey)
	require.Equal(t,
		[]string{hex.EncodeToString(deprecatedKey.PubKey().SerializeCompressed())},
		info.DeprecatedSignerPublicKeys,
	)

	// GetInfo returns a defensive copy: mutating the result must not leak into
	// the service's own deprecated keys.
	info.DeprecatedSignerPublicKeys[0] = "mutated"
	info2, err := svc.GetInfo(context.Background())
	require.NoError(t, err)
	require.NotEqual(t, "mutated", info2.DeprecatedSignerPublicKeys[0])
}

// countingFinalizer is a Finalizer whose Close dereferences the receiver, so a
// typed-nil value of it panics on the very Close() the service type-asserts.
// Used both to prove New rejects a typed nil and to check that Close forwards to
// a live finalizer.
type countingFinalizer struct {
	closeCalls int
}

func (m *countingFinalizer) SubmitTx(context.Context, string, []string) (string, string, []string, error) {
	return "", "", nil, nil
}

func (m *countingFinalizer) FinalizeTx(context.Context, string, []string) error {
	return nil
}

func (m *countingFinalizer) Close() { m.closeCalls++ }

// A requester steers which key signs by choosing which tweaked key appears
// in the tapscript it submits (resolveArkadeScriptSigner tries the current
// key, then falls through to every deprecated key). Without a cutoff,
// deprecated keys carry indefinite signing authority. These tests pin the
// activeDeprecatedSigners cutoff behavior: unset means unbounded (today's
// behavior, unchanged for deployments that don't opt in), set means the
// deprecated keys stop being usable, for both fresh signing and
// finalization, once the cutoff has passed.
func TestActiveDeprecatedSigners(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	deprecated := []signer{{secretKey: key}}

	t.Run("nil cutoff is unbounded", func(t *testing.T) {
		svc := &service{deprecatedSigners: deprecated}
		require.Equal(t, deprecated, svc.activeDeprecatedSigners())
	})

	t.Run("cutoff in the future still allows deprecated keys", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		svc := &service{deprecatedSigners: deprecated, deprecatedKeysValidUntil: &future}
		require.Equal(t, deprecated, svc.activeDeprecatedSigners())
	})

	t.Run("cutoff in the past rejects deprecated keys", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		svc := &service{deprecatedSigners: deprecated, deprecatedKeysValidUntil: &past}
		require.Empty(t, svc.activeDeprecatedSigners())
	})
}
