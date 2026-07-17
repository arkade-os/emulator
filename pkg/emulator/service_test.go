package emulator

import (
	"context"
	"encoding/hex"
	"testing"

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
		_, err := New(context.Background(), nil, nil, arkdKey.PubKey(), nil, arkade.ComputeLimits{})
		require.ErrorContains(t, err, "current signer key is required")
	})

	t.Run("nil arkd pubkey", func(t *testing.T) {
		_, err := New(context.Background(), signerKey, nil, nil, nil, arkade.ComputeLimits{})
		require.ErrorContains(t, err, "arkd public key is required")
	})

	t.Run("signing-only (nil finalizer)", func(t *testing.T) {
		svc, err := New(context.Background(), signerKey, nil, arkdKey.PubKey(), nil, arkade.ComputeLimits{})
		require.NoError(t, err)
		require.NotNil(t, svc)
		// Close must be a no-op, not a panic, when the finalizer is nil.
		require.NotPanics(t, svc.Close)
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
		context.Background(), signerKey, []*btcec.PrivateKey{deprecatedKey},
		arkdKey.PubKey(), nil, arkade.ComputeLimits{},
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
