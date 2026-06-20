package emulator

import (
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestResolveArkadeScriptSigner(t *testing.T) {
	type resolveCall struct {
		entry   arkade.EmulatorEntry
		wantKey *btcec.PrivateKey
	}

	t.Run("matches exist", func(t *testing.T) {
		currentKey := newResolverPrivateKey(t)
		deprecatedKey := newResolverPrivateKey(t)
		nonMatchingDeprecatedKey := newResolverPrivateKey(t)
		matchingDeprecatedKey := newResolverPrivateKey(t)

		entry := arkade.EmulatorEntry{Vin: 0, Script: []byte{txscript.OP_TRUE}}
		mixedEntries := []arkade.EmulatorEntry{
			{Vin: 0, Script: []byte{txscript.OP_TRUE}},
			{Vin: 1, Script: []byte{txscript.OP_FALSE}},
		}

		currentPtx := newResolverPacket(t, entry, currentKey.PubKey())
		deprecatedPtx := newResolverPacket(t, entry, deprecatedKey.PubKey())
		matchingDeprecatedPtx := newResolverPacket(t, entry, matchingDeprecatedKey.PubKey())
		mixedPtx := newResolverPacketForEntries(t, []resolverEntrySigner{
			{entry: mixedEntries[0], signerPublicKey: currentKey.PubKey()},
			{entry: mixedEntries[1], signerPublicKey: deprecatedKey.PubKey()},
		})

		tests := []struct {
			name       string
			current    signer
			deprecated []signer
			ptx        *psbt.Packet
			calls      []resolveCall
		}{
			{
				name:    "matches current signer",
				current: signer{currentKey},
				ptx:     currentPtx,
				calls:   []resolveCall{{entry: entry, wantKey: currentKey}},
			},
			{
				name:       "matches deprecated signer",
				current:    signer{currentKey},
				deprecated: []signer{{deprecatedKey}},
				ptx:        deprecatedPtx,
				calls:      []resolveCall{{entry: entry, wantKey: deprecatedKey}},
			},
			{
				name:       "prefers current signer",
				current:    signer{currentKey},
				deprecated: []signer{{currentKey}},
				ptx:        currentPtx,
				calls:      []resolveCall{{entry: entry, wantKey: currentKey}},
			},
			{
				name:       "tries deprecated signers in order",
				current:    signer{currentKey},
				deprecated: []signer{{nonMatchingDeprecatedKey}, {matchingDeprecatedKey}},
				ptx:        matchingDeprecatedPtx,
				calls:      []resolveCall{{entry: entry, wantKey: matchingDeprecatedKey}},
			},
			{
				name:       "resolves mixed key entries independently",
				current:    signer{currentKey},
				deprecated: []signer{{deprecatedKey}},
				ptx:        mixedPtx,
				calls: []resolveCall{
					{entry: mixedEntries[0], wantKey: currentKey},
					{entry: mixedEntries[1], wantKey: deprecatedKey},
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				for _, call := range tc.calls {
					matchedSigner, script, err := resolveArkadeScriptSigner(
						tc.current, tc.deprecated, tc.ptx, call.entry,
					)

					require.NoError(t, err)
					require.Same(t, call.wantKey, matchedSigner.secretKey)
					require.NotNil(t, script)
					require.Equal(t, arkade.ArkadeScriptHash(call.entry.Script), script.Hash())
				}
			})
		}
	})

	t.Run("error", func(t *testing.T) {
		currentKey := newResolverPrivateKey(t)
		deprecatedKey := newResolverPrivateKey(t)
		packetKey := newResolverPrivateKey(t)
		entry := arkade.EmulatorEntry{Vin: 0, Script: []byte{txscript.OP_TRUE}}

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		structuralPtx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		notFoundPtx := newResolverPacket(t, entry, packetKey.PubKey())

		tests := []struct {
			name       string
			current    signer
			deprecated []signer
			ptx        *psbt.Packet
			entry      arkade.EmulatorEntry
			requireErr func(t *testing.T, err error)
		}{
			{
				name:       "returns structural errors without fallback",
				current:    signer{currentKey},
				deprecated: []signer{{deprecatedKey}},
				ptx:        structuralPtx,
				entry:      entry,
				requireErr: func(t *testing.T, err error) {
					require.ErrorContains(t, err, "TaprootLeafScript")
				},
			},
			{
				name:       "returns not found after exhausting signers",
				current:    signer{currentKey},
				deprecated: []signer{{deprecatedKey}},
				ptx:        notFoundPtx,
				entry:      entry,
				requireErr: func(t *testing.T, err error) {
					require.ErrorIs(t, err, arkade.ErrTweakedArkadePubKeyNotFound)
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				matchedSigner, script, err := resolveArkadeScriptSigner(
					tc.current, tc.deprecated, tc.ptx, tc.entry,
				)

				tc.requireErr(t, err)
				require.Nil(t, matchedSigner.secretKey)
				require.Nil(t, script)
			})
		}
	})
}

func newResolverPrivateKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key
}

func newResolverPacket(t *testing.T, entry arkade.EmulatorEntry, signerPublicKey *btcec.PublicKey) *psbt.Packet {
	t.Helper()

	return newResolverPacketForEntries(t, []resolverEntrySigner{
		{entry: entry, signerPublicKey: signerPublicKey},
	})
}

type resolverEntrySigner struct {
	entry           arkade.EmulatorEntry
	signerPublicKey *btcec.PublicKey
}

func newResolverPacketForEntries(t *testing.T, entries []resolverEntrySigner) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	for range entries {
		tx.AddTxIn(&wire.TxIn{})
	}

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	for _, entry := range entries {
		tweakedSigner := arkade.ComputeArkadeScriptPublicKey(
			entry.signerPublicKey, arkade.ArkadeScriptHash(entry.entry.Script),
		)
		closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{tweakedSigner}}
		tapscript, err := closure.Script()
		require.NoError(t, err)

		ptx.Inputs[entry.entry.Vin].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			Script:      tapscript,
			LeafVersion: txscript.BaseLeafVersion,
		}}
	}

	return ptx
}
