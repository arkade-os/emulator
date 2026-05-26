package application

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ArkLabsHQ/emulator/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	sdkclient "github.com/arkade-os/go-sdk/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestFinalizerAccumulatorFlow(t *testing.T) {
	thisSigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	aliceSigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bobSigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdSigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScriptBytes := []byte{txscript.OP_TRUE}
	tweakedThisSigner := arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes))

	newScript := func(t *testing.T, closurePubKeys ...*btcec.PublicKey) *arkade.ArkadeScript {
		t.Helper()

		closure := arkscript.MultisigClosure{PubKeys: closurePubKeys}
		vtxoScript := arkscript.TapscriptsVtxoScript{
			Closures: []arkscript.Closure{&closure},
		}

		tapKey, tapTree, err := vtxoScript.TapTree()
		require.NoError(t, err)

		tapscript, err := closure.Script()
		require.NoError(t, err)

		merkleProof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(tapscript).TapHash())
		require.NoError(t, err)

		pkScript, err := arkscript.P2TRScript(tapKey)
		require.NoError(t, err)

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}})
		tx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: pkScript})

		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 2_000, PkScript: pkScript}
		ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: merkleProof.ControlBlock,
			Script:       merkleProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}}

		packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: arkadeScriptBytes})
		require.NoError(t, err)

		ext := extension.Extension{packet}
		txOut, err := ext.TxOut()
		require.NoError(t, err)
		ptx.UnsignedTx.AddTxOut(txOut)
		ptx.Outputs = append(ptx.Outputs, psbt.POutput{})

		emulatorPacket, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
		require.NoError(t, err)
		require.Len(t, emulatorPacket, 1)

		script, err := arkade.ReadArkadeScript(ptx, thisSigner.PubKey(), emulatorPacket[0])
		require.NoError(t, err)
		return script
	}

	validCases := []struct {
		name        string
		closures    [][]*btcec.PublicKey
		isFinalizer bool
	}{
		{
			// no owned inputs
			name:        "no owned inputs",
			closures:    nil,
			isFinalizer: false,
		},
		{
			// [this, arkd]
			name: "single finalizer input",
			closures: [][]*btcec.PublicKey{{
				tweakedThisSigner,
				arkdSigner.PubKey(),
			}},
			isFinalizer: true,
		},
		{
			// [this, bob, arkd]
			name: "single non-finalizer input",
			closures: [][]*btcec.PublicKey{{
				tweakedThisSigner,
				bobSigner.PubKey(),
				arkdSigner.PubKey(),
			}},
			isFinalizer: false,
		},
		{
			// vin 0: [this, arkd]
			// vin 1: [alice, this, arkd]
			name: "two finalizer inputs",
			closures: [][]*btcec.PublicKey{
				{
					tweakedThisSigner,
					arkdSigner.PubKey(),
				},
				{
					aliceSigner.PubKey(),
					tweakedThisSigner,
					arkdSigner.PubKey(),
				},
			},
			isFinalizer: true,
		},
		{
			// vin 0: [this, bob, arkd]
			// vin 1: [this, alice, arkd]
			name: "two non-finalizer inputs",
			closures: [][]*btcec.PublicKey{
				{
					tweakedThisSigner,
					bobSigner.PubKey(),
					arkdSigner.PubKey(),
				},
				{
					tweakedThisSigner,
					aliceSigner.PubKey(),
					arkdSigner.PubKey(),
				},
			},
			isFinalizer: false,
		},
	}

	invalidCases := []struct {
		name     string
		closures [][]*btcec.PublicKey
		wantErr  string
	}{
		{
			// vin 0: [this, bob, arkd]
			// vin 1: [alice, this, arkd]
			name: "mixed false then true",
			closures: [][]*btcec.PublicKey{
				{
					tweakedThisSigner,
					bobSigner.PubKey(),
					arkdSigner.PubKey(),
				},
				{
					aliceSigner.PubKey(),
					tweakedThisSigner,
					arkdSigner.PubKey(),
				},
			},
			wantErr: "different finalizer",
		},
		{
			// vin 0: [this, arkd]
			// vin 1: [this, bob, arkd]
			name: "mixed true then false",
			closures: [][]*btcec.PublicKey{
				{
					tweakedThisSigner,
					arkdSigner.PubKey(),
				},
				{
					tweakedThisSigner,
					bobSigner.PubKey(),
					arkdSigner.PubKey(),
				},
			},
			wantErr: "different finalizer",
		},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			acc := newFinalizerAccumulator(arkdSigner.PubKey())
			for vin, closure := range tc.closures {
				err := acc.checkScript(uint16(vin), newScript(t, closure...))
				require.NoError(t, err)
			}

			got, err := acc.isFinalizer()
			require.NoError(t, err)
			require.Equal(t, tc.isFinalizer, got)
		})
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			acc := newFinalizerAccumulator(arkdSigner.PubKey())
			for vin, closure := range tc.closures {
				err := acc.checkScript(uint16(vin), newScript(t, closure...))
				require.NoError(t, err)
			}

			got, err := acc.isFinalizer()
			require.ErrorContains(t, err, tc.wantErr)
			require.False(t, got)
		})
	}
}

func TestVerifyCheckpointSignatures(t *testing.T) {
	thisSigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	aliceSigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdSigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkadeScriptBytes := []byte{txscript.OP_TRUE}
	tweakedThisSigner := arkade.ComputeArkadeScriptPrivateKey(thisSigner, arkade.ArkadeScriptHash(arkadeScriptBytes))
	type checkpointSetup struct {
		packet     *psbt.Packet
		leaf       txscript.TapLeaf
		cbBytes    []byte
		thisKey    *btcec.PrivateKey
		aliceKey   *btcec.PrivateKey
		arkdPubKey *btcec.PublicKey
	}
	newCheckpoint := func(t *testing.T, closurePubKeys ...*btcec.PublicKey) checkpointSetup {
		t.Helper()
		vtxoScript := arkscript.TapscriptsVtxoScript{
			Closures: []arkscript.Closure{&arkscript.MultisigClosure{PubKeys: closurePubKeys}},
		}
		tapKey, tapTree, err := vtxoScript.TapTree()
		require.NoError(t, err)
		closure := vtxoScript.ForfeitClosures()[0]
		tapscript, err := closure.Script()
		require.NoError(t, err)
		leaf := txscript.NewBaseTapLeaf(tapscript)
		merkleProof, err := tapTree.GetTaprootMerkleProof(leaf.TapHash())
		require.NoError(t, err)
		pkScript, err := arkscript.P2TRScript(tapKey)
		require.NoError(t, err)
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}})
		tx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: pkScript})
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 2_000, PkScript: pkScript}
		ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: merkleProof.ControlBlock,
			Script:       merkleProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}}
		return checkpointSetup{
			packet:     ptx,
			leaf:       leaf,
			cbBytes:    merkleProof.ControlBlock,
			thisKey:    thisSigner,
			aliceKey:   aliceSigner,
			arkdPubKey: arkdSigner.PubKey(),
		}
	}
	makeSig := func(t *testing.T, signerKey *btcec.PrivateKey, ptx *psbt.Packet, leaf txscript.TapLeaf) *psbt.TaprootScriptSpendSig {
		t.Helper()
		prevoutFetcher, err := computePrevoutFetcher(ptx)
		require.NoError(t, err)
		txSigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)
		sig, err := txscript.RawTxInTapscriptSignature(
			ptx.UnsignedTx,
			txSigHashes,
			0,
			ptx.Inputs[0].WitnessUtxo.Value,
			ptx.Inputs[0].WitnessUtxo.PkScript,
			leaf,
			txscript.SigHashDefault,
			signerKey,
		)
		require.NoError(t, err)
		leafHash := leaf.TapHash()
		return &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: schnorr.SerializePubKey(signerKey.PubKey()),
			LeafHash:    leafHash[:],
			Signature:   sig[:64],
			SigHash:     txscript.SigHashDefault,
		}
	}
	t.Run("valid", func(t *testing.T) {
		t.Run("input without taproot leaf script is rejected", func(t *testing.T) {
			setup := newCheckpoint(t,
				arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes)),
				arkdSigner.PubKey(),
			)
			setup.packet.Inputs[0].TaprootLeafScript = nil
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.ErrorContains(t, err, "missing taproot leaf script")
		})
		t.Run("all non-arkd signers present in two of two closure", func(t *testing.T) {
			setup := newCheckpoint(t,
				arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes)),
				arkdSigner.PubKey(),
			)
			setup.packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
				makeSig(t, tweakedThisSigner, setup.packet, setup.leaf),
			}
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.NoError(t, err)
		})
		t.Run("all non-arkd signers present in three key closure", func(t *testing.T) {
			tweakedThis := arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes))
			setup := newCheckpoint(t,
				aliceSigner.PubKey(),
				tweakedThis,
				arkdSigner.PubKey(),
			)
			setup.packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
				makeSig(t, aliceSigner, setup.packet, setup.leaf),
				makeSig(t, tweakedThisSigner, setup.packet, setup.leaf),
			}
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.NoError(t, err)
		})
	})
	t.Run("invalid", func(t *testing.T) {
		t.Run("wrong parity bit in control block", func(t *testing.T) {
			setup := newCheckpoint(t,
				arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes)),
				arkdSigner.PubKey(),
			)
			corrupted := append([]byte(nil), setup.cbBytes...)
			corrupted[0] ^= 0x01
			setup.packet.Inputs[0].TaprootLeafScript[0].ControlBlock = corrupted
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.Error(t, err)
		})
		t.Run("wrong x coordinate from tampered merkle path", func(t *testing.T) {
			setup := newCheckpoint(t,
				arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes)),
				arkdSigner.PubKey(),
			)
			fakeNode := bytes.Repeat([]byte{1}, 32)
			corrupted := append(append([]byte(nil), setup.cbBytes...), fakeNode...)
			setup.packet.Inputs[0].TaprootLeafScript[0].ControlBlock = corrupted
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.Error(t, err)
		})
		t.Run("invalid signature", func(t *testing.T) {
			setup := newCheckpoint(t,
				arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes)),
				arkdSigner.PubKey(),
			)
			sig := makeSig(t, tweakedThisSigner, setup.packet, setup.leaf)
			sig.Signature[0] ^= 0xff
			setup.packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.Error(t, err)
		})
		t.Run("missing non-arkd signature", func(t *testing.T) {
			tweakedThis := arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes))
			setup := newCheckpoint(t,
				aliceSigner.PubKey(),
				tweakedThis,
				arkdSigner.PubKey(),
			)
			setup.packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
				makeSig(t, aliceSigner, setup.packet, setup.leaf),
			}
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.Error(t, err)
			require.ErrorContains(t, err, "missing signature")
		})
	})
}

type mockArkdClient struct {
	finalizeErrs     []error
	finalizeCalls    int
	finalizeTxids    []string
	finalizePayloads [][]string
}

func (m *mockArkdClient) GetInfo(context.Context) (*sdkclient.Info, error) {
	panic("unexpected call to GetInfo")
}
func (m *mockArkdClient) RegisterIntent(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("not implemented")
}
func (m *mockArkdClient) DeleteIntent(context.Context, string, string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockArkdClient) EstimateIntentFee(context.Context, string, string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}
func (m *mockArkdClient) ConfirmRegistration(context.Context, string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockArkdClient) SubmitTreeNonces(context.Context, string, string, tree.TreeNonces) error {
	return fmt.Errorf("not implemented")
}
func (m *mockArkdClient) SubmitTreeSignatures(context.Context, string, string, tree.TreePartialSigs) error {
	return fmt.Errorf("not implemented")
}
func (m *mockArkdClient) SubmitSignedForfeitTxs(context.Context, []string, string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockArkdClient) GetEventStream(context.Context, []string) (<-chan sdkclient.BatchEventChannel, func(), error) {
	return nil, func() {}, fmt.Errorf("not implemented")
}
func (m *mockArkdClient) SubmitTx(context.Context, string, []string) (string, string, []string, error) {
	panic("unexpected call to SubmitTx")
}
func (m *mockArkdClient) FinalizeTx(_ context.Context, txid string, checkpoints []string) error {
	m.finalizeCalls++
	m.finalizeTxids = append(m.finalizeTxids, txid)
	m.finalizePayloads = append(m.finalizePayloads, append([]string(nil), checkpoints...))
	if len(m.finalizeErrs) == 0 {
		return nil
	}
	err := m.finalizeErrs[0]
	m.finalizeErrs = m.finalizeErrs[1:]
	return err
}
func (m *mockArkdClient) GetPendingTx(context.Context, string, string) ([]sdkclient.AcceptedOffchainTx, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockArkdClient) GetTransactionsStream(context.Context) (<-chan sdkclient.TransactionEvent, func(), error) {
	return nil, func() {}, fmt.Errorf("not implemented")
}
func (m *mockArkdClient) ModifyStreamTopics(context.Context, []string, []string) ([]string, []string, []string, error) {
	return nil, nil, nil, fmt.Errorf("not implemented")
}
func (m *mockArkdClient) OverwriteStreamTopics(context.Context, []string) ([]string, []string, []string, error) {
	return nil, nil, nil, fmt.Errorf("not implemented")
}
func (m *mockArkdClient) Close() {}

func TestRetryFinalize(t *testing.T) {
	originalCfg := finalizeRetryConfig
	finalizeRetryConfig.MinAttempts = 3
	finalizeRetryConfig.InitialDelay = 10 * time.Millisecond
	finalizeRetryConfig.Jitter = 0
	finalizeRetryConfig.Multiplier = 1
	t.Cleanup(func() {
		finalizeRetryConfig = originalCfg
	})

	t.Run("success after retries", func(t *testing.T) {
		client := &mockArkdClient{
			finalizeErrs: []error{
				fmt.Errorf("retry 1"),
				fmt.Errorf("retry 2"),
				nil,
			},
		}
		svc := &service{arkdClient: client}
		checkpoints := []string{"checkpoint-a", "checkpoint-b"}
		err := svc.retryFinalize(
			t.Context(),
			"txid-123",
			checkpoints,
		)
		require.NoError(t, err)
		require.Equal(t, 3, client.finalizeCalls)
		require.Equal(t, []string{"txid-123", "txid-123", "txid-123"}, client.finalizeTxids)
		require.Equal(t, [][]string{
			{"checkpoint-a", "checkpoint-b"},
			{"checkpoint-a", "checkpoint-b"},
			{"checkpoint-a", "checkpoint-b"},
		}, client.finalizePayloads)
	})
	t.Run("exhausts minimum retries", func(t *testing.T) {
		client := &mockArkdClient{
			finalizeErrs: []error{
				fmt.Errorf("retry 1"),
				fmt.Errorf("retry 2"),
				fmt.Errorf("retry 3"),
				fmt.Errorf("retry 4"),
			},
		}
		svc := &service{arkdClient: client}
		ctx, cancel := context.WithCancel(t.Context())
		// simulates client hangup
		cancel()
		err := svc.retryFinalize(
			ctx,
			"txid-123",
			[]string{"checkpoint-a"},
		)
		require.ErrorContains(t, err, "context canceled")
		require.Equal(t, 3, client.finalizeCalls)
		require.Equal(t, []string{"txid-123", "txid-123", "txid-123"}, client.finalizeTxids)
		require.Equal(t, [][]string{
			{"checkpoint-a"},
			{"checkpoint-a"},
			{"checkpoint-a"},
		}, client.finalizePayloads)
	})
}
