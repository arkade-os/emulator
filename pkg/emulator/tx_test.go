package emulator

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
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
		f := &mockFinalizer{
			finalizeErrs: []error{
				fmt.Errorf("retry 1"),
				fmt.Errorf("retry 2"),
				nil,
			},
		}
		svc := &service{finalizer: f}
		checkpoints := []string{"checkpoint-a", "checkpoint-b"}
		err := svc.retryFinalize(
			t.Context(),
			"txid-123",
			checkpoints,
		)
		require.NoError(t, err)
		require.Equal(t, 3, f.finalizeCalls)
		require.Equal(t, []string{"txid-123", "txid-123", "txid-123"}, f.finalizeTxids)
		require.Equal(t, [][]string{
			{"checkpoint-a", "checkpoint-b"},
			{"checkpoint-a", "checkpoint-b"},
			{"checkpoint-a", "checkpoint-b"},
		}, f.finalizePayloads)
	})
	t.Run("exhausts minimum retries", func(t *testing.T) {
		f := &mockFinalizer{
			finalizeErrs: []error{
				fmt.Errorf("retry 1"),
				fmt.Errorf("retry 2"),
				fmt.Errorf("retry 3"),
				fmt.Errorf("retry 4"),
			},
		}
		svc := &service{finalizer: f}
		ctx, cancel := context.WithCancel(t.Context())
		// simulates client hangup
		cancel()
		err := svc.retryFinalize(
			ctx,
			"txid-123",
			[]string{"checkpoint-a"},
		)
		require.ErrorContains(t, err, "context canceled")
		require.Equal(t, 3, f.finalizeCalls)
		require.Equal(t, []string{"txid-123", "txid-123", "txid-123"}, f.finalizeTxids)
		require.Equal(t, [][]string{
			{"checkpoint-a"},
			{"checkpoint-a"},
			{"checkpoint-a"},
		}, f.finalizePayloads)
	})
}

// TestSubmitTx covers both modes of SubmitTx when the emulator is in the
// finalizer role (last non-arkd signer): signing-only (nil finalizer) and the
// full finalizer round-trip. The arkd responses are made distinct from the
// input so the assertions verify behavior, not an echo.
func TestSubmitTx(t *testing.T) {
	t.Run("signing-only", func(t *testing.T) {
		// nil finalizer: SubmitTx signs and returns without any arkd round-trip.
		svc, arkTxInput := newTestServiceNilFinalizer(t)

		out, err := svc.SubmitTx(context.Background(), arkTxInput)
		require.NoError(t, err)

		// returns the input ark tx (signed), not a finalized tx from arkd.
		require.Equal(t, arkTxInput.ArkTx.UnsignedTx.TxHash(), out.ArkTx.UnsignedTx.TxHash())
		// the emulator signed both the ark tx input and the checkpoint input.
		require.NotEmpty(t, out.ArkTx.Inputs[0].TaprootScriptSpendSig)
		// signing-only merges no arkd signature: exactly the emulator's own.
		require.Len(t, out.Checkpoints[0].Inputs[0].TaprootScriptSpendSig, 1)
		// the signed checkpoint verifies against every non-arkd signer, i.e. it
		// is a valid signing-only result arkd can later finalize.
		require.NoError(t, verifyNonArkdCheckpointSignatures(out.Checkpoints, svc.arkdPubKey))
	})

	t.Run("finalizer", func(t *testing.T) {
		// non-nil finalizer: SubmitTx verifies the non-arkd checkpoint signatures,
		// submits to arkd, merges arkd's checkpoint signature, finalizes, and
		// returns arkd's final ark tx.
		svc, arkTxInput := newTestServiceNilFinalizer(t)

		// arkd "returns" a different ark tx (distinct txid) so we can prove
		// SubmitTx returns arkd's finalized tx rather than the input.
		finalArkMsg := wire.NewMsgTx(2)
		finalArkMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xfe}, Index: 3}})
		finalArkMsg.AddTxOut(&wire.TxOut{Value: 1234, PkScript: []byte{txscript.OP_TRUE}})
		finalArkPtx, err := psbt.NewFromUnsignedTx(finalArkMsg)
		require.NoError(t, err)
		finalArkPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 5_000, PkScript: []byte{txscript.OP_TRUE}}
		finalArkB64, err := finalArkPtx.B64Encode()
		require.NoError(t, err)

		// arkd "returns" each checkpoint (matching txid) carrying an extra,
		// distinct signature, so we can prove the merge appends arkd's sig.
		arkdSig := &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: bytes.Repeat([]byte{0xab}, 32),
			LeafHash:    bytes.Repeat([]byte{0xcd}, 32),
			Signature:   bytes.Repeat([]byte{0xee}, 64),
		}
		arkdCheckpoints := make([]string, len(arkTxInput.Checkpoints))
		for i, cp := range arkTxInput.Checkpoints {
			arkdCp, err := psbt.NewFromUnsignedTx(cp.UnsignedTx)
			require.NoError(t, err)
			arkdCp.Inputs[0].WitnessUtxo = cp.Inputs[0].WitnessUtxo
			arkdCp.Inputs[0].TaprootLeafScript = cp.Inputs[0].TaprootLeafScript
			arkdCp.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{arkdSig}
			enc, err := arkdCp.B64Encode()
			require.NoError(t, err)
			arkdCheckpoints[i] = enc
		}

		fin := &submittingFinalizer{finalArkTx: finalArkB64, arkdCheckpoints: arkdCheckpoints}
		svc.finalizer = fin

		out, err := svc.SubmitTx(context.Background(), arkTxInput)
		require.NoError(t, err)

		// arkd was driven exactly once for submit and once for finalize.
		require.Equal(t, 1, fin.submitCalls)
		require.Equal(t, 1, fin.finalizeCalls)

		// SubmitTx returns arkd's finalized ark tx, not the input.
		require.Equal(t, finalArkMsg.TxHash(), out.ArkTx.UnsignedTx.TxHash())
		require.NotEqual(t, arkTxInput.ArkTx.UnsignedTx.TxHash(), out.ArkTx.UnsignedTx.TxHash())

		// the merged checkpoint carries both the emulator's and arkd's signatures.
		mergedSigs := out.Checkpoints[0].Inputs[0].TaprootScriptSpendSig
		require.GreaterOrEqual(t, len(mergedSigs), 2)
		require.True(t, hasSignature(mergedSigs, arkdSig.Signature), "arkd signature must be merged in")

		// SubmitTx forwarded the encoded checkpoints, and the merged set went to finalize.
		require.Len(t, fin.submitCheckpoints, len(arkTxInput.Checkpoints))
		require.NotEmpty(t, fin.submitCheckpoints[0])
		require.Len(t, fin.finalizeCheckpoints, len(arkTxInput.Checkpoints))
	})
}

// newTestServiceNilFinalizer constructs a service with finalizer=nil and a
// fully-formed OffchainTx where the emulator is the last non-arkd signer
// (finalizer role). The arkade script is OP_TRUE so it always executes.
func newTestServiceNilFinalizer(t *testing.T) (*service, OffchainTx) {
	t.Helper()

	emulatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScriptBytes := []byte{txscript.OP_TRUE}
	scriptHash := arkade.ArkadeScriptHash(arkadeScriptBytes)

	// The closure has the emulator's tweaked key as the last signer before arkd.
	// finalizerAccumulator.checkScript: since arkd is last, it checks second-to-last,
	// which is our tweaked emulator key → isFinalizer = true.
	tweakedEmulatorPub := arkade.ComputeArkadeScriptPublicKey(emulatorKey.PubKey(), scriptHash)
	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{tweakedEmulatorPub, arkdKey.PubKey()}}

	vtxoScript := arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{&closure}}
	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	forfeitClosure := vtxoScript.ForfeitClosures()[0]
	forfeitScript, err := forfeitClosure.Script()
	require.NoError(t, err)

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	require.NoError(t, err)

	vtxoPkScript, err := arkscript.P2TRScript(vtxoTapKey)
	require.NoError(t, err)

	// -- prevout ark tx: a transaction that has the vtxo output we'll spend --
	prevArkTx := wire.NewMsgTx(2)
	prevArkTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 0}})
	prevArkTx.AddTxOut(&wire.TxOut{Value: 5_000, PkScript: vtxoPkScript})
	prevArkTxHash := prevArkTx.TxHash()

	// -- checkpoint tx: spends output 0 of prevArkTx --
	checkpointTx := wire.NewMsgTx(2)
	checkpointTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prevArkTxHash, Index: 0}})
	checkpointTx.AddTxOut(&wire.TxOut{Value: 4_900, PkScript: vtxoPkScript})

	checkpointPtx, err := psbt.NewFromUnsignedTx(checkpointTx)
	require.NoError(t, err)
	checkpointPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 5_000, PkScript: vtxoPkScript}
	checkpointPtx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: merkleProof.ControlBlock,
		Script:       merkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	// -- ark tx: spends checkpoint tx's txid as its input's prevout --
	checkpointTxID := checkpointPtx.UnsignedTx.TxHash()

	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: checkpointTxID, Index: 0}})
	arkTx.AddTxOut(&wire.TxOut{Value: 4_800, PkScript: vtxoPkScript})

	// OP_RETURN with emulator packet
	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: arkadeScriptBytes})
	require.NoError(t, err)
	ext := extension.Extension{emulatorPacket}
	opReturnOut, err := ext.TxOut()
	require.NoError(t, err)
	arkTx.AddTxOut(opReturnOut)

	arkPtx, err := psbt.NewFromUnsignedTx(arkTx)
	require.NoError(t, err)
	// set WitnessUtxo (the output of the checkpoint that this ark tx input spends)
	arkPtx.Inputs[0].WitnessUtxo = checkpointPtx.UnsignedTx.TxOut[0]
	// set TaprootLeafScript so resolveArkadeScriptSigner can read the closure
	arkPtx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: merkleProof.ControlBlock,
		Script:       merkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	arkPtx.Outputs = append(arkPtx.Outputs, psbt.POutput{})

	// set PrevArkTxField so prevOutFetcherForArkTx can find the prevout ark tx
	require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevArkTxField, *prevArkTx))

	svc := &service{
		signer:        signer{emulatorKey},
		arkdPubKey:    arkdKey.PubKey(),
		finalizer:     nil, // signing-only mode
		computeLimits: arkade.DefaultComputeLimits(),
	}

	return svc, OffchainTx{
		ArkTx:       arkPtx,
		Checkpoints: []*psbt.Packet{checkpointPtx},
	}
}

// mockFinalizer implements the Finalizer interface for testing.
type mockFinalizer struct {
	finalizeErrs     []error
	finalizeCalls    int
	finalizeTxids    []string
	finalizePayloads [][]string
}

func (m *mockFinalizer) SubmitTx(context.Context, string, []string) (string, string, []string, error) {
	panic("unexpected call to SubmitTx")
}
func (m *mockFinalizer) FinalizeTx(_ context.Context, txid string, checkpoints []string) error {
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

// submittingFinalizer is a Finalizer that records its SubmitTx/FinalizeTx
// arguments and returns caller-configured responses, so a test can drive and
// inspect SubmitTx's full finalizer path.
type submittingFinalizer struct {
	// responses returned by SubmitTx.
	finalArkTx      string
	arkdCheckpoints []string

	// recorded call arguments.
	submitCalls         int
	submitCheckpoints   []string
	finalizeCalls       int
	finalizeCheckpoints []string
}

func (m *submittingFinalizer) SubmitTx(_ context.Context, _ string, checkpoints []string) (string, string, []string, error) {
	m.submitCalls++
	m.submitCheckpoints = checkpoints
	return "arkd-txid", m.finalArkTx, m.arkdCheckpoints, nil
}

func (m *submittingFinalizer) FinalizeTx(_ context.Context, _ string, checkpoints []string) error {
	m.finalizeCalls++
	m.finalizeCheckpoints = checkpoints
	return nil
}

func hasSignature(sigs []*psbt.TaprootScriptSpendSig, want []byte) bool {
	for _, s := range sigs {
		if bytes.Equal(s.Signature, want) {
			return true
		}
	}
	return false
}
