package application

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	sdkclient "github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestIndexCheckpoints(t *testing.T) {
	newCheckpoint := func(t *testing.T, id byte) *psbt.Packet {
		t.Helper()
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{id}}})
		tx.AddTxOut(&wire.TxOut{Value: 1})
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		return ptx
	}
	newArkTx := func(t *testing.T, checkpoints ...*psbt.Packet) *psbt.Packet {
		t.Helper()
		tx := wire.NewMsgTx(2)
		for _, checkpoint := range checkpoints {
			tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: checkpoint.UnsignedTx.TxHash()}})
		}
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		return ptx
	}

	first := newCheckpoint(t, 1)
	second := newCheckpoint(t, 2)
	arkPtx := newArkTx(t, first, second)

	indexed, err := indexCheckpoints(arkPtx, []*psbt.Packet{second, first})
	require.NoError(t, err)
	require.Same(t, first, indexed[first.UnsignedTx.TxID()])
	require.Same(t, second, indexed[second.UnsignedTx.TxID()])

	_, err = indexCheckpoints(arkPtx, []*psbt.Packet{first})
	require.ErrorContains(t, err, "expected 2 checkpoints")

	_, err = indexCheckpoints(arkPtx, []*psbt.Packet{first, first})
	require.ErrorContains(t, err, "duplicate checkpoint")

	arkPtx.UnsignedTx.TxIn[1].PreviousOutPoint.Hash = first.UnsignedTx.TxHash()
	_, err = indexCheckpoints(arkPtx, []*psbt.Packet{first, second})
	require.ErrorContains(t, err, "associated with multiple ark inputs")
}

func TestValidateCheckpoint(t *testing.T) {
	type setup struct {
		arkPtx         *psbt.Packet
		checkpoint     *psbt.Packet
		previousOutput *wire.TxOut
		expectedLeaf   txscript.TapLeaf
		foreignLeaf    *psbt.TaprootTapLeafScript
	}

	newSetup := func(t *testing.T, unrelatedOutput bool) setup {
		t.Helper()

		firstKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		secondKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		closures := []*arkscript.MultisigClosure{
			{PubKeys: []*btcec.PublicKey{firstKey.PubKey()}},
			{PubKeys: []*btcec.PublicKey{secondKey.PubKey()}},
		}
		vtxoScript := arkscript.TapscriptsVtxoScript{
			Closures: []arkscript.Closure{closures[0], closures[1]},
		}
		tapKey, tapTree, err := vtxoScript.TapTree()
		require.NoError(t, err)
		vtxoPkScript, err := arkscript.P2TRScript(tapKey)
		require.NoError(t, err)

		leafField := func(t *testing.T, closure arkscript.Closure) (*psbt.TaprootTapLeafScript, txscript.TapLeaf) {
			t.Helper()
			script, err := closure.Script()
			require.NoError(t, err)
			leaf := txscript.NewBaseTapLeaf(script)
			proof, err := tapTree.GetTaprootMerkleProof(leaf.TapHash())
			require.NoError(t, err)
			return &psbt.TaprootTapLeafScript{
				ControlBlock: proof.ControlBlock,
				Script:       proof.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			}, leaf
		}
		authorizedField, authorizedLeaf := leafField(t, closures[0])
		foreignField, _ := leafField(t, closures[1])

		const amount = int64(100_000)
		previousOutput := &wire.TxOut{Value: amount, PkScript: vtxoPkScript}
		previousTx := wire.NewMsgTx(2)
		previousTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{9}}})
		previousTx.AddTxOut(previousOutput)

		checkpointOutputScript := vtxoPkScript
		if unrelatedOutput {
			attackerKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			checkpointOutputScript, err = txscript.PayToTaprootScript(attackerKey.PubKey())
			require.NoError(t, err)
		}
		checkpointOutput := &wire.TxOut{Value: amount, PkScript: checkpointOutputScript}
		checkpointTx := wire.NewMsgTx(2)
		checkpointTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: previousTx.TxHash()}})
		checkpointTx.AddTxOut(checkpointOutput)
		checkpointTx.AddTxOut(txutils.AnchorOutput())
		checkpoint, err := psbt.NewFromUnsignedTx(checkpointTx)
		require.NoError(t, err)
		checkpoint.Inputs[0].WitnessUtxo = &wire.TxOut{Value: amount, PkScript: append([]byte(nil), vtxoPkScript...)}
		checkpoint.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{authorizedField}

		arkTx := wire.NewMsgTx(2)
		arkOutpoint := wire.OutPoint{Hash: checkpointTx.TxHash()}
		arkTx.AddTxIn(&wire.TxIn{PreviousOutPoint: arkOutpoint})
		arkPtx, err := psbt.NewFromUnsignedTx(arkTx)
		require.NoError(t, err)
		arkPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: amount, PkScript: append([]byte(nil), checkpointOutputScript...)}
		arkPtx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{authorizedField}

		return setup{
			arkPtx:         arkPtx,
			checkpoint:     checkpoint,
			previousOutput: previousOutput,
			expectedLeaf:   authorizedLeaf,
			foreignLeaf:    foreignField,
		}
	}

	t.Run("valid", func(t *testing.T) {
		setup := newSetup(t, false)
		require.NoError(t, validateCheckpoint(setup.arkPtx, 0, setup.checkpoint, setup.previousOutput, setup.expectedLeaf))
	})

	t.Run("multiple checkpoint inputs", func(t *testing.T) {
		setup := newSetup(t, false)
		setup.checkpoint.UnsignedTx.AddTxIn(&wire.TxIn{})
		setup.checkpoint.Inputs = append(setup.checkpoint.Inputs, psbt.PInput{})
		err := validateCheckpoint(setup.arkPtx, 0, setup.checkpoint, setup.previousOutput, setup.expectedLeaf)
		require.ErrorContains(t, err, "exactly one input")
	})

	t.Run("extra checkpoint output", func(t *testing.T) {
		setup := newSetup(t, false)
		setup.checkpoint.UnsignedTx.AddTxOut(&wire.TxOut{})
		err := validateCheckpoint(setup.arkPtx, 0, setup.checkpoint, setup.previousOutput, setup.expectedLeaf)
		require.ErrorContains(t, err, "one vtxo output and one anchor output")
	})

	t.Run("checkpoint output mismatch", func(t *testing.T) {
		setup := newSetup(t, false)
		setup.arkPtx.Inputs[0].WitnessUtxo.Value--
		err := validateCheckpoint(setup.arkPtx, 0, setup.checkpoint, setup.previousOutput, setup.expectedLeaf)
		require.ErrorContains(t, err, "checkpoint output does not match")
	})

	t.Run("unauthenticated checkpoint input", func(t *testing.T) {
		setup := newSetup(t, false)
		setup.checkpoint.Inputs[0].WitnessUtxo.Value--
		err := validateCheckpoint(setup.arkPtx, 0, setup.checkpoint, setup.previousOutput, setup.expectedLeaf)
		require.ErrorContains(t, err, "does not match previous ark transaction")
	})

	t.Run("missing previous ark transaction", func(t *testing.T) {
		setup := newSetup(t, false)
		err := validateCheckpoint(setup.arkPtx, 0, setup.checkpoint, nil, setup.expectedLeaf)
		require.ErrorContains(t, err, "missing authenticated previous ark output")
	})

	t.Run("substituted checkpoint leaf", func(t *testing.T) {
		setup := newSetup(t, false)
		setup.checkpoint.Inputs[0].TaprootLeafScript[0] = setup.foreignLeaf
		err := validateCheckpoint(setup.arkPtx, 0, setup.checkpoint, setup.previousOutput, setup.expectedLeaf)
		require.ErrorContains(t, err, "tapleaf does not match ark input")
	})

	t.Run("unrelated checkpoint destination", func(t *testing.T) {
		setup := newSetup(t, true)
		err := validateCheckpoint(setup.arkPtx, 0, setup.checkpoint, setup.previousOutput, setup.expectedLeaf)
		require.ErrorContains(t, err, "ark input tapleaf")
		require.ErrorContains(t, err, "not committed by witness utxo")
	})
}

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

// TestSubmitTxBindsCheckpointToArkInput proves the checkpoint accompanying an
// ark input is bound to that input before the emulator signs it: its input 0
// leaf must be guarded by the same arkade tweaked key that the executed script
// authorises, and its output must match the witness utxo the ark input asserts.
func TestSubmitTxBindsCheckpointToArkInput(t *testing.T) {
	t.Run("baseline consistent request is signed", func(t *testing.T) {
		h := newSubmitTxHarness(t, tweakedAliceArkd, tweakedAliceArkd)

		res, err := h.submit(t)
		require.NoError(t, err)
		require.Len(t, res.Checkpoints, 1)
		require.Len(t, res.Checkpoints[0].Inputs[0].TaprootScriptSpendSig, 1)
	})

	t.Run("checkpoint leaf not guarded by the arkade key is rejected", func(t *testing.T) {
		h := newSubmitTxHarness(t, tweakedAliceArkd, aliceArkd)

		_, err := h.submit(t)
		require.Error(t, err)
		require.ErrorContains(t, err, "checkpoint")
	})

	t.Run("ark input witness utxo not matching checkpoint output is rejected", func(t *testing.T) {
		h := newSubmitTxHarness(t, tweakedAliceArkd, tweakedArkd)
		// claim a far larger amount than the checkpoint actually pays
		h.arkPtx.Inputs[0].WitnessUtxo.Value = 100_000_000

		_, err := h.submit(t)
		require.Error(t, err)
		require.ErrorContains(t, err, "mismatch")
	})
}

// TestSubmitTxHandlesMalformedArkdCheckpointResponse proves a missing or
// input-less checkpoint in arkd's response is reported as an error instead of
// panicking the request after the emulator has already signed.
func TestSubmitTxHandlesMalformedArkdCheckpointResponse(t *testing.T) {
	newFinalizerHarness := func(t *testing.T) *submitTxHarness {
		t.Helper()
		// tweakedArkd on the ark leaf makes the emulator the finalizer
		return newSubmitTxHarness(t, tweakedArkd, tweakedArkd)
	}

	t.Run("missing checkpoint in arkd response", func(t *testing.T) {
		h := newFinalizerHarness(t)
		h.svc.arkdClient = &finalizingArkdClient{
			mockArkdClient: &mockArkdClient{},
			arkTx:          encodePacket(t, h.arkPtx),
			checkpoints:    nil,
		}

		require.NotPanics(t, func() {
			_, err := h.submit(t)
			require.Error(t, err)
			require.ErrorContains(t, err, "checkpoint")
		})
	})

	t.Run("checkpoint without inputs in arkd response", func(t *testing.T) {
		h := newFinalizerHarness(t)

		// same txid as the submitted checkpoint but stripped of psbt inputs
		empty, err := psbt.NewFromUnsignedTx(h.checkpoint.UnsignedTx.Copy())
		require.NoError(t, err)
		empty.Inputs = nil

		h.svc.arkdClient = &finalizingArkdClient{
			mockArkdClient: &mockArkdClient{},
			arkTx:          encodePacket(t, h.arkPtx),
			checkpoints:    []string{encodePacket(t, empty)},
		}

		require.NotPanics(t, func() {
			_, err := h.submit(t)
			require.Error(t, err)
			require.ErrorContains(t, err, "checkpoint")
		})
	})
}

// TestRetryWithBackoffIsBounded proves the retry loop terminates on its own
// budget even when the caller supplies a context that never expires.
func TestRetryWithBackoffIsBounded(t *testing.T) {
	cfg := retryConfig{
		MinAttempts:  10,
		MaxAttempts:  4,
		MaxElapsed:   time.Second,
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		Multiplier:   1,
	}

	attempts := 0
	done := make(chan error, 1)
	go func() {
		done <- retryWithBackoff(
			context.Background(),
			cfg,
			func() error { attempts++; return errAlwaysFails },
			nil,
		)
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		require.Equal(t, 4, attempts)
	case <-time.After(10 * time.Second):
		t.Fatal("retryWithBackoff did not return without a context deadline")
	}
}

func TestRetryWithBackoffExhaustsElapsedBudget(t *testing.T) {
	cfg := retryConfig{
		MaxAttempts:  0, // disabled: only the elapsed budget may fire
		MaxElapsed:   time.Millisecond,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     50 * time.Millisecond,
		Multiplier:   1,
		Jitter:       0, // deterministic delay
	}

	attempts := 0
	err := retryWithBackoff(
		context.Background(),
		cfg,
		func() error { attempts++; return errAlwaysFails },
		nil,
	)

	require.ErrorContains(t, err, "retry budget exhausted after attempt 1")
	require.Equal(t, 1, attempts)
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

// finalizingArkdClient lets a test drive the arkd finalization branch of
// SubmitTx, which the shared mock deliberately panics on.
type finalizingArkdClient struct {
	*mockArkdClient
	arkTx       string
	checkpoints []string
}

func (c *finalizingArkdClient) SubmitTx(
	context.Context, string, []string,
) (string, string, []string, error) {
	return "final-txid", c.arkTx, c.checkpoints, nil
}

// submitTxHarness builds a complete, self consistent ark tx + checkpoint pair
// so that individual bindings can be broken one at a time.
type submitTxHarness struct {
	svc        *service
	arkPtx     *psbt.Packet
	checkpoint *psbt.Packet
}

// newSubmitTxHarness wires an ark tx spending a checkpoint output. arkClosure
// and checkpointClosure select which pubkeys guard each leaf.
func newSubmitTxHarness(
	t *testing.T,
	arkClosure func(tweaked *btcec.PublicKey, alice, arkd *btcec.PublicKey) []*btcec.PublicKey,
	checkpointClosure func(tweaked *btcec.PublicKey, alice, arkd *btcec.PublicKey) []*btcec.PublicKey,
) *submitTxHarness {
	t.Helper()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	aliceKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScriptBytes := []byte{txscript.OP_TRUE}
	tweaked := arkade.ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes),
	)

	cpLeaf, cpInputPkScript := taprootLeaf(
		t, checkpointClosure(tweaked, aliceKey.PubKey(), arkdKey.PubKey())...,
	)
	arkLeaf, cpOutputPkScript := taprootLeaf(
		t, arkClosure(tweaked, aliceKey.PubKey(), arkdKey.PubKey())...,
	)

	// checkpoint spends a vtxo and pays the script the ark tx will spend
	prevTx := wire.NewMsgTx(2)
	prevTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{7}, Index: 0},
	})
	prevTx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: cpInputPkScript})

	cpTx := wire.NewMsgTx(2)
	cpTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 0},
	})
	cpTx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: cpOutputPkScript})
	cpTx.AddTxOut(txutils.AnchorOutput())

	checkpoint, err := psbt.NewFromUnsignedTx(cpTx)
	require.NoError(t, err)
	checkpoint.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 10_000, PkScript: cpInputPkScript}
	checkpoint.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{cpLeaf}

	// ark tx spends the checkpoint output
	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: checkpoint.UnsignedTx.TxHash(), Index: 0},
	})
	arkTx.AddTxOut(&wire.TxOut{Value: 9_000, PkScript: cpOutputPkScript})

	arkPtx, err := psbt.NewFromUnsignedTx(arkTx)
	require.NoError(t, err)
	arkPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 10_000, PkScript: cpOutputPkScript}
	arkPtx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{arkLeaf}
	require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevArkTxField, *prevTx))

	packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: arkadeScriptBytes})
	require.NoError(t, err)

	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)
	arkPtx.UnsignedTx.AddTxOut(txOut)
	arkPtx.Outputs = append(arkPtx.Outputs, psbt.POutput{})

	return &submitTxHarness{
		svc: &service{
			signer:        signer{secretKey: signerKey},
			arkdPubKey:    arkdKey.PubKey(),
			computeLimits: arkade.DefaultComputeLimits(),
		},
		arkPtx:     arkPtx,
		checkpoint: checkpoint,
	}
}

func (h *submitTxHarness) submit(t *testing.T) (*OffchainTx, error) {
	t.Helper()

	return h.svc.SubmitTx(t.Context(), OffchainTx{
		ArkTx:       h.arkPtx,
		Checkpoints: []*psbt.Packet{h.checkpoint},
	})
}

// taprootLeaf builds a single closure vtxo script and returns everything needed
// to both fund and spend it.
func taprootLeaf(t *testing.T, pubkeys ...*btcec.PublicKey) (*psbt.TaprootTapLeafScript, []byte) {
	t.Helper()

	closure := arkscript.MultisigClosure{PubKeys: pubkeys}
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

	return &psbt.TaprootTapLeafScript{
		ControlBlock: merkleProof.ControlBlock,
		Script:       merkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}, pkScript
}

// tweakedAliceArkd keeps the emulator from being the finalizer, so SubmitTx
// returns before ever contacting arkd.
func tweakedAliceArkd(tweaked, alice, arkd *btcec.PublicKey) []*btcec.PublicKey {
	return []*btcec.PublicKey{tweaked, alice, arkd}
}

func tweakedArkd(tweaked, _, arkd *btcec.PublicKey) []*btcec.PublicKey {
	return []*btcec.PublicKey{tweaked, arkd}
}

func aliceArkd(_, alice, arkd *btcec.PublicKey) []*btcec.PublicKey {
	return []*btcec.PublicKey{alice, arkd}
}

func encodePacket(t *testing.T, ptx *psbt.Packet) string {
	t.Helper()

	encoded, err := ptx.B64Encode()
	require.NoError(t, err)

	return encoded
}

var errAlwaysFails = fmt.Errorf("always fails")
