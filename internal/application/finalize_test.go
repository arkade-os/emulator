package application

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
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
		t.Run("input without taproot leaf script is rejected", func(t *testing.T) {
			setup := newCheckpoint(t,
				arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes)),
				arkdSigner.PubKey(),
			)
			setup.packet.Inputs[0].TaprootLeafScript = nil
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.ErrorContains(t, err, "missing taproot leaf script")
		})
		t.Run("input with more than one taproot leaf script is rejected", func(t *testing.T) {
			// VerifyTapscriptSigs skips inputs without exactly one leaf script
			setup := newCheckpoint(t,
				aliceSigner.PubKey(),
				arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes)),
				arkdSigner.PubKey(),
			)
			setup.packet.Inputs[0].TaprootLeafScript = append(
				setup.packet.Inputs[0].TaprootLeafScript, setup.packet.Inputs[0].TaprootLeafScript[0],
			)
			setup.packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{
				makeSig(t, tweakedThisSigner, setup.packet, setup.leaf),
			}
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.ErrorContains(t, err, "missing taproot leaf script")
		})
		t.Run("input whose prevout is not taproot is rejected", func(t *testing.T) {
			// VerifyTapscriptSigs skips non-taproot prevouts without erroring
			setup := newCheckpoint(t,
				arkade.ComputeArkadeScriptPublicKey(thisSigner.PubKey(), arkade.ArkadeScriptHash(arkadeScriptBytes)),
				arkdSigner.PubKey(),
			)
			setup.packet.Inputs[0].WitnessUtxo = &wire.TxOut{
				Value: 2_000, PkScript: []byte{txscript.OP_TRUE},
			}
			err := verifyNonArkdCheckpointSignatures([]*psbt.Packet{setup.packet}, setup.arkdPubKey)
			require.ErrorContains(t, err, "signatures were not verified")
		})
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

func TestIsFinalizerRole(t *testing.T) {
	t.Run("last non-arkd signer", func(t *testing.T) {
		svc, tx, _ := newTestService(t, true)
		signed, err := svc.Service.SubmitTx(t.Context(), tx)
		require.NoError(t, err)

		ok, err := isFinalizerRole(signed.ArkTx, []int{0}, svc.signerPubKeys, svc.arkdPubKey)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("another signer comes after us", func(t *testing.T) {
		svc, tx, _ := newTestService(t, false)
		signed, err := svc.Service.SubmitTx(t.Context(), tx)
		require.NoError(t, err)

		ok, err := isFinalizerRole(signed.ArkTx, []int{0}, svc.signerPubKeys, svc.arkdPubKey)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("unsigned input not counted", func(t *testing.T) {
		svc, tx, _ := newTestService(t, true)

		ok, err := isFinalizerRole(tx.ArkTx, []int{0}, svc.signerPubKeys, svc.arkdPubKey)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("signature present before the call not counted", func(t *testing.T) {
		svc, tx, _ := newTestService(t, true)
		in := &tx.ArkTx.Inputs[0]
		tweaked, err := arkade.ReadArkadeScript(tx.ArkTx, svc.signerPubKeys[0], arkade.EmulatorEntry{Vin: 0, Script: []byte{txscript.OP_TRUE}})
		require.NoError(t, err)
		in.TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
			XOnlyPubKey: schnorr.SerializePubKey(tweaked.PubKey()),
			Signature:   make([]byte, 64),
		}}

		ok, err := isFinalizerRole(tx.ArkTx, []int{len(in.TaprootScriptSpendSig)}, svc.signerPubKeys, svc.arkdPubKey)
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func TestSubmitTx(t *testing.T) {
	t.Run("not finalizer", func(t *testing.T) {
		svc, tx, arkd := newTestService(t, false)

		out, err := svc.SubmitTx(t.Context(), tx)
		require.NoError(t, err)
		require.Equal(t, tx.ArkTx.UnsignedTx.TxHash(), out.ArkTx.UnsignedTx.TxHash())
		require.NotEmpty(t, out.ArkTx.Inputs[0].TaprootScriptSpendSig)
		require.Zero(t, arkd.submitCalls)
		require.Zero(t, arkd.finalizeCalls)
	})

	t.Run("finalizer", func(t *testing.T) {
		svc, tx, arkd := newTestService(t, true)

		// distinct txid, to tell arkd's final tx from the input
		finalArkMsg := wire.NewMsgTx(2)
		finalArkMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xfe}, Index: 3}})
		finalArkMsg.AddTxOut(&wire.TxOut{Value: 1234, PkScript: []byte{txscript.OP_TRUE}})
		finalArkPtx, err := psbt.NewFromUnsignedTx(finalArkMsg)
		require.NoError(t, err)
		finalArkPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 5_000, PkScript: []byte{txscript.OP_TRUE}}
		arkd.finalArkTx = encodePacket(t, finalArkPtx)

		// arkd's checkpoints carry an extra signature to detect the merge
		arkdSig := &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: bytes.Repeat([]byte{0xab}, 32),
			LeafHash:    bytes.Repeat([]byte{0xcd}, 32),
			Signature:   bytes.Repeat([]byte{0xee}, 64),
		}
		for _, cp := range tx.Checkpoints {
			arkdCp, err := psbt.NewFromUnsignedTx(cp.UnsignedTx)
			require.NoError(t, err)
			arkdCp.Inputs[0].WitnessUtxo = cp.Inputs[0].WitnessUtxo
			arkdCp.Inputs[0].TaprootLeafScript = cp.Inputs[0].TaprootLeafScript
			arkdCp.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{arkdSig}
			arkd.arkdCheckpoints = append(arkd.arkdCheckpoints, encodePacket(t, arkdCp))
		}

		out, err := svc.SubmitTx(t.Context(), tx)
		require.NoError(t, err)

		require.Equal(t, 1, arkd.submitCalls)
		require.Equal(t, 1, arkd.finalizeCalls)

		require.Equal(t, finalArkMsg.TxHash(), out.ArkTx.UnsignedTx.TxHash())

		mergedSigs := out.Checkpoints[0].Inputs[0].TaprootScriptSpendSig
		require.GreaterOrEqual(t, len(mergedSigs), 2)
		require.True(t, hasSignature(mergedSigs, arkdSig.Signature), "arkd signature must be merged in")

		require.Len(t, arkd.submitCheckpoints, len(tx.Checkpoints))
		submitted, err := psbt.NewFromRawBytes(strings.NewReader(arkd.submitCheckpoints[0]), true)
		require.NoError(t, err)
		require.False(t, hasSignature(submitted.Inputs[0].TaprootScriptSpendSig, arkdSig.Signature))

		require.Len(t, arkd.finalizePayloads, 1)
		finalized, err := psbt.NewFromRawBytes(strings.NewReader(arkd.finalizePayloads[0][0]), true)
		require.NoError(t, err)
		require.True(t,
			hasSignature(finalized.Inputs[0].TaprootScriptSpendSig, arkdSig.Signature),
			"FinalizeTx must receive the merged checkpoints",
		)
	})

	t.Run("submit error", func(t *testing.T) {
		svc, tx, arkd := newTestService(t, true)
		arkd.submitErr = fmt.Errorf("arkd rejected tx")

		out, err := svc.SubmitTx(t.Context(), tx)
		require.ErrorContains(t, err, "failed to submit tx on arkd")
		require.ErrorContains(t, err, "arkd rejected tx")
		require.Nil(t, out)
		require.Equal(t, 1, arkd.submitCalls)
		require.Zero(t, arkd.finalizeCalls)
		require.Len(t, tx.Checkpoints[0].Inputs[0].TaprootScriptSpendSig, 1)
	})

	t.Run("arkd returns unknown checkpoint txid", func(t *testing.T) {
		svc, tx, arkd := newTestService(t, true)

		otherTx := wire.NewMsgTx(2)
		otherTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x99}, Index: 7}})
		otherTx.AddTxOut(&wire.TxOut{Value: 42, PkScript: []byte{txscript.OP_TRUE}})
		otherPtx, err := psbt.NewFromUnsignedTx(otherTx)
		require.NoError(t, err)
		arkd.finalArkTx = encodePacket(t, otherPtx)
		arkd.arkdCheckpoints = []string{arkd.finalArkTx}

		out, err := svc.SubmitTx(t.Context(), tx)
		require.ErrorContains(t, err, "arkd returned no checkpoint for txid")
		require.Nil(t, out)
		require.Zero(t, arkd.finalizeCalls)
	})

	t.Run("arkd returns checkpoint without inputs", func(t *testing.T) {
		svc, tx, arkd := newTestService(t, true)

		// same txid as the submitted checkpoint but stripped of psbt inputs
		empty, err := psbt.NewFromUnsignedTx(tx.Checkpoints[0].UnsignedTx.Copy())
		require.NoError(t, err)
		empty.Inputs = nil
		arkd.finalArkTx = encodePacket(t, tx.ArkTx)
		arkd.arkdCheckpoints = []string{encodePacket(t, empty)}

		require.NotPanics(t, func() {
			_, err := svc.SubmitTx(t.Context(), tx)
			require.ErrorContains(t, err, "checkpoint")
		})
		require.Zero(t, arkd.finalizeCalls)
	})

	t.Run("verifies checkpoint signatures before submitting", func(t *testing.T) {
		svc, tx, arkd := newTestService(t, true)

		// garbage signature for the tweaked emulator key
		in := &tx.Checkpoints[0].Inputs[0]
		leaf := in.TaprootLeafScript[0]
		leafHash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()
		in.TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
			XOnlyPubKey: leaf.Script[1:33],
			LeafHash:    leafHash[:],
			Signature:   make([]byte, 64),
			SigHash:     txscript.SigHashDefault,
		}}

		out, err := svc.SubmitTx(t.Context(), tx)
		require.ErrorContains(t, err, "failed to verify non-arkd signatures on checkpoints")
		require.Nil(t, out)
		require.Zero(t, arkd.submitCalls)
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
		arkd := &fakeArkd{finalizeErrs: []error{fmt.Errorf("retry 1"), fmt.Errorf("retry 2"), nil}}
		svc := &service{arkd: arkd}
		err := svc.retryFinalize(t.Context(), "txid-123", []string{"checkpoint-a", "checkpoint-b"})
		require.NoError(t, err)
		require.Equal(t, 3, arkd.finalizeCalls)
		require.Equal(t, []string{"txid-123", "txid-123", "txid-123"}, arkd.finalizeTxids)
		require.Equal(t, [][]string{
			{"checkpoint-a", "checkpoint-b"},
			{"checkpoint-a", "checkpoint-b"},
			{"checkpoint-a", "checkpoint-b"},
		}, arkd.finalizePayloads)
	})

	t.Run("exhausts minimum retries", func(t *testing.T) {
		arkd := &fakeArkd{finalizeErrs: []error{
			fmt.Errorf("retry 1"), fmt.Errorf("retry 2"), fmt.Errorf("retry 3"), fmt.Errorf("retry 4"),
		}}
		svc := &service{arkd: arkd}
		ctx, cancel := context.WithCancel(t.Context())
		// simulates client hangup
		cancel()
		err := svc.retryFinalize(ctx, "txid-123", []string{"checkpoint-a"})
		require.ErrorContains(t, err, "context canceled")
		require.Equal(t, 3, arkd.finalizeCalls)
	})
}

func TestClose(t *testing.T) {
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	idx := &testIndexer{}
	lib, err := emulator.New(t.Context(), signerKey, nil, nil, arkdKey.PubKey(), idx, arkade.DefaultComputeLimits())
	require.NoError(t, err)
	arkd := &fakeArkd{}
	svc, err := newService(lib, arkd, arkdKey.PubKey())
	require.NoError(t, err)

	svc.Close()
	require.Equal(t, 1, idx.closeCalls)
	require.Equal(t, 1, arkd.closeCalls)
}

// newTestService returns a service and an OP_TRUE OffchainTx. lastSigner makes
// the emulator the last non-arkd signer; otherwise alice follows it.
func newTestService(t *testing.T, lastSigner bool) (*service, emulator.OffchainTx, *fakeArkd) {
	t.Helper()

	emulatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	aliceKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScriptBytes := []byte{txscript.OP_TRUE}
	scriptHash := arkade.ArkadeScriptHash(arkadeScriptBytes)
	tweakedEmulatorPub := arkade.ComputeArkadeScriptPublicKey(emulatorKey.PubKey(), scriptHash)

	pubKeys := []*btcec.PublicKey{tweakedEmulatorPub, arkdKey.PubKey()}
	if !lastSigner {
		pubKeys = []*btcec.PublicKey{tweakedEmulatorPub, aliceKey.PubKey(), arkdKey.PubKey()}
	}
	closure := arkscript.MultisigClosure{PubKeys: pubKeys}

	vtxoScript := arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{&closure}}
	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	forfeitScript, err := vtxoScript.ForfeitClosures()[0].Script()
	require.NoError(t, err)
	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(forfeitScript).TapHash())
	require.NoError(t, err)
	leafScript := []*psbt.TaprootTapLeafScript{{
		ControlBlock: merkleProof.ControlBlock,
		Script:       merkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	vtxoPkScript, err := arkscript.P2TRScript(vtxoTapKey)
	require.NoError(t, err)

	prevArkTx := wire.NewMsgTx(2)
	prevArkTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 0}})
	prevArkTx.AddTxOut(&wire.TxOut{Value: 5_000, PkScript: vtxoPkScript})

	checkpointTx := wire.NewMsgTx(2)
	checkpointTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prevArkTx.TxHash(), Index: 0}})
	checkpointTx.AddTxOut(&wire.TxOut{Value: 5_000, PkScript: vtxoPkScript})
	checkpointTx.AddTxOut(txutils.AnchorOutput())
	checkpointPtx, err := psbt.NewFromUnsignedTx(checkpointTx)
	require.NoError(t, err)
	checkpointPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 5_000, PkScript: vtxoPkScript}
	checkpointPtx.Inputs[0].TaprootLeafScript = leafScript

	arkTx := wire.NewMsgTx(2)
	arkTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: checkpointPtx.UnsignedTx.TxHash(), Index: 0}})
	arkTx.AddTxOut(&wire.TxOut{Value: 4_800, PkScript: vtxoPkScript})
	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: arkadeScriptBytes})
	require.NoError(t, err)
	opReturnOut, err := extension.Extension{emulatorPacket}.TxOut()
	require.NoError(t, err)
	arkTx.AddTxOut(opReturnOut)

	arkPtx, err := psbt.NewFromUnsignedTx(arkTx)
	require.NoError(t, err)
	arkPtx.Inputs[0].WitnessUtxo = checkpointPtx.UnsignedTx.TxOut[0]
	arkPtx.Inputs[0].TaprootLeafScript = leafScript
	require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevArkTxField, *prevArkTx))

	lib, err := emulator.New(
		t.Context(), emulatorKey, nil, nil, arkdKey.PubKey(), &testIndexer{},
		arkade.DefaultComputeLimits(),
	)
	require.NoError(t, err)

	arkd := &fakeArkd{}
	svc, err := newService(lib, arkd, arkdKey.PubKey())
	require.NoError(t, err)

	return svc, emulator.OffchainTx{
		ArkTx:       arkPtx,
		Checkpoints: []*psbt.Packet{checkpointPtx},
	}, arkd
}

type testIndexer struct {
	indexer.Indexer
	closeCalls int
}

func (i *testIndexer) Close() { i.closeCalls++ }

type fakeArkd struct {
	finalArkTx      string
	arkdCheckpoints []string
	submitErr       error
	finalizeErrs    []error

	submitCalls       int
	submitCheckpoints []string
	finalizeCalls     int
	finalizeTxids     []string
	finalizePayloads  [][]string
	closeCalls        int
}

func (f *fakeArkd) SubmitTx(_ context.Context, _ string, checkpoints []string) (string, string, []string, error) {
	f.submitCalls++
	f.submitCheckpoints = checkpoints
	if f.submitErr != nil {
		return "", "", nil, f.submitErr
	}
	return "arkd-txid", f.finalArkTx, f.arkdCheckpoints, nil
}

func (f *fakeArkd) FinalizeTx(_ context.Context, txid string, checkpoints []string) error {
	f.finalizeCalls++
	f.finalizeTxids = append(f.finalizeTxids, txid)
	f.finalizePayloads = append(f.finalizePayloads, append([]string(nil), checkpoints...))
	if len(f.finalizeErrs) == 0 {
		return nil
	}
	err := f.finalizeErrs[0]
	f.finalizeErrs = f.finalizeErrs[1:]
	return err
}

func (f *fakeArkd) Close() { f.closeCalls++ }

func hasSignature(sigs []*psbt.TaprootScriptSpendSig, want []byte) bool {
	for _, s := range sigs {
		if bytes.Equal(s.Signature, want) {
			return true
		}
	}
	return false
}

func encodePacket(t *testing.T, ptx *psbt.Packet) string {
	t.Helper()
	encoded, err := ptx.B64Encode()
	require.NoError(t, err)
	return encoded
}
