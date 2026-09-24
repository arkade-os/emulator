package emulator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
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

// submitTxHarness builds a complete, self consistent ark tx + checkpoint pair
// so that individual bindings can be broken one at a time.
type submitTxHarness struct {
	svc        *service
	arkPtx     *psbt.Packet
	checkpoint *psbt.Packet
}

func TestSubmitTx(t *testing.T) {
	svc, arkTxInput := newTestSigningService(t)

	out, err := svc.SubmitTx(context.Background(), arkTxInput)
	require.NoError(t, err)

	require.Equal(t, arkTxInput.ArkTx.UnsignedTx.TxHash(), out.ArkTx.UnsignedTx.TxHash())
	require.NotEmpty(t, out.ArkTx.Inputs[0].TaprootScriptSpendSig)
	require.Len(t, out.Checkpoints[0].Inputs[0].TaprootScriptSpendSig, 1)
}

// newTestSigningService returns a service and an OP_TRUE OffchainTx where the
// emulator is the last non-arkd signer.
func newTestSigningService(t *testing.T) (*service, OffchainTx) {
	t.Helper()

	emulatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScriptBytes := []byte{txscript.OP_TRUE}
	scriptHash := arkade.ArkadeScriptHash(arkadeScriptBytes)

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
	checkpointTx.AddTxOut(&wire.TxOut{Value: 5_000, PkScript: vtxoPkScript})
	checkpointTx.AddTxOut(txutils.AnchorOutput())

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
		computeLimits: arkade.DefaultComputeLimits(),
	}

	return svc, OffchainTx{
		ArkTx:       arkPtx,
		Checkpoints: []*psbt.Packet{checkpointPtx},
	}
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
