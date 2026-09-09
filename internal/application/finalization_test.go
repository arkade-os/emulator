package application

import (
	"context"
	"errors"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkintent "github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestSubmitFinalizationValidatesForfeitOutputs proves the emulator only signs
// a forfeit whose output side matches the one tree.BuildForfeitTx produces for
// the vtxo committed by the intent proof and the connector taken from the
// connector tree. Matching the vtxo input against a previously signed intent
// proof is not enough on its own: the requester supplies the whole forfeit, so
// without an output check a legitimately approved input can be spent into any
// transaction they like.
func TestSubmitFinalizationValidatesForfeitOutputs(t *testing.T) {
	fix := newForfeitFixture(t)

	attackerScript := fix.randomP2TRScript(t)

	t.Run("canonical forfeit is signed", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)

		signed, err := fix.submit(t, forfeit)
		require.NoError(t, err)
		require.Len(t, signed.Forfeits, 1)
		require.Len(t, forfeit.Inputs[0].TaprootScriptSpendSig, 1)
	})

	t.Run("whole value redirected to the requester", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)
		forfeit.UnsignedTx.TxOut = []*wire.TxOut{{
			Value:    fix.vtxoPrevout.Value + fix.connectorOutput.Value,
			PkScript: attackerScript,
		}}

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("value split into an extra output", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)
		total := fix.vtxoPrevout.Value + fix.connectorOutput.Value
		forfeit.UnsignedTx.TxOut = []*wire.TxOut{
			{Value: 1, PkScript: fix.forfeitScript},
			{Value: total - 1, PkScript: attackerScript},
			txutils.AnchorOutput(),
		}

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("anchor replaced by a requester output", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)
		forfeit.UnsignedTx.TxOut[1] = &wire.TxOut{Value: 0, PkScript: attackerScript}

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("forfeit output value does not conserve the inputs", func(t *testing.T) {
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)
		forfeit.UnsignedTx.TxOut[0].Value -= 5_000

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	// the witness utxo is checked against the intent proof before the output
	// side is validated, so an inflated prevout fails the binding check
	t.Run("vtxo prevout inflated against the intent proof", func(t *testing.T) {
		inflated := &wire.TxOut{
			Value:    fix.vtxoPrevout.Value * 10,
			PkScript: fix.vtxoPrevout.PkScript,
		}
		forfeit := fix.buildForfeit(t, inflated, fix.connectorOutput)

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "witness UTXO does not match intent proof")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("connector prevout does not match the tree", func(t *testing.T) {
		forged := &wire.TxOut{
			Value:    fix.connectorOutput.Value * 100,
			PkScript: fix.connectorOutput.PkScript,
		}
		forfeit := fix.buildForfeit(t, fix.vtxoPrevout, forged)

		_, err := fix.submit(t, forfeit)
		require.ErrorContains(t, err, "malformed forfeit")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("connector outside the tree", func(t *testing.T) {
		bogusConnector := wire.OutPoint{Hash: chainhash.Hash{0x99}, Index: 0}
		forfeit, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{&fix.vtxoOutpoint, &bogusConnector},
			[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{fix.vtxoPrevout, fix.connectorOutput},
			fix.forfeitScript,
			0,
		)
		require.NoError(t, err)
		forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{fix.leafScript}

		_, err = fix.submit(t, forfeit)
		require.ErrorContains(t, err, "is not part of the tree")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})
}

// TestSubmitFinalizationRejectsUnknownCommitmentTx proves SubmitFinalization
// signs nothing — forfeits included — when the commitment tx is not a
// commitment tx known to the arkd indexer.
func TestSubmitFinalizationRejectsUnknownCommitmentTx(t *testing.T) {
	// keep the retry loop fast for the unit test
	oldRetryConfig := commitmentTxRetryConfig
	commitmentTxRetryConfig = retryConfig{
		MinAttempts:  1,
		MaxAttempts:  2,
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		Multiplier:   1,
	}
	t.Cleanup(func() { commitmentTxRetryConfig = oldRetryConfig })

	fix := newForfeitFixture(t)
	forfeit := fix.buildForfeit(t, fix.vtxoPrevout, fix.connectorOutput)

	svc := &service{
		signer:        signer{fix.signerKey},
		indexerClient: &mockIndexerClient{err: errors.New("batch not found")},
	}
	_, err := svc.SubmitFinalization(t.Context(), BatchFinalization{
		Intent:        fix.intent,
		Forfeits:      []*psbt.Packet{forfeit},
		ConnectorTree: fix.connectorTree,
		CommitmentTx:  fix.commitmentTx,
	})
	require.ErrorContains(t, err, "not known to arkd indexer")
	require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
}

func TestValidateForfeitOutputs(t *testing.T) {
	vtxo := &wire.TxOut{Value: 100_000, PkScript: []byte{txscript.OP_TRUE}}
	connector := &wire.TxOut{Value: 450, PkScript: []byte{txscript.OP_TRUE}}

	newForfeit := func(t *testing.T) *psbt.Packet {
		t.Helper()

		tx := wire.NewMsgTx(3)
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxOut(&wire.TxOut{
			Value:    vtxo.Value + connector.Value - txutils.ANCHOR_VALUE,
			PkScript: []byte{txscript.OP_TRUE},
		})
		tx.AddTxOut(txutils.AnchorOutput())
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		ptx.Inputs[0].WitnessUtxo = vtxo
		ptx.Inputs[1].WitnessUtxo = connector
		return ptx
	}

	// not a packet mutation: the vtxo prevout argument itself is missing
	t.Run("nil vtxo prevout is rejected", func(t *testing.T) {
		err := validateForfeitOutputs(newForfeit(t), 0, nil, connector)
		require.ErrorContains(t, err, "missing vtxo prevout for input 0")
	})

	tests := []struct {
		name    string
		mutate  func(*psbt.Packet)
		wantErr string
	}{
		{name: "valid"},
		{
			name: "missing vtxo witness utxo",
			mutate: func(ptx *psbt.Packet) {
				ptx.Inputs[0].WitnessUtxo = nil
			},
			wantErr: "missing witness utxo for input 0",
		},
		{
			name: "missing connector witness utxo",
			mutate: func(ptx *psbt.Packet) {
				ptx.Inputs[1].WitnessUtxo = nil
			},
			wantErr: "missing witness utxo for input 1",
		},
		{
			name: "vtxo witness utxo mismatch",
			mutate: func(ptx *psbt.Packet) {
				ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: vtxo.Value - 1, PkScript: vtxo.PkScript}
			},
			wantErr: "does not spend the vtxo committed by the intent proof",
		},
		{
			name: "connector witness utxo mismatch",
			mutate: func(ptx *psbt.Packet) {
				ptx.Inputs[1].WitnessUtxo = &wire.TxOut{Value: connector.Value - 1, PkScript: connector.PkScript}
			},
			wantErr: "does not spend the connector output of the tree",
		},
		{
			name: "extra output",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}})
			},
			wantErr: "expected 2 outputs",
		},
		{
			name: "anchor script replaced",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.TxOut[1].PkScript = []byte{txscript.OP_TRUE}
			},
			wantErr: "is not the anchor output",
		},
		{
			name: "wrong anchor value",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.TxOut[1].Value = txutils.ANCHOR_VALUE + 1
			},
			wantErr: "is not the anchor output",
		},
		{
			name: "wrong value",
			mutate: func(ptx *psbt.Packet) {
				ptx.UnsignedTx.TxOut[0].Value--
			},
			wantErr: "output 0 pays",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			forfeit := newForfeit(t)
			if tc.mutate != nil {
				tc.mutate(forfeit)
			}

			err := validateForfeitOutputs(forfeit, 0, vtxo, connector)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestLeafOutput(t *testing.T) {
	connectorTx := wire.NewMsgTx(3)
	connectorTx.AddTxIn(&wire.TxIn{})
	connectorTx.AddTxOut(&wire.TxOut{Value: 450, PkScript: []byte{0x52}})
	connectorTx.AddTxOut(txutils.AnchorOutput())

	root, err := psbt.NewFromUnsignedTx(connectorTx)
	require.NoError(t, err)

	connectorTree := &tree.TxTree{Root: root}
	txid := connectorTx.TxHash()

	t.Run("nil tree", func(t *testing.T) {
		require.Nil(t, leafOutput(nil, wire.OutPoint{Hash: txid, Index: 0}))
	})

	t.Run("outpoint not in the tree", func(t *testing.T) {
		require.Nil(t, leafOutput(
			connectorTree, wire.OutPoint{Hash: chainhash.Hash{0xff}, Index: 0},
		))
	})

	t.Run("output index out of range", func(t *testing.T) {
		require.Nil(t, leafOutput(connectorTree, wire.OutPoint{Hash: txid, Index: 5}))
	})

	t.Run("anchor output", func(t *testing.T) {
		require.Nil(t, leafOutput(connectorTree, wire.OutPoint{Hash: txid, Index: 1}))
	})

	t.Run("non-leaf node", func(t *testing.T) {
		parent := &tree.TxTree{Root: root, Children: map[uint32]*tree.TxTree{0: {}}}
		require.Nil(t, leafOutput(parent, wire.OutPoint{Hash: txid, Index: 0}))
	})

	t.Run("leaf output is returned", func(t *testing.T) {
		out := leafOutput(connectorTree, wire.OutPoint{Hash: txid, Index: 0})
		require.Equal(t, connectorTx.TxOut[0], out)
	})
}

func TestSubmitFinalizationValidatesAuthorizedInput(t *testing.T) {
	emulatorKey := newResolverPrivateKey(t)
	arkdKey := newResolverPrivateKey(t)
	arkadeScript := []byte{txscript.OP_TRUE}
	tweakedKey := arkade.ComputeArkadeScriptPublicKey(
		emulatorKey.PubKey(), arkade.ArkadeScriptHash(arkadeScript),
	)

	authorizedClosure := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{tweakedKey, arkdKey.PubKey()}}
	foreignClosure := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{tweakedKey}}
	vtxoScript := arkscript.TapscriptsVtxoScript{
		Closures: []arkscript.Closure{authorizedClosure, foreignClosure},
	}
	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	pkScript, err := arkscript.P2TRScript(tapKey)
	require.NoError(t, err)
	authorizedLeaf := finalizationTapLeaf(t, authorizedClosure, tapTree)
	foreignLeaf := finalizationTapLeaf(t, foreignClosure, tapTree)
	prevout := &wire.TxOut{Value: 100_000, PkScript: pkScript}
	outpoint := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}

	tests := []struct {
		name           string
		proofLeaf      *psbt.TaprootTapLeafScript
		commitmentLeaf *psbt.TaprootTapLeafScript
		commitment     *wire.TxOut
		wantErr        string
	}{
		{
			name:           "matching authorized input",
			proofLeaf:      authorizedLeaf,
			commitmentLeaf: authorizedLeaf,
			commitment:     prevout,
		},
		{
			name:           "foreign leaf",
			proofLeaf:      authorizedLeaf,
			commitmentLeaf: foreignLeaf,
			commitment:     prevout,
			wantErr:        "taproot leaf script does not match intent proof",
		},
		{
			name:           "different prevout",
			proofLeaf:      authorizedLeaf,
			commitmentLeaf: authorizedLeaf,
			commitment:     &wire.TxOut{Value: prevout.Value - 1, PkScript: prevout.PkScript},
			wantErr:        "witness UTXO does not match intent proof",
		},
		{
			name:           "different prevout script",
			proofLeaf:      authorizedLeaf,
			commitmentLeaf: authorizedLeaf,
			commitment:     &wire.TxOut{Value: prevout.Value, PkScript: []byte{txscript.OP_TRUE}},
			wantErr:        "witness UTXO does not match intent proof",
		},
		{
			name:           "leaf without arkd signer",
			proofLeaf:      foreignLeaf,
			commitmentLeaf: foreignLeaf,
			commitment:     prevout,
			wantErr:        "finalization leaf does not require the arkd signer",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intent := signedFinalizationIntent(
				t, emulatorKey, arkadeScript, tc.proofLeaf, prevout, outpoint,
			)
			commitment := finalizationCommitment(t, tc.commitmentLeaf, tc.commitment, outpoint)
			svc := &service{
				signer:        signer{emulatorKey},
				arkdPubKey:    arkdKey.PubKey(),
				indexerClient: &mockIndexerClient{},
			}

			signed, err := svc.SubmitFinalization(context.Background(), BatchFinalization{
				Intent:       intent,
				CommitmentTx: commitment,
			})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Empty(t, commitment.Inputs[0].TaprootScriptSpendSig)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, signed.CommitmentTx)
			require.NotEmpty(t, signed.CommitmentTx.Inputs[0].TaprootScriptSpendSig)
		})
	}
}

// forfeitFixture holds a signer that already approved an intent proof for a
// single vtxo, plus the connector tree that vtxo's forfeit must use.
type forfeitFixture struct {
	signerKey         *btcec.PrivateKey
	arkdKey           *btcec.PrivateKey
	intent            Intent
	commitmentTx      *psbt.Packet
	connectorTree     *tree.TxTree
	leafScript        *psbt.TaprootTapLeafScript
	forfeitScript     []byte
	vtxoOutpoint      wire.OutPoint
	vtxoPrevout       *wire.TxOut
	connectorOutpoint wire.OutPoint
	connectorOutput   *wire.TxOut
}

func newForfeitFixture(t *testing.T) *forfeitFixture {
	t.Helper()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScript := []byte{txscript.OP_TRUE}
	scriptHash := arkade.ArkadeScriptHash(arkadeScript)

	// the finalization leaf must require the arkd signer, see validateFinalizationInput
	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{
		arkade.ComputeArkadeScriptPublicKey(signerKey.PubKey(), scriptHash),
		arkdKey.PubKey(),
	}}
	vtxoScript := arkscript.TapscriptsVtxoScript{
		Closures: []arkscript.Closure{&closure},
	}

	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	tapscript, err := closure.Script()
	require.NoError(t, err)

	tapLeaf := txscript.NewBaseTapLeaf(tapscript)
	merkleProof, err := tapTree.GetTaprootMerkleProof(tapLeaf.TapHash())
	require.NoError(t, err)

	vtxoPkScript, err := arkscript.P2TRScript(tapKey)
	require.NoError(t, err)

	fix := &forfeitFixture{
		signerKey: signerKey,
		arkdKey:   arkdKey,
		leafScript: &psbt.TaprootTapLeafScript{
			ControlBlock: merkleProof.ControlBlock,
			Script:       merkleProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		},
		vtxoOutpoint: wire.OutPoint{Hash: chainhash.Hash{0xa1}, Index: 0},
		vtxoPrevout:  &wire.TxOut{Value: 100_000, PkScript: vtxoPkScript},
	}
	fix.forfeitScript = fix.randomP2TRScript(t)

	// the connector tree: a single leaf paying one connector output
	connectorTx := wire.NewMsgTx(3)
	connectorTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xb1}, Index: 0},
	})
	connectorTx.AddTxOut(&wire.TxOut{Value: 450, PkScript: fix.randomP2TRScript(t)})
	connectorTx.AddTxOut(txutils.AnchorOutput())

	connectorPtx, err := psbt.NewFromUnsignedTx(connectorTx)
	require.NoError(t, err)

	fix.connectorTree = &tree.TxTree{Root: connectorPtx}
	fix.connectorOutpoint = wire.OutPoint{Hash: connectorTx.TxHash(), Index: 0}
	fix.connectorOutput = connectorTx.TxOut[0]

	fix.intent = Intent{Proof: fix.newSignedIntentProof(t, arkadeScript, tapLeaf)}

	// a commitment tx with no input the signer owns, so the boarding branch of
	// SubmitFinalization is reached but signs nothing
	commitmentTx := wire.NewMsgTx(3)
	commitmentTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xc1}, Index: 0},
	})
	commitmentTx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: fix.randomP2TRScript(t)})
	commitmentPtx, err := psbt.NewFromUnsignedTx(commitmentTx)
	require.NoError(t, err)
	commitmentPtx.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value: 2_000, PkScript: fix.randomP2TRScript(t),
	}
	fix.commitmentTx = commitmentPtx

	return fix
}

// newSignedIntentProof builds the intent proof the emulator signed in the past:
// input 0 is the message input, input 1 spends the vtxo and carries the
// emulator's own tapscript signature.
func (f *forfeitFixture) newSignedIntentProof(
	t *testing.T, arkadeScript []byte, tapLeaf txscript.TapLeaf,
) arkintent.Proof {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xd1}, Index: 0},
	})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: f.vtxoOutpoint})

	packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 1, Script: arkadeScript})
	require.NoError(t, err)
	packetOut, err := extension.Extension{packet}.TxOut()
	require.NoError(t, err)
	tx.AddTxOut(packetOut)

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// the message input reuses the vtxo script, see intent.New
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value: 0, PkScript: f.vtxoPrevout.PkScript,
	}
	ptx.Inputs[1].WitnessUtxo = f.vtxoPrevout
	ptx.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.leafScript}

	prevoutFetcher, err := computePrevoutFetcher(ptx)
	require.NoError(t, err)

	signingKey := arkade.ComputeArkadeScriptPrivateKey(
		f.signerKey, arkade.ArkadeScriptHash(arkadeScript),
	)
	message, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(tx, prevoutFetcher), txscript.SigHashDefault,
		tx, 1, prevoutFetcher, tapLeaf,
	)
	require.NoError(t, err)

	sig, err := schnorr.Sign(signingKey, message)
	require.NoError(t, err)

	leafHash := tapLeaf.TapHash()
	ptx.Inputs[1].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
		XOnlyPubKey: schnorr.SerializePubKey(signingKey.PubKey()),
		LeafHash:    leafHash[:],
		Signature:   sig.Serialize(),
		SigHash:     txscript.SigHashDefault,
	}}

	return arkintent.Proof{Packet: *ptx}
}

// buildForfeit produces the forfeit tx a requester would submit, spending the
// vtxo and its connector with the prevouts it claims they have.
func (f *forfeitFixture) buildForfeit(
	t *testing.T, vtxoPrevout, connectorOutput *wire.TxOut,
) *psbt.Packet {
	t.Helper()

	forfeit, err := tree.BuildForfeitTx(
		[]*wire.OutPoint{&f.vtxoOutpoint, &f.connectorOutpoint},
		[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
		[]*wire.TxOut{vtxoPrevout, connectorOutput},
		f.forfeitScript,
		0,
	)
	require.NoError(t, err)

	forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{f.leafScript}

	return forfeit
}

func (f *forfeitFixture) submit(
	t *testing.T, forfeits ...*psbt.Packet,
) (*SignedBatchFinalization, error) {
	t.Helper()

	svc := &service{
		signer:        signer{f.signerKey},
		arkdPubKey:    f.arkdKey.PubKey(),
		indexerClient: &mockIndexerClient{},
	}
	return svc.SubmitFinalization(t.Context(), BatchFinalization{
		Intent:        f.intent,
		Forfeits:      forfeits,
		ConnectorTree: f.connectorTree,
		CommitmentTx:  f.commitmentTx,
	})
}

func (f *forfeitFixture) randomP2TRScript(t *testing.T) []byte {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pkScript, err := arkscript.P2TRScript(key.PubKey())
	require.NoError(t, err)
	return pkScript
}

// mockIndexerClient confirms every commitment tx unless err is set; any
// other call panics on the nil embedded interface.
type mockIndexerClient struct {
	indexer.Indexer
	err error
}

func (m *mockIndexerClient) GetCommitmentTx(
	context.Context, string,
) (*indexer.CommitmentTx, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &indexer.CommitmentTx{}, nil
}

func finalizationTapLeaf(
	t *testing.T, closure arkscript.Closure, tapTree arklib.TaprootTree,
) *psbt.TaprootTapLeafScript {
	t.Helper()

	script, err := closure.Script()
	require.NoError(t, err)
	proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(script).TapHash())
	require.NoError(t, err)
	return &psbt.TaprootTapLeafScript{
		ControlBlock: proof.ControlBlock,
		Script:       proof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}
}

func signedFinalizationIntent(
	t *testing.T,
	emulatorKey *btcec.PrivateKey,
	arkadeScript []byte,
	tapLeaf *psbt.TaprootTapLeafScript,
	prevout *wire.TxOut,
	outpoint wire.OutPoint,
) Intent {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{2}}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: outpoint})
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	for i := range ptx.Inputs {
		ptx.Inputs[i].WitnessUtxo = prevout
	}
	ptx.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}

	packet, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 1, Script: arkadeScript})
	require.NoError(t, err)
	packetOutput, err := (extension.Extension{packet}).TxOut()
	require.NoError(t, err)
	ptx.UnsignedTx.AddTxOut(packetOutput)
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})

	prevoutFetcher, err := computePrevoutFetcher(ptx)
	require.NoError(t, err)
	require.NoError(t, (signer{emulatorKey}).signInput(
		ptx, 1, arkade.ArkadeScriptHash(arkadeScript), prevoutFetcher,
	))

	return Intent{Proof: arkintent.Proof{Packet: *ptx}}
}

func finalizationCommitment(
	t *testing.T, tapLeaf *psbt.TaprootTapLeafScript, prevout *wire.TxOut, outpoint wire.OutPoint,
) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: outpoint})
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Inputs[0].WitnessUtxo = prevout
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}
	return ptx
}
