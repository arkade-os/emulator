// ponytail: superseded by arkd-signer, delete with internal/
package application

import (
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkintent "github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestSignerFor(t *testing.T) {
	currentKey := newResolverPrivateKey(t)
	deprecatedKey := newResolverPrivateKey(t)
	foreignKey := newResolverPrivateKey(t)
	hash := arkade.ArkadeScriptHash([]byte{txscript.OP_TRUE})
	request := func(keys ...*btcec.PrivateKey) emulator.SignRequest {
		req := emulator.SignRequest{ScriptHash: hash}
		for _, key := range keys {
			req.ClosurePubKeys = append(
				req.ClosurePubKeys, arkade.ComputeArkadeScriptPublicKey(key.PubKey(), hash),
			)
		}
		return req
	}
	svc := &service{signer: signer{currentKey}, deprecatedSigners: []signer{{deprecatedKey}}}

	matched, ok := svc.signerFor(request(foreignKey, currentKey))
	require.True(t, ok)
	require.Same(t, currentKey, matched.secretKey)

	matched, ok = svc.signerFor(request(deprecatedKey))
	require.True(t, ok)
	require.Same(t, deprecatedKey, matched.secretKey)

	_, ok = svc.signerFor(request(foreignKey))
	require.False(t, ok)

	// untweaked key never matches
	_, ok = svc.signerFor(emulator.SignRequest{
		ScriptHash: hash, ClosurePubKeys: []*btcec.PublicKey{currentKey.PubKey()},
	})
	require.False(t, ok)

	past := time.Now().Add(-time.Hour)
	svc.deprecatedKeysValidUntil = &past
	_, ok = svc.signerFor(request(deprecatedKey))
	require.False(t, ok)
}

// TestSignInputRejectsUncommittedTaprootLeaf proves the signer refuses to
// produce a tapscript signature for a leaf script that the prevout does not
// commit to. The leaf is taken verbatim from the requester's PSBT, so without
// the control block check the emulator authorises a spend of a tapscript that
// is not in the taproot tree being spent.
func TestSignInputRejectsUncommittedTaprootLeaf(t *testing.T) {
	signerKey := newResolverPrivateKey(t)
	arkadeScript := []byte{txscript.OP_TRUE}
	tweak := arkade.ArkadeScriptHash(arkadeScript)

	t.Run("committed leaf is signed", func(t *testing.T) {
		ptx, fetcher := newSignableInput(t, signerKey, arkadeScript)

		err := signer{signerKey}.signInput(ptx, 0, tweak, fetcher)
		require.NoError(t, err)
		require.Len(t, ptx.Inputs[0].TaprootScriptSpendSig, 1)
	})

	t.Run("leaf swapped for one outside the tree", func(t *testing.T) {
		ptx, fetcher := newSignableInput(t, signerKey, arkadeScript)

		// a closure the requester controls, still carrying the tweaked emulator
		// key so every other check passes, but not committed by the prevout
		attackerKey := newResolverPrivateKey(t)
		forged := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{
			arkade.ComputeArkadeScriptPublicKey(signerKey.PubKey(), tweak),
			attackerKey.PubKey(),
		}}
		forgedScript, err := forged.Script()
		require.NoError(t, err)
		ptx.Inputs[0].TaprootLeafScript[0].Script = forgedScript

		err = signer{signerKey}.signInput(ptx, 0, tweak, fetcher)
		require.ErrorContains(t, err, "not committed")
		require.Empty(t, ptx.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("missing control block", func(t *testing.T) {
		ptx, fetcher := newSignableInput(t, signerKey, arkadeScript)
		ptx.Inputs[0].TaprootLeafScript[0].ControlBlock = nil

		err := signer{signerKey}.signInput(ptx, 0, tweak, fetcher)
		require.ErrorContains(t, err, "control block")
		require.Empty(t, ptx.Inputs[0].TaprootScriptSpendSig)
	})
}

// newSignableInput builds a single-input packet spending a real taproot output
// whose tree commits to the arkade script's forfeit closure, mirroring what
// arkd hands the emulator.
func newSignableInput(
	t *testing.T, signerKey *btcec.PrivateKey, arkadeScript []byte,
) (*psbt.Packet, txscript.PrevOutputFetcher) {
	t.Helper()

	tweakedSigner := arkade.ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), arkade.ArkadeScriptHash(arkadeScript),
	)
	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{tweakedSigner}}
	vtxoScript := arkscript.TapscriptsVtxoScript{
		Closures: []arkscript.Closure{&closure},
	}

	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	tapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := tapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(tapscript).TapHash(),
	)
	require.NoError(t, err)

	pkScript, err := arkscript.P2TRScript(tapKey)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0},
	})
	tx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: pkScript})

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 2_000, PkScript: pkScript}
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: merkleProof.ControlBlock,
		Script:       merkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	fetcher, err := computePrevoutFetcher(ptx)
	require.NoError(t, err)

	return ptx, fetcher
}

func newResolverPrivateKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key
}

func TestSignInputRejectsUnsafeSighashTypes(t *testing.T) {
	key := newResolverPrivateKey(t)
	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{
		arkade.ComputeArkadeScriptPublicKey(key.PubKey(), nil),
	}}
	tapscript, err := closure.Script()
	require.NoError(t, err)

	leaf := txscript.NewBaseTapLeaf(tapscript)
	tapTree := txscript.AssembleTaprootScriptTree(leaf)
	root := tapTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(key.PubKey(), root[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	// single-leaf tree: the control block carries only the internal key, no
	// inclusion proof
	controlBlock := txscript.ControlBlock{
		InternalKey:     key.PubKey(),
		OutputKeyYIsOdd: outputKey.SerializeCompressed()[0] == 0x03,
		LeafVersion:     txscript.BaseLeafVersion,
	}
	controlBlockBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	prevout := &wire.TxOut{Value: 1000, PkScript: pkScript}
	prevoutFetcher := txscript.NewCannedPrevOutputFetcher(prevout.PkScript, prevout.Value)

	newPacket := func(t *testing.T, sighashType txscript.SigHashType) *psbt.Packet {
		t.Helper()

		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxOut(&wire.TxOut{Value: 900, PkScript: pkScript})
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		ptx.Inputs[0].WitnessUtxo = prevout
		ptx.Inputs[0].SighashType = sighashType
		ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: controlBlockBytes,
			Script:       tapscript,
			LeafVersion:  txscript.BaseLeafVersion,
		}}
		return ptx
	}

	tests := []struct {
		name        string
		sighashType txscript.SigHashType
		accepted    bool
	}{
		{name: "default", sighashType: txscript.SigHashDefault, accepted: true},
		{name: "all", sighashType: txscript.SigHashAll, accepted: true},
		{name: "none", sighashType: txscript.SigHashNone},
		{name: "single", sighashType: txscript.SigHashSingle},
		{name: "anyonecanpay", sighashType: txscript.SigHashAnyOneCanPay},
		{name: "all anyonecanpay", sighashType: txscript.SigHashAll | txscript.SigHashAnyOneCanPay},
		{name: "none anyonecanpay", sighashType: txscript.SigHashNone | txscript.SigHashAnyOneCanPay},
		{name: "single anyonecanpay", sighashType: txscript.SigHashSingle | txscript.SigHashAnyOneCanPay},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ptx := newPacket(t, tc.sighashType)

			err := signer{key}.signInput(ptx, 0, nil, prevoutFetcher)

			if tc.accepted {
				require.NoError(t, err)
				require.Len(t, ptx.Inputs[0].TaprootScriptSpendSig, 1)
				require.Equal(t, tc.sighashType, ptx.Inputs[0].TaprootScriptSpendSig[0].SigHash)
				return
			}

			require.ErrorContains(t, err, "unsupported sighash type")
			require.Empty(t, ptx.Inputs[0].TaprootScriptSpendSig)
		})
	}
}

func TestSignFinalization(t *testing.T) {
	deprecatedKey := newResolverPrivateKey(t)
	arkdKey := newResolverPrivateKey(t)
	arkadeScript := []byte{txscript.OP_TRUE}
	closure := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{
		arkade.ComputeArkadeScriptPublicKey(deprecatedKey.PubKey(), arkade.ArkadeScriptHash(arkadeScript)),
		arkdKey.PubKey(),
	}}
	vtxoScript := arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{closure}}
	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	vtxoPkScript, err := arkscript.P2TRScript(tapKey)
	require.NoError(t, err)
	leaf := finalizationTapLeaf(t, closure, tapTree)
	vtxoPrevout := &wire.TxOut{Value: 100_000, PkScript: vtxoPkScript}
	vtxoOutpoint := wire.OutPoint{Hash: chainhash.Hash{0xa1}, Index: 0}
	forfeitScript := randomP2TRScript(t)

	connectorTx := wire.NewMsgTx(3)
	connectorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xb1}}})
	connectorTx.AddTxOut(&wire.TxOut{Value: 450, PkScript: randomP2TRScript(t)})
	connectorTx.AddTxOut(txutils.AnchorOutput())
	connectorPtx, err := psbt.NewFromUnsignedTx(connectorTx)
	require.NoError(t, err)
	connectorOutpoint := wire.OutPoint{Hash: connectorTx.TxHash(), Index: 0}

	commitmentTx := wire.NewMsgTx(3)
	commitmentTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xc1}}})
	commitmentTx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: randomP2TRScript(t)})
	commitmentPtx, err := psbt.NewFromUnsignedTx(commitmentTx)
	require.NoError(t, err)
	commitmentPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 2_000, PkScript: randomP2TRScript(t)}

	buildForfeit := func(t *testing.T, vtxo wire.OutPoint) *psbt.Packet {
		forfeit, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{&vtxo, &connectorOutpoint},
			[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{vtxoPrevout, connectorTx.TxOut[0]},
			forfeitScript, 0,
		)
		require.NoError(t, err)
		forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{leaf}
		return forfeit
	}
	submit := func(t *testing.T, validUntil time.Time, forfeits ...*psbt.Packet) (*SignedBatchFinalization, error) {
		svc := &service{
			lib:                      emulator.New(arkade.DefaultComputeLimits()),
			signer:                   signer{newResolverPrivateKey(t)},
			deprecatedSigners:        []signer{{deprecatedKey}},
			deprecatedKeysValidUntil: &validUntil,
			arkdForfeitPkScript:      forfeitScript,
		}
		return svc.signFinalization(t.Context(), emulator.BatchFinalization{
			Intents:      []emulator.Intent{signedFinalizationIntent(t, deprecatedKey, arkadeScript, leaf, vtxoPrevout, vtxoOutpoint)},
			Forfeits:     forfeits,
			CommitmentTx: commitmentPtx,
		}, &tree.TxTree{Root: connectorPtx})
	}
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)

	t.Run("approved forfeit signed, unapproved skipped", func(t *testing.T) {
		unapproved := buildForfeit(t, wire.OutPoint{Hash: chainhash.Hash{0xa2}})
		approved := buildForfeit(t, vtxoOutpoint)
		signed, err := submit(t, future, unapproved, approved)
		require.NoError(t, err)
		require.Equal(t, []*psbt.Packet{approved}, signed.Forfeits)
		require.Len(t, approved.Inputs[0].TaprootScriptSpendSig, 1)
		require.Empty(t, unapproved.Inputs[0].TaprootScriptSpendSig)
		require.Nil(t, signed.CommitmentTx)
	})

	t.Run("forfeit paying elsewhere rejected", func(t *testing.T) {
		forfeit := buildForfeit(t, vtxoOutpoint)
		forfeit.UnsignedTx.TxOut[0].PkScript = randomP2TRScript(t)
		_, err := submit(t, future, forfeit)
		require.ErrorContains(t, err, "output 0 does not pay the arkd forfeit script")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("deprecated key past cutoff no longer approves", func(t *testing.T) {
		forfeit := buildForfeit(t, vtxoOutpoint)
		_, err := submit(t, past, forfeit)
		require.ErrorContains(t, err, "failed to find any valid input/entry pairs")
		require.Empty(t, forfeit.Inputs[0].TaprootScriptSpendSig)
	})
}

func randomP2TRScript(t *testing.T) []byte {
	t.Helper()
	pkScript, err := arkscript.P2TRScript(newResolverPrivateKey(t).PubKey())
	require.NoError(t, err)
	return pkScript
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
) emulator.Intent {
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

	return emulator.Intent{Proof: arkintent.Proof{Packet: *ptx}}
}
