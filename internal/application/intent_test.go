package application

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestValidateMessage(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour).Unix()
	future := now.Add(time.Hour).Unix()

	tests := []struct {
		name    string
		message IntentMessage
		wantErr string // "" means the message is accepted
	}{
		// every type is accepted inside a valid window
		{"register valid", &intent.RegisterMessage{ValidAt: past, ExpireAt: future}, ""},
		{"estimate-fee valid", &intent.EstimateIntentFeeMessage{ValidAt: past, ExpireAt: future}, ""},
		{"delete valid", &intent.DeleteMessage{ExpireAt: future}, ""},
		{"get-pending-tx valid", &intent.GetPendingTxMessage{ExpireAt: future}, ""},
		{"get-intent valid", &intent.GetIntentMessage{ExpireAt: future}, ""},
		{"get-data valid", &intent.GetDataMessage{ExpireAt: future}, ""},

		// zero timestamps mean "no bound" -> always valid
		{"delete no expiry", &intent.DeleteMessage{}, ""},

		// expired (ExpireAt in the past)
		{"register expired", &intent.RegisterMessage{ExpireAt: past}, "expired"},
		{"delete expired", &intent.DeleteMessage{ExpireAt: past}, "expired"},

		// not valid yet (only register/estimate-fee carry ValidAt)
		{"register not valid yet", &intent.RegisterMessage{ValidAt: future}, "not valid yet"},
		{"estimate-fee not valid yet", &intent.EstimateIntentFeeMessage{ValidAt: future}, "not valid yet"},

		// a message type the switch doesn't handle
		{"unsupported type", unknownMessage{}, "unsupported intent message type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMessage(tc.message)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestSubmitIntentMessageInputBinding covers the message input (index 0) of an
// intent proof. It is signed with input 1's arkade script hash, so its script
// must actually be input 1's script: the VM never executes input 0 on its own.
// A proof declaring a different script for input 0 must be rejected rather than
// yielding a signature bound to a script that was never executed for it.
func TestSubmitIntentMessageInputBinding(t *testing.T) {
	signerKey := newResolverPrivateKey(t)
	arkadeScript, err := txscript.NewScriptBuilder().
		AddData([]byte("type")).
		AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).
		AddData([]byte(intent.IntentMessageTypeRegister)).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)
	tweaked := arkade.ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), arkade.ArkadeScriptHash(arkadeScript),
	)

	owned := newIntentVtxo(t, tweaked)
	// a script the emulator never executes, standing in for an attacker-declared
	// message input
	foreign := newIntentVtxo(t, newResolverPrivateKey(t).PubKey())

	entry := arkade.EmulatorEntry{Vin: 1, Script: arkadeScript}

	t.Run("signs message input when scripts match", func(t *testing.T) {
		ptx := newIntentProof(t, []intentVtxo{owned, owned}, entry)

		signed, err := submitTestIntent(t, signerKey, ptx)
		require.NoError(t, err)
		require.NotEmpty(t, signed.Inputs[1].TaprootScriptSpendSig)
		require.NotEmpty(t, signed.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("rejects mismatched message input script", func(t *testing.T) {
		ptx := newIntentProof(t, []intentVtxo{foreign, owned}, entry)

		signed, err := submitTestIntent(t, signerKey, ptx)
		require.ErrorContains(t, err, "message input")
		require.Nil(t, signed)
		// nothing may be signed once the proof is rejected
		require.Empty(t, ptx.Inputs[0].TaprootScriptSpendSig)
	})

	t.Run("rejects missing witness utxo", func(t *testing.T) {
		for _, inputIdx := range []int{0, 1} {
			t.Run(fmt.Sprintf("input %d", inputIdx), func(t *testing.T) {
				ptx := newIntentProof(t, []intentVtxo{owned, owned}, entry)
				ptx.Inputs[inputIdx].WitnessUtxo = nil

				signed, err := submitTestIntent(t, signerKey, ptx)
				require.ErrorContains(t, err, "witness utxo")
				require.Nil(t, signed)
			})
		}
	})
}

func TestValidateIntentMessageCommitment(t *testing.T) {
	message, encoded := testRegisterMessage(t)
	ptx := newIntentProof(
		t, []intentVtxo{{}, {pkScript: []byte{txscript.OP_TRUE}}},
		arkade.EmulatorEntry{Vin: 1, Script: []byte{txscript.OP_TRUE}},
	)
	ptx.Inputs[1].WitnessUtxo = &wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}}
	bindIntentProofToMessage(t, ptx, encoded)

	request := Intent{
		Proof:   intent.Proof{Packet: *ptx},
		Message: message,
	}
	require.NoError(t, validateIntentMessageCommitment(request, encoded))

	// a proof bound to non-canonical bytes fails the outpoint comparison
	require.ErrorContains(t,
		validateIntentMessageCommitment(request, " "+encoded), "synthetic message input")
	require.ErrorContains(t, validateIntentMessageCommitment(request, strings.Replace(
		encoded, `"expire_at":`, `"expire_at":1,"expire_at":`, 1,
	)), "synthetic message input")

	request.Proof.UnsignedTx.TxIn[0].PreviousOutPoint.Hash[0] ^= 0xff
	require.ErrorContains(t,
		validateIntentMessageCommitment(request, encoded), "synthetic message input")
}

func TestSubmitIntentRejectsOnchainOutputsBeforeSigning(t *testing.T) {
	signerKey := newResolverPrivateKey(t)
	arkadeScript := []byte{txscript.OP_TRUE}
	tweaked := arkade.ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), arkade.ArkadeScriptHash(arkadeScript),
	)
	owned := newIntentVtxo(t, tweaked)
	ptx := newIntentProof(
		t, []intentVtxo{owned, owned},
		arkade.EmulatorEntry{Vin: 1, Script: arkadeScript},
	)

	svc := &service{signer: signer{signerKey}}
	signed, err := svc.SubmitIntent(t.Context(), Intent{
		Proof: intent.Proof{Packet: *ptx},
		Message: &intent.RegisterMessage{
			OnchainOutputIndexes: []int{0},
		},
	})

	require.ErrorContains(t, err, "onchain outputs are not supported")
	require.Nil(t, signed)
	require.Empty(t, ptx.Inputs[0].TaprootScriptSpendSig)
	require.Empty(t, ptx.Inputs[1].TaprootScriptSpendSig)
}

// TestSubmitIntentEntryResolution covers how SubmitIntent treats entries that do
// not resolve to one of its signers. Entries attributed to another emulator are
// legitimately skipped (as in SubmitTx/SubmitOnchainTx), but a malformed entry
// must fail the whole request, and a proof where nothing was signed must not be
// returned as if it had succeeded.
func TestSubmitIntentEntryResolution(t *testing.T) {
	signerKey := newResolverPrivateKey(t)
	arkadeScript := []byte{txscript.OP_TRUE}
	tweaked := arkade.ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), arkade.ArkadeScriptHash(arkadeScript),
	)

	owned := newIntentVtxo(t, tweaked)
	foreign := newIntentVtxo(t, newResolverPrivateKey(t).PubKey())

	ownedEntry := arkade.EmulatorEntry{Vin: 1, Script: arkadeScript}
	otherEntry := arkade.EmulatorEntry{Vin: 2, Script: arkadeScript}

	t.Run("skips entries owned by another signer", func(t *testing.T) {
		ptx := newIntentProof(t, []intentVtxo{owned, owned, foreign}, ownedEntry, otherEntry)

		signed, err := submitTestIntent(t, signerKey, ptx)
		require.NoError(t, err)
		require.NotEmpty(t, signed.Inputs[1].TaprootScriptSpendSig)
		require.Empty(t, signed.Inputs[2].TaprootScriptSpendSig)
	})

	t.Run("rejects malformed entry instead of skipping it", func(t *testing.T) {
		ptx := newIntentProof(t, []intentVtxo{owned, owned, foreign}, ownedEntry, otherEntry)
		// a structurally broken input is not "someone else's entry", it must not
		// be silently dropped from an otherwise successful response
		ptx.Inputs[2].TaprootLeafScript = nil

		signed, err := submitTestIntent(t, signerKey, ptx)
		require.ErrorContains(t, err, "failed to read arkade script")
		require.Nil(t, signed)
	})

	t.Run("rejects proof with nothing signed", func(t *testing.T) {
		// the only entry targets the message input, which the loop always skips,
		// so no input is ever signed
		ptx := newIntentProof(
			t, []intentVtxo{owned, owned},
			arkade.EmulatorEntry{Vin: 0, Script: arkadeScript},
		)

		signed, err := submitTestIntent(t, signerKey, ptx)
		require.ErrorContains(t, err, "valid input/entry pairs")
		require.Nil(t, signed)
	})
}

// unknownMessage satisfies IntentMessage but is not one of the six arkd types,
// so it exercises validateMessage's default branch.
type unknownMessage struct{}

func (unknownMessage) Encode() (string, error) { return "", nil }
func (unknownMessage) Decode(string) error     { return nil }

func submitTestIntent(
	t *testing.T, signerKey *btcec.PrivateKey, ptx *psbt.Packet,
) (*psbt.Packet, error) {
	t.Helper()

	message, encoded := testRegisterMessage(t)
	if len(ptx.Inputs) > 1 && ptx.Inputs[1].WitnessUtxo != nil {
		bindIntentProofToMessage(t, ptx, encoded)
	}
	svc := &service{signer: signer{signerKey}}
	return svc.SubmitIntent(t.Context(), Intent{
		Proof:   intent.Proof{Packet: *ptx},
		Message: message,
	})
}

func TestExpiryForScriptOnlyQueriesIndexerForPushExpiry(t *testing.T) {
	calls := 0
	svc := &service{indexerClient: expiryIndexer{calls: &calls}}
	txid := chainhash.Hash{}.String()

	pushedOpcode, err := txscript.NewScriptBuilder().
		AddData([]byte{arkade.OP_PUSHEXPIRY}).Script()
	require.NoError(t, err)

	for _, script := range [][]byte{{txscript.OP_TRUE}, pushedOpcode} {
		_, err := svc.expiryForScript(t.Context(), script, txid, 0)
		require.NoError(t, err)
	}
	require.Zero(t, calls)

	_, err = svc.expiryForScript(t.Context(), []byte{arkade.OP_PUSHEXPIRY}, txid, 0)
	require.ErrorContains(t, err, "not found")
	require.Equal(t, 1, calls)

	svc.indexerClient = expiryIndexer{vtxos: []types.Vtxo{{
		Outpoint:  types.Outpoint{Txid: chainhash.Hash{1}.String()},
		ExpiresAt: time.Now().Add(time.Minute),
	}}}
	_, err = svc.expiryForScript(t.Context(), []byte{arkade.OP_PUSHEXPIRY}, txid, 0)
	require.ErrorContains(t, err, "not found")

	svc.indexerClient = expiryIndexer{vtxos: []types.Vtxo{{
		Outpoint: types.Outpoint{Txid: txid},
	}}}
	_, err = svc.expiryForScript(t.Context(), []byte{arkade.OP_PUSHEXPIRY}, txid, 0)
	require.ErrorContains(t, err, "has no expiry")
}

func TestSubmitIntentPushExpiry(t *testing.T) {
	signerKey := newResolverPrivateKey(t)
	expiresAt := time.Now().Add(time.Minute).Truncate(time.Second)
	script, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHEXPIRY).AddInt64(expiresAt.Unix()).AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_TRUE).Script()
	require.NoError(t, err)
	tweaked := arkade.ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), arkade.ArkadeScriptHash(script),
	)
	owned := newIntentVtxo(t, tweaked)
	ptx := newIntentProof(
		t, []intentVtxo{owned, owned}, arkade.EmulatorEntry{Vin: 1, Script: script},
	)
	outpoint := ptx.UnsignedTx.TxIn[1].PreviousOutPoint
	message, encoded := testRegisterMessage(t)
	bindIntentProofToMessage(t, ptx, encoded)

	svc := &service{
		signer: signer{signerKey},
		indexerClient: expiryIndexer{vtxos: []types.Vtxo{{
			Outpoint:  types.Outpoint{Txid: outpoint.Hash.String(), VOut: outpoint.Index},
			ExpiresAt: expiresAt,
		}}},
	}
	signed, err := svc.SubmitIntent(t.Context(), Intent{
		Proof:   intent.Proof{Packet: *ptx},
		Message: message,
	})

	require.NoError(t, err)
	require.NotEmpty(t, signed.Inputs[1].TaprootScriptSpendSig)
}

func testRegisterMessage(t *testing.T) (*intent.RegisterMessage, string) {
	t.Helper()
	message := &intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		ExpireAt:    time.Now().Add(time.Hour).Unix(),
	}
	encoded, err := message.Encode()
	require.NoError(t, err)
	return message, encoded
}

func bindIntentProofToMessage(t *testing.T, ptx *psbt.Packet, encoded string) {
	t.Helper()
	require.GreaterOrEqual(t, len(ptx.UnsignedTx.TxIn), 2)
	require.GreaterOrEqual(t, len(ptx.Inputs), 2)
	require.NotNil(t, ptx.Inputs[1].WitnessUtxo)

	firstInput := ptx.UnsignedTx.TxIn[1]
	expected, err := intent.New(encoded, []intent.Input{{
		OutPoint:    &firstInput.PreviousOutPoint,
		Sequence:    firstInput.Sequence,
		WitnessUtxo: ptx.Inputs[1].WitnessUtxo,
	}}, nil)
	require.NoError(t, err)
	ptx.UnsignedTx.TxIn[0].PreviousOutPoint = expected.UnsignedTx.TxIn[0].PreviousOutPoint
}

// intentVtxo is a taproot coin with a single multisig closure, enough for the
// emulator to resolve and execute an arkade script against it.
type intentVtxo struct {
	pkScript     []byte
	leafScript   []byte
	controlBlock []byte
}

func newIntentVtxo(t *testing.T, closurePubKeys ...*btcec.PublicKey) intentVtxo {
	t.Helper()

	closure := arkscript.MultisigClosure{PubKeys: closurePubKeys}
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

	return intentVtxo{
		pkScript:     pkScript,
		leafScript:   merkleProof.Script,
		controlBlock: merkleProof.ControlBlock,
	}
}

// newIntentProof builds an intent-proof shaped psbt: input 0 is the message
// input built from input 1's script, the remaining inputs are the coins being
// proven. Each proven input carries the authenticated prevout tx it spends.
// The entries are embedded in the emulator packet OP_RETURN output.
func newIntentProof(
	t *testing.T, inputs []intentVtxo, entries ...arkade.EmulatorEntry,
) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{1}, Index: 0,
	}})
	prevTxs := make(map[int]*wire.MsgTx)
	for i := 1; i < len(inputs); i++ {
		prevTx := wire.NewMsgTx(2)
		prevTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
			Hash: chainhash.Hash{byte(i + 100)}, Index: 0,
		}})
		prevTx.AddTxOut(&wire.TxOut{Value: 2_000, PkScript: inputs[i].pkScript})
		prevTxs[i] = prevTx
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}})
	}
	tx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: inputs[0].pkScript})

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	for i, in := range inputs {
		// like intent.New, the message input carries the script of input 1 with
		// a zero value
		value := int64(2_000)
		if i == 0 {
			value = 0
		}
		ptx.Inputs[i].WitnessUtxo = &wire.TxOut{Value: value, PkScript: in.pkScript}
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: in.controlBlock,
			Script:       in.leafScript,
			LeafVersion:  txscript.BaseLeafVersion,
		}}
		if prevTx, ok := prevTxs[i]; ok {
			require.NoError(t, txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *prevTx))
		}
	}

	packet, err := arkade.NewPacket(entries...)
	require.NoError(t, err)

	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)
	ptx.UnsignedTx.AddTxOut(txOut)
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})

	return ptx
}

type expiryIndexer struct {
	indexer.Indexer
	calls *int
	vtxos []types.Vtxo
}

func (e expiryIndexer) GetVtxos(
	context.Context, ...indexer.GetVtxosOption,
) (*indexer.VtxosResponse, error) {
	if e.calls != nil {
		(*e.calls)++
	}
	return &indexer.VtxosResponse{Vtxos: e.vtxos}, nil
}
