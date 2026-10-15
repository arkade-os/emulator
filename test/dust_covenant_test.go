package test

import (
	"encoding/hex"
	"sort"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/test/covenant"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// The covenant logic itself is proven without a stack in test/covenant. This
// file checks the parts only a live arkd and emulator can: that the emulator
// signs a covenant-satisfying spend, that arkd accepts the resulting
// transaction, and that the bitcoin accounting holds end to end.

// ARKD_VTXO_MIN_AMOUNT=1 in docker-compose.regtest.yml. Not exposed by GetInfo.
const dustCovenantVtxoMinAmount = int64(1)

// Genesis-era timestamp: always already satisfied, as in htlc_test.go.
const dustCovenantLocktime = arklib.AbsoluteLocktime(500_000_000)

// onlyForfeitScript requires exactly one forfeit closure; this taptree has four.
func tapscriptAt(t *testing.T, vtxoScript script.TapscriptsVtxoScript, i int) []byte {
	t.Helper()
	s, err := vtxoScript.Closures[i].Script()
	require.NoError(t, err)
	return s
}

type dustContract struct {
	params   covenant.Params
	scripts  covenant.Scripts
	vtxo     script.TapscriptsVtxoScript
	pkScript []byte
}

func newDustContract(
	t *testing.T, server, emulator, sender *btcec.PublicKey, p covenant.Params,
) dustContract {
	t.Helper()
	scripts, err := covenant.Build(p, dustCovenantVtxoMinAmount)
	require.NoError(t, err)
	vtxo := covenant.VtxoScript(server, emulator, sender, p, scripts)
	return dustContract{
		params:   p,
		scripts:  scripts,
		vtxo:     vtxo,
		pkScript: p2trScriptForVtxoScript(t, vtxo),
	}
}

func (c dustContract) input(t *testing.T, prevTx *wire.MsgTx, leaf int) offchain.VtxoInput {
	t.Helper()
	return vtxoInputFromScriptOutput(t, prevTx, 0, c.vtxo, tapscriptAt(t, c.vtxo, leaf))
}

func (c dustContract) payout(t *testing.T, key *btcec.PublicKey, value int64) []byte {
	t.Helper()
	s, err := covenant.PayoutPkScript(key, value, c.params.Dust)
	require.NoError(t, err)
	return s
}

// issuancePacket mints a fresh asset across the given outputs. Zero amounts are
// omitted, so a recipient genuinely holds no entry for the asset. Outputs are
// emitted in vout order: ranging a map directly would randomise it between runs.
func issuancePacket(t *testing.T, amounts map[uint16]uint64) asset.Packet {
	t.Helper()
	vouts := make([]uint16, 0, len(amounts))
	for vout := range amounts {
		vouts = append(vouts, vout)
	}
	sort.Slice(vouts, func(i, j int) bool { return vouts[i] < vouts[j] })

	outs := make([]asset.AssetOutput, 0, len(amounts))
	for _, vout := range vouts {
		amt := amounts[vout]
		if amt == 0 {
			continue
		}
		o, err := asset.NewAssetOutput(vout, amt)
		require.NoError(t, err)
		outs = append(outs, *o)
	}
	grp, err := asset.NewAssetGroup(nil, nil, []asset.AssetInput{}, outs, []asset.Metadata{})
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

// transferPacket moves an existing asset from vin 0 across the given outputs.
// Multi-output transfers are fine, unlike multi-output issuance; the
// asset-account prototype's routing packet splits across three.
func transferPacket(
	t *testing.T, id asset.AssetId, total uint64, amounts map[uint16]uint64,
) asset.Packet {
	t.Helper()
	in, err := asset.NewAssetInput(0, total)
	require.NoError(t, err)

	vouts := make([]uint16, 0, len(amounts))
	for vout := range amounts {
		vouts = append(vouts, vout)
	}
	sort.Slice(vouts, func(i, j int) bool { return vouts[i] < vouts[j] })

	outs := make([]asset.AssetOutput, 0, len(amounts))
	for _, vout := range vouts {
		if amounts[vout] == 0 {
			continue
		}
		o, err := asset.NewAssetOutput(vout, amounts[vout])
		require.NoError(t, err)
		outs = append(outs, *o)
	}

	grp, err := asset.NewAssetGroup(&id, nil, []asset.AssetInput{*in}, outs, []asset.Metadata{})
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

// setPrevArkTxs attaches each input's previous arkade transaction. This is not
// automatic: executeArkadeScripts and the emulator skip inputs without the
// field, so FetchVtxoPrevOutPkScript returns nil and OP_INSPECTINPUTSCRIPTPUBKEY
// fails with "previous output not found". Only recycle needs it, being the only
// covenant that inspects a second input -- purchase reads input values, which
// resolve through FetchPrevOutput and the PSBT's witness UTXO instead.
// See test/cross_input_script_validation_test.go:345-346.
func setPrevArkTxs(t *testing.T, ptx *psbt.Packet, prevs ...*wire.MsgTx) {
	t.Helper()
	for i, prev := range prevs {
		require.NoError(t, txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *prev))
	}
}

// mergePacket moves the covenant's units at vin 0, plus whatever the receiver's
// account already held at vin 1, into a single output at vout 1.
func mergePacket(t *testing.T, id asset.AssetId, covenantUnits, accountUnits uint64) asset.Packet {
	t.Helper()
	in0, err := asset.NewAssetInput(0, covenantUnits)
	require.NoError(t, err)
	inputs := []asset.AssetInput{*in0}
	if accountUnits > 0 {
		in1, err := asset.NewAssetInput(1, accountUnits)
		require.NoError(t, err)
		inputs = append(inputs, *in1)
	}
	out, err := asset.NewAssetOutput(1, covenantUnits+accountUnits)
	require.NoError(t, err)
	grp, err := asset.NewAssetGroup(
		&id, nil, inputs, []asset.AssetOutput{*out}, []asset.Metadata{},
	)
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

func TestDustCovenant(t *testing.T) {
	ctx := t.Context()

	sender, senderWallet, senderPubKey, grpcSender := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcSender.Close() })
	senderAddr := fundAndSettleAlice(t, ctx, sender, 100_000)

	receiver, receiverWallet, receiverPubKey, grpcReceiver := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcReceiver.Close() })
	_ = fundAndSettleAlice(t, ctx, receiver, 100_000)

	_, _, operatorPubKey, grpcOperator := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcOperator.Close() })

	emulator, emulatorPubKey, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() { _ = conn.Close() })

	indexerSvc := setupIndexer(t)

	infos, err := grpcSender.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScript, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	server := senderAddr.Signer
	dust := int64(infos.Dust)
	require.Greater(t, dust, dustCovenantVtxoMinAmount,
		"sub-dust outputs need ARKD_VTXO_MIN_AMOUNT below dust")

	exitDelay := uint32(infos.UnilateralExitDelay)
	senderAccount := defaultVtxoScript(senderPubKey, server, exitDelay)
	receiverAccount := defaultVtxoScript(receiverPubKey, server, exitDelay)
	operatorAccount := defaultVtxoScript(operatorPubKey, server, exitDelay)

	senderAccountPk := p2trScriptForVtxoScript(t, *senderAccount)
	receiverAccountPk := p2trScriptForVtxoScript(t, *receiverAccount)

	senderKey, _, err := senderAccount.TapTree()
	require.NoError(t, err)
	receiverKey, _, err := receiverAccount.TapTree()
	require.NoError(t, err)
	operatorKey, _, err := operatorAccount.TapTree()
	require.NoError(t, err)

	baseParams := func() covenant.Params {
		return covenant.Params{
			ReceiverKey: receiverKey,
			SenderKey:   senderKey,
			OperatorKey: operatorKey,
			Dust:        dust,
			Topup:       dust,
			Locktime:    dustCovenantLocktime,
		}
	}

	// arkd registers a submitted transaction's outputs asynchronously, so
	// spending one immediately can lose the race and fail with VTXO_NOT_FOUND.
	//
	// Waiting on the outpoints specifically, rather than on the transaction:
	// GetVirtualTxs returns the transaction before its outputs are spendable, so
	// waiting on that still raced. The subscription helper was not used either --
	// a subscription opened per funding transaction, over scripts an earlier
	// subscription had already registered and removed on cleanup, never delivered
	// its events (got 0/3) even though the transaction was accepted.
	awaitSpendable := func(t *testing.T, tx *wire.MsgTx, vouts ...uint32) {
		t.Helper()
		txid := tx.TxID()
		outpoints := make([]types.Outpoint, 0, len(vouts))
		for _, vout := range vouts {
			outpoints = append(outpoints, types.Outpoint{Txid: txid, VOut: vout})
		}
		require.Eventually(t, func() bool {
			res, err := indexerSvc.GetVtxos(ctx, indexer.WithOutpoints(outpoints))
			if err != nil || res == nil || len(res.Vtxos) != len(outpoints) {
				return false
			}
			for _, v := range res.Vtxos {
				if v.Spent {
					return false
				}
			}
			return true
		}, 30*time.Second, 250*time.Millisecond, "vtxos of %s not spendable", txid)
	}

	// Each funding transaction uses its own freshly settled funder and is never
	// chained into the next. Spending a settled VTXO works; spending a funder's
	// change from a previous arkade transaction produced an invalid signature in
	// the checkpoint, and the asset-account prototype likewise funds once and
	// only ever spends that transaction's first output. A funder per call also
	// removes the cross-subtest coupling entirely.
	//
	// Outputs, each with a distinct script -- two outputs sharing one script make
	// the wallet sign for the wrong prevout amount:
	//
	//	[0] sender account, two dust units, carrying the whole issuance
	//	[1] funder change, unused
	//
	// The sender gets two dust units because the lockup splits this account into
	// the covenant and the receiver's account, and each needs one.
	fundAccounts := func(t *testing.T, packet *asset.Packet) *wire.MsgTx {
		t.Helper()

		funder, funderWallet, funderPubKey, grpcFunder := setupArkSDKwithPublicKey(t)
		t.Cleanup(func() { grpcFunder.Close() })
		_ = fundAndSettleAlice(t, ctx, funder, 100_000)

		funderAccount := defaultVtxoScript(funderPubKey, server, exitDelay)
		funderAccountPk := p2trScriptForVtxoScript(t, *funderAccount)
		funding := findAccountInput(t, ctx, funder, indexerSvc, *funderAccount)

		change := funding.Amount - 2*dust
		require.Positive(t, change)

		tx, cps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{funding},
			[]*wire.TxOut{
				{Value: 2 * dust, PkScript: senderAccountPk},
				{Value: change, PkScript: funderAccountPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		if packet != nil {
			addAssetPacketToTx(t, tx, *packet)
		}

		submitWithArkd(t, ctx, tx, cps, funderWallet, grpcFunder)
		awaitSpendable(t, tx.UnsignedTx, 0)

		return tx.UnsignedTx
	}

	// mint issues a fresh asset to a single output. Issuance must happen in its
	// own transaction: the covenant pins the AssetID, which for an issuance
	// derives from that transaction's own txid, so issuing inside the lockup
	// would make the address depend on a txid that depends on the address.
	//
	// Single-output deliberately. A two-output issuance made the funding
	// transaction fail to finalize with an invalid checkpoint signature, while
	// multi-output *transfers* are fine -- the asset-account prototype's routing
	// packet splits across three. So the split happens in the lockup instead.
	mint := func(t *testing.T, units uint64) (*wire.MsgTx, asset.AssetId) {
		t.Helper()
		packet := issuancePacket(t, map[uint16]uint64{0: units})
		tx := fundAccounts(t, &packet)
		h := tx.TxHash()
		return tx, asset.AssetId{Txid: [asset.TX_HASH_SIZE]byte(h), Index: 0}
	}

	// lockup splits the sender's funded account into the covenant and the
	// receiver's account, in one transfer:
	//
	//	[0] covenant, dust, carrying sent units
	//	[1] receiver account, dust, carrying priorUnits (its balance before the
	//	    payment, which the recycle covenant must tolerate at any value)
	//
	// Doing the split here rather than at issuance is what keeps the issuance
	// single-output; see mint. The sender's own bitcoin commitment is unchanged
	// either way, since both dust units came from the funder.
	lockup := func(
		t *testing.T, fundTx *wire.MsgTx, c dustContract, sent, priorUnits uint64,
	) *wire.MsgTx {
		t.Helper()
		in := vtxoInputFromScriptOutput(
			t, fundTx, 0, *senderAccount, onlyForfeitScript(t, *senderAccount),
		)
		require.Equal(t, 2*c.params.Dust, in.Amount)

		tx, cps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{in},
			[]*wire.TxOut{
				{Value: c.params.Dust, PkScript: c.pkScript},
				{Value: c.params.Dust, PkScript: receiverAccountPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		if c.params.AssetID != nil {
			// vin is the transaction input index, not the funding output index.
			addAssetPacketToTx(t, tx, transferPacket(t, *c.params.AssetID,
				sent+priorUnits, map[uint16]uint64{0: sent, 1: priorUnits},
			))
		}

		submitWithArkd(t, ctx, tx, cps, senderWallet, grpcSender)
		awaitSpendable(t, tx.UnsignedTx, 0, 1)

		return tx.UnsignedTx
	}

	// Leaves other than refundSender carry no human key, so the emulator's
	// signature is the only one a covenant-only spend needs.
	submitToEmulator := func(t *testing.T, ptx *psbt.Packet, cps []*psbt.Packet) error {
		t.Helper()
		encoded, err := ptx.B64Encode()
		require.NoError(t, err)
		_, _, err = emulator.SubmitTx(ctx, encoded, encodeCheckpoints(t, cps))
		return err
	}

	// LeafRefundSender's closure carries the sender's key, so the sender signs the
	// arkade transaction and its checkpoints alongside the emulator.
	submitSenderSigned := func(t *testing.T, ptx *psbt.Packet, cps []*psbt.Packet) error {
		t.Helper()
		signed, err := senderWallet.SignTransaction(ctx, b64(t, ptx), nil)
		require.NoError(t, err)
		_, _, err = emulator.SubmitTx(
			ctx, signed, signCheckpoints(t, ctx, senderWallet, nil, cps),
		)
		return err
	}

	// A merge also spends the receiver's own account, so the receiver must sign
	// the arkade transaction and its checkpoints. The emulator supplies only the
	// covenant input's signature.
	submitMerge := func(t *testing.T, ptx *psbt.Packet, cps []*psbt.Packet) error {
		t.Helper()
		signed, err := receiverWallet.SignTransaction(ctx, b64(t, ptx), nil)
		require.NoError(t, err)
		_, _, err = emulator.SubmitTx(
			ctx, signed, signCheckpoints(t, ctx, receiverWallet, nil, cps),
		)
		return err
	}

	t.Run("purchase", func(t *testing.T) {
		const units = uint64(100)

		mintTx, assetID := mint(t, units)

		p := baseParams()
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, c, units, 0)

		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, covenant.LeafPurchase)},
			[]*wire.TxOut{{Value: dust, PkScript: receiverAccountPk}},
			checkpointScript,
		)
		require.NoError(t, err)
		// The AssetID stays the issuance txid for the asset's whole life; it does
		// not become the lockup's txid when the asset moves.
		addAssetPacketToTx(t, claimTx, createTransferAssetPacket(
			t, mintTx.TxHash(), 0, 0, 0, units,
		))
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Purchase},
		})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))
		require.NoError(t, submitToEmulator(t, claimTx, claimCps))
	})

	// recycleCase drives the merge path for a receiver holding priorUnits of the
	// same asset. priorUnits == 0 exercises the lookup miss path.
	recycleCase := func(t *testing.T, priorUnits uint64) {
		t.Helper()
		const sent = uint64(1)

		mintTx, assetID := mint(t, sent+priorUnits)

		p := baseParams()
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, c, sent, priorUnits)

		covenantIn := c.input(t, lockTx, covenant.LeafRecycle)
		accountIn := vtxoInputFromScriptOutput(
			t, lockTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
		)

		merged := covenantIn.Amount + accountIn.Amount - p.Topup
		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{covenantIn, accountIn},
			[]*wire.TxOut{
				{Value: p.Topup, PkScript: c.payout(t, operatorKey, p.Topup)},
				{Value: merged, PkScript: receiverAccountPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		addAssetPacketToTx(t, claimTx, mergePacket(t, assetID, sent, priorUnits))
		setPrevArkTxs(t, claimTx, lockTx, lockTx)
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Recycle},
		})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))
		require.NoError(t, submitMerge(t, claimTx, claimCps))

		require.Equal(t, accountIn.Amount, claimTx.UnsignedTx.TxOut[1].Value,
			"receiver's bitcoin balance must be unchanged")
		require.Equal(t, p.Topup, claimTx.UnsignedTx.TxOut[0].Value,
			"operator must recover its advance in full")
	}

	t.Run("recycle/receiver_holds_prior_balance", func(t *testing.T) {
		recycleCase(t, 20)
	})

	t.Run("recycle/receiver_holds_zero", func(t *testing.T) {
		recycleCase(t, 0)
	})

	t.Run("recovery/after_locktime", func(t *testing.T) {
		const units = uint64(7)

		mintTx, assetID := mint(t, units)

		p := baseParams()
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, c, units, 0)
		topup := p.RefundTopup(dustCovenantVtxoMinAmount)

		refundTx, refundCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, covenant.LeafRecovery)},
			[]*wire.TxOut{
				{Value: topup, PkScript: c.payout(t, operatorKey, topup)},
				{Value: dust - topup, PkScript: c.payout(t, senderKey, dust-topup)},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		refundTx.UnsignedTx.LockTime = uint32(p.Locktime)
		addAssetPacketToTx(t, refundTx, createTransferAssetPacket(
			t, mintTx.TxHash(), 0, 0, 1, units,
		))
		addEmulatorPacket(t, refundTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Refund},
		})

		// The live validation of the hardcoded vtxoMinAmount is arkd accepting this
		// transaction: the sender's returned payload is exactly that many sats, so
		// a higher configured minimum rejects it. Asserting dust-topup ==
		// dustCovenantVtxoMinAmount here would prove nothing, being true by
		// construction once RefundTopup has been applied.
		require.Less(t, dust-topup, dust, "sender's payload must be sub-dust")

		require.NoError(t, executeArkadeScripts(t, refundTx, refundCps, emulatorPubKey))
		require.NoError(t, submitToEmulator(t, refundTx, refundCps))
	})

	// LeafRefundSender is the only leaf carrying a human key. It shares the refund
	// covenant with LeafRecovery but not its closure, so the end-to-end path --
	// sender signs, emulator signs, arkd accepts -- needs its own coverage.
	t.Run("refund/sender_signed", func(t *testing.T) {
		const units = uint64(7)

		mintTx, assetID := mint(t, units)

		p := baseParams()
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, c, units, 0)
		topup := p.RefundTopup(dustCovenantVtxoMinAmount)

		refundTx, refundCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, covenant.LeafRefundSender)},
			[]*wire.TxOut{
				{Value: topup, PkScript: c.payout(t, operatorKey, topup)},
				{Value: dust - topup, PkScript: c.payout(t, senderKey, dust-topup)},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		addAssetPacketToTx(t, refundTx, createTransferAssetPacket(
			t, mintTx.TxHash(), 0, 0, 1, units,
		))
		addEmulatorPacket(t, refundTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Refund},
		})

		// No locktime is set: unlike recovery, this leaf is spendable immediately
		// because the sender's signature stands in for the timeout.
		require.NoError(t, executeArkadeScripts(t, refundTx, refundCps, emulatorPubKey))
		require.NoError(t, submitSenderSigned(t, refundTx, refundCps))
	})

	// The covenant does not read the locktime; the CLTV closure does. Only a live
	// emulator can reject this, which is why it has no counterpart in the
	// stack-free covenant tests.
	t.Run("recovery/rejected_before_locktime", func(t *testing.T) {
		const units = uint64(7)

		mintTx, assetID := mint(t, units)

		p := baseParams()
		p.AssetID = &assetID
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, mintTx, c, units, 0)
		topup := p.RefundTopup(dustCovenantVtxoMinAmount)

		tx, cps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{c.input(t, lockTx, covenant.LeafRecovery)},
			[]*wire.TxOut{
				{Value: topup, PkScript: c.payout(t, operatorKey, topup)},
				{Value: dust - topup, PkScript: c.payout(t, senderKey, dust-topup)},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		tx.UnsignedTx.LockTime = uint32(p.Locktime) - 1
		addAssetPacketToTx(t, tx, createTransferAssetPacket(
			t, mintTx.TxHash(), 0, 0, 1, units,
		))
		addEmulatorPacket(t, tx, []arkade.EmulatorEntry{{Vin: 0, Script: c.scripts.Refund}})

		// Asserting the covenant accepts first is what makes the rejection
		// meaningful: it isolates the failure to the CLTV closure rather than
		// letting the test pass for any unrelated reason.
		require.NoError(t, executeArkadeScripts(t, tx, cps, emulatorPubKey))
		require.Error(t, submitToEmulator(t, tx, cps))
	})

	t.Run("bitcoin_variant/recycle_50_sats", func(t *testing.T) {
		const payload = int64(50)

		// No asset anywhere: the bitcoin variant omits the asset clauses, and an
		// unaccounted asset on the input would be rejected by arkd.
		fundTx := fundAccounts(t, nil)

		p := baseParams()
		p.Topup = dust - payload
		c := newDustContract(t, server, emulatorPubKey, senderPubKey, p)

		lockTx := lockup(t, fundTx, c, 0, 0)

		covenantIn := c.input(t, lockTx, covenant.LeafRecycle)
		accountIn := vtxoInputFromScriptOutput(
			t, lockTx, 1, *receiverAccount, onlyForfeitScript(t, *receiverAccount),
		)

		merged := covenantIn.Amount + accountIn.Amount - p.Topup
		claimTx, claimCps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{covenantIn, accountIn},
			[]*wire.TxOut{
				{Value: p.Topup, PkScript: c.payout(t, operatorKey, p.Topup)},
				{Value: merged, PkScript: receiverAccountPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		setPrevArkTxs(t, claimTx, lockTx, lockTx)
		addEmulatorPacket(t, claimTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.scripts.Recycle},
		})

		require.NoError(t, executeArkadeScripts(t, claimTx, claimCps, emulatorPubKey))
		require.NoError(t, submitMerge(t, claimTx, claimCps))

		require.Equal(t, payload, claimTx.UnsignedTx.TxOut[1].Value-accountIn.Amount,
			"receiver must gain exactly the payload")
		require.Equal(t, dust-payload, claimTx.UnsignedTx.TxOut[0].Value,
			"operator must be made whole")
	})
}
