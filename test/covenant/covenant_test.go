package covenant_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/test/covenant"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// These run the covenants through the arkade engine directly: no arkd, no
// emulator, no regtest stack. They cover everything the covenant itself decides.
// They do not cover arkd's validation (asset balance, output minimums) or the
// tapscript closures' signature and timelock requirements, both of which the
// design depends on separately.

const (
	dust      = int64(330)
	minAmount = int64(1)
)

type prevOutFetcher struct {
	txscript.PrevOutputFetcher
}

func (prevOutFetcher) FetchPrevOutArkTx(wire.OutPoint) *wire.MsgTx { return nil }

// OP_INSPECTINPUTSCRIPTPUBKEY reads this, not FetchPrevOutput. Returning nil
// here makes every covenant that inspects an input fail before reaching the
// condition under test, which turns rejection tests green for the wrong reason.
func (f prevOutFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	prev := f.FetchPrevOutput(op)
	if prev == nil {
		return nil
	}
	return prev.PkScript
}

func key(t *testing.T, seed byte) *btcec.PublicKey {
	t.Helper()
	buf := make([]byte, 32)
	buf[31] = seed
	_, pub := btcec.PrivKeyFromBytes(buf)
	return pub
}

func p2tr(t *testing.T, k *btcec.PublicKey) []byte {
	t.Helper()
	s, err := script.P2TRScript(k)
	require.NoError(t, err)
	return s
}

func subDust(t *testing.T, k *btcec.PublicKey) []byte {
	t.Helper()
	s, err := script.SubDustScript(k)
	require.NoError(t, err)
	return s
}

type spend struct {
	prevouts []*wire.TxOut
	outputs  []*wire.TxOut
	packet   asset.Packet
}

func (s spend) clone() spend {
	out := spend{
		prevouts: make([]*wire.TxOut, len(s.prevouts)),
		outputs:  make([]*wire.TxOut, len(s.outputs)),
		packet:   clonePacket(s.packet),
	}
	for i, p := range s.prevouts {
		cp := *p
		cp.PkScript = bytes.Clone(p.PkScript)
		out.prevouts[i] = &cp
	}
	for i, o := range s.outputs {
		cp := *o
		cp.PkScript = bytes.Clone(o.PkScript)
		out.outputs[i] = &cp
	}
	return out
}

// A codec round trip rather than a field-by-field copy, so a pointer or slice
// ark-lib later adds to AssetGroup cannot end up shared. Test packets come from
// asset.NewPacket, which already validated them, so neither step can fail.
func clonePacket(p asset.Packet) asset.Packet {
	if p == nil {
		return nil
	}
	raw, err := p.Serialize()
	if err != nil {
		panic(err)
	}
	out, err := asset.NewPacketFromBytes(raw)
	if err != nil {
		panic(err)
	}
	return out
}

func TestSpendCloneIsDeep(t *testing.T) {
	orig := spend{
		prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 1))}},
		outputs:  []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 2))}},
		packet: packetOf(t, assetID(0),
			map[uint16]uint64{0: 7}, map[uint16]uint64{0: 7},
		),
	}
	before, err := orig.packet.Serialize()
	require.NoError(t, err)
	prevScript := bytes.Clone(orig.prevouts[0].PkScript)
	outScript := bytes.Clone(orig.outputs[0].PkScript)

	c := orig.clone()
	cloned, err := c.packet.Serialize()
	require.NoError(t, err)
	require.Equal(t, before, cloned)

	c.prevouts[0].PkScript[2] ^= 0xff
	c.outputs[0].PkScript[2] ^= 0xff
	c.packet[0].AssetId.Index = 9
	c.packet[0].Inputs[0].Amount = 1
	c.packet[0].Outputs[0].Amount = 1

	after, err := orig.packet.Serialize()
	require.NoError(t, err)
	require.Equal(t, before, after, "mutating a clone's packet changed the original")
	require.Equal(t, prevScript, orig.prevouts[0].PkScript)
	require.Equal(t, outScript, orig.outputs[0].PkScript)
}

// run executes the covenant as input 0 of a synthetic transaction.
func run(t *testing.T, script []byte, s spend) error {
	t.Helper()
	require.NotEmpty(t, s.prevouts)

	tx := &wire.MsgTx{Version: 2}
	prevouts := make(map[wire.OutPoint]*wire.TxOut, len(s.prevouts))
	for i, prev := range s.prevouts {
		op := wire.OutPoint{Hash: chainhash.Hash{byte(i + 1)}, Index: 0}
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op, Sequence: 0xfffffffd})
		prevouts[op] = prev
	}
	for _, o := range s.outputs {
		tx.AddTxOut(o)
	}

	fetcher := prevOutFetcher{txscript.NewMultiPrevOutFetcher(prevouts)}
	engine, err := arkade.NewEngine(
		script, tx, 0,
		txscript.NewSigCache(10),
		txscript.NewTxSigHashes(tx, fetcher),
		s.prevouts[0].Value,
		fetcher,
	)
	require.NoError(t, err)

	if s.packet != nil {
		engine.SetAssetPacket(s.packet)
	}
	return engine.Execute()
}

// requireRejected asserts the covenant rejected the spend by evaluating to
// false, not by failing to run. Index and stack errors mean the script aborted
// before reaching the condition under test -- a harness bug that would otherwise
// show up as a passing rejection test.
func requireRejected(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)

	var scriptErr txscript.Error
	require.ErrorAs(t, err, &scriptErr, "expected a script error, got %v", err)

	switch scriptErr.ErrorCode {
	case txscript.ErrEvalFalse, txscript.ErrVerify, txscript.ErrEqualVerify,
		txscript.ErrNumEqualVerify:
	default:
		t.Fatalf(
			"covenant aborted instead of evaluating false: %s (%v)",
			scriptErr.ErrorCode, err,
		)
	}
}

// assetID is arbitrary but must never equal the spending transaction's own hash,
// which the engine rejects as a fresh-issuance identity collision.
// Deliberately not palindromic, so reversing it produces a different value and
// the byte-order test means something.
func assetID(index uint16) asset.AssetId {
	var txid chainhash.Hash
	for i := range txid {
		txid[i] = byte(i + 1)
	}
	return asset.AssetId{Txid: txid, Index: index}
}

// reversedAssetID flips the txid byte order. The id must be in chainhash
// internal order; the reversed display hex is the classic way to get it wrong.
func reversedAssetID(id *asset.AssetId) *asset.AssetId {
	out := *id
	for i, j := 0, len(out.Txid)-1; i < j; i, j = i+1, j-1 {
		out.Txid[i], out.Txid[j] = out.Txid[j], out.Txid[i]
	}
	return &out
}

// packetOf builds a single-group packet. Zero amounts are omitted, so a receiver
// holding none of the asset genuinely has no entry, which drives the miss path.
// A packet need not balance: arkd is not involved here, so an unbalanced one
// isolates the covenant's own arithmetic.
func packetOf(
	t *testing.T, id asset.AssetId, ins, outs map[uint16]uint64,
) asset.Packet {
	t.Helper()
	assetIns := make([]asset.AssetInput, 0, len(ins))
	for vin, amt := range ins {
		if amt == 0 {
			continue
		}
		in, err := asset.NewAssetInput(vin, amt)
		require.NoError(t, err)
		assetIns = append(assetIns, *in)
	}
	assetOuts := make([]asset.AssetOutput, 0, len(outs))
	for vout, amt := range outs {
		if amt == 0 {
			continue
		}
		out, err := asset.NewAssetOutput(vout, amt)
		require.NoError(t, err)
		assetOuts = append(assetOuts, *out)
	}
	grp, err := asset.NewAssetGroup(&id, nil, assetIns, assetOuts, []asset.Metadata{})
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

func params(t *testing.T, withAsset bool) covenant.Params {
	t.Helper()
	p := covenant.Params{
		ReceiverKey: key(t, 1),
		SenderKey:   key(t, 2),
		OperatorKey: key(t, 3),
		Dust:        dust,
		Topup:       dust,
		Locktime:    500_000_000,
	}
	if withAsset {
		id := assetID(0)
		p.AssetID = &id
	}
	return p
}

func TestRecycle(t *testing.T) {
	p := params(t, true)
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	receiverPk := p2tr(t, p.ReceiverKey)

	// Topup == Dust, so the operator payout sits at the dust floor and pins P2TR.
	valid := func(priorUnits uint64) spend {
		return spend{
			prevouts: []*wire.TxOut{
				{Value: dust, PkScript: p2tr(t, key(t, 9))},
				{Value: dust, PkScript: receiverPk},
			},
			outputs: []*wire.TxOut{
				{Value: p.Topup, PkScript: p2tr(t, p.OperatorKey)},
				{Value: dust, PkScript: receiverPk},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 1, 1: priorUnits},
				map[uint16]uint64{1: 1 + priorUnits},
			),
		}
	}

	t.Run("receiver_holds_prior_balance", func(t *testing.T) {
		require.NoError(t, run(t, s.Recycle, valid(20)))
	})

	// The design's central claim: one script serves a receiver with no prior
	// holding, because a lookup miss returns (0, 0) and the flag is dropped.
	t.Run("receiver_holds_zero", func(t *testing.T) {
		require.NoError(t, run(t, s.Recycle, valid(0)))
	})

	t.Run("reject_wrong_receiver", func(t *testing.T) {
		c := valid(20).clone()
		c.outputs[1].PkScript = p2tr(t, key(t, 7))
		requireRejected(t, run(t, s.Recycle, c))
	})

	t.Run("reject_operator_underpaid", func(t *testing.T) {
		c := valid(20).clone()
		c.outputs[0].Value--
		c.outputs[1].Value++
		requireRejected(t, run(t, s.Recycle, c))
	})

	t.Run("reject_extra_input", func(t *testing.T) {
		c := valid(20).clone()
		c.prevouts = append(c.prevouts, &wire.TxOut{Value: 1000, PkScript: receiverPk})
		requireRejected(t, run(t, s.Recycle, c))
	})

	t.Run("reject_wrong_account_at_input_one", func(t *testing.T) {
		c := valid(20).clone()
		c.prevouts[1].PkScript = p2tr(t, p.SenderKey)
		requireRejected(t, run(t, s.Recycle, c))
	})

	t.Run("reject_asset_amount_shorted", func(t *testing.T) {
		c := valid(20).clone()
		c.packet = packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 1, 1: 20},
			map[uint16]uint64{0: 1, 1: 20},
		)
		requireRejected(t, run(t, s.Recycle, c))
	})

	// Before the found-flag was verified this passed: every lookup missed, the
	// sum degenerated to 0 == 0 + 0, and the asset constraint went unenforced.
	t.Run("reject_foreign_asset_id", func(t *testing.T) {
		c := valid(20).clone()
		c.packet = packetOf(t, assetID(7),
			map[uint16]uint64{0: 1, 1: 20},
			map[uint16]uint64{1: 21},
		)
		requireRejected(t, run(t, s.Recycle, c))
	})

	// The byte-order trap. A covenant built from a reversed txid can never match
	// a real packet; it must fail loudly rather than pass vacuously.
	t.Run("reject_reversed_asset_txid", func(t *testing.T) {
		bad := p
		bad.AssetID = reversedAssetID(p.AssetID)
		badScripts, err := covenant.Build(bad, minAmount)
		require.NoError(t, err)
		requireRejected(t, run(t, badScripts.Recycle, valid(20)))
	})
}

func TestPurchase(t *testing.T) {
	p := params(t, true)
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	receiverPk := p2tr(t, p.ReceiverKey)
	valid := spend{
		prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
		outputs:  []*wire.TxOut{{Value: dust, PkScript: receiverPk}},
		packet: packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 100}, map[uint16]uint64{0: 100},
		),
	}

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, run(t, s.Purchase, valid))
	})

	t.Run("reject_short_value", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].Value--
		requireRejected(t, run(t, s.Purchase, c))
	})

	t.Run("reject_wrong_receiver", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].PkScript = p2tr(t, key(t, 7))
		requireRejected(t, run(t, s.Purchase, c))
	})

	// Purchase enforces the asset constraint with the same required-lookup
	// pattern as recycle, so it needs the same rejection coverage: the
	// silent-pass mode these guard against is the defect this design fixes.
	t.Run("reject_foreign_asset_id", func(t *testing.T) {
		c := valid.clone()
		c.packet = packetOf(t, assetID(7),
			map[uint16]uint64{0: 100}, map[uint16]uint64{0: 100},
		)
		requireRejected(t, run(t, s.Purchase, c))
	})

	t.Run("reject_reversed_asset_txid", func(t *testing.T) {
		bad := p
		bad.AssetID = reversedAssetID(p.AssetID)
		badScripts, err := covenant.Build(bad, minAmount)
		require.NoError(t, err)
		requireRejected(t, run(t, badScripts.Purchase, valid))
	})

	t.Run("reject_asset_amount_shorted", func(t *testing.T) {
		c := valid.clone()
		c.packet = packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 100}, map[uint16]uint64{0: 99},
		)
		requireRejected(t, run(t, s.Purchase, c))
	})
}

// The refund covenant is where sub-dust pinning bites: with Topup == Dust the
// operator recovers Dust-1, itself below dust, so both payouts pin OP_RETURN.
func TestRefund(t *testing.T) {
	p := params(t, true)
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	topup := p.RefundTopup(minAmount)
	require.Equal(t, dust-minAmount, topup)

	valid := spend{
		prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
		outputs: []*wire.TxOut{
			{Value: topup, PkScript: subDust(t, p.OperatorKey)},
			{Value: dust - topup, PkScript: subDust(t, p.SenderKey)},
		},
		packet: packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
		),
	}

	t.Run("valid_subdust_pins", func(t *testing.T) {
		require.NoError(t, run(t, s.Refund, valid))
	})

	// Pinning a below-dust payout as P2TR is the silent-unspendability trap the
	// design warns about; the covenant must reject it.
	t.Run("reject_p2tr_where_subdust_required", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].PkScript = p2tr(t, p.OperatorKey)
		requireRejected(t, run(t, s.Refund, c))
	})

	t.Run("reject_sender_payload_diverted", func(t *testing.T) {
		c := valid.clone()
		c.outputs[1].PkScript = subDust(t, key(t, 7))
		requireRejected(t, run(t, s.Refund, c))
	})

	// Refund is the operator's and the sender's recovery route, so its asset
	// constraint needs the same rejection coverage as the claim paths.
	t.Run("reject_foreign_asset_id", func(t *testing.T) {
		c := valid.clone()
		c.packet = packetOf(t, assetID(7),
			map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
		)
		requireRejected(t, run(t, s.Refund, c))
	})

	t.Run("reject_reversed_asset_txid", func(t *testing.T) {
		bad := p
		bad.AssetID = reversedAssetID(p.AssetID)
		badScripts, err := covenant.Build(bad, minAmount)
		require.NoError(t, err)
		requireRejected(t, run(t, badScripts.Refund, valid))
	})

	t.Run("reject_asset_amount_shorted", func(t *testing.T) {
		c := valid.clone()
		c.packet = packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 7}, map[uint16]uint64{1: 6},
		)
		requireRejected(t, run(t, s.Refund, c))
	})
}

// The refund path in bitcoin mode drops the asset clauses entirely and still has
// to pin both sub-dust payouts, which TestRefund does not cover because it runs
// with an asset.
func TestBitcoinVariantRefund(t *testing.T) {
	const payload = int64(50)

	p := params(t, false)
	p.Topup = dust - payload
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	// Topup is already below dust, so nothing is reserved and the operator
	// recovers its advance whole.
	topup := p.RefundTopup(minAmount)
	require.Equal(t, dust-payload, topup)

	valid := spend{
		prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
		outputs: []*wire.TxOut{
			{Value: topup, PkScript: subDust(t, p.OperatorKey)},
			{Value: payload, PkScript: subDust(t, p.SenderKey)},
		},
	}

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, run(t, s.Refund, valid))
	})

	t.Run("reject_operator_shorted", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].Value--
		c.outputs[1].Value++
		requireRejected(t, run(t, s.Refund, c))
	})

	t.Run("reject_p2tr_where_subdust_required", func(t *testing.T) {
		c := valid.clone()
		c.outputs[1].PkScript = p2tr(t, p.SenderKey)
		requireRejected(t, run(t, s.Refund, c))
	})
}

// Bitcoin payload: no asset packet at all, and the operator's repayment is
// Dust-payload, below dust, so it pins sub-dust.
func TestBitcoinVariant(t *testing.T) {
	const payload = int64(50)

	p := params(t, false)
	p.Topup = dust - payload
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	receiverPk := p2tr(t, p.ReceiverKey)
	valid := spend{
		prevouts: []*wire.TxOut{
			{Value: dust, PkScript: p2tr(t, key(t, 9))},
			{Value: dust, PkScript: receiverPk},
		},
		outputs: []*wire.TxOut{
			{Value: p.Topup, PkScript: subDust(t, p.OperatorKey)},
			{Value: dust + payload, PkScript: receiverPk},
		},
	}

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, run(t, s.Recycle, valid))
		require.Equal(t, payload, valid.outputs[1].Value-valid.prevouts[1].Value,
			"receiver gains exactly the payload")
		require.Equal(t, dust-payload, valid.outputs[0].Value,
			"operator is made whole")
	})

	t.Run("reject_receiver_overpaid", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].Value--
		c.outputs[1].Value++
		requireRejected(t, run(t, s.Recycle, c))
	})

	// Purchase in bitcoin mode terminates via the asset-free branch, which no
	// other test reaches: recycle's bitcoin tests exercise a different script.
	t.Run("purchase", func(t *testing.T) {
		receiverPk := p2tr(t, p.ReceiverKey)
		valid := spend{
			prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
			outputs:  []*wire.TxOut{{Value: dust, PkScript: receiverPk}},
		}

		t.Run("valid", func(t *testing.T) {
			require.NoError(t, run(t, s.Purchase, valid))
		})

		t.Run("reject_short_value", func(t *testing.T) {
			c := valid.clone()
			c.outputs[0].Value--
			requireRejected(t, run(t, s.Purchase, c))
		})

		t.Run("reject_wrong_receiver", func(t *testing.T) {
			c := valid.clone()
			c.outputs[0].PkScript = p2tr(t, key(t, 7))
			requireRejected(t, run(t, s.Purchase, c))
		})
	})
}

func TestParamsValidation(t *testing.T) {
	p := params(t, false)

	t.Run("rejects_topup_above_dust", func(t *testing.T) {
		bad := p
		bad.Topup = dust + 1
		_, err := covenant.Build(bad, minAmount)
		require.Error(t, err)
	})

	t.Run("rejects_topup_below_min", func(t *testing.T) {
		bad := p
		bad.Topup = 0
		_, err := covenant.Build(bad, minAmount)
		require.Error(t, err)
	})

	// A zero absolute locktime is always satisfied, so the recovery leaf would be
	// spendable the moment the covenant is funded.
	t.Run("rejects_reclaim_locktime_not_after_locktime", func(t *testing.T) {
		p := params(t, false)
		p.ReclaimLocktime = p.Locktime
		_, err := covenant.Build(p, minAmount)
		require.ErrorContains(t, err, "must be after locktime")
	})

	t.Run("rejects_mixed_type_locktimes", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			set  func(*covenant.Params)
		}{
			{"height_then_timestamp", func(q *covenant.Params) {
				q.Locktime, q.ReclaimLocktime = 800_000, 500_000_001
			}},
			{"timestamp_then_height", func(q *covenant.Params) {
				q.Locktime, q.ReclaimLocktime = 500_000_000, 900_000
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				bad := p
				tc.set(&bad)
				_, err := covenant.Build(bad, minAmount)
				require.ErrorContains(t, err, "both be heights or both be timestamps")
			})
		}
	})

	t.Run("rejects_zero_locktime", func(t *testing.T) {
		bad := p
		bad.Locktime = 0
		_, err := covenant.Build(bad, minAmount)
		require.ErrorContains(t, err, "locktime")
	})

	// Receiver == operator is the dangerous collapse: the operator could satisfy
	// recycle while paying the top-up repayment to itself.
	t.Run("rejects_reused_keys", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			set  func(*covenant.Params)
		}{
			{"receiver_is_operator", func(q *covenant.Params) { q.OperatorKey = q.ReceiverKey }},
			{"receiver_is_sender", func(q *covenant.Params) { q.SenderKey = q.ReceiverKey }},
			{"sender_is_operator", func(q *covenant.Params) { q.OperatorKey = q.SenderKey }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				bad := p
				tc.set(&bad)
				_, err := covenant.Build(bad, minAmount)
				require.ErrorContains(t, err, "distinct")
			})
		}
	})

	t.Run("rejects_receiver_recovery_without_an_asset", func(t *testing.T) {
		btc := receiverParams(t, false)
		_, err := covenant.Build(btc, minAmount)
		require.ErrorContains(t, err, "requires an asset id")
	})

	t.Run("rejects_receiver_recovery_without_receipt_room", func(t *testing.T) {
		// RefundTopup caps at Dust-vtxoMinAmount, so the held-back sat only drops
		// under the minimum once the dust unit is worth less than two of them.
		tight := receiverParams(t, true)
		tight.Dust, tight.Topup = 3, 3
		_, err := covenant.Build(tight, 2)
		require.ErrorContains(t, err, "sats to host its receipt")
	})

	// RefundTopup only differs from Topup when the operator funded the whole
	// dust unit; that single sat is the cost of an abandoned asset payment.
	t.Run("refund_topup_reserves_one_min_amount_only_when_fully_funded", func(t *testing.T) {
		full := p
		full.Topup = dust
		require.Equal(t, dust-minAmount, full.RefundTopup(minAmount))

		partial := p
		partial.Topup = dust - 50
		require.Equal(t, dust-50, partial.RefundTopup(minAmount))
	})
}

// The last two subtests are the point: once the solver is paid, no leaf may
// hand the asset back.
func TestReclaim(t *testing.T) {
	p := params(t, true)
	p.ReclaimLocktime = p.Locktime + 100_000
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)
	require.NotNil(t, s.Reclaim)

	topup := p.RefundTopup(minAmount)
	valid := spend{
		prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
		outputs: []*wire.TxOut{
			{Value: topup, PkScript: subDust(t, p.OperatorKey)},
			{Value: dust - topup, PkScript: subDust(t, p.ReceiverKey)},
		},
		packet: packetOf(t, *p.AssetID,
			map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
		),
	}

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, run(t, s.Reclaim, valid))
	})

	t.Run("reject_operator_above_its_carrier", func(t *testing.T) {
		c := valid.clone()
		c.outputs[0].Value = topup + 1
		requireRejected(t, run(t, s.Reclaim, c))
	})

	t.Run("reject_receipt_diverted", func(t *testing.T) {
		c := valid.clone()
		c.outputs[1].PkScript = subDust(t, key(t, 7))
		requireRejected(t, run(t, s.Reclaim, c))
	})

	// The scripts differ only in which key holds vout 1, so swapping them is
	// not a compile error.
	t.Run("reclaim_refuses_paying_the_sender", func(t *testing.T) {
		c := valid.clone()
		c.outputs[1].PkScript = subDust(t, p.SenderKey)
		requireRejected(t, run(t, s.Reclaim, c))
	})

	t.Run("refund_refuses_paying_the_receiver", func(t *testing.T) {
		requireRejected(t, run(t, s.Refund, valid))
	})
}

// The backstop appears only when its locktime is set, never with the sender.
func TestReclaimLeafAssembly(t *testing.T) {
	server, emulator := key(t, 4), key(t, 5)

	p := params(t, false)
	s, err := covenant.Build(p, minAmount)
	require.NoError(t, err)
	require.Nil(t, s.Reclaim)
	require.Len(t, covenant.VtxoScript(server, emulator, p.SenderKey, p, s).Closures, 4)

	p.ReclaimLocktime = p.Locktime + 100_000
	s, err = covenant.Build(p, minAmount)
	require.NoError(t, err)

	closures := covenant.VtxoScript(server, emulator, p.SenderKey, p, s).Closures
	require.Len(t, closures, covenant.LeafReclaim+1)

	raw, err := closures[covenant.LeafReclaim].Script()
	require.NoError(t, err)
	require.NotContains(t, string(raw), string(schnorr.SerializePubKey(p.SenderKey)),
		"the post-claim leaf must not be reachable by the party already paid")
}

// The emulator key is tweaked with this to make a claim leaf unreachable.
func disabledLeafScript() []byte {
	return []byte{arkade.OP_FALSE}
}

func tapleaf(t *testing.T, v script.TapscriptsVtxoScript, i int) []byte {
	t.Helper()
	raw, err := v.Closures[i].Script()
	require.NoError(t, err)
	return raw
}

func TestClaimMode(t *testing.T) {
	p := params(t, true)

	legacy, err := covenant.Build(p, minAmount)
	require.NoError(t, err)

	recycleOnly := p
	recycleOnly.ClaimMode = "recycle"
	recycle, err := covenant.Build(recycleOnly, minAmount)
	require.NoError(t, err)

	purchaseOnly := p
	purchaseOnly.ClaimMode = "purchase"
	purchase, err := covenant.Build(purchaseOnly, minAmount)
	require.NoError(t, err)

	// Funded covenants are pinned to these scripts, so absence must change nothing.
	t.Run("absent_mode_keeps_legacy_programs", func(t *testing.T) {
		for _, mode := range []covenant.Scripts{recycle, purchase} {
			require.Equal(t, hex.EncodeToString(legacy.Recycle), hex.EncodeToString(mode.Recycle))
			require.Equal(t, hex.EncodeToString(legacy.Purchase), hex.EncodeToString(mode.Purchase))
			require.Equal(t, hex.EncodeToString(legacy.Refund), hex.EncodeToString(mode.Refund))
		}
	})

	t.Run("empty_mode_is_legacy", func(t *testing.T) {
		legacyMode := p
		legacyMode.ClaimMode = ""
		scripts, err := covenant.Build(legacyMode, minAmount)
		require.NoError(t, err)
		require.Equal(t, hex.EncodeToString(legacy.Recycle), hex.EncodeToString(scripts.Recycle))
		require.Equal(t, hex.EncodeToString(legacy.Purchase), hex.EncodeToString(scripts.Purchase))
		require.Equal(t, hex.EncodeToString(legacy.Refund), hex.EncodeToString(scripts.Refund))
	})

	t.Run("rejects_unknown_mode", func(t *testing.T) {
		bad := p
		bad.ClaimMode = "bogus"
		_, err := covenant.Build(bad, minAmount)
		require.ErrorContains(t, err, "claimMode")
	})

	// The mode has to reach the tree, not just the returned programs.
	t.Run("mode_changes_the_address_but_not_the_leaf_indexes", func(t *testing.T) {
		server, emulator := key(t, 4), key(t, 5)
		legacyTree := covenant.VtxoScript(server, emulator, p.SenderKey, p, legacy)
		recycleTree := covenant.VtxoScript(server, emulator, p.SenderKey, recycleOnly, recycle)
		purchaseTree := covenant.VtxoScript(server, emulator, p.SenderKey, purchaseOnly, purchase)

		require.Len(t, legacyTree.Closures, len(recycleTree.Closures))
		require.Len(t, legacyTree.Closures, len(purchaseTree.Closures))

		legacyKey, _, err := legacyTree.TapTree()
		require.NoError(t, err)
		recycleKey, _, err := recycleTree.TapTree()
		require.NoError(t, err)
		purchaseKey, _, err := purchaseTree.TapTree()
		require.NoError(t, err)
		require.False(t, legacyKey.IsEqual(recycleKey), "a committed mode must change the address")
		require.False(t, legacyKey.IsEqual(purchaseKey), "a committed mode must change the address")
		require.False(t, recycleKey.IsEqual(purchaseKey), "the two modes must differ")

		for _, i := range []int{covenant.LeafRefundSender, covenant.LeafRecovery} {
			require.Equal(t, tapleaf(t, legacyTree, i), tapleaf(t, recycleTree, i),
				"leaf %d must be untouched by a claim mode", i)
			require.Equal(t, tapleaf(t, legacyTree, i), tapleaf(t, purchaseTree, i),
				"leaf %d must be untouched by a claim mode", i)
		}
		require.Equal(t, tapleaf(t, legacyTree, covenant.LeafRecycle),
			tapleaf(t, recycleTree, covenant.LeafRecycle))
		require.Equal(t, tapleaf(t, legacyTree, covenant.LeafPurchase),
			tapleaf(t, purchaseTree, covenant.LeafPurchase))
	})

	// The forbidden closure must stay the two-key multisig shape arkd admits.
	t.Run("disabled_closure_keeps_its_shape", func(t *testing.T) {
		server, emulator := key(t, 4), key(t, 5)
		tree := covenant.VtxoScript(server, emulator, p.SenderKey, recycleOnly, recycle)

		raw := tapleaf(t, tree, covenant.LeafPurchase)
		closure, err := script.DecodeClosure(raw)
		require.NoError(t, err)
		decoded, ok := closure.(*script.MultisigClosure)
		require.True(t, ok, "disabled leaf must stay a multisig closure, got %T", closure)
		require.Len(t, decoded.PubKeys, 2)
		require.True(t, decoded.PubKeys[0].IsEqual(server))
		require.True(t, decoded.PubKeys[1].IsEqual(
			arkade.ComputeArkadeScriptPublicKey(emulator, arkade.ArkadeScriptHash(disabledLeafScript())),
		), "the disabled leaf must carry the false-script tweak")
	})

	// Buildable, but the emulator refuses to run the false script.
	t.Run("disabled_claim_script_is_unspendable", func(t *testing.T) {
		receiverPk := p2tr(t, p.ReceiverKey)
		valid := spend{
			prevouts: []*wire.TxOut{
				{Value: dust, PkScript: p2tr(t, key(t, 9))},
				{Value: dust, PkScript: receiverPk},
			},
			outputs: []*wire.TxOut{
				{Value: p.Topup, PkScript: p2tr(t, p.OperatorKey)},
				{Value: dust, PkScript: receiverPk},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 1, 1: 20},
				map[uint16]uint64{1: 21},
			),
		}

		require.NoError(t, run(t, recycle.Recycle, valid),
			"the permitted claim path must still be satisfiable")
		requireRejected(t, run(t, disabledLeafScript(), valid))
	})
}

// receiverParams is the already-settled delivery variant.
func receiverParams(t *testing.T, withAsset bool) covenant.Params {
	t.Helper()
	p := params(t, withAsset)
	p.RecoveryRecipient = covenant.RecoveryReceiver
	return p
}

func TestRecoveryRecipient(t *testing.T) {
	t.Run("empty_and_sender_recipients_are_legacy", func(t *testing.T) {
		p := params(t, true)
		legacy, err := covenant.Build(p, minAmount)
		require.NoError(t, err)

		sender := p
		sender.RecoveryRecipient = covenant.RecoverySender
		senderScripts, err := covenant.Build(sender, minAmount)
		require.NoError(t, err)
		require.Equal(t, hex.EncodeToString(legacy.Refund), hex.EncodeToString(senderScripts.Refund))
		require.Equal(t, hex.EncodeToString(legacy.Recycle), hex.EncodeToString(senderScripts.Recycle))
		require.Equal(t, hex.EncodeToString(legacy.Purchase), hex.EncodeToString(senderScripts.Purchase))
	})

	// The receiver must outrank the sender on every recovery leaf.
	t.Run("pays_the_receiver_on_every_recovery_leaf", func(t *testing.T) {
		p := receiverParams(t, true)
		s, err := covenant.Build(p, minAmount)
		require.NoError(t, err)

		topup := p.RefundTopup(minAmount)
		valid := spend{
			prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
			outputs: []*wire.TxOut{
				{Value: topup, PkScript: subDust(t, p.OperatorKey)},
				{Value: dust - topup, PkScript: subDust(t, p.ReceiverKey)},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
			),
		}

		require.NoError(t, run(t, s.Refund, valid), "refund must pay the receiver")

		// Only vout 1 is rewritten, isolating the recipient key.
		paying := func(k *btcec.PublicKey) spend {
			c := valid.clone()
			c.outputs[1].PkScript = subDust(t, k)
			return c
		}
		// The signed refund leaf must never pay the seller.
		requireRejected(t, run(t, s.Refund, paying(p.SenderKey)))
		requireRejected(t, run(t, s.Refund, paying(p.OperatorKey)))
	})

	// The script, not the CLTV, must be what rejects a sender-shaped refund.
	t.Run("old_sender_refund_rejects_under_both_recovery_scripts", func(t *testing.T) {
		p := receiverParams(t, true)
		p.ReclaimLocktime = p.Locktime + 100_000
		s, err := covenant.Build(p, minAmount)
		require.NoError(t, err)
		require.NotNil(t, s.Reclaim)

		topup := p.RefundTopup(minAmount)
		senderShaped := spend{
			prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
			outputs: []*wire.TxOut{
				{Value: topup, PkScript: subDust(t, p.OperatorKey)},
				{Value: dust - topup, PkScript: subDust(t, p.SenderKey)},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
			),
		}

		// The signed refund leaf and the CLTV recovery leaf share one program
		// here, so a rejected sender payout covers both paths at once.
		require.Equal(t, hex.EncodeToString(s.Refund), hex.EncodeToString(s.Reclaim),
			"receiver recovery makes the refund and reclaim programs identical")
		requireRejected(t, run(t, s.Refund, senderShaped))
		requireRejected(t, run(t, s.Reclaim, senderShaped))
	})

	// The operator cannot take the receipt's host sat, and the receipt must
	// carry the asset.
	t.Run("rejects_wrong_operator_amount_and_missing_asset", func(t *testing.T) {
		p := receiverParams(t, true)
		s, err := covenant.Build(p, minAmount)
		require.NoError(t, err)

		topup := p.RefundTopup(minAmount)
		valid := spend{
			prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
			outputs: []*wire.TxOut{
				{Value: topup, PkScript: subDust(t, p.OperatorKey)},
				{Value: dust - topup, PkScript: subDust(t, p.ReceiverKey)},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
			),
		}
		require.NoError(t, run(t, s.Refund, valid))

		t.Run("operator_above_its_carrier", func(t *testing.T) {
			c := valid.clone()
			c.outputs[0].Value = topup + 1
			requireRejected(t, run(t, s.Refund, c))
		})

		t.Run("operator_key_wrong", func(t *testing.T) {
			c := valid.clone()
			c.outputs[0].PkScript = subDust(t, key(t, 7))
			requireRejected(t, run(t, s.Refund, c))
		})

		t.Run("no_asset_packet", func(t *testing.T) {
			c := valid.clone()
			c.packet = nil
			// The lookup cannot run without a packet, so the script aborts rather
			// than evaluating false. Asserting that is the point: the asset clause
			// must not be skippable.
			err := run(t, s.Refund, c)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no asset packet")
		})

		t.Run("foreign_asset_id", func(t *testing.T) {
			c := valid.clone()
			c.packet = packetOf(t, assetID(7),
				map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
			)
			requireRejected(t, run(t, s.Refund, c))
		})
	})

	// Topup == Dust holds one VtxoMinAmount back for the receipt: 329 repaid.
	t.Run("full_dust_topup_recovers_all_but_the_receipt", func(t *testing.T) {
		p := receiverParams(t, true)
		s, err := covenant.Build(p, minAmount)
		require.NoError(t, err)

		require.Equal(t, dust, p.Topup)
		require.Equal(t, dust-minAmount, p.RefundTopup(minAmount))
		require.Equal(t, minAmount, p.UnrecoveredTopup(minAmount))

		topup := p.RefundTopup(minAmount)
		paid := spend{
			prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
			outputs: []*wire.TxOut{
				{Value: topup, PkScript: subDust(t, p.OperatorKey)},
				{Value: minAmount, PkScript: subDust(t, p.ReceiverKey)},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
			),
		}
		require.NoError(t, run(t, s.Refund, paid))

		// Claiming all 330 would strand the hosted asset below arkd's minimum.
		requireRejected(t, run(t, s.Refund, spend{
			prevouts: paid.prevouts,
			outputs: []*wire.TxOut{
				{Value: dust, PkScript: subDust(t, p.OperatorKey)},
				{Value: 0, PkScript: subDust(t, p.ReceiverKey)},
			},
			packet: paid.packet,
		}))
	})

	// A partially funded carrier leaves nothing to hold back.
	t.Run("partial_topup_recovers_whole", func(t *testing.T) {
		p := receiverParams(t, true)
		p.Topup = dust - 50
		s, err := covenant.Build(p, minAmount)
		require.NoError(t, err)

		require.Equal(t, dust-50, p.RefundTopup(minAmount))
		require.Zero(t, p.UnrecoveredTopup(minAmount), "the whole advance comes back")

		topup := p.RefundTopup(minAmount)
		valid := spend{
			prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
			outputs: []*wire.TxOut{
				{Value: topup, PkScript: subDust(t, p.OperatorKey)},
				{Value: dust - topup, PkScript: subDust(t, p.ReceiverKey)},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
			),
		}
		require.NoError(t, run(t, s.Refund, valid))
		require.Equal(t, dust-50, valid.outputs[0].Value, "no sat is held back")
	})

	// Repaid whole, yet the receipt still needs its own VtxoMinAmount: the
	// shortfall and the receipt are separate numbers.
	t.Run("precharged_loan_repays_whole_and_still_hosts_a_receipt", func(t *testing.T) {
		p := receiverParams(t, true)
		p.Topup = dust - minAmount
		s, err := covenant.Build(p, minAmount)
		require.NoError(t, err)

		require.Zero(t, p.UnrecoveredTopup(minAmount))
		require.Equal(t, minAmount, p.Dust-p.RefundTopup(minAmount))

		topup := p.RefundTopup(minAmount)
		require.Equal(t, dust-minAmount, topup)
		valid := spend{
			prevouts: []*wire.TxOut{{Value: dust, PkScript: p2tr(t, key(t, 9))}},
			outputs: []*wire.TxOut{
				{Value: topup, PkScript: subDust(t, p.OperatorKey)},
				{Value: minAmount, PkScript: subDust(t, p.ReceiverKey)},
			},
			packet: packetOf(t, *p.AssetID,
				map[uint16]uint64{0: 7}, map[uint16]uint64{1: 7},
			),
		}
		require.NoError(t, run(t, s.Refund, valid))
		require.Equal(t, topup, valid.outputs[0].Value, "the loan is repaid in full")
		require.Equal(t, minAmount, valid.outputs[1].Value,
			"the receipt is still hosted, though no principal was held back")
	})
}
