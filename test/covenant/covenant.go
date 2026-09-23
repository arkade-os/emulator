// Package covenant builds the arkade covenants for dust-free asset and
// sub-dust bitcoin transfers, where a service operator fronts the dust unit and
// the covenant guarantees its repayment.
//
// See docs/superpowers/specs/2026-09-07-dust-free-transfer-covenant-design.md.
package covenant

import (
	"crypto/sha256"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// Leaf positions in the taptree. Order fixes the merkle root, so it is part of
// the address and must not be reordered.
const (
	LeafRecycle = iota
	LeafPurchase
	LeafRefundSender
	LeafRecovery
	// Present only when ReclaimLocktime is set.
	LeafReclaim
)

// Params are the values committed at lockup. Together they determine the
// covenant scripts, hence the emulator tweak, hence the taproot output key.
type Params struct {
	ReceiverKey *btcec.PublicKey
	SenderKey   *btcec.PublicKey
	OperatorKey *btcec.PublicKey

	// Dust is the covenant output's value, equal to the Arkade Service's dust
	// setting. Topup is the operator's advance; the sender contributes the
	// remainder, which is zero for a pure-asset payment.
	Dust  int64
	Topup int64

	// AssetID is nil for the bitcoin variant. The asset introspection opcodes
	// raise "no asset packet" rather than returning zero when a transaction
	// carries no asset packet, so the two variants cannot share one script.
	AssetID *asset.AssetId

	Locktime arklib.AbsoluteLocktime

	// Zero omits the backstop leaf: the tree is not fixed-shape.
	ReclaimLocktime arklib.AbsoluteLocktime

	// Who the refund and recovery leaves pay. Empty is RecoverySender;
	// RecoveryReceiver is for a delivery already settled, where refunding the
	// paid seller is the failure being prevented.
	RecoveryRecipient string

	// Forbids one claim leaf. Empty keeps both.
	ClaimMode string

	ReceiverFare *ReceiverFare
}

// ReceiverFare is what the receiver owes the operator at claim, when the operator
// funded the whole dust. Currency "asset" always means Params.AssetID: a second
// asset id here would be a substitution nothing else in the leaf could check.
type ReceiverFare struct {
	Currency string
	Units    int64
}

const (
	RecoverySender   = "sender"
	RecoveryReceiver = "receiver"

	// A claim mode names the one claim leaf left live; the other is disabled.
	ClaimModeRecycle  = "recycle"
	ClaimModePurchase = "purchase"
)

func (p Params) Validate(vtxoMinAmount int64) error {
	switch {
	case p.ReceiverKey == nil || p.SenderKey == nil || p.OperatorKey == nil:
		return fmt.Errorf("covenant: receiver, sender and operator keys are required")
	case p.RecoveryRecipient != "" && p.RecoveryRecipient != RecoverySender &&
		p.RecoveryRecipient != RecoveryReceiver:
		return fmt.Errorf("covenant: unknown recovery recipient %q", p.RecoveryRecipient)
	case p.ClaimMode != "" && p.ClaimMode != ClaimModeRecycle &&
		p.ClaimMode != ClaimModePurchase:
		return fmt.Errorf("covenant: unknown claimMode %q", p.ClaimMode)
	case p.Dust <= 0:
		return fmt.Errorf("covenant: dust must be positive, got %d", p.Dust)
	case vtxoMinAmount <= 0:
		return fmt.Errorf("covenant: vtxoMinAmount must be positive, got %d", vtxoMinAmount)
	case p.Topup < vtxoMinAmount || p.Topup > p.Dust:
		return fmt.Errorf(
			"covenant: topup %d outside [%d, %d]", p.Topup, vtxoMinAmount, p.Dust,
		)
	case p.ReceiverKey.IsEqual(p.OperatorKey) ||
		p.ReceiverKey.IsEqual(p.SenderKey) ||
		p.SenderKey.IsEqual(p.OperatorKey):
		// Reusing a key collapses a role. Receiver == operator is the dangerous
		// one: the operator could satisfy recycle while paying the top-up
		// repayment to itself, collecting both sides of the trade. No signature
		// check catches this, because each role's key is legitimately its own.
		return fmt.Errorf("covenant: receiver, sender and operator keys must be distinct")
	case p.ReclaimLocktime != 0 && p.ReclaimLocktime.IsSeconds() != p.Locktime.IsSeconds():
		// Heights and timestamps do not order against each other.
		return fmt.Errorf(
			"covenant: reclaim locktime %d and locktime %d must both be heights or both be timestamps",
			p.ReclaimLocktime, p.Locktime,
		)
	case p.ReclaimLocktime != 0 && p.ReclaimLocktime <= p.Locktime:
		// Maturing first would let the operator reclaim from under a live claim.
		return fmt.Errorf(
			"covenant: reclaim locktime %d must be after locktime %d",
			p.ReclaimLocktime, p.Locktime,
		)
	case p.Locktime == 0:
		// A zero absolute locktime is always satisfied, which would make the
		// recovery leaf spendable the moment the covenant is funded and collapse
		// the timeout the operator's exposure is bounded by.
		return fmt.Errorf("covenant: locktime must be non-zero")
	case p.ReceiverFare != nil && p.ReceiverFare.Currency != "sats" &&
		p.ReceiverFare.Currency != "asset":
		return fmt.Errorf("covenant: receiver fare currency %q is unknown", p.ReceiverFare.Currency)
	case p.ReceiverFare != nil && p.AssetID == nil:
		return fmt.Errorf("covenant: receiver fare requires an asset id")
	case p.ReceiverFare != nil && p.Topup != p.Dust:
		return fmt.Errorf("covenant: receiver fare requires the operator to fund the whole dust")
	case p.ReceiverFare != nil && p.ClaimMode != ClaimModeRecycle:
		return fmt.Errorf("covenant: receiver fare is only defined for a recycle claim")
	case p.ReceiverFare != nil && p.RecoveryRecipient != RecoveryReceiver:
		return fmt.Errorf("covenant: receiver fare requires receiver-owned recovery")
	case p.ReceiverFare != nil && p.ReceiverFare.Units < 0:
		return fmt.Errorf("covenant: receiver fare units must not be negative")
	case p.RecoveryRecipient == RecoveryReceiver && p.AssetID == nil:
		return fmt.Errorf("covenant: receiver recovery requires an asset id")
	case p.RecoveryRecipient == RecoveryReceiver &&
		p.RefundTopup(vtxoMinAmount) < vtxoMinAmount:
		return fmt.Errorf(
			"covenant: receiver recovery needs at least %d sats to host its receipt", vtxoMinAmount,
		)
	}
	return nil
}

// RefundTopup is what the operator recovers on the refund leaves. It falls below
// Topup only when the operator funded the whole dust unit, where one
// vtxoMinAmount must stay behind to host the sender's returned asset: an asset
// cannot occupy an output on its own.
func (p Params) RefundTopup(vtxoMinAmount int64) int64 {
	if capped := p.Dust - vtxoMinAmount; p.Topup > capped {
		return capped
	}
	return p.Topup
}

// UnrecoveredTopup is Topup - RefundTopup(vtxoMinAmount): the carrier principal
// the refund leaves never return. A quote must reserve it before promising a
// whole carrier back. Distinct from the receipt's own value (Dust-RefundTopup),
// which stays non-zero even when this is zero.
func (p Params) UnrecoveredTopup(vtxoMinAmount int64) int64 {
	return p.Topup - p.RefundTopup(vtxoMinAmount)
}

// PayoutPkScript is the scriptPubKey a covenant-pinned payout must use: P2TR at
// or above dust, sub-dust OP_RETURN below it. It must agree with pinOutput, or
// the covenant rejects its own intended spend.
func PayoutPkScript(key *btcec.PublicKey, value, dust int64) ([]byte, error) {
	if value >= dust {
		return script.P2TRScript(key)
	}
	return script.SubDustScript(key)
}

// pinOutput binds an output to a key. pushScriptPubKey reports a witness program
// as (program, version) but anything else as (sha256(script), -1), so a
// below-dust output must be pinned in its sub-dust OP_RETURN form.
func pinOutput(
	b *txscript.ScriptBuilder, vout int64, key *btcec.PublicKey, value, dust int64,
) error {
	b.AddInt64(vout).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY)
	if value >= dust {
		b.AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
			AddData(schnorr.SerializePubKey(key)).AddOp(arkade.OP_EQUALVERIFY)
		return nil
	}
	subDust, err := script.SubDustScript(key)
	if err != nil {
		return err
	}
	h := sha256.Sum256(subDust)
	b.AddInt64(-1).AddOp(arkade.OP_EQUALVERIFY).AddData(h[:]).AddOp(arkade.OP_EQUALVERIFY)
	return nil
}

// appendAssetLookup leaves the asset amount on the stack and consumes the found
// flag. id.Txid must be in chainhash internal byte order, never the reversed
// display hex.
//
// required decides how the flag is consumed, and the distinction is load-bearing.
// A miss pushes (0, 0). Dropping the flag everywhere makes a wrong AssetID --
// whether from a byte-order slip or a deliberate substitution -- miss on every
// read, degenerating the sum to 0 == 0 + 0 so the covenant passes with the asset
// constraint silently unenforced. OP_VERIFY where the asset must exist turns
// that quiet failure into a loud one. Only the receiver's prior balance may
// legitimately be absent, so only that lookup drops.
func appendAssetLookup(
	b *txscript.ScriptBuilder, idx int64, id *asset.AssetId, output, required bool,
) {
	op := byte(arkade.OP_INSPECTINASSETLOOKUP)
	if output {
		op = byte(arkade.OP_INSPECTOUTASSETLOOKUP)
	}
	b.AddInt64(idx).AddData(id.Txid[:]).AddInt64(int64(id.Index)).AddOp(op)
	if required {
		b.AddOp(arkade.OP_VERIFY)
		return
	}
	b.AddOp(arkade.OP_DROP)
}

func finish(b *txscript.ScriptBuilder, hasAsset bool) ([]byte, error) {
	if !hasAsset {
		b.AddOp(arkade.OP_1)
	}
	return b.Script()
}

// BuildRecycle gates the receiver merging the covenant into an account they
// already own, repaying the operator's advance in sats.
//
//	in[0] covenant, in[1] receiver account
//	out[0] operator repaid Topup, out[1] receiver's merged account
//
// Output value is enforced as a sum over both inputs rather than as a constant,
// so the receiver's prior balance is irrelevant.
func BuildRecycle(p Params) ([]byte, error) {
	operatorSats := p.Topup
	assetFare := int64(0)
	if f := p.ReceiverFare; f != nil {
		if f.Currency == "sats" {
			operatorSats += f.Units
		} else {
			assetFare = f.Units
		}
	}

	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTNUMINPUTS).AddInt64(2).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(p.ReceiverKey)).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(operatorSats).AddOp(arkade.OP_EQUALVERIFY)

	if err := pinOutput(b, 0, p.OperatorKey, operatorSats, p.Dust); err != nil {
		return nil, err
	}

	b.AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(p.ReceiverKey)).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(0).AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddInt64(1).AddOp(arkade.OP_INSPECTINPUTVALUE).AddOp(arkade.OP_ADD).
		AddInt64(operatorSats).AddOp(arkade.OP_SUB).
		AddOp(arkade.OP_EQUALVERIFY)

	if p.AssetID != nil {
		if assetFare > 0 {
			appendAssetLookup(b, 0, p.AssetID, true, true)
			b.AddInt64(assetFare).AddOp(arkade.OP_EQUALVERIFY)
		}
		appendAssetLookup(b, 1, p.AssetID, true, true)
		appendAssetLookup(b, 0, p.AssetID, false, true)
		appendAssetLookup(b, 1, p.AssetID, false, false)
		b.AddOp(arkade.OP_ADD)
		if assetFare > 0 {
			b.AddInt64(assetFare).AddOp(arkade.OP_SUB)
		}
		b.AddOp(arkade.OP_EQUAL)
	}
	return finish(b, p.AssetID != nil)
}

// BuildPurchase pays the whole covenant to the receiver. The operator recovers
// nothing, having been compensated at lockup.
//
// Unlike BuildRecycle this deliberately does not pin the input count. It reads
// only in[0], and out[0] is tied to in[0]'s value and asset amount, so an extra
// input cannot divert the covenant -- whatever a spender adds flows to their own
// outputs. Recycle needs the guard because it reads a second input.
func BuildPurchase(p Params) ([]byte, error) {
	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(p.ReceiverKey)).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(0).AddOp(arkade.OP_INSPECTINPUTVALUE).AddOp(arkade.OP_EQUALVERIFY)

	if p.AssetID != nil {
		appendAssetLookup(b, 0, p.AssetID, true, true)
		appendAssetLookup(b, 0, p.AssetID, false, true)
		b.AddOp(arkade.OP_EQUAL)
	}
	return finish(b, p.AssetID != nil)
}

// BuildRefund returns the payload to the sender and repays the operator. Shared
// by the sender-signed refund leaf and the timelocked recovery leaf. The sender
// receives a sub-dust receipt, acceptable because the sender demonstrably owns a
// funded account and can merge it later; it would not be acceptable for the
// receiver, which is why no claim leaf pays sub-dust.
//
// Delegates to BuildReclaim when RecoveryRecipient is RecoveryReceiver.
func BuildRefund(p Params, vtxoMinAmount int64) ([]byte, error) {
	if p.RecoveryRecipient == RecoveryReceiver {
		return BuildReclaim(p, vtxoMinAmount)
	}
	topup := p.RefundTopup(vtxoMinAmount)
	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(topup).AddOp(arkade.OP_EQUALVERIFY)

	if err := pinOutput(b, 0, p.OperatorKey, topup, p.Dust); err != nil {
		return nil, err
	}

	b.AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(p.Dust - topup).AddOp(arkade.OP_EQUALVERIFY)

	if err := pinOutput(b, 1, p.SenderKey, p.Dust-topup, p.Dust); err != nil {
		return nil, err
	}

	if p.AssetID != nil {
		appendAssetLookup(b, 1, p.AssetID, true, true)
		appendAssetLookup(b, 0, p.AssetID, false, true)
		b.AddOp(arkade.OP_EQUAL)
	}
	return finish(b, p.AssetID != nil)
}

// BuildReclaim is the post-claim backstop: the operator recovers its carrier
// sats, the receiver keeps the asset on a hosted receipt. Same split as
// BuildRefund but paid to the receiver -- refunding post-claim would return the
// asset to an already-paid sender.
func BuildReclaim(p Params, vtxoMinAmount int64) ([]byte, error) {
	topup := p.RefundTopup(vtxoMinAmount)
	b := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(topup).AddOp(arkade.OP_EQUALVERIFY)

	if err := pinOutput(b, 0, p.OperatorKey, topup, p.Dust); err != nil {
		return nil, err
	}

	b.AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(p.Dust - topup).AddOp(arkade.OP_EQUALVERIFY)

	if err := pinOutput(b, 1, p.ReceiverKey, p.Dust-topup, p.Dust); err != nil {
		return nil, err
	}

	if p.AssetID != nil {
		appendAssetLookup(b, 1, p.AssetID, true, true)
		appendAssetLookup(b, 0, p.AssetID, false, true)
		b.AddOp(arkade.OP_EQUAL)
	}
	return finish(b, p.AssetID != nil)
}

type Scripts struct {
	Recycle  []byte
	Purchase []byte
	Refund   []byte
	Reclaim  []byte
}

// disableLeafScript is the payload whose emulator tweak makes a claim leaf
// unspendable. A bare OP_FALSE cannot be a tapscript leaf -- arkd does not admit
// that shape -- so the leaf keeps its multisig closure and only the co-signer
// moves. The mode is committed in VtxoScript; Build returns the live programs.
func disableLeafScript() []byte {
	return []byte{arkade.OP_FALSE}
}

func Build(p Params, vtxoMinAmount int64) (Scripts, error) {
	if err := p.Validate(vtxoMinAmount); err != nil {
		return Scripts{}, err
	}
	recycle, err := BuildRecycle(p)
	if err != nil {
		return Scripts{}, err
	}
	purchase, err := BuildPurchase(p)
	if err != nil {
		return Scripts{}, err
	}
	refund, err := BuildRefund(p, vtxoMinAmount)
	if err != nil {
		return Scripts{}, err
	}
	out := Scripts{Recycle: recycle, Purchase: purchase, Refund: refund}
	if p.ReclaimLocktime != 0 {
		if out.Reclaim, err = BuildReclaim(p, vtxoMinAmount); err != nil {
			return Scripts{}, err
		}
	}
	return out, nil
}

// VtxoScript assembles the four-leaf taptree. Every leaf but LeafRefundSender is
// arkade-only, so anyone able to construct a satisfying transaction may spend it
// -- that is what lets the receiver stay offline at payment time.
func VtxoScript(
	server, emulator, sender *btcec.PublicKey, p Params, s Scripts,
) script.TapscriptsVtxoScript {
	tweak := func(b []byte) *btcec.PublicKey {
		return arkade.ComputeArkadeScriptPublicKey(emulator, arkade.ArkadeScriptHash(b))
	}
	// A forbidden claim leaf keeps its index and sibling positions.
	claimKey := func(leaf int, live []byte) *btcec.PublicKey {
		disabled := (p.ClaimMode == ClaimModeRecycle && leaf == LeafPurchase) ||
			(p.ClaimMode == ClaimModePurchase && leaf == LeafRecycle)
		if disabled {
			return tweak(disableLeafScript())
		}
		return tweak(live)
	}
	v := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{server, claimKey(LeafRecycle, s.Recycle)},
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{server, claimKey(LeafPurchase, s.Purchase)},
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{server, sender, tweak(s.Refund)},
			},
			&script.CLTVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{server, tweak(s.Refund)},
				},
				Locktime: p.Locktime,
			},
		},
	}
	if s.Reclaim != nil {
		// Without the sender: unreachable by whoever was already paid.
		v.Closures = append(v.Closures, &script.CLTVMultisigClosure{
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{server, tweak(s.Reclaim)},
			},
			Locktime: p.ReclaimLocktime,
		})
	}
	return v
}
