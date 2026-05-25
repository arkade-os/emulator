package arkade

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// arkadeSighashTag is the BIP-340 tagged-hash tag used for the arkade VM's
// non-standard tapscript signature hash. It is intentionally distinct from
// chainhash.TagTapSighash (the BIP342 tag, "TapSighash") so the arkade digest
// domain is cryptographically separated from the Bitcoin digest domain: a
// signature valid under one can never pass verification under the other,
// regardless of message content.
var arkadeSighashTag = []byte("ArkadeTapSighash")

// isValidTaprootSigHash mirrors btcd's unexported isValidTaprootSigHash so that
// callers (e.g. OP_SIGHASH) can pre-validate a hashType byte before invoking
// the digest routine.
func isValidTaprootSigHash(hashType txscript.SigHashType) bool {
	switch hashType {
	case txscript.SigHashDefault, txscript.SigHashAll,
		txscript.SigHashNone, txscript.SigHashSingle:
		return true
	case 0x81, 0x82, 0x83:
		return true
	default:
		return false
	}
}

// computeArkadeSighash returns the 32-byte non-standard tapscript signature
// hash that OP_SIGHASH pushes and that the arkade VM's OP_CHECKSIG verifies
// against.
//
// The byte layout fed into the final tagged hash mirrors BIP342's sigMsg
// exactly, with two deliberate departures:
//
//  1. The sha_outputs digest (and the per-output digest used by SIGHASH_SINGLE)
//     is computed over a rewritten output stream where every introspector
//     packet entry's witness blob is omitted (witness_len = 0). Script bytes,
//     vin ordering, entry count, co-located ARK extension packets (asset
//     packet etc.), and every non-extension output pass through unchanged.
//
//  2. The final tagged hash uses arkadeSighashTag ("ArkadeTapSighash"), not
//     chainhash.TagTapSighash. The digest space is therefore disjoint from
//     BIP342's; this is the cryptographic signal that we are operating in a
//     non-standard sighash domain.
//
// The engine MUST be in a tapscript execution context (vm.taprootCtx != nil
// with a populated tapLeaf). The annex (if present) and the current code
// separator position are folded into the digest.
func computeArkadeSighash(vm *Engine,
	hashType txscript.SigHashType) ([]byte, error) {

	sigMsg, err := buildArkadeSigMsg(vm, hashType)
	if err != nil {
		return nil, err
	}
	digest := chainhash.TaggedHash(arkadeSighashTag, sigMsg)
	return digest[:], nil
}

// CalcTapscriptSignaturehash returns the non-standard arkade tapscript
// signature hash used by OP_CHECKSIG and OP_SIGHASH inside arkade scripts.
//
// The byte layout mirrors BIP342's tapscript sigMsg with arkade's witness
// masking and "ArkadeTapSighash" final tag. Callers should pass the tap leaf
// for the arkade script being signed.
func CalcTapscriptSignaturehash(
	sigHashes *txscript.TxSigHashes,
	hashType txscript.SigHashType,
	tx *wire.MsgTx,
	idx int,
	prevOutFetcher ArkPrevOutFetcher,
	tapLeaf txscript.TapLeaf,
) ([]byte, error) {
	if sigHashes == nil {
		return nil, fmt.Errorf("nil sighash cache")
	}
	if tx == nil {
		return nil, fmt.Errorf("nil transaction")
	}
	if prevOutFetcher == nil {
		return nil, fmt.Errorf("nil prevout fetcher")
	}

	tapLeafHash := tapLeaf.TapHash()
	vm := &Engine{
		tx:             *tx,
		txIdx:          idx,
		hashCache:      sigHashes,
		prevOutFetcher: prevOutFetcher,
		taprootCtx: &taprootExecutionCtx{
			tapLeaf:     tapLeaf,
			tapLeafHash: tapLeafHash,
			codeSepPos:  blankCodeSepValue,
		},
	}

	return computeArkadeSighash(vm, hashType)
}

// buildArkadeSigMsg returns the inner sigMsg byte stream that
// computeArkadeSighash feeds into the final BIP-340 tagged hash. Exposing this
// step lets tests cross-check the byte layout against btcd's BIP342
// implementation by wrapping our sigMsg with chainhash.TagTapSighash and
// comparing to txscript.CalcTapscriptSignaturehash over the witness-masked
// transaction — proving the only deliberate departures from BIP342 are the
// witness masking and the tag.
func buildArkadeSigMsg(vm *Engine, hashType txscript.SigHashType) ([]byte, error) {
	if vm.taprootCtx == nil {
		return nil, fmt.Errorf("tapscript sighash requested outside " +
			"of a tapscript execution context")
	}
	if !isValidTaprootSigHash(hashType) {
		return nil, fmt.Errorf("invalid taproot sighash type: 0x%02x",
			byte(hashType))
	}
	if vm.txIdx < 0 || vm.txIdx >= len(vm.tx.TxIn) {
		return nil, fmt.Errorf("input index %d out of range [0, %d)",
			vm.txIdx, len(vm.tx.TxIn))
	}

	tx := &vm.tx
	idx := vm.txIdx
	hashCache := vm.hashCache

	var sigMsg bytes.Buffer

	// 1. Epoch byte (BIP341 §3.1) — must be present inside the inner hash.
	sigMsg.WriteByte(0x00)

	// 2. hash_type.
	sigMsg.WriteByte(byte(hashType))

	// 3. nVersion, nLockTime.
	if err := binary.Write(&sigMsg, binary.LittleEndian, tx.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&sigMsg, binary.LittleEndian, tx.LockTime); err != nil {
		return nil, err
	}

	// 4. Cross-input midstates, unless ANYONECANPAY drops them.
	anyoneCanPay := hashType&txscript.SigHashAnyOneCanPay == txscript.SigHashAnyOneCanPay
	if !anyoneCanPay {
		sigMsg.Write(hashCache.HashPrevOutsV1[:])
		sigMsg.Write(hashCache.HashInputAmountsV1[:])
		sigMsg.Write(hashCache.HashInputScriptsV1[:])
		sigMsg.Write(hashCache.HashSequenceV1[:])
	}

	// 5. sha_outputs, unless SIGHASH_SINGLE or SIGHASH_NONE drop it. The
	// SINGLE-specific per-output digest goes in further below.
	sigHashMode := hashType & 0x03
	if sigHashMode != txscript.SigHashSingle && sigHashMode != txscript.SigHashNone {
		outputsHash, err := arkadeOutputsHash(tx)
		if err != nil {
			return nil, fmt.Errorf("arkade sha_outputs: %w", err)
		}
		sigMsg.Write(outputsHash)
	}

	// 6. spend_type = 2*ext_flag + annex_present. ext_flag is always 1 in
	// our tapscript-only engine.
	spendType := byte(2)
	hasAnnex := len(vm.taprootCtx.annex) > 0
	if hasAnnex {
		spendType = 3
	}
	sigMsg.WriteByte(spendType)

	// 7. Per-input data.
	input := tx.TxIn[idx]
	if anyoneCanPay {
		if err := wire.WriteOutPoint(&sigMsg, 0, 0, &input.PreviousOutPoint); err != nil {
			return nil, err
		}
		prevOut := vm.prevOutFetcher.FetchPrevOutput(input.PreviousOutPoint)
		if prevOut == nil {
			return nil, fmt.Errorf("no prevout for input %d", idx)
		}
		if err := wire.WriteTxOut(&sigMsg, 0, 0, prevOut); err != nil {
			return nil, err
		}
		if err := binary.Write(&sigMsg, binary.LittleEndian, input.Sequence); err != nil {
			return nil, err
		}
	} else {
		if err := binary.Write(&sigMsg, binary.LittleEndian, uint32(idx)); err != nil {
			return nil, err
		}
	}

	// 8. Annex hash, if present.
	if hasAnnex {
		var annexBuf bytes.Buffer
		if err := wire.WriteVarBytes(&annexBuf, 0, vm.taprootCtx.annex); err != nil {
			return nil, err
		}
		annexHash := sha256.Sum256(annexBuf.Bytes())
		sigMsg.Write(annexHash[:])
	}

	// 9. SIGHASH_SINGLE per-output digest. If the input index happens to
	// map to the introspector-packet OP_RETURN, substitute the masked
	// version so the digest stays witness-blob-independent.
	if sigHashMode == txscript.SigHashSingle {
		if idx >= len(tx.TxOut) {
			return nil, fmt.Errorf("SIGHASH_SINGLE: no output at input index %d", idx)
		}
		out := tx.TxOut[idx]
		masked, maskedIdx, err := maskExtensionOutput(tx)
		if err != nil {
			return nil, fmt.Errorf("arkade single-output rewrite: %w", err)
		}
		if maskedIdx == idx {
			out = masked
		}
		h := sha256.New()
		if err := wire.WriteTxOut(h, 0, 0, out); err != nil {
			return nil, err
		}
		sigMsg.Write(h.Sum(nil))
	}

	// 10. BIP342 tapscript extension (ext_flag = 1).
	leafHash := vm.taprootCtx.tapLeafHash
	sigMsg.Write(leafHash[:])
	sigMsg.WriteByte(0x00) // key_version, always 0 for base leaf version.
	if err := binary.Write(&sigMsg, binary.LittleEndian, vm.taprootCtx.codeSepPos); err != nil {
		return nil, err
	}

	return sigMsg.Bytes(), nil
}

// maskExtensionOutput finds the single OP_RETURN output carrying an
// introspector packet (there is at most one per tx — extension.IsExtension
// returns on the first match and the extension parser rejects duplicate
// packet types) and returns a copy with every entry's witness blob masked
// out, along with its index in tx.TxOut.
//
// Returns (nil, -1, nil) when there is no such output, when the extension
// fails to parse, or when the extension contains no introspector packet —
// masking is fail-open at any parsing boundary so a corrupted OP_RETURN
// cannot disable digest computation.
func maskExtensionOutput(tx *wire.MsgTx) (*wire.TxOut, int, error) {
	for i, out := range tx.TxOut {
		if out == nil || !extension.IsExtension(out.PkScript) {
			continue
		}
		// First (and effectively only) extension OP_RETURN found.
		ext, err := extension.NewExtensionFromBytes(out.PkScript)
		if err != nil {
			return nil, -1, nil
		}
		for j, pkt := range ext {
			if pkt.Type() != PacketType {
				continue
			}
			unknown, ok := pkt.(extension.UnknownPacket)
			if !ok {
				return nil, -1, nil
			}
			ip, err := DeserializeIntrospectorPacket(unknown.Data)
			if err != nil {
				return nil, -1, nil
			}
			maskedData, err := serializeIntrospectorPacketMasked(ip)
			if err != nil {
				return nil, -1, fmt.Errorf("reserialize masked introspector packet: %w", err)
			}
			ext[j] = extension.UnknownPacket{
				PacketType: PacketType,
				Data:       maskedData,
			}
			newScript, err := ext.Serialize()
			if err != nil {
				return nil, -1, fmt.Errorf("reserialize masked extension: %w", err)
			}
			return &wire.TxOut{Value: out.Value, PkScript: newScript}, i, nil
		}
		// Extension present but no introspector packet inside.
		return nil, -1, nil
	}
	return nil, -1, nil
}

// arkadeOutputsHash mirrors BIP342's sha_outputs but substitutes the single
// introspector-packet OP_RETURN (if any) with its witness-masked form before
// hashing. Every other output is hashed exactly as it appears in the tx.
func arkadeOutputsHash(tx *wire.MsgTx) ([]byte, error) {
	masked, maskedIdx, err := maskExtensionOutput(tx)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	for i, out := range tx.TxOut {
		if i == maskedIdx {
			out = masked
		}
		if err := wire.WriteTxOut(h, 0, 0, out); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// signatureVerifier is an abstract interface that allows the op code execution
// to abstract over the _type_ of signature validation being executed.
type signatureVerifier interface {
	// Verify returns whether or not the signature verifier context deems the
	// signature to be valid for the given context.
	Verify() verifyResult
}

type verifyResult struct {
	sigValid bool
}

// taprootSigVerifier verifies signatures according to the segwit v1 rules,
// which are described in BIP 341.
type taprootSigVerifier struct {
	pubKey  *btcec.PublicKey
	pkBytes []byte

	fullSigBytes []byte
	sig          *schnorr.Signature

	hashType txscript.SigHashType

	sigCache  *txscript.SigCache
	hashCache *txscript.TxSigHashes

	tx *wire.MsgTx

	inputIndex int

	annex []byte

	prevOuts txscript.PrevOutputFetcher
}

// parseTaprootSigAndPubKey attempts to parse the public key and signature for
// a taproot spend that may be a keyspend or script path spend. This function
// returns an error if the pubkey is invalid, or the sig is.
func parseTaprootSigAndPubKey(pkBytes, rawSig []byte,
) (*btcec.PublicKey, *schnorr.Signature, txscript.SigHashType, error) {

	// Now that we have the raw key, we'll parse it into a schnorr public
	// key we can work with.
	pubKey, err := schnorr.ParsePubKey(pkBytes)
	if err != nil {
		return nil, nil, 0, err
	}

	// Next, we'll parse the signature, which may or may not be appended
	// with the desired sighash flag.
	var (
		sig         *schnorr.Signature
		sigHashType txscript.SigHashType
	)
	switch {
	// If the signature is exactly 64 bytes, then we know we're using the
	// implicit SIGHASH_DEFAULT sighash type.
	case len(rawSig) == schnorr.SignatureSize:
		// First, parse out the signature which is just the raw sig itself.
		sig, err = schnorr.ParseSignature(rawSig)
		if err != nil {
			return nil, nil, 0, err
		}

		// If the sig is 64 bytes, then we'll assume that it's the
		// default sighash type, which is actually an alias for
		// SIGHASH_ALL.
		sigHashType = txscript.SigHashDefault

	// Otherwise, if this is a signature, with a sighash looking byte
	// appended that isn't all zero, then we'll extract the sighash from
	// the end of the signature.
	case len(rawSig) == schnorr.SignatureSize+1 && rawSig[64] != 0:
		// Extract the sighash type, then snip off the last byte so we can
		// parse the signature.
		sigHashType = txscript.SigHashType(rawSig[schnorr.SignatureSize])

		rawSig = rawSig[:schnorr.SignatureSize]
		sig, err = schnorr.ParseSignature(rawSig)
		if err != nil {
			return nil, nil, 0, err
		}

	// Otherwise, this is an invalid signature, so we need to bail out.
	default:
		str := fmt.Sprintf("invalid sig len: %v", len(rawSig))
		return nil, nil, 0, scriptError(txscript.ErrInvalidTaprootSigLen, str)
	}

	return pubKey, sig, sigHashType, nil
}

// newTaprootSigVerifier returns a new instance of a taproot sig verifier given
// the necessary contextual information.
func newTaprootSigVerifier(pkBytes []byte, fullSigBytes []byte,
	tx *wire.MsgTx, inputIndex int, prevOuts txscript.PrevOutputFetcher,
	sigCache *txscript.SigCache, hashCache *txscript.TxSigHashes,
	annex []byte) (*taprootSigVerifier, error) {

	pubKey, sig, sigHashType, err := parseTaprootSigAndPubKey(
		pkBytes, fullSigBytes,
	)
	if err != nil {
		return nil, err
	}

	return &taprootSigVerifier{
		pubKey:       pubKey,
		pkBytes:      pkBytes,
		sig:          sig,
		fullSigBytes: fullSigBytes,
		hashType:     sigHashType,
		tx:           tx,
		inputIndex:   inputIndex,
		prevOuts:     prevOuts,
		sigCache:     sigCache,
		hashCache:    hashCache,
		annex:        annex,
	}, nil
}

// verifySig attempts to verify a BIP 340 signature using the internal public
// key and signature, and the passed sigHash as the message digest.
func (t *taprootSigVerifier) verifySig(sigHash []byte) bool {
	// At this point, we can check to see if this signature is already
	// included in the sigCache and is valid or not (if one was passed in).
	cacheKey, _ := chainhash.NewHash(sigHash)
	if t.sigCache != nil {
		if t.sigCache.Exists(*cacheKey, t.fullSigBytes, t.pkBytes) {
			return true
		}
	}

	// If we didn't find the entry in the cache, then we'll perform full
	// verification as normal, adding the entry to the cache if it's found
	// to be valid.
	sigValid := t.sig.Verify(sigHash, t.pubKey)
	if sigValid {
		if t.sigCache != nil {
			// The sig is valid, so we'll add it to the cache.
			t.sigCache.Add(*cacheKey, t.fullSigBytes, t.pkBytes)
		}

		return true
	}

	// Otherwise the sig is invalid if we get to this point.
	return false
}

// Verify returns whether or not the signature verifier context deems the
// signature to be valid for the given context.
//
// NOTE: This is part of the signatureVerifier interface.
func (t *taprootSigVerifier) Verify() verifyResult {
	// Before we attempt to verify the signature, we'll need to first
	// compute the sighash based on the input and tx information.
	sigHash, err := txscript.CalcTaprootSignatureHash(
		t.hashCache, t.hashType, t.tx, t.inputIndex, t.prevOuts,
	)
	if err != nil {
		// TODO(roasbeef): propagate the error here?
		return verifyResult{}
	}

	return verifyResult{
		sigValid: t.verifySig(sigHash),
	}
}

// A compile-time assertion to ensure taprootSigVerifier implements the
// signatureVerifier interface.
var _ signatureVerifier = (*taprootSigVerifier)(nil)

// baseTapscriptSigVerifier verifies a signature for an input spending a
// tapscript leaf from the previous output.
type baseTapscriptSigVerifier struct {
	*taprootSigVerifier

	vm *Engine
}

// newBaseTapscriptSigVerifier returns a new sig verifier for tapscript input
// spends. If the public key or signature aren't correctly formatted, an error
// is returned.
func newBaseTapscriptSigVerifier(pkBytes, rawSig []byte,
	vm *Engine) (*baseTapscriptSigVerifier, error) {

	switch len(pkBytes) {
	// If the public key is zero bytes, then this is invalid, and will fail
	// immediately.
	case 0:
		return nil, scriptError(txscript.ErrTaprootPubkeyIsEmpty, "")

	// If the public key is 32 byte as we expect, then we'll parse things
	// as normal.
	case 32:
		baseTaprootVerifier, err := newTaprootSigVerifier(
			pkBytes, rawSig, &vm.tx, vm.txIdx, vm.prevOutFetcher,
			vm.sigCache, vm.hashCache, vm.taprootCtx.annex,
		)
		if err != nil {
			return nil, err
		}

		return &baseTapscriptSigVerifier{
			taprootSigVerifier: baseTaprootVerifier,
			vm:                 vm,
		}, nil

	// Unknown public key type — always reject.
	default:
		str := fmt.Sprintf("pubkey of length %v was used",
			len(pkBytes))
		return nil, scriptError(
			txscript.ErrDiscourageUpgradeablePubKeyType, str,
		)
	}
}

// Verify returns whether or not the signature verifier context deems the
// signature to be valid for the given context.
//
// NOTE: This is part of the signatureVerifier interface.
func (b *baseTapscriptSigVerifier) Verify() verifyResult {
	// Compute the non-standard arkade tapscript sighash via the shared
	// helper so OP_CHECKSIG and OP_SIGHASH agree on the signed message.
	// This is NOT a BIP342 digest — see computeArkadeSighash.
	sigHash, err := computeArkadeSighash(b.vm, b.hashType)
	if err != nil {
		return verifyResult{}
	}

	return verifyResult{
		sigValid: b.verifySig(sigHash),
	}
}

// A compile-time assertion to ensure baseTapscriptSigVerifier implements the
// signatureVerifier interface.
var _ signatureVerifier = (*baseTapscriptSigVerifier)(nil)
