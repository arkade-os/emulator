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

// sigHashMask defines the number of bits of the hash type which is used
// to identify which outputs are signed.
const sigHashMask = 0x1f

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
//     is computed over a rewritten output stream where every emulator
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
// masking and "ArkadeTapSighash" final tag. Callers should pass the active
// Bitcoin spending tapleaf whose hash the signature commits to.
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

	vm := &Engine{
		tx:             *tx,
		txIdx:          idx,
		hashCache:      sigHashes,
		prevOutFetcher: prevOutFetcher,
		taprootCtx:     newTaprootExecutionCtxForLeaf(tapLeaf),
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
	sigHashMode := hashType & sigHashMask
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
	// map to the emulator-packet OP_RETURN, substitute the masked
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
// emulator packet (there is at most one per tx — extension.IsExtension
// returns on the first match and the extension parser rejects duplicate
// packet types) and returns a copy with every entry's witness blob masked
// out, along with its index in tx.TxOut.
//
// Returns (nil, -1, nil) when there is no such output, when the extension
// fails to parse, or when the extension contains no emulator packet —
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
			ip, err := DeserializeEmulatorPacket(unknown.Data)
			if err != nil {
				return nil, -1, nil
			}
			maskedData, err := serializeEmulatorPacketMasked(ip)
			if err != nil {
				return nil, -1, fmt.Errorf("reserialize masked emulator packet: %w", err)
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
		// Extension present but no emulator packet inside.
		return nil, -1, nil
	}
	return nil, -1, nil
}

// arkadeOutputsHash mirrors BIP342's sha_outputs but substitutes the single
// emulator-packet OP_RETURN (if any) with its witness-masked form before
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

// tapscriptSigVerifier verifies a Schnorr signature against the arkade
// tapscript sighash (see computeArkadeSighash). Arkade is tapscript-only, so
// there is no keyspend code path to abstract over.
type tapscriptSigVerifier struct {
	pubKey  *btcec.PublicKey
	pkBytes []byte

	fullSigBytes []byte
	sig          *schnorr.Signature

	hashType txscript.SigHashType

	vm *Engine
}

// parseTaprootSigAndPubKey parses the 32-byte x-only pubkey and the schnorr
// signature (with optional trailing sighash byte) used by tapscript spends.
func parseTaprootSigAndPubKey(pkBytes, rawSig []byte,
) (*btcec.PublicKey, *schnorr.Signature, txscript.SigHashType, error) {

	pubKey, err := schnorr.ParsePubKey(pkBytes)
	if err != nil {
		return nil, nil, 0, err
	}

	var (
		sig         *schnorr.Signature
		sigHashType txscript.SigHashType
	)
	switch {
	// 64 bytes → implicit SIGHASH_DEFAULT (alias for SIGHASH_ALL).
	case len(rawSig) == schnorr.SignatureSize:
		sig, err = schnorr.ParseSignature(rawSig)
		if err != nil {
			return nil, nil, 0, err
		}
		sigHashType = txscript.SigHashDefault

	// 65 bytes with a non-zero trailing byte → explicit sighash type.
	case len(rawSig) == schnorr.SignatureSize+1 && rawSig[64] != 0:
		sigHashType = txscript.SigHashType(rawSig[schnorr.SignatureSize])
		sig, err = schnorr.ParseSignature(rawSig[:schnorr.SignatureSize])
		if err != nil {
			return nil, nil, 0, err
		}

	default:
		str := fmt.Sprintf("invalid sig len: %v", len(rawSig))
		return nil, nil, 0, scriptError(txscript.ErrInvalidTaprootSigLen, str)
	}

	return pubKey, sig, sigHashType, nil
}

// newTapscriptSigVerifier constructs a verifier for an OP_CHECKSIG /
// OP_CHECKSIGADD input. Rejects empty or non-32-byte pubkeys per BIP342.
func newTapscriptSigVerifier(pkBytes, fullSigBytes []byte,
	vm *Engine) (*tapscriptSigVerifier, error) {

	switch len(pkBytes) {
	case 0:
		return nil, scriptError(txscript.ErrTaprootPubkeyIsEmpty, "")
	case 32:
		// Fall through.
	default:
		str := fmt.Sprintf("pubkey of length %v was used", len(pkBytes))
		return nil, scriptError(
			txscript.ErrDiscourageUpgradeablePubKeyType, str,
		)
	}

	pubKey, sig, hashType, err := parseTaprootSigAndPubKey(pkBytes, fullSigBytes)
	if err != nil {
		return nil, err
	}

	return &tapscriptSigVerifier{
		pubKey:       pubKey,
		pkBytes:      pkBytes,
		sig:          sig,
		fullSigBytes: fullSigBytes,
		hashType:     hashType,
		vm:           vm,
	}, nil
}

// verifySig checks the signature against sigHash, consulting and populating
// the engine's sigCache when present.
func (v *tapscriptSigVerifier) verifySig(sigHash []byte) bool {
	cacheKey, _ := chainhash.NewHash(sigHash)
	if v.vm.sigCache != nil {
		if v.vm.sigCache.Exists(*cacheKey, v.fullSigBytes, v.pkBytes) {
			return true
		}
	}

	if !v.sig.Verify(sigHash, v.pubKey) {
		return false
	}
	if v.vm.sigCache != nil {
		v.vm.sigCache.Add(*cacheKey, v.fullSigBytes, v.pkBytes)
	}
	return true
}

// Verify returns true if the signature is valid under the arkade tapscript
// sighash domain. A sighash-construction error is reported as an invalid
// signature — callers (OP_CHECKSIG, OP_CHECKSIGADD) treat both cases the same.
func (v *tapscriptSigVerifier) Verify() bool {
	sigHash, err := computeArkadeSighash(v.vm, v.hashType)
	if err != nil {
		return false
	}
	return v.verifySig(sigHash)
}
