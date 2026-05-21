package arkade

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// isValidTaprootSigHash mirrors btcd's unexported isValidTaprootSigHash so that
// callers (e.g. OP_SIGHASH) can pre-validate a hashType byte before invoking
// btcd's sighash routines.
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

// computeTapscriptSighash returns the 32-byte BIP342 tapscript signature hash
// for the engine's currently executing input under the given hashType.
//
// The engine MUST be in a tapscript execution context (vm.taprootCtx != nil
// with a populated tapLeaf). The annex (if present) and the current code
// separator position are folded into the digest, matching how a signature
// produced by signing this leaf would be validated.
func computeTapscriptSighash(vm *Engine,
	hashType txscript.SigHashType) ([]byte, error) {

	if vm.taprootCtx == nil {
		return nil, fmt.Errorf("tapscript sighash requested outside " +
			"of a tapscript execution context")
	}

	// Override the default blank codesep value installed by
	// CalcTapscriptSignaturehash so that any OP_CODESEPARATOR run earlier
	// in this script is committed to.
	leafHash := vm.taprootCtx.tapLeafHash
	opts := []txscript.TaprootSigHashOption{
		txscript.WithBaseTapscriptVersion(
			vm.taprootCtx.codeSepPos, leafHash[:],
		),
	}
	if len(vm.taprootCtx.annex) > 0 {
		opts = append(opts, txscript.WithAnnex(vm.taprootCtx.annex))
	}

	return txscript.CalcTapscriptSignaturehash(
		vm.hashCache, hashType, &vm.tx, vm.txIdx, vm.prevOutFetcher,
		vm.taprootCtx.tapLeaf, opts...,
	)
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
	// Compute the proper BIP342 tapscript sighash via the shared helper so
	// that OP_CHECKSIG and OP_SIGHASH agree on the signed message.
	sigHash, err := computeTapscriptSighash(b.vm, b.hashType)
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
