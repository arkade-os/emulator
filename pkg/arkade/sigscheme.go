package arkade

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// sigAlgo is the high nibble of an extended public key's scheme prefix.
type sigAlgo uint8

const (
	algoSchnorr sigAlgo = 0
	algoECDSA   sigAlgo = 1
)

// schemeKey is a parsed public key tagged with the (algorithm, curve) it must
// be verified under. Exactly one of secpPub / nistPub is populated.
type schemeKey struct {
	algo    sigAlgo
	curve   int64
	secpPub *btcec.PublicKey // secp256k1 (schnorr or ecdsa)
	nistPub *ecdsa.PublicKey // secp256r1 (ecdsa)
}

// parseSchemePubKey resolves a stack public key to its signature scheme.
//
// Dispatch is length-first for backwards compatibility:
//
//	len == 32          -> Schnorr / secp256k1 (legacy x-only, unchanged)
//	0x10 || 33B SEC1   -> ECDSA / secp256k1
//	0x11 || 33B SEC1   -> ECDSA / secp256r1
//
// The prefix packs (algo<<4)|curveID, curveID reusing curveByID. Any other
// prefix or length is a reserved/unknown pubkey type and fails closed with
// ErrDiscourageUpgradeablePubKeyType, preserving the BIP342 upgrade slot.
func parseSchemePubKey(pkBytes []byte) (*schemeKey, error) {
	if len(pkBytes) == 0 {
		return nil, scriptError(txscript.ErrTaprootPubkeyIsEmpty, "")
	}

	// Legacy bare 32-byte x-only key.
	if len(pkBytes) == 32 {
		pk, err := schnorr.ParsePubKey(pkBytes)
		if err != nil {
			return nil, err
		}
		return &schemeKey{algo: algoSchnorr, curve: CurveSecp256k1, secpPub: pk}, nil
	}

	prefix := pkBytes[0]
	algo := sigAlgo(prefix >> 4)
	curveID := int64(prefix & 0x0f)
	key := pkBytes[1:]

	discourage := func() (*schemeKey, error) {
		return nil, scriptError(txscript.ErrDiscourageUpgradeablePubKeyType,
			fmt.Sprintf("unsupported pubkey scheme prefix 0x%02x", prefix))
	}

	// Only ECDSA is implemented in the extended range; Schnorr-extended
	// (incl. reserved 0x00/0x01) and every unknown algo fail closed.
	if algo != algoECDSA || len(key) != 33 {
		return discourage()
	}

	switch curveID {
	case CurveSecp256k1:
		pk, err := secp.ParsePubKey(key)
		if err != nil {
			return nil, scriptError(txscript.ErrInvalidStackOperation,
				"invalid secp256k1 ecdsa pubkey")
		}
		return &schemeKey{algo: algoECDSA, curve: CurveSecp256k1, secpPub: pk}, nil

	case CurveSecp256r1:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key)
		if x == nil {
			return nil, scriptError(txscript.ErrInvalidStackOperation,
				"invalid secp256r1 ecdsa pubkey")
		}
		// Re-expand the validated point to SEC1 uncompressed and parse it with
		// the non-deprecated Go 1.26 constructor (ecdsa.PublicKey.X/Y are
		// deprecated for direct construction).
		uncompressed := make([]byte, 65)
		uncompressed[0] = 0x04
		x.FillBytes(uncompressed[1:33])
		y.FillBytes(uncompressed[33:65])
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
		if err != nil {
			return nil, scriptError(txscript.ErrInvalidStackOperation,
				"invalid secp256r1 ecdsa pubkey")
		}
		return &schemeKey{algo: algoECDSA, curve: CurveSecp256r1, nistPub: pk}, nil

	default:
		return discourage()
	}
}

// verify reports whether sig is a valid signature by k over msg. msg is the
// value each scheme verifies against directly — the arkade sighash for the
// CHECKSIG family, or the popped stack item for CSFS. The opcode never hashes:
// Schnorr folds msg into its BIP340 tagged challenge; ECDSA treats msg as the
// pre-computed digest. sig is a 64-byte compact r||s for both algorithms;
// ECDSA additionally requires canonical, low-s scalars. For ECDSA, msg is
// expected to be a 32-byte digest (the intended input, e.g. via OP_SHA256);
// non-32-byte messages are reduced per each curve library's own rule and are
// not portable across curves.
func (k *schemeKey) verify(msg, sig []byte) bool {
	switch k.algo {
	case algoSchnorr:
		parsed, err := schnorr.ParseSignature(sig)
		if err != nil {
			return false
		}
		return parsed.Verify(msg, k.secpPub)

	case algoECDSA:
		if len(sig) != 64 {
			return false
		}
		switch k.curve {
		case CurveSecp256k1:
			return verifyECDSASecp256k1(k.secpPub, msg, sig)
		case CurveSecp256r1:
			return verifyECDSASecp256r1(k.nistPub, msg, sig)
		}
	}
	return false
}

// verifyECDSASecp256k1 verifies a low-s, canonical 64-byte r||s ECDSA
// signature over secp256k1 with msg as the digest.
func verifyECDSASecp256k1(pub *btcec.PublicKey, msg, sig []byte) bool {
	var r, s secp.ModNScalar
	if r.SetByteSlice(sig[:32]) || r.IsZero() { // overflow-or-zero => invalid
		return false
	}
	if s.SetByteSlice(sig[32:]) || s.IsZero() {
		return false
	}
	if s.IsOverHalfOrder() { // reject high-s (malleable)
		return false
	}
	return btcecdsa.NewSignature(&r, &s).Verify(msg, pub)
}

// verifyECDSASecp256r1 verifies a low-s, canonical 64-byte r||s ECDSA
// signature over secp256r1 (NIST P-256) with msg as the digest.
func verifyECDSASecp256r1(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	n := elliptic.P256().Params().N
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 { // reject high-s (malleable)
		return false
	}
	return ecdsa.Verify(pub, msg, r, s)
}
