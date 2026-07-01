package arkade

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
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
