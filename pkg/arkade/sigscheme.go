package arkade

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type sigScheme uint8

const (
	schemeSchnorrSecp256k1 sigScheme = iota
	schemeECDSASecp256k1
	schemeECDSASecp256r1
)

const (
	extPubKeyECDSASecp256k1 = 0x10
	extPubKeyECDSASecp256r1 = 0x11
)

type schemeKey struct {
	scheme  sigScheme
	secpPub *btcec.PublicKey
	nistPub *ecdsa.PublicKey
}

// parseSchemePubKey keeps legacy 32-byte x-only keys as Schnorr/secp256k1 and
// uses one-byte prefixes for extended ECDSA keys.
func parseSchemePubKey(pkBytes []byte) (*schemeKey, error) {
	if len(pkBytes) == 0 {
		return nil, scriptError(txscript.ErrTaprootPubkeyIsEmpty, "")
	}

	if len(pkBytes) == 32 {
		pk, err := schnorr.ParsePubKey(pkBytes)
		if err != nil {
			return nil, err
		}
		return &schemeKey{scheme: schemeSchnorrSecp256k1, secpPub: pk}, nil
	}

	prefix := pkBytes[0]
	key := pkBytes[1:]

	if len(key) != 33 {
		return nil, scriptError(txscript.ErrDiscourageUpgradeablePubKeyType,
			"unsupported pubkey scheme")
	}

	switch prefix {
	case extPubKeyECDSASecp256k1:
		pk, err := secp.ParsePubKey(key)
		if err != nil {
			return nil, scriptError(txscript.ErrInvalidStackOperation,
				"invalid secp256k1 ecdsa pubkey")
		}
		return &schemeKey{scheme: schemeECDSASecp256k1, secpPub: pk}, nil

	case extPubKeyECDSASecp256r1:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key)
		if x == nil {
			return nil, scriptError(txscript.ErrInvalidStackOperation,
				"invalid secp256r1 ecdsa pubkey")
		}
		// ecdsa.ParseUncompressedPublicKey avoids constructing PublicKey via
		// deprecated X/Y fields while still accepting compressed stack keys.
		uncompressed := make([]byte, 65)
		uncompressed[0] = 0x04
		x.FillBytes(uncompressed[1:33])
		y.FillBytes(uncompressed[33:65])
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
		if err != nil {
			return nil, scriptError(txscript.ErrInvalidStackOperation,
				"invalid secp256r1 ecdsa pubkey")
		}
		return &schemeKey{scheme: schemeECDSASecp256r1, nistPub: pk}, nil

	default:
		return nil, scriptError(txscript.ErrDiscourageUpgradeablePubKeyType,
			"unsupported pubkey scheme")
	}
}

// verify uses msg directly. For ECDSA that must already be a 32-byte digest;
// the opcode deliberately does not hash stack data for the caller.
func (k *schemeKey) verify(msg, sig []byte) bool {
	switch k.scheme {
	case schemeSchnorrSecp256k1:
		parsed, err := schnorr.ParseSignature(sig)
		if err != nil {
			return false
		}
		return parsed.Verify(msg, k.secpPub)

	case schemeECDSASecp256k1:
		if len(msg) != 32 || len(sig) != 64 {
			return false
		}
		return verifyECDSASecp256k1(k.secpPub, msg, sig)

	case schemeECDSASecp256r1:
		if len(msg) != 32 || len(sig) != 64 {
			return false
		}
		return verifyECDSASecp256r1(k.nistPub, msg, sig)
	}
	return false
}

func verifyECDSASecp256k1(pub *btcec.PublicKey, msg, sig []byte) bool {
	var r, s secp.ModNScalar
	if r.SetByteSlice(sig[:32]) || r.IsZero() {
		return false
	}
	if s.SetByteSlice(sig[32:]) || s.IsZero() {
		return false
	}
	if s.IsOverHalfOrder() {
		return false
	}
	return btcecdsa.NewSignature(&r, &s).Verify(msg, pub)
}

func verifyECDSASecp256r1(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	n := elliptic.P256().Params().N
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		return false
	}
	return ecdsa.Verify(pub, msg, r, s)
}
