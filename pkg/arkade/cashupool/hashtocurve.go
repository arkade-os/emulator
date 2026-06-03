// Package cashupool is an off-chain Go reference library for the Cashu
// nullifier-pool proof-of-concept.  It is the source of truth for the
// in-script Cashu verifier implemented in Arkade Script.
package cashupool

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// DomainSeparator is the NUT-00 hash_to_curve domain tag.
var DomainSeparator = []byte("Secp256k1_HashToCurve_Cashu_")

// HashToCurve maps a secret to a secp256k1 point per Cashu NUT-00, returning
// the point and the winning counter.
//
// Algorithm (NUT-00):
//
//	msg  = SHA256(DomainSeparator || secret)
//	for c = 0, 1, 2, …:
//	    cand = SHA256(msg || uint32_little_endian(c))
//	    try to parse 0x02||cand as a compressed secp256k1 point
//	    if valid: return (point, c)
//
// The returned point always has an even Y coordinate (0x02 prefix) because
// btcec.ParsePubKey with a 0x02 prefix selects the even-Y solution.
func HashToCurve(secret []byte) (*btcec.PublicKey, uint32) {
	// msg = SHA256(DomainSeparator || secret)
	h := sha256.New()
	h.Write(DomainSeparator)
	h.Write(secret)
	msg := h.Sum(nil)

	// Scratch buffer: 4 bytes for little-endian counter.
	var ctrBuf [4]byte

	for c := uint32(0); ; c++ {
		binary.LittleEndian.PutUint32(ctrBuf[:], c)

		// cand = SHA256(msg || uint32_le(c))
		h2 := sha256.New()
		h2.Write(msg)
		h2.Write(ctrBuf[:])
		cand := h2.Sum(nil) // 32 bytes

		// Build 33-byte compressed encoding: 0x02 || cand (even-Y lift_x).
		compressed := make([]byte, 33)
		compressed[0] = 0x02
		copy(compressed[1:], cand)

		Y, err := btcec.ParsePubKey(compressed)
		if err != nil {
			// cand is not a valid x-coordinate on secp256k1; try next counter.
			continue
		}
		return Y, c
	}
}

// GrindSecret returns a secret of the form "<prefix>-<i>" whose HashToCurve
// winning counter is <= maxCounter.  It iterates i = 0, 1, 2, … until a
// matching secret is found.  Used by tests to construct K-bounded test vectors.
func GrindSecret(prefix string, maxCounter uint32) []byte {
	for i := 0; ; i++ {
		secret := []byte(fmt.Sprintf("%s-%d", prefix, i))
		_, c := HashToCurve(secret)
		if c <= maxCounter {
			return secret
		}
	}
}
