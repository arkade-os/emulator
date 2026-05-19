package arkade

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

/**
F: introspector public key
f:      "       secret key
t: script_hash
G: generator (F = f * G)

VtxoArkadeScript = F + t*G = (f + t) * G

to migrate from "f" private key to "s", we compute migration scalar m = f - s

then to sign the VtxoArkadeScript:
we use the private key (s' = s + m + t) instead of (f' = f + t)
**/
func TestTweakMigrate(t *testing.T) {
	scriptHash := ArkadeScriptHash([]byte("OP_TRUE"))
	first, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	// first_introspector_pubkey + scriptHash = contract_key
	// we assume some funds are locked into this key
	firstContractKey := ComputeArkadeScriptPublicKey(first.PubKey(), scriptHash)


	// introspector operator wants to migrate to a new key
	second, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	
	// introspector computes the migration tweak = (first key - second key) modulo curve order
	tweakScalar := new(btcec.ModNScalar).NegateVal(&second.Key)
	tweakScalar.Add(&first.Key)
	tweakBytes := tweakScalar.Bytes()
	migrationTweak := tweakBytes[:]

	// applying the migration tweak then the scriptHash to the second pubkey reproduces the first contract key
	migrated := ComputeArkadeScriptPublicKey(second.PubKey(), migrationTweak)
	secondContractKey := ComputeArkadeScriptPublicKey(migrated, scriptHash)

	// first = second so no need to move the funds to a new address
	require.Equal(t,
		schnorr.SerializePubKey(firstContractKey),
		schnorr.SerializePubKey(secondContractKey),
	)

	// if someone pass the "old" firstContractKey to introspector
	// the signer can sign using privkey = second_privkey + script_hash + migration_tweak
	seckeyForOldContract := ComputeArkadeScriptPrivateKey(ComputeArkadeScriptPrivateKey(second, migrationTweak), scriptHash)

	require.Equal(
		t,
		schnorr.SerializePubKey(firstContractKey),
		schnorr.SerializePubKey(seckeyForOldContract.PubKey()),
	)
}

func TestArkadeScriptKeyTweaking(t *testing.T) {
	testVector := []struct {
		name                string
		script              []byte
		priv                *btcec.PrivateKey
		prefix              byte
		expectedTweakedPref byte
	}{
		{
			name:                "even",
			script:              []byte("OP_TRUE"),
			priv:                mustPrivKeyFromSeedWithPrefix(t, "private-key-seed-even", secp256k1.PubKeyFormatCompressedEven),
			prefix:              secp256k1.PubKeyFormatCompressedEven,
			expectedTweakedPref: 0,
		},
		{
			name:                "odd",
			script:              []byte("OP_TRUE"),
			priv:                mustPrivKeyFromSeedWithPrefix(t, "private-key-seed-odd", secp256k1.PubKeyFormatCompressedOdd),
			prefix:              secp256k1.PubKeyFormatCompressedOdd,
			expectedTweakedPref: 0,
		},
		{
			name:                "even_to_tweaked_odd",
			script:              []byte("OP_TRUE"), // don't change script or tweaked key might not be odd
			priv:                mustPrivKeyFromHexString(t, "05717677ccec3c6ec975b8356b104808b6e149b82d9816d2d7c3b25dd658c220"),
			prefix:              secp256k1.PubKeyFormatCompressedEven,
			expectedTweakedPref: secp256k1.PubKeyFormatCompressedOdd,
		},
		{
			name:                "even_to_tweaked_even",
			script:              []byte("OP_TRUE"), // don't change script or tweaked key might not be even
			priv:                mustPrivKeyFromHexString(t, "2b6f9e9c6b1b6ada475009bb6ac01e7cacc5879ab2610b1ad017cf7e467665af"),
			prefix:              secp256k1.PubKeyFormatCompressedEven,
			expectedTweakedPref: secp256k1.PubKeyFormatCompressedEven,
		},
	}

	for _, tc := range testVector {
		t.Run(fmt.Sprintf("roundtrip_%s", tc.name), func(t *testing.T) {
			require.Equal(t, tc.prefix, tc.priv.PubKey().SerializeCompressed()[0])

			scriptHash := ArkadeScriptHash(tc.script)
			tweakedPriv := ComputeArkadeScriptPrivateKey(tc.priv, scriptHash)
			expectedTweakedPub := ComputeArkadeScriptPublicKey(tc.priv.PubKey(), scriptHash)

			require.Equal(
				t,
				schnorr.SerializePubKey(expectedTweakedPub),
				schnorr.SerializePubKey(tweakedPriv.PubKey()),
			)
		})

		t.Run(fmt.Sprintf("verify_sig_%s", tc.name), func(t *testing.T) {
			require.Equal(t, tc.prefix, tc.priv.PubKey().SerializeCompressed()[0])

			scriptHash := ArkadeScriptHash(tc.script)
			tweakedPriv := ComputeArkadeScriptPrivateKey(tc.priv, scriptHash)
			tweakedPub := ComputeArkadeScriptPublicKey(tc.priv.PubKey(), scriptHash)

			msg := sha256.Sum256([]byte("yo"))
			sig, err := schnorr.Sign(tweakedPriv, msg[:])
			require.NoError(t, err)

			parsedSig, err := schnorr.ParseSignature(sig.Serialize())
			require.NoError(t, err)

			xOnlyPub := schnorr.SerializePubKey(tweakedPub)
			parsedPub, err := schnorr.ParsePubKey(xOnlyPub)
			require.NoError(t, err)

			require.True(t, parsedSig.Verify(msg[:], parsedPub))
			require.False(t, parsedSig.Verify(msg[:], tc.priv.PubKey()))

			if tc.expectedTweakedPref != 0 {
				require.Equal(t, tc.expectedTweakedPref, tweakedPriv.PubKey().SerializeCompressed()[0])
			}
		})
	}
}

func mustPrivKeyFromSeedWithPrefix(t *testing.T, seed string, prefix byte) *btcec.PrivateKey {
	t.Helper()
	digest := sha256.Sum256([]byte(seed))
	privKey, _ := btcec.PrivKeyFromBytes(digest[:])

	if prefix != secp256k1.PubKeyFormatCompressedEven && prefix != secp256k1.PubKeyFormatCompressedOdd {
		t.Fatalf("unsupported compressed prefix 0x%x", prefix)
	}

	if privKey.PubKey().SerializeCompressed()[0] == prefix {
		return privKey
	}

	negated := privKey.Key
	negated.Negate()
	result := &btcec.PrivateKey{Key: negated}
	require.Equal(t, prefix, result.PubKey().SerializeCompressed()[0])
	return result
}

func mustHexToBytes(t *testing.T, hexStr string) []byte {
	t.Helper()
	data, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	return data
}

func mustPrivKeyFromHexString(t *testing.T, hex string) *btcec.PrivateKey {
	t.Helper()
	priv, _ := btcec.PrivKeyFromBytes(mustHexToBytes(t, hex))
	return priv
}
