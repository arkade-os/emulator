package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Oracle message format used in the test: 16 bytes total, prefixed with a
// 4-byte magic tag identifying the message kind. The 12 trailing bytes are
// the payload (timestamp, price, …) — the script doesn't introspect them,
// it just hashes the whole thing.
const (
	oracleMessageLen = 16
)

var oracleMessageMagic = []byte("ORCL")

// TestCSFSEmulationECDSASecp256r1 emulates OP_CHECKSIGFROMSTACK for an ECDSA
// signature over secp256r1, built only out of OP_ECMUL / OP_ECADD. The
// verifying public key (Px, Py) is committed statically in the script. The
// raw oracle message is provided in the witness, hashed inside the script,
// and the script enforces a minimal envelope (length + magic tag) before
// running ECDSA verification on the digest. This binds the signature to a
// specific structured message — without that binding the witness-hinted
// ECDSA verifier accepts public-data-only forgeries.
//
// ECDSA verification with witness shortcuts:
//
//	z    = BIN2NUM(SHA256(m) ‖ 0x00)        ← computed in-script, see below
//	u1   = z · s⁻¹ (mod n)                  ← supplied as a witness hint
//	u2   = r · s⁻¹ (mod n)                  ← supplied as a witness hint
//	R    = u1·G + u2·P
//	accept iff R.x mod n == r
//
// The two `EQUALVERIFY` lines (u1·s ≡ z, u2·s ≡ r) pin u1, u2 uniquely to
// (r, s, z), replacing the modular inversion.
//
// Hash convention: arkade BigNums are sign-magnitude little-endian, so
// `OP_BIN2NUM` reads the SHA-256 output as an LE integer (the byte-reversed
// big-endian integer). A 0x00 byte is appended before BIN2NUM so the result
// is always positive regardless of whether the top hash byte's high bit is
// set. The Go-side signer must use the same convention.
func TestCSFSEmulationECDSASecp256r1(t *testing.T) {
	ctx := t.Context()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 100_000)
	indexerSvc := setupIndexer(t)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// A well-formed oracle message: 4-byte tag + 12-byte payload.
	message := append([]byte{}, oracleMessageMagic...)
	message = append(message, []byte("price=42000\x00")...)
	require.Len(t, message, oracleMessageLen)

	r, s := signOracleMessage(t, priv, message)
	u1, u2 := ecdsaHints(t, message, r, s)

	px, py := p256PubKeyCoords(t, &priv.PublicKey)
	arkadeScript := ecdsaSecp256r1VerifyScript(t, px, py)
	arkadeScriptHash := arkade.ArkadeScriptHash(arkadeScript)

	vtxoScript := createArkadeOnlyVtxoScript(aliceAddr.Signer, introspectorPubKey, arkadeScriptHash)

	const contractAmount = int64(10_000)
	vtxoInput := fund(t, ctx, alice, indexerSvc, aliceAddr.Signer, vtxoScript, contractAmount)

	// Witness pushed in order; m ends up on top of the stack: [r, u1, u2, s, m].
	validWitness := wire.TxWitness{
		bnBytes(r),
		bnBytes(u1),
		bnBytes(u2),
		bnBytes(s),
		message,
	}

	receiverPkScript := randomP2TR(t)

	buildSpend := func(w wire.TxWitness) (*psbt.Packet, []*psbt.Packet) {
		spendTx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{vtxoInput},
			[]*wire.TxOut{{Value: contractAmount, PkScript: receiverPkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		addIntrospectorPacket(t, spendTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: arkadeScript, Witness: w},
		})
		return spendTx, checkpoints
	}

	t.Run("valid_signature_accepted", func(t *testing.T) {
		spendTx, checkpoints := buildSpend(validWitness)

		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, spendTx, 0)

		encoded, err := spendTx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
		require.NoError(t, err)
		waitForVtxos()
	})

	t.Run("tampered_signature_rejected", func(t *testing.T) {
		// Flip the lowest bit of s. Recompute u1, u2 against the tampered s so
		// the two scalar-relation EQUALVERIFY lines still pass; the final R.x
		// check is what must reject.
		sBad := new(big.Int).Xor(s, big.NewInt(1))
		u1Bad, u2Bad := ecdsaHintsExplicit(t, message, r, sBad)

		spendTx, checkpoints := buildSpend(wire.TxWitness{
			bnBytes(r), bnBytes(u1Bad), bnBytes(u2Bad), bnBytes(sBad), message,
		})
		encoded, err := spendTx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	})

	t.Run("wrong_message_magic_rejected", func(t *testing.T) {
		// Same key, same length, but the magic tag mismatches.
		badMsg := append([]byte("XXXX"), message[4:]...)

		spendTx, checkpoints := buildSpend(wire.TxWitness{
			bnBytes(r), bnBytes(u1), bnBytes(u2), bnBytes(s), badMsg,
		})
		encoded, err := spendTx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	})
}

// signOracleMessage signs `m` under priv using ECDSA over P-256 with the
// LE-of-SHA256 digest convention the script expects.
func signOracleMessage(t *testing.T, priv *ecdsa.PrivateKey, m []byte) (r, s *big.Int) {
	t.Helper()
	digest := leDigest(m)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	require.NoError(t, err)
	return r, s
}

// ecdsaHints returns the (u1, u2) witness shortcuts for (r, s, z) where z is
// derived from m the same way the script will derive it.
func ecdsaHints(t *testing.T, m []byte, r, s *big.Int) (u1, u2 *big.Int) {
	return ecdsaHintsExplicit(t, m, r, s)
}

func ecdsaHintsExplicit(t *testing.T, m []byte, r, s *big.Int) (u1, u2 *big.Int) {
	t.Helper()
	n := elliptic.P256().Params().N
	z := new(big.Int).SetBytes(leDigest(m))
	sInv := new(big.Int).ModInverse(s, n)
	require.NotNil(t, sInv)
	u1 = new(big.Int).Mod(new(big.Int).Mul(z, sInv), n)
	u2 = new(big.Int).Mod(new(big.Int).Mul(r, sInv), n)
	return u1, u2
}

// p256PubKeyCoords pulls (X, Y) out of an ECDSA P-256 public key via the
// new SEC1 uncompressed encoding API. Direct access to `pub.X` / `pub.Y` is
// deprecated since Go 1.26.
func p256PubKeyCoords(t *testing.T, pub *ecdsa.PublicKey) (px, py *big.Int) {
	t.Helper()
	enc, err := pub.Bytes()
	require.NoError(t, err)
	// SEC1 uncompressed: 0x04 || X (32 bytes) || Y (32 bytes) for P-256.
	require.Len(t, enc, 65)
	require.Equal(t, byte(0x04), enc[0])
	return new(big.Int).SetBytes(enc[1:33]), new(big.Int).SetBytes(enc[33:65])
}

// leDigest returns SHA256(m) byte-reversed, so when fed to ecdsa.Sign /
// SetBytes (which read big-endian) it represents the same integer that the
// in-script `BIN2NUM(SHA256(m) ‖ 0x00)` produces.
func leDigest(m []byte) []byte {
	h := sha256.Sum256(m)
	out := make([]byte, len(h))
	for i := range h {
		out[i] = h[len(h)-1-i]
	}
	return out
}

// ecdsaSecp256r1VerifyScript builds the verifier. The verifying public key
// (px, py) is committed to as inline data pushes; only signatures by that
// key on a well-formed oracle message satisfy the script.
//
// Witness order on the stack (top right):
//
//	[r, u1, u2, s, m]
//
// Stack diagrams use top-on-right convention.
func ecdsaSecp256r1VerifyScript(t *testing.T, px, py *big.Int) []byte {
	t.Helper()

	params := elliptic.P256().Params()
	nBytes := bnBytes(params.N)
	gxBytes := bnBytes(params.Gx)
	gyBytes := bnBytes(params.Gy)
	pxBytes := bnBytes(px)
	pyBytes := bnBytes(py)

	out, err := txscript.NewScriptBuilder().
		// Stack: [r, u1, u2, s, m]
		//
		// A) Envelope checks on the oracle message.
		AddOp(arkade.OP_SIZE).                    // [..., m, len(m)]
		AddInt64(oracleMessageLen).               // [..., m, len(m), 16]
		AddOp(arkade.OP_EQUALVERIFY).             // [..., m]
		AddOp(arkade.OP_DUP).                     // [..., m, m]
		AddInt64(int64(len(oracleMessageMagic))). // [..., m, m, 4]
		AddOp(arkade.OP_LEFT).                    // [..., m, m[:4]]
		AddData(oracleMessageMagic).              // [..., m, m[:4], "ORCL"]
		AddOp(arkade.OP_EQUALVERIFY).             // [..., m]
		//
		// B) Hash the message and convert to a positive BigNum digest z.
		// 0x00 sign-extension byte makes BIN2NUM treat the result as positive
		// regardless of the high bit of SHA-256's last byte.
		AddOp(arkade.OP_SHA256).  // [..., h]            (32 BE bytes)
		AddData([]byte{0x00}).    // [..., h, 0x00]
		AddOp(arkade.OP_CAT).     // [..., h‖0x00]       (33 bytes, positive)
		AddOp(arkade.OP_BIN2NUM). // [r, u1, u2, s, z]
		//
		// C) Verify u1·s ≡ z (mod n).
		AddOp(arkade.OP_OVER).                    // [..., s, z, s]
		AddOp(arkade.OP_4).AddOp(arkade.OP_PICK). // [..., s, z, s, u1]
		AddOp(arkade.OP_MUL).                     // [..., s, z, u1·s]
		AddData(nBytes).AddOp(arkade.OP_MOD).     // [..., s, z, (u1·s) mod n]
		AddOp(arkade.OP_SWAP).                    // [..., s, (u1·s) mod n, z]
		AddData(nBytes).AddOp(arkade.OP_MOD).     // [..., s, (u1·s) mod n, z mod n]
		AddOp(arkade.OP_EQUALVERIFY).             // [r, u1, u2, s]
		//
		// D) Verify u2·s ≡ r (mod n).
		AddOp(arkade.OP_OVER).                    // [..., u2, s, u2]
		AddOp(arkade.OP_MUL).                     // [..., u2, u2·s]
		AddData(nBytes).AddOp(arkade.OP_MOD).     // [..., u2, (u2·s) mod n]
		AddOp(arkade.OP_3).AddOp(arkade.OP_PICK). // [..., u2, (u2·s) mod n, r]
		AddData(nBytes).AddOp(arkade.OP_MOD).     // [..., u2, (u2·s) mod n, r mod n]
		AddOp(arkade.OP_EQUALVERIFY).             // [r, u1, u2]
		//
		// E) u1·G on secp256r1.
		AddData(gxBytes).AddData(gyBytes).         // [..., r, u1, u2, Gx, Gy]
		AddOp(arkade.OP_3).AddOp(arkade.OP_ROLL).  // [..., r, u2, Gx, Gy, u1]
		AddOp(arkade.OP_1).AddOp(arkade.OP_ECMUL). // [r, u2, u1Gx, u1Gy]
		//
		// F) u2·P on secp256r1 (Px, Py committed in the script).
		AddData(pxBytes).AddData(pyBytes).         // [..., r, u2, u1Gx, u1Gy, Px, Py]
		AddOp(arkade.OP_4).AddOp(arkade.OP_ROLL).  // [..., r, u1Gx, u1Gy, Px, Py, u2]
		AddOp(arkade.OP_1).AddOp(arkade.OP_ECMUL). // [r, u1Gx, u1Gy, u2Px, u2Py]
		//
		// G) R = u1·G + u2·P, accept iff R.x mod n == r.
		AddOp(arkade.OP_1).AddOp(arkade.OP_ECADD). // [r, Rx, Ry]
		AddOp(arkade.OP_DROP).                     // [r, Rx]
		AddData(nBytes).AddOp(arkade.OP_MOD).      // [r, Rx mod n]
		AddOp(arkade.OP_EQUAL).                    // [bool]
		Script()
	require.NoError(t, err)
	return out
}
