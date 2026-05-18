package test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	gnarkbn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"
)

const groth16BN254PublicInput = int64(9)

type bn254G1Point struct {
	x *big.Int
	y *big.Int
}

type bn254G2Point struct {
	xC0 *big.Int
	xC1 *big.Int
	yC0 *big.Int
	yC1 *big.Int
}

type groth16BN254Fixture struct {
	ic0      bn254G1Point
	ic1      bn254G1Point
	alpha    bn254G1Point
	betaNeg  bn254G2Point
	gammaNeg bn254G2Point
	deltaNeg bn254G2Point

	proofA bn254G1Point
	proofB bn254G2Point
	proofC bn254G1Point
}

// TestGroth16BN254VerificationInScript verifies the Groth16 verifier equation
// in Arkade Script:
//
//	e(A, B) * e(C, -delta) * e(vk_x, -gamma) * e(alpha, -beta) == 1
//
// The script computes vk_x = IC0 + public_input*IC1 with OP_ECMUL and
// OP_ECADD, then checks the four-pair product with OP_ECPAIRING.
func TestGroth16BN254VerificationInScript(t *testing.T) {
	ctx := t.Context()

	fixture := newGroth16BN254Fixture(t)
	requireGroth16BN254Pairing(t, fixture, groth16BN254PublicInput, fixture.proofC, true)

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

	arkadeScript := groth16BN254VerifierScript(t, fixture)
	arkadeScriptHash := arkade.ArkadeScriptHash(arkadeScript)

	vtxoScript := createArkadeOnlyVtxoScript(aliceAddr.Signer, introspectorPubKey, arkadeScriptHash)

	const contractAmount = int64(10_000)
	vtxoInput := fund(t, ctx, alice, indexerSvc, aliceAddr.Signer, vtxoScript, contractAmount)
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

	t.Run("wrong_public_input_rejected", func(t *testing.T) {
		witness := groth16BN254Witness(fixture, groth16BN254PublicInput+1, fixture.proofC)
		spendTx, checkpoints := buildSpend(witness)

		err := executeArkadeScripts(t, spendTx, checkpoints, introspectorPubKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "false stack entry at end of script execution")

		encoded, err := spendTx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	})

	t.Run("tampered_proof_rejected", func(t *testing.T) {
		tamperedC := bn254G1Add(fixture.proofC, fixture.ic1)
		requireGroth16BN254Pairing(t, fixture, groth16BN254PublicInput, tamperedC, false)

		witness := groth16BN254Witness(fixture, groth16BN254PublicInput, tamperedC)
		spendTx, checkpoints := buildSpend(witness)

		err := executeArkadeScripts(t, spendTx, checkpoints, introspectorPubKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "false stack entry at end of script execution")
	})

	t.Run("valid_proof_accepted", func(t *testing.T) {
		witness := groth16BN254Witness(fixture, groth16BN254PublicInput, fixture.proofC)
		spendTx, checkpoints := buildSpend(witness)

		require.NoError(t, executeArkadeScripts(t, spendTx, checkpoints, introspectorPubKey))

		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, spendTx, 0)

		encoded, err := spendTx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
		require.NoError(t, err)
		waitForVtxos()
	})
}

func newGroth16BN254Fixture(t *testing.T) groth16BN254Fixture {
	t.Helper()

	// Static gnark Groth16 BN254 fixture for the circuit Y*Y = X with public
	// input X=9 and private witness Y=3.
	return groth16BN254Fixture{
		ic0: g1Hex(
			t,
			"214762f5e1b31936df442f16298fdc668254fe4d3c13f92d8c0b0988aabd869d",
			"1413a9ea941737df505a163fe8469f445791833e637a0daaf82849deee477c9f",
		),
		ic1: g1Hex(
			t,
			"a671871e2e742344d42f7317f15020c8ffd06b9a6d5fc2604effb253ea63140",
			"27b737a8668cf74d50fc8a41387b3d15de347cd6af0698b385c4f8611459faec",
		),
		alpha: g1Hex(
			t,
			"84af1dd3073d98496ae82b47b686deeab8520d014edfb1d4b89c6bc9815e7e4",
			"1baf84027fc4c511a8e6fde1bf178f7f4142c5847c7cf08be0ef48c3de402941",
		),
		betaNeg: g2Hex(
			t,
			"1d6e87de4fa9d755e73537d1016fa6bf5e6314154b1cc29c15f525fbc6b74ce",
			"1efd2d59f1887688bd7eaa5e7fa318e3b7855916fdc7d28c219ea89b4fb6bbc3",
			"467f0733b737da7d9de233a0c3461530a746263f1f4823fed0240d2ca313cc7",
			"16fe7eba648bf65b33187de2872b48c01f70b7d4c63292e7c9d882ee34e820a6",
		),
		gammaNeg: g2Hex(
			t,
			"1f66abcb6a97665b70301df80c6c117895bf0d805a4ec298159df4be9a9e4afd",
			"1e8f987221464dbe10ca749d5d30a012a8a29a88cc59dea49f198e412fc2bd7c",
			"eb34da773a8038d2c0888b9516db9a3030999d84d5218eb93163293970eaa30",
			"2c63398cabafdcf2ec24ef25190420153b5db9536f95bc98fbe2c4ebf4b7788a",
		),
		deltaNeg: g2Hex(
			t,
			"103420825ef79a5c489e93d5e686988fdd35565f906873a0a76d95feddd0e613",
			"2cddd0828035c3469a02325690251bf93c962b04a2de6679a5c793802ce85795",
			"2e0ce45661beb79b08d8f6a50a505223a5b83e963afe98c65542bfaed2bb8c6d",
			"1e125142c038ef6508779d59fc45bd0fe8a779656e090411b704373e7b708d30",
		),
		proofA: g1Hex(
			t,
			"288965af2fd92b46c200c6486f4d3d2d9853b43006a939487265ca003dae3d1a",
			"b74788ac234aab5cf97938435bc4a2e1038af3ecd6147c49d02a7621cc64491",
		),
		proofB: g2Hex(
			t,
			"2614fad1fd4c641ef5b29564ec1b06a18bbeed7b0a8af8b1d646ba467dcff714",
			"decd8fba51fd1505cb39610ed8cc87918bb6e3d9aab7103b9ca1313d744b428",
			"5200fcb224cc519810eed7af57d6f58a57a49bc52aa43577e0dd5d79c8e8361",
			"2ada81fd1ec597c95138d4ccecaf7d0355116e550043cd373b7fd711f7c96a14",
		),
		proofC: g1Hex(
			t,
			"2776c430308e75b457828e0b5514b0ba6e99311a8509fa8673aad885714ab569",
			"78c80a2a5bbc6c24fc811086b1e021b1aa58a943006992ee23dc5214da3303",
		),
	}
}

func groth16BN254Witness(f groth16BN254Fixture, publicInput int64, proofC bn254G1Point) wire.TxWitness {
	return wire.TxWitness{
		bnBytes(f.proofA.x),
		bnBytes(f.proofA.y),
		bnBytes(f.proofB.xC1),
		bnBytes(f.proofB.xC0),
		bnBytes(f.proofB.yC1),
		bnBytes(f.proofB.yC0),
		bnBytes(proofC.x),
		bnBytes(proofC.y),
		bnBytes(big.NewInt(publicInput)),
	}
}

func groth16BN254VerifierScript(t *testing.T, f groth16BN254Fixture) []byte {
	t.Helper()

	builder := txscript.NewScriptBuilder()

	// Witness stack, top on right:
	// [A_x, A_y, B_x_c1, B_x_c0, B_y_c1, B_y_c0, C_x, C_y, public_input]
	addG1(builder, f.ic1)
	builder.
		AddOp(arkade.OP_2).AddOp(arkade.OP_ROLL).
		AddInt64(arkade.CurveAltBN128).AddOp(arkade.OP_ECMUL)
	addG1(builder, f.ic0)
	builder.AddInt64(arkade.CurveAltBN128).AddOp(arkade.OP_ECADD)

	// Save computed vk_x while completing the pairing stack. The witness proof
	// points already form the first pair (A, B) and G1 side of the second pair
	// (C, -delta).
	builder.AddOp(arkade.OP_TOALTSTACK).AddOp(arkade.OP_TOALTSTACK)
	addG2(builder, f.deltaNeg)
	builder.AddOp(arkade.OP_FROMALTSTACK).AddOp(arkade.OP_FROMALTSTACK)
	addG2(builder, f.gammaNeg)
	addG1(builder, f.alpha)
	addG2(builder, f.betaNeg)

	script, err := builder.
		AddInt64(4).
		AddInt64(arkade.CurveAltBN128).
		AddOp(arkade.OP_ECPAIRING).
		Script()
	require.NoError(t, err)
	return script
}

func addG1(builder *txscript.ScriptBuilder, p bn254G1Point) {
	builder.AddData(bnBytes(p.x)).AddData(bnBytes(p.y))
}

func addG2(builder *txscript.ScriptBuilder, p bn254G2Point) {
	builder.
		AddData(bnBytes(p.xC1)).
		AddData(bnBytes(p.xC0)).
		AddData(bnBytes(p.yC1)).
		AddData(bnBytes(p.yC0))
}

func requireGroth16BN254Pairing(
	t *testing.T, f groth16BN254Fixture, publicInput int64, proofC bn254G1Point, expected bool,
) {
	t.Helper()

	vkX := bn254G1Add(
		bn254G1Mul(f.ic1, big.NewInt(publicInput)),
		f.ic0,
	)

	ok, err := gnarkbn254.PairingCheck(
		[]gnarkbn254.G1Affine{
			toGnarkG1(f.proofA),
			toGnarkG1(proofC),
			toGnarkG1(vkX),
			toGnarkG1(f.alpha),
		},
		[]gnarkbn254.G2Affine{
			toGnarkG2(f.proofB),
			toGnarkG2(f.deltaNeg),
			toGnarkG2(f.gammaNeg),
			toGnarkG2(f.betaNeg),
		},
	)
	require.NoError(t, err)
	require.Equal(t, expected, ok)
}

func g1Hex(t *testing.T, x, y string) bn254G1Point {
	t.Helper()
	return bn254G1Point{x: bigHex(t, x), y: bigHex(t, y)}
}

func g2Hex(t *testing.T, xC0, xC1, yC0, yC1 string) bn254G2Point {
	t.Helper()
	return bn254G2Point{
		xC0: bigHex(t, xC0),
		xC1: bigHex(t, xC1),
		yC0: bigHex(t, yC0),
		yC1: bigHex(t, yC1),
	}
}

func bigHex(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	require.True(t, ok, "invalid hex bigint %q", s)
	return v
}

func bn254G1Mul(p bn254G1Point, scalar *big.Int) bn254G1Point {
	in := toGnarkG1(p)
	var out gnarkbn254.G1Affine
	out.ScalarMultiplication(&in, scalar)
	return fromGnarkG1(out)
}

func bn254G1Add(a, b bn254G1Point) bn254G1Point {
	ga := toGnarkG1(a)
	gb := toGnarkG1(b)
	var out gnarkbn254.G1Affine
	out.Add(&ga, &gb)
	return fromGnarkG1(out)
}

func toGnarkG1(p bn254G1Point) gnarkbn254.G1Affine {
	var out gnarkbn254.G1Affine
	out.X.SetBigInt(p.x)
	out.Y.SetBigInt(p.y)
	return out
}

func fromGnarkG1(p gnarkbn254.G1Affine) bn254G1Point {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return bn254G1Point{x: new(big.Int).Set(&x), y: new(big.Int).Set(&y)}
}

func toGnarkG2(p bn254G2Point) gnarkbn254.G2Affine {
	var out gnarkbn254.G2Affine
	out.X.A0.SetBigInt(p.xC0)
	out.X.A1.SetBigInt(p.xC1)
	out.Y.A0.SetBigInt(p.yC0)
	out.Y.A1.SetBigInt(p.yC1)
	return out
}
