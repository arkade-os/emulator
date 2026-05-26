package test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// 32-byte HTLC preimage + its HASH160 (RIPEMD160(SHA256(preimage)))
var (
	htlcPreimage = []byte{
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	}
	htlcPreimageHash = []byte{
		0x87, 0x39, 0xf4, 0x0e, 0xc4, 0xdb, 0xf5, 0x69, 0xdc, 0xb3,
		0x81, 0x34, 0xc6, 0xe7, 0x31, 0x09, 0x08, 0x56, 0x69, 0x81,
	}
)

const (
	contractAmount = int64(10_000)
	refundLocktime = uint32(500_000_000) // genesis timelock so always valid
)

// TestCovenantHTLC exercises an HTLC whose spending rules are enforced by
// arkade covenants instead of receiver/sender signatures.
//
// The VTXO is owned by a 2-of-2 multisig (arkd signer + emulator-tweaked
// key) wrapped in a path-specific predicate closure. The emulator only
// signs once the arkade covenant on the spending tx passes, pinning output[i]
// to the current input — so a taker claiming several HTLCs in one tx cannot
// collapse them onto a single output.
//
//		OP_PUSHCURRENTINPUTINDEX OP_DUP
//		OP_INSPECTOUTPUTSCRIPTPUBKEY
//		OP_1 OP_EQUALVERIFY            # force taproot
//		<receiver_or_sender_witness_program> OP_EQUALVERIFY
//		OP_INSPECTOUTPUTVALUE
//		OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTVALUE
//		OP_GREATERTHANOREQUAL
//
//	  - Claim:  ConditionMultisigClosure with HASH160 over the preimage.
//	  - Refund: CLTVMultisigClosure with an absolute timelock.
func TestCovenantHTLC(t *testing.T) {
	ctx := t.Context()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	emulatorClient, emulatorPubKey, conn := setupEmulatorClient(t, ctx)
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

	t.Run("claim", func(t *testing.T) {
		receiverPkScript := randomP2TR(t)

		preimageCondition, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_HASH160).
			AddData(htlcPreimageHash).
			AddOp(txscript.OP_EQUAL).
			Script()
		require.NoError(t, err)

		arkadeScript := enforcePayTo(t, receiverPkScript)

		htlcVtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.ConditionMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{
							// server
							aliceAddr.Signer,
							// emulator
							arkade.ComputeArkadeScriptPublicKey(
								emulatorPubKey,
								arkade.ArkadeScriptHash(arkadeScript),
							),
						},
					},
					Condition: preimageCondition,
				},
			},
		}

		htlcInput := fund(
			t, ctx, alice, indexerSvc,
			aliceAddr.Signer, htlcVtxoScript, contractAmount,
		)

		// arkade witness is empty (script reads index from OP_PUSHCURRENTINPUTINDEX);
		// condition witness reveals the preimage.
		witness := wire.TxWitness{}
		conditionWitness := wire.TxWitness{htlcPreimage}

		buildClaim := func(outputs []*wire.TxOut) (*psbt.Packet, []*psbt.Packet) {
			ptx, checkpoints, err := offchain.BuildTxs(
				[]offchain.VtxoInput{htlcInput}, outputs, checkpointScriptBytes,
			)
			require.NoError(t, err)

			require.NoError(t, txutils.SetArkPsbtField(
				ptx, 0, txutils.ConditionWitnessField, conditionWitness,
			))
			for _, cp := range checkpoints {
				require.NoError(t, txutils.SetArkPsbtField(
					cp, 0, txutils.ConditionWitnessField, conditionWitness,
				))
			}

			addEmulatorPacket(t, ptx, []arkade.EmulatorEntry{
				{Vin: 0, Script: arkadeScript, Witness: witness},
			})
			return ptx, checkpoints
		}

		submitAndExpectFailure := func(outputs []*wire.TxOut) {
			candidateTx, checkpoints := buildClaim(outputs)

			encodedTx, err := candidateTx.B64Encode()
			require.NoError(t, err)

			_, _, err = emulatorClient.SubmitTx(
				ctx, encodedTx, encodeCheckpoints(t, checkpoints),
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to process transaction")
		}

		// Invalid: wrong destination at output 0
		submitAndExpectFailure([]*wire.TxOut{
			{Value: contractAmount, PkScript: []byte{0x6a}}, // OP_RETURN
		})

		// Invalid: wrong amount at output 0
		submitAndExpectFailure([]*wire.TxOut{
			{Value: contractAmount - 1, PkScript: receiverPkScript},
			{Value: 1, PkScript: randomP2TR(t)}, // need a change
		})

		// Valid: preimage revealed + right output
		validTx, validCheckpoints := buildClaim(
			[]*wire.TxOut{{Value: contractAmount, PkScript: receiverPkScript}},
		)

		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, validTx, 0)

		encodedValidTx, err := validTx.B64Encode()
		require.NoError(t, err)

		_, _, err = emulatorClient.SubmitTx(
			ctx, encodedValidTx, encodeCheckpoints(t, validCheckpoints),
		)
		require.NoError(t, err)

		waitForVtxos()
	})

	t.Run("claim_multiple", func(t *testing.T) {
		// Single taker claims several HTLCs in one ark tx; inputs and
		// outputs are paired by index.
		const numHTLCs = 3

		receiverPkScript := randomP2TR(t)
		arkadeScript := enforcePayTo(t, receiverPkScript)
		arkadeScriptHash := arkade.ArkadeScriptHash(arkadeScript)

		preimages := make([][]byte, numHTLCs)
		htlcInputs := make([]offchain.VtxoInput, numHTLCs)

		for i := range numHTLCs {
			preimage := make([]byte, 32)
			for j := range preimage {
				preimage[j] = byte(i + 1)
			}
			preimages[i] = preimage

			preimageCondition, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(btcutil.Hash160(preimage)).
				AddOp(txscript.OP_EQUAL).
				Script()
			require.NoError(t, err)

			htlcVtxoScript := script.TapscriptsVtxoScript{
				Closures: []script.Closure{
					&script.ConditionMultisigClosure{
						MultisigClosure: script.MultisigClosure{
							PubKeys: []*btcec.PublicKey{
								aliceAddr.Signer,
								arkade.ComputeArkadeScriptPublicKey(
									emulatorPubKey, arkadeScriptHash,
								),
							},
						},
						Condition: preimageCondition,
					},
				},
			}

			htlcInputs[i] = fund(
				t, ctx, alice, indexerSvc,
				aliceAddr.Signer, htlcVtxoScript, contractAmount,
			)
		}

		outputs := make([]*wire.TxOut, numHTLCs)
		for i := range numHTLCs {
			outputs[i] = &wire.TxOut{Value: contractAmount, PkScript: receiverPkScript}
		}

		ptx, checkpoints, err := offchain.BuildTxs(
			htlcInputs, outputs, checkpointScriptBytes,
		)
		require.NoError(t, err)

		// One condition witness per input on the ark tx, plus one per
		// checkpoint (each checkpoint has a single input).
		entries := make([]arkade.EmulatorEntry, numHTLCs)
		for i, preimage := range preimages {
			require.NoError(t, txutils.SetArkPsbtField(
				ptx, i, txutils.ConditionWitnessField, wire.TxWitness{preimage},
			))
			entries[i] = arkade.EmulatorEntry{
				Vin:     uint16(i),
				Script:  arkadeScript,
				Witness: wire.TxWitness{},
			}
		}
		for i, cp := range checkpoints {
			require.NoError(t, txutils.SetArkPsbtField(
				cp, 0, txutils.ConditionWitnessField, wire.TxWitness{preimages[i]},
			))
		}

		addEmulatorPacket(t, ptx, entries)

		vouts := make([]uint32, numHTLCs)
		for i := range numHTLCs {
			vouts[i] = uint32(i)
		}
		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, ptx, vouts...)

		encodedTx, err := ptx.B64Encode()
		require.NoError(t, err)

		_, _, err = emulatorClient.SubmitTx(
			ctx, encodedTx, encodeCheckpoints(t, checkpoints),
		)
		require.NoError(t, err)

		waitForVtxos()
	})

	t.Run("refund", func(t *testing.T) {
		senderPkScript := randomP2TR(t)
		arkadeScript := enforcePayTo(t, senderPkScript)

		htlcVtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.CLTVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{
							// server
							aliceAddr.Signer,
							// emulator
							arkade.ComputeArkadeScriptPublicKey(
								emulatorPubKey,
								arkade.ArkadeScriptHash(arkadeScript),
							),
						},
					},
					Locktime: arklib.AbsoluteLocktime(refundLocktime),
				},
			},
		}

		htlcInput := fund(
			t, ctx, alice, indexerSvc,
			aliceAddr.Signer, htlcVtxoScript, contractAmount,
		)

		witness := wire.TxWitness{}

		submitAndExpectFailure := func(outputs []*wire.TxOut) {
			candidateTx, checkpoints, err := offchain.BuildTxs(
				[]offchain.VtxoInput{htlcInput}, outputs, checkpointScriptBytes,
			)
			require.NoError(t, err)

			addEmulatorPacket(t, candidateTx, []arkade.EmulatorEntry{
				{Vin: 0, Script: arkadeScript, Witness: witness},
			})

			encodedTx, err := candidateTx.B64Encode()
			require.NoError(t, err)

			_, _, err = emulatorClient.SubmitTx(
				ctx, encodedTx, encodeCheckpoints(t, checkpoints),
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to process transaction")
		}

		// Invalid: wrong destination at output 0
		submitAndExpectFailure([]*wire.TxOut{
			{Value: contractAmount, PkScript: []byte{0x6a}}, // OP_RETURN
		})

		// Invalid: wrong amount at output 0
		submitAndExpectFailure([]*wire.TxOut{
			{Value: contractAmount - 1, PkScript: senderPkScript},
			{Value: 1, PkScript: randomP2TR(t)},
		})

		// Valid: CLTV satisfied + right output
		validTx, validCheckpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{htlcInput},
			[]*wire.TxOut{{Value: contractAmount, PkScript: senderPkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)

		addEmulatorPacket(t, validTx, []arkade.EmulatorEntry{
			{Vin: 0, Script: arkadeScript, Witness: witness},
		})

		waitForVtxos := watchForPreconfirmedVtxos(t, indexerSvc, validTx, 0)

		encodedValidTx, err := validTx.B64Encode()
		require.NoError(t, err)

		_, _, err = emulatorClient.SubmitTx(
			ctx, encodedValidTx, encodeCheckpoints(t, validCheckpoints),
		)
		require.NoError(t, err)

		waitForVtxos()
	})
}

// enforcePayTo builds an arkade script asserting that the output at the
// current input index goes to pkScript for at least the input's value.
func enforcePayTo(t *testing.T, pkScript []byte) []byte {
	t.Helper()

	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_DUP).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // segwit v1
		AddData(pkScript[2:]).        // witness program
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_GREATERTHANOREQUAL).
		Script()
	require.NoError(t, err)

	return s
}

// randomP2TR returns a fresh P2TR scriptPubKey. Used for destinations where
// the identity is irrelevant to the test.
func randomP2TR(t *testing.T) []byte {
	t.Helper()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript, err := txscript.PayToTaprootScript(priv.PubKey())
	require.NoError(t, err)

	return pkScript
}

// fund locks contractAmount into a VTXO with the given script and
// returns the spend input for its forfeit leaf.
func fund(
	t *testing.T,
	ctx context.Context,
	alice arksdk.ArkClient,
	indexerSvc indexer.Indexer,
	serverSigner *btcec.PublicKey,
	htlcVtxoScript script.TapscriptsVtxoScript,
	contractAmount int64,
) offchain.VtxoInput {
	t.Helper()

	htlcTapKey, _, err := htlcVtxoScript.TapTree()
	require.NoError(t, err)

	htlcAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: htlcTapKey,
		Signer:     serverSigner,
	}
	htlcAddrStr, err := htlcAddr.EncodeV0()
	require.NoError(t, err)

	fundingTxid, err := alice.SendOffChain(ctx, []types.Receiver{
		{To: htlcAddrStr, Amount: uint64(contractAmount)},
	})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxid)

	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	htlcTapscript := onlyForfeitScript(t, htlcVtxoScript)
	htlcVout, htlcOutput := findTaprootOutput(t, fundingPtx.UnsignedTx, htlcTapKey)
	require.Equal(t, contractAmount, htlcOutput.Value)

	return vtxoInputFromScriptOutput(
		t, fundingPtx.UnsignedTx, htlcVout, htlcVtxoScript, htlcTapscript,
	)
}
