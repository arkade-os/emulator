package emulator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestArkPrevOutFetcher(t *testing.T) {
	fix := readPrevOutFixtures(t)

	t.Run("cases", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				checkpoints := decodePSBTs(t, f.Checkpoints)
				require.Len(t, f.ExpectedVtxoPkScripts, len(ptx.Inputs))

				fetcher, err := newPrevOutFetcher(ptx, checkpoints)
				if f.ErrorContains != "" {
					require.ErrorContains(t, err, f.ErrorContains)
					return
				}
				require.NoError(t, err)

				for inputIndex := range ptx.Inputs {
					fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.PrevArkTxField)
					require.NoError(t, err)

					outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
					if len(fields) == 0 {
						require.Nil(t, fetcher.FetchPrevOutArkTx(outpoint))
						require.Nil(t, fetcher.FetchVtxoPrevOutPkScript(outpoint))
						continue
					}

					require.Len(t, fields, 1)

					got := fetcher.FetchPrevOutArkTx(outpoint)
					require.NotNil(t, got)
					require.Equal(t, fields[0].TxHash(), got.TxHash())

					expectedPkScriptHex := f.ExpectedVtxoPkScripts[inputIndex]
					if expectedPkScriptHex == "" {
						require.Nil(t, fetcher.FetchVtxoPrevOutPkScript(outpoint))
						continue
					}

					expectedPkScript, err := hex.DecodeString(expectedPkScriptHex)
					require.NoError(t, err)
					require.Equal(t, expectedPkScript, fetcher.FetchVtxoPrevOutPkScript(outpoint))
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fix.Invalid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				checkpoints := decodePSBTs(t, f.Checkpoints)
				_, err := newPrevOutFetcher(ptx, checkpoints)
				require.Error(t, err)
				require.Contains(t, err.Error(), f.ErrorContains)
			})
		}
	})
}

func TestOnchainPrevOutFetcher(t *testing.T) {
	fix := readOnchainPrevOutFixtures(t)

	t.Run("cases", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)

				fetcher, err := prevOutFetcherForOnchainTx(ptx)
				if f.ErrorContains != "" {
					require.ErrorContains(t, err, f.ErrorContains)
					return
				}
				require.NoError(t, err)

				for inputIndex := range ptx.Inputs {
					fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.PrevoutTxField)
					require.NoError(t, err)

					outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
					if len(fields) == 0 {
						require.Nil(t, fetcher.FetchPrevOutArkTx(outpoint))
						continue
					}

					require.Len(t, fields, 1)

					got := fetcher.FetchPrevOutArkTx(outpoint)
					require.NotNil(t, got)
					require.Equal(t, fields[0].TxHash(), got.TxHash())
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fix.Invalid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				_, err := prevOutFetcherForOnchainTx(ptx)
				require.Error(t, err)
				require.Contains(t, err.Error(), f.ErrorContains)
			})
		}
	})
}

// TestPrevOutFetcherForIntentReconcilesWitnessUtxo proves that an intent whose
// prevout tx hashes correctly to the spent outpoint can no longer assert an
// unrelated amount or script through the witness utxo the VM introspects.
func TestPrevOutFetcherForIntentReconcilesWitnessUtxo(t *testing.T) {
	honestScript := testPkScript(0xaa)
	prevTx := newFundingTx(10_000, honestScript)
	outpoint := wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	// input 0 is the BIP322 message input: zero value, mirroring the script of
	// the first real input
	newIntent := func(t *testing.T, op wire.OutPoint, witnessUtxo *wire.TxOut) *psbt.Packet {
		t.Helper()
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{5}}})
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: op})
		tx.AddTxOut(&wire.TxOut{Value: 500, PkScript: testPkScript(0xdd)})
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		ptx.Inputs[0].WitnessUtxo = &wire.TxOut{PkScript: witnessUtxo.PkScript}
		ptx.Inputs[1].WitnessUtxo = witnessUtxo
		require.NoError(t, txutils.SetArkPsbtField(ptx, 1, arkade.PrevArkTxField, *prevTx))
		return ptx
	}

	t.Run("inflated value is rejected", func(t *testing.T) {
		ptx := newIntent(t, outpoint, &wire.TxOut{Value: 100_000_000, PkScript: honestScript})
		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "value mismatch")
	})

	t.Run("forged script is rejected", func(t *testing.T) {
		ptx := newIntent(t, outpoint, &wire.TxOut{Value: 10_000, PkScript: testPkScript(0xbb)})
		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "script mismatch")
	})

	t.Run("output index out of range is rejected", func(t *testing.T) {
		op := wire.OutPoint{Hash: prevTx.TxHash(), Index: 7}
		ptx := newIntent(t, op, &wire.TxOut{Value: 10_000, PkScript: honestScript})
		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "out of range")
	})

	t.Run("missing prevout tx field is rejected", func(t *testing.T) {
		ptx := newIntent(t, outpoint, &wire.TxOut{Value: 10_000, PkScript: honestScript})
		ptx.Inputs[1].Unknowns = nil
		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "missing prevout tx for input 1")
	})

	t.Run("matching prevout is accepted", func(t *testing.T) {
		ptx := newIntent(t, outpoint, &wire.TxOut{Value: 10_000, PkScript: honestScript})
		fetcher, err := prevOutFetcherForIntent(ptx)
		require.NoError(t, err)
		require.Equal(t, honestScript, fetcher.FetchVtxoPrevOutPkScript(outpoint))
	})
}

// TestPrevOutFetcherForOnchainTxReconcilesWitnessUtxo is the SubmitOnchainTx
// counterpart of TestPrevOutFetcherForIntentReconcilesWitnessUtxo.
func TestPrevOutFetcherForOnchainTxReconcilesWitnessUtxo(t *testing.T) {
	honestScript := testPkScript(0xaa)
	prevTx := newFundingTx(10_000, honestScript)
	outpoint := wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	newOnchain := func(t *testing.T, witnessUtxo *wire.TxOut) *psbt.Packet {
		t.Helper()
		ptx := newSpendingPacket(t, outpoint, witnessUtxo)
		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, *prevTx))
		return ptx
	}

	t.Run("inflated value is rejected", func(t *testing.T) {
		ptx := newOnchain(t, &wire.TxOut{Value: 100_000_000, PkScript: honestScript})
		_, err := prevOutFetcherForOnchainTx(ptx)
		require.ErrorContains(t, err, "value mismatch")
	})

	t.Run("forged script is rejected", func(t *testing.T) {
		ptx := newOnchain(t, &wire.TxOut{Value: 10_000, PkScript: testPkScript(0xbb)})
		_, err := prevOutFetcherForOnchainTx(ptx)
		require.ErrorContains(t, err, "script mismatch")
	})

	t.Run("matching prevout is accepted", func(t *testing.T) {
		ptx := newOnchain(t, &wire.TxOut{Value: 10_000, PkScript: honestScript})
		_, err := prevOutFetcherForOnchainTx(ptx)
		require.NoError(t, err)
	})
}

// TestPrevOutFetcherForArkTxReconcilesCheckpointWitnessUtxo proves the ark tx
// flow reconciles the verified prevout tx against the checkpoint input it
// actually funds. The prevout tx carried by an ark tx input describes the
// checkpoint's input 0, not the ark input itself.
func TestPrevOutFetcherForArkTxReconcilesCheckpointWitnessUtxo(t *testing.T) {
	vtxoScript := testPkScript(0xaa)
	checkpointOutScript := testPkScript(0xcc)
	prevTx := newFundingTx(10_000, vtxoScript)
	vtxoOutpoint := wire.OutPoint{Hash: prevTx.TxHash(), Index: 0}

	build := func(t *testing.T, checkpointWitnessUtxo *wire.TxOut) (*psbt.Packet, []*psbt.Packet) {
		t.Helper()

		cpTx := wire.NewMsgTx(2)
		cpTx.AddTxIn(&wire.TxIn{PreviousOutPoint: vtxoOutpoint})
		cpTx.AddTxOut(&wire.TxOut{Value: 9_500, PkScript: checkpointOutScript})

		checkpoint, err := psbt.NewFromUnsignedTx(cpTx)
		require.NoError(t, err)
		checkpoint.Inputs[0].WitnessUtxo = checkpointWitnessUtxo

		arkPtx := newSpendingPacket(
			t,
			wire.OutPoint{Hash: checkpoint.UnsignedTx.TxHash(), Index: 0},
			&wire.TxOut{Value: 9_500, PkScript: checkpointOutScript},
		)
		require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevArkTxField, *prevTx))

		return arkPtx, []*psbt.Packet{checkpoint}
	}

	t.Run("inflated checkpoint value is rejected", func(t *testing.T) {
		arkPtx, checkpoints := build(t, &wire.TxOut{Value: 100_000_000, PkScript: vtxoScript})
		_, err := prevOutFetcherForArkTx(arkPtx, checkpoints)
		require.ErrorContains(t, err, "value mismatch")
	})

	t.Run("forged checkpoint script is rejected", func(t *testing.T) {
		arkPtx, checkpoints := build(t, &wire.TxOut{Value: 10_000, PkScript: testPkScript(0xbb)})
		_, err := prevOutFetcherForArkTx(arkPtx, checkpoints)
		require.ErrorContains(t, err, "script mismatch")
	})

	t.Run("missing checkpoint witness utxo is rejected", func(t *testing.T) {
		arkPtx, checkpoints := build(t, nil)
		_, err := prevOutFetcherForArkTx(arkPtx, checkpoints)
		require.ErrorContains(t, err, "witness utxo")
	})

	t.Run("matching prevout is accepted", func(t *testing.T) {
		arkPtx, checkpoints := build(t, &wire.TxOut{Value: 10_000, PkScript: vtxoScript})
		fetcher, err := prevOutFetcherForArkTx(arkPtx, checkpoints)
		require.NoError(t, err)
		require.Equal(
			t,
			vtxoScript,
			fetcher.FetchVtxoPrevOutPkScript(arkPtx.UnsignedTx.TxIn[0].PreviousOutPoint),
		)
	})
}

func TestSubmitOnchainTxRejectsAnyOneCanPayPrevoutLie(t *testing.T) {
	emulatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	const (
		signedAmount        = int64(10_000)
		realOtherAmount     = int64(1_000)
		declaredOtherAmount = int64(9_000_000)
	)
	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(1).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddInt64(declaredOtherAmount).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)
	tweakedKey := arkade.ComputeArkadeScriptPublicKey(emulatorKey.PubKey(), arkade.ArkadeScriptHash(arkadeScript))
	closure := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{tweakedKey}}
	vtxoScript := arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{closure}}
	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)
	pkScript, err := arkscript.P2TRScript(tapKey)
	require.NoError(t, err)
	leafScript, err := closure.Script()
	require.NoError(t, err)
	proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(leafScript).TapHash())
	require.NoError(t, err)

	previousTx := func(marker byte, value int64) *wire.MsgTx {
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{marker}}})
		tx.AddTxOut(&wire.TxOut{Value: value, PkScript: pkScript})
		return tx
	}
	signedPrevTx := previousTx(1, signedAmount)
	otherPrevTx := previousTx(2, realOtherAmount)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: signedPrevTx.TxHash()}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: otherPrevTx.TxHash()}})
	tx.AddTxOut(&wire.TxOut{Value: signedAmount, PkScript: pkScript})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	packet.Inputs[0].WitnessUtxo = signedPrevTx.TxOut[0]
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: proof.ControlBlock,
		Script:       proof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	packet.Inputs[0].SighashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	packet.Inputs[1].WitnessUtxo = &wire.TxOut{Value: declaredOtherAmount, PkScript: pkScript}
	require.NoError(t, txutils.SetArkPsbtField(packet, 0, arkade.PrevoutTxField, *signedPrevTx))
	require.NoError(t, txutils.SetArkPsbtField(packet, 1, arkade.PrevoutTxField, *otherPrevTx))

	emulatorPacket, err := arkade.NewPacket(arkade.EmulatorEntry{Vin: 0, Script: arkadeScript})
	require.NoError(t, err)
	packetOutput, err := extension.Extension{emulatorPacket}.TxOut()
	require.NoError(t, err)
	packet.UnsignedTx.AddTxOut(packetOutput)
	packet.Outputs = append(packet.Outputs, psbt.POutput{})

	service := &service{
		signer:        signer{secretKey: emulatorKey},
		arkdPubKey:    arkdKey.PubKey(),
		computeLimits: arkade.DefaultComputeLimits(),
	}
	_, err = service.SubmitOnchainTx(context.Background(), OnchainTx{Tx: packet})
	require.ErrorContains(t, err, "prevout tx value mismatch for input 1")
}

func TestPrevOutFetcherForIntentMessageInput(t *testing.T) {
	pkScript := testPkScript(0xaa)

	realPrevTx := wire.NewMsgTx(2)
	realPrevTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}}})
	realPrevTx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: pkScript})

	newIntentProof := func(t *testing.T, messageUtxo *wire.TxOut) *psbt.Packet {
		t.Helper()
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{2}}})
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: realPrevTx.TxHash()}})
		tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: []byte{txscript.OP_RETURN}})
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		ptx.Inputs[0].WitnessUtxo = messageUtxo
		ptx.Inputs[1].WitnessUtxo = realPrevTx.TxOut[0]
		require.NoError(t, txutils.SetArkPsbtField(ptx, 1, arkade.PrevArkTxField, *realPrevTx))
		return ptx
	}

	t.Run("valid message input", func(t *testing.T) {
		ptx := newIntentProof(t, &wire.TxOut{PkScript: pkScript})
		fetcher, err := prevOutFetcherForIntent(ptx)
		require.NoError(t, err)

		messageOutpoint := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
		require.Equal(t, pkScript, fetcher.FetchVtxoPrevOutPkScript(messageOutpoint))

		realOutpoint := ptx.UnsignedTx.TxIn[1].PreviousOutPoint
		require.Equal(t, pkScript, fetcher.FetchVtxoPrevOutPkScript(realOutpoint))
	})

	t.Run("non-zero message input value with fabricated prevout tx", func(t *testing.T) {
		fabricatedPrevTx := wire.NewMsgTx(2)
		fabricatedPrevTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{3}}})
		fabricatedPrevTx.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: pkScript})

		ptx := newIntentProof(t, fabricatedPrevTx.TxOut[0])
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = fabricatedPrevTx.TxHash()
		require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevArkTxField, *fabricatedPrevTx))

		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "intent message input witness utxo is invalid")
	})

	t.Run("message input script does not mirror first real input", func(t *testing.T) {
		otherScript := []byte{txscript.OP_RETURN}
		ptx := newIntentProof(t, &wire.TxOut{PkScript: otherScript})
		_, err := prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "intent message input witness utxo is invalid")
	})

	t.Run("single input", func(t *testing.T) {
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{2}}})
		tx.AddTxOut(&wire.TxOut{Value: 0, PkScript: []byte{txscript.OP_RETURN}})
		ptx, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)
		ptx.Inputs[0].WitnessUtxo = &wire.TxOut{PkScript: pkScript}

		_, err = prevOutFetcherForIntent(ptx)
		require.ErrorContains(t, err, "intent proof must have at least 2 inputs")
	})
}

type fixtures struct {
	Valid   []validFixture   `json:"valid"`
	Invalid []invalidFixture `json:"invalid"`
}

type validFixture struct {
	Name                  string   `json:"name"`
	Psbt                  string   `json:"psbt"`
	Checkpoints           []string `json:"checkpoints"`
	ExpectedVtxoPkScripts []string `json:"expectedVtxoPkScripts"`
	ErrorContains         string   `json:"errorContains"`
}

type invalidFixture struct {
	Name          string   `json:"name"`
	Psbt          string   `json:"psbt"`
	Checkpoints   []string `json:"checkpoints"`
	ErrorContains string   `json:"errorContains"`
}

func readPrevOutFixtures(t testing.TB) fixtures {
	t.Helper()

	data, err := os.ReadFile("testdata/ark_prevout_fetcher.json")
	require.NoError(t, err)

	var fix fixtures
	require.NoError(t, json.Unmarshal(data, &fix))

	return fix
}

type onchainFixtures struct {
	Valid   []onchainValidFixture   `json:"valid"`
	Invalid []onchainInvalidFixture `json:"invalid"`
}

type onchainValidFixture struct {
	Name          string `json:"name"`
	Psbt          string `json:"psbt"`
	ErrorContains string `json:"errorContains"`
}

type onchainInvalidFixture struct {
	Name          string `json:"name"`
	Psbt          string `json:"psbt"`
	ErrorContains string `json:"errorContains"`
}

func readOnchainPrevOutFixtures(t testing.TB) onchainFixtures {
	t.Helper()

	data, err := os.ReadFile("testdata/onchain_prevout_fetcher.json")
	require.NoError(t, err)

	var fix onchainFixtures
	require.NoError(t, json.Unmarshal(data, &fix))

	return fix
}

func newPrevOutFetcher(
	ptx *psbt.Packet, checkpoints []*psbt.Packet,
) (arkade.ArkPrevOutFetcher, error) {
	if len(checkpoints) == 0 {
		return prevOutFetcherForIntent(ptx)
	}

	return prevOutFetcherForArkTx(ptx, checkpoints)
}

func decodePSBT(t testing.TB, b64 string) *psbt.Packet {
	t.Helper()

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	require.NoError(t, err)

	return ptx
}

func decodePSBTs(t testing.TB, b64Packets []string) []*psbt.Packet {
	t.Helper()

	packets := make([]*psbt.Packet, 0, len(b64Packets))
	for _, b64 := range b64Packets {
		ptx := decodePSBT(t, b64)
		packets = append(packets, ptx)
	}

	return packets
}

// testPkScript builds a deterministic p2tr-looking output script.
func testPkScript(b byte) []byte {
	return append([]byte{txscript.OP_1, 0x20}, bytes.Repeat([]byte{b}, 32)...)
}

func newFundingTx(value int64, pkScript []byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{9}, Index: 0}})
	tx.AddTxOut(&wire.TxOut{Value: value, PkScript: pkScript})
	return tx
}

func newSpendingPacket(t testing.TB, prevout wire.OutPoint, witnessUtxo *wire.TxOut) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevout})
	tx.AddTxOut(&wire.TxOut{Value: 500, PkScript: testPkScript(0xdd)})

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Inputs[0].WitnessUtxo = witnessUtxo

	return ptx
}
