package arkade

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestArkadeScriptExecuteUsesSpendingTapLeafForSighash(t *testing.T) {
	t.Parallel()

	signingKey, _ := btcec.PrivKeyFromBytes([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	})
	pubKeyX := schnorr.SerializePubKey(signingKey.PubKey())
	arkadeScript, err := txscript.NewScriptBuilder().
		AddData(pubKeyX).
		AddOp(OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	closureTapLeaf := txscript.NewBaseTapLeaf([]byte{OP_TRUE})
	require.NotEqual(t, closureTapLeaf.TapHash(),
		txscript.NewBaseTapLeaf(arkadeScript).TapHash(),
		"test requires the spending leaf to differ from the arkade script")

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x01}, Index: 0}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: outpoint,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    900,
			PkScript: []byte{OP_TRUE},
		}},
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		outpoint: {Value: 1_000, PkScript: []byte{OP_1, 0x20}},
	}
	prevOutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(prevOuts), nil, nil,
	)
	sighashes := txscript.NewTxSigHashes(tx, prevOutFetcher)
	digest, err := CalcArkadeScriptSignatureHash(
		sighashes, txscript.SigHashDefault, tx, 0, prevOutFetcher,
		closureTapLeaf, BlankCodeSepValue,
	)
	require.NoError(t, err)

	sig, err := schnorr.Sign(signingKey, digest)
	require.NoError(t, err)

	script := &ArkadeScript{
		script:          arkadeScript,
		witness:         wire.TxWitness{sig.Serialize()},
		spendingTapLeaf: closureTapLeaf,
	}
	require.NoError(t, script.Execute(tx, prevOutFetcher, 0))
}

func TestArkadeScriptExecuteUsesCodeSeparatorForSighash(t *testing.T) {
	t.Parallel()

	signingKey, _ := btcec.PrivKeyFromBytes([]byte{
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	})
	pubKeyX := schnorr.SerializePubKey(signingKey.PubKey())
	// OP_CODESEPARATOR is the first opcode (position 0). Per BIP342 it sets
	// codesep_pos to its own opcode position, which the following OP_CHECKSIG
	// must commit to.
	arkadeScript, err := txscript.NewScriptBuilder().
		AddOp(OP_CODESEPARATOR).
		AddData(pubKeyX).
		AddOp(OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	spendingTapLeaf := txscript.NewBaseTapLeaf([]byte{OP_TRUE})
	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x02}, Index: 0}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: outpoint,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    900,
			PkScript: []byte{OP_TRUE},
		}},
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		outpoint: {Value: 1_000, PkScript: []byte{OP_1, 0x20}},
	}
	prevOutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(prevOuts), nil, nil,
	)
	sighashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	const codeSepPos = uint32(0) // OP_CODESEPARATOR is opcode 0 in the script.

	// A signature that commits to the executed code-separator position must
	// verify.
	digest, err := CalcArkadeScriptSignatureHash(
		sighashes, txscript.SigHashDefault, tx, 0, prevOutFetcher,
		spendingTapLeaf, codeSepPos,
	)
	require.NoError(t, err)
	sig, err := schnorr.Sign(signingKey, digest)
	require.NoError(t, err)
	script := &ArkadeScript{
		script:          arkadeScript,
		witness:         wire.TxWitness{sig.Serialize()},
		spendingTapLeaf: spendingTapLeaf,
	}
	require.NoError(t, script.Execute(tx, prevOutFetcher, 0),
		"signature committing to the executed codesep position must verify")

	// A signature that ignores the code separator (blank codesep_pos, the
	// pre-BIP342 behavior) must now be rejected.
	staleDigest, err := CalcArkadeScriptSignatureHash(
		sighashes, txscript.SigHashDefault, tx, 0, prevOutFetcher,
		spendingTapLeaf, BlankCodeSepValue,
	)
	require.NoError(t, err)
	staleSig, err := schnorr.Sign(signingKey, staleDigest)
	require.NoError(t, err)
	staleScript := &ArkadeScript{
		script:          arkadeScript,
		witness:         wire.TxWitness{staleSig.Serialize()},
		spendingTapLeaf: spendingTapLeaf,
	}
	require.Error(t, staleScript.Execute(tx, prevOutFetcher, 0),
		"signature ignoring the code separator must fail")
}

func TestArkadeScriptExecuteUpdatesCodeSepPosOnCodeSeparator(t *testing.T) {
	t.Parallel()

	// OP_CODESEPARATOR is opcode 0; OP_TRUE leaves a truthy stack so execution
	// completes successfully and we can observe codesep_pos at each step.
	arkadeScript := []byte{OP_CODESEPARATOR, OP_TRUE}

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x04}, Index: 0}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: outpoint,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    900,
			PkScript: []byte{OP_TRUE},
		}},
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		outpoint: {Value: 1_000, PkScript: []byte{OP_1, 0x20}},
	}
	prevOutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(prevOuts), nil, nil,
	)

	script := &ArkadeScript{
		script:          arkadeScript,
		spendingTapLeaf: txscript.NewBaseTapLeaf([]byte{OP_TRUE}),
	}

	var seen []uint32
	err := script.Execute(tx, prevOutFetcher, 0,
		WithDebugCallback(func(_ *StepInfo, e *Engine) error {
			seen = append(seen, e.taprootCtx.codeSepPos)
			return nil
		}),
	)
	require.NoError(t, err)

	// The callback fires once for the initial state, then after each step.
	require.GreaterOrEqual(t, len(seen), 2)
	require.Equal(t, BlankCodeSepValue, seen[0],
		"codesep_pos must start at the blank sentinel")
	require.Equal(t, uint32(0), seen[1],
		"codesep_pos must equal the OP_CODESEPARATOR opcode position after it executes")
}

func TestArkadeScriptExecuteOpSighashUsesCodeSeparatorPosition(t *testing.T) {
	t.Parallel()

	spendingTapLeaf := txscript.NewBaseTapLeaf([]byte{OP_TRUE})

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x05}, Index: 0}
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: outpoint,
			Sequence:         0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:    900,
			PkScript: []byte{OP_TRUE},
		}},
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{
		outpoint: {Value: 1_000, PkScript: []byte{OP_1, 0x20}},
	}
	prevOutFetcher := newTestArkPrevOutFetcher(
		txscript.NewMultiPrevOutFetcher(prevOuts), nil, nil,
	)
	sighashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	expectedDigest, err := CalcArkadeScriptSignatureHash(
		sighashes, txscript.SigHashDefault, tx, 0, prevOutFetcher,
		spendingTapLeaf, 0,
	)
	require.NoError(t, err)
	blankDigest, err := CalcArkadeScriptSignatureHash(
		sighashes, txscript.SigHashDefault, tx, 0, prevOutFetcher,
		spendingTapLeaf, BlankCodeSepValue,
	)
	require.NoError(t, err)
	require.NotEqual(t, blankDigest, expectedDigest,
		"test requires the code separator position to affect OP_SIGHASH")

	arkadeScript, err := txscript.NewScriptBuilder().
		AddOp(OP_CODESEPARATOR).
		AddOp(OP_0).
		AddOp(OP_SIGHASH).
		AddData(expectedDigest).
		AddOp(OP_EQUAL).
		Script()
	require.NoError(t, err)

	script := &ArkadeScript{
		script:          arkadeScript,
		spendingTapLeaf: spendingTapLeaf,
	}
	require.NoError(t, script.Execute(tx, prevOutFetcher, 0),
		"OP_SIGHASH must include the last executed OP_CODESEPARATOR position")
}

func TestReadArkadeScriptRejectsNonBaseSpendingTapLeafVersion(t *testing.T) {
	t.Parallel()

	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	arkadeScript := []byte{OP_TRUE}
	tweakedPubKey := ComputeArkadeScriptPublicKey(
		signerKey.PubKey(), ArkadeScriptHash(arkadeScript),
	)
	closure := scriptlib.MultisigClosure{
		PubKeys: []*btcec.PublicKey{tweakedPubKey},
	}
	spendingScript, err := closure.Script()
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x03}, Index: 0},
	})
	tx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: []byte{OP_TRUE}})

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script:      spendingScript,
		LeafVersion: txscript.TapscriptLeafVersion(txscript.BaseLeafVersion + 2),
	}}

	_, err = ReadArkadeScript(ptx, signerKey.PubKey(), EmulatorEntry{
		Vin:    0,
		Script: arkadeScript,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported taproot leaf version")
}

func TestReadArkadeScript(t *testing.T) {
	fix := readScriptFixtures(t)

	t.Run("valid", func(t *testing.T) {
		for _, f := range fix.Valid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				signerPubKey := decodeXOnlyPubKey(t, f.SignerPublicKey)
				entry := decodeEntry(t, f.Entry)

				result, err := ReadArkadeScript(ptx, signerPubKey, entry)
				require.NoError(t, err)
				require.NotNil(t, result)

				require.Equal(t, entry.Script, result.script)
				require.Equal(t, ArkadeScriptHash(entry.Script), result.hash)
				require.Equal(t, len(entry.Witness), len(result.witness))
				for i := range entry.Witness {
					require.Equal(t, entry.Witness[i], result.witness[i])
				}

				expectedPubKey := ComputeArkadeScriptPublicKey(signerPubKey, result.hash)
				require.True(t, expectedPubKey.IsEqual(result.pubkey))

				tapscript := ptx.Inputs[entry.Vin].TaprootLeafScript[0].Script
				require.Equal(t, txscript.NewBaseTapLeaf(tapscript),
					result.spendingTapLeaf)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range fix.Invalid {
			t.Run(f.Name, func(t *testing.T) {
				ptx := decodePSBT(t, f.Psbt)
				signerPubKey := decodeXOnlyPubKey(t, f.SignerPublicKey)
				entry := decodeEntry(t, f.Entry)

				_, err := ReadArkadeScript(ptx, signerPubKey, entry)
				require.Error(t, err)
				require.Contains(t, err.Error(), f.ErrorContains)
			})
		}
	})
}

type scriptFixtureEntry struct {
	Vin     int      `json:"vin"`
	Script  string   `json:"script"`
	Witness []string `json:"witness"`
}

type validScriptFixture struct {
	Name            string             `json:"name"`
	SignerPublicKey string             `json:"signerPublicKey"`
	Psbt            string             `json:"psbt"`
	Entry           scriptFixtureEntry `json:"entry"`
}

type invalidScriptFixture struct {
	Name            string             `json:"name"`
	SignerPublicKey string             `json:"signerPublicKey"`
	Psbt            string             `json:"psbt"`
	Entry           scriptFixtureEntry `json:"entry"`
	ErrorContains   string             `json:"errorContains"`
}

type scriptFixtures struct {
	Valid   []validScriptFixture   `json:"valid"`
	Invalid []invalidScriptFixture `json:"invalid"`
}

func readScriptFixtures(t *testing.T) scriptFixtures {
	t.Helper()
	data, err := os.ReadFile("testdata/read_arkade_script.json")
	require.NoError(t, err)

	var fix scriptFixtures
	require.NoError(t, json.Unmarshal(data, &fix))
	return fix
}

func decodePSBT(t *testing.T, b64 string) *psbt.Packet {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	require.NoError(t, err)
	return ptx
}

func decodeXOnlyPubKey(t *testing.T, hexStr string) *btcec.PublicKey {
	t.Helper()
	data, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	pubKey, err := schnorr.ParsePubKey(data)
	require.NoError(t, err)
	return pubKey
}

func decodeEntry(t *testing.T, raw scriptFixtureEntry) EmulatorEntry {
	t.Helper()
	script, err := hex.DecodeString(raw.Script)
	require.NoError(t, err)

	witness := make(wire.TxWitness, len(raw.Witness))
	for i, w := range raw.Witness {
		witness[i], err = hex.DecodeString(w)
		require.NoError(t, err)
	}

	return EmulatorEntry{
		Vin:     uint16(raw.Vin),
		Script:  script,
		Witness: witness,
	}
}
