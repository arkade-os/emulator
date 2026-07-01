package arkade

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// checkSigLeafECDSA builds `<pubkey> OP_CHECKSIG` and runs it with sig as the
// sole witness item, returning the engine's Execute error.
func checkSigLeafECDSA(t *testing.T, extendedPubKey []byte,
	signCompact func(digest []byte) []byte) error {
	t.Helper()

	leaf, err := txscript.NewScriptBuilder().
		AddData(extendedPubKey).
		AddOp(OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	engine := runTapscriptLeaf(t, leaf, wire.TxWitness{nil}, 2_000_000)
	digest := arkadeDigest(t, &engine.tx, 0, engine.prevOutFetcher,
		leaf, txscript.SigHashDefault)
	engine.tx.TxIn[0].Witness[0] = signCompact(digest)
	return engine.Execute()
}

func TestOpCheckSigECDSASecp256k1(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	pk := append([]byte{0x10}, priv.PubKey().SerializeCompressed()...)
	err := checkSigLeafECDSA(t, pk, func(d []byte) []byte {
		return ecdsaK1Compact(t, priv, d)
	})
	require.NoError(t, err)
}

func TestOpCheckSigECDSASecp256r1(t *testing.T) {
	t.Parallel()
	priv, comp := r1CompressedPubKey(t)
	pk := append([]byte{0x11}, comp...)
	err := checkSigLeafECDSA(t, pk, func(d []byte) []byte {
		return ecdsaR1Compact(t, priv, d)
	})
	require.NoError(t, err)
}

func TestOpCheckSigECDSAWrongKeyRejected(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	other, _ := btcec.NewPrivateKey()
	pk := append([]byte{0x10}, priv.PubKey().SerializeCompressed()...)
	err := checkSigLeafECDSA(t, pk, func(d []byte) []byte {
		return ecdsaK1Compact(t, other, d) // signed by the wrong key
	})
	require.Error(t, err)
}

// verifies the explicit sighash-type byte path still works for ECDSA: a
// 65-byte sig (64 core + 0x01 SIGHASH_ALL) over the SIGHASH_ALL digest.
func TestOpCheckSigECDSAExplicitSighashByte(t *testing.T) {
	t.Parallel()
	priv, _ := btcec.NewPrivateKey()
	pk := append([]byte{0x10}, priv.PubKey().SerializeCompressed()...)

	leaf, err := txscript.NewScriptBuilder().AddData(pk).AddOp(OP_CHECKSIG).Script()
	require.NoError(t, err)
	engine := runTapscriptLeaf(t, leaf, wire.TxWitness{nil}, 2_000_000)
	digest := arkadeDigest(t, &engine.tx, 0, engine.prevOutFetcher,
		leaf, txscript.SigHashAll)
	engine.tx.TxIn[0].Witness[0] = append(
		ecdsaK1Compact(t, priv, digest), byte(txscript.SigHashAll))
	require.NoError(t, engine.Execute())
}
