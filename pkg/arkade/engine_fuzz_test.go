package arkade

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func FuzzNewEngineExecuteArbitraryNoPanic(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzz.NewConsumer(data)

		tx, scriptPubKey := fuzzMsgTx(t, fz)

		txIdx := -1
		if b, err := fz.GetByte(); err == nil {
			txIdx = int(b)%(len(tx.TxIn)+3) - 1
		}

		prevoutFetcher, inputAmount := fuzzPrevFetcher(t, fz, &tx, txIdx)

		sigCache := txscript.NewSigCache(32)
		hashCache := txscript.NewTxSigHashes(&tx, prevoutFetcher)

		vm, err := NewEngine(scriptPubKey, &tx, txIdx, sigCache, hashCache, inputAmount, prevoutFetcher)

		if err == nil {
			_ = vm.Execute()
		}
	})
}

func FuzzNewEngineExecuteTaprootScriptPathNoPanic(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzz.NewConsumer(data)

		tx, scriptPubKey := fuzzMsgTxWithTaprootScriptPath(t, fz)
		txIdx := 0

		prevoutFetcher, inputAmount := fuzzPrevFetcher(t, fz, &tx, txIdx)

		sigCache := txscript.NewSigCache(32)
		hashCache := txscript.NewTxSigHashes(&tx, prevoutFetcher)

		vm, err := NewEngine(scriptPubKey, &tx, txIdx, sigCache, hashCache, inputAmount, prevoutFetcher)

		if err == nil {
			_ = vm.Execute()
		}
	})
}

func FuzzNewEngineExecuteCommittedTaprootScriptPathNoPanic(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzz.NewConsumer(data)

		tx, scriptPubKey := fuzzMsgTxWithCommittedTaprootScriptPath(t, fz)
		txIdx := 0

		prevoutFetcher, inputAmount := fuzzPrevFetcher(t, fz, &tx, txIdx)

		sigCache := txscript.NewSigCache(32)
		hashCache := txscript.NewTxSigHashes(&tx, prevoutFetcher)

		vm, err := NewEngine(scriptPubKey, &tx, txIdx, sigCache, hashCache, inputAmount, prevoutFetcher)

		if err == nil {
			_ = vm.Execute()
		}
	})
}

func fuzzMsgTx(t *testing.T, fz *fuzz.ConsumeFuzzer) (wire.MsgTx, []byte) {
	t.Helper()

	// Step 1: Build a mostly-random transaction shell with at least one input.
	var tx wire.MsgTx
	_ = fz.GenerateStruct(&tx.Version)
	_ = fz.GenerateStruct(&tx.LockTime)
	inCount := 1
	if b, err := fz.GetByte(); err == nil {
		inCount = int(b%8) + 1
	}
	outCount := 0
	if b, err := fz.GetByte(); err == nil {
		outCount = int(b % 8)
	}

	// Step 2: Fill the inputs with random outpoints, sequences, and sigscripts.
	tx.TxIn = make([]*wire.TxIn, inCount)
	for i := range tx.TxIn {
		in := &wire.TxIn{}
		_ = fz.GenerateStruct(&in.PreviousOutPoint)
		_ = fz.GenerateStruct(&in.Sequence)
		in.SignatureScript, _ = fz.GetBytes()
		tx.TxIn[i] = in
	}

	// Step 3: Fill the outputs with random values and scripts.
	tx.TxOut = make([]*wire.TxOut, outCount)
	for i := range tx.TxOut {
		out := &wire.TxOut{}
		_ = fz.GenerateStruct(&out.Value)
		out.PkScript, _ = fz.GetBytes()
		tx.TxOut[i] = out
	}

	// Step 4: Return a fully arbitrary scriptPubKey for NewEngine.
	scriptPubKey, _ := fz.GetBytes()

	return tx, scriptPubKey
}

func fuzzMsgTxWithTaprootScriptPath(t *testing.T, fz *fuzz.ConsumeFuzzer) (wire.MsgTx, []byte) {
	t.Helper()

	// Step 1: Build a random transaction shell with at least one input.
	var tx wire.MsgTx
	_ = fz.GenerateStruct(&tx.Version)
	_ = fz.GenerateStruct(&tx.LockTime)
	inCount := 1
	if b, err := fz.GetByte(); err == nil {
		inCount = int(b%4) + 1
	}
	outCount := 0
	if b, err := fz.GetByte(); err == nil {
		outCount = int(b % 4)
	}

	// Step 2: Build script-path-shaped witnesses.
	tx.TxIn = make([]*wire.TxIn, inCount)
	for i := range tx.TxIn {
		in := &wire.TxIn{}
		_ = fz.GenerateStruct(&in.PreviousOutPoint)
		_ = fz.GenerateStruct(&in.Sequence)
		in.SignatureScript = nil

		script, _ := fz.GetBytes()

		keySeed, _ := fz.GetBytes()
		priv, _ := btcec.PrivKeyFromBytes(normalizePrivKeySeed(keySeed))

		controlBlock := make([]byte, 33)
		controlBlock[0] = byte(txscript.BaseLeafVersion)
		copy(controlBlock[1:], schnorr.SerializePubKey(priv.PubKey()))

		stackCount := 0
		if b, err := fz.GetByte(); err == nil {
			stackCount = int(b % 3)
		}
		in.Witness = make(wire.TxWitness, 0, stackCount+2)
		for range stackCount {
			elem, _ := fz.GetBytes()
			in.Witness = append(in.Witness, elem)
		}
		in.Witness = append(in.Witness, script, controlBlock)
		tx.TxIn[i] = in
	}

	// Step 3: Fill the outputs with random values and scripts.
	tx.TxOut = make([]*wire.TxOut, outCount)
	for i := range tx.TxOut {
		out := &wire.TxOut{}
		_ = fz.GenerateStruct(&out.Value)
		out.PkScript, _ = fz.GetBytes()
		tx.TxOut[i] = out
	}

	// Step 4: Return a taproot witness program with a random 32-byte program.
	prog, _ := fz.GetBytes()
	if len(prog) < 32 {
		p := make([]byte, 32)
		copy(p, prog)
		prog = p
	}
	prog = prog[:32]
	scriptPubKey := append([]byte{OP_1, 0x20}, prog...)
	return tx, scriptPubKey
}

func fuzzMsgTxWithCommittedTaprootScriptPath(t *testing.T, fz *fuzz.ConsumeFuzzer) (wire.MsgTx, []byte) {
	t.Helper()

	// Step 1: Build the smallest transaction shell that can exercise the full
	// taproot script-path flow.
	var tx wire.MsgTx
	_ = fz.GenerateStruct(&tx.Version)
	_ = fz.GenerateStruct(&tx.LockTime)
	tx.TxIn = []*wire.TxIn{{}}
	_ = fz.GenerateStruct(&tx.TxIn[0].PreviousOutPoint)
	_ = fz.GenerateStruct(&tx.TxIn[0].Sequence)
	tx.TxIn[0].SignatureScript = nil

	// Step 2: Choose a small parseable tapscript plus any stack items it needs.
	script := []byte{OP_TRUE}
	initialStack := wire.TxWitness{}
	if b, err := fz.GetByte(); err == nil {
		switch b % 3 {
		case 1:
			script = []byte{OP_DUP, OP_DROP, OP_TRUE}
			initialStack = wire.TxWitness{[]byte{0x01}}
		case 2:
			script = []byte{OP_IF, OP_TRUE, OP_ELSE, OP_TRUE, OP_ENDIF}
			initialStack = wire.TxWitness{[]byte{0x01}}
		}
	}

	// Step 3: Build a coherent taproot output key and matching control block so
	// execution can get past the leaf-commitment checks.
	keySeed, _ := fz.GetBytes()
	internalPriv, _ := btcec.PrivKeyFromBytes(normalizePrivKeySeed(keySeed))

	leaf := txscript.NewBaseTapLeaf(script)
	leafHash := leaf.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalPriv.PubKey(), leafHash[:])

	controlBlock := &txscript.ControlBlock{
		InternalKey:     internalPriv.PubKey(),
		LeafVersion:     txscript.BaseLeafVersion,
		OutputKeyYIsOdd: outputKey.SerializeCompressed()[0] == 0x03,
	}
	controlBytes, _ := controlBlock.ToBytes()

	witness := append(initialStack, script, controlBytes)
	tx.TxIn[0].Witness = witness

	// Step 4: Return the taproot output script that commits to the witness
	// script above.
	scriptPubKey, _ := txscript.PayToTaprootScript(outputKey)
	return tx, scriptPubKey
}

func fuzzPrevFetcher(t *testing.T, consumer *fuzz.ConsumeFuzzer, tx *wire.MsgTx, txIdx int) (ArkPrevOutFetcher, int64) {
	t.Helper()

	// Step 1: Build a random prevout set for every input in the transaction.
	prevouts := make(map[wire.OutPoint]*wire.TxOut, len(tx.TxIn))
	for _, txIn := range tx.TxIn {
		pkScript, _ := consumer.GetBytes()
		value, _ := consumer.GetInt()
		prevouts[txIn.PreviousOutPoint] = &wire.TxOut{
			Value:    int64(value),
			PkScript: pkScript,
		}
	}

	// Step 2: Return both the fetcher and the selected prevout amount when the
	// index is valid.
	fetcher := newTestArkPrevOutFetcher(txscript.NewMultiPrevOutFetcher(prevouts), nil, nil)
	inputAmount := int64(0)
	if txIdx >= 0 && txIdx < len(tx.TxIn) {
		if prev := fetcher.FetchPrevOutput(tx.TxIn[txIdx].PreviousOutPoint); prev != nil {
			inputAmount = prev.Value
		}
	}
	return fetcher, inputAmount
}

func normalizePrivKeySeed(seed []byte) []byte {
	key := make([]byte, 32)
	copy(key, seed)

	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		key[0] = 1
	}

	return key
}
