package emulator

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// prevOutFetcherForIntent computes and validate prevouts for an intent tx
func prevOutFetcherForIntent(ptx *psbt.Packet) (arkade.ArkPrevOutFetcher, error) {
	baseFetcher, err := computePrevoutFetcher(ptx)
	if err != nil {
		return nil, err
	}

	prevoutTxs, err := decodePrevoutTxsFromField(ptx, arkade.PrevArkTxField)
	if err != nil {
		return nil, err
	}

	prevOutArkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(prevoutTxs))
	prevOutIdxs := make(map[wire.OutPoint]uint32, len(prevoutTxs))
	if len(ptx.Inputs) < 2 {
		return nil, fmt.Errorf("intent proof must have at least 2 inputs")
	}
	// Input 0 is always the BIP322 message input; its output carries zero value
	// and mirrors the first real input script.
	expected := &wire.TxOut{PkScript: ptx.Inputs[1].WitnessUtxo.PkScript}
	if !equalTxOut(ptx.Inputs[0].WitnessUtxo, expected) {
		return nil, fmt.Errorf("intent message input witness utxo is invalid")
	}
	outpoint := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
	prevOutArkTxs[outpoint] = &wire.MsgTx{TxOut: []*wire.TxOut{expected}}
	prevOutIdxs[outpoint] = 0
	for inputIndex := 1; inputIndex < len(ptx.Inputs); inputIndex++ {
		prevTx, ok := prevoutTxs[inputIndex]
		if !ok {
			return nil, fmt.Errorf("missing prevout tx for input %d", inputIndex)
		}
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		if err := validatePrevoutTx(inputIndex, prevTx, outpoint.Hash); err != nil {
			return nil, err
		}

		if err := reconcilePrevout(
			inputIndex, prevTx, outpoint.Index, ptx.Inputs[inputIndex].WitnessUtxo,
		); err != nil {
			return nil, err
		}

		prevOutArkTxs[outpoint] = prevTx
		prevOutIdxs[outpoint] = outpoint.Index
	}

	return newMapArkPrevOutFetcher(baseFetcher, prevOutArkTxs, prevOutIdxs), nil
}

// prevOutFetcherForArkTx computes and validate prevouts for an Ark tx using its checkpoints
func prevOutFetcherForArkTx(
	ptx *psbt.Packet, checkpoints []*psbt.Packet,
) (*mapArkPrevOutFetcher, error) {
	baseFetcher, err := computePrevoutFetcher(ptx)
	if err != nil {
		return nil, err
	}

	prevoutTxs, err := decodePrevoutTxsFromField(ptx, arkade.PrevArkTxField)
	if err != nil {
		return nil, err
	}

	checkpointsByTxid := make(map[string]*psbt.Packet, len(checkpoints))
	for _, checkpoint := range checkpoints {
		checkpointsByTxid[checkpoint.UnsignedTx.TxID()] = checkpoint
	}

	prevOutArkTxs := make(map[wire.OutPoint]*wire.MsgTx, len(prevoutTxs))
	prevOutIdxs := make(map[wire.OutPoint]uint32, len(prevoutTxs))
	for inputIndex := range ptx.Inputs {
		prevTx, ok := prevoutTxs[inputIndex]
		if !ok {
			return nil, fmt.Errorf("missing prevout tx for input %d", inputIndex)
		}
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		checkpointTxid := outpoint.Hash.String()
		checkpoint, ok := checkpointsByTxid[checkpointTxid]
		if !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}
		if len(checkpoint.Inputs) == 0 || len(checkpoint.UnsignedTx.TxIn) == 0 {
			return nil, fmt.Errorf("checkpoint has no inputs for input %d", inputIndex)
		}
		if len(checkpoint.Inputs) != 1 || len(checkpoint.UnsignedTx.TxIn) != 1 {
			return nil, fmt.Errorf("checkpoint must have exactly one input for ark input %d", inputIndex)
		}

		// the checkpoint txid is pinned by the ark input outpoint, so its
		// outputs are authenticated and the ark input witness utxo must agree
		if err := reconcilePrevout(
			inputIndex, checkpoint.UnsignedTx, outpoint.Index, ptx.Inputs[inputIndex].WitnessUtxo,
		); err != nil {
			return nil, fmt.Errorf("ark input: %w", err)
		}

		checkpointInputPrevout := checkpoint.UnsignedTx.TxIn[0].PreviousOutPoint
		if err := validatePrevoutTx(inputIndex, prevTx, checkpointInputPrevout.Hash); err != nil {
			return nil, err
		}

		// the prevout tx carried by an ark tx input funds the checkpoint input,
		// not the ark input itself, so it must be reconciled against the
		// checkpoint witness utxo
		if err := reconcilePrevout(
			inputIndex, prevTx, checkpointInputPrevout.Index, checkpoint.Inputs[0].WitnessUtxo,
		); err != nil {
			return nil, err
		}

		prevOutArkTxs[outpoint] = prevTx
		prevOutIdxs[outpoint] = checkpointInputPrevout.Index
	}

	return newMapArkPrevOutFetcher(baseFetcher, prevOutArkTxs, prevOutIdxs), nil
}

// prevOutFetcherForOnchainTx computes and validate prevouts for ExecuteOnchainTx
func prevOutFetcherForOnchainTx(ptx *psbt.Packet) (arkade.ArkPrevOutFetcher, error) {
	baseFetcher, err := computePrevoutFetcher(ptx)
	if err != nil {
		return nil, err
	}

	prevoutTxs, err := decodePrevoutTxsFromField(ptx, arkade.PrevoutTxField)
	if err != nil {
		return nil, err
	}

	prevOutTxs := make(map[wire.OutPoint]*wire.MsgTx, len(prevoutTxs))
	prevOutIdxs := make(map[wire.OutPoint]uint32, len(prevoutTxs))
	for inputIndex := range ptx.Inputs {
		prevTx, ok := prevoutTxs[inputIndex]
		if !ok {
			return nil, fmt.Errorf("missing prevout tx for input %d", inputIndex)
		}
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint

		if err := validatePrevoutTx(inputIndex, prevTx, outpoint.Hash); err != nil {
			return nil, err
		}

		if err := reconcilePrevout(
			inputIndex, prevTx, outpoint.Index, ptx.Inputs[inputIndex].WitnessUtxo,
		); err != nil {
			return nil, err
		}

		prevOutTxs[outpoint] = prevTx
		prevOutIdxs[outpoint] = outpoint.Index
	}

	return newMapArkPrevOutFetcher(baseFetcher, prevOutTxs, prevOutIdxs), nil
}

// decodePrevoutTxsFromField decodes prevout transactions from the given psbt field
// arkade.PrevArkTxField is used by offchain transactions
// arkade.PrevoutTxField is used by onchain transactions
func decodePrevoutTxsFromField(
	ptx *psbt.Packet, field txutils.ArkPsbtFieldCoder[wire.MsgTx],
) (map[int]*wire.MsgTx, error) {
	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("malformed psbt")
	}

	prevoutTxs := make(map[int]*wire.MsgTx)

	for inputIndex := range ptx.Inputs {
		fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, field)
		if err != nil {
			return nil, fmt.Errorf("failed to decode prevout tx for input %d: %w", inputIndex, err)
		}

		if len(fields) == 0 {
			continue
		}
		if len(fields) > 1 {
			return nil, fmt.Errorf("multiple prevout tx fields found for input %d", inputIndex)
		}

		prevTx := fields[0]
		prevTxCopy := prevTx
		prevoutTxs[inputIndex] = &prevTxCopy
	}

	return prevoutTxs, nil
}

type mapArkPrevOutFetcher struct {
	txscript.PrevOutputFetcher
	arkTxs      map[wire.OutPoint]*wire.MsgTx
	prevOutIdxs map[wire.OutPoint]uint32
}

func newMapArkPrevOutFetcher(
	base txscript.PrevOutputFetcher,
	arkTxs map[wire.OutPoint]*wire.MsgTx,
	prevOutIdxs map[wire.OutPoint]uint32,
) *mapArkPrevOutFetcher {
	return &mapArkPrevOutFetcher{
		PrevOutputFetcher: base,
		arkTxs:            arkTxs,
		prevOutIdxs:       prevOutIdxs,
	}
}

func (f *mapArkPrevOutFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if f.arkTxs == nil {
		return nil
	}
	return f.arkTxs[op]
}

func (f *mapArkPrevOutFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	prevOut := f.fetchVtxoPrevOut(op)
	if prevOut == nil {
		return nil
	}
	return prevOut.PkScript
}

func (f *mapArkPrevOutFetcher) fetchVtxoPrevOut(op wire.OutPoint) *wire.TxOut {
	if f.arkTxs == nil || f.prevOutIdxs == nil {
		return nil
	}

	idx, foundIdx := f.prevOutIdxs[op]
	arkTx, foundTx := f.arkTxs[op]

	if !foundIdx || !foundTx {
		return nil
	}

	if idx >= uint32(len(arkTx.TxOut)) {
		return nil
	}

	return arkTx.TxOut[idx]
}

func validatePrevoutTx(inputIndex int, prevTx *wire.MsgTx, expectedHash chainhash.Hash) error {
	actualHash := prevTx.TxHash()
	if actualHash != expectedHash {
		return fmt.Errorf(
			"prevout tx hash mismatch for input %d: got %s, expected %s",
			inputIndex, actualHash, expectedHash,
		)
	}

	return nil
}

// reconcilePrevout asserts the witness utxo asserted by the requester matches
// exactly the output it claims to spend on the verified prevout tx.
// The prevout tx only proves it hashes to the spent outpoint, it says nothing
// about the witness utxo: without this check a requester can pair a
// self-consistent prevout tx with a witness utxo declaring any amount and
// script, which is what the VM introspects and what the signature commits to.
func reconcilePrevout(
	inputIndex int, prevTx *wire.MsgTx, outputIndex uint32, witnessUtxo *wire.TxOut,
) error {
	if witnessUtxo == nil {
		return fmt.Errorf("witness utxo is nil for input %d", inputIndex)
	}

	if outputIndex >= uint32(len(prevTx.TxOut)) {
		return fmt.Errorf(
			"prevout tx output index out of range for input %d: index=%d outputs=%d",
			inputIndex, outputIndex, len(prevTx.TxOut),
		)
	}

	prevOut := prevTx.TxOut[outputIndex]
	if prevOut.Value != witnessUtxo.Value {
		return fmt.Errorf(
			"prevout tx value mismatch for input %d: got %d, expected %d",
			inputIndex, witnessUtxo.Value, prevOut.Value,
		)
	}

	if !bytes.Equal(prevOut.PkScript, witnessUtxo.PkScript) {
		return fmt.Errorf(
			"prevout tx script mismatch for input %d: got %x, expected %x",
			inputIndex, witnessUtxo.PkScript, prevOut.PkScript,
		)
	}

	return nil
}

func equalTxOut(a, b *wire.TxOut) bool {
	return a != nil && b != nil && a.Value == b.Value && bytes.Equal(a.PkScript, b.PkScript)
}

func computePrevoutFetcher(ptx *psbt.Packet) (txscript.PrevOutputFetcher, error) {
	prevouts := make(map[wire.OutPoint]*wire.TxOut)

	for index, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			return nil, fmt.Errorf("witness utxo is nil")
		}

		if len(ptx.UnsignedTx.TxIn) <= index {
			return nil, fmt.Errorf("input index out of range")
		}

		outpoint := ptx.UnsignedTx.TxIn[index].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	return txscript.NewMultiPrevOutFetcher(prevouts), nil
}

type packetScript struct {
	vin    int
	script *arkade.ArkadeScript
}

// packetScripts returns every emulator packet entry's arkade script, in packet order.
func packetScripts(ptx *psbt.Packet) ([]packetScript, error) {
	if ptx == nil || ptx.UnsignedTx == nil {
		return nil, fmt.Errorf("missing transaction")
	}
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse emulator packet: %w", err)
	}
	scripts := make([]packetScript, 0, len(packet))
	for _, entry := range packet {
		vin := int(entry.Vin)
		script, err := arkade.NewArkadeScript(ptx, entry)
		if err != nil {
			return nil, fmt.Errorf("failed to read arkade script: %w vin=%d", err, vin)
		}
		scripts = append(scripts, packetScript{vin, script})
	}
	return scripts, nil
}

// pushExpiryVins returns the input indexes whose emulator packet script uses
// OP_PUSHEXPIRY.
func pushExpiryVins(tx *wire.MsgTx) ([]int, error) {
	if tx == nil {
		return nil, fmt.Errorf("missing transaction")
	}
	packet, err := arkade.FindEmulatorPacket(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse emulator packet: %w", err)
	}
	var vins []int
	for _, entry := range packet {
		if int(entry.Vin) >= len(tx.TxIn) {
			continue
		}
		needsExpiry, err := hasPushExpiryOpcode(entry.Script)
		if err != nil {
			return nil, err
		}
		if needsExpiry {
			vins = append(vins, int(entry.Vin))
		}
	}
	return vins, nil
}

func hasPushExpiryOpcode(script []byte) (bool, error) {
	tokenizer := arkade.MakeScriptTokenizer(0, script)
	for tokenizer.Next() {
		if tokenizer.Opcode() == arkade.OP_PUSHEXPIRY {
			return true, nil
		}
	}
	return false, tokenizer.Err()
}

func expiryForScript(
	script []byte, outpoint wire.OutPoint, expiries map[wire.OutPoint]int64,
) (int64, error) {
	needsExpiry, err := hasPushExpiryOpcode(script)
	if err != nil || !needsExpiry {
		return 0, err
	}
	expiresAt, ok := expiries[outpoint]
	if !ok {
		return 0, fmt.Errorf("vtxo %s not found", outpoint)
	}
	if expiresAt <= 0 {
		return 0, fmt.Errorf("vtxo %s has no expiry", outpoint)
	}
	return expiresAt, nil
}

func indexCheckpoints(arkPtx *psbt.Packet, checkpoints []*psbt.Packet) (map[string]*psbt.Packet, error) {
	if arkPtx == nil || arkPtx.UnsignedTx == nil {
		return nil, fmt.Errorf("missing ark transaction")
	}
	if len(checkpoints) != len(arkPtx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("expected %d checkpoints, got %d", len(arkPtx.UnsignedTx.TxIn), len(checkpoints))
	}

	indexed := make(map[string]*psbt.Packet, len(checkpoints))
	for i, checkpoint := range checkpoints {
		if checkpoint == nil || checkpoint.UnsignedTx == nil {
			return nil, fmt.Errorf("checkpoint %d is missing its transaction", i)
		}
		txid := checkpoint.UnsignedTx.TxID()
		if _, exists := indexed[txid]; exists {
			return nil, fmt.Errorf("duplicate checkpoint %s", txid)
		}
		indexed[txid] = checkpoint
	}

	used := make(map[string]struct{}, len(arkPtx.UnsignedTx.TxIn))
	for inputIndex, input := range arkPtx.UnsignedTx.TxIn {
		txid := input.PreviousOutPoint.Hash.String()
		if _, ok := indexed[txid]; !ok {
			return nil, fmt.Errorf("checkpoint not found for input %d", inputIndex)
		}
		if _, exists := used[txid]; exists {
			return nil, fmt.Errorf("checkpoint %s is associated with multiple ark inputs", txid)
		}
		used[txid] = struct{}{}
	}

	return indexed, nil
}

func validateCheckpoint(
	arkPtx *psbt.Packet, inputIndex int, checkpoint *psbt.Packet,
	previousOutput *wire.TxOut, expectedLeaf txscript.TapLeaf,
) error {
	if inputIndex < 0 || inputIndex >= len(arkPtx.Inputs) || inputIndex >= len(arkPtx.UnsignedTx.TxIn) {
		return fmt.Errorf("ark input index out of range")
	}
	if checkpoint == nil || checkpoint.UnsignedTx == nil || len(checkpoint.Inputs) != 1 || len(checkpoint.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("checkpoint must have exactly one input")
	}
	if len(checkpoint.UnsignedTx.TxOut) != 2 {
		return fmt.Errorf("checkpoint must have one vtxo output and one anchor output")
	}

	arkOutpoint := arkPtx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
	if arkOutpoint.Hash != checkpoint.UnsignedTx.TxHash() {
		return fmt.Errorf("ark input does not spend checkpoint")
	}
	if arkOutpoint.Index != 0 {
		return fmt.Errorf("ark input must spend checkpoint output 0")
	}
	if !equalTxOut(arkPtx.Inputs[inputIndex].WitnessUtxo, checkpoint.UnsignedTx.TxOut[arkOutpoint.Index]) {
		return fmt.Errorf("checkpoint output does not match ark input witness utxo")
	}
	if !equalTxOut(checkpoint.UnsignedTx.TxOut[1], txutils.AnchorOutput()) {
		return fmt.Errorf("checkpoint anchor output is invalid")
	}

	if previousOutput == nil {
		return fmt.Errorf("missing authenticated previous ark output")
	}
	if !equalTxOut(checkpoint.Inputs[0].WitnessUtxo, previousOutput) {
		return fmt.Errorf("checkpoint input witness utxo does not match previous ark transaction")
	}
	if checkpoint.UnsignedTx.TxOut[0].Value != previousOutput.Value {
		return fmt.Errorf("checkpoint vtxo output value does not match its input")
	}

	if err := validateTaprootLeaf(arkPtx.Inputs[inputIndex], expectedLeaf); err != nil {
		return fmt.Errorf("ark input tapleaf: %w", err)
	}
	if err := validateTaprootLeaf(checkpoint.Inputs[0], expectedLeaf); err != nil {
		return fmt.Errorf("checkpoint tapleaf: %w", err)
	}

	return nil
}

func validateTaprootLeaf(input psbt.PInput, expectedLeaf txscript.TapLeaf) error {
	if input.WitnessUtxo == nil || !txscript.IsPayToTaproot(input.WitnessUtxo.PkScript) {
		return fmt.Errorf("witness utxo is not taproot")
	}
	if len(input.TaprootLeafScript) == 0 || input.TaprootLeafScript[0] == nil {
		return fmt.Errorf("missing taproot leaf script")
	}

	leaf := input.TaprootLeafScript[0]
	controlBlock, err := txscript.ParseControlBlock(leaf.ControlBlock)
	if err != nil {
		return fmt.Errorf("invalid control block: %w", err)
	}
	if controlBlock.LeafVersion != leaf.LeafVersion {
		return fmt.Errorf("control block leaf version does not match taproot leaf script")
	}
	if txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash() != expectedLeaf.TapHash() {
		return fmt.Errorf("tapleaf does not match ark input")
	}
	if err := txscript.VerifyTaprootLeafCommitment(controlBlock, input.WitnessUtxo.PkScript[2:], leaf.Script); err != nil {
		return fmt.Errorf("tapleaf is not committed by witness utxo: %w", err)
	}

	return nil
}

// approvedInput is an intent proof input carrying a valid tapscript signature of at least one closure key.
type approvedInput struct {
	prevout wire.TxOut
	script  *arkade.ArkadeScript
	// signers are the closure keys whose signature on the proof input verified
	signers []*btcec.PublicKey
}

// validateInput checks ptx's input spends the approved outpoint and prevout through the approved leaf.
func (a approvedInput) validateInput(ptx *psbt.Packet, inputIndex int, outpoint wire.OutPoint) error {
	if inputIndex < 0 || len(ptx.Inputs) <= inputIndex || len(ptx.UnsignedTx.TxIn) <= inputIndex {
		return fmt.Errorf("input %d: PSBT input index out of range", inputIndex)
	}
	if ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint != outpoint {
		return fmt.Errorf("input %d: outpoint does not match intent proof", inputIndex)
	}

	input := ptx.Inputs[inputIndex]
	if input.WitnessUtxo == nil || input.WitnessUtxo.Value != a.prevout.Value ||
		!bytes.Equal(input.WitnessUtxo.PkScript, a.prevout.PkScript) {
		return fmt.Errorf("input %d: witness UTXO does not match intent proof", inputIndex)
	}
	if len(input.TaprootLeafScript) == 0 || input.TaprootLeafScript[0] == nil {
		return fmt.Errorf("input %d: missing taproot leaf script", inputIndex)
	}

	tapLeaf := input.TaprootLeafScript[0]
	if txscript.NewTapLeaf(tapLeaf.LeafVersion, tapLeaf.Script).TapHash() !=
		a.script.TapLeaf().TapHash() {
		return fmt.Errorf("input %d: taproot leaf script does not match intent proof", inputIndex)
	}

	return nil
}

// approvedInputs returns, by outpoint, the proof inputs with an emulator packet entry whose
// tapscript sigs include a valid one from a closure key of the entry script.
func approvedInputs(proof *psbt.Packet) (map[wire.OutPoint]approvedInput, error) {
	if len(proof.Inputs) != len(proof.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("malformed psbt")
	}
	prevoutFetcher, err := computePrevoutFetcher(proof)
	if err != nil {
		return nil, err
	}
	sighashes := txscript.NewTxSigHashes(proof.UnsignedTx, prevoutFetcher)

	packet, err := arkade.FindEmulatorPacket(proof.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse emulator packet: %w", err)
	}

	approved := make(map[wire.OutPoint]approvedInput)
	for _, entry := range packet {
		inputIndex := int(entry.Vin)
		// in intent proof, input index 0 is the message input: no forfeit spends it
		if inputIndex == 0 || inputIndex >= len(proof.Inputs) {
			continue
		}
		input := proof.Inputs[inputIndex]
		if len(input.TaprootScriptSpendSig) == 0 {
			continue
		}

		script, err := arkade.NewArkadeScript(proof, entry)
		if err != nil {
			return nil, fmt.Errorf("failed to read arkade script: %w", err)
		}

		var signers []*btcec.PublicKey
		for _, sig := range input.TaprootScriptSpendSig {
			var signer *btcec.PublicKey
			for _, pubkey := range script.ClosurePubKeys() {
				if bytes.Equal(schnorr.SerializePubKey(pubkey), sig.XOnlyPubKey) {
					signer = pubkey
					break
				}
			}
			if signer == nil {
				continue
			}
			tapscriptSig, err := schnorr.ParseSignature(sig.Signature)
			if err != nil {
				return nil, fmt.Errorf("failed to parse tapscript signature: %w", err)
			}
			message, err := txscript.CalcTapscriptSignaturehash(
				sighashes, sig.SigHash, proof.UnsignedTx, inputIndex, prevoutFetcher, script.TapLeaf(),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate tapscript signature hash: %w", err)
			}
			if !tapscriptSig.Verify(message, signer) {
				return nil, fmt.Errorf("invalid signature for input %d", inputIndex)
			}
			signers = append(signers, signer)
		}
		if len(signers) == 0 {
			continue
		}

		approved[proof.UnsignedTx.TxIn[inputIndex].PreviousOutPoint] = approvedInput{
			script:  script,
			signers: signers,
			prevout: wire.TxOut{
				Value:    input.WitnessUtxo.Value,
				PkScript: append([]byte(nil), input.WitnessUtxo.PkScript...),
			},
		}
	}
	return approved, nil
}

