package emulator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// SubmitFinalization doesn't execute arkade scripts, it only signs the forfeits and the commitment tx
// if and only if the intent proof contains the signer's signature (it means we executed the arkade script in the past)
// before signing the forfeits, we also verify that is it part of the commitment tx
func (s *service) SubmitFinalization(ctx context.Context, finalization BatchFinalization) (*SignedBatchFinalization, error) {
	// Callers must check the commitment tx is known to arkd before calling:
	// a client-chosen commitment tx would let a replayed proof bypass the
	// arkade script execution that justified it.
	if finalization.CommitmentTx == nil {
		return nil, fmt.Errorf("commitment tx is required")
	}
	if !s.trustedCommitmentTx {
		if err := validateBatchPaysIntent(
			finalization.Intent, finalization.CommitmentTx, finalization.VtxoTree,
		); err != nil {
			return nil, fmt.Errorf("batch does not pay the intent: %w", err)
		}
	}

	signedInputs, err := getSignedInputAssociations(
		finalization.Intent.Proof.Packet, s.signer, s.activeDeprecatedSigners(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed inputs: %w", err)
	}

	if len(signedInputs) == 0 {
		return nil, fmt.Errorf("no signed inputs found in intent proof")
	}

	signedForfeits := make([]*psbt.Packet, 0, len(finalization.Forfeits))

	for _, forfeit := range finalization.Forfeits {
		if len(forfeit.Inputs) != 2 {
			return nil, fmt.Errorf(
				"malformed forfeit %s: expected 2 inputs, got %d",
				forfeit.UnsignedTx.TxID(), len(forfeit.Inputs),
			)
		}
		if len(forfeit.UnsignedTx.TxIn) != 2 {
			return nil, fmt.Errorf(
				"malformed forfeit %s: expected 2 inputs, got %d",
				forfeit.UnsignedTx.TxID(), len(forfeit.UnsignedTx.TxIn),
			)
		}

		for inputIndex, input := range forfeit.UnsignedTx.TxIn {
			association, ok := signedInputs[input.PreviousOutPoint]
			if !ok {
				continue
			}
			if err := association.validateFinalizationInput(forfeit, inputIndex); err != nil {
				return nil, err
			}

			// validate connector is part of the connector tree
			connectorIndex := inputIndex ^ 1 // if inputIndex is 0, connectorIndex is 1, and vice versa
			connector := forfeit.UnsignedTx.TxIn[connectorIndex].PreviousOutPoint
			connectorOutput := leafOutput(finalization.ConnectorTree, connector)
			if connectorOutput == nil {
				return nil, fmt.Errorf("connector %s is not part of the tree", connector)
			}
			// the input side alone says nothing about where the forfeit sends the
			// vtxo: without this the requester can reuse a vtxo input we signed in
			// the past and redirect its value anywhere
			if err := validateForfeitOutputs(
				forfeit, inputIndex, &association.prevout, connectorOutput, s.arkdForfeitPkScript,
			); err != nil {
				return nil, fmt.Errorf(
					"malformed forfeit %s: %w", forfeit.UnsignedTx.TxID(), err,
				)
			}

			// sign the forfeit
			prevoutFetcher, err := computePrevoutFetcher(forfeit)
			if err != nil {
				return nil, err
			}
			if err := association.signer.signInput(
				forfeit, inputIndex, association.script.Hash(), prevoutFetcher,
			); err != nil {
				return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
			}
			signedForfeits = append(signedForfeits, forfeit)
			delete(signedInputs, input.PreviousOutPoint)
		}
	}

	signedBatchFinalization := &SignedBatchFinalization{
		Forfeits: signedForfeits,
	}

	if len(signedInputs) == 0 {
		// all signed inputs were matched to forfeits, no boarding inputs remain
		return signedBatchFinalization, nil
	}

	prevoutFetcher, err := computePrevoutFetcher(finalization.CommitmentTx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher for commitment tx: %w", err)
	}

	signed := false

	for inputIndex, input := range finalization.CommitmentTx.UnsignedTx.TxIn {
		association, ok := signedInputs[input.PreviousOutPoint]
		if !ok {
			continue
		}
		if err := association.validateFinalizationInput(
			finalization.CommitmentTx, inputIndex,
		); err != nil {
			return nil, err
		}

		if err := association.signer.signInput(
			finalization.CommitmentTx, inputIndex, association.script.Hash(), prevoutFetcher,
		); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}
		signed = true
	}

	if signed {
		signedBatchFinalization.CommitmentTx = finalization.CommitmentTx
	}

	return signedBatchFinalization, nil
}

type signedInputAssociation struct {
	script  *arkade.ArkadeScript
	signer  signer
	prevout wire.TxOut
}

func (a signedInputAssociation) validateFinalizationInput(
	ptx *psbt.Packet, inputIndex int,
) error {
	if len(ptx.Inputs) <= inputIndex {
		return fmt.Errorf("input %d: PSBT input index out of range", inputIndex)
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

// getSignedInputAssociations iterates over tapscript sigs to find arkade script inputs with valid signature.
func getSignedInputAssociations(
	ptx psbt.Packet,
	current signer,
	deprecated []signer,
) (map[wire.OutPoint]signedInputAssociation, error) {
	prevoutFetcher, err := computePrevoutFetcher(&ptx)
	if err != nil {
		return nil, err
	}
	sighashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	signedInputs := make(map[wire.OutPoint]signedInputAssociation)

	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return nil, fmt.Errorf("malformed psbt")
	}

	// Parse EmulatorPacket from the transaction's OP_RETURN output
	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse emulator packet: %w", err)
	}

	if len(packet) == 0 {
		return nil, fmt.Errorf("no emulator packet found in transaction")
	}

	for _, entry := range packet {
		inputIndex := int(entry.Vin)

		if inputIndex == 0 {
			// in intent proof, input index 0 is the message input
			// it is not a valid vtxo output : no forfeit will be associated to it
			// we can skip it
			continue
		}

		if inputIndex >= len(ptx.Inputs) {
			continue
		}

		input := ptx.Inputs[inputIndex]
		if len(input.TaprootScriptSpendSig) == 0 {
			continue // not signed: skip
		}

		candidates := append([]signer{current}, deprecated...)
		for _, candidate := range candidates {
			script, err := arkade.ReadArkadeScript(&ptx, candidate.secretKey.PubKey(), entry)
			if err != nil {
				if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) {
					continue
				}
				return nil, fmt.Errorf("failed to read arkade script: %w", err)
			}

			xOnlyPubKey := schnorr.SerializePubKey(script.PubKey())

			for _, sig := range input.TaprootScriptSpendSig {
				if !bytes.Equal(sig.XOnlyPubKey, xOnlyPubKey) {
					continue
				}

				tapscriptSig, err := schnorr.ParseSignature(sig.Signature)
				if err != nil {
					return nil, fmt.Errorf("failed to parse tapscript signature: %w", err)
				}

				message, err := txscript.CalcTapscriptSignaturehash(
					sighashes, sig.SigHash, ptx.UnsignedTx, inputIndex, prevoutFetcher, script.TapLeaf(),
				)
				if err != nil {
					return nil, fmt.Errorf("failed to calculate tapscript signature hash: %w", err)
				}

				if !tapscriptSig.Verify(message, script.PubKey()) {
					return nil, fmt.Errorf("invalid signature for input %d", inputIndex)
				}

				signedInputs[ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint] = signedInputAssociation{
					script: script,
					signer: candidate,
					prevout: wire.TxOut{
						Value:    input.WitnessUtxo.Value,
						PkScript: append([]byte(nil), input.WitnessUtxo.PkScript...),
					},
				}
				break
			}
			if _, ok := signedInputs[ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint]; ok {
				break
			}
		}

	}
	return signedInputs, nil
}

// validateForfeitOutputs checks the output side of a forfeit against the two
// prevouts it spends. tree.BuildForfeitTx, which arkd itself replays to accept a
// forfeit, collects the vtxo and the connector into a single output paying
// arkd's forfeit script, followed by the anchor, so the whole output side is
// determined by data the emulator can trust: the intent proof signature commits
// the vtxo prevout, the connector comes from the tree, the destination from GetInfo.
func validateForfeitOutputs(
	forfeit *psbt.Packet, vtxoIndex int, vtxoPrevout, connectorOutput *wire.TxOut,
	forfeitPkScript []byte,
) error {
	if vtxoPrevout == nil {
		return fmt.Errorf("missing vtxo prevout for input %d", vtxoIndex)
	}

	spentVtxo := forfeit.Inputs[vtxoIndex].WitnessUtxo
	if spentVtxo == nil {
		return fmt.Errorf("missing witness utxo for input %d", vtxoIndex)
	}
	if spentVtxo.Value != vtxoPrevout.Value ||
		!bytes.Equal(spentVtxo.PkScript, vtxoPrevout.PkScript) {
		return fmt.Errorf(
			"input %d does not spend the vtxo committed by the intent proof", vtxoIndex,
		)
	}

	connectorIndex := vtxoIndex ^ 1
	spentConnector := forfeit.Inputs[connectorIndex].WitnessUtxo
	if spentConnector == nil {
		return fmt.Errorf("missing witness utxo for input %d", connectorIndex)
	}
	if spentConnector.Value != connectorOutput.Value ||
		!bytes.Equal(spentConnector.PkScript, connectorOutput.PkScript) {
		return fmt.Errorf(
			"input %d does not spend the connector output of the tree", connectorIndex,
		)
	}

	if len(forfeit.UnsignedTx.TxOut) != 2 {
		return fmt.Errorf("expected 2 outputs, got %d", len(forfeit.UnsignedTx.TxOut))
	}

	anchor := forfeit.UnsignedTx.TxOut[1]
	if anchor.Value != txutils.ANCHOR_VALUE ||
		!bytes.Equal(anchor.PkScript, txutils.ANCHOR_PKSCRIPT) {
		return fmt.Errorf("output 1 is not the anchor output")
	}

	expectedValue := vtxoPrevout.Value + connectorOutput.Value - txutils.ANCHOR_VALUE
	if forfeit.UnsignedTx.TxOut[0].Value != expectedValue {
		return fmt.Errorf(
			"output 0 pays %d, expected %d",
			forfeit.UnsignedTx.TxOut[0].Value, expectedValue,
		)
	}
	if !bytes.Equal(forfeit.UnsignedTx.TxOut[0].PkScript, forfeitPkScript) {
		return fmt.Errorf("output 0 does not pay the arkd forfeit script")
	}

	return nil
}

// leafOutput returns the output spent by outpoint if it is a non-anchor output
// of a leaf of the tree, nil otherwise.
func leafOutput(tree *tree.TxTree, outpoint wire.OutPoint) *wire.TxOut {
	if tree == nil {
		return nil
	}

	node := tree.Find(outpoint.Hash.String())
	if node == nil {
		return nil
	}

	if len(node.Children) != 0 {
		// not a leaf
		return nil
	}

	if len(node.Root.UnsignedTx.TxOut) <= int(outpoint.Index) {
		// index out of range
		return nil
	}

	output := node.Root.UnsignedTx.TxOut[outpoint.Index]

	if bytes.Equal(output.PkScript, txutils.ANCHOR_PKSCRIPT) {
		return nil
	}

	return output
}

// validateBatchPaysIntent checks the batch pays every output of the register
// intent proof, the outputs its arkade scripts were executed against: onchain
// ones in the commitment tx, offchain ones in a leaf of the vtxo tree rooted in it.
func validateBatchPaysIntent(
	request Intent, commitmentTx *psbt.Packet, vtxoTree *tree.TxTree,
) error {
	message, ok := request.Message.(*intent.RegisterMessage)
	if !ok {
		return fmt.Errorf("expected a register intent message, got %T", request.Message)
	}
	encodedMessage, err := message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode intent message: %w", err)
	}
	if err := validateIntentMessageCommitment(request, encodedMessage); err != nil {
		return fmt.Errorf("intent message is not committed by the proof: %w", err)
	}
	onchain := countTxOuts(commitmentTx.UnsignedTx.TxOut)
	offchain := make(map[txOutKey]int)
	if vtxoTree != nil {
		if vtxoTree.Root == nil || len(vtxoTree.Root.UnsignedTx.TxIn) != 1 {
			return fmt.Errorf("invalid vtxo tree root")
		}
		root := vtxoTree.Root.UnsignedTx.TxIn[0].PreviousOutPoint
		if root.Hash != commitmentTx.UnsignedTx.TxHash() ||
			int(root.Index) >= len(commitmentTx.UnsignedTx.TxOut) {
			return fmt.Errorf("vtxo tree is not rooted in the commitment tx")
		}
		for _, leaf := range vtxoTree.Leaves() {
			for key, n := range countTxOuts(leaf.UnsignedTx.TxOut) {
				offchain[key] += n
			}
		}
	}

	for i, out := range request.Proof.UnsignedTx.TxOut {
		// the extension and the placeholder of a proof without outputs pay no one
		if extension.IsExtension(out.PkScript) ||
			(out.Value == 0 && bytes.Equal(out.PkScript, []byte{txscript.OP_RETURN})) {
			continue
		}
		paid := offchain
		if slices.Contains(message.OnchainOutputIndexes, i) {
			paid = onchain
		}
		key := txOutKey{out.Value, string(out.PkScript)}
		if paid[key] == 0 {
			return fmt.Errorf("output %d is not paid", i)
		}
		paid[key]--
	}
	return nil
}

type txOutKey struct {
	value    int64
	pkScript string
}

func countTxOuts(outs []*wire.TxOut) map[txOutKey]int {
	counts := make(map[txOutKey]int, len(outs))
	for _, out := range outs {
		if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
			continue
		}
		counts[txOutKey{out.Value, string(out.PkScript)}]++
	}
	return counts
}
