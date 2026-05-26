package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// SubmitFinalization doesn't execute arkade scripts, it only signs the forfeits and the commitment tx
// if and only if the intent proof contains the signer's signature (it means we executed the arkade script in the past)
// before signing the forfeits, we also verify that is it part of the commitment tx
func (s *service) SubmitFinalization(ctx context.Context, finalization BatchFinalization) (*SignedBatchFinalization, error) {
	signedInputs, err := getSignedInputAssociations(
		finalization.Intent.Proof.Packet, s.signer, s.deprecatedSigners,
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

			// validate connector is part of the connector tree
			connectorIndex := inputIndex ^ 1 // if inputIndex is 0, connectorIndex is 1, and vice versa
			connector := forfeit.UnsignedTx.TxIn[connectorIndex].PreviousOutPoint
			if !hasLeaf(finalization.ConnectorTree, connector) {
				return nil, fmt.Errorf("connector %s is not part of the tree", connector)
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
	script *arkade.ArkadeScript
	signer signer
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

	// Parse IntrospectorPacket from the transaction's OP_RETURN output
	packet, err := arkade.FindIntrospectorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse introspector packet: %w", err)
	}

	if len(packet) == 0 {
		return nil, fmt.Errorf("no introspector packet found in transaction")
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

func hasLeaf(tree *tree.TxTree, outpoint wire.OutPoint) bool {
	if tree == nil {
		return false
	}

	node := tree.Find(outpoint.Hash.String())
	if node == nil {
		return false
	}

	if len(node.Children) != 0 {
		// not a leaf
		return false
	}

	if len(node.Root.UnsignedTx.TxOut) <= int(outpoint.Index) {
		// index out of range
		return false
	}

	output := node.Root.UnsignedTx.TxOut[outpoint.Index]

	// false if the output is anchor
	return !bytes.Equal(output.PkScript, txutils.ANCHOR_PKSCRIPT)
}
