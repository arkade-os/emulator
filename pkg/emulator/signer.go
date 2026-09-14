package emulator

import (
	"errors"
	"fmt"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

type signer struct {
	secretKey *btcec.PrivateKey
}

func (s signer) signInput(ptx *psbt.Packet, inputIndex int, tweak []byte, prevoutFetcher txscript.PrevOutputFetcher) error {
	if len(ptx.Inputs) <= inputIndex || len(ptx.UnsignedTx.TxIn) <= inputIndex {
		return fmt.Errorf("input index out of range, cannot sign")
	}

	signingKey := arkade.ComputeArkadeScriptPrivateKey(s.secretKey, tweak)

	input := ptx.Inputs[inputIndex]
	// only sighash types committing to every input and output are safe: any other
	// type lets the requester replace outputs or prevouts the covenant approved
	if input.SighashType != txscript.SigHashDefault && input.SighashType != txscript.SigHashAll {
		return fmt.Errorf("unsupported sighash type 0x%02x, cannot sign", uint32(input.SighashType))
	}

	// if not a taproot input, skip because arkd-wallet is taproot only accounts
	if !txscript.IsPayToTaproot(input.WitnessUtxo.PkScript) {
		return fmt.Errorf("not a taproot input, cannot sign")
	}

	// the whole codebase reads and signs the leaf at index 0, reject ambiguous inputs
	// instead of silently picking one of several declared leaves
	if len(input.TaprootLeafScript) != 1 || input.TaprootLeafScript[0] == nil {
		return fmt.Errorf(
			"expected exactly 1 taproot leaf script, got %d, cannot sign",
			len(input.TaprootLeafScript),
		)
	}

	// the leaf script is the requester's assertion until it is checked against
	// the taproot output key committed in the prevout being spent
	if err := arkade.VerifyTaprootLeafCommitment(
		input.WitnessUtxo.PkScript, input.TaprootLeafScript[0],
	); err != nil {
		return fmt.Errorf("cannot sign input: %w", err)
	}

	// only sign digests committing to every input and output: NONE, SINGLE and
	// ANYONECANPAY leave part of the transaction free to change after signing
	if input.SighashType != txscript.SigHashDefault &&
		input.SighashType != txscript.SigHashAll {
		return fmt.Errorf(
			"unsupported sighash type 0x%02x, cannot sign", byte(input.SighashType),
		)
	}

	tapLeaf := txscript.NewBaseTapLeaf(input.TaprootLeafScript[0].Script)
	txSigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	signature, err := txscript.RawTxInTapscriptSignature(
		ptx.UnsignedTx, txSigHashes, inputIndex, input.WitnessUtxo.Value,
		input.WitnessUtxo.PkScript, tapLeaf, input.SighashType, signingKey,
	)
	if err != nil {
		return err
	}

	leafHash := tapLeaf.TapHash()

	ptx.Inputs[inputIndex].TaprootScriptSpendSig = append(ptx.Inputs[inputIndex].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		Signature:   signature[:64], // remove the last byte (sig hash type) because signature is already encoded
		XOnlyPubKey: schnorr.SerializePubKey(signingKey.PubKey()),
		LeafHash:    leafHash[:],
		SigHash:     input.SighashType,
	})

	return nil
}

func resolveArkadeScriptSigner(
	current signer,
	deprecated []signer,
	ptx *psbt.Packet,
	entry arkade.EmulatorEntry,
) (signer, *arkade.ArkadeScript, error) {
	script, err := arkade.ReadArkadeScript(ptx, current.secretKey.PubKey(), entry)
	if err == nil {
		return current, script, nil
	}
	if !errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) {
		return signer{}, nil, err
	}

	for _, deprecatedSigner := range deprecated {
		script, err := arkade.ReadArkadeScript(ptx, deprecatedSigner.secretKey.PubKey(), entry)
		if err == nil {
			return deprecatedSigner, script, nil
		}
		if !errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) {
			return signer{}, nil, err
		}
	}

	return signer{}, nil, err
}
