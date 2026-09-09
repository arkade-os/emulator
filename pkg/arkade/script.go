package arkade

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var ErrTweakedArkadePubKeyNotFound = errors.New("tweaked arkade script public key not found in tapscript")

type ArkadeScript struct {
	script          []byte
	hash            []byte
	witness         wire.TxWitness
	pubkey          *btcec.PublicKey
	spendingTapLeaf txscript.TapLeaf
	closurePubkeys  []*btcec.PublicKey
}

type ExecuteOption func(*Engine)

// WithExpiry sets the VTXO's expiry timestamp for OP_PUSHEXPIRY.
func WithExpiry(expiry int64) ExecuteOption {
	return func(engine *Engine) {
		engine.expiry = &expiry
	}
}

// WithIntentMessage binds a canonical intent message to script execution.
func WithIntentMessage(raw string) ExecuteOption {
	return func(engine *Engine) { engine.intentMessage = []byte(raw) }
}

func WithDebugCallback(callback func(*StepInfo, *Engine) error) ExecuteOption {
	return func(engine *Engine) {
		engine.stepCallback = func(step *StepInfo) error {
			return callback(step, engine)
		}
	}
}

// WithComputeLimits applies partial per-input opcode-execution compute-limit
// overrides for this execution. The overrides are applied on top of
// DefaultComputeLimits, so opcodes absent from c keep their defaults. A nil map
// means no override; the engine keeps its current limits.
func WithComputeLimits(c ComputeLimits) ExecuteOption {
	return func(engine *Engine) {
		if c == nil {
			return
		}
		limits := DefaultComputeLimits()
		for op, limit := range c {
			limits[op] = limit
		}
		engine.limits = limits
	}
}

// WithExactComputeLimits replaces the compute-limit table exactly. Opcodes
// absent from c are unlimited. This is intended for already-resolved
// configuration tables; most callers should use WithComputeLimits for partial
// overrides.
func WithExactComputeLimits(c ComputeLimits) ExecuteOption {
	return func(engine *Engine) {
		if c == nil {
			return
		}
		engine.limits = cloneComputeLimits(c)
	}
}

// ArkPrevOutFetcher extends txscript.PrevOutputFetcher with the ability to
// look up previous ark transactions by outpoint. Both methods are keyed by
// the spending input's outpoint but serve different purposes:
//
//   - FetchPrevOutput returns the TxOut being spent (used for sighash
//     computation). This is the direct previous output — an ark tx output
//     for intents or a checkpoint output for ark transactions.
//
//   - FetchPrevOutArkTx returns the full previous ark transaction. This is
//     always the ark transaction, regardless of whether a checkpoint sits in between.
//
//   - FetchVtxoPrevOutPkScript returns the previous output script. This is
//     always the ark transaction, regardless of whether a checkpoint sits in between.
type ArkPrevOutFetcher interface {
	txscript.PrevOutputFetcher
	FetchPrevOutArkTx(wire.OutPoint) *wire.MsgTx

	FetchVtxoPrevOutPkScript(wire.OutPoint) []byte
}

// VerifyTaprootLeafCommitment checks that leaf, combined with its control
// block, recomputes to the taproot output key committed in pkScript. Without
// it a taproot leaf script is nothing more than the requester's assertion, and
// the signer would sign a tapscript spend for a leaf that is not part of the
// taproot tree being spent.
func VerifyTaprootLeafCommitment(pkScript []byte, leaf *psbt.TaprootTapLeafScript) error {
	if !txscript.IsPayToTaproot(pkScript) {
		return fmt.Errorf("prevout script is not a taproot output")
	}

	controlBlock, err := txscript.ParseControlBlock(leaf.ControlBlock)
	if err != nil {
		return fmt.Errorf("failed to parse taproot control block: %w", err)
	}

	// the leaf hash committed by the merkle proof is computed with the control
	// block's leaf version, so a mismatch would prove a different leaf
	if controlBlock.LeafVersion != leaf.LeafVersion {
		return fmt.Errorf(
			"control block leaf version 0x%02x does not match tapscript leaf version 0x%02x",
			byte(controlBlock.LeafVersion), byte(leaf.LeafVersion),
		)
	}

	// pkScript is OP_1 <32-byte output key>, the witness program starts at byte 2
	if err := txscript.VerifyTaprootLeafCommitment(
		controlBlock, pkScript[2:], leaf.Script,
	); err != nil {
		return fmt.Errorf("taproot leaf script is not committed by the prevout script: %w", err)
	}

	return nil
}

// ReadArkadeScript reads an arkade script from an EmulatorEntry and validates
// it against the tapscript in the PSBT input. The entry contains the script and
// witness data extracted from the Emulator Packet (OP_RETURN TLV).
func ReadArkadeScript(ptx *psbt.Packet, signerPublicKey *btcec.PublicKey, entry EmulatorEntry) (*ArkadeScript, error) {
	inputIndex := int(entry.Vin)
	if len(ptx.Inputs) <= inputIndex {
		return nil, fmt.Errorf("input index out of range")
	}

	input := ptx.Inputs[inputIndex]
	if len(input.TaprootLeafScript) == 0 {
		return nil, fmt.Errorf("input does not specify any TaprootLeafScript")
	}

	spendingTapscript := input.TaprootLeafScript[0]
	if spendingTapscript == nil {
		return nil, fmt.Errorf("input does not specify any TaprootLeafScript")
	}
	if spendingTapscript.LeafVersion != txscript.BaseLeafVersion {
		return nil, fmt.Errorf("unsupported taproot leaf version: 0x%02x",
			byte(spendingTapscript.LeafVersion))
	}

	scriptHash := ArkadeScriptHash(entry.Script)
	expectedPublicKey := ComputeArkadeScriptPublicKey(signerPublicKey, scriptHash)
	expectedPublicKeyXonly := schnorr.SerializePubKey(expectedPublicKey)

	closure, err := scriptlib.DecodeClosure(spendingTapscript.Script)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tapscript: %w", err)
	}

	var pubkeys []*btcec.PublicKey
	switch c := closure.(type) {
	case *scriptlib.MultisigClosure:
		pubkeys = c.PubKeys
	case *scriptlib.CSVMultisigClosure:
		pubkeys = c.PubKeys
	case *scriptlib.CLTVMultisigClosure:
		pubkeys = c.PubKeys
	case *scriptlib.ConditionMultisigClosure:
		pubkeys = c.PubKeys
	case *scriptlib.ConditionCSVMultisigClosure:
		pubkeys = c.PubKeys
	default:
		return nil, fmt.Errorf("unsupported closure type: %T", closure)
	}

	found := false
	for _, pubkey := range pubkeys {
		xonly := schnorr.SerializePubKey(pubkey)
		if bytes.Equal(xonly, expectedPublicKeyXonly) {
			found = true
			break
		}
	}

	if !found {
		return nil, ErrTweakedArkadePubKeyNotFound
	}

	return &ArkadeScript{
		script:  entry.Script,
		hash:    scriptHash,
		witness: entry.Witness,
		pubkey:  expectedPublicKey,
		spendingTapLeaf: txscript.NewTapLeaf(
			spendingTapscript.LeafVersion, spendingTapscript.Script,
		),
		closurePubkeys: pubkeys,
	}, nil
}

func (s *ArkadeScript) Execute(spendingTx *wire.MsgTx, prevOutFetcher ArkPrevOutFetcher, inputIndex int, opts ...ExecuteOption) error {
	// fail closed when the fetcher misses: the sighash midstates commit to every
	// input's amount and script, so a miss is either signed as a fabricated zero
	// value the introspection opcodes also see, or panics while hashing them
	for i, txIn := range spendingTx.TxIn {
		if prevOutFetcher.FetchPrevOutput(txIn.PreviousOutPoint) == nil {
			return fmt.Errorf("no prevout found for input %d", i)
		}
	}

	inputAmount := prevOutFetcher.FetchPrevOutput(
		spendingTx.TxIn[inputIndex].PreviousOutPoint,
	).Value

	engine, err := NewEngine(
		s.script,
		spendingTx,
		inputIndex,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(spendingTx, prevOutFetcher),
		inputAmount,
		prevOutFetcher,
	)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	engine.taprootCtx = newTaprootExecutionCtxForLeaf(s.spendingTapLeaf)

	for _, opt := range opts {
		opt(engine)
	}

	// Parse asset packet from transaction extension if present
	ext, err := extension.NewExtensionFromTx(spendingTx)
	if err != nil {
		if !errors.Is(err, extension.ErrExtensionNotFound) {
			return fmt.Errorf("failed to parse extension: %w", err)
		}
	} else if ap := ext.GetAssetPacket(); ap != nil {
		engine.SetAssetPacket(ap)
	}

	// Parse & set emulator packet from transaction outputs if present
	packet, err := FindEmulatorPacket(spendingTx)
	if err != nil {
		return fmt.Errorf("failed to parse emulator packet: %w", err)
	}
	if packet != nil {
		engine.SetEmulatorPacket(packet)
	}

	if len(s.witness) > 0 {
		engine.SetStack(s.witness)
	}

	if err := engine.Execute(); err != nil {
		return fmt.Errorf("failed to execute arkade script: %w", err)
	}

	return nil
}

func (s *ArkadeScript) Hash() []byte {
	return append([]byte(nil), s.hash...)
}

func (s *ArkadeScript) PubKey() *btcec.PublicKey {
	return s.pubkey
}

// TapLeaf returns the Bitcoin spending tapleaf from the PSBT input. Arkade
// signature hashes commit to this leaf hash, while the arkade script itself is
// committed separately by the emulator key tweak and packet entry.
func (s *ArkadeScript) TapLeaf() txscript.TapLeaf {
	return s.spendingTapLeaf
}

func (s *ArkadeScript) Script() []byte {
	return append([]byte(nil), s.script...)
}

func (s *ArkadeScript) ClosurePubKeys() []*btcec.PublicKey {
	return s.closurePubkeys
}
