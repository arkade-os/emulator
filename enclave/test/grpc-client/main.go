// grpc-client is the attestation-verifying gRPC client used by the
// introspector enclave integration test. It builds on
// github.com/ArkLabsHQ/introspector-enclave/client to verify the NSM
// attestation document, pin PCR0, and pin the TLS leaf-cert fingerprint
// against the attestation's user_data — then dials IntrospectorService
// over native gRPC.
//
// Modes:
//
//	-rpc info        Calls GetInfo and prints the signer pubkey.
//	-rpc submit-tx   Calls GetInfo to learn the signer pubkey, builds a valid
//	                 arkade ark_tx + checkpoint pair on a non-finalizer closure
//	                 (so introspector signs and returns without invoking the
//	                 downstream arkd SubmitTx/FinalizeTx), then calls SubmitTx
//	                 and asserts both ArkTx + Checkpoints come back signed.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/ArkLabsHQ/introspector-enclave/client"
	introspectorv1 "github.com/ArkLabsHQ/introspector/api-spec/protobuf/gen/introspector/v1"
	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

func main() {
	url := flag.String("url", "", "enclave HTTPS URL (e.g. https://localhost:8443)")
	pcr0 := flag.String("pcr0", "", "expected PCR0 hex")
	insecureCOSE := flag.Bool("insecure-skip-cose", false, "skip COSE Sign1 signature + AWS Nitro chain verification (local QEMU tests only)")
	rpc := flag.String("rpc", "info", "RPC to invoke: info | submit-tx")
	flag.Parse()

	if *url == "" || *pcr0 == "" {
		fmt.Fprintln(os.Stderr, "error: both -url and -pcr0 are required")
		os.Exit(2)
	}

	ctx := context.Background()

	c, err := client.New(*url, client.Options{
		ExpectedPCR0:           *pcr0,
		InsecureSkipCOSEVerify: *insecureCOSE,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build client: %v\n", err)
		os.Exit(1)
	}

	conn, err := c.GRPCConn(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: dial gRPC (attestation chain failed): %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	svc := introspectorv1.NewIntrospectorServiceClient(conn)

	switch *rpc {
	case "info":
		runGetInfo(ctx, svc)
	case "submit-tx":
		runSubmitTx(ctx, svc)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown -rpc %q (want info | submit-tx)\n", *rpc)
		os.Exit(2)
	}
}

func runGetInfo(ctx context.Context, svc introspectorv1.IntrospectorServiceClient) {
	resp, err := svc.GetInfo(ctx, &introspectorv1.GetInfoRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: GetInfo: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Attestation Verified: true\n")
	fmt.Printf("Version:              %s\n", resp.GetVersion())
	fmt.Printf("Signer Pubkey:        %s\n", resp.GetSignerPubkey())
}

func runSubmitTx(ctx context.Context, svc introspectorv1.IntrospectorServiceClient) {
	info, err := svc.GetInfo(ctx, &introspectorv1.GetInfoRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: GetInfo (for signer pubkey): %v\n", err)
		os.Exit(1)
	}
	signerPubkeyBytes, err := hex.DecodeString(info.GetSignerPubkey())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: decode signer pubkey hex: %v\n", err)
		os.Exit(1)
	}
	signerPubkey, err := btcec.ParsePubKey(signerPubkeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse signer pubkey: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Signer Pubkey:        %s\n", info.GetSignerPubkey())

	arkTxB64, checkpointB64s, err := buildSubmitTxFixture(signerPubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build fixture: %v\n", err)
		os.Exit(1)
	}

	resp, err := svc.SubmitTx(ctx, &introspectorv1.SubmitTxRequest{
		ArkTx:         arkTxB64,
		CheckpointTxs: checkpointB64s,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: SubmitTx: %v\n", err)
		os.Exit(1)
	}

	if resp.GetSignedArkTx() == "" {
		fmt.Fprintln(os.Stderr, "error: SubmitTx response missing SignedArkTx")
		os.Exit(1)
	}
	if len(resp.GetSignedCheckpointTxs()) == 0 {
		fmt.Fprintln(os.Stderr, "error: SubmitTx response missing SignedCheckpointTxs")
		os.Exit(1)
	}

	fmt.Printf("SubmitTx OK:          ark_tx=%d bytes, checkpoints=%d\n",
		len(resp.GetSignedArkTx()), len(resp.GetSignedCheckpointTxs()))
}

// buildSubmitTxFixture builds a valid arkade ark_tx + checkpoint pair that
// exercises introspector's SubmitTx without crossing into the downstream arkd
// SubmitTx/FinalizeTx call. It puts the introspector's tweaked key first and
// a random "bob" key last in the closure, which makes the finalizer
// accumulator decide that bob (not the introspector) is the finalizer — so
// introspector signs its input + checkpoint and returns immediately.
//
// Adapted from introspector-example/examples/enclave-client/main.go's
// buildExampleTx; closure order is the only deliberate difference.
func buildSubmitTxFixture(signerPubkey *btcec.PublicKey) (string, []string, error) {
	bobPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate bob key: %w", err)
	}
	bobPubKey := bobPrivKey.PubKey()

	destPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate dest key: %w", err)
	}
	destPkScript, err := script.P2TRScript(destPrivKey.PubKey())
	if err != nil {
		return "", nil, fmt.Errorf("build dest script: %w", err)
	}

	// Arkade script: verify output 0's pubkey matches the destination's x-only key.
	arkadeScriptBytes, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(destPkScript[2:]).
		AddOp(arkade.OP_EQUAL).
		Script()
	if err != nil {
		return "", nil, fmt.Errorf("build arkade script: %w", err)
	}

	tweakedPubKey := arkade.ComputeArkadeScriptPublicKey(
		signerPubkey, arkade.ArkadeScriptHash(arkadeScriptBytes),
	)

	// Non-finalizer closure: tweakedThis appears first, bob is last. The
	// finalizer accumulator picks the last non-arkd key and compares against
	// tweakedSigner — bob ≠ tweakedSigner, so isFinalizer=false and the
	// introspector skips the downstream arkd SubmitTx call.
	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{tweakedPubKey, bobPubKey},
			},
		},
	}

	_, vtxoTapTree, err := vtxoScript.TapTree()
	if err != nil {
		return "", nil, fmt.Errorf("build vtxo tap tree: %w", err)
	}

	closure := vtxoScript.ForfeitClosures()[0]
	closureScript, err := closure.Script()
	if err != nil {
		return "", nil, fmt.Errorf("build closure script: %w", err)
	}

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(closureScript).TapHash(),
	)
	if err != nil {
		return "", nil, fmt.Errorf("get merkle proof: %w", err)
	}

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	if err != nil {
		return "", nil, fmt.Errorf("parse control block: %w", err)
	}

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	unrollKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", nil, fmt.Errorf("generate unroll key: %w", err)
	}
	unrollClosure := &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{unrollKey.PubKey()},
		},
		Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 10},
	}
	unrollScript, err := unrollClosure.Script()
	if err != nil {
		return "", nil, fmt.Errorf("build unroll script: %w", err)
	}

	const amount = int64(10000)
	fakeOutpoint := &wire.OutPoint{
		Hash:  chainhash.Hash{0x01},
		Index: 0,
	}

	arkTx, checkpointPsbts, err := offchain.BuildTxs(
		[]offchain.VtxoInput{{
			Outpoint:           fakeOutpoint,
			Tapscript:          tapscript,
			Amount:             amount,
			RevealedTapscripts: []string{hex.EncodeToString(closureScript)},
		}},
		[]*wire.TxOut{{Value: amount, PkScript: destPkScript}},
		unrollScript,
	)
	if err != nil {
		return "", nil, fmt.Errorf("build txs: %w", err)
	}

	// Encode the arkade script as an IntrospectorPacket in an OP_RETURN
	// extension output on the ark tx — this is the format introspector reads
	// via arkade.FindIntrospectorPacket at SubmitTx time.
	packet, err := arkade.NewPacket(arkade.IntrospectorEntry{Vin: 0, Script: arkadeScriptBytes})
	if err != nil {
		return "", nil, fmt.Errorf("build introspector packet: %w", err)
	}
	ext := extension.Extension{packet}
	extTxOut, err := ext.TxOut()
	if err != nil {
		return "", nil, fmt.Errorf("encode extension txout: %w", err)
	}
	arkTx.UnsignedTx.AddTxOut(extTxOut)
	arkTx.Outputs = append(arkTx.Outputs, psbt.POutput{})

	encodedArkTx, err := arkTx.B64Encode()
	if err != nil {
		return "", nil, fmt.Errorf("encode ark tx: %w", err)
	}

	encodedCheckpoints := make([]string, 0, len(checkpointPsbts))
	for _, cp := range checkpointPsbts {
		enc, err := cp.B64Encode()
		if err != nil {
			return "", nil, fmt.Errorf("encode checkpoint: %w", err)
		}
		encodedCheckpoints = append(encodedCheckpoints, enc)
	}

	return encodedArkTx, encodedCheckpoints, nil
}
