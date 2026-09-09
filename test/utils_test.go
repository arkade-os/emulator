package test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type delegateBatchEventsHandler struct {
	intentId       string
	intent         emulatorclient.Intent
	vtxosToForfeit []types.VtxoWithTapTree
	signerSession  tree.SignerSession
	emulatorClient emulatorclient.TransportClient
	wallet         identity.Identity
	client         client.Client
	explorer       explorer.Explorer

	forfeitAddress string

	batchExpiry  arklib.RelativeLocktime
	cacheBatchId string
}

func (h *delegateBatchEventsHandler) OnBatchStarted(
	ctx context.Context, event client.BatchStartedEvent,
) (bool, time.Duration, error) {
	buf := sha256.Sum256([]byte(h.intentId))
	hashedIntentId := hex.EncodeToString(buf[:])

	for _, hash := range event.HashedIntentIds {
		if hash == hashedIntentId {
			if err := h.client.ConfirmRegistration(ctx, h.intentId); err != nil {
				return false, -1, err
			}
			h.cacheBatchId = event.Id
			h.batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
			return false, time.Duration(event.BatchExpiry) * time.Second, nil
		}
	}

	return true, -1, nil
}

func (h *delegateBatchEventsHandler) OnBatchFinalized(
	_ context.Context, event client.BatchFinalizedEvent,
) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnBatchFailed(
	_ context.Context, event client.BatchFailedEvent,
) error {
	if event.Id == h.cacheBatchId {
		return fmt.Errorf("batch failed: %s", event.Reason)
	}
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeTxEvent(context.Context, client.TreeTxEvent) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeSignatureEvent(context.Context, client.TreeSignatureEvent) error {
	return nil
}

func (h *delegateBatchEventsHandler) OnTreeSigningStarted(
	ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	myPubkey := h.signerSession.GetPublicKey()
	if !slices.Contains(event.CosignersPubkeys, myPubkey) {
		return true, nil
	}

	arkInfos, err := h.client.GetInfo(ctx)
	if err != nil {
		return false, err
	}
	h.forfeitAddress = arkInfos.ForfeitAddress

	forfeitPubKeyBytes, err := hex.DecodeString(arkInfos.ForfeitPubKey)
	if err != nil {
		return false, err
	}
	forfeitPubKey, err := btcec.ParsePubKey(forfeitPubKeyBytes)
	if err != nil {
		return false, err
	}

	sweepClosure := script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{forfeitPubKey}},
		Locktime:        h.batchExpiry,
	}

	script, err := sweepClosure.Script()
	if err != nil {
		return false, err
	}

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, err
	}

	batchOutput := commitmentTx.UnsignedTx.TxOut[0]
	batchOutputAmount := batchOutput.Value

	sweepTapLeaf := txscript.NewBaseTapLeaf(script)
	sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	generateAndSendNonces := func(session tree.SignerSession) error {
		if err := session.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
			return err
		}

		nonces, err := session.GetNonces()
		if err != nil {
			return err
		}

		return h.client.SubmitTreeNonces(ctx, event.Id, session.GetPublicKey(), nonces)
	}

	if err := generateAndSendNonces(h.signerSession); err != nil {
		return false, err
	}

	return false, nil
}

func (h *delegateBatchEventsHandler) OnTreeNonces(context.Context, client.TreeNoncesEvent) (
	bool, error,
) {
	return false, nil
}

func (h *delegateBatchEventsHandler) OnTreeNoncesAggregated(
	ctx context.Context, event client.TreeNoncesAggregatedEvent,
) (bool, error) {
	h.signerSession.SetAggregatedNonces(event.Nonces)

	sigs, err := h.signerSession.Sign()
	if err != nil {
		return false, err
	}

	err = h.client.SubmitTreeSignatures(
		ctx,
		event.Id,
		h.signerSession.GetPublicKey(),
		sigs,
	)
	return err == nil, err
}

func (h *delegateBatchEventsHandler) OnBatchFinalization(
	ctx context.Context, event client.BatchFinalizationEvent,
	vtxoTree, connectorTree *tree.TxTree,
) ([]string, error) {
	if len(h.vtxosToForfeit) <= 0 {
		return nil, nil
	}

	if connectorTree == nil {
		return nil, fmt.Errorf("connector tree is nil")
	}

	forfeits, err := h.createAndSignForfeits(ctx, h.vtxosToForfeit, connectorTree.Leaves())
	if err != nil {
		return nil, err
	}

	flatConnectorTree, err := connectorTree.Serialize()
	if err != nil {
		return nil, err
	}

	signedForfeits, signedCommitmentTx, err := h.emulatorClient.SubmitFinalization(
		ctx, h.intent, forfeits, flatConnectorTree, event.Tx,
	)
	if err != nil {
		return nil, err
	}

	return signedForfeits, h.client.SubmitSignedForfeitTxs(ctx, signedForfeits, signedCommitmentTx)
}

func (h *delegateBatchEventsHandler) OnStreamStarted(_ context.Context, _ client.StreamStartedEvent) error {
	return nil
}

func (h *delegateBatchEventsHandler) createAndSignForfeits(
	ctx context.Context, vtxosToSign []types.VtxoWithTapTree, connectorsLeaves []*psbt.Packet,
) ([]string, error) {
	parsedForfeitAddr, err := btcutil.DecodeAddress(h.forfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	forfeitPkScript, err := txscript.PayToAddrScript(parsedForfeitAddr)
	if err != nil {
		return nil, err
	}

	signedForfeitTxs := make([]string, 0, len(vtxosToSign))
	for i, vtxo := range vtxosToSign {
		connectorTx := connectorsLeaves[i]

		var connector *wire.TxOut
		var connectorOutpoint *wire.OutPoint
		for outIndex, output := range connectorTx.UnsignedTx.TxOut {
			if bytes.Equal(txutils.ANCHOR_PKSCRIPT, output.PkScript) {
				continue
			}

			connector = output
			connectorOutpoint = &wire.OutPoint{
				Hash:  connectorTx.UnsignedTx.TxHash(),
				Index: uint32(outIndex),
			}
			break
		}

		if connector == nil {
			return nil, fmt.Errorf("connector not found for vtxo %s", vtxo.Outpoint.String())
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return nil, err
		}

		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, err
		}

		vtxoOutputScript, err := script.P2TRScript(vtxoTapKey)
		if err != nil {
			return nil, err
		}

		vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return nil, err
		}

		vtxoInput := &wire.OutPoint{
			Hash:  *vtxoTxHash,
			Index: vtxo.VOut,
		}

		forfeitClosures := vtxoScript.ForfeitClosures()
		if len(forfeitClosures) <= 0 {
			return nil, fmt.Errorf("no forfeit closures found")
		}

		forfeitClosure := forfeitClosures[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return nil, err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		leafProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, err
		}

		tapscript := psbt.TaprootTapLeafScript{
			ControlBlock: leafProof.ControlBlock,
			Script:       leafProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		vtxoLocktime := arklib.AbsoluteLocktime(0)
		if cltv, ok := forfeitClosure.(*script.CLTVMultisigClosure); ok {
			vtxoLocktime = cltv.Locktime
		}

		vtxoPrevout := &wire.TxOut{
			Value:    int64(vtxo.Amount),
			PkScript: vtxoOutputScript,
		}

		vtxoSequence := wire.MaxTxInSequenceNum
		if vtxoLocktime != 0 {
			vtxoSequence = wire.MaxTxInSequenceNum - 1
		}

		forfeitTx, err := tree.BuildForfeitTx(
			[]*wire.OutPoint{vtxoInput, connectorOutpoint},
			[]uint32{vtxoSequence, wire.MaxTxInSequenceNum},
			[]*wire.TxOut{vtxoPrevout, connector},
			forfeitPkScript,
			uint32(vtxoLocktime),
		)
		if err != nil {
			return nil, err
		}

		forfeitTx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{&tapscript}

		b64, err := forfeitTx.B64Encode()
		if err != nil {
			return nil, err
		}

		signedForfeitTx, err := h.wallet.SignTransaction(ctx, b64, nil)
		if err != nil {
			return nil, err
		}

		signedForfeitTxs = append(signedForfeitTxs, signedForfeitTx)
	}

	return signedForfeitTxs, nil
}

type boardingBatchEventsHandler struct {
	*delegateBatchEventsHandler
	boardingVtxo types.VtxoWithTapTree
}

func (h *boardingBatchEventsHandler) OnBatchFinalization(
	ctx context.Context, event client.BatchFinalizationEvent,
	vtxoTree, connectorTree *tree.TxTree,
) ([]string, error) {
	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
	if err != nil {
		return nil, err
	}

	boardingVtxoScript, err := script.ParseVtxoScript(h.boardingVtxo.Tapscripts)
	if err != nil {
		return nil, err
	}

	forfeitClosures := boardingVtxoScript.ForfeitClosures()
	if len(forfeitClosures) <= 0 {
		return nil, fmt.Errorf("no forfeit closures found")
	}

	forfeitClosure := forfeitClosures[0]

	forfeitScript, err := forfeitClosure.Script()
	if err != nil {
		return nil, err
	}

	_, taprootTree, err := boardingVtxoScript.TapTree()
	if err != nil {
		return nil, err
	}

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	forfeitProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get taproot merkle proof for boarding utxo: %s", err,
		)
	}

	tapscript := &psbt.TaprootTapLeafScript{
		ControlBlock: forfeitProof.ControlBlock,
		Script:       forfeitProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	for i := range commitmentPtx.Inputs {
		prevout := commitmentPtx.UnsignedTx.TxIn[i].PreviousOutPoint

		if h.boardingVtxo.Txid == prevout.Hash.String() &&
			h.boardingVtxo.VOut == prevout.Index {
			commitmentPtx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
				tapscript,
			}
			break
		}
	}

	b64, err := commitmentPtx.B64Encode()
	if err != nil {
		return nil, err
	}

	signedCommitmentTx, err := h.wallet.SignTransaction(ctx, b64, nil)
	if err != nil {
		return nil, err
	}

	_, signedCommitmentTx, err = h.emulatorClient.SubmitFinalization(
		ctx, h.intent, []string{}, nil, signedCommitmentTx,
	)
	if err != nil {
		return nil, err
	}

	return nil, h.client.SubmitSignedForfeitTxs(ctx, []string{}, signedCommitmentTx)
}

func getBatchExpiryLocktime(expiry uint32) arklib.RelativeLocktime {
	if expiry >= 512 {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: expiry}
	}
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: expiry}
}

// setupWallet creates and unlocks a new wallet
func setupWallet(t *testing.T, ctx context.Context) (identity.Identity, *btcec.PrivateKey, *btcec.PublicKey) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewStore()
	require.NoError(t, err)

	wallet, err := singlekeywallet.NewIdentity(walletStore)
	require.NoError(t, err)

	_, err = wallet.Create(ctx, chaincfg.RegressionNetParams, password, hex.EncodeToString(privKey.Serialize()))
	require.NoError(t, err)

	_, err = wallet.Unlock(ctx, password)
	require.NoError(t, err)

	return wallet, privKey, privKey.PubKey()
}

// fundAndSettleAlice funds alice's account via boarding and settles
// sends 1$
func fundAndSettleAlice(t *testing.T, ctx context.Context, alice arksdk.Wallet, amount int64) *arklib.Address {
	offchainAddr, boardingAddress := receive(t, alice)

	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)

	amountBtc := strings.TrimSuffix(btcutil.Amount(amount).Format(btcutil.AmountBTC), " BTC")

	_, err = runCommand("nigiri", "faucet", boardingAddress, amountBtc)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		balance, err := alice.Balance(ctx)
		return err == nil && balance.OnchainBalance.Total > 0
	}, 30*time.Second, 500*time.Millisecond, "boarding utxo not detected by wallet")

	_, err = alice.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	return aliceAddr
}

func encodeCheckpoints(t *testing.T, checkpoints []*psbt.Packet) []string {
	t.Helper()

	encodedCheckpoints := make([]string, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		encoded, err := checkpoint.B64Encode()
		require.NoError(t, err)
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

	return encodedCheckpoints
}

func buildWalletFundedTx(
	t *testing.T,
	ctx context.Context,
	alice arksdk.Wallet,
	indexerSvc indexer.Indexer,
	alicePubKey *btcec.PublicKey,
	serverSigner *btcec.PublicKey,
	unilateralExitDelay uint32,
	outputs []*wire.TxOut,
	checkpointScriptBytes []byte,
) (*psbt.Packet, []*psbt.Packet) {
	t.Helper()

	exitDelayType := arklib.LocktimeTypeBlock
	if unilateralExitDelay >= 512 {
		exitDelayType = arklib.LocktimeTypeSecond
	}
	fundingVtxoScript := script.NewDefaultVtxoScript(
		alicePubKey,
		serverSigner,
		arklib.RelativeLocktime{
			Type:  exitDelayType,
			Value: unilateralExitDelay,
		},
	)
	fundingTapscript := onlyForfeitScript(t, *fundingVtxoScript)
	fundingTapKey, _, err := fundingVtxoScript.TapTree()
	require.NoError(t, err)

	fundingPkScript, err := script.P2TRScript(fundingTapKey)
	require.NoError(t, err)
	spendableVtxos, _, err := alice.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)

	var fundingVtxo types.Vtxo
	for _, vtxo := range spendableVtxos {
		if vtxo.Script == hex.EncodeToString(fundingPkScript) {
			fundingVtxo = vtxo
			break
		}
	}
	require.NotEmpty(t, fundingVtxo.Txid)

	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingVtxo.Txid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	fundingOutputIndex, fundingOutput := findTaprootOutput(t, fundingPtx.UnsignedTx, fundingTapKey)
	require.Equal(t, fundingVtxo.VOut, fundingOutputIndex)
	require.Equal(t, int64(fundingVtxo.Amount), fundingOutput.Value)

	fundingInput := vtxoInputFromScriptOutput(
		t,
		fundingPtx.UnsignedTx,
		fundingOutputIndex,
		*fundingVtxoScript,
		fundingTapscript,
	)

	outputValue := int64(0)
	for _, output := range outputs {
		outputValue += output.Value
	}
	changeValue := fundingOutput.Value - outputValue
	require.Positive(t, changeValue)

	txOutputs := make([]*wire.TxOut, 0, len(outputs)+1)
	txOutputs = append(txOutputs, outputs...)
	txOutputs = append(txOutputs, &wire.TxOut{
		Value:    changeValue,
		PkScript: fundingPkScript,
	})

	ptx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{fundingInput},
		txOutputs,
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	return ptx, checkpoints
}

func submitWithArkd(
	t *testing.T,
	ctx context.Context,
	candidateTx *psbt.Packet,
	checkpoints []*psbt.Packet,
	walletSvc identity.Identity,
	grpcClient client.Client,
) {
	t.Helper()

	encodedTx, err := candidateTx.B64Encode()
	require.NoError(t, err)

	signedTx, err := walletSvc.SignTransaction(ctx, encodedTx, nil)
	require.NoError(t, err)

	txid, _, signedCheckpoints, err := grpcClient.SubmitTx(ctx, signedTx, encodeCheckpoints(t, checkpoints))
	require.NoError(t, err)
	require.NotEmpty(t, txid)
	require.NotEmpty(t, signedCheckpoints)

	finalCheckpoints := make([]string, 0, len(signedCheckpoints))
	for _, checkpoint := range signedCheckpoints {
		signedCheckpoint, err := walletSvc.SignTransaction(ctx, checkpoint, nil)
		require.NoError(t, err)
		finalCheckpoints = append(finalCheckpoints, signedCheckpoint)
	}

	require.NoError(t, grpcClient.FinalizeTx(ctx, txid, finalCheckpoints))
}

// watchForPreconfirmedVtxos subscribes to the output scripts of candidateTx at the
// given vouts BEFORE the tx is submitted, and returns a wait function.
func watchForPreconfirmedVtxos(
	t *testing.T,
	indexerSvc indexer.Indexer,
	candidateTx *psbt.Packet,
	vouts ...uint32,
) func() {
	t.Helper()

	ctx := t.Context()

	hexScripts := make([]string, 0, len(vouts))
	wantedVouts := make(map[uint32]struct{}, len(vouts))
	for _, vout := range vouts {
		hexScripts = append(
			hexScripts,
			hex.EncodeToString(candidateTx.UnsignedTx.TxOut[vout].PkScript),
		)
		wantedVouts[vout] = struct{}{}
	}

	subId, eventCh, closeFn, err := indexerSvc.NewSubscription(ctx, hexScripts)
	require.NoError(t, err)

	return func() {
		t.Helper()
		defer func() {
			// nolint:errcheck
			indexerSvc.UpdateSubscription(ctx, subId, nil, hexScripts)
			closeFn()
		}()

		txid := candidateTx.UnsignedTx.TxID()
		got := make(map[uint32]types.Vtxo, len(vouts))

		timeout := time.After(10 * time.Second)
		for len(got) < len(vouts) {
			select {
			case event, ok := <-eventCh:
				if !ok {
					require.FailNow(t, "subscription channel closed before all vtxos received")
					return
				}
				require.NoError(t, event.Err)
				if event.Data == nil {
					continue
				}
				for _, v := range event.Data.NewVtxos {
					if v.Txid != txid {
						continue
					}
					if _, ok := wantedVouts[v.VOut]; ok {
						got[v.VOut] = v
					}
				}
			case <-timeout:
				require.FailNowf(
					t,
					"timeout waiting for vtxo subscription event",
					"got %d/%d", len(got), len(vouts),
				)
				return
			}
		}

		for _, v := range got {
			require.True(t, v.Preconfirmed, "vtxo %s:%d must be preconfirmed", v.Txid, v.VOut)
			require.False(t, v.Spent, "vtxo %s:%d must not be spent", v.Txid, v.VOut)
		}
	}
}

// createIssuanceAssetPacket creates a simple asset issuance packet with one output
func createIssuanceAssetPacket(t *testing.T, vout uint16, amount uint64) asset.Packet {
	assetOutput, err := asset.NewAssetOutput(vout, amount)
	require.NoError(t, err)

	assetGroup, err := asset.NewAssetGroup(
		nil,                  // nil AssetId means issuance (will use current tx hash)
		nil,                  // no control asset
		[]asset.AssetInput{}, // no inputs (issuance)
		[]asset.AssetOutput{*assetOutput},
		[]asset.Metadata{}, // no metadata
	)
	require.NoError(t, err)

	assetPacket, err := asset.NewPacket([]asset.AssetGroup{*assetGroup})
	require.NoError(t, err)

	return assetPacket
}

// createTransferAssetPacket creates an asset transfer packet for an existing asset
func createTransferAssetPacket(t *testing.T, mintTxHash chainhash.Hash, groupIndex uint16, vin uint16, vout uint16, amount uint64) asset.Packet {
	assetId := &asset.AssetId{Txid: [asset.TX_HASH_SIZE]byte(mintTxHash), Index: groupIndex}

	assetInput, err := asset.NewAssetInput(vin, amount)
	require.NoError(t, err)

	assetOutput, err := asset.NewAssetOutput(vout, amount)
	require.NoError(t, err)

	assetGroup, err := asset.NewAssetGroup(
		assetId,
		nil, // no control asset
		[]asset.AssetInput{*assetInput},
		[]asset.AssetOutput{*assetOutput},
		[]asset.Metadata{},
	)
	require.NoError(t, err)

	assetPacket, err := asset.NewPacket([]asset.AssetGroup{*assetGroup})
	require.NoError(t, err)

	return assetPacket
}

// createArkadeScriptWithAssetIntrospection creates an arkade script that verifies:
// - Output goes to specified address
// - Exactly 1 asset group
// - Asset output sum equals expected amount
func createArkadeScriptWithAssetIntrospection(t *testing.T, alicePkScript []byte, assetAmount int64) []byte {
	arkadeScript, err := txscript.NewScriptBuilder().
		// Check output 0 goes to alice's address
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(alicePkScript[2:]). // only witness program
		AddOp(arkade.OP_EQUALVERIFY).
		// Check: 1 asset group
		AddOp(arkade.OP_INSPECTNUMASSETGROUPS).
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check: sum of outputs for group 0 equals assetAmount.
		AddInt64(0). // group index
		AddInt64(1). // source = outputs
		AddOp(arkade.OP_INSPECTASSETGROUPSUM).
		AddInt64(assetAmount).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

// setupEmulatorClient creates and returns an emulator client and its signer public key
func setupEmulatorClient(t *testing.T, ctx context.Context) (emulatorclient.TransportClient, *btcec.PublicKey, *grpc.ClientConn) {
	conn, err := grpc.NewClient("localhost:7073", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	emulatorClient := emulatorclient.NewGRPCClient(conn)

	emulatorInfo, err := emulatorClient.GetInfo(ctx)
	require.NoError(t, err)
	require.NotNil(t, emulatorInfo)

	publicKeyBytes, err := hex.DecodeString(emulatorInfo.SignerPublicKey)
	require.NoError(t, err)

	publicKey, err := btcec.ParsePubKey(publicKeyBytes)
	require.NoError(t, err)

	return &prevArkTxEmulatorClient{TransportClient: emulatorClient}, publicKey, conn
}

var integrationPrevArkTxs sync.Map
var skipPrevArkTxFields sync.Map

type prevArkTxEmulatorClient struct {
	emulatorclient.TransportClient
}

func (c *prevArkTxEmulatorClient) SubmitTx(
	ctx context.Context, encodedArkTx string, encodedCheckpoints []string,
) (string, []string, error) {
	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(encodedArkTx), true)
	if err != nil {
		return "", nil, err
	}
	if _, skip := skipPrevArkTxFields.Load(arkPtx.UnsignedTx.TxID()); !skip {
		checkpoints := make(map[string]*psbt.Packet, len(encodedCheckpoints))
		for _, encoded := range encodedCheckpoints {
			checkpoint, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
			if err != nil {
				return "", nil, err
			}
			checkpoints[checkpoint.UnsignedTx.TxID()] = checkpoint
		}
		for inputIndex, input := range arkPtx.UnsignedTx.TxIn {
			fields, err := txutils.GetArkPsbtFields(arkPtx, inputIndex, arkade.PrevArkTxField)
			if err != nil {
				return "", nil, err
			}
			if len(fields) > 0 {
				continue
			}
			checkpoint := checkpoints[input.PreviousOutPoint.Hash.String()]
			if checkpoint == nil || len(checkpoint.UnsignedTx.TxIn) != 1 {
				continue
			}
			parentTxid := checkpoint.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
			parent, ok := integrationPrevArkTxs.Load(parentTxid)
			if !ok {
				return "", nil, fmt.Errorf("previous ark transaction %s not retained by integration test", parentTxid)
			}
			if err := txutils.SetArkPsbtField(arkPtx, inputIndex, arkade.PrevArkTxField, *parent.(*wire.MsgTx)); err != nil {
				return "", nil, err
			}
		}
		encodedArkTx, err = arkPtx.B64Encode()
		if err != nil {
			return "", nil, err
		}
	}

	signedArkTx, signedCheckpoints, err := c.TransportClient.SubmitTx(ctx, encodedArkTx, encodedCheckpoints)
	if err == nil {
		integrationPrevArkTxs.Store(arkPtx.UnsignedTx.TxID(), arkPtx.UnsignedTx.Copy())
	}
	return signedArkTx, signedCheckpoints, err
}

func (c *prevArkTxEmulatorClient) SubmitIntent(
	ctx context.Context, intent emulatorclient.Intent,
) (string, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(intent.Proof), true)
	if err != nil {
		return "", err
	}
	for inputIndex := 1; inputIndex < len(ptx.UnsignedTx.TxIn); inputIndex++ {
		input := ptx.UnsignedTx.TxIn[inputIndex]
		fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.PrevArkTxField)
		if err != nil {
			return "", err
		}
		if len(fields) > 0 {
			continue
		}
		parent, ok := integrationPrevArkTxs.Load(input.PreviousOutPoint.Hash.String())
		if !ok {
			return "", fmt.Errorf("previous ark transaction %s not retained by integration test", input.PreviousOutPoint.Hash)
		}
		if err := txutils.SetArkPsbtField(ptx, inputIndex, arkade.PrevArkTxField, *parent.(*wire.MsgTx)); err != nil {
			return "", err
		}
	}
	intent.Proof, err = ptx.B64Encode()
	if err != nil {
		return "", err
	}
	return c.TransportClient.SubmitIntent(ctx, intent)
}

type recordingIndexer struct {
	indexer.Indexer
}

func (i *recordingIndexer) GetVirtualTxs(
	ctx context.Context, txids []string, opts ...indexer.PageOption,
) (*indexer.VirtualTxsResponse, error) {
	response, err := i.Indexer.GetVirtualTxs(ctx, txids, opts...)
	if err != nil {
		return nil, err
	}
	for _, encoded := range response.Txs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
		if err != nil {
			return nil, err
		}
		integrationPrevArkTxs.Store(ptx.UnsignedTx.TxID(), ptx.UnsignedTx.Copy())
	}
	return response, nil
}

// createVtxoScriptWithArkadeScript creates a vtxo script with a multisig closure containing the arkade script pubkey
func createVtxoScriptWithArkadeScript(bobPubKey, aliceSigner, emulatorPubKey *btcec.PublicKey, arkadeScriptHash []byte) script.TapscriptsVtxoScript {
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					bobPubKey,
					aliceSigner,
					arkade.ComputeArkadeScriptPublicKey(emulatorPubKey, arkadeScriptHash),
				},
			},
		},
	}
}

func createVtxoScriptWithArkadeExitClosure(
	bobPubKey, aliceSigner, emulatorPubKey *btcec.PublicKey,
	arkadeScriptHash []byte, csvLocktime arklib.RelativeLocktime,
) script.TapscriptsVtxoScript {
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{bobPubKey, aliceSigner},
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{
						bobPubKey,
						arkade.ComputeArkadeScriptPublicKey(emulatorPubKey, arkadeScriptHash),
					},
				},
				Locktime: csvLocktime,
			},
		},
	}
}

// addEmulatorPacket builds an EmulatorPacket with the given entries and
// embeds it into the transaction's OP_RETURN output. If an existing ARK OP_RETURN
// (e.g. from an asset packet) is present, the emulator data is merged into it.
// Otherwise a new OP_RETURN is inserted before the last output (P2A anchor).
func addEmulatorPacket(t *testing.T, ptx *psbt.Packet, entries []arkade.EmulatorEntry) {
	packet, err := arkade.NewPacket(entries...)
	require.NoError(t, err)

	// Look for an existing OP_RETURN with ARK extension (e.g. asset packet).
	for i, out := range ptx.UnsignedTx.TxOut {
		if !extension.IsExtension(out.PkScript) {
			continue
		}
		// Parse existing extension and append the emulator packet.
		ext, err := extension.NewExtensionFromBytes(out.PkScript)
		if err != nil {
			continue
		}

		ext = append(ext, packet)
		combined, err := ext.Serialize()
		require.NoError(t, err)

		ptx.UnsignedTx.TxOut[i].PkScript = combined
		return
	}

	// No existing ARK extension — insert a new one.
	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)

	lastIdx := len(ptx.UnsignedTx.TxOut) - 1
	lastOut := ptx.UnsignedTx.TxOut[lastIdx]
	if bytes.Equal(lastOut.PkScript, txutils.ANCHOR_PKSCRIPT) {
		// Insert before the P2A anchor so the server rebuild matches.
		ptx.UnsignedTx.TxOut[lastIdx] = txOut
		ptx.UnsignedTx.AddTxOut(lastOut)
	} else {
		// No anchor (e.g. intent proofs) — append at the end so payment
		// output indices are not shifted.
		ptx.UnsignedTx.AddTxOut(txOut)
	}
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
}

// createVtxoScriptWithArkadeAndCSV creates a vtxo script with arkade closure + CSV closure
func createVtxoScriptWithArkadeAndCSV(bobPubKey, aliceSigner, emulatorPubKey *btcec.PublicKey, arkadeScriptHash []byte) script.TapscriptsVtxoScript {
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					bobPubKey,
					aliceSigner,
					arkade.ComputeArkadeScriptPublicKey(emulatorPubKey, arkadeScriptHash),
				},
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{
						bobPubKey,
						aliceSigner,
					},
				},
				Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512 * 10},
			},
		},
	}
}

// uint64LE returns an 8-byte little-endian encoding of v.
func uint64LE(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

type testArkPrevOutFetcher struct {
	txscript.PrevOutputFetcher
	arkTxs      map[wire.OutPoint]*wire.MsgTx
	prevoutIdxs map[wire.OutPoint]uint32
}

func (f *testArkPrevOutFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if f.arkTxs == nil {
		return nil
	}
	return f.arkTxs[op]
}

func (f *testArkPrevOutFetcher) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if f.arkTxs == nil || f.prevoutIdxs == nil {
		return nil
	}

	idx, foundIdx := f.prevoutIdxs[op]
	arkTx, foundTx := f.arkTxs[op]

	if !foundIdx || !foundTx {
		return nil
	}

	if idx >= uint32(len(arkTx.TxOut)) {
		return nil
	}

	return arkTx.TxOut[idx].PkScript
}

func executeArkadeScripts(t *testing.T, ptx *psbt.Packet, checkpoints []*psbt.Packet, signerPublicKey *btcec.PublicKey, opts ...arkade.ExecuteOption) error {
	t.Helper()

	if len(ptx.Inputs) != len(ptx.UnsignedTx.TxIn) {
		return fmt.Errorf("malformed psbt")
	}

	var checkpointsByTxid map[string]*psbt.Packet
	if len(checkpoints) > 0 {
		checkpointsByTxid = make(map[string]*psbt.Packet, len(checkpoints))
		for _, checkpoint := range checkpoints {
			checkpointsByTxid[checkpoint.UnsignedTx.TxID()] = checkpoint
		}
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut, len(ptx.Inputs))
	arkTxs := make(map[wire.OutPoint]*wire.MsgTx)
	prevoutIdxs := make(map[wire.OutPoint]uint32)

	for inputIndex, input := range ptx.Inputs {
		outpoint := ptx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo

		fields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.PrevArkTxField)
		require.NoError(t, err)

		if len(fields) == 0 {
			continue
		}

		prevTx := fields[0]
		prevTxCopy := prevTx

		if checkpointsByTxid == nil {
			arkTxs[outpoint] = &prevTxCopy
			prevoutIdxs[outpoint] = outpoint.Index
			continue
		}

		checkpoint := checkpointsByTxid[outpoint.Hash.String()]
		checkpointInputPrevout := checkpoint.UnsignedTx.TxIn[0].PreviousOutPoint
		arkTxs[outpoint] = &prevTxCopy
		prevoutIdxs[outpoint] = checkpointInputPrevout.Index
	}

	prevOutFetcher := &testArkPrevOutFetcher{
		PrevOutputFetcher: txscript.NewMultiPrevOutFetcher(prevouts),
		arkTxs:            arkTxs,
		prevoutIdxs:       prevoutIdxs,
	}

	packet, err := arkade.FindEmulatorPacket(ptx.UnsignedTx)
	if err != nil {
		return fmt.Errorf("failed to parse emulator packet: %w", err)
	}
	if len(packet) == 0 {
		return fmt.Errorf("no emulator packet found in transaction")
	}

	for _, entry := range packet {
		inputIndex := int(entry.Vin)
		script, err := arkade.ReadArkadeScript(ptx, signerPublicKey, entry)
		if err != nil {
			return fmt.Errorf("failed to read arkade script at input %d: %w", inputIndex, err)
		}

		err = script.Execute(ptx.UnsignedTx, prevOutFetcher, inputIndex, opts...)
		if err != nil {
			return fmt.Errorf("failed to execute arkade script at input %d: %w", inputIndex, err)
		}
	}

	return nil
}

// createArkadeOnlyVtxoScript builds a VTXO script with a 2-of-2 multisig
// (server signer + arkade-tweaked emulator key). No separate owner key.
func createArkadeOnlyVtxoScript(
	serverSigner *btcec.PublicKey,
	emulatorPubKey *btcec.PublicKey,
	arkadeScriptHash []byte,
) script.TapscriptsVtxoScript {
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					serverSigner,
					arkade.ComputeArkadeScriptPublicKey(emulatorPubKey, arkadeScriptHash),
				},
			},
		},
	}
}

func onlyForfeitScript(t *testing.T, vtxoScript script.TapscriptsVtxoScript) []byte {
	t.Helper()

	closures := vtxoScript.ForfeitClosures()
	require.Len(t, closures, 1)

	tapscript, err := closures[0].Script()
	require.NoError(t, err)

	return tapscript
}

func p2trScriptForVtxoScript(t *testing.T, vtxoScript script.TapscriptsVtxoScript) []byte {
	t.Helper()

	tapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)

	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	return pkScript
}

func vtxoInputFromScriptOutput(
	t *testing.T,
	prevTx *wire.MsgTx,
	outIndex uint32,
	vtxoScript script.TapscriptsVtxoScript,
	tapscript []byte,
) offchain.VtxoInput {
	t.Helper()
	integrationPrevArkTxs.Store(prevTx.TxID(), prevTx.Copy())

	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	expectedPkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	require.Equal(t, expectedPkScript, prevTx.TxOut[outIndex].PkScript)

	merkleProof, err := tapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(tapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	revealedTapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)

	return offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  prevTx.TxHash(),
			Index: outIndex,
		},
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: merkleProof.Script,
		},
		Amount:             prevTx.TxOut[outIndex].Value,
		RevealedTapscripts: revealedTapscripts,
	}
}

func findTaprootOutput(t *testing.T, tx *wire.MsgTx, tapKey *btcec.PublicKey) (uint32, *wire.TxOut) {
	t.Helper()

	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	for index, output := range tx.TxOut {
		if bytes.Equal(output.PkScript, pkScript) {
			return uint32(index), output
		}
	}

	require.FailNow(t, "taproot output not found")
	return 0, nil
}

func addExtensionPacket(t *testing.T, ptx *psbt.Packet, packet extension.Packet) {
	t.Helper()

	for index, output := range ptx.UnsignedTx.TxOut {
		if !extension.IsExtension(output.PkScript) {
			continue
		}

		ext, err := extension.NewExtensionFromBytes(output.PkScript)
		require.NoError(t, err)

		ext = append(ext, packet)
		txOut, err := ext.TxOut()
		require.NoError(t, err)

		ptx.UnsignedTx.TxOut[index] = txOut
		return
	}

	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)

	lastIdx := len(ptx.UnsignedTx.TxOut) - 1
	lastOut := ptx.UnsignedTx.TxOut[lastIdx]
	if bytes.Equal(lastOut.PkScript, txutils.ANCHOR_PKSCRIPT) {
		ptx.UnsignedTx.TxOut[lastIdx] = txOut
		ptx.UnsignedTx.AddTxOut(lastOut)
	} else {
		ptx.UnsignedTx.AddTxOut(txOut)
	}
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
}

// To get debug output for script execution: call `executeArkadeScripts(t, psbt, checkpoints, pubkey, debugScriptExecution(t))`
//
//nolint:unused
func debugScriptExecution(t *testing.T) arkade.ExecuteOption {
	formatHexStack := func(items [][]byte) string {
		if len(items) == 0 {
			return "[]"
		}

		hexItems := make([]string, len(items))
		for i := range items {
			if len(items[i]) == 0 {
				hexItems[i] = "0"
				continue
			}
			hexItems[i] = hex.EncodeToString(items[i])
		}

		return "[" + strings.Join(hexItems, " ") + "]"
	}

	return arkade.WithDebugCallback(
		func(step *arkade.StepInfo, engine *arkade.Engine) error {
			disasm, err := engine.DisasmPC()
			if err != nil {
				disasm = "<done>"
			}
			t.Logf(
				"op=%s stack=%s altstack=%s",
				disasm,
				formatHexStack(step.Stack),
				formatHexStack(step.AltStack),
			)
			return nil
		},
	)
}

// bnBytes returns the canonical Arkade BigNum encoding of v
// (sign-magnitude little-endian, with a 0x00/0x80 sign-extension byte added
// only when the high bit of the magnitude's MSB would otherwise collide with
// the sign bit). Zero encodes as the empty slice.
func bnBytes(v *big.Int) []byte {
	if v.Sign() == 0 {
		return nil
	}
	out := new(big.Int).Abs(v).Bytes()
	slices.Reverse(out)
	if out[len(out)-1]&0x80 != 0 {
		extra := byte(0x00)
		if v.Sign() < 0 {
			extra = 0x80
		}
		out = append(out, extra)
	} else if v.Sign() < 0 {
		out[len(out)-1] |= 0x80
	}
	return out
}

// randomP2TRScript returns a fresh P2TR scriptPubKey. Used for destinations
// where the identity is irrelevant to the test.
func randomP2TRScript(t *testing.T) []byte {
	t.Helper()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript, err := txscript.PayToTaprootScript(priv.PubKey())
	require.NoError(t, err)

	return pkScript
}

// receive returns a fresh offchain and boarding address for the wallet.
func receive(t *testing.T, w arksdk.Wallet) (offchainAddr, boardingAddr string) {
	t.Helper()
	offchainAddr, err := w.NewOffchainAddress(t.Context())
	require.NoError(t, err)
	boardingAddr, err = w.NewBoardingAddress(t.Context())
	require.NoError(t, err)
	return offchainAddr, boardingAddr
}
