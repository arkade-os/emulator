package test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/explorer"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

const (
	solverDust = int64(330)

	solverAliceUSDT = uint64(100) // alice's initial USDT balance
	solverBobUSDT   = uint64(50)  // amount alice pays to bob
	solverChange    = uint64(45)  // alice's USDT change
	solverFeeUSDT   = uint64(5)   // = aliceUSDT - bobUSDT - change
)

// TestAssetAccountCovenant exercises a non-interactive USDT payment routed
// by an arbitrary "solver" bot. Alice pays Bob 50 USDT while keeping her
// total BTC commitment at exactly 330 sats (one dust unit): the solver
// advances 330 sats transiently and recovers them when Bob merges his
// claim back into his account VTXO.
//
// Phases:
//
//	Phase 0 — setup: alice mints 100 USDT into a 330-sat account VTXO.
//
//	Phase 1 — alice locks her entire 330-sat account into solverContract.
//	          aliceAccount (330 + 100 USDT) ──► solverContract (330 + 100)
//	          No BTC change — alice only needs 330 sats.
//
//	Phase 2 — solver routes (provides 330 sats of BTC dust transiently).
//	          solverContract + solver 100k ──► bobClaim       (330 + 50)
//	                                       └──► alice account  (330 + 45)
//	                                       └──► solverFee     (330 + 5)  partial-match
//	                                       └──► solver change
//	          Alice's 45-USDT change goes straight to her account pkScript:
//	          the 330 sats backing it came from her own Phase 1 input, so no
//	          claim covenant is needed.
//
//	Phase 3 — only bob has to claim (he owes the solver 330 sats refund).
//	          bobClaim + bobAccount ──► refund(330→solver) + bobAccount'
//
// Net BTC: alice never spent any (her account stays at 330 sats). Solver
// advanced 330 sats and got it back from bob.
//
// Educational simplifications: the covenants do not pin the asset_id (and
// drop the NUMASSETGROUPS == 1 gate). Asset substitution is therefore
// possible and should be mitigated in production by pinning (txid, gidx)
// on every OP_INSPECTOUTASSETAT call. Bob's account is also assumed empty
// (0 USDT) before the claim, which lets bobClaim pin output[1] USDT to 50.
func TestAssetAccountCovenant(t *testing.T) {
	ctx := t.Context()

	alice, aliceWallet, alicePubKey, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcAlice.Close() })
	aliceAddr := fundAndSettleAlice(t, ctx, alice, 100_000)

	bob, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcBob.Close() })
	_ = fundAndSettleAlice(t, ctx, bob, 100_000)

	solver, solverWallet, solverPubKey, grpcSolver := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcSolver.Close() })
	_ = fundAndSettleAlice(t, ctx, solver, 100_000)

	introspector, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		// nolint:errcheck
		conn.Close()
	})

	indexerSvc := setupIndexer(t)
	explorerSvc, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScript, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	server := aliceAddr.Signer
	exitDelay := uint32(infos.UnilateralExitDelay)

	// Each user's "account VTXO" is just their default-vtxo-script, the same
	// one a settle would create.
	bobAccount := defaultVtxoScript(bobPubKey, server, exitDelay)
	bobAccountPk := p2trScriptForVtxoScript(t, *bobAccount)
	aliceAccount := defaultVtxoScript(alicePubKey, server, exitDelay)
	aliceAccountPk := p2trScriptForVtxoScript(t, *aliceAccount)
	solverAccount := defaultVtxoScript(solverPubKey, server, exitDelay)
	solverAccountPk := p2trScriptForVtxoScript(t, *solverAccount)

	// Build the two covenants. Each is a bare arkade-tweaked closure: the
	// arkade script alone gates the spend — no human signature required.
	// (No aliceClaim — alice's 45-USDT change in Phase 2 goes directly to
	//  her account pkScript since she funded the dust herself in Phase 1.)
	bobClaimArkade := enforceBobClaim(t, solverAccountPk, bobAccountPk, solverBobUSDT)
	bobClaim := createArkadeOnlyVtxoScript(server, introspectorPubKey, arkade.ArkadeScriptHash(bobClaimArkade))
	bobClaimPk := p2trScriptForVtxoScript(t, bobClaim)

	solverArkade := enforceSolverRouting(t, bobClaimPk, aliceAccountPk)
	solverContract := createArkadeOnlyVtxoScript(server, introspectorPubKey, arkade.ArkadeScriptHash(solverArkade))
	solverContractPk := p2trScriptForVtxoScript(t, solverContract)

	// =========================================================================
	// Phase 0 — mint 100 USDT into a fresh 330-sat alice account VTXO.
	// =========================================================================

	mintTx, mintCps := buildWalletFundedTx(
		t, ctx, alice, indexerSvc, alicePubKey, server, exitDelay,
		[]*wire.TxOut{{Value: solverDust, PkScript: aliceAccountPk}},
		checkpointScript,
	)
	addAssetPacketToTx(t, mintTx, createIssuanceAssetPacket(t, 0, solverAliceUSDT))
	submitWithArkd(t, ctx, mintTx, mintCps, aliceWallet, grpcAlice)

	mintTxHash := mintTx.UnsignedTx.TxHash()
	aliceAccountInput := vtxoInputFromScriptOutput(
		t, mintTx.UnsignedTx, 0, *aliceAccount, onlyForfeitScript(t, *aliceAccount),
	)

	// =========================================================================
	// Phase 1 — alice spends her entire 330-sat account into solverContract.
	// No BTC change: the 330 sats == one dust unit == alice's only commitment.
	// =========================================================================

	lockTx, lockCps, err := offchain.BuildTxs(
		[]offchain.VtxoInput{aliceAccountInput},
		[]*wire.TxOut{{Value: solverDust, PkScript: solverContractPk}},
		checkpointScript,
	)
	require.NoError(t, err)
	addAssetPacketToTx(t, lockTx, createTransferAssetPacket(t, mintTxHash, 0, 0, 0, solverAliceUSDT))
	submitWithArkd(t, ctx, lockTx, lockCps, aliceWallet, grpcAlice)

	solverContractInput := vtxoInputFromScriptOutput(
		t, lockTx.UnsignedTx, 0, solverContract, onlyForfeitScript(t, solverContract),
	)

	// =========================================================================
	// Phase 2 — solver routes the covenant. Solver's BTC VTXO covers the dust
	// delta; one of the dust outputs (bobClaim) is the 330 sats the solver
	// will recover from bob in Phase 3.
	// =========================================================================

	solverBtcInput := findAccountInput(t, ctx, solver, indexerSvc, *solverAccount)

	// Random P2TR for the fee output — proof that output[2] only requires a
	// *partial* match (pkScript free, BTC + USDT pinned).
	solverFeePk := randomP2TRScript(t)
	solverChangeBtc := solverContractInput.Amount + solverBtcInput.Amount - 3*solverDust

	buildRoute := func(outputs []*wire.TxOut, packet asset.Packet) (*psbt.Packet, []*psbt.Packet) {
		t.Helper()
		ptx, cps, err := offchain.BuildTxs(
			[]offchain.VtxoInput{solverContractInput, solverBtcInput},
			outputs, checkpointScript,
		)
		require.NoError(t, err)
		addAssetPacketToTx(t, ptx, packet)
		addIntrospectorPacket(t, ptx, []arkade.IntrospectorEntry{{Vin: 0, Script: solverArkade}})
		return ptx, cps
	}

	defaultRouteOuts := []*wire.TxOut{
		{Value: solverDust, PkScript: bobClaimPk},
		{Value: solverDust, PkScript: aliceAccountPk}, // alice's change: directly to her account
		{Value: solverDust, PkScript: solverFeePk},
		{Value: solverChangeBtc, PkScript: solverAccountPk},
	}
	defaultRoutePkt := buildRoutePacket(t, mintTxHash, solverBobUSDT, solverChange, solverFeeUSDT)

	submitRoute := func(ptx *psbt.Packet, cps []*psbt.Packet) error {
		t.Helper()
		// Solver signs only its own BTC input (vin=1); the covenant input is
		// signed by the introspector after the arkade script passes.
		signed, err := solverWallet.SignTransaction(ctx, explorerSvc, b64(t, ptx))
		require.NoError(t, err)
		_, _, err = introspector.SubmitTx(ctx, signed, signCheckpoints(t, ctx, solverWallet, explorerSvc, cps))
		return err
	}

	// Invalid: wrong claim destination on output[0].
	{
		bad := append([]*wire.TxOut(nil), defaultRouteOuts...)
		bad[0] = &wire.TxOut{Value: solverDust, PkScript: randomP2TRScript(t)}
		err := submitRoute(buildRoute(bad, defaultRoutePkt))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	// Invalid: wrong USDT amount on alice change output.
	{
		err := submitRoute(buildRoute(
			defaultRouteOuts,
			buildRoutePacket(t, mintTxHash, solverBobUSDT, solverChange-1, solverFeeUSDT),
		))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	// Valid: solver picks any pkScript for its fee output.
	routeTx, routeCps := buildRoute(defaultRouteOuts, defaultRoutePkt)
	waitClaims := watchForPreconfirmedVtxos(t, indexerSvc, routeTx, 0, 1, 2)
	require.NoError(t, submitRoute(routeTx, routeCps))
	waitClaims()

	bobClaimInput := vtxoInputFromScriptOutput(t, routeTx.UnsignedTx, 0, bobClaim, onlyForfeitScript(t, bobClaim))

	// =========================================================================
	// Phase 3 — only bob merges. Bob's merge refunds 330 sats to the solver,
	// closing the loop on the dust advance. Alice has nothing to do — her
	// 45-USDT VTXO from Phase 2 is already at her account pkScript.
	// =========================================================================

	bobAccountInput := findAccountInput(t, ctx, bob, indexerSvc, *bobAccount)
	bobMergeTx, bobMergeCps, err := offchain.BuildTxs(
		[]offchain.VtxoInput{bobClaimInput, bobAccountInput},
		[]*wire.TxOut{
			{Value: solverDust, PkScript: solverAccountPk},          // refund
			{Value: bobAccountInput.Amount, PkScript: bobAccountPk}, // bob account'
		},
		checkpointScript,
	)
	require.NoError(t, err)
	addAssetPacketToTx(t, bobMergeTx, createTransferAssetPacket(t, mintTxHash, 0, 0, 1, solverBobUSDT))
	addIntrospectorPacket(t, bobMergeTx, []arkade.IntrospectorEntry{{Vin: 0, Script: bobClaimArkade}})

	waitBob := watchForPreconfirmedVtxos(t, indexerSvc, bobMergeTx, 1)
	signedBob, err := bobWallet.SignTransaction(ctx, explorerSvc, b64(t, bobMergeTx))
	require.NoError(t, err)
	_, _, err = introspector.SubmitTx(ctx, signedBob, signCheckpoints(t, ctx, bobWallet, explorerSvc, bobMergeCps))
	require.NoError(t, err)
	waitBob()
}

// enforceSolverRouting builds the arkade script gating the solver's spend of
// solverContract:
//
//	output[0] = bobClaim       (330 sats + 50 USDT, full pkScript match)
//	output[1] = alice account  (330 sats + 45 USDT, full pkScript match)
//	output[2] = solver fee     (330 sats + 5 USDT, *any* pkScript)
//
// OP_INSPECTOUTASSETAT pushes (txid, gidx, amount). We drop txid+gidx with
// OP_NIP OP_NIP and keep only the amount — see the test doc on the
// asset-substitution caveat.
func enforceSolverRouting(t *testing.T, bobClaimPk, aliceAccountPk []byte) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		// output[0] — bobClaim
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(bobClaimPk[2:]).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(solverDust).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddInt64(0).AddOp(arkade.OP_INSPECTOUTASSETAT).
		AddOp(arkade.OP_NIP).AddOp(arkade.OP_NIP).
		AddInt64(int64(solverBobUSDT)).AddOp(arkade.OP_EQUALVERIFY).
		// output[1] — alice account (her change)
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(aliceAccountPk[2:]).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(solverDust).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).AddInt64(0).AddOp(arkade.OP_INSPECTOUTASSETAT).
		AddOp(arkade.OP_NIP).AddOp(arkade.OP_NIP).
		AddInt64(int64(solverChange)).AddOp(arkade.OP_EQUALVERIFY).
		// output[2] — solver fee (pkScript free)
		AddInt64(2).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(solverDust).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(2).AddInt64(0).AddOp(arkade.OP_INSPECTOUTASSETAT).
		AddOp(arkade.OP_NIP).AddOp(arkade.OP_NIP).
		AddInt64(int64(solverFeeUSDT)).AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)
	return s
}

// enforceBobClaim gates bob's merge of bobClaim into his account VTXO:
//
//	output[0] = 330 sats to solverPk      (the BTC refund — closes the loop)
//	output[1] = bob's account pkScript with exactly bobUSDT at group 0
//
// The asset-packet balance handles output[1]'s BTC value (we don't pin it).
func enforceBobClaim(t *testing.T, solverPk, bobAccountPk []byte, bobUSDT uint64) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddInt64(0).AddOp(arkade.OP_EQUALVERIFY).
		// output[0] — solver refund
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(solverPk[2:]).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddInt64(solverDust).AddOp(arkade.OP_EQUALVERIFY).
		// output[1] — bob's reformed account
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY).
		AddData(bobAccountPk[2:]).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).AddInt64(0).AddOp(arkade.OP_INSPECTOUTASSETAT).
		AddOp(arkade.OP_NIP).AddOp(arkade.OP_NIP).
		AddInt64(int64(bobUSDT)).AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)
	return s
}

// buildRoutePacket creates the asset transfer packet for the solver's route:
// one input (vin=0, sum = bob+change+fee) → three outputs (vout=0,1,2).
func buildRoutePacket(t *testing.T, mintTxHash chainhash.Hash, bob, change, fee uint64) asset.Packet {
	t.Helper()
	id := &asset.AssetId{Txid: [asset.TX_HASH_SIZE]byte(mintTxHash), Index: 0}
	in, err := asset.NewAssetInput(0, bob+change+fee)
	require.NoError(t, err)
	o0, err := asset.NewAssetOutput(0, bob)
	require.NoError(t, err)
	o1, err := asset.NewAssetOutput(1, change)
	require.NoError(t, err)
	o2, err := asset.NewAssetOutput(2, fee)
	require.NoError(t, err)
	grp, err := asset.NewAssetGroup(id, nil,
		[]asset.AssetInput{*in},
		[]asset.AssetOutput{*o0, *o1, *o2},
		[]asset.Metadata{},
	)
	require.NoError(t, err)
	pkt, err := asset.NewPacket([]asset.AssetGroup{*grp})
	require.NoError(t, err)
	return pkt
}

// findAccountInput resolves a user's settled account VTXO into a spendable
// offchain.VtxoInput.
func findAccountInput(
	t *testing.T, ctx context.Context,
	sdk arksdk.ArkClient, indexerSvc indexer.Indexer,
	accountVtxoScript script.TapscriptsVtxoScript,
) offchain.VtxoInput {
	t.Helper()
	pk := p2trScriptForVtxoScript(t, accountVtxoScript)

	spendable, _, err := sdk.ListVtxos(ctx)
	require.NoError(t, err)

	var account types.Vtxo
	for _, v := range spendable {
		if v.Script == hex.EncodeToString(pk) {
			account = v
			break
		}
	}
	require.NotEmpty(t, account.Txid, "account vtxo not found")

	prev, err := indexerSvc.GetVirtualTxs(ctx, []string{account.Txid})
	require.NoError(t, err)
	require.Len(t, prev.Txs, 1)

	prevPtx, err := psbt.NewFromRawBytes(strings.NewReader(prev.Txs[0]), true)
	require.NoError(t, err)

	return vtxoInputFromScriptOutput(
		t, prevPtx.UnsignedTx, account.VOut,
		accountVtxoScript, onlyForfeitScript(t, accountVtxoScript),
	)
}

// defaultVtxoScript is the canonical user-account VTXO script: 2-of-2 multisig
// (user + server) with a CSV unilateral-exit closure.
func defaultVtxoScript(userPubKey, serverSigner *btcec.PublicKey, exitDelay uint32) *script.TapscriptsVtxoScript {
	lt := arklib.LocktimeTypeBlock
	if exitDelay >= 512 {
		lt = arklib.LocktimeTypeSecond
	}
	return script.NewDefaultVtxoScript(
		userPubKey, serverSigner,
		arklib.RelativeLocktime{Type: lt, Value: exitDelay},
	)
}

func b64(t *testing.T, ptx *psbt.Packet) string {
	t.Helper()
	s, err := ptx.B64Encode()
	require.NoError(t, err)
	return s
}

func signCheckpoints(
	t *testing.T, ctx context.Context,
	w wallet.WalletService, exp explorer.Explorer,
	cps []*psbt.Packet,
) []string {
	t.Helper()
	out := make([]string, 0, len(cps))
	for _, cp := range cps {
		signed, err := w.SignTransaction(ctx, exp, b64(t, cp))
		require.NoError(t, err)
		out = append(out, signed)
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
