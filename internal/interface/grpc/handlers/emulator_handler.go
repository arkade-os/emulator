package handlers

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/internal/application"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/psbt/v2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type handler struct {
	version string
	svc     application.Service
}

func New(version string, service application.Service) *handler {
	return &handler{version: version, svc: service}
}

func (h *handler) GetInfo(
	ctx context.Context, _ *emulatorv1.GetInfoRequest,
) (*emulatorv1.GetInfoResponse, error) {
	info, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, serviceError(err, "failed to get info")
	}

	return &emulatorv1.GetInfoResponse{
		OperatorPubkey:            info.SignerPublicKey,
		DeprecatedOperatorPubkeys: append([]string(nil), info.DeprecatedSignerPublicKeys...),
		Version:                   h.version,
	}, nil
}

func (h *handler) SubmitOffchainTx(
	ctx context.Context, req *emulatorv1.SubmitOffchainTxRequest,
) (*emulatorv1.SubmitOffchainTxResponse, error) {
	arkTx := req.GetArkadeTx()
	checkpoints := req.GetCheckpointTxs()

	if len(arkTx) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing arkade tx")
	}

	if len(checkpoints) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing checkpoint txs")
	}

	arkPtx, err := parsePsbt(arkTx)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid arkade tx: %v", err)
	}

	checkpointPsbt := make([]*psbt.Packet, 0, len(checkpoints))
	for i, checkpoint := range checkpoints {
		checkpointPtx, err := parsePsbt(checkpoint)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid checkpoint tx %d: %v", i, err)
		}
		checkpointPsbt = append(checkpointPsbt, checkpointPtx)
	}

	offchainTx := emulator.OffchainTx{
		ArkTx:       arkPtx,
		Checkpoints: checkpointPsbt,
	}

	approvedTx, err := h.svc.SubmitTx(ctx, offchainTx)
	if err != nil {
		return nil, serviceError(err, "failed to process transaction")
	}

	encodedArkTx, err := approvedTx.ArkTx.B64Encode()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode arkade tx")
	}

	encodedCheckpointTxs := make([]string, 0, len(approvedTx.Checkpoints))
	for _, checkpoint := range approvedTx.Checkpoints {
		encodedCheckpointTx, err := checkpoint.B64Encode()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode checkpoint tx")
		}
		encodedCheckpointTxs = append(encodedCheckpointTxs, encodedCheckpointTx)
	}

	return &emulatorv1.SubmitOffchainTxResponse{
		SignedArkadeTx:      encodedArkTx,
		SignedCheckpointTxs: encodedCheckpointTxs,
	}, nil
}

func (h *handler) SubmitProof(
	ctx context.Context, req *emulatorv1.SubmitProofRequest,
) (*emulatorv1.SubmitProofResponse, error) {
	unsignedProof := req.GetBip322Proof()

	if unsignedProof == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bip322 proof")
	}

	proof, err := parseBip322Proof(unsignedProof)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid bip322 proof: %v", err))
	}

	signedProof, err := h.svc.SubmitIntent(ctx, *proof)
	if err != nil {
		return nil, serviceError(err, "failed to process bip322 proof")
	}

	encodedProof, err := signedProof.B64Encode()
	if err != nil {
		log.WithError(err).Error("failed to encode bip322 proof")
		return nil, status.Error(codes.Internal, internalErrMsg)
	}

	return &emulatorv1.SubmitProofResponse{
		SignedProof: encodedProof,
	}, nil
}

func (h *handler) SubmitForfeitTxs(
	ctx context.Context, req *emulatorv1.SubmitForfeitTxsRequest,
) (*emulatorv1.SubmitForfeitTxsResponse, error) {
	signedProof := req.GetSignedBip322Proof()
	forfeitTxs := req.GetForfeits()
	connectorTree := req.GetConnectorTree()
	commitmentTx := req.GetCommitmentTx()

	if signedProof == nil {
		return nil, status.Error(codes.InvalidArgument, "missing signed bip322 proof")
	}

	proof, err := parseBip322Proof(signedProof)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid signed bip322 proof: %v", err))
	}

	if len(commitmentTx) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing commitment tx")
	}

	commitmentPtx, err := parsePsbt(commitmentTx)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid commitment tx: %v", err)
	}

	forfeitPsbt := make([]*psbt.Packet, 0, len(forfeitTxs))
	for i, forfeit := range forfeitTxs {
		forfeitPtx, err := parsePsbt(forfeit)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid forfeit tx %d: %v", i, err)
		}
		forfeitPsbt = append(forfeitPsbt, forfeitPtx)
	}

	batchFinalization := emulator.BatchFinalization{
		Proofs:       []emulator.Proof{*proof},
		Forfeits:     forfeitPsbt,
		CommitmentTx: commitmentPtx,
	}

	var connectorTxTree *tree.TxTree
	if len(forfeitPsbt) > 0 {
		if len(connectorTree) <= 0 {
			return nil, status.Error(codes.InvalidArgument, "missing connector tree")
		}

		connectorTxTree, err = parseTxTree(connectorTree)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid connector tree: %v", err))
		}

		if err := verifyTreeRelatedToCommitment(commitmentPtx, connectorTxTree); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid connector tree: %v", err))
		}

	}

	signedBatchFinalization, err := h.svc.SubmitFinalization(ctx, batchFinalization, connectorTxTree)
	if err != nil {
		return nil, serviceError(err, "failed to process forfeit txs")
	}

	encodedForfeits := make([]string, 0, len(signedBatchFinalization.Forfeits))
	for _, forfeit := range signedBatchFinalization.Forfeits {
		encodedForfeit, err := forfeit.B64Encode()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode forfeit")
		}
		encodedForfeits = append(encodedForfeits, encodedForfeit)
	}

	resp := &emulatorv1.SubmitForfeitTxsResponse{
		SignedForfeits: encodedForfeits,
	}

	if signedBatchFinalization.CommitmentTx != nil {
		encodedCommitmentTx, err := signedBatchFinalization.CommitmentTx.B64Encode()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode commitment tx")
		}
		resp.SignedCommitmentTx = encodedCommitmentTx
	}

	return resp, nil
}

func (h *handler) SubmitOnchainTx(
	ctx context.Context, req *emulatorv1.SubmitOnchainTxRequest,
) (*emulatorv1.SubmitOnchainTxResponse, error) {
	b64 := req.GetTx()
	if len(b64) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing tx")
	}

	ptx, err := parsePsbt(b64)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tx: %v", err)
	}

	signed, err := h.svc.SubmitOnchainTx(ctx, emulator.OnchainTx{Tx: ptx})
	if err != nil {
		return nil, serviceError(err, "failed to process onchain tx")
	}

	encoded, err := signed.B64Encode()
	if err != nil {
		log.WithError(err).Error("failed to encode onchain tx")
		return nil, status.Error(codes.Internal, internalErrMsg)
	}

	return &emulatorv1.SubmitOnchainTxResponse{SignedTx: encoded}, nil
}

func verifyTreeRelatedToCommitment(commitmentPtx *psbt.Packet, txTree *tree.TxTree) error {
	if len(txTree.Root.UnsignedTx.TxIn) != 1 {
		return fmt.Errorf("invalid tx tree root")
	}

	rootInput := txTree.Root.UnsignedTx.TxIn[0]
	if rootInput.PreviousOutPoint.Hash.String() != commitmentPtx.UnsignedTx.TxID() {
		return fmt.Errorf("root is not commitment tx")
	}

	if int(rootInput.PreviousOutPoint.Index) >= len(commitmentPtx.UnsignedTx.TxOut) {
		return fmt.Errorf("root input index out of range")
	}

	return nil
}

func parseTxTree(fromProto []*emulatorv1.TxTreeNode) (*tree.TxTree, error) {
	flat := make(tree.FlatTxTree, 0)
	for _, node := range fromProto {
		flat = append(flat, tree.TxTreeNode{
			Txid:     node.GetTxid(),
			Tx:       node.GetTx(),
			Children: node.GetChildren(),
		})
	}

	txTree, err := tree.NewTxTree(flat)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx tree: %w", err)
	}
	if err := txTree.Validate(); err != nil {
		return nil, fmt.Errorf("invalid tx tree: %w", err)
	}

	return txTree, nil
}
