package handlers

import (
	"context"
	"fmt"
	"strings"

	emulatorv1 "github.com/ArkLabsHQ/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/ArkLabsHQ/emulator/internal/application"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcutil/psbt"
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
		return nil, err
	}

	return &emulatorv1.GetInfoResponse{
		SignerPubkey:            info.SignerPublicKey,
		DeprecatedSignerPubkeys: append([]string(nil), info.DeprecatedSignerPublicKeys...),
		Version:                 h.version,
	}, nil
}

func (h *handler) SubmitTx(
	ctx context.Context, req *emulatorv1.SubmitTxRequest,
) (*emulatorv1.SubmitTxResponse, error) {
	arkTx := req.GetArkTx()
	checkpoints := req.GetCheckpointTxs()

	if len(arkTx) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing ark tx")
	}

	if len(checkpoints) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing checkpoint txs")
	}

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(arkTx), true)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ark tx")
	}

	checkpointPsbt := make([]*psbt.Packet, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid checkpoint tx")
		}
		checkpointPsbt = append(checkpointPsbt, checkpointPtx)
	}

	offchainTx := application.OffchainTx{
		ArkTx:       arkPtx,
		Checkpoints: checkpointPsbt,
	}

	approvedTx, err := h.svc.SubmitTx(ctx, offchainTx)
	if err != nil {
		log.WithError(err).Error("failed to process transaction")
		return nil, status.Error(codes.Internal, "failed to process transaction")
	}

	encodedArkTx, err := approvedTx.ArkTx.B64Encode()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode ark tx")
	}

	encodedCheckpointTxs := make([]string, 0, len(approvedTx.Checkpoints))
	for _, checkpoint := range approvedTx.Checkpoints {
		encodedCheckpointTx, err := checkpoint.B64Encode()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode checkpoint tx")
		}
		encodedCheckpointTxs = append(encodedCheckpointTxs, encodedCheckpointTx)
	}

	return &emulatorv1.SubmitTxResponse{
		SignedArkTx:         encodedArkTx,
		SignedCheckpointTxs: encodedCheckpointTxs,
	}, nil
}

func (h *handler) SubmitIntent(
	ctx context.Context, req *emulatorv1.SubmitIntentRequest,
) (*emulatorv1.SubmitIntentResponse, error) {
	unsignedIntent := req.GetIntent()

	if unsignedIntent == nil {
		return nil, status.Error(codes.InvalidArgument, "missing intent")
	}

	intent, err := parseIntent(unsignedIntent)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid intent: %v", err))
	}

	signedIntentProof, err := h.svc.SubmitIntent(ctx, *intent)
	if err != nil {
		log.WithError(err).Error("failed to process intent")
		return nil, status.Error(codes.Internal, "failed to process intent")
	}

	encodedProof, err := signedIntentProof.B64Encode()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode proof")
	}

	return &emulatorv1.SubmitIntentResponse{
		SignedProof: encodedProof,
	}, nil
}

func (h *handler) SubmitFinalization(
	ctx context.Context, req *emulatorv1.SubmitFinalizationRequest,
) (*emulatorv1.SubmitFinalizationResponse, error) {
	signedIntent := req.GetSignedIntent()
	forfeitTxs := req.GetForfeits()
	connectorTree := req.GetConnectorTree()
	commitmentTx := req.GetCommitmentTx()

	if signedIntent == nil {
		return nil, status.Error(codes.InvalidArgument, "missing signed intent")
	}

	intent, err := parseIntent(signedIntent)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid signed intent: %v", err))
	}

	if len(commitmentTx) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing commitment tx")
	}

	commitmentPtx, err := psbt.NewFromRawBytes(strings.NewReader(commitmentTx), true)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid commitment tx")
	}

	forfeitPsbt := make([]*psbt.Packet, 0, len(forfeitTxs))
	for _, forfeit := range forfeitTxs {
		forfeitPtx, err := psbt.NewFromRawBytes(strings.NewReader(forfeit), true)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid forfeit tx")
		}
		forfeitPsbt = append(forfeitPsbt, forfeitPtx)
	}

	batchFinalization := application.BatchFinalization{
		Intent:       *intent,
		Forfeits:     forfeitPsbt,
		CommitmentTx: commitmentPtx,
	}

	if len(forfeitPsbt) > 0 {
		if len(connectorTree) <= 0 {
			return nil, status.Error(codes.InvalidArgument, "missing connector tree")
		}

		connectorTxTree, err := parseTxTree(connectorTree)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid connector tree: %v", err))
		}

		if err := verifyTreeRelatedToCommitment(commitmentPtx, connectorTxTree); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid connector tree: %v", err))
		}

		batchFinalization.ConnectorTree = connectorTxTree
	}

	signedBatchFinalization, err := h.svc.SubmitFinalization(ctx, batchFinalization)
	if err != nil {
		log.WithError(err).Error("failed to process finalization")
		return nil, status.Error(codes.Internal, "failed to process finalization")
	}

	encodedForfeits := make([]string, 0, len(signedBatchFinalization.Forfeits))
	for _, forfeit := range signedBatchFinalization.Forfeits {
		encodedForfeit, err := forfeit.B64Encode()
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode forfeit")
		}
		encodedForfeits = append(encodedForfeits, encodedForfeit)
	}

	resp := &emulatorv1.SubmitFinalizationResponse{
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

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid tx")
	}

	signed, err := h.svc.SubmitOnchainTx(ctx, application.OnchainTx{Tx: ptx})
	if err != nil {
		log.WithError(err).Error("failed to process onchain tx")
		return nil, status.Error(codes.Internal, "failed to process onchain tx")
	}

	encoded, err := signed.B64Encode()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode tx")
	}

	return &emulatorv1.SubmitOnchainTxResponse{SignedTx: encoded}, nil
}

func verifyTreeRelatedToCommitment(commitmentPtx *psbt.Packet, txTree *tree.TxTree) error {
	if len(txTree.Root.Inputs) != len(commitmentPtx.UnsignedTx.TxIn) {
		return fmt.Errorf("invalid number of inputs")
	}
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

func parseIntent(fromProto *emulatorv1.Intent) (*application.Intent, error) {
	proof := fromProto.GetProof()
	message := fromProto.GetMessage()

	if len(proof) <= 0 {
		return nil, fmt.Errorf("missing proof")
	}

	if len(message) <= 0 {
		return nil, fmt.Errorf("missing message")
	}

	proofPsbt, err := psbt.NewFromRawBytes(strings.NewReader(proof), true)
	if err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}

	var registerMessage intent.RegisterMessage
	if err := registerMessage.Decode(message); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	intentProof := intent.Proof{Packet: *proofPsbt}
	return &application.Intent{
		Proof:   intentProof,
		Message: registerMessage,
	}, nil
}
