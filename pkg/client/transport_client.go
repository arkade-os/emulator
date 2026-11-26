package client

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"google.golang.org/grpc"
)

type Info struct {
	Version                   string
	OperatorPubkey            string
	DeprecatedOperatorPubkeys []string
}

// Bip322Proof is a BIP322 proof. Proof is the base64 PSBT and Message is the canonical message
// the proof signs.
type Bip322Proof struct {
	Proof   string
	Message string
}

type TransportClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	SubmitOffchainTx(ctx context.Context, tx string, checkpoints []string) (
		signedTx string, signedCheckpoints []string, err error,
	)
	SubmitProof(ctx context.Context, proof Bip322Proof) (signedProof string, err error)
	SubmitForfeitTxs(
		ctx context.Context,
		proof Bip322Proof,
		forfeits []string,
		connectorTree tree.FlatTxTree, commitmentTx string,
	) (signedForfeits []string, signedCommitmentTx string, err error)
	SubmitOnchainTx(ctx context.Context, tx string) (signedTx string, err error)
}

// grpcClient implements TransportClient using gRPC
type grpcClient struct {
	client emulatorv1.EmulatorServiceClient
}

// NewGRPCClient creates a new gRPC-based transport client
func NewGRPCClient(conn *grpc.ClientConn) TransportClient {
	return &grpcClient{
		client: emulatorv1.NewEmulatorServiceClient(conn),
	}
}

func (c *grpcClient) GetInfo(ctx context.Context) (*Info, error) {
	req := &emulatorv1.GetInfoRequest{}
	resp, err := c.client.GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}

	return &Info{
		Version:                   resp.GetVersion(),
		OperatorPubkey:            resp.GetOperatorPubkey(),
		DeprecatedOperatorPubkeys: append([]string(nil), resp.GetDeprecatedOperatorPubkeys()...),
	}, nil
}

func (c *grpcClient) SubmitOffchainTx(
	ctx context.Context, tx string, checkpoints []string,
) (signedTx string, signedCheckpoints []string, err error) {
	req := &emulatorv1.SubmitOffchainTxRequest{
		ArkadeTx:      tx,
		CheckpointTxs: checkpoints,
	}

	resp, err := c.client.SubmitOffchainTx(ctx, req)
	if err != nil {
		return "", nil, err
	}

	return resp.GetSignedArkadeTx(), resp.GetSignedCheckpointTxs(), nil
}

func (c *grpcClient) SubmitProof(ctx context.Context, proof Bip322Proof) (string, error) {
	req := &emulatorv1.SubmitProofRequest{
		Bip322Proof: &emulatorv1.Bip322Proof{
			Proof:   proof.Proof,
			Message: proof.Message,
		},
	}

	resp, err := c.client.SubmitProof(ctx, req)
	if err != nil {
		return "", err
	}

	return resp.GetSignedProof(), nil
}

func (c *grpcClient) SubmitForfeitTxs(
	ctx context.Context,
	proof Bip322Proof, forfeits []string,
	connectorTree tree.FlatTxTree, commitmentTx string,
) (signedForfeits []string, signedCommitmentTx string, err error) {
	connectorTreeNodes := castTxTree(connectorTree)

	req := &emulatorv1.SubmitForfeitTxsRequest{
		SignedBip322Proof: &emulatorv1.Bip322Proof{
			Proof:   proof.Proof,
			Message: proof.Message,
		},
		Forfeits:      forfeits,
		ConnectorTree: connectorTreeNodes,
		CommitmentTx:  commitmentTx,
	}

	resp, err := c.client.SubmitForfeitTxs(ctx, req)
	if err != nil {
		return nil, "", err
	}

	return resp.GetSignedForfeits(), resp.GetSignedCommitmentTx(), nil
}

func (c *grpcClient) SubmitOnchainTx(ctx context.Context, tx string) (string, error) {
	req := &emulatorv1.SubmitOnchainTxRequest{Tx: tx}

	resp, err := c.client.SubmitOnchainTx(ctx, req)
	if err != nil {
		return "", err
	}

	return resp.GetSignedTx(), nil
}

func castTxTree(tree tree.FlatTxTree) []*emulatorv1.TxTreeNode {
	nodes := make([]*emulatorv1.TxTreeNode, 0, len(tree))
	for _, node := range tree {
		nodes = append(nodes, &emulatorv1.TxTreeNode{
			Txid:     node.Txid,
			Tx:       node.Tx,
			Children: node.Children,
		})
	}
	return nodes
}
