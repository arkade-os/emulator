package client

import (
	"context"

	emulatorv1 "github.com/ArkLabsHQ/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"google.golang.org/grpc"
)

type Info struct {
	Version                    string
	SignerPublicKey            string
	DeprecatedSignerPublicKeys []string
}

type Intent struct {
	Proof   string
	Message string
}

type TransportClient interface {
	GetInfo(ctx context.Context) (*Info, error)
	SubmitTx(ctx context.Context, tx string, checkpoints []string) (
		signedTx string, signedCheckpoints []string, err error,
	)
	SubmitIntent(ctx context.Context, intent Intent) (signedProof string, err error)
	SubmitFinalization(
		ctx context.Context,
		intent Intent,
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
		Version:                    resp.GetVersion(),
		SignerPublicKey:            resp.GetSignerPubkey(),
		DeprecatedSignerPublicKeys: append([]string(nil), resp.GetDeprecatedSignerPubkeys()...),
	}, nil
}

func (c *grpcClient) SubmitTx(ctx context.Context, tx string, checkpoints []string) (signedTx string, signedCheckpoints []string, err error) {
	req := &emulatorv1.SubmitTxRequest{
		ArkTx:         tx,
		CheckpointTxs: checkpoints,
	}

	resp, err := c.client.SubmitTx(ctx, req)
	if err != nil {
		return "", nil, err
	}

	return resp.GetSignedArkTx(), resp.GetSignedCheckpointTxs(), nil
}

func (c *grpcClient) SubmitIntent(ctx context.Context, intent Intent) (string, error) {
	req := &emulatorv1.SubmitIntentRequest{
		Intent: &emulatorv1.Intent{
			Proof:   intent.Proof,
			Message: intent.Message,
		},
	}

	resp, err := c.client.SubmitIntent(ctx, req)
	if err != nil {
		return "", err
	}

	return resp.GetSignedProof(), nil
}

func (c *grpcClient) SubmitFinalization(
	ctx context.Context,
	intent Intent, forfeits []string,
	connectorTree tree.FlatTxTree, commitmentTx string,
) (signedForfeits []string, signedCommitmentTx string, err error) {
	connectorTreeNodes := castTxTree(connectorTree)

	req := &emulatorv1.SubmitFinalizationRequest{
		SignedIntent: &emulatorv1.Intent{
			Proof:   intent.Proof,
			Message: intent.Message,
		},
		Forfeits:      forfeits,
		ConnectorTree: connectorTreeNodes,
		CommitmentTx:  commitmentTx,
	}

	resp, err := c.client.SubmitFinalization(ctx, req)
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
