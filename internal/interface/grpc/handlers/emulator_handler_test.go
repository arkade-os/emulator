package handlers

import (
	"context"
	"fmt"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/internal/application"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// leakyDetail stands in for the kind of implementation detail an internal error
// can carry: paths, key material identifiers, internal state.
const leakyDetail = "/opt/signer/keys/secret.db: deprecated key #3 rejected sighash"

// failingService returns an error carrying leakyDetail from every signing call.
type failingService struct{}

func (failingService) GetInfo(context.Context) (*application.Info, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) SubmitTx(
	context.Context, emulator.OffchainTx,
) (*emulator.OffchainTx, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) SubmitIntent(
	context.Context, emulator.Proof,
) (*psbt.Packet, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) SubmitFinalization(
	context.Context, emulator.BatchFinalization, *tree.TxTree,
) (*application.SignedBatchFinalization, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) SubmitOnchainTx(
	context.Context, emulator.OnchainTx,
) (*psbt.Packet, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (failingService) Close() {}

// requireGenericInternal asserts the caller got a generic Internal error with no
// trace of the underlying detail.
func requireGenericInternal(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "expected a grpc status error, got %v", err)
	require.Equal(t, codes.Internal, st.Code())
	require.NotContains(t, st.Message(), leakyDetail)
	require.NotContains(t, st.Message(), "boom")
	require.Equal(t, internalErrMsg, st.Message())
}

// newBip322ProofProto builds a BIP322 proof the parser accepts, so the request reaches the
// application service.
func newBip322ProofProto(t *testing.T) *emulatorv1.Bip322Proof {
	t.Helper()
	msg := intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete},
	}
	return &emulatorv1.Bip322Proof{
		Proof:   newProofB64(t),
		Message: encodeMsg(t, msg),
	}
}

// TestInternalErrorsAreNotLeaked proves each signing endpoint returns a generic
// message rather than the raw internal error, which is reachable by
// unauthenticated callers.
func TestInternalErrorsAreNotLeaked(t *testing.T) {
	h := New("test", failingService{})
	ctx := context.Background()
	ptx := newProofB64(t)

	t.Run("SubmitOffchainTx", func(t *testing.T) {
		_, err := h.SubmitOffchainTx(ctx, &emulatorv1.SubmitOffchainTxRequest{
			ArkadeTx:      ptx,
			CheckpointTxs: []string{ptx},
		})
		requireGenericInternal(t, err)
	})

	t.Run("SubmitProof", func(t *testing.T) {
		_, err := h.SubmitProof(ctx, &emulatorv1.SubmitProofRequest{
			Bip322Proof: newBip322ProofProto(t),
		})
		requireGenericInternal(t, err)
	})

	t.Run("SubmitForfeitTxs", func(t *testing.T) {
		_, err := h.SubmitForfeitTxs(ctx, &emulatorv1.SubmitForfeitTxsRequest{
			SignedBip322Proof: newBip322ProofProto(t),
			CommitmentTx:      ptx,
		})
		requireGenericInternal(t, err)
	})

	t.Run("SubmitOnchainTx", func(t *testing.T) {
		_, err := h.SubmitOnchainTx(ctx, &emulatorv1.SubmitOnchainTxRequest{
			Tx: ptx,
		})
		requireGenericInternal(t, err)
	})
}

// TestValidationErrorsStayDescriptive pins the other half of the fix: errors a
// legitimate caller needs in order to correct its request are not genericized.
func TestValidationErrorsStayDescriptive(t *testing.T) {
	h := New("test", failingService{})
	ctx := context.Background()

	_, err := h.SubmitOffchainTx(ctx, &emulatorv1.SubmitOffchainTxRequest{})
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "missing arkade tx", st.Message())

	_, err = h.SubmitOnchainTx(ctx, &emulatorv1.SubmitOnchainTxRequest{Tx: "not-a-psbt"})
	st, ok = status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "invalid tx: illegal base64 data at input byte 3", st.Message())
}
