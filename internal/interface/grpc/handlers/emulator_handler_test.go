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

// newIntentProto builds an intent the parser accepts, so the request reaches
// the application service.
func newIntentProto(t *testing.T) *emulatorv1.Intent {
	t.Helper()
	msg := intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{Type: intent.IntentMessageTypeDelete},
	}
	return &emulatorv1.Intent{
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

	t.Run("SubmitTx", func(t *testing.T) {
		_, err := h.SubmitTx(ctx, &emulatorv1.SubmitTxRequest{
			ArkTx:         ptx,
			CheckpointTxs: []string{ptx},
		})
		requireGenericInternal(t, err)
	})

	t.Run("SubmitIntent", func(t *testing.T) {
		_, err := h.SubmitIntent(ctx, &emulatorv1.SubmitIntentRequest{
			Intent: newIntentProto(t),
		})
		requireGenericInternal(t, err)
	})

	t.Run("SubmitFinalization", func(t *testing.T) {
		_, err := h.SubmitFinalization(ctx, &emulatorv1.SubmitFinalizationRequest{
			SignedIntent: newIntentProto(t),
			CommitmentTx: ptx,
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

// scriptVerdict stands in for the emulator's deterministic rejection of the
// caller's own transaction: its detail describes the caller's script, so it is
// safe and useful to relay.
const scriptVerdict = "emulate offchain tx ark_txid=deadbeef: input 0: failed to execute arkade script: " +
	"script=1 opcode=OP_EQUAL position=2: final script validation failed: " +
	"false stack entry at end of script execution"

// arkdVerdict stands in for a deterministic arkd refusal of the forwarded tx.
const arkdVerdict = "ASSET_INPUT_INVALID (35): input 0 owns asset 3c7321 but amount mismatch: 10000 != 10"

// rejectingService refuses every signing call with a classified rejection.
type rejectingService struct{}

func (rejectingService) GetInfo(context.Context) (*application.Info, error) {
	return nil, fmt.Errorf("boom: %s", leakyDetail)
}

func (rejectingService) SubmitTx(
	context.Context, emulator.OffchainTx,
) (*emulator.OffchainTx, error) {
	return nil, &emulator.Error{
		Operation:       "emulate offchain tx",
		TransactionKind: "ark",
		TxID:            "deadbeef",
		Err: fmt.Errorf(
			"input 0: failed to execute arkade script: script=1 opcode=OP_EQUAL position=2: " +
				"final script validation failed: false stack entry at end of script execution",
		),
	}
}

func (rejectingService) SubmitIntent(
	context.Context, emulator.Proof,
) (*psbt.Packet, error) {
	return nil, &application.ArkdError{
		Code: codes.InvalidArgument,
		Msg:  arkdVerdict,
		Err:  status.Error(codes.InvalidArgument, arkdVerdict),
	}
}

func (rejectingService) SubmitFinalization(
	context.Context, emulator.BatchFinalization, *tree.TxTree,
) (*application.SignedBatchFinalization, error) {
	return nil, &emulator.Error{
		Operation:       "emulate batch finalization",
		TransactionKind: "forfeit",
		TxID:            "deadbeef",
		Err:             fmt.Errorf("missing signature for approved input 0"),
	}
}

func (rejectingService) SubmitOnchainTx(
	context.Context, emulator.OnchainTx,
) (*psbt.Packet, error) {
	return nil, &emulator.Error{
		Operation:       "emulate onchain tx",
		TransactionKind: "onchain",
		TxID:            "deadbeef",
		Err:             fmt.Errorf("input 0: failed to execute arkade script: %s", scriptVerdict),
	}
}

func (rejectingService) Close() {}

// TestRejectionsAreRelayed proves deterministic rejections of the caller's own
// transaction reach the caller with a fitting status code and the full
// message, instead of a generic internal error.
func TestRejectionsAreRelayed(t *testing.T) {
	h := New("test", rejectingService{})
	ctx := context.Background()
	ptx := newProofB64(t)

	t.Run("SubmitTx relays the emulation verdict", func(t *testing.T) {
		_, err := h.SubmitTx(ctx, &emulatorv1.SubmitTxRequest{
			ArkTx:         ptx,
			CheckpointTxs: []string{ptx},
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
		require.Equal(t, scriptVerdict, st.Message())
	})

	t.Run("SubmitIntent relays the arkd status and message", func(t *testing.T) {
		_, err := h.SubmitIntent(ctx, &emulatorv1.SubmitIntentRequest{
			Intent: newIntentProto(t),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
		require.Contains(t, st.Message(), arkdVerdict)
	})

	t.Run("SubmitFinalization relays the emulation verdict", func(t *testing.T) {
		_, err := h.SubmitFinalization(ctx, &emulatorv1.SubmitFinalizationRequest{
			SignedIntent: newIntentProto(t),
			CommitmentTx: ptx,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
		require.Contains(t, st.Message(), "missing signature for approved input 0")
	})

	t.Run("SubmitOnchainTx relays the emulation verdict", func(t *testing.T) {
		_, err := h.SubmitOnchainTx(ctx, &emulatorv1.SubmitOnchainTxRequest{
			Tx: ptx,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
		require.Contains(t, st.Message(), "opcode=OP_EQUAL position=2")
	})
}

// TestValidationErrorsStayDescriptive pins the other half of the fix: errors a
// legitimate caller needs in order to correct its request are not genericized.
func TestValidationErrorsStayDescriptive(t *testing.T) {
	h := New("test", failingService{})
	ctx := context.Background()

	_, err := h.SubmitTx(ctx, &emulatorv1.SubmitTxRequest{})
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "missing ark tx", st.Message())

	_, err = h.SubmitOnchainTx(ctx, &emulatorv1.SubmitOnchainTxRequest{Tx: "not-a-psbt"})
	st, ok = status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "invalid tx", st.Message())
}
