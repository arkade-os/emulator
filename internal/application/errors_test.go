package application

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestArkdRejection(t *testing.T) {
	t.Run("relayable status keeps code and arkd message", func(t *testing.T) {
		err := status.Error(
			codes.InvalidArgument, "ASSET_INPUT_INVALID (35): amount mismatch: 10000 != 10",
		)
		rej := arkdRejection(err)
		require.NotNil(t, rej)
		require.Equal(t, codes.InvalidArgument, rej.Code)
		require.Equal(t, "ASSET_INPUT_INVALID (35): amount mismatch: 10000 != 10", rej.Msg)
		require.ErrorContains(t, rej, "arkd rejected the tx")
		require.ErrorContains(t, rej, "10000 != 10")
	})

	t.Run("wrapped status keeps the inner arkd message", func(t *testing.T) {
		inner := status.Error(codes.FailedPrecondition, "checkpoint tx already finalized")
		err := fmt.Errorf("retry exhausted after attempt 15: %w", inner)
		rej := arkdRejection(err)
		require.NotNil(t, rej)
		require.Equal(t, codes.FailedPrecondition, rej.Code)
		require.Equal(t, "checkpoint tx already finalized", rej.Msg)
	})

	t.Run("server faults are not relayed", func(t *testing.T) {
		require.Nil(t, arkdRejection(status.Error(codes.Internal, "db down")))
		require.Nil(t, arkdRejection(status.Error(codes.Unavailable, "connection refused")))
		require.Nil(t, arkdRejection(status.Error(codes.Unknown, "unexpected")))
	})

	t.Run("non-status errors are not relayed", func(t *testing.T) {
		require.Nil(t, arkdRejection(errors.New("arkd rejected tx")))
	})
}

// TestSubmitTxRelaysArkdRejection proves a deterministic arkd refusal of the
// forwarded tx surfaces as an *ArkdError, not a generic wrapped failure.
func TestSubmitTxRelaysArkdRejection(t *testing.T) {
	svc, tx, arkd := newTestService(t, true)
	arkd.submitErr = status.Error(
		codes.InvalidArgument, "ASSET_INPUT_INVALID (35): amount mismatch: 10000 != 10",
	)

	out, err := svc.SubmitTx(t.Context(), tx)
	require.Nil(t, out)

	var arkdErr *ArkdError
	require.ErrorAs(t, err, &arkdErr)
	require.Equal(t, codes.InvalidArgument, arkdErr.Code)
	require.ErrorContains(t, err, "ASSET_INPUT_INVALID (35): amount mismatch: 10000 != 10")
	require.Equal(t, 1, arkd.submitCalls)
	require.Zero(t, arkd.finalizeCalls)
}

// TestSubmitTxHidesArkdFault proves a non-relayable arkd failure keeps the
// existing generic wrap.
func TestSubmitTxHidesArkdFault(t *testing.T) {
	svc, tx, arkd := newTestService(t, true)
	arkd.submitErr = status.Error(codes.Unavailable, "connection refused")

	out, err := svc.SubmitTx(t.Context(), tx)
	require.Nil(t, out)

	var arkdErr *ArkdError
	require.False(t, errors.As(err, &arkdErr))
	require.ErrorContains(t, err, "failed to submit tx on arkd")
}
