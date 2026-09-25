package application

import (
	"context"
	"fmt"

	"github.com/arkade-os/emulator/pkg/emulator"
)

// SubmitFinalization signs nothing unless the commitment tx is an arkd-built
// artifact: a client-chosen commitment tx (e.g. an ark tx spending a pending
// checkpoint outpoint) would let a replayed proof bypass the arkade script
// execution that justified it. arkd indexes its commitment txs on round
// finalization; the write may lag the RoundFinalizationStarted event, so retry.
func (s *service) SubmitFinalization(
	ctx context.Context, finalization emulator.BatchFinalization,
) (*emulator.SignedBatchFinalization, error) {
	if finalization.CommitmentTx == nil {
		return nil, fmt.Errorf("commitment tx is required")
	}
	commitmentTxid := finalization.CommitmentTx.UnsignedTx.TxID()
	err := retryWithBackoff(ctx, commitmentTxRetryConfig,
		func() error {
			_, err := s.indexer.GetCommitmentTx(ctx, commitmentTxid)
			return err
		}, nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"commitment tx %s not known to arkd indexer: %w", commitmentTxid, err,
		)
	}
	return s.Service.SubmitFinalization(ctx, finalization)
}
