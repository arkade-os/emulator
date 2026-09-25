package application

import (
	"context"
	"fmt"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// fetchOffchainData returns the arkd indexer data of the given vtxos; the
// signer rejects any required vtxo missing from the result.
func (s *service) fetchOffchainData(
	ctx context.Context, outpoints []wire.OutPoint,
) (emulator.OffchainData, error) {
	var data emulator.OffchainData
	if len(outpoints) == 0 {
		return data, nil
	}
	query := make([]clientlib.Outpoint, 0, len(outpoints))
	for _, outpoint := range outpoints {
		query = append(query, clientlib.Outpoint{Txid: outpoint.Hash.String(), VOut: outpoint.Index})
	}
	var response *clientlib.VtxosResponse
	err := retryWithBackoff(ctx, indexerRetryConfig,
		func() error {
			var err error
			response, err = s.indexer.GetVtxos(ctx, clientlib.WithOutpoints(query))
			return err
		}, nil,
	)
	if err != nil {
		return data, fmt.Errorf("failed to fetch vtxos: %w", err)
	}
	data.VtxoExpiries = make(map[wire.OutPoint]int64, len(outpoints))
	if response == nil {
		return data, nil
	}
	for _, vtxo := range response.Vtxos {
		hash, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return data, fmt.Errorf("invalid vtxo txid %s: %w", vtxo.Txid, err)
		}
		data.VtxoExpiries[wire.OutPoint{Hash: *hash, Index: vtxo.VOut}] = vtxo.ExpiresAt.Unix()
	}
	return data, nil
}
