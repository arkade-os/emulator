package emulator

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// fixtures are deterministic PSBTs built from fixed keys, see testdata/*.json
type fixtureFile struct {
	Valid   []fixtureCase `json:"valid"`
	Invalid []fixtureCase `json:"invalid"`
}

type fixtureCase struct {
	Name            string           `json:"name"`
	ArkTx           string           `json:"arkTx,omitempty"`
	Checkpoints     []string         `json:"checkpoints,omitempty"`
	Proof           string           `json:"proof,omitempty"`
	Message         string           `json:"message,omitempty"`
	Tx              string           `json:"tx,omitempty"`
	Intents         []string         `json:"intents,omitempty"`
	Forfeits        []string         `json:"forfeits,omitempty"`
	CommitmentTx    string           `json:"commitmentTx,omitempty"`
	VtxoExpiries    map[string]int64 `json:"vtxoExpiries,omitempty"`
	ExpiryOutpoints []string         `json:"expiryOutpoints,omitempty"`
	Requests        []fixtureRequest `json:"requests,omitempty"`
	ErrorContains   string           `json:"errorContains,omitempty"`
}

type fixtureRequest struct {
	Txid           string   `json:"txid"`
	InputIndex     int      `json:"inputIndex"`
	ScriptHash     string   `json:"scriptHash"`
	ClosurePubKeys []string `json:"closurePubKeys"`
}

var testService = New(arkade.DefaultComputeLimits())

func TestEmulateOffchainTx(t *testing.T) {
	fix := loadFixtures(t, "offchain_tx.json")
	for _, c := range fix.Valid {
		t.Run(c.Name, func(t *testing.T) {
			tx := offchainTx(t, c)
			requests, err := testService.EmulateOffchainTx(t.Context(), tx, offchainData(t, c))
			require.NoError(t, err)
			assertRequests(t, c.Requests, requests)

			outpoints, err := tx.ExpiryOutpoints()
			require.NoError(t, err)
			require.Equal(t, c.ExpiryOutpoints, outpointStrings(outpoints))
		})
	}
	for _, c := range fix.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			_, err := testService.EmulateOffchainTx(t.Context(), offchainTx(t, c), offchainData(t, c))
			require.ErrorContains(t, err, c.ErrorContains)
		})
	}
}

func TestEmulateIntent(t *testing.T) {
	fix := loadFixtures(t, "intent.json")
	for _, c := range fix.Valid {
		t.Run(c.Name, func(t *testing.T) {
			intent := intentFixture(t, c.Proof, c.Message)
			requests, err := testService.EmulateIntent(t.Context(), intent, offchainData(t, c))
			require.NoError(t, err)
			assertRequests(t, c.Requests, requests)

			outpoints, err := intent.ExpiryOutpoints()
			require.NoError(t, err)
			require.Equal(t, c.ExpiryOutpoints, outpointStrings(outpoints))
		})
	}
	for _, c := range fix.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			_, err := testService.EmulateIntent(t.Context(), intentFixture(t, c.Proof, c.Message), offchainData(t, c))
			require.ErrorContains(t, err, c.ErrorContains)
		})
	}
}

func TestEmulateOnchainTx(t *testing.T) {
	fix := loadFixtures(t, "onchain_tx.json")
	for _, c := range fix.Valid {
		t.Run(c.Name, func(t *testing.T) {
			requests, err := testService.EmulateOnchainTx(t.Context(), OnchainTx{Tx: decodePSBT(t, c.Tx)})
			require.NoError(t, err)
			assertRequests(t, c.Requests, requests)
		})
	}
	for _, c := range fix.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			_, err := testService.EmulateOnchainTx(t.Context(), OnchainTx{Tx: decodePSBT(t, c.Tx)})
			require.ErrorContains(t, err, c.ErrorContains)
		})
	}
}

func TestEmulateBatchFinalization(t *testing.T) {
	fix := loadFixtures(t, "batch_finalization.json")
	for _, c := range fix.Valid {
		t.Run(c.Name, func(t *testing.T) {
			requests, err := testService.EmulateBatchFinalization(t.Context(), batchFinalization(t, c))
			require.NoError(t, err)
			assertRequests(t, c.Requests, requests)
		})
	}
	for _, c := range fix.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			_, err := testService.EmulateBatchFinalization(t.Context(), batchFinalization(t, c))
			require.ErrorContains(t, err, c.ErrorContains)
		})
	}
}

func loadFixtures(t *testing.T, file string) fixtureFile {
	data, err := os.ReadFile("testdata/" + file)
	require.NoError(t, err)
	var fix fixtureFile
	require.NoError(t, json.Unmarshal(data, &fix))
	return fix
}

func assertRequests(t *testing.T, want []fixtureRequest, got []SignRequest) {
	require.Len(t, got, len(want))
	for i, req := range got {
		require.Equal(t, want[i].Txid, req.Packet.UnsignedTx.TxID())
		require.Equal(t, want[i].InputIndex, req.InputIndex)
		require.Equal(t, want[i].ScriptHash, hex.EncodeToString(req.ScriptHash))
		require.Equal(t, want[i].ClosurePubKeys, xonlyHex(req.ClosurePubKeys))
	}
}

func offchainTx(t *testing.T, c fixtureCase) OffchainTx {
	var arkTx *psbt.Packet
	if c.ArkTx != "" {
		arkTx = decodePSBT(t, c.ArkTx)
	}
	return OffchainTx{ArkTx: arkTx, Checkpoints: decodePSBTs(t, c.Checkpoints)}
}

func offchainData(t *testing.T, c fixtureCase) OffchainData {
	data := OffchainData{VtxoExpiries: map[wire.OutPoint]int64{}}
	for s, expiry := range c.VtxoExpiries {
		outpoint, err := wire.NewOutPointFromString(s)
		require.NoError(t, err)
		data.VtxoExpiries[*outpoint] = expiry
	}
	return data
}

func intentFixture(t *testing.T, proof, message string) Intent {
	return Intent{Proof: intent.Proof{Packet: *decodePSBT(t, proof)}, Message: message}
}

func batchFinalization(t *testing.T, c fixtureCase) BatchFinalization {
	finalization := BatchFinalization{Forfeits: decodePSBTs(t, c.Forfeits)}
	if c.CommitmentTx != "" {
		finalization.CommitmentTx = decodePSBT(t, c.CommitmentTx)
	}
	for _, proof := range c.Intents {
		finalization.Intents = append(finalization.Intents, intentFixture(t, proof, ""))
	}
	return finalization
}

func decodePSBT(t *testing.T, b64 string) *psbt.Packet {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	require.NoError(t, err)
	return ptx
}

func decodePSBTs(t *testing.T, b64s []string) []*psbt.Packet {
	packets := make([]*psbt.Packet, 0, len(b64s))
	for _, b64 := range b64s {
		packets = append(packets, decodePSBT(t, b64))
	}
	return packets
}

func xonlyHex(keys []*btcec.PublicKey) []string {
	var out []string
	for _, key := range keys {
		out = append(out, hex.EncodeToString(schnorr.SerializePubKey(key)))
	}
	return out
}

func outpointStrings(outpoints []wire.OutPoint) []string {
	var out []string
	for _, outpoint := range outpoints {
		out = append(out, outpoint.String())
	}
	return out
}
