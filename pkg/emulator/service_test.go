package emulator

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	arkintent "github.com/arkade-os/arkd/pkg/ark-lib/intent"
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
	Proofs          []string         `json:"intents,omitempty"`
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

	t.Run("valid", func(t *testing.T) {
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
	})

	t.Run("invalid", func(t *testing.T) {
		for _, c := range fix.Invalid {
			t.Run(c.Name, func(t *testing.T) {
				tx := offchainTx(t, c)
				requests, err := testService.EmulateOffchainTx(t.Context(), tx, offchainData(t, c))
				require.ErrorContains(t, err, c.ErrorContains)
				require.Nil(t, requests)
				var emulationErr *Error
				require.ErrorAs(t, err, &emulationErr)
				require.Equal(t, "emulate offchain tx", emulationErr.Operation)
				require.Equal(t, "ark", emulationErr.TransactionKind)
				if tx.ArkTx != nil {
					require.ErrorContains(t, err, "ark_txid="+tx.ArkTx.UnsignedTx.TxID())
					require.Equal(t, tx.ArkTx.UnsignedTx.TxID(), emulationErr.TxID)
				}
			})
		}
	})
}

func TestEmulateBatchRegistration(t *testing.T) {
	fix := loadFixtures(t, "intent.json")

	t.Run("valid", func(t *testing.T) {
		for _, c := range fix.Valid {
			t.Run(c.Name, func(t *testing.T) {
				registration := proofFixture(t, c.Proof, c.Message)
				requests, err := testService.EmulateBatchRegistration(t.Context(), registration, offchainData(t, c))
				require.NoError(t, err)
				assertRequests(t, c.Requests, requests)

				outpoints, err := registration.ExpiryOutpoints()
				require.NoError(t, err)
				require.Equal(t, c.ExpiryOutpoints, outpointStrings(outpoints))
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, c := range fix.Invalid {
			t.Run(c.Name, func(t *testing.T) {
				registration := proofFixture(t, c.Proof, c.Message)
				requests, err := testService.EmulateBatchRegistration(t.Context(), registration, offchainData(t, c))
				require.ErrorContains(t, err, c.ErrorContains)
				require.Nil(t, requests)
				var emulationErr *Error
				require.ErrorAs(t, err, &emulationErr)
				require.Equal(t, "emulate batch registration", emulationErr.Operation)
				require.Equal(t, "proof", emulationErr.TransactionKind)
				require.Equal(t, registration.Proof.Packet.UnsignedTx.TxID(), emulationErr.TxID)
				require.ErrorContains(t, err, "proof_txid="+registration.Proof.Packet.UnsignedTx.TxID())
			})
		}
	})
}

func TestEmulateOnchainTx(t *testing.T) {
	fix := loadFixtures(t, "onchain_tx.json")

	t.Run("valid", func(t *testing.T) {
		for _, c := range fix.Valid {
			t.Run(c.Name, func(t *testing.T) {
				requests, err := testService.EmulateOnchainTx(t.Context(), OnchainTx{Tx: decodePSBT(t, c.Tx)})
				require.NoError(t, err)
				assertRequests(t, c.Requests, requests)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, c := range fix.Invalid {
			t.Run(c.Name, func(t *testing.T) {
				tx := decodePSBT(t, c.Tx)
				requests, err := testService.EmulateOnchainTx(t.Context(), OnchainTx{Tx: tx})
				require.ErrorContains(t, err, c.ErrorContains)
				require.Nil(t, requests)
				var emulationErr *Error
				require.ErrorAs(t, err, &emulationErr)
				require.Equal(t, "emulate onchain tx", emulationErr.Operation)
				require.Equal(t, "onchain", emulationErr.TransactionKind)
				require.Equal(t, tx.UnsignedTx.TxID(), emulationErr.TxID)
				require.ErrorContains(t, err, "txid="+tx.UnsignedTx.TxID())
			})
		}
	})
}

func TestEmulateBatchFinalization(t *testing.T) {
	fix := loadFixtures(t, "batch_finalization.json")

	t.Run("valid", func(t *testing.T) {
		for _, c := range fix.Valid {
			t.Run(c.Name, func(t *testing.T) {
				requests, err := testService.EmulateBatchFinalization(t.Context(), batchFinalization(t, c))
				require.NoError(t, err)
				assertRequests(t, c.Requests, requests)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, c := range fix.Invalid {
			t.Run(c.Name, func(t *testing.T) {
				requests, err := testService.EmulateBatchFinalization(t.Context(), batchFinalization(t, c))
				require.ErrorContains(t, err, c.ErrorContains)
				require.Nil(t, requests)
				var emulationErr *Error
				require.ErrorAs(t, err, &emulationErr)
				require.Equal(t, "emulate batch finalization", emulationErr.Operation)
				require.Contains(t, []string{"proof", "forfeit", "commitment"}, emulationErr.TransactionKind)
				require.NotEmpty(t, emulationErr.TxID)
			})
		}
	})
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

func proofFixture(t *testing.T, proof, message string) Proof {
	return Proof{Proof: arkintent.Proof{Packet: *decodePSBT(t, proof)}, Message: message}
}

func batchFinalization(t *testing.T, c fixtureCase) BatchFinalization {
	finalization := BatchFinalization{Forfeits: decodePSBTs(t, c.Forfeits)}
	if c.CommitmentTx != "" {
		finalization.CommitmentTx = decodePSBT(t, c.CommitmentTx)
	}
	for _, proof := range c.Proofs {
		finalization.Proofs = append(finalization.Proofs, proofFixture(t, proof, ""))
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
