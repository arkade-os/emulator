// Command genvectors exports deterministic script fixtures for the TypeScript
// port. -update rewrites them; without it the committed file is asserted.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/emulator/test/covenant"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

const fixturePath = "testdata/taxi_carrier_vectors.json"

var update = flag.Bool("update", false, "rewrite the committed fixtures")

// referenceRevision pins the commit the committed fixtures describe, so a reader
// can tell which reference the bytes came from. Bump it deliberately with -update
// when the covenant semantics change; deriving it from the environment instead
// would make the no-update assertion fail wherever that environment is absent.
const referenceRevision = "d4771c80982e77a55a6f8863155f45cec1dd12e5"

type jsonParams struct {
	ReceiverKey          string  `json:"receiverKey"`
	SenderKey            string  `json:"senderKey"`
	OperatorKey          string  `json:"operatorKey"`
	Dust                 int64   `json:"dust"`
	Topup                int64   `json:"topup"`
	AssetTxid            *string `json:"assetTxid"`
	AssetIndex           *uint16 `json:"assetIndex"`
	Locktime             uint32  `json:"locktime"`
	ReclaimLocktime      uint32  `json:"reclaimLocktime,omitempty"`
	RecoveryRecipient    string  `json:"recoveryRecipient,omitempty"`
	ClaimMode            string  `json:"claimMode,omitempty"`
	ReceiverFareCurrency string  `json:"receiverFareCurrency,omitempty"`
	ReceiverFareUnits    int64   `json:"receiverFareUnits,omitempty"`
}

type vector struct {
	Name          string     `json:"name"`
	Params        jsonParams `json:"params"`
	VtxoMinAmount int64      `json:"vtxoMinAmount"`
	Recycle       string     `json:"recycle"`
	Purchase      string     `json:"purchase"`
	Refund        string     `json:"refund"`
	Reclaim       string     `json:"reclaim,omitempty"`
	DisabledLeaf  string     `json:"disabledLeaf,omitempty"`
}

type document struct {
	Reference string   `json:"reference"`
	Cases     []vector `json:"cases"`
}

// Derived from a fixed scalar: raw fill bytes are not guaranteed on-curve.
func key(fill byte) *btcec.PublicKey {
	var b [32]byte
	for i := range b {
		b[i] = fill
	}
	priv, _ := btcec.PrivKeyFromBytes(b[:])
	return priv.PubKey()
}

func spec(name string, p covenant.Params, min int64) (vector, error) {
	scripts, err := covenant.Build(p, min)
	if err != nil {
		return vector{}, err
	}
	holder := covenant.VtxoScript(key(0x04), key(0x05), p.SenderKey, p, scripts)

	v := vector{
		Name:          name,
		VtxoMinAmount: min,
		Recycle:       hex.EncodeToString(scripts.Recycle),
		Purchase:      hex.EncodeToString(scripts.Purchase),
		Refund:        hex.EncodeToString(scripts.Refund),
		Reclaim:       hex.EncodeToString(scripts.Reclaim),
	}
	if p.ClaimMode != "" {
		leaf := covenant.LeafPurchase
		if p.ClaimMode == covenant.ClaimModePurchase {
			leaf = covenant.LeafRecycle
		}
		raw, err := holder.Closures[leaf].Script()
		if err != nil {
			return vector{}, err
		}
		v.DisabledLeaf = hex.EncodeToString(raw)
	}

	v.Params = jsonParams{
		ReceiverKey:       hex.EncodeToString(schnorr.SerializePubKey(p.ReceiverKey)),
		SenderKey:         hex.EncodeToString(schnorr.SerializePubKey(p.SenderKey)),
		OperatorKey:       hex.EncodeToString(schnorr.SerializePubKey(p.OperatorKey)),
		Dust:              p.Dust,
		Topup:             p.Topup,
		Locktime:          uint32(p.Locktime),
		ReclaimLocktime:   uint32(p.ReclaimLocktime),
		RecoveryRecipient: p.RecoveryRecipient,
		ClaimMode:         p.ClaimMode,
	}
	if p.ReceiverFare != nil {
		v.Params.ReceiverFareCurrency = p.ReceiverFare.Currency
		v.Params.ReceiverFareUnits = p.ReceiverFare.Units
	}
	if p.AssetID != nil {
		txid := hex.EncodeToString(p.AssetID.Txid[:])
		idx := p.AssetID.Index
		v.Params.AssetTxid, v.Params.AssetIndex = &txid, &idx
	}
	return v, nil
}

func build() (document, error) {
	receiver, sender, operator := key(0x01), key(0x02), key(0x03)
	base := func(withAsset bool) covenant.Params {
		p := covenant.Params{
			ReceiverKey: receiver,
			SenderKey:   sender,
			OperatorKey: operator,
			Dust:        330,
			Topup:       330,
			Locktime:    arklib.AbsoluteLocktime(800000),
		}
		if withAsset {
			var id asset.AssetId
			for i := range id.Txid {
				id.Txid[i] = 0x11
			}
			p.AssetID = &id
		}
		return p
	}

	receiverFull := base(true)
	receiverFull.RecoveryRecipient = covenant.RecoveryReceiver
	receiverFull.ReclaimLocktime = receiverFull.Locktime + 100_000

	// The pre-charged variant: a quote that reserves one sat of receipt hosting
	// so the refund returns the whole carrier.
	receiverExact := base(true)
	receiverExact.Topup = 329
	receiverExact.RecoveryRecipient = covenant.RecoveryReceiver

	recycleOnly := base(true)
	recycleOnly.ClaimMode = covenant.ClaimModeRecycle
	purchaseOnly := base(true)
	purchaseOnly.ClaimMode = covenant.ClaimModePurchase

	receiverPaid := func(fare *covenant.ReceiverFare) covenant.Params {
		p := base(true)
		p.ClaimMode = covenant.ClaimModeRecycle
		p.RecoveryRecipient = covenant.RecoveryReceiver
		p.ReclaimLocktime = p.Locktime + 100_000
		p.ReceiverFare = fare
		return p
	}

	cases := []struct {
		name   string
		params covenant.Params
		min    int64
	}{
		{"legacy-btc", base(false), 1},
		{"legacy-asset", base(true), 1},
		{"receiver-receipt-dust330", receiverFull, 1},
		{"receiver-receipt-topup329", receiverExact, 1},
		{"claim-mode-recycle", recycleOnly, 1},
		{"claim-mode-purchase", purchaseOnly, 1},
		{"receiver-paid-sats-fare", receiverPaid(&covenant.ReceiverFare{Currency: "sats", Units: 7}), 1},
		{"receiver-paid-asset-fare", receiverPaid(&covenant.ReceiverFare{Currency: "asset", Units: 9}), 1},
		{"receiver-paid-zero-fare", receiverPaid(&covenant.ReceiverFare{Currency: "sats", Units: 0}), 1},
	}

	doc := document{Reference: referenceRevision}
	for _, c := range cases {
		v, err := spec(c.name, c.params, c.min)
		if err != nil {
			return document{}, err
		}
		doc.Cases = append(doc.Cases, v)
	}
	return doc, nil
}

func encode(t *testing.T, doc document) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	return append(raw, '\n')
}

// TestLegacyStillMatchesPublishedVectors re-derives the legacy parameter sets at
// the old vtxoMinAmount and asserts the published TypeScript vectors still come
// out byte for byte. Those vectors are the existing funded-covenant contract, so
// this is what makes "empty params are unchanged" a check rather than a claim.
func TestLegacyStillMatchesPublishedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "published_legacy_vectors.json"))
	require.NoError(t, err)

	var published struct {
		Cases []struct {
			Name   string `json:"name"`
			Params struct {
				Dust  int64   `json:"dust"`
				Topup int64   `json:"topup"`
				Txid  *string `json:"assetTxid"`
				Lock  uint32  `json:"locktime"`
			} `json:"params"`
			VtxoMinAmount int64  `json:"vtxoMinAmount"`
			Recycle       string `json:"recycle"`
			Purchase      string `json:"purchase"`
			Refund        string `json:"refund"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &published))
	require.NotEmpty(t, published.Cases)

	receiver, sender, operator := key(0x01), key(0x02), key(0x03)
	checked := 0
	for _, c := range published.Cases {
		p := covenant.Params{
			ReceiverKey: receiver,
			SenderKey:   sender,
			OperatorKey: operator,
			Dust:        c.Params.Dust,
			Topup:       c.Params.Topup,
			Locktime:    arklib.AbsoluteLocktime(c.Params.Lock),
		}
		if c.Params.Txid != nil {
			decoded, err := hex.DecodeString(*c.Params.Txid)
			require.NoError(t, err)
			var id asset.AssetId
			copy(id.Txid[:], decoded)
			p.AssetID = &id
		}

		scripts, err := covenant.Build(p, c.VtxoMinAmount)
		require.NoError(t, err, c.Name)
		require.Equal(t, c.Recycle, hex.EncodeToString(scripts.Recycle), c.Name)
		require.Equal(t, c.Purchase, hex.EncodeToString(scripts.Purchase), c.Name)
		require.Equal(t, c.Refund, hex.EncodeToString(scripts.Refund), c.Name)
		checked++
	}
	t.Logf("re-verified %d published legacy vectors", checked)
}

func TestFixtures(t *testing.T) {
	doc, err := build()
	require.NoError(t, err)
	got := encode(t, doc)

	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(fixturePath), 0o755))
		require.NoError(t, os.WriteFile(fixturePath, got, 0o644))
		t.Logf("wrote %s", fixturePath)
		return
	}

	want, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "run with -update to create the fixtures")
	// core.autocrlf rewrites the checked-out fixture; only the bytes matter.
	normalize := func(b []byte) string {
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	require.Equal(t, normalize(want), normalize(got),
		"committed fixtures differ from the reference; regenerate with -update")
}
