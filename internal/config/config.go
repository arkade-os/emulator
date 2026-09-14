package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc/metadata"
)

const (
	SecretKey                = "SECRET_KEY"
	DeprecatedKeys           = "DEPRECATED_KEYS"
	DeprecatedKeysValidUntil = "DEPRECATED_KEYS_VALID_UNTIL"
	Port                     = "PORT"
	LogLevel                 = "LOG_LEVEL"
	ArkdURL                  = "ARKD_URL"
	ArkdIndexerURL           = "ARKD_INDEXER_URL"
	ComputeLimits            = "COMPUTE_LIMITS"
)

var (
	defaultPort     = uint32(7073)
	defaultLogLevel = log.DebugLevel
)

type Config struct {
	CurrentKey               *btcec.PrivateKey
	DeprecatedKeys           []*btcec.PrivateKey
	DeprecatedKeysValidUntil *time.Time
	Port                     uint32
	ArkdURL                  string
	ArkdIndexerURL           string
	ComputeLimits            arkade.ComputeLimits
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("EMULATOR")
	viper.AutomaticEnv()

	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(LogLevel, defaultLogLevel)

	currentKey, err := parsePrivateKey(viper.GetString(SecretKey), "secret key")
	if err != nil {
		return nil, err
	}

	var deprecatedKeys []*btcec.PrivateKey
	seenKeys := map[string]struct{}{
		hex.EncodeToString(currentKey.Serialize()): {},
	}
	deprecatedKeyHex := viper.GetString(DeprecatedKeys)
	if deprecatedKeyHex != "" {
		for keyHex := range strings.SplitSeq(deprecatedKeyHex, ",") {
			deprecatedKey, err := parsePrivateKey(keyHex, "deprecated key")
			if err != nil {
				return nil, err
			}
			keyID := hex.EncodeToString(deprecatedKey.Serialize())
			if _, ok := seenKeys[keyID]; ok {
				return nil, fmt.Errorf("duplicate deprecated key")
			}
			seenKeys[keyID] = struct{}{}
			deprecatedKeys = append(deprecatedKeys, deprecatedKey)
		}
	}

	logLevel := viper.GetInt(LogLevel)
	log.SetLevel(log.Level(logLevel))

	computeLimits, err := parseComputeLimits(viper.GetString(ComputeLimits))
	if err != nil {
		return nil, err
	}

	var deprecatedKeysValidUntil *time.Time
	if raw := viper.GetString(DeprecatedKeysValidUntil); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, fmt.Errorf("invalid %s, want RFC3339 timestamp: %w", DeprecatedKeysValidUntil, err)
		}
		deprecatedKeysValidUntil = &t
	}

	cfg := &Config{
		CurrentKey:               currentKey,
		DeprecatedKeys:           deprecatedKeys,
		DeprecatedKeysValidUntil: deprecatedKeysValidUntil,
		Port:                     viper.GetUint32(Port),
		ArkdURL:                  viper.GetString(ArkdURL),
		ArkdIndexerURL:           viper.GetString(ArkdIndexerURL),
		ComputeLimits:            computeLimits,
	}
	if cfg.ArkdURL == "" {
		return nil, fmt.Errorf("missing arkd url")
	}
	// if unset, default to the same endpoint as arkd
	if cfg.ArkdIndexerURL == "" {
		cfg.ArkdIndexerURL = cfg.ArkdURL
	}
	return cfg, nil
}

// parseComputeLimits builds the per-input opcode compute brake from the
// EMULATOR_COMPUTE_LIMITS override, applied on top of the engine defaults. The
// override is a comma-separated list of OPCODE=limit pairs, e.g.
// "OP_ECPAIRING=8,OP_MODEXP=128"; an empty value yields the defaults unchanged.
// It errors on an unknown opcode name, a non-integer limit, or a negative
// limit.
func parseComputeLimits(raw string) (arkade.ComputeLimits, error) {
	limits := arkade.DefaultComputeLimits()
	if strings.TrimSpace(raw) == "" {
		return limits, nil
	}

	for pair := range strings.SplitSeq(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			return nil, fmt.Errorf(
				"invalid empty compute limit override in %q", raw)
		}
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf(
				"invalid compute limit override %q, want OPCODE=limit", pair)
		}
		name = strings.TrimSpace(name)
		op, ok := arkade.OpcodeByName[name]
		if !ok {
			return nil, fmt.Errorf("unknown opcode %q in compute limits", name)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			delete(limits, op)
			continue
		}
		limit, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("invalid limit for opcode %q: %w", name, err)
		}
		limits[op] = limit
	}

	if err := limits.Validate(); err != nil {
		return nil, err
	}
	return limits, nil
}

func parsePrivateKey(keyHex, name string) (*btcec.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid %s length", name)
	}
	var keyBytes32 [32]byte
	copy(keyBytes32[:], keyBytes)

	var scalar btcec.ModNScalar
	if scalar.SetBytes(&keyBytes32) != 0 || scalar.IsZero() {
		return nil, fmt.Errorf("invalid %s", name)
	}

	key, _ := btcec.PrivKeyFromBytes(keyBytes)
	if key == nil {
		return nil, fmt.Errorf("invalid %s", name)
	}
	return key, nil
}

// emulator.Service.Close closes its finalizer and indexer by type-asserting
// interface{ Close() }, so a client-lib change to Close() error would silently
// stop closing the arkd connections handed off below. Fail at compile time instead.
var _ interface{ Close() } = client.Client(nil)
var _ interface{ Close() } = indexer.Indexer(nil)

var arkdConnectRetryConfig = retryConfig{
	MinAttempts:  0,
	InitialDelay: 1 * time.Second,
	MaxDelay:     45 * time.Second,
	Multiplier:   2.0,
	Jitter:       0.2,
}

// versionedIndexer tags every indexer call with the emulator's x-sdk-version,
// the way client-lib's grpc client does for arkd calls via its interceptor.
type versionedIndexer struct {
	indexer.Indexer
	version string
}

func (v versionedIndexer) ctx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-sdk-version", v.version)
}

func (v versionedIndexer) GetVtxos(ctx context.Context, opts ...indexer.GetVtxosOption) (*indexer.VtxosResponse, error) {
	return v.Indexer.GetVtxos(v.ctx(ctx), opts...)
}

func (v versionedIndexer) GetCommitmentTx(ctx context.Context, txid string) (*indexer.CommitmentTx, error) {
	return v.Indexer.GetCommitmentTx(v.ctx(ctx), txid)
}

func (c *Config) AppService(ctx context.Context, version string) (emulator.Service, error) {
	clientVersion := "emulator/" + version

	arkdClient, err := grpcclient.NewClient(c.ArkdURL, clientVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to create arkd client: %w", err)
	}
	indexerClient, err := grpcindexer.NewClient(c.ArkdIndexerURL)
	if err != nil {
		arkdClient.Close()
		return nil, fmt.Errorf("failed to create arkd indexer client: %w", err)
	}
	// Both hold open gRPC connections; close them unless they are handed off to
	// a successfully constructed service (which then owns their lifecycle).
	handedOff := false
	defer func() {
		if !handedOff {
			arkdClient.Close()
			indexerClient.Close()
		}
	}()

	var info *client.Info
	// arkd may still be booting when the emulator starts, retry if it fails.
	err = retryWithBackoff(
		ctx, arkdConnectRetryConfig,
		func() error {
			var e error
			info, e = arkdClient.GetInfo(ctx)
			return e
		},
		func(attempt int, e error) {
			log.WithField("attempt", attempt).Warnf("arkd not ready: %s", e)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch arkd info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("arkd info is required")
	}
	if info.SignerPubKey == "" {
		return nil, fmt.Errorf("arkd info does not include signer pubkey")
	}
	pk, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid arkd signer pubkey: %w", err)
	}
	arkdPubKey, err := btcec.ParsePubKey(pk)
	if err != nil {
		return nil, fmt.Errorf("invalid arkd signer pubkey: %w", err)
	}
	svc, err := emulator.New(
		ctx, c.CurrentKey, c.DeprecatedKeys, c.DeprecatedKeysValidUntil, arkdPubKey,
		arkdClient, versionedIndexer{indexerClient, clientVersion}, c.ComputeLimits,
	)
	if err != nil {
		return nil, err
	}
	handedOff = true
	return svc, nil
}
