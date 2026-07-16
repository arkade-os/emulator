package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/arkade-os/go-sdk/client"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	SecretKey      = "SECRET_KEY"
	DeprecatedKeys = "DEPRECATED_KEYS"
	Port           = "PORT"
	LogLevel       = "LOG_LEVEL"
	ArkdURL        = "ARKD_URL"
	ComputeLimits  = "COMPUTE_LIMITS"
)

var (
	defaultPort     = uint32(7073)
	defaultLogLevel = log.DebugLevel
)

type Config struct {
	CurrentKey     *btcec.PrivateKey
	DeprecatedKeys []*btcec.PrivateKey
	Port           uint32
	ArkdURL        string
	ComputeLimits  arkade.ComputeLimits
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

	cfg := &Config{
		CurrentKey:     currentKey,
		DeprecatedKeys: deprecatedKeys,
		Port:           viper.GetUint32(Port),
		ArkdURL:        viper.GetString(ArkdURL),
		ComputeLimits:  computeLimits,
	}
	if cfg.ArkdURL == "" {
		return nil, fmt.Errorf("missing arkd url")
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

var arkdConnectRetryConfig = emulator.RetryConfig{
	MinAttempts:  0,
	InitialDelay: 1 * time.Second,
	MaxDelay:     45 * time.Second,
	Multiplier:   2.0,
	Jitter:       0.2,
}

func (c *Config) AppService(ctx context.Context) (emulator.Service, error) {
	arkdClient, err := grpcclient.NewClient(c.ArkdURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create arkd client: %w", err)
	}
	// arkdClient holds an open gRPC connection; close it unless it is handed
	// off to a successfully constructed service (which then owns its lifecycle).
	handedOff := false
	defer func() {
		if !handedOff {
			arkdClient.Close()
		}
	}()

	var info *client.Info
	// arkd may still be booting when the emulator starts, retry if it fails.
	err = emulator.RetryWithBackoff(
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
	svc, err := emulator.New(ctx, c.CurrentKey, c.DeprecatedKeys, arkdPubKey, arkdClient, c.ComputeLimits)
	if err != nil {
		return nil, err
	}
	handedOff = true
	return svc, nil
}
