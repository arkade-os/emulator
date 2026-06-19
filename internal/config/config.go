package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	SecretKey       = "SECRET_KEY"
	DeprecatedKeys  = "DEPRECATED_KEYS"
	Datadir         = "DATADIR"
	Port            = "PORT"
	NoTLS           = "NO_TLS"
	TLSExtraIPs     = "TLS_EXTRA_IPS"
	TLSExtraDomains = "TLS_EXTRA_DOMAINS"
	LogLevel        = "LOG_LEVEL"
	ArkdURL         = "ARKD_URL"
	ComputeLimits   = "COMPUTE_LIMITS"
)

var (
	defaultDatadir         = arklib.AppDataDir("emulator", false)
	defaultPort            = uint32(7073)
	defaultNoTLS           = false
	defaultTLSExtraIPs     = []string{}
	defaultTLSExtraDomains = []string{}
	defaultLogLevel        = log.DebugLevel
)

type Config struct {
	CurrentKey      *btcec.PrivateKey
	DeprecatedKeys  []*btcec.PrivateKey
	Datadir         string
	Port            uint32
	NoTLS           bool
	TLSExtraIPs     []string
	TLSExtraDomains []string
	ArkdURL         string
	ComputeLimits   arkade.ComputeLimits
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("EMULATOR")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(NoTLS, defaultNoTLS)
	viper.SetDefault(TLSExtraIPs, defaultTLSExtraIPs)
	viper.SetDefault(TLSExtraDomains, defaultTLSExtraDomains)
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
		CurrentKey:      currentKey,
		DeprecatedKeys:  deprecatedKeys,
		Datadir:         viper.GetString(Datadir),
		Port:            viper.GetUint32(Port),
		NoTLS:           viper.GetBool(NoTLS),
		TLSExtraIPs:     viper.GetStringSlice(TLSExtraIPs),
		TLSExtraDomains: viper.GetStringSlice(TLSExtraDomains),
		ArkdURL:         viper.GetString(ArkdURL),
		ComputeLimits:   computeLimits,
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

func (c *Config) AppService(ctx context.Context) (emulator.Service, error) {
	arkdClient, err := grpcclient.NewClient(c.ArkdURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create arkd client: %w", err)
	}
	info, err := arkdClient.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch arkd info: %w", err)
	}
	pk, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return nil, err
	}
	arkdPubKey, err := btcec.ParsePubKey(pk)
	if err != nil {
		return nil, err
	}
	return emulator.New(ctx, c.CurrentKey, c.DeprecatedKeys, arkdPubKey, arkdClient, c.ComputeLimits)
}
