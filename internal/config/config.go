package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ArkLabsHQ/introspector/internal/application"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
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
)

var (
	defaultDatadir         = arklib.AppDataDir("introspector", false)
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
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("INTROSPECTOR")
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

	cfg := &Config{
		CurrentKey:      currentKey,
		DeprecatedKeys:  deprecatedKeys,
		Datadir:         viper.GetString(Datadir),
		Port:            viper.GetUint32(Port),
		NoTLS:           viper.GetBool(NoTLS),
		TLSExtraIPs:     viper.GetStringSlice(TLSExtraIPs),
		TLSExtraDomains: viper.GetStringSlice(TLSExtraDomains),
		ArkdURL:         viper.GetString(ArkdURL),
	}
	if cfg.ArkdURL == "" {
		return nil, fmt.Errorf("missing arkd url")
	}
	return cfg, nil
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

func (c *Config) AppService(ctx context.Context) (application.Service, error) {
	return application.New(ctx, c.CurrentKey, c.DeprecatedKeys, c.ArkdURL)
}
