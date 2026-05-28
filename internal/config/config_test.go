package config

import (
	"encoding/hex"
	"maps"
	"math/big"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	defaultEnv := map[string]string{
		"EMULATOR_SECRET_KEY": testKeyHex(1),
		"EMULATOR_ARKD_URL":   "http://arkd:7070",
	}
	envWith := func(overrides map[string]string) map[string]string {
		env := make(map[string]string, len(defaultEnv)+len(overrides))
		maps.Copy(env, defaultEnv)
		maps.Copy(env, overrides)
		return env
	}

	type validTest struct {
		name               string
		env                map[string]string
		deprecatedKeyHexes []string
	}

	validTests := []validTest{
		{
			name: "loads required env vars",
			env:  envWith(nil),
		},
		{
			name: "allows empty deprecated keys",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": "",
			}),
		},
		{
			name: "parses single deprecated key",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": testKeyHex(2),
			}),
			deprecatedKeyHexes: []string{testKeyHex(2)},
		},
		{
			name: "parses deprecated keys in order",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": testKeyHex(2) + "," + testKeyHex(3),
			}),
			deprecatedKeyHexes: []string{testKeyHex(2), testKeyHex(3)},
		},
	}

	t.Run("valid", func(t *testing.T) {
		for _, tt := range validTests {
			t.Run(tt.name, func(t *testing.T) {
				cfg, err := loadConfigForTest(t, tt.env)

				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.NotNil(t, cfg.CurrentKey)
				require.Equal(t, tt.env["EMULATOR_SECRET_KEY"], hex.EncodeToString(cfg.CurrentKey.Serialize()))
				require.Equal(t, tt.env["EMULATOR_ARKD_URL"], cfg.ArkdURL)
				require.Len(t, cfg.DeprecatedKeys, len(tt.deprecatedKeyHexes))
				for i, expected := range tt.deprecatedKeyHexes {
					require.Equal(t, expected, hex.EncodeToString(cfg.DeprecatedKeys[i].Serialize()))
				}
			})
		}
	})

	type invalidTest struct {
		name    string
		env     map[string]string
		wantErr string
	}

	curveOrder := new(big.Int).Set(btcec.S256().Params().N)
	aboveCurveOrder := new(big.Int).Add(curveOrder, big.NewInt(1))

	invalidTests := []invalidTest{
		{
			name: "missing arkd url",
			env: map[string]string{
				"EMULATOR_SECRET_KEY": testKeyHex(1),
			},
			wantErr: "missing arkd url",
		},
		{
			name: "invalid current key hex",
			env: envWith(map[string]string{
				"EMULATOR_SECRET_KEY": "not-hex",
			}),
			wantErr: "invalid secret key",
		},
		{
			name: "invalid deprecated key hex",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": "not-hex",
			}),
			wantErr: "invalid deprecated key",
		},
		{
			name: "current key with wrong length",
			env: envWith(map[string]string{
				"EMULATOR_SECRET_KEY": hex.EncodeToString(make([]byte, 31)),
			}),
			wantErr: "invalid secret key length",
		},
		{
			name: "deprecated key with wrong length",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": hex.EncodeToString(make([]byte, 31)),
			}),
			wantErr: "invalid deprecated key length",
		},
		{
			name: "current key scalar zero",
			env: envWith(map[string]string{
				"EMULATOR_SECRET_KEY": hex.EncodeToString(make([]byte, 32)),
			}),
			wantErr: "invalid secret key",
		},
		{
			name: "deprecated key scalar zero",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": hex.EncodeToString(make([]byte, 32)),
			}),
			wantErr: "invalid deprecated key",
		},
		{
			name: "current key scalar curve order",
			env: envWith(map[string]string{
				"EMULATOR_SECRET_KEY": scalarHex(curveOrder),
			}),
			wantErr: "invalid secret key",
		},
		{
			name: "deprecated key scalar curve order",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": scalarHex(curveOrder),
			}),
			wantErr: "invalid deprecated key",
		},
		{
			name: "current key scalar above curve order",
			env: envWith(map[string]string{
				"EMULATOR_SECRET_KEY": scalarHex(aboveCurveOrder),
			}),
			wantErr: "invalid secret key",
		},
		{
			name: "deprecated key scalar above curve order",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": scalarHex(aboveCurveOrder),
			}),
			wantErr: "invalid deprecated key",
		},
		{
			name: "current key in deprecated keys",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": testKeyHex(1),
			}),
			wantErr: "duplicate deprecated key",
		},
		{
			name: "duplicate deprecated keys",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": testKeyHex(2) + "," + testKeyHex(2),
			}),
			wantErr: "duplicate deprecated key",
		},
		{
			name: "leading comma in deprecated keys",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": "," + testKeyHex(2),
			}),
			wantErr: "invalid deprecated key length",
		},
		{
			name: "trailing comma in deprecated keys",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": testKeyHex(2) + ",",
			}),
			wantErr: "invalid deprecated key length",
		},
		{
			name: "double comma in deprecated keys",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": testKeyHex(2) + ",," + testKeyHex(3),
			}),
			wantErr: "invalid deprecated key length",
		},
		{
			name: "whitespace in deprecated keys",
			env: envWith(map[string]string{
				"EMULATOR_DEPRECATED_KEYS": testKeyHex(2) + ", " + testKeyHex(3),
			}),
			wantErr: "invalid deprecated key",
		},
	}

	t.Run("invalid", func(t *testing.T) {
		for _, tt := range invalidTests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := loadConfigForTest(t, tt.env)

				require.ErrorContains(t, err, tt.wantErr)
			})
		}
	})
}

func loadConfigForTest(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	for key, value := range env {
		t.Setenv(key, value)
	}
	return LoadConfig()
}

func testKeyHex(fill byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return hex.EncodeToString(key)
}

func scalarHex(n *big.Int) string {
	key := make([]byte, 32)
	bytes := n.Bytes()
	copy(key[32-len(bytes):], bytes)
	return hex.EncodeToString(key)
}

const testSecretKey = "0000000000000000000000000000000000000000000000000000000000000001"

func TestLoadConfigUsesEmulatorEnvPrefix(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	t.Setenv("EMULATOR_SECRET_KEY", testSecretKey)
	t.Setenv("EMULATOR_ARKD_URL", "http://127.0.0.1:7070")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:7070", cfg.ArkdURL)
	require.NotNil(t, cfg.CurrentKey)
}

func TestLoadConfigIgnoresOldEnvPrefix(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	t.Setenv("INTRO"+"SPECTOR_SECRET_KEY", testSecretKey)
	t.Setenv("EMULATOR_SECRET_KEY", "not-hex")
	t.Setenv("EMULATOR_ARKD_URL", "http://127.0.0.1:7070")

	_, err := LoadConfig()
	require.Error(t, err)
}

func TestParseComputeLimitsEmptyReturnsDefaults(t *testing.T) {
	got, err := parseComputeLimits("")
	require.NoError(t, err)
	require.Equal(t, arkade.DefaultComputeLimits(), got)
}

func TestParseComputeLimitsOverridesSingleOpcode(t *testing.T) {
	got, err := parseComputeLimits("OP_ECPAIRING=8")
	require.NoError(t, err)

	require.Equal(t, 8, got[arkade.OP_ECPAIRING])
	// Unspecified opcodes keep their defaults.
	require.Equal(t, arkade.DefaultComputeLimits()[arkade.OP_MODEXP],
		got[arkade.OP_MODEXP])
}

func TestParseComputeLimitsOverridesMultipleOpcodesWithSpaces(t *testing.T) {
	got, err := parseComputeLimits(" OP_ECPAIRING=8 , OP_MODEXP=128 ")
	require.NoError(t, err)

	require.Equal(t, 8, got[arkade.OP_ECPAIRING])
	require.Equal(t, 128, got[arkade.OP_MODEXP])
}

func TestParseComputeLimitsUnknownOpcodeErrors(t *testing.T) {
	_, err := parseComputeLimits("OP_NOT_A_REAL_OPCODE=5")
	require.ErrorContains(t, err, "OP_NOT_A_REAL_OPCODE")
}

func TestParseComputeLimitsNonIntegerErrors(t *testing.T) {
	_, err := parseComputeLimits("OP_ECPAIRING=lots")
	require.Error(t, err)
}

func TestParseComputeLimitsMalformedPairErrors(t *testing.T) {
	_, err := parseComputeLimits("OP_ECPAIRING")
	require.Error(t, err)
}

func TestParseComputeLimitsNegativeErrors(t *testing.T) {
	_, err := parseComputeLimits("OP_ECPAIRING=-1")
	require.Error(t, err)
}

func TestLoadConfigParsesComputeLimitsOverride(t *testing.T) {
	cfg, err := loadConfigForTest(t, map[string]string{
		"EMULATOR_SECRET_KEY":     testKeyHex(1),
		"EMULATOR_ARKD_URL":       "http://arkd:7070",
		"EMULATOR_COMPUTE_LIMITS": "OP_ECPAIRING=8",
	})
	require.NoError(t, err)
	require.Equal(t, 8, cfg.ComputeLimits[arkade.OP_ECPAIRING])
}

func TestLoadConfigDefaultsComputeLimitsWhenUnset(t *testing.T) {
	cfg, err := loadConfigForTest(t, map[string]string{
		"EMULATOR_SECRET_KEY": testKeyHex(1),
		"EMULATOR_ARKD_URL":   "http://arkd:7070",
	})
	require.NoError(t, err)
	require.Equal(t, arkade.DefaultComputeLimits(), cfg.ComputeLimits)
}
