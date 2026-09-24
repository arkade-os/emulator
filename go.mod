module github.com/arkade-os/emulator

go 1.26.6

replace github.com/arkade-os/emulator/pkg/arkade => ./pkg/arkade

replace github.com/arkade-os/emulator/pkg/client => ./pkg/client

replace github.com/arkade-os/emulator/pkg/emulator => ./pkg/emulator

replace github.com/arkade-os/emulator/api-spec => ./api-spec

require (
	github.com/arkade-os/arkd/pkg/ark-lib v0.8.1-0.20260901090427-f863e4847193
	github.com/arkade-os/arkd/pkg/client-lib v0.0.0-20260901090427-f863e4847193
	github.com/arkade-os/arkd/pkg/client-wallet v0.0.0-20260901090427-f863e4847193
	github.com/arkade-os/arkd/pkg/errors v0.0.0-20260901090427-f863e4847193
	github.com/arkade-os/arkd/pkg/macaroons v0.7.1-0.20260901090427-f863e4847193
	github.com/arkade-os/emulator/api-spec v0.0.0-20260923130525-1c9e71118ed3
	github.com/arkade-os/emulator/pkg/arkade v0.0.0-20260923130525-1c9e71118ed3
	github.com/arkade-os/emulator/pkg/client v0.0.0-00010101000000-000000000000
	github.com/arkade-os/emulator/pkg/emulator v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd v0.26.2
	github.com/btcsuite/btcd/address/v2 v2.0.0
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/btcsuite/btcd/btcutil/v2 v2.0.1
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0
	github.com/btcsuite/btcd/psbt/v2 v2.0.0
	github.com/btcsuite/btcd/txscript/v2 v2.0.0
	github.com/btcsuite/btcd/wire/v2 v2.0.1
	github.com/btcsuite/btcwallet v0.18.0
	github.com/consensys/gnark-crypto v0.19.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/meshapi/grpc-api-gateway v0.1.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.63.0
	go.opentelemetry.io/otel v1.44.0
	google.golang.org/grpc v1.83.2
	gopkg.in/macaroon-bakery.v2 v2.3.0
)

require (
	cel.dev/expr v0.25.2 // indirect
	github.com/aead/siphash v1.0.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/arkade-os/arkd/api-spec v0.0.0-20260901090427-f863e4847193 // indirect
	github.com/arkade-os/arkd/pkg/kvdb v0.7.1-0.20260901090427-f863e4847193 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/btcsuite/btcd/v2transport v1.1.0 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/btcsuite/btclog/v2 v2.0.1-0.20250728225537-6090e87c6c5b // indirect
	github.com/btcsuite/btcwallet/wallet/txauthor v1.4.0 // indirect
	github.com/btcsuite/btcwallet/wallet/txrules v1.3.0 // indirect
	github.com/btcsuite/btcwallet/wallet/txsizes v1.3.0 // indirect
	github.com/btcsuite/btcwallet/walletdb v1.6.0 // indirect
	github.com/btcsuite/btcwallet/wtxmgr v1.6.0 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/decred/dcrd/lru v1.1.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-macaroon-bakery/macaroonpb v1.0.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang-migrate/migrate/v4 v4.18.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/cel-go v0.26.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.16.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/lightninglabs/gozmq v0.0.0-20191113021534-d20a764486bf // indirect
	github.com/lightninglabs/neutrino v0.18.0 // indirect
	github.com/lightninglabs/neutrino/cache v1.1.4 // indirect
	github.com/lightningnetwork/lnd v0.21.0-beta.rc2.0.20260828055859-d24719e0a3d3 // indirect
	github.com/lightningnetwork/lnd/clock v1.1.1 // indirect
	github.com/lightningnetwork/lnd/fn/v2 v2.0.9 // indirect
	github.com/lightningnetwork/lnd/healthcheck v1.2.6 // indirect
	github.com/lightningnetwork/lnd/queue v1.2.0 // indirect
	github.com/lightningnetwork/lnd/ticker v1.1.1 // indirect
	github.com/lightningnetwork/lnd/tlv v1.4.0 // indirect
	github.com/lightningnetwork/lnd/tor v1.2.0 // indirect
	github.com/ltcsuite/ltcd v0.23.5 // indirect
	github.com/miekg/dns v1.1.62 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/rogpeppe/fastuuid v1.2.0 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/soheilhy/cmux v0.1.5 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tidwall/gjson v1.19.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20220101234140-673ab2c3ae75 // indirect
	github.com/xiang90/probing v0.0.0-20221125231312-a49e3df8f510 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	go.etcd.io/etcd/api/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.15 // indirect
	go.etcd.io/etcd/client/v2 v2.305.15 // indirect
	go.etcd.io/etcd/client/v3 v3.5.15 // indirect
	go.etcd.io/etcd/pkg/v3 v3.5.15 // indirect
	go.etcd.io/etcd/raft/v3 v3.5.15 // indirect
	go.etcd.io/etcd/server/v3 v3.5.15 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.43.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.41.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/sdk v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	go.opentelemetry.io/proto/otlp v1.10.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/exp v0.0.0-20250811191247-51f88131bc50 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	google.golang.org/genproto v0.0.0-20241118233622-e639e219e697 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/errgo.v1 v1.0.1 // indirect
	gopkg.in/macaroon.v2 v2.1.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/gc/v3 v3.0.0-20240801135723-a856999a2e4a // indirect
	modernc.org/libc v1.61.0 // indirect
	modernc.org/sqlite v1.33.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
