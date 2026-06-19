module github.com/arkade-os/emulator/pkg/emulator

go 1.26.4

require (
	github.com/arkade-os/arkd/pkg/ark-lib v0.8.1-0.20260423153230-9b5d8e96256f
	github.com/arkade-os/emulator/pkg/arkade v0.0.0-00010101000000-000000000000
	github.com/arkade-os/go-sdk v0.8.2-0.20260217102020-4153ef9cde49
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
)

require (
	cel.dev/expr v0.25.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/arkade-os/arkd/pkg/errors v0.0.0-20260303153651-8615412e4dea // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/consensys/gnark-crypto v0.19.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/google/cel-go v0.26.1 // indirect
	github.com/meshapi/grpc-api-gateway v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20250106191152-7588d65b2ba8 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/arkade-os/emulator/pkg/arkade => ../arkade

replace github.com/btcsuite/btcd/btcec/v2 => github.com/btcsuite/btcd/btcec/v2 v2.3.3

replace github.com/arkade-os/go-sdk => github.com/arkade-os/go-sdk v0.8.2-0.20260303154656-f29d9e77d5c7

replace github.com/arkade-os/arkd/pkg/errors => github.com/arkade-os/arkd/pkg/errors v0.0.0-20260303153651-8615412e4dea
