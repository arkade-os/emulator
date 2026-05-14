module github.com/ArkLabsHQ/introspector/pkg/arkade

go 1.26.2

require (
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6
	github.com/arkade-os/arkd/pkg/ark-lib v0.8.1-0.20260318170839-137daaec3a70
	github.com/btcsuite/btcd v0.24.3-0.20240921052913-67b8efd3ba53
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/consensys/gnark-crypto v0.19.2
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.48.0
)

require (
	github.com/arkade-os/arkd/pkg/errors v0.0.0-20260303153651-8615412e4dea // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/sys v0.41.0 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/arkade-os/arkd/pkg/errors => github.com/arkade-os/arkd/pkg/errors v0.0.0-20260303153651-8615412e4dea
