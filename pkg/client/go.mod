module github.com/arkade-os/emulator/pkg/client

go 1.27.3

replace github.com/arkade-os/emulator/api-spec => ../../api-spec

require (
	github.com/arkade-os/arkd/pkg/ark-lib v0.8.1-0.20261105114752-97386cb3d95c
	github.com/arkade-os/emulator/api-spec v0.1.0
	google.golang.org/grpc v1.83.2
)

require (
	github.com/arkade-os/arkd/pkg/errors v0.0.0-20261105114752-97386cb3d95c // indirect
	github.com/btcsuite/btcd v0.26.2 // indirect
	github.com/btcsuite/btcd/address/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.5.0 // indirect
	github.com/btcsuite/btcd/btcutil/v2 v2.0.1 // indirect
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/psbt/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/txscript/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/wire/v2 v2.0.1 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	github.com/meshapi/grpc-api-gateway v0.1.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
