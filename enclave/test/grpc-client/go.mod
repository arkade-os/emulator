module github.com/ArkLabsHQ/introspector/enclave/test/grpc-client

go 1.26.2

// Both source repos are mounted into the test-runner Docker build
// context; replace directives point at the local working trees so the
// grpc-client picks up the in-development client.GRPCConn and the
// introspector api-spec stubs.
replace github.com/ArkLabsHQ/introspector-enclave => /home/joshua/introspector-enclave

replace github.com/ArkLabsHQ/introspector/api-spec => /home/joshua/introspector/api-spec

replace github.com/ArkLabsHQ/introspector/pkg/arkade => /home/joshua/introspector/pkg/arkade

require (
	github.com/ArkLabsHQ/introspector-enclave v0.0.36
	github.com/ArkLabsHQ/introspector/api-spec v0.0.0-00010101000000-000000000000
	github.com/ArkLabsHQ/introspector/pkg/arkade v0.0.0-00010101000000-000000000000
	github.com/arkade-os/arkd/pkg/ark-lib v0.8.1-0.20260318170839-137daaec3a70
	github.com/btcsuite/btcd v0.25.0
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btcwallet v0.16.17
)

require (
	github.com/arkade-os/arkd/pkg/errors v0.0.0-20260303153651-8615412e4dea // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/btcwallet/walletdb v1.5.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/hf/nitrite v0.0.0-20211104000856-f9e0dcc73703 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/lightninglabs/neutrino/cache v1.1.2 // indirect
	github.com/lightningnetwork/lnd/fn v1.2.1 // indirect
	github.com/lightningnetwork/lnd/tlv v1.2.6 // indirect
	github.com/meshapi/grpc-api-gateway v0.1.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20250106191152-7588d65b2ba8 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
