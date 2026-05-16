// mock-arkd is a stub implementation of the arkd gRPC service, sufficient
// for introspector's startup GetInfo() call to succeed. Only GetInfo is
// implemented; every other RPC returns Unimplemented via the embedded
// UnimplementedArkServiceServer.
package main

import (
	"context"
	"log"
	"net"
	"os"

	arkv1 "github.com/arkade-os/go-sdk/api-spec/protobuf/gen/ark/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Hex-encoded compressed secp256k1 public key the mock returns.
// Real value derived from a known fixture private key; the only requirement
// from introspector's side (internal/application/service.go:62-89) is that
// it decodes as a valid compressed pubkey.
const fixtureSignerPubkey = "02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737"

type mockArk struct {
	arkv1.UnimplementedArkServiceServer
}

func (mockArk) GetInfo(_ context.Context, _ *arkv1.GetInfoRequest) (*arkv1.GetInfoResponse, error) {
	return &arkv1.GetInfoResponse{
		SignerPubkey: fixtureSignerPubkey,
		Network:      "regtest",
	}, nil
}

func main() {
	addr := os.Getenv("MOCK_ARKD_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	srv := grpc.NewServer()
	arkv1.RegisterArkServiceServer(srv, mockArk{})
	reflection.Register(srv)
	log.Printf("mock-arkd listening on %s, signer_pubkey=%s", addr, fixtureSignerPubkey)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
