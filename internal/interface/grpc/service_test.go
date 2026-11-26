package grpcservice

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/internal/interface/grpc/interceptors"
	"github.com/meshapi/grpc-api-gateway/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// stubEmulatorServer records the Arkade transaction it was handed so tests can tell whether
// a request reached the handler or was rejected before it.
type stubEmulatorServer struct {
	emulatorv1.UnimplementedEmulatorServiceServer
	gotArkadeTxLen int
}

func (s *stubEmulatorServer) SubmitOffchainTx(
	_ context.Context, req *emulatorv1.SubmitOffchainTxRequest,
) (*emulatorv1.SubmitOffchainTxResponse, error) {
	s.gotArkadeTxLen = len(req.GetArkadeTx())
	return &emulatorv1.SubmitOffchainTxResponse{SignedArkadeTx: "ok"}, nil
}

// lazyHandler lets the router be built before the gateway that it fronts.
type lazyHandler struct{ h http.Handler }

func (l *lazyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.h.ServeHTTP(w, r)
}

type testServer struct {
	url    string
	client emulatorv1.EmulatorServiceClient
	stub   *stubEmulatorServer
}

// newTestServer stands up the production server wiring - the same server
// options, interceptors and router used by newServer - in front of a stub
// handler.
func newTestServer(t *testing.T) *testServer {
	t.Helper()

	stub := &stubEmulatorServer{}
	grpcConfig := append(
		serverOptions(),
		// No macaroon service configured, matching the current deployment.
		interceptors.UnaryInterceptor(nil),
		interceptors.StreamInterceptor(nil),
	)
	grpcServer := grpc.NewServer(grpcConfig...)
	emulatorv1.RegisterEmulatorServiceServer(grpcServer, stub)

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	lazy := &lazyHandler{h: http.NotFoundHandler()}
	httpSrv := httptest.NewUnstartedServer(router(grpcServer, lazy))
	httpSrv.Config.Protocols = protocols
	httpSrv.Start()
	t.Cleanup(httpSrv.Close)
	t.Cleanup(grpcServer.Stop)

	addr := strings.TrimPrefix(httpSrv.URL, "http://")
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Let the client send freely so the server is the only bound.
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
	)
	if err != nil {
		t.Fatalf("failed to create client: %s", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	gwmux := gateway.NewServeMux()
	emulatorv1.RegisterEmulatorServiceHandler(context.Background(), gwmux, conn)
	lazy.h = gwmux

	return &testServer{
		url:    httpSrv.URL,
		client: emulatorv1.NewEmulatorServiceClient(conn),
		stub:   stub,
	}
}

// TestServerRejectsOversizedMessage proves the signing endpoints refuse to
// buffer an arbitrarily large gRPC message. The handlers parse every PSBT they
// are handed before validating anything, so an unbounded message would be an
// unbounded allocation in the signer.
func TestServerRejectsOversizedMessage(t *testing.T) {
	srv := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	oversized := strings.Repeat("a", maxReceiveMessageSize+(1<<20))
	_, err := srv.client.SubmitOffchainTx(ctx, &emulatorv1.SubmitOffchainTxRequest{
		ArkadeTx:      oversized,
		CheckpointTxs: []string{"cp"},
	})
	if err == nil {
		t.Fatalf(
			"expected oversized request to be rejected, but it reached the handler with %d bytes",
			srv.stub.gotArkadeTxLen,
		)
	}
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted, got %s: %s", got, err)
	}
	if srv.stub.gotArkadeTxLen != 0 {
		t.Fatalf("oversized request reached the handler with %d bytes", srv.stub.gotArkadeTxLen)
	}
}

// TestServerAcceptsLegitimateMessage guards the bound against being set so low
// that a realistic batch of checkpoint txs is refused. A signer that rejects
// legitimate finalizations is its own availability problem.
func TestServerAcceptsLegitimateMessage(t *testing.T) {
	srv := newTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ~2MB of checkpoint txs, comfortably within a legitimate batch.
	checkpoints := make([]string, 0, 32)
	for i := range 32 {
		checkpoints = append(checkpoints, fmt.Sprintf("%d%s", i, strings.Repeat("b", 64*1024)))
	}

	if _, err := srv.client.SubmitOffchainTx(ctx, &emulatorv1.SubmitOffchainTxRequest{
		ArkadeTx:      "arktx",
		CheckpointTxs: checkpoints,
	}); err != nil {
		t.Fatalf("legitimate sized request was rejected: %s", err)
	}
}

// TestJSONGatewayBoundsOversizedBody is the load-bearing memory test. The JSON
// gateway decodes the whole request body before the message ever reaches the
// gRPC receive limit, so without a body cap a single request drives allocation
// proportional to whatever the caller sends. Measured before the cap was added:
// a 256MB body produced ~1.75GB of server-side allocation.
func TestJSONGatewayBoundsOversizedBody(t *testing.T) {
	srv := newTestServer(t)

	const bodySize = 256 * 1024 * 1024
	body := fmt.Sprintf(
		`{"arkade_tx":%q,"checkpoint_txs":["cp"]}`, strings.Repeat("a", bodySize),
	)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	resp, err := http.Post(
		srv.url+"/v1/offchain-tx", "application/json", strings.NewReader(body),
	)
	if err != nil {
		// Refusing the connection outright is an acceptable rejection.
		return
	}
	defer func() { _ = resp.Body.Close() }()

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("oversized JSON body was accepted with status %s", resp.Status)
	}
	if srv.stub.gotArkadeTxLen != 0 {
		t.Fatalf("oversized JSON body reached the handler with %d bytes", srv.stub.gotArkadeTxLen)
	}

	// The cap should keep allocation far below the body the caller offered.
	if allocated > bodySize/4 {
		t.Fatalf(
			"oversized JSON body drove %dMB of allocation for a %dMB body; body cap not effective",
			allocated/(1024*1024), bodySize/(1024*1024),
		)
	}
}

// TestJSONGatewayAcceptsLegitimateBody guards the body cap against rejecting a
// payload the gRPC path would accept.
func TestJSONGatewayAcceptsLegitimateBody(t *testing.T) {
	srv := newTestServer(t)

	// ~1MB Arkade transaction, well within a legitimate payload.
	body := fmt.Sprintf(
		`{"arkade_tx":%q,"checkpoint_txs":["cp"]}`, strings.Repeat("a", 1024*1024),
	)

	resp, err := http.Post(
		srv.url+"/v1/offchain-tx", "application/json", strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("legitimate JSON request failed: %s", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legitimate JSON request was rejected with status %s", resp.Status)
	}
}
