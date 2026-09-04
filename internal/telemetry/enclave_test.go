package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

type exportRequest struct {
	path        string
	authorize   string
	contentType string
	body        []byte
	err         error
}

func TestSetupExportsToEnclaveRuntimeOnShutdown(t *testing.T) {
	requests := make(chan exportRequest, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		requests <- exportRequest{
			path:        r.URL.Path,
			authorize:   r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			body:        body,
			err:         err,
		}
		w.WriteHeader(http.StatusOK)
	})

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	t.Setenv(runtimeProxyEnv, port)
	t.Setenv(runtimeTokenEnv, "test-runtime-token")

	oldTracerProvider := otel.GetTracerProvider()
	oldPropagator := otel.GetTextMapPropagator()
	oldLoggerProvider := global.GetLoggerProvider()
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	t.Cleanup(func() {
		otel.SetTracerProvider(oldTracerProvider)
		otel.SetTextMapPropagator(oldPropagator)
		global.SetLoggerProvider(oldLoggerProvider)
		log.StandardLogger().ReplaceHooks(oldHooks)
	})

	shutdown, err := Setup(context.Background(), "test-version")
	require.NoError(t, err)

	ctx, span := otel.Tracer("telemetry-test").Start(context.Background(), "startup")
	log.WithContext(ctx).Info("startup failed")
	span.End()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, shutdown(shutdownCtx))

	received := make(map[string]exportRequest, 2)
	for range 2 {
		select {
		case req := <-requests:
			received[req.path] = req
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for enclave telemetry export")
		}
	}

	traceReq, ok := received[traceEndpointPath]
	require.True(t, ok, "trace request was not exported")
	assertEnclaveRequest(t, traceReq)
	var traces coltracepb.ExportTraceServiceRequest
	require.NoError(t, proto.Unmarshal(traceReq.body, &traces))
	require.NotEmpty(t, traces.ResourceSpans)

	logReq, ok := received[logEndpointPath]
	require.True(t, ok, "log request was not exported")
	assertEnclaveRequest(t, logReq)
	var logs collogspb.ExportLogsServiceRequest
	require.NoError(t, proto.Unmarshal(logReq.body, &logs))
	require.NotEmpty(t, logs.ResourceLogs)
}

func assertEnclaveRequest(t *testing.T, req exportRequest) {
	t.Helper()
	require.Equal(t, "Bearer test-runtime-token", req.authorize)
	require.True(t, strings.HasPrefix(req.contentType, "application/x-protobuf"))
	require.NoError(t, req.err)
	require.NotEmpty(t, req.body)
}
