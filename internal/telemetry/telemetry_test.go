package telemetry

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	testToken       = "test-token"
	testVersion     = "test-version"
	testEnvironment = "test"

	// An incoming traceparent, naming the parent span.
	parentTraceID     = "4bf92f3577b34da6a3ce929d0e0e4736"
	parentSpanID      = "00f067aa0ba902b7"
	traceparent       = "00-" + parentTraceID + "-" + parentSpanID + "-01"
	traceparentHeader = "traceparent"
)

// checkSpan names the spans of a Health/Check call.
var checkSpan = strings.TrimPrefix(healthpb.Health_Check_FullMethodName, "/")

type exportRequest struct {
	path        string
	authorize   string
	contentType string
	body        []byte
	err         error
}

// unsetOtelEnv clears the variables loadOtelConfig reads.
func unsetOtelEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		otelTokenEnv, otelEndpointEnv, otelServiceNameEnv, otelEnvironmentEnv,
		defaultOtelTokenEnv, defaultOtelPortEnv,
	} {
		t.Setenv(key, "")
	}
}

// newCollector serves OTLP/HTTP and returns its address and what it receives.
// Requests to a stalled path are recorded but never answered.
func newCollector(t *testing.T, stalled ...string) (string, <-chan exportRequest) {
	t.Helper()

	requests := make(chan exportRequest, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		requests <- exportRequest{
			path:        r.URL.Path,
			authorize:   r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			body:        body,
			err:         err,
		}
		if slices.Contains(stalled, r.URL.Path) {
			<-r.Context().Done() // until the exporter gives up
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server.Listener.Addr().String(), requests
}

// unmarshalExport checks the export to path and decodes it into msg.
func unmarshalExport(
	t *testing.T, received map[string]exportRequest, path string, msg proto.Message,
) {
	t.Helper()

	req, ok := received[path]
	require.True(t, ok, "nothing exported to %s", path)
	require.NoError(t, req.err)
	require.Equal(t, "Bearer "+testToken, req.authorize)
	require.True(t, strings.HasPrefix(req.contentType, "application/x-protobuf"))
	require.NoError(t, proto.Unmarshal(req.body, msg))
}

func resourceAttributes(res *resourcepb.Resource) map[string]string {
	attrs := map[string]string{}
	for _, kv := range res.GetAttributes() {
		attrs[kv.GetKey()] = kv.GetValue().GetStringValue()
	}
	return attrs
}

func findLogRecord(
	t *testing.T, logs *collogspb.ExportLogsServiceRequest, body string,
) *logspb.LogRecord {
	t.Helper()
	for _, resourceLogs := range logs.GetResourceLogs() {
		for _, scopeLogs := range resourceLogs.GetScopeLogs() {
			for _, record := range scopeLogs.GetLogRecords() {
				if record.GetBody().GetStringValue() == body {
					return record
				}
			}
		}
	}
	require.Failf(t, "log record not exported", "%q", body)
	return nil
}

// recordSpans records global spans. Call it before newTracedServer.
func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()

	recorded := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorded))
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	// It stays installed, so stop later tests' spans reaching recorded.
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return recorded
}

// newTracedServer mimics the emulator's router: GETs go to a traced gateway,
// which calls gRPC over loopback; everything else goes straight to gRPC.
func newTracedServer(t *testing.T) *httptest.Server {
	t.Helper()

	grpcServer := grpc.NewServer(GRPCServerOption())
	healthpb.RegisterHealthServer(grpcServer, health.NewServer())
	t.Cleanup(grpcServer.Stop)

	srv := httptest.NewUnstartedServer(nil)
	conn, err := grpc.NewClient(
		srv.Listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		GRPCDialOption(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := healthpb.NewHealthClient(conn)

	gateway := HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := client.Check(r.Context(), &healthpb.HealthCheckRequest{}); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	}))
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gateway.ServeHTTP(w, r)
			return
		}
		grpcServer.ServeHTTP(w, r)
	})
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// endedSpans returns a finished request's spans. The gRPC server span ends
// after the handler returns, so it is waited for.
func endedSpans(
	t *testing.T, srv *httptest.Server, recorded *tracetest.SpanRecorder,
) []sdktrace.ReadOnlySpan {
	t.Helper()

	srv.Close()
	var spans []sdktrace.ReadOnlySpan
	require.Eventually(t, func() bool {
		spans = recorded.Ended()
		for _, span := range spans {
			if span.Name() == checkSpan && span.SpanKind() == trace.SpanKindServer {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "gRPC server span not recorded")
	return spans
}

// requireChildOfParent asserts span is a child of the traceparent's span.
func requireChildOfParent(t *testing.T, span sdktrace.ReadOnlySpan) {
	t.Helper()

	require.Equal(t, trace.SpanKindServer, span.SpanKind())
	require.Equal(t, parentTraceID, span.SpanContext().TraceID().String())
	require.Equal(t, parentTraceID, span.Parent().TraceID().String())
	require.Equal(t, parentSpanID, span.Parent().SpanID().String())
	require.True(t, span.Parent().IsRemote())
}

func findSpan(
	t *testing.T, spans []sdktrace.ReadOnlySpan, name string, kind trace.SpanKind,
) sdktrace.ReadOnlySpan {
	t.Helper()

	for _, span := range spans {
		if span.Name() == name && span.SpanKind() == kind {
			return span
		}
	}
	require.Failf(t, "span not recorded", "%s span %q", kind, name)
	return nil
}

func TestLoadOtelConfig(t *testing.T) {
	t.Run("nothing set leaves telemetry off", func(t *testing.T) {
		unsetOtelEnv(t)

		require.Equal(t, OtelConfig{
			Endpoint:    net.JoinHostPort(defaultOtelHost, defaultOtelPort),
			ServiceName: defaultServiceName,
			Environment: defaultDeploymentEnvironment,
		}, loadOtelConfig())
	})

	t.Run("defaults to what the enclave runtime provides", func(t *testing.T) {
		const token, port = "runtime-token", "9090"
		unsetOtelEnv(t)
		t.Setenv(defaultOtelTokenEnv, " "+token+"\n") // padded to check trimming
		t.Setenv(defaultOtelPortEnv, port)

		require.Equal(t, OtelConfig{
			Token:       token,
			Endpoint:    net.JoinHostPort(defaultOtelHost, port),
			ServiceName: defaultServiceName,
			Environment: defaultDeploymentEnvironment,
		}, loadOtelConfig())
	})

	t.Run("EMULATOR_OTEL variables override the defaults", func(t *testing.T) {
		want := OtelConfig{
			Token:       "collector-token",
			Endpoint:    "127.0.0.1:4318",
			ServiceName: "signer",
			Environment: "mutinynet",
		}
		unsetOtelEnv(t)
		t.Setenv(defaultOtelTokenEnv, "runtime-token")
		t.Setenv(defaultOtelPortEnv, "9090")
		t.Setenv(otelTokenEnv, want.Token)
		t.Setenv(otelEndpointEnv, want.Endpoint)
		t.Setenv(otelServiceNameEnv, want.ServiceName)
		t.Setenv(otelEnvironmentEnv, want.Environment)

		require.Equal(t, want, loadOtelConfig())
	})

	t.Run("default token is not sent to a custom endpoint", func(t *testing.T) {
		const endpoint = "collector.example.com:4318"
		unsetOtelEnv(t)
		t.Setenv(defaultOtelTokenEnv, "runtime-token")
		t.Setenv(otelEndpointEnv, endpoint)

		require.Equal(t, OtelConfig{
			Endpoint:    endpoint,
			ServiceName: defaultServiceName,
			Environment: defaultDeploymentEnvironment,
		}, loadOtelConfig())
	})
}

func TestSetupRejectsInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://127.0.0.1:4318", "http://collector", "127.0.0.1",
	} {
		t.Run(endpoint, func(t *testing.T) {
			unsetOtelEnv(t)
			t.Setenv(otelTokenEnv, testToken)
			t.Setenv(otelEndpointEnv, endpoint)

			_, err := Setup(context.Background(), testVersion)
			require.ErrorContains(t, err, endpoint)
		})
	}
}

func TestSetupWithoutTokenExportsNothing(t *testing.T) {
	endpoint, requests := newCollector(t)
	unsetOtelEnv(t)
	t.Setenv(otelEndpointEnv, endpoint)

	shutdown, err := Setup(context.Background(), testVersion)
	require.NoError(t, err)

	ctx, span := otel.Tracer(t.Name()).Start(context.Background(), "startup")
	log.WithContext(ctx).Info("startup")
	CountSignature()
	span.End()
	require.NoError(t, shutdown(context.Background()))

	// Shutdown flushes, so anything exported has arrived by now.
	require.Zero(t, len(requests), "exports made without a token")
}

func TestSetupExportsTelemetryOnShutdown(t *testing.T) {
	endpoint, requests := newCollector(t)
	unsetOtelEnv(t)
	t.Setenv(otelTokenEnv, testToken)
	t.Setenv(otelEndpointEnv, endpoint)
	t.Setenv(otelEnvironmentEnv, testEnvironment)
	// Start with no propagator, so the check below sees the one Setup installs.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())

	shutdown, err := Setup(context.Background(), testVersion)
	require.NoError(t, err)
	// Ensure spans can join the caller's trace from its traceparent.
	require.Subset(t, otel.GetTextMapPropagator().Fields(), propagation.TraceContext{}.Fields())

	const logMessage = "startup failed"
	// More than one, to check the per-call counter lookups add up.
	const signatureCount = 2
	ctx, span := otel.Tracer(t.Name()).Start(context.Background(), "startup")
	log.WithContext(ctx).Info(logMessage)
	for range signatureCount {
		CountSignature()
	}
	span.End()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, shutdown(shutdownCtx))

	received := make(map[string]exportRequest, 3)
	for range 3 {
		select {
		case req := <-requests:
			received[req.path] = req
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for telemetry export")
		}
	}
	// Every signal carries the configured resource.
	wantResource := map[string]string{
		string(semconv.ServiceNameKey):           defaultServiceName,
		string(semconv.ServiceVersionKey):        testVersion,
		string(semconv.DeploymentEnvironmentKey): testEnvironment,
	}

	var traces coltracepb.ExportTraceServiceRequest
	unmarshalExport(t, received, defaultTraceEndpointPath, &traces)
	require.NotEmpty(t, traces.GetResourceSpans())
	require.Equal(t, wantResource, resourceAttributes(traces.GetResourceSpans()[0].GetResource()))

	var metrics colmetricspb.ExportMetricsServiceRequest
	unmarshalExport(t, received, defaultMetricEndpointPath, &metrics)
	require.NotEmpty(t, metrics.GetResourceMetrics())
	require.Equal(t, wantResource, resourceAttributes(metrics.GetResourceMetrics()[0].GetResource()))
	// The signature total is the only metric.
	scopeMetrics := metrics.GetResourceMetrics()[0].GetScopeMetrics()
	require.Len(t, scopeMetrics, 1)
	require.Len(t, scopeMetrics[0].GetMetrics(), 1)
	signatures := scopeMetrics[0].GetMetrics()[0]
	require.Equal(t, signaturesMetricName, signatures.GetName())
	require.True(t, signatures.GetSum().GetIsMonotonic())
	require.Len(t, signatures.GetSum().GetDataPoints(), 1)
	require.EqualValues(t, signatureCount, signatures.GetSum().GetDataPoints()[0].GetAsInt())

	var logs collogspb.ExportLogsServiceRequest
	unmarshalExport(t, received, defaultLogEndpointPath, &logs)
	require.NotEmpty(t, logs.GetResourceLogs())
	require.Equal(t, wantResource, resourceAttributes(logs.GetResourceLogs()[0].GetResource()))

	// Logrus entries are exported with their span.
	record := findLogRecord(t, &logs, logMessage)
	require.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, record.GetSeverityNumber())
	require.Equal(t, span.SpanContext().TraceID().String(), hex.EncodeToString(record.GetTraceId()))
	require.Equal(t, span.SpanContext().SpanID().String(), hex.EncodeToString(record.GetSpanId()))
}

func TestShutdownIsNotHeldUpByOneSignal(t *testing.T) {
	endpoint, requests := newCollector(t, defaultLogEndpointPath)
	unsetOtelEnv(t)
	t.Setenv(otelTokenEnv, testToken)
	t.Setenv(otelEndpointEnv, endpoint)

	shutdown, err := Setup(context.Background(), testVersion)
	require.NoError(t, err)

	_, span := otel.Tracer(t.Name()).Start(context.Background(), "startup")
	log.Info("startup")
	CountSignature()
	span.End()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.Error(t, shutdown(shutdownCtx), "the stalled log export should time out")

	// The other signals are flushed despite the stalled logs.
	received := map[string]bool{}
	for len(requests) > 0 {
		received[(<-requests).path] = true
	}
	require.True(t, received[defaultTraceEndpointPath], "traces not flushed")
	require.True(t, received[defaultMetricEndpointPath], "metrics not flushed")
}

func TestSpansJoinParentTrace(t *testing.T) {
	t.Run("gRPC request has one span, under its parent", func(t *testing.T) {
		recorded := recordSpans(t)
		srv := newTracedServer(t)

		// h2c with a traceparent header, as a proxy would send it.
		conn, err := grpc.NewClient(
			srv.Listener.Addr().String(),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		ctx := metadata.AppendToOutgoingContext(
			context.Background(), traceparentHeader, traceparent,
		)
		_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
		require.NoError(t, err)

		spans := endedSpans(t, srv, recorded)
		require.Len(t, spans, 1, "only otelgrpc may trace a gRPC request")
		require.Equal(t, checkSpan, spans[0].Name())
		requireChildOfParent(t, spans[0])
	})

	t.Run("HTTP request nests the gateway's gRPC call", func(t *testing.T) {
		recorded := recordSpans(t)
		srv := newTracedServer(t)

		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		req.Header.Set(traceparentHeader, traceparent)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		spans := endedSpans(t, srv, recorded)
		// The loopback hop adds no emulator.http span.
		require.Len(t, spans, 3)
		gateway := findSpan(t, spans, httpSpanName, trace.SpanKindServer)
		client := findSpan(t, spans, checkSpan, trace.SpanKindClient)
		server := findSpan(t, spans, checkSpan, trace.SpanKindServer)

		requireChildOfParent(t, gateway)
		require.Equal(t, gateway.SpanContext().SpanID(), client.Parent().SpanID())
		require.Equal(t, client.SpanContext().SpanID(), server.Parent().SpanID())
		require.Equal(t, parentTraceID, server.SpanContext().TraceID().String())
	})
}

// TestInstrumentationRecordsNoMetrics: only the signature total is exported.
func TestInstrumentationRecordsNoMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(provider)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	srv := newTracedServer(t)

	// Also drives the gateway's loopback gRPC call.
	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	srv.Close()

	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &collected))
	require.Empty(t, collected.ScopeMetrics)
}
