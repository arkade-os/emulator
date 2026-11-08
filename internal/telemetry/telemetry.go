package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc"
)

const (
	otelTokenEnv       = "EMULATOR_OTEL_TOKEN"
	otelEndpointEnv    = "EMULATOR_OTEL_ENDPOINT"
	otelServiceNameEnv = "EMULATOR_OTEL_SERVICE_NAME"
	otelEnvironmentEnv = "EMULATOR_OTEL_ENVIRONMENT"

	// Defaults, as provided by the enclave runtime.
	defaultOtelTokenEnv          = "ENCLAVE_RUNTIME_TOKEN"
	defaultOtelPortEnv           = "ENCLAVE_PROXY_PORT"
	defaultOtelHost              = "127.0.0.1"
	defaultOtelPort              = "8080"
	defaultServiceName           = "emulator"
	defaultDeploymentEnvironment = "enclave"

	defaultTraceEndpointPath = "/v1/traces"
	defaultLogEndpointPath   = "/v1/logs"

	instrumentationName = "github.com/arkade-os/emulator"
	httpSpanName        = defaultServiceName + ".http"
)

// OtelConfig configures telemetry export.
type OtelConfig struct {
	Token       string // bearer token; telemetry is off without one
	Endpoint    string // OTLP/HTTP collector host:port, no TLS
	ServiceName string
	Environment string
}

// loadOtelConfig reads EMULATOR_OTEL_* variables, falling back to defaults.
func loadOtelConfig() OtelConfig {
	cfg := OtelConfig{
		Token:       envOr(otelTokenEnv, ""),
		Endpoint:    envOr(otelEndpointEnv, ""),
		ServiceName: envOr(otelServiceNameEnv, defaultServiceName),
		Environment: envOr(otelEnvironmentEnv, defaultDeploymentEnvironment),
	}
	// The default token is sent only to the default endpoint, never elsewhere.
	if cfg.Endpoint == "" {
		cfg.Endpoint = net.JoinHostPort(
			defaultOtelHost, envOr(defaultOtelPortEnv, defaultOtelPort),
		)
		cfg.Token = envOr(otelTokenEnv, os.Getenv(defaultOtelTokenEnv))
	}
	return cfg
}

// validateEndpoint accepts only host:port, which is all WithEndpoint takes.
func validateEndpoint(endpoint string) error {
	_, port, err := net.SplitHostPort(endpoint)
	if err == nil {
		_, err = strconv.ParseUint(port, 10, 16)
	}
	if err != nil {
		return fmt.Errorf("invalid OTLP endpoint %q, want host:port: %w", endpoint, err)
	}
	return nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

// Setup exports traces and logs over OTLP/HTTP and returns a shutdown function
// that flushes them.
func Setup(ctx context.Context, version string) (func(context.Context) error, error) {
	cfg := loadOtelConfig()
	if cfg.Token == "" {
		return func(context.Context) error { return nil }, nil
	}
	if err := validateEndpoint(cfg.Endpoint); err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Authorization": "Bearer " + cfg.Token,
	}

	res, err := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(version),
		semconv.DeploymentEnvironment(cfg.Environment),
	))
	if err != nil {
		return nil, fmt.Errorf("create telemetry resource: %w", err)
	}

	traceExporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(cfg.Endpoint),
		otlptracehttp.WithURLPath(defaultTraceEndpointPath),
		otlptracehttp.WithInsecure(),
		otlptracehttp.WithHeaders(headers),
	)
	if err != nil {
		return nil, fmt.Errorf("create trace exporter: %w", err)
	}

	logExporter, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpoint(cfg.Endpoint),
		otlploghttp.WithURLPath(defaultLogEndpointPath),
		otlploghttp.WithInsecure(),
		otlploghttp.WithHeaders(headers),
	)
	if err != nil {
		_ = traceExporter.Shutdown(ctx)
		return nil, fmt.Errorf("create log exporter: %w", err)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
		sdklog.WithResource(res),
	)

	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	global.SetLoggerProvider(loggerProvider)
	log.AddHook(otellogrus.NewHook(
		instrumentationName,
		otellogrus.WithLoggerProvider(loggerProvider),
		otellogrus.WithVersion(version),
	))

	return func(shutdownCtx context.Context) error {
		// Concurrently, so one slow flush can't use up the other's deadline.
		shutdowns := []func(context.Context) error{
			loggerProvider.Shutdown, tracerProvider.Shutdown,
		}
		errs := make([]error, len(shutdowns))
		var wg sync.WaitGroup
		for i, shutdown := range shutdowns {
			wg.Go(func() { errs[i] = shutdown(shutdownCtx) })
		}
		wg.Wait()
		return errors.Join(errs...)
	}, nil
}

// The instrumentation below joins the trace in the request's traceparent.

// HTTPHandler traces HTTP requests. Wrap only the HTTP routes, so gRPC
// requests are traced once, by GRPCServerOption.
func HTTPHandler(h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, httpSpanName)
}

// GRPCServerOption traces incoming RPCs.
func GRPCServerOption() grpc.ServerOption {
	return grpc.StatsHandler(otelgrpc.NewServerHandler())
}

// GRPCDialOption traces outgoing RPCs and propagates their trace.
func GRPCDialOption() grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler())
}
