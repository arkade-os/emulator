package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	serviceName       = "emulator"
	defaultProxyPort  = "8080"
	runtimeTokenEnv   = "ENCLAVE_RUNTIME_TOKEN"
	runtimeProxyEnv   = "ENCLAVE_PROXY_PORT"
	traceEndpointPath = "/v1/traces"
	logEndpointPath   = "/v1/logs"
)

// Setup configures the emulator to export OTLP/HTTP protobuf telemetry to the
// enclave runtime's loopback ingest API. Outside an enclave, where the runtime
// token is absent, telemetry remains disabled so local development still works.
func Setup(ctx context.Context, version string) (func(context.Context) error, error) {
	token := strings.TrimSpace(os.Getenv(runtimeTokenEnv))
	if token == "" {
		return func(context.Context) error { return nil }, nil
	}

	port := strings.TrimSpace(os.Getenv(runtimeProxyEnv))
	if port == "" {
		port = defaultProxyPort
	}
	endpoint := "127.0.0.1:" + port
	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	res, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", serviceName),
		attribute.String("service.version", version),
		attribute.String("deployment.environment", "enclave"),
	))
	if err != nil {
		return nil, fmt.Errorf("create telemetry resource: %w", err)
	}

	traceExporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithURLPath(traceEndpointPath),
		otlptracehttp.WithInsecure(),
		otlptracehttp.WithHeaders(headers),
	)
	if err != nil {
		return nil, fmt.Errorf("create enclave trace exporter: %w", err)
	}

	logExporter, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpoint(endpoint),
		otlploghttp.WithURLPath(logEndpointPath),
		otlploghttp.WithInsecure(),
		otlploghttp.WithHeaders(headers),
	)
	if err != nil {
		_ = traceExporter.Shutdown(ctx)
		return nil, fmt.Errorf("create enclave log exporter: %w", err)
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
		"github.com/arkade-os/emulator",
		otellogrus.WithLoggerProvider(loggerProvider),
		otellogrus.WithVersion(version),
	))

	return func(shutdownCtx context.Context) error {
		return errors.Join(
			loggerProvider.Shutdown(shutdownCtx),
			tracerProvider.Shutdown(shutdownCtx),
		)
	}, nil
}
