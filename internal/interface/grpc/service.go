package grpcservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/arkade-os/emulator/internal/config"
	interfaces "github.com/arkade-os/emulator/internal/interface"
	"github.com/arkade-os/emulator/internal/interface/grpc/handlers"
	"github.com/meshapi/grpc-api-gateway/gateway"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	tlsKeyFile  = "key.pem"
	tlsCertFile = "cert.pem"
	tlsFolder   = "tls"
)

type service struct {
	version    string
	config     Config
	cfg        *config.Config
	appSvc     emulator.Service
	server     *http.Server
	grpcServer *grpc.Server
}

func NewService(
	version string, cfg *config.Config,
) (interfaces.Service, error) {
	config := Config{
		Datadir:         cfg.Datadir,
		Port:            cfg.Port,
		NoTLS:           cfg.NoTLS,
		TLSExtraIPs:     cfg.TLSExtraIPs,
		TLSExtraDomains: cfg.TLSExtraDomains,
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid service config: %s", err)
	}

	if !config.insecure() {
		if err := generateOperatorTLSKeyCert(
			config.tlsDatadir(), config.TLSExtraIPs, config.TLSExtraDomains,
		); err != nil {
			return nil, err
		}
		log.Debugf("generated TLS key pair at path: %s", config.tlsDatadir())
	}

	return &service{
		version: version,
		config:  config,
		cfg:     cfg,
	}, nil
}

func (s *service) Start() error {
	if err := s.start(); err != nil {
		return err
	}
	log.Infof("started listening at %s", s.config.address())

	return nil
}

func (s *service) Stop() {
	if s.appSvc != nil {
		s.appSvc.Close()
	}
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}
	if s.server != nil {
		// nolint
		s.server.Shutdown(context.Background())
	}
	log.Info("shutdown service")
}

func (s *service) start() error {
	tlsConfig, err := s.config.tlsConfig()
	if err != nil {
		return err
	}

	if err := s.newServer(tlsConfig); err != nil {
		return err
	}

	// Start main server
	if s.config.insecure() {
		// nolint:all
		go s.server.ListenAndServe()
	} else {
		// nolint:all
		go s.server.ListenAndServeTLS("", "")
	}

	return nil
}

func (s *service) newServer(tlsConfig *tls.Config) error {
	ctx := context.Background()

	otelHandler := otelgrpc.NewServerHandler(
		otelgrpc.WithTracerProvider(otel.GetTracerProvider()),
	)

	grpcConfig := []grpc.ServerOption{
		grpc.StatsHandler(otelHandler),
	}
	creds := insecure.NewCredentials()
	if !s.config.insecure() {
		creds = credentials.NewTLS(tlsConfig)
	}
	grpcConfig = append(grpcConfig, grpc.Creds(creds))

	// Server grpc.
	grpcServer := grpc.NewServer(grpcConfig...)

	appSvc, err := s.cfg.AppService(ctx)
	if err != nil {
		return err
	}
	s.appSvc = appSvc
	appHandler := handlers.New(s.version, appSvc)
	emulatorv1.RegisterEmulatorServiceServer(grpcServer, appHandler)

	healthHandler := handlers.NewHealthHandler()
	grpchealth.RegisterHealthServer(grpcServer, healthHandler)

	// Creds for grpc gateway reverse proxy.
	gatewayCreds := insecure.NewCredentials()
	if !s.config.insecure() {
		gatewayCreds = credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, // #nosec
		})
	}
	gatewayOpts := grpc.WithTransportCredentials(gatewayCreds)
	conn, err := grpc.NewClient(
		s.config.gatewayAddress(), gatewayOpts,
	)
	if err != nil {
		return err
	}

	customMatcher := func(key string) (string, bool) {
		switch key {
		case "X-Macaroon":
			return "macaroon", true
		default:
			return key, false
		}
	}
	// Reverse proxy grpc-gateway.
	gwmux := gateway.NewServeMux(
		gateway.WithIncomingHeaderMatcher(customMatcher),
		gateway.WithHealthzEndpoint(grpchealth.NewHealthClient(conn)),
	)

	// Register public services on main gateway
	emulatorv1.RegisterEmulatorServiceHandler(ctx, gwmux, conn)

	grpcGateway := http.Handler(gwmux)
	handler := router(grpcServer, grpcGateway)
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	httpServerHandler := http.Handler(mux)
	if s.config.insecure() {
		httpServerHandler = h2c.NewHandler(httpServerHandler, &http2.Server{})
	}

	s.grpcServer = grpcServer
	s.server = &http.Server{
		Addr:      s.config.address(),
		Handler:   httpServerHandler,
		TLSConfig: tlsConfig,
	}

	return nil
}

func router(
	grpcServer *grpc.Server, grpcGateway http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOptionRequest(r) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			return
		}

		if isHttpRequest(r) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Add("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

			grpcGateway.ServeHTTP(w, r)
			return
		}
		grpcServer.ServeHTTP(w, r)
	})
}

func isOptionRequest(req *http.Request) bool {
	return req.Method == http.MethodOptions
}

func isHttpRequest(req *http.Request) bool {
	return req.Method == http.MethodGet ||
		strings.Contains(req.Header.Get("Content-Type"), "application/json")
}
