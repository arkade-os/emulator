package grpcservice

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/arkade-os/arkd/pkg/macaroons"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/internal/application"
	"github.com/arkade-os/emulator/internal/config"
	interfaces "github.com/arkade-os/emulator/internal/interface"
	"github.com/arkade-os/emulator/internal/interface/grpc/handlers"
	"github.com/arkade-os/emulator/internal/interface/grpc/interceptors"
	"github.com/meshapi/grpc-api-gateway/gateway"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

type service struct {
	version    string
	config     Config
	cfg        *config.Config
	appSvc     application.Service
	server     *http.Server
	grpcServer *grpc.Server
	// macaroonSvc gates the signing endpoints when set. It is nil until a
	// deployment configures macaroon auth, in which case requests are served
	// unauthenticated.
	macaroonSvc *macaroons.Service
}

func NewService(
	version string, cfg *config.Config,
) (interfaces.Service, error) {
	config := Config{
		Port: cfg.Port,
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid service config: %s", err)
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
	if err := s.newServer(); err != nil {
		return err
	}

	// nolint:all
	go s.server.ListenAndServe()

	return nil
}

const (
	// maxReceiveMessageSize bounds a single inbound grpc message. The signing
	// handlers parse every PSBT, checkpoint, forfeit and tree element they are
	// handed before validating anything, so an unbounded message is an
	// unbounded allocation. This pins the bound explicitly instead of relying
	// on the grpc-go default.
	maxReceiveMessageSize = 4 * 1024 * 1024

	// maxHTTPRequestBodySize bounds a request arriving through the JSON
	// gateway. The gateway decodes the whole body before the message ever
	// reaches the grpc receive limit, so the bound has to be applied here too.
	// It is larger than maxReceiveMessageSize to leave room for JSON encoding
	// overhead on an otherwise legitimate payload.
	maxHTTPRequestBodySize = 8 * 1024 * 1024

	// maxConcurrentStreams bounds concurrent streams per grpc transport. It
	// takes effect when the server is driven through Serve(listener); on the
	// ServeHTTP path used here concurrency is governed by net/http's HTTP/2
	// server, which defaults to 250 streams per connection.
	maxConcurrentStreams = 256
)

func serverOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
		grpc.MaxRecvMsgSize(maxReceiveMessageSize),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
	}
}

func (s *service) newServer() error {
	ctx := context.Background()

	otelHandler := otelgrpc.NewServerHandler(
		otelgrpc.WithTracerProvider(otel.GetTracerProvider()),
	)

	// No macaroon service is configured today, so the interceptors run without
	// authentication. They are still installed so that the request logging and
	// the macaroon check are in place the moment one is provided.
	if s.macaroonSvc == nil {
		log.Warn("no macaroon service configured, serving requests without authentication")
	}

	grpcConfig := serverOptions()
	grpcConfig = append(
		grpcConfig,
		grpc.StatsHandler(otelHandler),
		interceptors.UnaryInterceptor(s.macaroonSvc),
		interceptors.StreamInterceptor(s.macaroonSvc),
	)

	// Server grpc.
	grpcServer := grpc.NewServer(grpcConfig...)

	appSvc, err := s.cfg.AppService(ctx, s.version)
	if err != nil {
		return err
	}
	s.appSvc = appSvc
	appHandler := handlers.New(s.version, appSvc)
	emulatorv1.RegisterEmulatorServiceServer(grpcServer, appHandler)

	healthHandler := handlers.NewHealthHandler()
	grpchealth.RegisterHealthServer(grpcServer, healthHandler)

	// Creds for grpc gateway reverse proxy.
	gatewayOpts := grpc.WithTransportCredentials(insecure.NewCredentials())
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

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	s.grpcServer = grpcServer
	s.server = &http.Server{
		Addr:      s.config.address(),
		Handler:   httpServerHandler,
		Protocols: protocols,
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

			// The gateway decodes the whole body before the message reaches
			// the grpc receive limit, so cap it here as well.
			r.Body = http.MaxBytesReader(w, r.Body, maxHTTPRequestBodySize)

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
