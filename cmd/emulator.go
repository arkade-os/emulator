package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arkade-os/emulator/internal/config"
	grpcservice "github.com/arkade-os/emulator/internal/interface/grpc"
	"github.com/arkade-os/emulator/internal/telemetry"
	log "github.com/sirupsen/logrus"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	shutdownTelemetry, err := telemetry.Setup(context.Background(), Version)
	if err != nil {
		log.Errorf("failed to initialize telemetry: %s", err)
		os.Exit(1)
	}

	runErr := run()
	if runErr != nil {
		// Log while the providers are still active, then flush below. This makes
		// configuration and service startup failures visible from the enclave.
		log.Error(runErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdownTelemetry(ctx); err != nil {
		log.Errorf("failed to flush telemetry: %s", err)
	}

	if runErr != nil {
		os.Exit(1)
	}
}

func run() error {

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	log.WithFields(log.Fields{
		"version": Version,
		"port":    cfg.Port,
	}).Info("config loaded")

	svc, err := grpcservice.NewService(Version, cfg)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	log.Debug("starting service...")
	if err := svc.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, os.Interrupt)
	<-sigChan

	log.Debug("shutting down service...")
	svc.Stop()
	return nil
}
