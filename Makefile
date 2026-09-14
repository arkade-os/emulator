.PHONY: build build-all docker-run docker-stop format integrationtest run test proto proto-lint

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X 'main.Version=$(VERSION)'

define setup_env
    $(eval include $(1))
    $(eval export)
endef

proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

# proto-lint: lints protos
proto-lint:
	@echo "Linting protos..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

run:
	@echo "Running emulator..."
	$(call setup_env, envs/emulator.dev.env)
	@go run cmd/emulator.go

test:
	@echo "Running unit tests..."
	@go test -v $$(go list ./... | grep -v '/test$$') github.com/arkade-os/emulator/pkg/arkade/... github.com/arkade-os/emulator/pkg/client/... github.com/arkade-os/emulator/pkg/emulator/...

integrationtest:
	@echo "Running integration test..."
	@go test -v ./test/...

# docker-run: starts docker test environment
docker-run:
	@echo "Running dockerized arkd and arkd wallet in test mode on regtest..."
	@docker compose -f docker-compose.regtest.yml up --build -d

# docker-stop: tears down docker test environment
docker-stop:
	@echo "Stopping dockerized arkd and arkd wallet in test mode on regtest..."
	@docker compose -f docker-compose.regtest.yml down -v

build:
	@echo "Building emulator $(VERSION)..."
	@go build -ldflags="$(LDFLAGS)" -o build/emulator-$(shell go env GOOS)-$(shell go env GOARCH) cmd/emulator.go

build-all:
	@echo "Building emulator $(VERSION) for all platforms..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o build/emulator-linux-amd64 cmd/emulator.go
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o build/emulator-linux-arm64 cmd/emulator.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o build/emulator-darwin-amd64 cmd/emulator.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o build/emulator-darwin-arm64 cmd/emulator.go

lint:
	golangci-lint run --fix

format:
	@go fmt ./...