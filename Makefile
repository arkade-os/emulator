.PHONY: build build-all docker-run docker-stop format integrationtest run test proto proto-lint

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
	@echo "Running introspector..."
	$(call setup_env, envs/introspector.dev.env)
	@go run cmd/introspector.go

test:
	@echo "Running unit tests..."
	@go test -v $$(go list ./... | grep -v '/test$$') github.com/ArkLabsHQ/introspector/pkg/arkade/... github.com/ArkLabsHQ/introspector/pkg/client/...

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
	@echo "Building introspector..."
	@go build -o build/introspector-$(shell go env GOOS)-$(shell go env GOARCH) cmd/introspector.go

build-all:
	@echo "Building introspector for all platforms..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/introspector-linux-amd64 cmd/introspector.go
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o build/introspector-linux-arm64 cmd/introspector.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o build/introspector-darwin-amd64 cmd/introspector.go
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o build/introspector-darwin-arm64 cmd/introspector.go

lint:
	golangci-lint run --fix

# === QEMU enclave integration test (introspector inside Nitro enclave) ===
# Builds the introspector EIF against the local working tree of
# introspector-enclave (RUNTIME_LOCAL_PATH) so the test exercises the
# in-development http2/gRPC framework changes.
.PHONY: enclave-test enclave-test-build enclave-test-run

enclave-test: enclave-test-cli enclave-test-build enclave-test-run

# Rebuild the enclave CLI from the local introspector-enclave checkout so
# the EIF build picks up any in-development CLI changes (e.g. new flake
# inputs). Without this step we would silently use a stale /tmp/enclave.
enclave-test-cli:
	@echo "Building enclave CLI from /home/joshua/introspector-enclave..."
	@cd /home/joshua/introspector-enclave && \
	  go build -o /tmp/enclave ./cli/cmd/enclave

enclave-test-build:
	@echo "Building introspector EIF from local source..."
	@RUNTIME_LOCAL_PATH=/home/joshua/introspector-enclave \
	  SUPERVISOR_LOCAL_PATH=/home/joshua/introspector-enclave \
	  APP_LOCAL_PATH=$(CURDIR) \
	  /tmp/enclave build

enclave-test-run:
	@cd enclave/test && docker compose --profile test down -v
	@cd enclave/test && docker compose --profile test run --build test-runner

format:
	@go fmt ./...