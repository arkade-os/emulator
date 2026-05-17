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

# === QEMU enclave integration test ===
# Thin wrappers around `enclave test {build,init,start,down}` from the
# introspector-enclave CLI (must be on $PATH). `make enclave-test` runs
# the full loop: build EIF, scaffold compose + ensure mock-arkd is wired
# in, boot the stack, run integration-test.sh, tear down.
.PHONY: enclave-test enclave-test-build enclave-test-init enclave-test-start enclave-test-down

define MOCK_ARKD_BLOCK

    mock-arkd:
        build:
            context: ../../
            dockerfile: enclave/test/mock-arkd/Dockerfile
        network_mode: host
        environment:
            MOCK_ARKD_ADDR: ":8081"
        healthcheck:
            test: ["CMD-SHELL", "/usr/local/bin/grpcurl -plaintext -max-time 2 localhost:8081 list"]
            interval: 5s
            timeout: 3s
            retries: 5
endef
export MOCK_ARKD_BLOCK

enclave-test: enclave-test-build enclave-test-init enclave-test-start
	@./enclave/test/integration-test.sh
	@$(MAKE) enclave-test-down

enclave-test-build:
	@enclave test build

# `enclave test init` is merge-only-new on the compose file; the grep
# guard keeps the mock-arkd append idempotent across re-runs.
enclave-test-init:
	@enclave test init
	@if ! grep -q '^    mock-arkd:' enclave/test/docker-compose.yml; then \
	  echo "$$MOCK_ARKD_BLOCK" >> enclave/test/docker-compose.yml; \
	fi

enclave-test-start:
	@enclave test start

enclave-test-down:
	@enclave test down

format:
	@go fmt ./...