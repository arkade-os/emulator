# Build context is the introspector repo root so the mock can resolve
# any vendored deps from go.mod. Output binary listens on :8081.
FROM golang:1.26-bookworm AS builder
WORKDIR /src
COPY enclave/test/mock-arkd/go.mod enclave/test/mock-arkd/go.sum* ./
COPY enclave/test/mock-arkd/main.go .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -o /mock-arkd .

FROM debian:bookworm-slim
COPY --from=builder /mock-arkd /usr/local/bin/mock-arkd
# Bake grpcurl in so docker-compose's healthcheck can probe the gRPC port.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget \
    && wget -qO- https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz \
       | tar xz -C /usr/local/bin grpcurl \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/mock-arkd"]
