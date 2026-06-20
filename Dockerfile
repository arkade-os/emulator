# First image used to build the sources
FROM golang:1.26.4 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Copy go.mod and go.sum files first for better caching
COPY go.mod go.sum ./
COPY api-spec/go.mod api-spec/go.sum ./api-spec/
COPY pkg/arkade/go.mod pkg/arkade/go.sum ./pkg/arkade/
COPY pkg/client/go.mod pkg/client/go.sum ./pkg/client/
COPY pkg/emulator/go.mod pkg/emulator/go.sum ./pkg/emulator/

# Download dependencies
RUN go mod download
RUN cd api-spec && go mod download
RUN cd pkg/arkade && go mod download
RUN cd pkg/client && go mod download
RUN cd pkg/emulator && go mod download

# Copy the rest of the source code
COPY . .

# ENV GOPROXY=https://goproxy.io,direct
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o ./bin/emulator ./cmd/emulator.go

# Second image, running the executable
FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/* /app/

ENV PATH="/app:${PATH}"
ENV EMULATOR_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "emulator" ]
