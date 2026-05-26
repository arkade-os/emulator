FROM golang:1.24-alpine3.20 AS builder

RUN apk add --no-cache git
RUN go install github.com/bufbuild/buf/cmd/buf@v1.55.1
RUN go install github.com/meshapi/grpc-api-gateway/codegen/cmd/protoc-gen-grpc-api-gateway@v0.0.11
RUN go install github.com/meshapi/grpc-api-gateway/codegen/cmd/protoc-gen-openapiv3@v0.0.11
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1

ENTRYPOINT ["/go/bin/buf"]
