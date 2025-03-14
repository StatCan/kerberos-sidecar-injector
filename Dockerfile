# Build the sidecar-injector binary
FROM golang:1.22 AS builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o kerberos-sidecar-injector ./cmd


FROM alpine:latest

# install curl for prestop script
RUN apk --no-cache add curl

WORKDIR /

# install binary
COPY --from=builder /workspace/kerberos-sidecar-injector .

USER 65532:65532

ENTRYPOINT ["/kerberos-sidecar-injector"]
