# Build stage: compile Go binary
FROM golang:1.24-alpine AS builder

ARG VERSION
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /build

# Copy Go SDK (placed alongside by CI or Docker build context)
COPY golang-sdk/ ./golang-sdk/

# Copy source
COPY src/ ./src/

WORKDIR /build/src

# Patch replace directive for build context
RUN go mod edit -replace github.com/phasehq/golang-sdk=../golang-sdk

# Download dependencies and build
RUN go mod download && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w${VERSION:+ -X github.com/phasehq/cli/pkg/version.Version=${VERSION}}" \
    -o /phase ./

# Runtime stage: minimal scratch image
FROM alpine:3.21

# Install CA certificates for HTTPS API calls
RUN apk add --no-cache ca-certificates

COPY --from=builder /phase /usr/local/bin/phase

ENTRYPOINT ["phase"]
CMD ["--help"]
