# Build stage: compile Go binary
FROM golang:1.24-alpine AS builder

ARG VERSION
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /build

# Copy source
COPY src/ ./src/

WORKDIR /build/src

# Build
RUN go mod download && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w${VERSION:+ -X github.com/phasehq/cli/pkg/version.Version=${VERSION}}" \
    -o /phase ./

# Runtime stage: minimal scratch image
FROM alpine:3.21
RUN apk add --no-cache ca-certificates

COPY --from=builder /phase /usr/local/bin/phase

ENTRYPOINT ["phase"]
CMD ["--help"]
