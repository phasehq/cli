# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /build/src

COPY src/go.mod src/go.sum ./
RUN go mod download

COPY src/ ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w${VERSION:+ -X github.com/phasehq/cli/pkg/version.Version=${VERSION}}" \
    -o /phase ./

# Runtime stage
FROM alpine:3.21
RUN apk add --no-cache ca-certificates && \
    addgroup -S phase && adduser -S phase -G phase

COPY --from=builder /phase /usr/local/bin/phase

USER phase

ENTRYPOINT ["phase"]
CMD ["--help"]
