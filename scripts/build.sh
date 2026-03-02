#!/usr/bin/env bash
#
# Cross-compile the Phase CLI for all supported platforms.
# Produces raw binaries — no archives, no checksums
#
# Usage (from repo root):
#   scripts/build.sh
#   VERSION=2.0.0 OUTPUT_DIR=./dist scripts/build.sh

set -euo pipefail

# Auto-detect the src/ directory relative to this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_ROOT/src"

if [ ! -f "$SRC_DIR/go.mod" ]; then
    echo "Error: Cannot find go.mod in $SRC_DIR" >&2
    exit 1
fi

VERSION="${VERSION:-dev}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/dist}"

# Resolve OUTPUT_DIR to absolute path
OUTPUT_DIR="$(cd "$(dirname "$OUTPUT_DIR")" 2>/dev/null && pwd)/$(basename "$OUTPUT_DIR")" || OUTPUT_DIR="$(pwd)/$OUTPUT_DIR"

LDFLAGS="-s -w -X github.com/phasehq/cli/pkg/version.Version=${VERSION}"

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
    "freebsd/amd64"
    "freebsd/arm64"
    "openbsd/amd64"
    "netbsd/amd64"
    "linux/mips"
    "linux/mipsle"
    "linux/mips64"
    "linux/mips64le"
    "linux/riscv64"
    "linux/ppc64le"
    "linux/s390x"
)

mkdir -p "$OUTPUT_DIR"

echo "Building Phase CLI v${VERSION} for ${#TARGETS[@]} targets..."
echo ""

cd "$SRC_DIR"

FAILED=()

for target in "${TARGETS[@]}"; do
    os="${target%/*}"
    arch="${target#*/}"

    output="phase-cli_${os}_${arch}"
    if [ "$os" = "windows" ]; then
        output="${output}.exe"
    fi

    printf "  %-24s" "${os}/${arch}"

    if CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
        go build -trimpath -ldflags "$LDFLAGS" -o "${OUTPUT_DIR}/${output}" ./ 2>&1; then
        echo "ok"
    else
        echo "FAILED"
        FAILED+=("${os}/${arch}")
    fi
done

BUILT=$(find "$OUTPUT_DIR" -name 'phase-cli_*' | wc -l | tr -d ' ')
echo ""
echo "Done. ${BUILT}/${#TARGETS[@]} binaries in ${OUTPUT_DIR}/"

if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo "Failed targets:"
    for f in "${FAILED[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
