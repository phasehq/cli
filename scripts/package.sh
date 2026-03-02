#!/usr/bin/env bash
#
# Package Phase CLI binaries into .deb, .rpm, .apk using FPM.
# Requires: fpm (gem install fpm)
#
# Usage (from repo root):
#   scripts/package.sh
#   VERSION=2.0.0 INPUT_DIR=dist scripts/package.sh

set -euo pipefail

VERSION="${VERSION:-dev}"
INPUT_DIR="${INPUT_DIR:-dist}"
OUTPUT_DIR="${OUTPUT_DIR:-dist/pkg}"

PACKAGE_NAME="phase"
DESCRIPTION="Phase CLI - open-source secret manager"
MAINTAINER="Phase <info@phase.dev>"
URL="https://phase.dev"
LICENSE="GPL-3.0"

# Arch mappings: Go name → package manager name
pkg_arch() {
    local fmt="$1" go_arch="$2"
    case "$fmt" in
        deb) echo "$go_arch" ;;  # deb uses amd64/arm64 as-is
        rpm|apk)
            case "$go_arch" in
                amd64) echo "x86_64" ;;
                arm64) echo "aarch64" ;;
            esac
            ;;
    esac
}

TARGETS=("amd64" "arm64")

if ! command -v fpm > /dev/null; then
    echo "Error: fpm is not installed. Install with: gem install fpm" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "Packaging Phase CLI v${VERSION}..."
echo ""

for arch in "${TARGETS[@]}"; do
    binary="${INPUT_DIR}/phase-cli_linux_${arch}"

    if [ ! -f "$binary" ]; then
        echo "Warning: $binary not found, skipping $arch"
        continue
    fi

    # Common flags (positional arg must come last, after per-format flags)
    FPM_COMMON=(
        -s dir
        --name "$PACKAGE_NAME"
        --version "$VERSION"
        --maintainer "$MAINTAINER"
        --description "$DESCRIPTION"
        --url "$URL"
        --license "$LICENSE"
        --provides phase
        --replaces "phase < 2.0.0"
        --force
    )

    # .deb
    printf "  %-12s" "deb/${arch}"
    fpm "${FPM_COMMON[@]}" -t deb \
        --architecture "$(pkg_arch deb "$arch")" \
        --package "${OUTPUT_DIR}/" \
        "${binary}=/usr/bin/phase" > /dev/null
    echo "ok"

    # .rpm
    printf "  %-12s" "rpm/${arch}"
    fpm "${FPM_COMMON[@]}" -t rpm \
        --architecture "$(pkg_arch rpm "$arch")" \
        --rpm-summary "$DESCRIPTION" \
        --package "${OUTPUT_DIR}/" \
        "${binary}=/usr/bin/phase" > /dev/null
    echo "ok"

    # .apk
    printf "  %-12s" "apk/${arch}"
    fpm "${FPM_COMMON[@]}" -t apk \
        --architecture "$(pkg_arch apk "$arch")" \
        --package "${OUTPUT_DIR}/" \
        "${binary}=/usr/bin/phase" > /dev/null
    echo "ok"
done

# Generate checksums
echo ""
if ls "$OUTPUT_DIR"/*.deb "$OUTPUT_DIR"/*.rpm "$OUTPUT_DIR"/*.apk > /dev/null; then
    (cd "$OUTPUT_DIR" && sha256sum *.deb *.rpm *.apk > checksums.txt)
    echo "Packages:"
    ls -lh "$OUTPUT_DIR/"
else
    echo "No packages were produced."
    exit 1
fi
