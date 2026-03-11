#!/usr/bin/env bash
#
# Rename build artifacts to the standard naming convention and generate checksums.
#
# Convention: phase_cli_{version}_{os}_{arch}[.ext]
#
# Usage (from repo root):
#   scripts/process-assets.sh
#   VERSION=2.0.0 BINARIES_DIR=dist PACKAGES_DIR=dist/pkg OUTPUT_DIR=release scripts/process-assets.sh

set -euo pipefail

VERSION="${VERSION:?VERSION is required}"
BINARIES_DIR="${BINARIES_DIR:-dist}"
PACKAGES_DIR="${PACKAGES_DIR:-dist/pkg}"
OUTPUT_DIR="${OUTPUT_DIR:-release}"

mkdir -p "$OUTPUT_DIR"

echo "Processing assets for Phase CLI v${VERSION}..."
echo ""

# ─── Asset Map ────────────────────────────────────────────────────────────────
#
# Each entry: "source_dir|source_filename|dest_filename"
#
# To add a new asset, just add a line to this list.
# Use B for BINARIES_DIR, P for PACKAGES_DIR as shorthand.

B="$BINARIES_DIR"
P="$PACKAGES_DIR"

ASSETS=(
    # Binaries — Linux
    "${B}|phase-cli_linux_amd64|phase_cli_${VERSION}_linux_amd64"
    "${B}|phase-cli_linux_arm64|phase_cli_${VERSION}_linux_arm64"
    "${B}|phase-cli_linux_arm|phase_cli_${VERSION}_linux_arm"
    "${B}|phase-cli_linux_386|phase_cli_${VERSION}_linux_386"
    "${B}|phase-cli_linux_mips|phase_cli_${VERSION}_linux_mips"
    "${B}|phase-cli_linux_mipsle|phase_cli_${VERSION}_linux_mipsle"
    "${B}|phase-cli_linux_mips64|phase_cli_${VERSION}_linux_mips64"
    "${B}|phase-cli_linux_mips64le|phase_cli_${VERSION}_linux_mips64le"
    "${B}|phase-cli_linux_riscv64|phase_cli_${VERSION}_linux_riscv64"
    "${B}|phase-cli_linux_ppc64le|phase_cli_${VERSION}_linux_ppc64le"
    "${B}|phase-cli_linux_s390x|phase_cli_${VERSION}_linux_s390x"

    # Binaries — macOS
    "${B}|phase-cli_darwin_amd64|phase_cli_${VERSION}_darwin_amd64"
    "${B}|phase-cli_darwin_arm64|phase_cli_${VERSION}_darwin_arm64"

    # Binaries — Windows
    "${B}|phase-cli_windows_amd64.exe|phase_cli_${VERSION}_windows_amd64.exe"
    "${B}|phase-cli_windows_arm64.exe|phase_cli_${VERSION}_windows_arm64.exe"

    # Binaries — BSD
    "${B}|phase-cli_freebsd_amd64|phase_cli_${VERSION}_freebsd_amd64"
    "${B}|phase-cli_freebsd_arm64|phase_cli_${VERSION}_freebsd_arm64"
    "${B}|phase-cli_openbsd_amd64|phase_cli_${VERSION}_openbsd_amd64"
    "${B}|phase-cli_netbsd_amd64|phase_cli_${VERSION}_netbsd_amd64"

    # DEB packages (FPM names: phase_{version}_{arch}.deb)
    "${P}|phase_${VERSION}_amd64.deb|phase_cli_${VERSION}_linux_amd64.deb"
    "${P}|phase_${VERSION}_arm64.deb|phase_cli_${VERSION}_linux_arm64.deb"

    # RPM packages (FPM names: phase-{version}-1.{arch}.rpm)
    "${P}|phase-${VERSION}-1.x86_64.rpm|phase_cli_${VERSION}_linux_amd64.rpm"
    "${P}|phase-${VERSION}-1.aarch64.rpm|phase_cli_${VERSION}_linux_arm64.rpm"

    # APK packages (FPM names: phase_{version}_{arch}.apk)
    "${P}|phase_${VERSION}_x86_64.apk|phase_cli_${VERSION}_linux_amd64.apk"
    "${P}|phase_${VERSION}_aarch64.apk|phase_cli_${VERSION}_linux_arm64.apk"
)

# ─── Process ──────────────────────────────────────────────────────────────────

RENAMED=0
MISSING=0
FAILED=0
MISSING_FILES=()
FAILED_FILES=()

for entry in "${ASSETS[@]}"; do
    IFS='|' read -r src_dir src_name dest_name <<< "$entry"

    src_path="${src_dir}/${src_name}"
    dest_path="${OUTPUT_DIR}/${dest_name}"

    if [ ! -f "$src_path" ]; then
        printf "  %-55s MISSING\n" "$src_name"
        MISSING=$((MISSING + 1))
        MISSING_FILES+=("$src_name")
        continue
    fi

    if cp "$src_path" "$dest_path"; then
        printf "  %-55s -> %s\n" "$src_name" "$dest_name"
        RENAMED=$((RENAMED + 1))
    else
        printf "  %-55s FAILED\n" "$src_name"
        FAILED=$((FAILED + 1))
        FAILED_FILES+=("$src_name")
    fi
done

# ─── Checksums ────────────────────────────────────────────────────────────────

echo ""

if [ "$RENAMED" -gt 0 ]; then
    (cd "$OUTPUT_DIR" && sha256sum -- * > checksums.txt 2>/dev/null || true)
fi

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "Summary: ${RENAMED} renamed, ${MISSING} missing, ${FAILED} failed"
echo ""

if [ "$MISSING" -gt 0 ]; then
    echo "Missing source files:"
    for f in "${MISSING_FILES[@]}"; do
        echo "  - $f"
    done
    echo ""
fi

if [ "$FAILED" -gt 0 ]; then
    echo "Failed to copy:"
    for f in "${FAILED_FILES[@]}"; do
        echo "  - $f"
    done
    echo ""
fi

if [ "$RENAMED" -gt 0 ]; then
    echo "Release assets in ${OUTPUT_DIR}/:"
    ls -1 "$OUTPUT_DIR/"
fi

if [ "$FAILED" -gt 0 ]; then
    echo "ERROR: ${FAILED} assets failed to copy." >&2
    exit 1
fi

if [ "$RENAMED" -eq 0 ]; then
    echo "ERROR: No assets were produced." >&2
    exit 1
fi
