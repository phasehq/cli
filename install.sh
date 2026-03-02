#!/bin/sh
#
#              /$$
#             | $$
#     /$$$$$$ | $$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$
#    /$$__  $$| $$__  $$ |____  $$ /$$_____/ /$$__  $$
#   | $$  \ $$| $$  \ $$  /$$$$$$$|  $$$$$$ | $$$$$$$$
#   | $$  | $$| $$  | $$ /$$__  $$ \____  $$| $$_____/
#   | $$$$$$$/| $$  | $$|  $$$$$$$ /$$$$$$$/|  $$$$$$$
#   | $$____/ |__/  |__/ \_______/|_______/  \_______/
#   | $$
#   |__/
# 
# Phase CLI installer.
# 
# Usage:
#   curl -fsSL https://pkg.phase.dev/install.sh | sh
#   curl -fsSL https://pkg.phase.dev/install.sh | sh -s -- --version 2.0.0
#
# Supports: Linux, macOS, FreeBSD, OpenBSD, NetBSD
# Architectures: x86_64, arm64, armv7, mips, mips64, riscv64, ppc64le, s390x

set -e

REPO="phasehq/cli"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="phase"

# --- Helpers ---

die() {
    echo "Error: $1" >&2
    exit 1
}

info() {
    echo "  $1"
}

# Run a command with elevated privileges if needed
do_install() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo > /dev/null 2>&1; then
        sudo "$@"
    elif command -v doas > /dev/null 2>&1; then
        doas "$@"
    else
        die "This script must be run as root or with sudo/doas available."
    fi
}

# Download a URL to a file. Prefers curl, falls back to wget.
fetch() {
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "curl or wget is required to download files."
    fi
}

# Download a URL to stdout.
fetch_stdout() {
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$1"
    elif command -v wget > /dev/null 2>&1; then
        wget -qO - "$1"
    else
        die "curl or wget is required to download files."
    fi
}

# --- Detection ---

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)                    OS="linux" ;;
        Darwin)                   OS="darwin" ;;
        FreeBSD)                  OS="freebsd" ;;
        OpenBSD)                  OS="openbsd" ;;
        NetBSD)                   OS="netbsd" ;;
        MINGW*|MSYS*|CYGWIN*)     die "Windows is not supported by this script. Use Scoop instead: scoop bucket add phasehq https://github.com/phasehq/scoop-cli.git && scoop install phase" ;;
        *)                        die "Unsupported operating system: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)     ARCH="amd64" ;;
        aarch64|arm64)    ARCH="arm64" ;;
        armv7l|armv6l)    ARCH="arm" ;;
        mips)             ARCH="mips" ;;
        mipsel)           ARCH="mipsle" ;;
        mips64)           ARCH="mips64" ;;
        mips64el)         ARCH="mips64le" ;;
        riscv64)          ARCH="riscv64" ;;
        ppc64le)          ARCH="ppc64le" ;;
        s390x)            ARCH="s390x" ;;
        i386|i686)        ARCH="386" ;;
        *)                die "Unsupported architecture: $ARCH" ;;
    esac
}

get_latest_version() {
    fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" | \
        sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p'
}

# --- Install ---

cleanup_legacy() {
    # Clean up any remnants of the PyInstaller-based Python CLI (v1.x).
    # The old install script installed differently depending on distro/arch:
    #   A) DEB package  (Ubuntu/Debian amd64):  dpkg package "phase" -> /usr/lib/phase/ + /usr/bin/phase symlink
    #   B) RPM package  (Fedora/RHEL amd64):    rpm package "phase"  -> /usr/lib/phase/ + /usr/bin/phase symlink
    #   C) APK package  (Alpine amd64+arm64):    apk package "phase"  -> Python setuptools install + /usr/bin/phase
    #   D) Binary zip   (arm64 non-Alpine, Arch): raw files           -> /usr/local/bin/phase + /usr/local/bin/_internal/

    found_legacy=false

    # --- Package manager cleanup (removes tracked files + database entry) ---

    # Scenario A: DEB package
    if command -v dpkg > /dev/null 2>&1; then
        if dpkg -s phase > /dev/null 2>&1; then
            info "Removing legacy Phase CLI v1 DEB package..."
            do_install dpkg --purge phase 2>/dev/null || do_install dpkg -r phase 2>/dev/null || true
            found_legacy=true
        fi
    fi

    # Scenario B: RPM package
    if command -v rpm > /dev/null 2>&1; then
        if rpm -q phase > /dev/null 2>&1; then
            info "Removing legacy Phase CLI v1 RPM package..."
            do_install rpm -e --nodeps phase 2>/dev/null || true
            found_legacy=true
        fi
    fi

    # Scenario C: APK package
    if command -v apk > /dev/null 2>&1; then
        if apk info -e phase > /dev/null 2>&1; then
            info "Removing legacy Phase CLI v1 APK package..."
            do_install apk del phase 2>/dev/null || true
            found_legacy=true
        fi
    fi

    # --- Filesystem cleanup (catch anything left after package removal) ---

    # Scenario D: PyInstaller _internal directory from binary zip install
    if [ -d "${INSTALL_DIR}/_internal" ]; then
        info "Removing legacy PyInstaller _internal directory..."
        do_install rm -rf "${INSTALL_DIR}/_internal"
        found_legacy=true
    fi

    # Stale symlink at /usr/bin/phase from DEB/RPM packages
    if [ -L "/usr/bin/phase" ]; then
        link_target=$(readlink "/usr/bin/phase" 2>/dev/null || true)
        case "$link_target" in
            *lib/phase/phase*)
                info "Removing stale symlink /usr/bin/phase..."
                do_install rm -f "/usr/bin/phase"
                found_legacy=true
                ;;
        esac
    fi

    # Leftover /usr/lib/phase/ directory from DEB/RPM packages
    if [ -d "/usr/lib/phase" ]; then
        info "Removing legacy /usr/lib/phase/ directory..."
        do_install rm -rf "/usr/lib/phase"
        found_legacy=true
    fi

    if [ "$found_legacy" = true ]; then
        info "Legacy Phase CLI v1 cleanup complete."
    fi
}

install_binary() {
    version="$1"

    asset_name="phase-cli_${OS}_${ARCH}"
    download_url="https://github.com/${REPO}/releases/download/v${version}/${asset_name}"

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    echo ""
    info "Phase CLI v${version} (${OS}/${ARCH})"
    echo ""

    info "Downloading ${download_url}..."
    fetch "$download_url" "${tmpdir}/${asset_name}"

    chmod +x "${tmpdir}/${asset_name}"

    # Ensure install directory exists
    if [ ! -d "$INSTALL_DIR" ]; then
        do_install mkdir -p "$INSTALL_DIR"
    fi

    info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
    do_install install -m 755 "${tmpdir}/${asset_name}" "${INSTALL_DIR}/${BINARY_NAME}"

    cleanup_legacy

    echo ""
    info "Phase CLI v${version} installed successfully."
    echo ""

    # Show the installed version
    "${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || true
}

# --- Main ---

main() {
    detect_platform

    VERSION=""

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: install.sh [--version VERSION]"
                echo ""
                echo "Install the Phase CLI. If no version is specified, the latest release is installed."
                exit 0
                ;;
            *)
                die "Unknown option: $1. Use --help for usage."
                ;;
        esac
    done

    if [ -z "$VERSION" ]; then
        info "Fetching latest version..."
        VERSION=$(get_latest_version)
        if [ -z "$VERSION" ]; then
            die "Could not determine latest version. Specify one with --version"
        fi
    fi

    install_binary "$VERSION"
}

main "$@"
