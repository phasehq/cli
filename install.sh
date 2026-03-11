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

# Check if we can write to INSTALL_DIR (or create it) without elevated privileges.
# If not, fall back to ~/.local/bin for rootless installs.
check_install_dir() {
    if [ "$(id -u)" -eq 0 ] || command -v sudo > /dev/null 2>&1 || command -v doas > /dev/null 2>&1; then
        return
    fi

    # No privilege escalation available — use a user-local directory
    INSTALL_DIR="${HOME}/.local/bin"
    info "No root/sudo/doas available. Installing to ${INSTALL_DIR} instead."
    info "Make sure ${INSTALL_DIR} is in your PATH."
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

# Detect the Linux distro family for package-based installs.
detect_distro() {
    DISTRO=""
    if [ "$OS" != "linux" ]; then
        return
    fi

    if [ -f /etc/os-release ]; then
        _distro_id=$(grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
        case "$_distro_id" in
            ubuntu|debian)              DISTRO="deb" ;;
            fedora|rhel|centos|amzn|rocky|ol|almalinux) DISTRO="rpm" ;;
            alpine)                     DISTRO="apk" ;;
        esac
    fi
}

get_latest_version() {
    fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" | \
        sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p'
}

# --- Install ---

cleanup_legacy() {
    # Clean up remnants of the old Python CLI (v1.x).
    #
    # Package-managed installs (deb/rpm/apk): the v2.0 packages use
    # --replaces, so the package manager handles the upgrade cleanly.
    # We just nudge the user to use the package instead of this script.
    #
    # Binary zip installs (old arm64, Arch): clean up the leftover
    # _internal/ directory and stale symlinks.

    if command -v dpkg > /dev/null 2>&1 && dpkg -s phase > /dev/null 2>&1; then
        echo ""
        info "Detected Phase CLI v1 installed via DEB package."
        info "Upgrade with the v2 package instead: dpkg -i phase_<version>_<arch>.deb"
        info "Download from: https://github.com/${REPO}/releases"
        echo ""
    elif command -v rpm > /dev/null 2>&1 && rpm -q phase > /dev/null 2>&1; then
        echo ""
        info "Detected Phase CLI v1 installed via RPM package."
        info "Upgrade with the v2 package instead: rpm -Uvh phase-<version>-1.<arch>.rpm"
        info "Download from: https://github.com/${REPO}/releases"
        echo ""
    elif command -v apk > /dev/null 2>&1 && apk info -e phase > /dev/null 2>&1; then
        echo ""
        info "Detected Phase CLI v1 installed via APK package."
        info "Upgrade with the v2 package instead: apk add --allow-untrusted phase_<version>_<arch>.apk"
        info "Download from: https://github.com/${REPO}/releases"
        echo ""
    fi

    # Clean up binary zip leftovers (_internal/ directory)
    for dir in "${INSTALL_DIR}/_internal" "/usr/bin/_internal"; do
        if [ -d "$dir" ]; then
            info "Removing legacy ${dir}..."
            do_install rm -rf "$dir"
        fi
    done

    # Clean up stale symlinks pointing to old /usr/lib/phase/
    if [ -L "/usr/bin/phase" ]; then
        link_target=$(readlink "/usr/bin/phase" 2>/dev/null || true)
        case "$link_target" in
            *lib/phase/phase*)
                info "Removing stale symlink /usr/bin/phase..."
                do_install rm -f "/usr/bin/phase"
                ;;
        esac
    fi
}

# Asset naming convention: phase_cli_{version}_{os}_{arch}[.ext]
asset_url() {
    echo "https://github.com/${REPO}/releases/download/v${1}/phase_cli_${1}_${2}_${3}${4}"
}

install_package() {
    version="$1"

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    echo ""
    info "Phase CLI v${version} (${OS}/${ARCH})"
    echo ""

    case "$DISTRO" in
        deb)
            pkg_file="phase_cli_${version}_linux_${ARCH}.deb"
            download_url=$(asset_url "$version" "linux" "$ARCH" ".deb")
            info "Downloading ${pkg_file}..."
            fetch "$download_url" "${tmpdir}/${pkg_file}"
            info "Installing via dpkg..."
            do_install dpkg -i "${tmpdir}/${pkg_file}"
            ;;
        rpm)
            pkg_file="phase_cli_${version}_linux_${ARCH}.rpm"
            download_url=$(asset_url "$version" "linux" "$ARCH" ".rpm")
            info "Downloading ${pkg_file}..."
            fetch "$download_url" "${tmpdir}/${pkg_file}"
            info "Installing via rpm..."
            do_install rpm -Uvh "${tmpdir}/${pkg_file}"
            ;;
        apk)
            pkg_file="phase_cli_${version}_linux_${ARCH}.apk"
            download_url=$(asset_url "$version" "linux" "$ARCH" ".apk")
            info "Downloading ${pkg_file}..."
            fetch "$download_url" "${tmpdir}/${pkg_file}"
            info "Installing via apk..."
            do_install apk add --allow-untrusted "${tmpdir}/${pkg_file}"
            ;;
        *)
            # No supported package manager — install raw binary
            install_binary "$version"
            return
            ;;
    esac

    cleanup_legacy

    echo ""
    info "Phase CLI v${version} installed successfully."
    echo ""

    phase --version 2>/dev/null || true
}

install_binary() {
    version="$1"

    asset_name="phase_cli_${version}_${OS}_${ARCH}"
    download_url=$(asset_url "$version" "$OS" "$ARCH" "")

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    echo ""
    info "Phase CLI v${version} (${OS}/${ARCH})"
    echo ""

    info "Downloading ${asset_name}..."
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
                echo ""
                echo "Options:"
                echo "  --version VERSION   Install a specific version"
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

    check_install_dir
    detect_distro

    # Use native package manager on supported Linux distros, raw binary elsewhere
    if [ -n "$DISTRO" ]; then
        install_package "$VERSION"
    else
        install_binary "$VERSION"
    fi
}

main "$@"
