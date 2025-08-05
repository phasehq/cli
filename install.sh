#!/bin/bash

set -e

REPO="phasehq/cli"
BASE_URL="https://github.com/$REPO/releases/download"

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo "Can't detect OS type."
        exit 1
    fi
}

has_sudo_access() {
    if sudo -n true 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

can_install_without_sudo() {
    case $OS in
        ubuntu|debian)
            if dpkg -l >/dev/null 2>&1; then
                return 0
            fi
            ;;
        fedora|rhel|centos)
            if rpm -q rpm >/dev/null 2>&1; then
                return 0
            fi
            ;;
        alpine)
            if apk --version >/dev/null 2>&1; then
                return 0
            fi
            ;;
        arch)
            if pacman -V >/dev/null 2>&1; then
                return 0
            fi
            ;;
    esac
    return 1
}

prompt_sudo() {
    if [ "$EUID" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            echo "This operation requires elevated privileges. Please enter your sudo password if prompted."
            sudo -v
            if [ $? -ne 0 ]; then
                echo "Failed to obtain sudo privileges. Exiting."
                exit 1
            fi
        else
            echo "Error: This script must be run as root or with sudo privileges."
            exit 1
        fi
    fi
}

install_tool() {
    local TOOL=$1
    echo "Installing $TOOL..."
    if [ "$EUID" -eq 0 ] || can_install_without_sudo; then
        case $OS in
            ubuntu|debian)
                apt-get update && apt-get install -y $TOOL
                ;;
            fedora|rhel|centos)
                yum install -y $TOOL
                ;;
            alpine)
                apk add $TOOL
                ;;
            arch)
                pacman -Sy --noconfirm $TOOL
                ;;
        esac
    else
        prompt_sudo
        case $OS in
            ubuntu|debian)
                sudo apt-get update && sudo apt-get install -y $TOOL
                ;;
            fedora|rhel|centos)
                sudo yum install -y $TOOL
                ;;
            alpine)
                sudo apk add $TOOL
                ;;
            arch)
                sudo pacman -Sy --noconfirm $TOOL
                ;;
        esac
    fi
}

check_required_tools() {
    for TOOL in wget curl jq sha256sum unzip; do
        if ! command -v $TOOL > /dev/null; then
            install_tool $TOOL
        fi
    done
}

get_latest_version() {
    curl -s "https://api.github.com/repos/$REPO/releases/latest" | jq -r .tag_name | cut -c 2-
}

wget_download() {
    if wget --help 2>&1 | grep -q '\--show-progress'; then
        wget --show-progress "$1" -O "$2"
    else
        wget "$1" -O "$2"
    fi
}

verify_checksum() {
    local file="$1"
    local checksum_url="$2"
    local checksum_file="$TMPDIR/checksum.sha256"
    
    wget_download "$checksum_url" "$checksum_file"
    
    while IFS= read -r line; do
        local expected_checksum=$(echo "$line" | awk '{print $1}')
        local target_file=$(echo "$line" | awk '{print $2}')

        if [[ -e "$target_file" ]]; then
            local computed_checksum=$(sha256sum "$target_file" | awk '{print $1}')
            
            if [[ "$expected_checksum" != "$computed_checksum" ]]; then
                echo "Checksum verification failed for $target_file!"
                exit 1
            fi
        fi
    done < "$checksum_file"
}

install_from_binary() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ZIP_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.zip"
            CHECKSUM_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.zip.sha256"
            EXTRACT_DIR="Linux-binary/phase"
            ;;
        aarch64)
            ZIP_URL="$BASE_URL/v$VERSION/phase_cli_linux_arm64_$VERSION.zip"
            CHECKSUM_URL="$BASE_URL/v$VERSION/phase_cli_linux_arm64_$VERSION.zip.sha256"
            EXTRACT_DIR="Linux-binary-arm64/phase"
            ;;
        *)
            echo "Unsupported architecture: $ARCH. This script supports x86_64 and arm64."
            exit 1
            ;;
    esac

    wget_download "$ZIP_URL" "$TMPDIR/phase_cli_${ARCH}_$VERSION.zip"
    unzip "$TMPDIR/phase_cli_${ARCH}_$VERSION.zip" -d "$TMPDIR"

    BINARY_PATH="$TMPDIR/$EXTRACT_DIR/phase"
    INTERNAL_DIR_PATH="$TMPDIR/$EXTRACT_DIR/_internal"

    verify_checksum "$BINARY_PATH" "$CHECKSUM_URL"
    chmod +x "$BINARY_PATH"

    if [ "$EUID" -eq 0 ]; then
        # Running as root, no need for sudo
        mv "$BINARY_PATH" /usr/local/bin/phase
        mv "$INTERNAL_DIR_PATH" /usr/local/bin/_internal
    elif command -v sudo >/dev/null 2>&1; then
        # Not root, but sudo is available
        echo "This operation requires elevated privileges. Please enter your sudo password if prompted."
        sudo mv "$BINARY_PATH" /usr/local/bin/phase
        sudo mv "$INTERNAL_DIR_PATH" /usr/local/bin/_internal
    else
        echo "Error: This script must be run as root or with sudo privileges."
        exit 1
    fi
}

install_package() {
    ARCH=$(uname -m)
    # For non-Alpine ARM64 systems, fall back to binary installation
    if [ "$ARCH" = "aarch64" ] && [ "$OS" != "alpine" ]; then
        install_from_binary
        echo "phase-cli version $VERSION successfully installed"
        return
    fi

    if [ "$EUID" -ne 0 ] && ! can_install_without_sudo; then
        prompt_sudo
    fi

    case $OS in
        ubuntu|debian)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.deb"
            wget_download $PACKAGE_URL $TMPDIR/phase_cli_linux_amd64_$VERSION.deb
            verify_checksum "$TMPDIR/phase_cli_linux_amd64_$VERSION.deb" "$PACKAGE_URL.sha256"
            if [ "$EUID" -eq 0 ] || can_install_without_sudo; then
                dpkg -i $TMPDIR/phase_cli_linux_amd64_$VERSION.deb
            else
                sudo dpkg -i $TMPDIR/phase_cli_linux_amd64_$VERSION.deb
            fi
            ;;

        fedora|rhel|centos)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.rpm"
            wget_download $PACKAGE_URL $TMPDIR/phase_cli_linux_amd64_$VERSION.rpm
            verify_checksum "$TMPDIR/phase_cli_linux_amd64_$VERSION.rpm" "$PACKAGE_URL.sha256"
            if [ "$EUID" -eq 0 ]; then
                rpm -Uvh $TMPDIR/phase_cli_linux_amd64_$VERSION.rpm
            else
                echo "Installing RPM package. This may require sudo privileges."
                sudo rpm -Uvh $TMPDIR/phase_cli_linux_amd64_$VERSION.rpm
            fi
            ;;

        alpine)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.apk"
            wget_download $PACKAGE_URL $TMPDIR/phase_cli_linux_amd64_$VERSION.apk
            verify_checksum "$TMPDIR/phase_cli_linux_amd64_$VERSION.apk" "$PACKAGE_URL.sha256"
            if [ "$EUID" -eq 0 ] || can_install_without_sudo; then
                apk add --allow-untrusted $TMPDIR/phase_cli_linux_amd64_$VERSION.apk
            else
                sudo apk add --allow-untrusted $TMPDIR/phase_cli_linux_amd64_$VERSION.apk
            fi
            ;;

        *)
            install_from_binary
            ;;
    esac
    echo "phase-cli version $VERSION successfully installed"
}

main() {
    detect_os
    check_required_tools
    TMPDIR=$(mktemp -d)

    # Default to the latest version unless a specific version is requested
    VERSION=$(get_latest_version)

    # Parse command-line arguments
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version)
                VERSION="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done

    install_package
}

main "$@"
