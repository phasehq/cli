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

check_required_tools() {
    for TOOL in sudo wget curl jq sha256sum unzip; do
        if ! command -v $TOOL > /dev/null; then
            echo "Installing $TOOL..."
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

has_sudo_access() {
    if sudo -n true 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

install_from_binary() {
    ZIP_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.zip"
    CHECKSUM_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.sha256"
    
    wget_download $ZIP_URL $TMPDIR/phase_cli_linux_amd64_$VERSION.zip
    
    unzip $TMPDIR/phase_cli_linux_amd64_$VERSION.zip -d $TMPDIR
    
    BINARY_PATH="$TMPDIR/Linux-binary/phase/phase"
    INTERNAL_DIR_PATH="$TMPDIR/Linux-binary/phase/_internal"
    
    verify_checksum "$BINARY_PATH" "$CHECKSUM_URL"
    
    chmod +x $BINARY_PATH
    
    if ! has_sudo_access; then
        echo "Moving items to /usr/local/bin. Please enter your sudo password or run as root."
    fi

    sudo mv $BINARY_PATH /usr/local/bin/phase
    sudo mv $INTERNAL_DIR_PATH /usr/local/bin/_internal
}

install_package() {
    case $OS in
        ubuntu|debian)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.deb"
            wget_download $PACKAGE_URL $TMPDIR/phase_cli_linux_amd64_$VERSION.deb
            verify_checksum "$TMPDIR/phase_cli_linux_amd64_$VERSION.deb" "$PACKAGE_URL.sha256"
            sudo dpkg -i $TMPDIR/phase_cli_linux_amd64_$VERSION.deb
            ;;

        fedora|rhel|centos)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.rpm"
            wget_download $PACKAGE_URL $TMPDIR/phase_cli_linux_amd64_$VERSION.rpm
            verify_checksum "$TMPDIR/phase_cli_linux_amd64_$VERSION.rpm" "$PACKAGE_URL.sha256"
            sudo rpm -U $TMPDIR/phase_cli_linux_amd64_$VERSION.rpm
            ;;

        alpine)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.apk"
            wget_download $PACKAGE_URL $TMPDIR/phase_cli_linux_amd64_$VERSION.apk
            verify_checksum "$TMPDIR/phase_cli_linux_amd64_$VERSION.apk" "$PACKAGE_URL.sha256"
            sudo apk add --allow-untrusted $TMPDIR/phase_cli_linux_amd64_$VERSION.apk
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
