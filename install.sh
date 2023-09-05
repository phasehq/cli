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
    for TOOL in sudo wget curl jq sha256sum; do
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

        # Check if the target file exists
        if [[ -e "$target_file" ]]; then
            # Compute the checksum
            local computed_checksum=$(sha256sum "$target_file" | awk '{print $1}')
            
            # Verify the checksum
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

is_phase_installed() {
    if command -v phase > /dev/null; then
        return 0
    else
        return 1
    fi
}

is_phase_installed_via_pip() {
    if pip list 2>/dev/null | grep -q phase-cli || pip3 list 2>/dev/null | grep -q phase-cli; then
        return 0
    else
        return 1
    fi
}

install_package() {
    if is_phase_installed_via_pip; then
        echo "phase-cli is already installed via pip. Please upgrade using pip."
        exit 0
    fi

    VERSION=$(get_latest_version)
    TMPDIR=$(mktemp -d)

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
            if is_phase_installed; then
                sudo rpm -U $TMPDIR/phase_cli_linux_amd64_$VERSION.rpm
            else
                sudo rpm -i $TMPDIR/phase_cli_linux_amd64_$VERSION.rpm
            fi
            ;;

        alpine)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.apk"
            wget_download $PACKAGE_URL $TMPDIR/phase_cli_linux_amd64_$VERSION.apk
            verify_checksum "$TMPDIR/phase_cli_linux_amd64_$VERSION.apk" "$PACKAGE_URL.sha256"
            sudo apk add --allow-untrusted $TMPDIR/phase_cli_linux_amd64_$VERSION.apk
            ;;

        *)
            if [ "$(uname -m)" == "x86_64" ]; then
                BINARY_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION"
                wget_download $BINARY_URL $TMPDIR/phase_cli_linux_amd64_$VERSION
                verify_checksum "$TMPDIR/phase_cli_linux_amd64_$VERSION" "$BINARY_URL.sha256"
                chmod +x $TMPDIR/phase_cli_linux_amd64_$VERSION
                if ! has_sudo_access; then
                    echo "Moving binary to /usr/local/bin. Please enter your sudo password or run as root."
                fi
                sudo mv $TMPDIR/phase_cli_linux_amd64_$VERSION /usr/local/bin/phase
            else
                echo "Unsupported OS type and architecture."
                exit 1
            fi
            ;;
    esac

    echo "phase-cli version $VERSION successfully installed"
}

main() {
    detect_os
    check_required_tools
    install_package
}

main
