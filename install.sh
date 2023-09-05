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
                    sudo pacman -Sy --noconfirm $TOOL
                    ;;
            esac
        fi
    done
}

get_latest_version() {
    curl -s "https://api.github.com/repos/$REPO/releases/latest" | jq -r .tag_name | cut -c 2- # remove the 'v' prefix
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
    sha256sum -c "$checksum_file" --ignore-missing

    if [[ $? -ne 0 ]]; then
        echo "Checksum verification failed!"
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
            wget_download $PACKAGE_URL $TMPDIR/phase.deb
            verify_checksum "$TMPDIR/phase.deb" "$PACKAGE_URL.sha256"
            sudo dpkg -i $TMPDIR/phase.deb
            ;;

        fedora|rhel|centos)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.rpm"
            wget_download $PACKAGE_URL $TMPDIR/phase.rpm
            verify_checksum "$TMPDIR/phase.rpm" "$PACKAGE_URL.sha256"
            if is_phase_installed; then
                sudo rpm -U $TMPDIR/phase.rpm
            else
                sudo rpm -i $TMPDIR/phase.rpm
            fi
            ;;

        alpine)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_alpine_linux_amd64_$VERSION.apk"
            wget_download $PACKAGE_URL $TMPDIR/phase.apk
            verify_checksum "$TMPDIR/phase.apk" "$PACKAGE_URL.sha256"
            sudo apk add --allow-untrusted $TMPDIR/phase.apk
            ;;

        *)
            if [ "$(uname -m)" == "x86_64" ]; then
                BINARY_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION"
                wget_download $BINARY_URL $TMPDIR/phase
                verify_checksum "$TMPDIR/phase" "$BINARY_URL.sha256"
                chmod +x $TMPDIR/phase
                if ! has_sudo_access; then
                    echo "Moving binary to /usr/local/bin. Please enter your sudo password or run as root."
                fi
                sudo mv $TMPDIR/phase /usr/local/bin/
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
