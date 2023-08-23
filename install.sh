#!/bin/bash

set -e

PACKAGE_MIRROR="https://phase-pkg.s3.eu-central-1.amazonaws.com"

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
    for TOOL in sudo wget curl; do
        if ! command -v $TOOL > /dev/null; then
            echo "Installing $TOOL..."
            case $OS in
                ubuntu|debian)
                    apt-get update && sudo apt-get install -y $TOOL
                    ;;
                fedora|rhel|centos)
                    yum install -y $TOOL
                    ;;
                alpine)
                    apk add $TOOL
                    ;;
            esac
        fi
    done
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

wget_download() {
    # Check if wget supports --show-progress
    if wget --help 2>&1 | grep -q '\--show-progress'; then
        wget --show-progress "$1" -O "$2"
    else
        wget "$1" -O "$2"
    fi
}

install_binary() {
    BINARY_URL="$PACKAGE_MIRROR/latest/phase_cli_linux_amd64_latest"
    BINARY="$TMPDIR/phase"

    echo "Downloading phase-cli binary..."
    wget_download $BINARY_URL $BINARY

    echo "Making binary executable..."
    chmod +x $BINARY

    if ! has_sudo_access; then
        echo "Moving binary to /usr/local/bin. Please enter your sudo password or run as root."
    fi
    sudo mv $BINARY /usr/local/bin/phase

    echo "phase-cli installed."
}

install_package() {
    TMPDIR=$(mktemp -d)

    case $OS in
        ubuntu|debian)
            PACKAGE_URL="$PACKAGE_MIRROR/latest/phase_cli_amd64_latest.deb"
            HASH_URL="$PACKAGE_URL.sha512"
            ;;
        fedora|rhel|centos)
            PACKAGE_URL="$PACKAGE_MIRROR/latest/phase_cli_amd64_latest.rpm"
            HASH_URL="$PACKAGE_URL.sha512"
            ;;
        alpine)
            PACKAGE_PATH="$TMPDIR/phase_cli_amd64_latest.apk"
            HASH_PATH="$TMPDIR/hash"
            PACKAGE_URL="$PACKAGE_MIRROR/latest/phase_cli_amd64_latest.apk"
            HASH_URL="$PACKAGE_URL.sha512"
            
            echo "Downloading phase-cli..."
            wget_download $PACKAGE_URL $PACKAGE_PATH
            echo "Getting phase-cli hash..."
            wget_download $HASH_URL $HASH_PATH

            EXPECTED_HASH=$(cut -d ' ' -f 1 $HASH_PATH)

            if ! echo "$EXPECTED_HASH $PACKAGE_PATH" | sha512sum -c -w 2>/dev/null; then
                echo "SHA-512 hash verification failed!"
                exit 1
            else
                echo "SHA-512 hash verification successful."
            fi
            
            sudo apk add --allow-untrusted $PACKAGE_PATH
            ;;
        *)
            install_binary
            exit 0
            ;;
    esac

    # Fetch the version using phase -v
    VERSION=$(phase -v)
    echo "phase-cli version $VERSION successfully installed"
}

main() {
    detect_os
    check_required_tools
    install_package
}

main
