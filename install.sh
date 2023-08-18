#!/bin/bash

set -e

PACKAGE_MIRROR="https://pkg.phase.dev"

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo "Can't detect OS type."
        exit 1
    fi
}

install_binary() {
    BINARY_URL="$PACKAGE_MIRROR/latest/phase_cli_linux_amd64_latest"
    BINARY="$TMPDIR/phase"

    echo "Downloading phase-cli binary..."
    wget $BINARY_URL -O $BINARY

    echo "Making binary executable..."
    chmod +x $BINARY

    echo "Moving binary to /usr/local/bin. Please enter your sudo password or run as root."
    sudo mv $BINARY /usr/local/bin/phase

    echo "phase-cli installed."
}

install_package() {
    TMPDIR=$(mktemp -d)

    case $OS in
        ubuntu|debian)
            PACKAGE_URL="$PACKAGE_MIRROR/latest/phase_cli_amd64_latest.deb"
            HASH_URL="$PACKAGE_URL.sha512"
            PACKAGE_MANAGER="dpkg"
            ;;
        fedora|rhel|centos)
            PACKAGE_URL="$PACKAGE_MIRROR/latest/phase_cli_amd64_latest.rpm"
            HASH_URL="$PACKAGE_URL.sha512"
            PACKAGE_MANAGER="rpm"
            ;;
        alpine)
            PACKAGE_URL="$PACKAGE_MIRROR/latest/phase_cli_amd64_latest.apk"
            HASH_URL="$PACKAGE_URL.sha512"
            PACKAGE_MANAGER="apk"
            ;;
        *)
            install_binary
            exit 0
            ;;
    esac

    PACKAGE="$TMPDIR/package"
    HASH="$TMPDIR/hash"

    echo "Downloading phase-cli package..."
    wget $PACKAGE_URL -O $PACKAGE
    echo "Downloading phase-cli package hash..."
    wget $HASH_URL -O $HASH

    EXPECTED_HASH=$(cut -d ' ' -f 1 $HASH)

    echo "Verifying SHA512 hash"
    echo "$EXPECTED_HASH $PACKAGE" | sha512sum --check

    echo "Installing package using $PACKAGE_MANAGER..."
    echo "Please enter your sudo password."
    case $OS in
        ubuntu|debian)
            sudo dpkg -i $PACKAGE
            ;;
        fedora|rhel|centos)
            sudo rpm -i $PACKAGE
            ;;
        alpine)
            sudo apk add --allow-untrusted $PACKAGE
            ;;
    esac

    echo "Phase package installed."
}

main() {
    detect_os
    install_package
}

main
