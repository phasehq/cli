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
            PACKAGE_URL="$PACKAGE_MIRROR/latest/phase_cli_amd64_latest.apk"
            HASH_URL="$PACKAGE_URL.sha512"
            ;;
        *)
            echo "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    PACKAGE="$TMPDIR/package"
    HASH="$TMPDIR/hash"

    echo "Downloading package..."
    wget $PACKAGE_URL -O $PACKAGE
    echo "Downloading hash..."
    wget $HASH_URL -O $HASH

    echo "Checking hash..."
    cd $TMPDIR
    sha512sum --check $HASH

    echo "Installing package..."
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
}

main() {
    detect_os
    install_package
}

main
