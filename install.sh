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

    echo "Downloading package..."
    wget $PACKAGE_URL -O package
    echo "Downloading hash..."
    wget $HASH_URL -O hash

    echo "Checking hash..."
    echo "$(cat hash) package" | sha512sum --check

    echo "Installing package..."
    case $OS in
        ubuntu|debian)
            sudo dpkg -i package
            ;;
        fedora|rhel|centos)
            sudo rpm -i package
            ;;
        alpine)
            sudo apk add --allow-untrusted package
            ;;
    esac
}


main() {
    detect_os
    install_package
}

main
