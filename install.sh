#!/bin/bash

set -e

REPO="https://github.com/phasehq/cli"
PACKAGE_MIRROR="https://phasehq.github.io/cli/latest"

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
            PACKAGE_URL="$PACKAGE_MIRROR/deb/latest.deb"
            HASH_URL="$PACKAGE_URL.sha512"
            ;;
        fedora|rhel|centos)
            PACKAGE_URL="$PACKAGE_MIRROR/rpm/latest.rpm"
            HASH_URL="$PACKAGE_URL.sha512"
            ;;
        alpine)
            PACKAGE_URL="$PACKAGE_MIRROR/apk/latest.apk"
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
