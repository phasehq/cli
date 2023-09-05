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
    for TOOL in sudo wget curl jq; do
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

install_package() {
    VERSION=$(get_latest_version)
    TMPDIR=$(mktemp -d)

    case $OS in
        ubuntu|debian)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.deb"
            wget_download $PACKAGE_URL $TMPDIR/phase.deb
            sudo dpkg -i $TMPDIR/phase.deb
            ;;

        fedora|rhel|centos)
            PACKAGE_URL="$BASE_URL/v$VERSION/phase_cli_linux_amd64_$VERSION.rpm"
            wget_download $PACKAGE_URL $TMPDIR/phase.rpm
            if is_phase_installed; then
                sudo rpm -U $TMPDIR/phase.rpm
            else
                sudo rpm -i $TMPDIR/phase.rpm
            fi
            ;;

        alpine)
            BINARY_URL="$BASE_URL/v$VERSION/phase_cli_alpine_linux_amd64_$VERSION"
            wget_download $BINARY_URL $TMPDIR/phase
            chmod +x $TMPDIR/phase
            if ! has_sudo_access; then
                echo "Moving binary to /usr/local/bin. Please enter your sudo password or run as root."
            fi
            sudo mv $TMPDIR/phase /usr/local/bin/
            ;;

        *)
            echo "Unsupported OS type."
            exit 1
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
