# Maintainer: Phase <info@phase.dev>
pkgname=phase
pkgver=1.21.1
pkgrel=0
pkgdesc="Phase CLI"
url="https://phase.dev"
arch="all"
license="GPL-3.0"
depends="python3 py3-pip"
makedepends="python3-dev py3-setuptools py3-pip build-base"
# No need to trace dependencies, pip install is bringing in pre-compiled wheels with binary dependencies that the Alpine package scanner can't properly resolve
options="!check !tracedeps"

build() {
    python3 setup.py build
}

package() {
    python3 setup.py install --prefix=/usr --root="$pkgdir" --skip-build
    pyver=$(python3 -c "import sys; print(f'python{sys.version_info.major}.{sys.version_info.minor}')")
    site_pkg_dir="$pkgdir/usr/lib/$pyver/site-packages"
    vendor_dir="$site_pkg_dir/phase_cli/vendor"
    mkdir -p "$vendor_dir"
    # Install runtime deps into the private vendor dir to avoid conflicts with other packages
    pip3 install --no-cache-dir --target="$vendor_dir" -r requirements.txt
    # Tell Python about that directory
    echo "phase_cli/vendor" > "$site_pkg_dir/phase_cli_vendor.pth"
}
