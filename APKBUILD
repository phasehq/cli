# Maintainer: Phase <info@phase.dev>
pkgname=phase
pkgver=1.19.2
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
    pip3 install --target="$pkgdir/usr/lib/$pyver/site-packages" -r requirements.txt
}
