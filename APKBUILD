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
options="!check"

build() {
    python3 setup.py build
}

package() {
    python3 setup.py install --prefix=/usr --root="$pkgdir" --skip-build
    pip3 install --target="$pkgdir/usr/lib/python3.11/site-packages" -r requirements.txt
}
