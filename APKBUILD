# Maintainer: Phase <info@phase.dev>
pkgname=phase
pkgver=1.3.1
pkgrel=0
pkgdesc="Phase CLI"
url="https://phase.dev"
arch="all"
license="GPL-3.0"
depends=""
makedepends="python3"
install=""
subpackages=""
source="phase"

# Verify the source with sha256sums
# You can generate it with 'sha256sum'
sha256sums="SKIP"

package() {
    cd "$srcdir"
    install -Dm755 phase "$pkgdir/usr/bin/phase"
}
