# Maintainer: Phase <info@phase.dev>
pkgname=phase
pkgver=1.17.5
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
    cd "$startdir"
    
    # Install the executable
    install -Dm755 phase "$pkgdir/usr/bin/phase"
    
    # Copy the _internal directory
    cp -r _internal "$pkgdir/usr/bin/"
}
