# Maintainer: Phase <info@phase.dev>
pkgname=phase
pkgver=1.8.0
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

    # Create the directory structure for the CLI
    mkdir -p "$pkgdir/usr/bin/"
    mkdir -p "$pkgdir/usr/lib/phase/"

    # Copy the main executable to /usr/bin
    install -Dm755 phase/phase "$pkgdir/usr/bin/phase"
    
    # Copy all other dependencies to /usr/lib/phase
    cp -R phase/* "$pkgdir/usr/lib/phase/"
    
    # Remove the main executable from /usr/lib/phase to avoid duplication
    rm "$pkgdir/usr/lib/phase/phase"
}
