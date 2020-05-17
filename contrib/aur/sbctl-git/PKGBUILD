# Maintainer: Morten Linderud <foxboron@archlinux.org>

pkgname=sbctl-git
pkgver=r10.gb7504de
pkgrel=1
pkgdesc="💻 Secure Boot key manager"
arch=("x86_64")
url="https://github.com/Foxboron/sbctl"
license=("MIT")
depends=("sbsigntools")
makedepends=("go" "git" "asciidoc")
source=("git+https://github.com/Foxboron/sbctl.git?signed")
validpgpkeys=("C100346676634E80C940FB9E9C02FF419FECBE16")
sha256sums=('SKIP')

pkgver() {
    cd "${pkgname%-git}"
    printf 'r%s.g%s' "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build(){
    cd "${pkgname%-git}"
    export CGO_LDFLAGS="${LDFLAGS}"
    export CGO_CFLAGS="${CFLAGS}"
    export CGO_CPPFLAGS="${CPPFLAGS}"
    export CGO_CXXFLAGS="${CXXFLAGS}"
    export GOFLAGS="-buildmode=pie -trimpath -mod=readonly -modcacherw"
    make
}

package(){
    cd "${pkgname%-git}"
    make PREFIX="$pkgdir/usr" install
}
