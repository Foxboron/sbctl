# Maintainer: Morten Linderud <foxboron@archlinux.org>

pkgname=sbctl-git
pkgver=r37.g833e3e4
pkgrel=1
pkgdesc="Secure Boot key manager"
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
    export GOFLAGS="-buildmode=pie -trimpath -modcacherw"
    make
}

package(){
    cd "${pkgname%-git}"
    make PROGNM="sbctl-git" PREFIX="$pkgdir/usr" install
    ./sbctl completion bash | install -Dm644 /dev/stdin "$pkgdir/usr/share/bash-completion/completions/sbctl"
    ./sbctl completion zsh | install -Dm644 /dev/stdin "$pkgdir/usr/share/zsh/site-functions/_sbctl"
    ./sbctl completion fish | install -Dm644 /dev/stdin "$pkgdir/usr/share/fish/vendor_completions.d/sbctl.fish"
    install -Dm644 ./contrib/pacman/99-sbctl.hook "${pkgdir}/usr/share/libalpm/hooks/99-sbctl.hook"
}
