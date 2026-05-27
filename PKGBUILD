# local development PKGBUILD - not intended for package repositories

options=(!strip debug)

pkgname=zpicotls
pkgver=1.3
pkgrel=1
pkgdesc='zpicotls'
url='https://github.com/kaldron-labs/zpicotls'
license=('MIT')
arch=('x86_64')
depends=('openssl' 'brotli')
makedepends=('cmake' 'git' 'pkgconf')
_cmake_prefix=/usr
if [[ -n ${MINGW_PACKAGE_PREFIX} ]]; then
    depends=("${MINGW_PACKAGE_PREFIX}-openssl" "${MINGW_PACKAGE_PREFIX}-brotli")
    makedepends=("${MINGW_PACKAGE_PREFIX}-cmake" "${MINGW_PACKAGE_PREFIX}-pkgconf" 'git')
    _cmake_prefix="${MINGW_PREFIX}"
fi

prepare() {
    cd "$startdir"
    git submodule update --init --recursive
}

build() {
    cd "$startdir"
    cmake -S . -B build \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON \
        -DCMAKE_INSTALL_PREFIX="${_cmake_prefix}" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_INSTALL_RPATH=
    cmake --build build
}

package() {
    cd "$startdir"
    DESTDIR="$pkgdir" cmake --install build
}
