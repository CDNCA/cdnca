#!/bin/sh
# Builds the OWASP CRS engine extension: libmodsecurity v3 + the
# ModSecurity-nginx dynamic module (--with-compat) against the OpenResty build
# environment this script runs in (an openresty/openresty Alpine image that
# ships gcc/g++ and /usr/local/openresty/pcre2).
#
#   build.sh <source-dir> <openresty-tarball | nginx-source-dir> <out-prefix>
#
# <source-dir> holds the tarballs named in sources.lock.json; every tarball is
# checked against its pinned sha256 before use. The second argument is either
# a pinned OpenResty tarball or an already verified (and patched) nginx source
# tree; the module is built from exactly that nginx so it loads into it.
# The result is installed below <out-prefix> (the node installs the extension
# at the same absolute path; rpath points at <out-prefix>/lib):
#   lib/libmodsecurity.so.3, lib/libyajl.so.2, lib/libxml2.so.16,
#   lib/libstdc++.so.6, lib/libgcc_s.so.1, modules/ngx_http_modsecurity_module.so,
#   unicode.mapping, LICENSE.*
# ModSecurity-nginx carries the CDNCA patches of sources.lock.json "patches"
# ($modsecurity_rule_ids, waf-gap6). The extension carries no rule text: OWASP CRS arrives with the signed system
# rule catalog. Paths and timestamps are fixed (SOURCE_DATE_EPOCH,
# -ffile-prefix-map, deterministic ar) for byte-identical rebuilds.
set -eu

src="$1"
nginx_input="$2"
prefix="$3"
here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
lock="${here}/sources.lock.json"
work=/tmp/cdnca-modsecurity-build
jobs="${BUILD_JOBS:-4}"

lock_value() { # source field
  sed -n "/\"$1\": {/,/}/p" "${lock}" | sed -n "s/.*\"$2\": \"\\([^\"]*\\)\".*/\\1/p" | head -1
}
verified() { # source -> path
  file="$(lock_value "$1" file)"
  sum="$(lock_value "$1" sha256)"
  [ -n "${file}" ] && [ -n "${sum}" ] || { echo "sources.lock.json: missing $1" >&2; exit 1; }
  printf '%s  %s\n' "${sum}" "${src}/${file}" | sha256sum -c - >/dev/null || {
    echo "sha256 mismatch: ${src}/${file}" >&2; exit 1; }
  printf '%s\n' "${src}/${file}"
}

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1760486400}"
export TZ=UTC LC_ALL=C ZERO_AR_DATE=1 ARFLAGS=crD
repro="-ffile-prefix-map=${work}=/build -fdebug-prefix-map=${work}=/build -g0 -O2 -fPIC"
export CFLAGS="${repro}" CXXFLAGS="${repro}"
rm -rf "${work}"
mkdir -p "${work}/bin" "${prefix}/lib" "${prefix}/include" "${prefix}/modules"
# No network packages: a pkg-config that knows no packages makes configure use
# the explicit --with-<lib>=PATH locations below.
printf '%s\n' '#!/bin/sh' 'case "$1" in --version) echo 0.29.2;; --atleast-pkgconfig-version*) exit 0;; *) exit 1;; esac' \
  >"${work}/bin/pkg-config"
chmod 0755 "${work}/bin/pkg-config"
export PATH="${work}/bin:${PATH}"

# yajl 2.1.0 (JSON request bodies). Built directly from its eight C files; the
# upstream CMake only adds a generated version header.
tar -xzf "$(verified yajl)" -C "${work}"
yajl="${work}/yajl-2.1.0"
mkdir -p "${yajl}/out/include/yajl"
cp "${yajl}"/src/api/yajl_common.h "${yajl}"/src/api/yajl_gen.h "${yajl}"/src/api/yajl_parse.h \
  "${yajl}"/src/api/yajl_tree.h "${yajl}/out/include/yajl/"
sed -e 's/${YAJL_MAJOR}/2/' -e 's/${YAJL_MINOR}/1/' -e 's/${YAJL_MICRO}/0/' \
  "${yajl}/src/api/yajl_version.h.cmake" >"${yajl}/out/include/yajl/yajl_version.h"
(cd "${yajl}/src" && gcc ${CFLAGS} -std=c99 -DYAJL_BUILD -I"${yajl}/out/include" -shared \
  -Wl,-soname,libyajl.so.2 -Wl,--build-id=none -o "${prefix}/lib/libyajl.so.2" \
  yajl.c yajl_alloc.c yajl_buf.c yajl_encode.c yajl_gen.c yajl_lex.c yajl_parser.c yajl_tree.c yajl_version.c)
ln -sf libyajl.so.2 "${prefix}/lib/libyajl.so"
cp -R "${yajl}/out/include/yajl" "${prefix}/include/"

# libxml2 2.15.4 (XML / SOAP request bodies, CRS XML:/* targets): parser and
# XPath only; no network, catalog, Python, zlib, lzma or ICU.
tar -xJf "$(verified libxml2)" -C "${work}"
cd "${work}/libxml2-2.15.4"
./configure --prefix="${prefix}" --disable-static --enable-shared --disable-dependency-tracking \
  --without-python --without-docs --without-catalog --without-debug --without-http --without-modules \
  --without-zlib --without-icu --without-readline --without-history --without-schematron \
  LDFLAGS="-Wl,--build-id=none" >"${work}/libxml2-configure.log"
make -j"${jobs}" libxml2.la >"${work}/libxml2-make.log"
make install-libLTLIBRARIES >"${work}/libxml2-install.log"
make -C include install >>"${work}/libxml2-install.log"
# libmodsecurity looks for <prefix>/include/libxml/parser.h
ln -sfn libxml2/libxml "${prefix}/include/libxml"

# libmodsecurity: PCRE2 from OpenResty, yajl and libxml2 above, every optional
# network / database / scripting dependency off (SecRemoteRules, Lua, GeoIP,
# LMDB stay unavailable on the node by construction).
tar -xzf "$(verified libmodsecurity)" -C "${work}"
cd "${work}/modsecurity-v3.0.17"
./configure --prefix="${prefix}" --disable-static --enable-shared --disable-examples \
  --disable-doxygen-doc --disable-dependency-tracking --disable-debug-logs \
  --with-pcre2=/usr/local/openresty/pcre2 --with-yajl="${prefix}" \
  --without-curl --without-lua --without-lmdb --without-geoip --without-maxmind \
  --without-ssdeep --with-libxml="${prefix}" \
  LDFLAGS="-Wl,--build-id=none -Wl,-rpath,${prefix}/lib:/usr/local/openresty/pcre2/lib" >"${work}/configure.log"
# Only the library (others/ = bundled libinjection + mbedtls, src/); the
# upstream tools and test suites are not part of the node runtime.
make -C others -j"${jobs}" >"${work}/make.log"
make -C src -j"${jobs}" >>"${work}/make.log"
make -C src install >"${work}/install.log"
rm -f "${prefix}"/lib/*.la "${prefix}"/lib/libmodsecurity.so "${prefix}/lib/libmodsecurity.so.3"
real="$(ls "${prefix}"/lib/libmodsecurity.so.3.* | head -1)"
mv "${real}" "${prefix}/lib/libmodsecurity.so.3"
ln -sf libmodsecurity.so.3 "${prefix}/lib/libmodsecurity.so"
rm -rf "${prefix}/bin" "${prefix}/lib/pkgconfig" "${prefix}/lib/cmake" "${prefix}/share"
real="$(ls "${prefix}"/lib/libxml2.so.*.* | head -1)"
mv "${real}" "${prefix}/lib/libxml2.so.16"
rm -f "${prefix}"/lib/libxml2.so.16.* "${prefix}/lib/libxml2.la"
ln -sf libxml2.so.16 "${prefix}/lib/libxml2.so"
# The runtime image may not carry the C++ runtime; ship the exact builder copy.
for runtime in libstdc++.so.6 libgcc_s.so.1; do
  cp -L "/usr/lib/${runtime}" "${prefix}/lib/${runtime}"
done

# ModSecurity-nginx as a --with-compat dynamic module for the bundled nginx,
# with the CDNCA patches of sources.lock.json "patches" (pinned sha256,
# applied exactly: no fuzz).
tar -xzf "$(verified modsecurity_nginx)" -C "${work}"
for patch_file in $(sed -n 's/.*"file": "\(patches\/[^"]*\)".*/\1/p' "${lock}"); do
  patch_sum="$(sed -n "/\"file\": \"$(printf '%s' "${patch_file}" | sed 's/[\/.]/\\&/g')\"/,/}/p" "${lock}" | sed -n 's/.*"sha256": "\([^"]*\)".*/\1/p' | head -1)"
  printf '%s  %s\n' "${patch_sum}" "${here}/${patch_file}" | sha256sum -c - >/dev/null || {
    echo "sha256 mismatch: ${patch_file}" >&2; exit 1; }
  patch -p1 -F0 -N -d "${work}/ModSecurity-nginx-v1.0.4" <"${here}/${patch_file}" >"${work}/patch.log"
done
if [ -d "${nginx_input}" ]; then
  nginx_src="$(ls -d "${nginx_input}"/bundle/nginx-* 2>/dev/null | head -1)"
  [ -n "${nginx_src}" ] || nginx_src="${nginx_input}"
  cp -R "${nginx_src}" "${work}/nginx-src"
  nginx_src="${work}/nginx-src"
else
  tar -xzf "${nginx_input}" -C "${work}"
  nginx_src="$(ls -d "${work}"/openresty-*/bundle/nginx-* | head -1)"
fi
[ -f "${nginx_src}/src/core/nginx.h" ] || { echo "no nginx source in ${nginx_input}" >&2; exit 1; }
cd "${nginx_src}"
MODSECURITY_INC="${prefix}/include" MODSECURITY_LIB="${prefix}/lib" ./configure --with-compat \
  --with-cc-opt="${repro} -I/usr/local/openresty/pcre2/include" \
  --with-ld-opt="-L/usr/local/openresty/pcre2/lib -Wl,--build-id=none -Wl,-rpath,${prefix}/lib" \
  --without-http_gzip_module \
  --add-dynamic-module="${work}/ModSecurity-nginx-v1.0.4" >"${work}/nginx-configure.log"
make -j"${jobs}" modules >"${work}/nginx-make.log"
install -m 0555 objs/ngx_http_modsecurity_module.so "${prefix}/modules/ngx_http_modsecurity_module.so"
strip --strip-unneeded "${prefix}/modules/ngx_http_modsecurity_module.so" "${prefix}/lib/libmodsecurity.so.3" \
  "${prefix}/lib/libyajl.so.2" "${prefix}/lib/libxml2.so.16"
chmod 0444 "${prefix}"/lib/*.so.* 2>/dev/null || true

install -m 0444 "${work}/modsecurity-v3.0.17/LICENSE" "${prefix}/LICENSE.libmodsecurity"
install -m 0444 "${work}/modsecurity-v3.0.17/unicode.mapping" "${prefix}/unicode.mapping"
install -m 0444 "${work}/libxml2-2.15.4/Copyright" "${prefix}/LICENSE.libxml2"
install -m 0444 "${work}/yajl-2.1.0/COPYING" "${prefix}/LICENSE.yajl"
cd /
rm -rf "${work}"
find "${prefix}" -type f | LC_ALL=C sort | xargs sha256sum
