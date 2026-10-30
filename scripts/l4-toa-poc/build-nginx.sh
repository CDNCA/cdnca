#!/bin/sh
# Build the bundled NGINX core with only the stream module, for the PoC.
# /work/src is the output of edge/openresty/native/verify-sources.mjs (the
# signed tarball with the locked chain, which includes 22-cdnca-stream-toa);
# set TOA_PATCH to apply the patch on a tree verified before it was locked.
set -eu
rm -rf /build && mkdir -p /build
cp -a /work/src/bundle/nginx-1.31.1 /build/nginx
cd /build/nginx
if [ -n "${TOA_PATCH:-}" ]; then
	patch -p1 -F 0 --dry-run < "$TOA_PATCH" >/dev/null
	patch -p1 -F 0 < "$TOA_PATCH"
fi
grep -q '"proxy_toa"' src/stream/ngx_stream_proxy_module.c
./configure --prefix=/build/out --without-http --with-stream --with-stream_realip_module \
	--with-compat --with-cc-opt='-O2 -Werror' >/build/configure.log 2>&1
make -j"$(nproc)" >/build/make.log 2>&1
make install >/dev/null
/build/out/sbin/nginx -V 2>&1 | head -1
