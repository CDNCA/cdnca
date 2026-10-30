#!/bin/sh
# The one OpenResty build recipe for the native node package
# (edge/openresty/native/Dockerfile) and the container image
# (edge/openresty/Dockerfile): download the locked tarball, verify signature and
# the ordered patch chain (verify-sources.mjs + sources.lock.json), then build and
# install the complete bundle (NGINX, LuaJIT, Lua/C modules, dynamic modules) to
# /usr/local/openresty. Run in the pinned build_base image with the build
# dependencies installed. Writes the verification result to /source-verification.json.
#   usage: sh build-openresty.sh SOURCE_CONTRACT_DIR
set -eu
contract=$1
source_url=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).source.url)' "${contract}/sources.lock.json")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  "${source_url}" -o /tmp/openresty.tar.gz
node "${contract}/verify-sources.mjs" /tmp/openresty.tar.gz /tmp/openresty-source > /source-verification.json
cd /tmp/openresty-source
./configure -j4 \
  --with-pcre \
  --with-cc-opt='-DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include' \
  --with-ld-opt='-L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -Wl,-rpath,/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib' \
  --with-compat --without-http_rds_json_module --without-http_rds_csv_module --without-lua_rds_parser \
  --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module \
  --with-http_addition_module --with-http_auth_request_module --with-http_dav_module \
  --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module \
  --with-http_mp4_module --with-http_random_index_module --with-http_realip_module \
  --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module \
  --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-http_v3_module \
  --with-http_geoip_module=dynamic --with-http_image_filter_module=dynamic --with-http_xslt_module=dynamic \
  --with-mail --with-mail_ssl_module --with-stream --with-stream_ssl_module \
  --with-stream_ssl_preread_module --with-stream_realip_module --with-threads \
  --with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT' --with-pcre-jit \
  --add-module=/tmp/openresty-source/bundle/cdnca-ja4 \
  --add-module=/tmp/openresty-source/bundle/ngx_brotli
make -j4
make install
