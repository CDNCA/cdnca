#!/bin/sh
# Build the full OpenResty (LuaJIT, stream, ssl_preread, realip) from the
# verified, patched source tree at /work/src (verify-sources.mjs output,
# which includes the cdnca-stream-toa patch) into /usr/local/openresty.
set -eu
export DEBIAN_FRONTEND=noninteractive
command -v cc >/dev/null 2>&1 || {
	apt-get update -qq >/dev/null
	apt-get install -y -qq --no-install-recommends build-essential perl libpcre2-dev libssl-dev zlib1g-dev \
		clang llvm libbpf-dev bpftool tcpdump iproute2 python3 ca-certificates >/dev/null
}
rm -rf /build && cp -a /work/src /build
cd /build
grep -q '"proxy_toa"' bundle/nginx-1.31.1/src/stream/ngx_stream_proxy_module.c
./configure --prefix=/usr/local/openresty --with-pcre --with-compat \
	--with-stream --with-stream_ssl_module --with-stream_ssl_preread_module --with-stream_realip_module \
	--without-http_rds_json_module --without-http_rds_csv_module --without-lua_rds_parser \
	--without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module \
	-j"$(nproc)" >/build/configure.log 2>&1
make -j"$(nproc)" >/build/make.log 2>&1
make install >/dev/null
/usr/local/openresty/bin/openresty -V 2>&1 | head -1
