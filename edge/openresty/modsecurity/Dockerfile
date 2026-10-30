# Builds the OWASP CRS engine extension (libmodsecurity + ModSecurity-nginx
# --with-compat dynamic module) for the native node runtime. It uses the same
# pinned base image and the same verified, patched OpenResty source as
# edge/openresty/native/Dockerfile (read only, never modified here), so the
# module loads into exactly that nginx. The extension is a separate signed
# artifact (cmd/waf-engine-package); node packages do not contain it.
#
#   docker build -f edge/openresty/modsecurity/Dockerfile --target extension \
#     --output type=local,dest=<dir> .
FROM openresty/openresty@sha256:e260a5b63b78700eb8047e934950a17b4ab3980a77ef254ec486fff8ea4617e6 AS builder
RUN apk add --no-cache build-base linux-headers perl nodejs gnupg patch patchelf curl
COPY edge/openresty/native/verify-sources.mjs edge/openresty/native/sources.lock.json /source-contract/
COPY edge/openresty/native/patches /source-contract/patches
RUN curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    https://openresty.org/download/openresty-1.31.1.1.tar.gz -o /tmp/openresty.tar.gz \
    && node /source-contract/verify-sources.mjs /tmp/openresty.tar.gz /tmp/openresty-source > /source-verification.json
COPY edge/openresty/modsecurity /recipe
# Built at a scratch prefix, then made relocatable: the agent installs every
# version under its own extension directory.
ARG BUILD_PREFIX=/opt/cdnca-waf-crs
# PCRE2 of the exported native runtime (scripts/native-node-export.mjs rewrites
# its ELF rpath to /opt/cdnca-node/current/runtime) and of the image layout.
ARG RUNTIME_RPATH=/opt/cdnca-node/current/runtime/openresty/pcre2/lib:/opt/cdnca-node/current/runtime/lib:/usr/local/openresty/pcre2/lib
RUN sh /recipe/fetch-sources.sh /tmp/modsecurity-src \
    && BUILD_JOBS=4 sh /recipe/build.sh /tmp/modsecurity-src /tmp/openresty-source "${BUILD_PREFIX}" > /build.sha256 \
    && rm -rf "${BUILD_PREFIX}/include" "${BUILD_PREFIX}/lib/libyajl.so" "${BUILD_PREFIX}/lib/libxml2.so" \
      "${BUILD_PREFIX}/lib/libmodsecurity.so" \
    && patchelf --set-rpath "\$ORIGIN/../lib:${RUNTIME_RPATH}" "${BUILD_PREFIX}/modules/ngx_http_modsecurity_module.so" \
    && for library in libmodsecurity.so.3 libxml2.so.16 libyajl.so.2; do \
         patchelf --set-rpath "\$ORIGIN:${RUNTIME_RPATH}" "${BUILD_PREFIX}/lib/${library}"; done \
    && cp /source-verification.json "${BUILD_PREFIX}/source-verification.json" \
    && cp /recipe/sources.lock.json "${BUILD_PREFIX}/sources.lock.json" \
    && /usr/local/openresty/nginx/sbin/nginx -V 2>&1 | head -1 > "${BUILD_PREFIX}/base-image-nginx.txt" \
    && sed -n 's/^#define NGINX_VERSION *"\([0-9.]*\)".*/\1/p' /tmp/openresty-source/bundle/nginx-*/src/core/nginx.h \
      > "${BUILD_PREFIX}/nginx-version.txt"

FROM scratch AS extension
COPY --from=builder /opt/cdnca-waf-crs/ /
