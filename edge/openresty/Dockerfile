# Node container image. OpenResty is the same complete bundle as the native node
# package: the builder stage is edge/openresty/native/Dockerfile's builder (same
# pinned build_base, verify-sources.mjs + sources.lock.json + patches, shared
# build-openresty.sh), and /usr/local/openresty is copied over as a whole.
# tests/edge-openresty-runtime-parity.test.mjs keeps the two in step.
#   OPENRESTY_BUILD_IMAGE  build_base.reference of sources.lock.json (also the
#                          native runtime base).
#   OPENRESTY_IMAGE        runtime base: the official alpine-fat image of the same
#                          OpenResty release (perl for resty, curl and the build
#                          toolchain that the smoke harnesses use); its own
#                          /usr/local/openresty is overwritten by the build.
ARG OPENRESTY_BUILD_IMAGE=openresty/openresty@sha256:e260a5b63b78700eb8047e934950a17b4ab3980a77ef254ec486fff8ea4617e6
ARG OPENRESTY_IMAGE=openresty/openresty@sha256:035818c9596ce60cdc816fc1941db0414d50398644ec9567b45fded04a76e7d0
FROM ${OPENRESTY_BUILD_IMAGE} AS builder
RUN apk add --no-cache build-base linux-headers perl zlib-dev geoip-dev gd-dev libxslt-dev brotli-dev nodejs gnupg patch patchelf curl
COPY edge/openresty/native/verify-sources.mjs edge/openresty/native/sources.lock.json edge/openresty/native/build-openresty.sh /source-contract/
COPY edge/openresty/native/patches /source-contract/patches
# Shared with the native node package (edge/openresty/native/Dockerfile); see build-openresty.sh.
RUN sh /source-contract/build-openresty.sh /source-contract

COPY edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua /source-contract/vendor/ipmatcher.lua
# The firewall action engine matches CIDRs with lua-resty-ipmatcher, which the
# base image does not ship: the same vendored file as the native builder
# (edge/openresty/vendor/lua-resty-ipmatcher, tag v0.6.1 at the commit and
# digest below), checked against the pin here.
ARG IPMATCHER_COMMIT=62d4c44d67227e8f3fe02331c2f8b90fe0d7ccd1
ARG IPMATCHER_SHA256=1c40f52bed3f85964bfa4c2ff686d11ed12643c08caf0addfb74e3996bf6bd0a
RUN set -eux; \
	cp /source-contract/vendor/ipmatcher.lua /tmp/cdnca-ipmatcher.lua; \
	printf '%s  %s\n' "${IPMATCHER_SHA256}" /tmp/cdnca-ipmatcher.lua | sha256sum -c -

# HTTP/3 health probe the Agent runs (openresty.http3_probe): the committed
# client module, built statically by the builder pinned in http3/versions.env.
FROM golang@sha256:895e5feab11a4b3774d24ee3c9579028456b82ad37f42a9eb6f82adaf776a201 AS h3probe
ARG GOPROXY=https://goproxy.cn,direct
ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=readonly GOPROXY=${GOPROXY}
WORKDIR /h3probe-src
COPY edge/openresty/http3/client/client.mod /h3probe-src/go.mod
COPY edge/openresty/http3/client/client.sum /h3probe-src/go.sum
COPY edge/openresty/http3/client/main.go /h3probe-src/main.go
RUN go mod download && go vet ./... && go build -trimpath -ldflags '-s -w -buildid=' -o /out/h3probe . && /out/h3probe version

FROM ${OPENRESTY_IMAGE}

ARG OPENRESTY_BUILD_IMAGE=openresty/openresty@sha256:e260a5b63b78700eb8047e934950a17b4ab3980a77ef254ec486fff8ea4617e6
ARG OPENRESTY_VERSION=1.31.1.1
ARG OPENRESTY_SOURCE_DIGEST=sha256:035818c9596ce60cdc816fc1941db0414d50398644ec9567b45fded04a76e7d0
ARG OPENRESTY_TARBALL_URL=https://openresty.org/download/openresty-1.31.1.1.tar.gz
ARG OPENRESTY_TARBALL_SHA256=65b78baadd3f0984055de89bf13f4a1932e5bfe9c31932037a134ea2b1a0ce42
ARG SOURCE_DATE_EPOCH=1743801795
ARG ENTRYPOINT_BASE64
ARG ENTRYPOINT_SHA256

LABEL org.opencontainers.image.title="CDNCA edge OpenResty runtime" \
      org.opencontainers.image.version="${OPENRESTY_VERSION}" \
      org.opencontainers.image.base.digest="${OPENRESTY_SOURCE_DIGEST}" \
      org.opencontainers.image.source="${OPENRESTY_TARBALL_URL}" \
      io.cdnca.openresty.source.sha256="${OPENRESTY_TARBALL_SHA256}" \
      io.cdnca.openresty.build.base="${OPENRESTY_BUILD_IMAGE}" \
      io.cdnca.openresty.source.lock="edge/openresty/native/sources.lock.json"

# Drop the base image's own OpenResty (and its luarocks) so the tree is exactly
# the native one.
RUN rm -rf /usr/local/openresty
COPY --from=builder /usr/local/openresty /usr/local/openresty
COPY --from=builder --chmod=0444 /source-contract/sources.lock.json /usr/local/share/cdnca/runtime/sources.lock.json
COPY --from=builder --chmod=0444 /source-verification.json /usr/local/share/cdnca/runtime/source-verification.json
COPY --from=builder --chmod=0444 /tmp/cdnca-ipmatcher.lua /usr/local/openresty/site/lualib/resty/ipmatcher.lua
COPY --from=h3probe --chmod=0555 /out/h3probe /usr/local/bin/h3probe

COPY --chmod=0444 edge/openresty/range/guard.lua /usr/local/share/cdnca/range/guard.lua
COPY --chmod=0444 edge/openresty/lua/cdnca_waf.lua /usr/local/share/cdnca/security/cdnca_waf.lua
COPY --chmod=0444 edge/openresty/lua/cdnca_rule_interp.lua /usr/local/share/cdnca/security/cdnca_rule_interp.lua
COPY --chmod=0444 edge/openresty/lua/cdnca_banlist.lua /usr/local/share/cdnca/security/cdnca_banlist.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_site.lua /usr/local/share/cdnca/dynroute/cdnca_site.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_site_admin.lua /usr/local/share/cdnca/dynroute/cdnca_site_admin.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_tls.lua /usr/local/share/cdnca/dynroute/cdnca_tls.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_origin.lua /usr/local/share/cdnca/dynroute/cdnca_origin.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_originauth.lua /usr/local/share/cdnca/dynroute/cdnca_originauth.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_origintls.lua /usr/local/share/cdnca/dynroute/cdnca_origintls.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_cache.lua /usr/local/share/cdnca/dynroute/cdnca_cache.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_security.lua /usr/local/share/cdnca/dynroute/cdnca_security.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_managed_waf.lua /usr/local/share/cdnca/dynroute/cdnca_managed_waf.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_rule_plan.lua /usr/local/share/cdnca/dynroute/cdnca_rule_plan.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_bot.lua /usr/local/share/cdnca/dynroute/cdnca_bot.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_filters.lua /usr/local/share/cdnca/dynroute/cdnca_filters.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_limits.lua /usr/local/share/cdnca/dynroute/cdnca_limits.lua
COPY --chmod=0444 edge/openresty/ccv2/engine.lua /usr/local/share/cdnca/security/cc.lua
COPY --chmod=0444 edge/openresty/httppolicy/engine.lua /usr/local/share/cdnca/httppolicy/engine.lua
COPY --chmod=0444 edge/openresty/firewallaction/engine.lua /usr/local/share/cdnca/firewallaction/engine.lua
COPY --chmod=0444 edge/openresty/siteaccess/engine.lua /usr/local/share/cdnca/siteaccess/engine.lua
COPY --chmod=0444 edge/openresty/ccadaptive/engine.lua /usr/local/share/cdnca/security/cc_adaptive.lua
COPY --chmod=0444 edge/openresty/urlauth/engine.lua /usr/local/share/cdnca/security/url_auth.lua
COPY --chmod=0444 edge/openresty/challenge/engine.lua /usr/local/share/cdnca/challenge/engine.lua
COPY --chmod=0444 edge/openresty/challenge/crypto.lua /usr/local/share/cdnca/challenge/crypto.lua
COPY --chmod=0444 edge/openresty/challenge/ip.lua /usr/local/share/cdnca/challenge/ip.lua
COPY --chmod=0444 edge/openresty/errorpage/handler.lua /usr/local/share/cdnca/errorpage/handler.lua
COPY --chmod=0444 edge/openresty/originauth/engine.lua /usr/local/share/cdnca/originauth/engine.lua
COPY --chmod=0444 edge/openresty/originauth/crypto.lua /usr/local/share/cdnca/originauth/crypto.lua
COPY --chmod=0444 edge/openresty/l4geo/engine.lua /opt/cdnca/l4geo/engine.lua
COPY --chmod=0444 edge/openresty/l4geo/cdnca_l4_geo.lua /opt/cdnca/l4geo/cdnca_l4_geo.lua
COPY --chmod=0444 edge/openresty/iplib/cdnca_iplib.lua /usr/local/share/cdnca/security/cdnca_iplib.lua
COPY --chmod=0444 edge/openresty/iplib/cdnca_iplib.lua /opt/cdnca/l4geo/cdnca_iplib.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_dynroute.lua /usr/local/share/cdnca/dynroute/cdnca_dynroute.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_telemetry.lua /usr/local/share/cdnca/dynroute/cdnca_telemetry.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_webp.lua /usr/local/share/cdnca/dynroute/cdnca_webp.lua
COPY --chmod=0444 edge/openresty/dynroute/cdnca_webp_codec.lua /usr/local/share/cdnca/dynroute/cdnca_webp_codec.lua
COPY --chmod=0444 edge/openresty/sched302/cdnca_sched302.lua /usr/local/share/cdnca/sched302/cdnca_sched302.lua

RUN set -eu; \
	chmod 0555 /usr/local/share/cdnca /usr/local/share/cdnca/runtime /usr/local/share/cdnca/range /usr/local/share/cdnca/security /usr/local/share/cdnca/challenge /usr/local/share/cdnca/httppolicy /usr/local/share/cdnca/firewallaction /usr/local/share/cdnca/siteaccess /usr/local/share/cdnca/errorpage /usr/local/share/cdnca/originauth /usr/local/share/cdnca/dynroute /usr/local/share/cdnca/sched302 /opt/cdnca /opt/cdnca/l4geo; \
	chmod 0555 /usr/local/openresty/site/lualib/resty; \
	printf '%s  %s\n' d528c1309c2bfa0c9c48348185c1966d8a764a67164099cf6a522955667f7fdc /usr/local/share/cdnca/range/guard.lua | sha256sum -c -; \
	 echo '92f3fd132d9a526afaf0264fc537969e6e28498654abc39f908a2e88472ab7f7  /usr/local/share/cdnca/security/cdnca_waf.lua' | sha256sum -c -; \
		echo 'f319da5a0c9ea6cfb977261a8ddca63f57530336d28851dc5fcf80715f1dedb0  /usr/local/share/cdnca/security/cdnca_rule_interp.lua' | sha256sum -c -; \
		echo 'ea49f5bfa9b7945d5af8f521ae4cecd95cca7ef0ea89363afe2e8c5b077e4e8f  /usr/local/share/cdnca/security/cdnca_banlist.lua' | sha256sum -c -; \
		echo '5011685413909ce4b8b2ff010e3d505378d3c9ac6797218afc16118c80b990c0  /usr/local/share/cdnca/dynroute/cdnca_site.lua' | sha256sum -c -; \
		echo 'beba3171b3e53abacc031fe7c73dd7da081dc3e3e4276f1a3034972cd723cebe  /usr/local/share/cdnca/dynroute/cdnca_site_admin.lua' | sha256sum -c -; \
		echo '66bc1559487b74f24cc5219df766ed46987e19785feb9b6cb4eeb8a8250c686f  /usr/local/share/cdnca/dynroute/cdnca_tls.lua' | sha256sum -c -; \
		echo '95b2185b927cdf68e8d83287080d678fafb93f90509899d1276827078684fe58  /usr/local/share/cdnca/dynroute/cdnca_origin.lua' | sha256sum -c -; \
		echo '858e87fffc8c8e246cf50ead9e272f673a97f682031a7e012a533722e3f5dbfd  /usr/local/share/cdnca/security/cc.lua' | sha256sum -c -; \
		echo '3df863a8177361103a0deb58cc1a8291f636f5a85c9d4d47f5613dde4f7171f8  /usr/local/share/cdnca/dynroute/cdnca_originauth.lua' | sha256sum -c -; \
		echo '9c11911356ffe8f11b73c8b4b145ce615094f015543fbed74687cab90cfdbbf2  /usr/local/share/cdnca/dynroute/cdnca_origintls.lua' | sha256sum -c -; \
		echo 'b40f1d01e84ef66c3c89eba411a8af181643f68112d615b5c8c35c3683efd460  /usr/local/share/cdnca/dynroute/cdnca_cache.lua' | sha256sum -c -; \
		echo '04adf8a5105fbeb1741c366cb139ee79907e8c0e527b4726054904d41606e71e  /usr/local/share/cdnca/dynroute/cdnca_security.lua' | sha256sum -c -; \
		echo '8526a9029ec4f0438dd4823cb1ac427ec6c5155d2a73927ec38e902522de0d91  /usr/local/share/cdnca/dynroute/cdnca_managed_waf.lua' | sha256sum -c -; \
		echo '88fa2f83ad725ec7facb984ddd6a58ce3e4c3138d29b37fe76b9e60a2a3412cb  /usr/local/share/cdnca/dynroute/cdnca_rule_plan.lua' | sha256sum -c -; \
		echo '780a3da89e488a77dce21096b6640bb7ac0ebf67bd6675b79519442ad3f83cc6  /usr/local/share/cdnca/dynroute/cdnca_bot.lua' | sha256sum -c -; \
		echo '540096964f040319c36d3ac41e1ac86121c762e6028fbffee3ec3562aafc26e0  /usr/local/share/cdnca/dynroute/cdnca_filters.lua' | sha256sum -c -; \
		echo '7442c3f1803bf8d013eb57c436b76e84a01e6a911f3a54b75fce1b1770baf471  /usr/local/share/cdnca/dynroute/cdnca_limits.lua' | sha256sum -c -; \
		echo '38314497958285c1072e4e1ef7d4c0fbe41e3e03ed148807a008a6cb88e4cb21  /usr/local/share/cdnca/security/cc_adaptive.lua' | sha256sum -c -; \
		echo '93405cdcf5e2a7edef1198cc3e09c6f1584cca6bd351e8561cb1c96c0aaa0bcc  /usr/local/share/cdnca/security/url_auth.lua' | sha256sum -c -; \
		echo '4b9bb65918b71c73b079e008a1c51af84000e3b431f361a0ea49009216090f47  /usr/local/share/cdnca/httppolicy/engine.lua' | sha256sum -c -; \
		echo '111498e20ea67dcf063ce61099367c0f914646776ab12f2df9843e3006896468  /usr/local/share/cdnca/firewallaction/engine.lua' | sha256sum -c -; \
		echo 'd1d4089ff06a88f39f298556cc7acac33ed9a4b1a9295788201ba804bbeaaeaf  /usr/local/share/cdnca/siteaccess/engine.lua' | sha256sum -c -; \
		echo '1c40f52bed3f85964bfa4c2ff686d11ed12643c08caf0addfb74e3996bf6bd0a  /usr/local/openresty/site/lualib/resty/ipmatcher.lua' | sha256sum -c -; \
		su nobody -s /bin/sh -c "/usr/local/openresty/bin/resty -e 'local m = assert(require([[resty.ipmatcher]]).new({ [[192.0.2.0/24]], [[2001:db8::/32]] })); assert(m:match([[192.0.2.9]]) and m:match([[2001:db8::1]]) and not m:match([[198.51.100.1]]))'"; \
		echo 'a6dbe6c1bc19e5732802d2c4e5ea0c9670752a01b57ac0ddd52c93b67d440f31  /usr/local/share/cdnca/challenge/engine.lua' | sha256sum -c -; \
		echo 'f3198f31e12cb5700d78a80ca4f038e97db949e847f3e8d27e228b4263dc0367  /usr/local/share/cdnca/challenge/crypto.lua' | sha256sum -c -; \
		echo '02372567c92ceea47959291959b2381e13836a2011a4819c52805f8f57324631  /usr/local/share/cdnca/challenge/ip.lua' | sha256sum -c -; \
		echo '9925161ff580e70b28ea54139c163a1ee309d4e9baff42c5a008323022a88555  /usr/local/share/cdnca/errorpage/handler.lua' | sha256sum -c -; \
		echo '4a5bd07cdd59f794e623ad439155db118e6998caf3e044bb7d42a668b279f540  /usr/local/share/cdnca/originauth/engine.lua' | sha256sum -c -; \
		echo '412001acc02f72f0cc5fe66216dfe58149776452e46a6fe3140b8dcc421d0b4f  /usr/local/share/cdnca/originauth/crypto.lua' | sha256sum -c -; \
		echo '23060482e83ed151be91e08ca39348ec9d66423143a380e2ffd6afeca6a2ce91  /opt/cdnca/l4geo/engine.lua' | sha256sum -c -; \
		echo '2eca890fb7c2845541cba744cf76b9a2ad880068e3e2f1961377f32ffaa19dad  /opt/cdnca/l4geo/cdnca_l4_geo.lua' | sha256sum -c -; \
		echo 'a50bfda12abcfac7906c405bd8d7eaf81010c29c840ddce2a4459ce453cebe83  /usr/local/share/cdnca/security/cdnca_iplib.lua' | sha256sum -c -; \
		echo 'a50bfda12abcfac7906c405bd8d7eaf81010c29c840ddce2a4459ce453cebe83  /opt/cdnca/l4geo/cdnca_iplib.lua' | sha256sum -c -; \
		echo '8b6fdc87b5f6114e695a175ddeb3743ea3a33e1928ec8cdf965d6c3eb9076e67  /usr/local/share/cdnca/dynroute/cdnca_dynroute.lua' | sha256sum -c -; \
		echo '911e19af52ff52dd71649817ab020fe293b17154b9fd1ec9928a8016dc1a2156  /usr/local/share/cdnca/dynroute/cdnca_telemetry.lua' | sha256sum -c -; \
		echo '8bb4d8252e1d9179024902e3e0718c17f5389306162e0494908fcee7738019ba  /usr/local/share/cdnca/dynroute/cdnca_webp.lua' | sha256sum -c -; \
		echo 'f25d44de9cb6919c7b8928df2a6b25df9c898884648ea3395b5959000351f481  /usr/local/share/cdnca/dynroute/cdnca_webp_codec.lua' | sha256sum -c -; \
		echo 'd5da71ac193e8d904b4aa447bde442bd0ffd3ff316b89ec8908657fb5ed9712e  /usr/local/share/cdnca/sched302/cdnca_sched302.lua' | sha256sum -c -; \
	    printf '%s' "${ENTRYPOINT_BASE64}" | base64 -d > /usr/local/bin/cdnca-openresty-entrypoint; \
    printf '%s  %s\n' "${ENTRYPOINT_SHA256}" /usr/local/bin/cdnca-openresty-entrypoint | sha256sum -c -; \
	    actual_version="$(openresty -V 2>&1 | sed -n 's/^nginx version: openresty\///p')"; \
	    test "${actual_version}" = "${OPENRESTY_VERSION}"; \
	    su nobody -s /bin/sh -c "/usr/local/openresty/bin/resty -e 'local cjson = require([[cjson.safe]]); local function read(path) local f = assert(io.open(path)); local v = assert(cjson.decode(f:read([[*a]]))); f:close(); return v end; local lock = read([[/usr/local/share/cdnca/runtime/sources.lock.json]]); local verified = read([[/usr/local/share/cdnca/runtime/source-verification.json]]); assert(lock.source.version == [[${OPENRESTY_VERSION}]] and lock.source.sha256 == [[${OPENRESTY_TARBALL_SHA256}]] and lock.source.url == [[${OPENRESTY_TARBALL_URL}]] and lock.build_base.reference == [[${OPENRESTY_BUILD_IMAGE}]]); assert(verified.source_sha256 == lock.source.sha256 and verified.patches == #lock.patches)'"; \
	    for flag in --with-stream_realip_module --with-http_v3_module --add-module=/tmp/openresty-source/bundle/cdnca-ja4 --add-module=/tmp/openresty-source/bundle/ngx_brotli; do openresty -V 2>&1 | grep -F -- "${flag}" >/dev/null; done; \
	    printf '%s\n' \
	      'load_module /usr/local/openresty/nginx/modules/ngx_http_geoip_module.so;' \
	      'load_module /usr/local/openresty/nginx/modules/ngx_http_image_filter_module.so;' \
	      'load_module /usr/local/openresty/nginx/modules/ngx_http_xslt_filter_module.so;' \
	      'events {}' 'http { log_format ja4 "$cdnca_ja4"; brotli on; brotli_comp_level $cookie_l; gzip_comp_level $cookie_l; }' \
	      'stream { server { listen 127.0.0.1:9; proxy_toa on; proxy_pass 127.0.0.1:10; } }' > /tmp/cdnca-openresty-module-check.conf; \
	    openresty -t -q -p /usr/local/openresty/nginx/ -c /tmp/cdnca-openresty-module-check.conf; \
	    rm -f /tmp/cdnca-openresty-module-check.conf /usr/local/openresty/nginx/logs/nginx.pid; \
	    chmod 0555 /usr/local/bin/cdnca-openresty-entrypoint; \
    /usr/local/bin/h3probe version | grep -F '"schema":"cdnca.h3probe/v1"' >/dev/null; \
	    touch -d "@${SOURCE_DATE_EPOCH}" /usr/local/openresty/nginx/sbin/nginx; \
	    touch -d "@${SOURCE_DATE_EPOCH}" /usr/local/bin/cdnca-openresty-entrypoint /usr/local/bin/h3probe /usr/local/share/cdnca/range/guard.lua \
	      /usr/local/share/cdnca/security/cdnca_waf.lua /usr/local/share/cdnca/security/cdnca_rule_interp.lua /usr/local/share/cdnca/security/cdnca_banlist.lua /usr/local/share/cdnca/security/cc.lua \
	      /usr/local/share/cdnca/dynroute/cdnca_site.lua /usr/local/share/cdnca/dynroute/cdnca_site_admin.lua /usr/local/share/cdnca/dynroute/cdnca_tls.lua /usr/local/share/cdnca/dynroute/cdnca_origin.lua \
	      /usr/local/share/cdnca/dynroute/cdnca_originauth.lua /usr/local/share/cdnca/dynroute/cdnca_origintls.lua /usr/local/share/cdnca/dynroute/cdnca_cache.lua /usr/local/share/cdnca/dynroute/cdnca_security.lua /usr/local/share/cdnca/dynroute/cdnca_managed_waf.lua /usr/local/share/cdnca/dynroute/cdnca_rule_plan.lua /usr/local/share/cdnca/dynroute/cdnca_bot.lua \
	      /usr/local/share/cdnca/security/cc_adaptive.lua /usr/local/share/cdnca/security/url_auth.lua \
	      /usr/local/share/cdnca/challenge/engine.lua /usr/local/share/cdnca/challenge/crypto.lua \
	      /usr/local/share/cdnca/challenge/ip.lua /usr/local/share/cdnca/httppolicy/engine.lua /usr/local/share/cdnca/firewallaction/engine.lua /usr/local/share/cdnca/siteaccess/engine.lua \
	      /usr/local/share/cdnca/errorpage/handler.lua /usr/local/share/cdnca/originauth/engine.lua /usr/local/share/cdnca/originauth/crypto.lua \
      /usr/local/openresty/site/lualib/resty/ipmatcher.lua \
	      /opt/cdnca/l4geo/engine.lua /opt/cdnca/l4geo/cdnca_l4_geo.lua \
	      /usr/local/share/cdnca/security/cdnca_iplib.lua /opt/cdnca/l4geo/cdnca_iplib.lua /usr/local/share/cdnca/dynroute/cdnca_dynroute.lua /usr/local/share/cdnca/dynroute/cdnca_telemetry.lua /usr/local/share/cdnca/dynroute/cdnca_webp.lua /usr/local/share/cdnca/dynroute/cdnca_webp_codec.lua /usr/local/share/cdnca/sched302/cdnca_sched302.lua \
	      /usr/local/share/cdnca/runtime/sources.lock.json /usr/local/share/cdnca/runtime/source-verification.json

ENV CDNCA_SECURITY_RUNTIME_READY_FILE=/var/run/cdnca/security-runtime.ready

STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
	  CMD test -f "$CDNCA_SECURITY_RUNTIME_READY_FILE" && \
	      printf '%s  %s\n' d528c1309c2bfa0c9c48348185c1966d8a764a67164099cf6a522955667f7fdc /usr/local/share/cdnca/range/guard.lua | sha256sum -c - >/dev/null && \
	      printf '%s  %s\n' 92f3fd132d9a526afaf0264fc537969e6e28498654abc39f908a2e88472ab7f7 /usr/local/share/cdnca/security/cdnca_waf.lua | sha256sum -c - >/dev/null && \
	      printf '%s  %s\n' 858e87fffc8c8e246cf50ead9e272f673a97f682031a7e012a533722e3f5dbfd /usr/local/share/cdnca/security/cc.lua | sha256sum -c - >/dev/null && \
	      grep -F '"cc_api_version":2' "$CDNCA_SECURITY_RUNTIME_READY_FILE" >/dev/null && \
	      printf '%s  %s\n' 38314497958285c1072e4e1ef7d4c0fbe41e3e03ed148807a008a6cb88e4cb21 /usr/local/share/cdnca/security/cc_adaptive.lua | sha256sum -c - >/dev/null && \
		      printf '%s  %s\n' 93405cdcf5e2a7edef1198cc3e09c6f1584cca6bd351e8561cb1c96c0aaa0bcc /usr/local/share/cdnca/security/url_auth.lua | sha256sum -c - >/dev/null && \
	      printf '%s  %s\n' a6dbe6c1bc19e5732802d2c4e5ea0c9670752a01b57ac0ddd52c93b67d440f31 /usr/local/share/cdnca/challenge/engine.lua | sha256sum -c - >/dev/null && \
	      printf '%s  %s\n' f3198f31e12cb5700d78a80ca4f038e97db949e847f3e8d27e228b4263dc0367 /usr/local/share/cdnca/challenge/crypto.lua | sha256sum -c - >/dev/null && \
	      printf '%s  %s\n' 02372567c92ceea47959291959b2381e13836a2011a4819c52805f8f57324631 /usr/local/share/cdnca/challenge/ip.lua | sha256sum -c - >/dev/null && \
	      printf '%s  %s\n' 23060482e83ed151be91e08ca39348ec9d66423143a380e2ffd6afeca6a2ce91 /opt/cdnca/l4geo/engine.lua | sha256sum -c - >/dev/null && \
	      printf '%s  %s\n' 2eca890fb7c2845541cba744cf76b9a2ad880068e3e2f1961377f32ffaa19dad /opt/cdnca/l4geo/cdnca_l4_geo.lua | sha256sum -c - >/dev/null && \
	      test -s /var/lib/cdnca-edge/shared/nginx.pid && kill -0 "$(cat /var/lib/cdnca-edge/shared/nginx.pid)" || exit 1

ENTRYPOINT ["/usr/local/bin/cdnca-openresty-entrypoint"]
