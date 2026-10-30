FROM openresty/openresty@sha256:e260a5b63b78700eb8047e934950a17b4ab3980a77ef254ec486fff8ea4617e6 AS builder
RUN apk add --no-cache build-base linux-headers perl zlib-dev geoip-dev gd-dev libxslt-dev brotli-dev nodejs gnupg patch patchelf curl
COPY edge/openresty/native/verify-sources.mjs edge/openresty/native/sources.lock.json edge/openresty/native/build-openresty.sh /source-contract/
COPY edge/openresty/native/patches /source-contract/patches
# Shared with the container image (edge/openresty/Dockerfile); see build-openresty.sh.
RUN sh /source-contract/build-openresty.sh /source-contract
# The firewall action engine needs resty.ipmatcher: the container image
# downloads the same pinned file, the native build is offline (vendored). In
# the source contract, so the exporter records it among the build inputs.
# After the OpenResty build: changing it does not rebuild OpenResty.
COPY edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua /source-contract/vendor/ipmatcher.lua

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

FROM openresty/openresty@sha256:e260a5b63b78700eb8047e934950a17b4ab3980a77ef254ec486fff8ea4617e6 AS runtime
COPY --from=builder /usr/local/openresty /usr/local/openresty
COPY --from=builder /source-contract/vendor/ipmatcher.lua /usr/local/openresty/lualib/resty/ipmatcher.lua
COPY edge/openresty/range/guard.lua /usr/local/share/cdnca/range/guard.lua
COPY edge/openresty/lua/cdnca_waf.lua /usr/local/share/cdnca/security/cdnca_waf.lua
COPY edge/openresty/lua/cdnca_rule_interp.lua /usr/local/share/cdnca/security/cdnca_rule_interp.lua
COPY edge/openresty/lua/cdnca_banlist.lua /usr/local/share/cdnca/security/cdnca_banlist.lua
COPY edge/openresty/dynroute/cdnca_site.lua /usr/local/share/cdnca/dynroute/cdnca_site.lua
COPY edge/openresty/dynroute/cdnca_site_admin.lua /usr/local/share/cdnca/dynroute/cdnca_site_admin.lua
COPY edge/openresty/dynroute/cdnca_tls.lua /usr/local/share/cdnca/dynroute/cdnca_tls.lua
COPY edge/openresty/dynroute/cdnca_origin.lua /usr/local/share/cdnca/dynroute/cdnca_origin.lua
COPY edge/openresty/dynroute/cdnca_originauth.lua /usr/local/share/cdnca/dynroute/cdnca_originauth.lua
COPY edge/openresty/dynroute/cdnca_origintls.lua /usr/local/share/cdnca/dynroute/cdnca_origintls.lua
COPY edge/openresty/dynroute/cdnca_cache.lua /usr/local/share/cdnca/dynroute/cdnca_cache.lua
COPY edge/openresty/dynroute/cdnca_filters.lua /usr/local/share/cdnca/dynroute/cdnca_filters.lua
COPY edge/openresty/dynroute/cdnca_limits.lua /usr/local/share/cdnca/dynroute/cdnca_limits.lua
COPY edge/openresty/ccv2/engine.lua /usr/local/share/cdnca/security/cc.lua
COPY edge/openresty/httppolicy/engine.lua /usr/local/share/cdnca/httppolicy/engine.lua
COPY edge/openresty/firewallaction/engine.lua /usr/local/share/cdnca/firewallaction/engine.lua
COPY edge/openresty/siteaccess/engine.lua /usr/local/share/cdnca/siteaccess/engine.lua
COPY edge/openresty/ccadaptive/engine.lua /usr/local/share/cdnca/security/cc_adaptive.lua
COPY edge/openresty/urlauth/engine.lua /usr/local/share/cdnca/security/url_auth.lua
COPY edge/openresty/challenge/engine.lua /usr/local/share/cdnca/challenge/engine.lua
COPY edge/openresty/challenge/crypto.lua /usr/local/share/cdnca/challenge/crypto.lua
COPY edge/openresty/challenge/ip.lua /usr/local/share/cdnca/challenge/ip.lua
COPY edge/openresty/errorpage/handler.lua /usr/local/share/cdnca/errorpage/handler.lua
COPY edge/openresty/originauth/engine.lua /usr/local/share/cdnca/originauth/engine.lua
COPY edge/openresty/originauth/crypto.lua /usr/local/share/cdnca/originauth/crypto.lua
COPY edge/openresty/l4geo/engine.lua /opt/cdnca/l4geo/engine.lua
COPY edge/openresty/l4geo/cdnca_l4_geo.lua /opt/cdnca/l4geo/cdnca_l4_geo.lua
COPY edge/openresty/iplib/cdnca_iplib.lua /usr/local/share/cdnca/security/cdnca_iplib.lua
COPY edge/openresty/iplib/cdnca_iplib.lua /opt/cdnca/l4geo/cdnca_iplib.lua
COPY edge/openresty/dynroute/cdnca_dynroute.lua /usr/local/share/cdnca/dynroute/cdnca_dynroute.lua
COPY edge/openresty/dynroute/cdnca_security.lua /usr/local/share/cdnca/dynroute/cdnca_security.lua
COPY edge/openresty/dynroute/cdnca_managed_waf.lua /usr/local/share/cdnca/dynroute/cdnca_managed_waf.lua
COPY edge/openresty/dynroute/cdnca_rule_plan.lua /usr/local/share/cdnca/dynroute/cdnca_rule_plan.lua
COPY edge/openresty/dynroute/cdnca_bot.lua /usr/local/share/cdnca/dynroute/cdnca_bot.lua
COPY edge/openresty/dynroute/cdnca_telemetry.lua /usr/local/share/cdnca/dynroute/cdnca_telemetry.lua
COPY edge/openresty/dynroute/cdnca_webp.lua /usr/local/share/cdnca/dynroute/cdnca_webp.lua
COPY edge/openresty/dynroute/cdnca_webp_codec.lua /usr/local/share/cdnca/dynroute/cdnca_webp_codec.lua
COPY edge/openresty/sched302/cdnca_sched302.lua /usr/local/share/cdnca/sched302/cdnca_sched302.lua
COPY --from=h3probe /out/h3probe /usr/local/bin/h3probe
RUN /usr/local/openresty/bin/openresty -V

FROM builder AS exporter
COPY --from=runtime /usr/local/openresty /native-root/usr/local/openresty
COPY --from=runtime /usr/local/share/cdnca /native-root/usr/local/share/cdnca
COPY --from=runtime /opt/cdnca/l4geo /native-root/opt/cdnca/l4geo
COPY --from=runtime /usr/local/bin/h3probe /native-root/usr/local/bin/h3probe
COPY --from=h3probe /h3probe-src /h3probe-src
COPY --from=runtime /lib /native-root/lib
COPY --from=runtime /usr/lib /native-root/usr/lib
COPY --from=runtime /lib/apk/db/installed /native-root/runtime-apk-inventory.txt
COPY scripts/native-node-export.mjs /native-node-export.mjs
RUN node /native-node-export.mjs /native-root /native-payload > /runtime-export.json \
    && mkdir -p /native-payload/evidence \
    && cp /runtime-export.json /native-payload/evidence/runtime-export.json \
    && cp /native-root/runtime-apk-inventory.txt /native-payload/evidence/runtime-apk-inventory.txt \
    && cp /source-contract/sources.lock.json /native-payload/evidence/runtime-sources.lock.json \
    && cp /source-verification.json /native-payload/evidence/source-verification.json \
    && find /source-contract /native-node-export.mjs /h3probe-src -type f | LC_ALL=C sort | xargs sha256sum > /native-payload/evidence/runtime-build-inputs.sha256 \
    && /usr/local/openresty/bin/openresty -V > /native-payload/evidence/openresty-V.txt 2>&1 \
    && chmod 0444 /native-payload/evidence/*

FROM scratch AS native-payload
COPY --from=exporter /native-payload /
