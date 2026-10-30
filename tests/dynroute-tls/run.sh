#!/bin/sh
# Dynamic routing D4 (TLS entry) acceptance on a real OpenResty (the node
# runtime image, one --rm --network none container): certificates by SNI on
# shared servers over TLS/h2/h3, unknown / missing SNI refused, SNI != Host
# routed by Host, per-site protocols and ciphers, certificate switch without
# interruption, OCSP stapling, client certificates; with SCALE=<sites> the
# certificate LRU hit rate and handshake times.
# ONLY=h2off (fp-site5a, 待出包前全量跑): HTTP/2 off for one of two sites on
# one shared port (native patch 27): ALPN, curl --http2, coalescing 421.
# ONLY=tlscustom (待出包前全量跑): a custom cipher preset site
# and a modern site on one shared port, openssl s_client -tls1_2 -cipher and the
# Go client: per-site TLS 1.2 suites, server order, TLS 1.3 untouched.
#   tests/dynroute-tls/run.sh                    all checks
#   SCALE=10000 ONLY=scale tests/dynroute-tls/run.sh
#   CDNCA_D4_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden,
#                    built from edge/openresty/native/Dockerfile --target runtime;
#                    must carry /usr/local/bin/h3probe)
#   CDNCA_D4_WRAP    command prefix (e.g. the shared-machine queue script)
#   CERT_LRU, WORKERS  cdnca_tls certificate LRU items and worker processes
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D4_IMAGE:-cdnca-native-runtime:edge-golden}
wrap=${CDNCA_D4_WRAP:-}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d4-tls.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/dyntls/cmd/cdnca-dyntls-check
# The node Lua tree exactly as the native Dockerfile installs it.
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
cp "${here}/nginx.conf" "${work}/nginx.conf"
chmod -R a+rX "${work}"
# Every test name resolves to loopback (h3probe dials the URL's host).
hosts=""
for name in shop blog legacy tls12 tls13 old modern rot mtls mtlsopt noh3 ocsp unknown x.shop h2on h2off custom; do
	hosts="${hosts} --add-host ${name}.example.test:127.0.0.1"
done
# shellcheck disable=SC2086
${wrap} docker run --rm --init --network none ${hosts} ${CDNCA_D4_DOCKER_ARGS:-} \
	--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
	--volume "${work}:/d4:ro" --entrypoint /d4/check "${image}" \
	-lua /d4/lua -conf /d4/nginx.conf -state /tmp/d4state -workers "${WORKERS:-2}" -scale "${SCALE:-0}" \
	-cert-lru "${CERT_LRU:-10000}" -only "${ONLY:-}"
