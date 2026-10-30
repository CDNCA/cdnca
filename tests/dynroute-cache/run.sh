#!/bin/sh
# D8 dynamic routing cache on the real node runtime (OpenResty 1.31.1.1 with
# native patch 24), one --rm --network none container: Range from the cached
# object, per-site rule TTL (patch 24), cookie/no-rule/no-store bypass with
# reasons, Lua plan == Go plan, purge generation (immediate, per site, fail
# closed after a restart until the agent syncs), prewarm through the shared
# server; then SCALE sites on the shared zone pool: Zipf hit rate, purge
# isolation (same zone, same paths), soft quota trimmed per site by LRU;
# statusheader: cache-status-header-on/-off/
# -escalated/-prewarm and -origin-forged (X-CDN-Cache only with the site
# object's cache_status_header, always on a prewarm, the origin's removed).
# The D0 golden: CDNCA_EDGE_GOLDEN_RENDERER=cdnca-dynroute tests/edge-golden/run.sh check cache
#   CDNCA_D8_IMAGE  node runtime image with patch 24 (default cdnca-native-runtime:edge-golden,
#                   built from edge/openresty/native/Dockerfile --target runtime)
#   ONLY=functional|extensions|rulematch|follow|statusheader|scale  SCALE (default 10000)  REQUESTS (default 100000)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D8_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d8.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/edgegolden/goldendyn/cmd/cdnca-cache-check
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
chmod -R a+rX "${work}"
docker run --rm --init --network none -v "${work}:/d8:ro" --entrypoint /d8/check "${image}" \
	-lua /d8/lua -workers "${WORKERS:-2}" -scale "${SCALE:-10000}" -requests "${REQUESTS:-100000}" -only "${ONLY:-}"
