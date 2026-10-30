#!/bin/sh
# ADR 0012 ML-07 layer 4 market supply limits on a real OpenResty (the node
# runtime image, one --rm --network none container): streams rendered by the
# agent's v2 compiler with subscription_limits (concurrent sessions, new
# sessions per second, bandwidth, stop) for throttle / pause / stop, driven
# by TCP clients (agents/edge-agent/internal/l4runtime/cmd/l4-subscription-check).
#   tests/l4-subscription-limits/run.sh
#   CDNCA_ML07_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
# Bandwidth renders proxy_download_rate_shared (native patch 28, L4F-E02):
# the image must be built from a tree with that patch, else nginx -t fails
# with 'unknown directive "proxy_download_rate_shared"'.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_ML07_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-ml07-l4.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/l4runtime/cmd/l4-subscription-check
# The L4 Lua tree from the working tree (not the image's copy).
mkdir -p "${work}/l4geo"
cp "${repo_root}/edge/openresty/l4geo/engine.lua" "${repo_root}/edge/openresty/l4geo/cdnca_l4_geo.lua" \
	"${repo_root}/edge/openresty/iplib/cdnca_iplib.lua" "${work}/l4geo/"
mkdir -p "${work}/l4geo/l4geo"
cp "${repo_root}/edge/openresty/l4geo/engine.lua" "${work}/l4geo/l4geo/engine.lua"
chmod -R a+rX "${work}"
docker run --rm --init --network none --volume "${work}:/ml07:ro" --entrypoint /ml07/check "${image}" \
	-lua /ml07/l4geo -state /tmp/l4sub
