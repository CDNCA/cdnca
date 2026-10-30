#!/bin/sh
# stream-be 源站列表/定源/ACL/IPv6开启 (tcp/udp v11) on a real OpenResty (the
# node runtime image, one --rm --network none container): the agent's v2
# compiler renders the streams, openresty -t checks them, TCP clients check
# weight split, down removal, ip_hash, ACL deny/allow and the [::] listener
# (agents/edge-agent/internal/l4runtime/cmd/l4-pool-check).
#   tests/l4-origin-pool/run.sh
#   CDNCA_L4POOL_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_L4POOL_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-l4pool.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/l4runtime/cmd/l4-pool-check
mkdir -p "${work}/l4geo/l4geo"
cp "${repo_root}/edge/openresty/l4geo/engine.lua" "${repo_root}/edge/openresty/l4geo/cdnca_l4_geo.lua" \
	"${repo_root}/edge/openresty/iplib/cdnca_iplib.lua" "${work}/l4geo/"
cp "${repo_root}/edge/openresty/l4geo/engine.lua" "${work}/l4geo/l4geo/engine.lua"
chmod -R a+rX "${work}"
docker run --rm --init --network none ${CDNCA_L4POOL_ENV:-} --volume "${work}:/l4pool:ro" --entrypoint /l4pool/check "${image}" \
	-lua /l4pool/l4geo -state /tmp/l4pool
