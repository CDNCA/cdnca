#!/bin/sh
# Dynamic routing D12 acceptance on a real OpenResty (the node runtime image,
# one --rm --network none container): v7 golden access/security log fields
# on a shared server, per-site attribution of SITES sites under mixed traffic
# and generation switches (100% required), capture events, the quic
# reuseport reload noise filter. See docs/edge/dynroute-telemetry.md.
#   tests/dynroute-telemetry/run.sh                       all checks (10 000 sites)
#   ONLY=golden,capture tests/dynroute-telemetry/run.sh
#   SITES=2000 REQUESTS=20000 tests/dynroute-telemetry/run.sh
#   CDNCA_D12_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden)
#   CDNCA_D12_WRAP    command prefix (e.g. the shared-machine queue script)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D12_IMAGE:-cdnca-native-runtime:edge-golden}
wrap=${CDNCA_D12_WRAP:-}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d12-telemetry.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/dyntelemetry/cmd/cdnca-dyntelemetry-check
# The node Lua tree exactly as the native Dockerfile installs it.
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
cp "${here}/nginx.conf" "${work}/nginx.conf"
mkdir -p "${work}/golden"
cp -R "${repo_root}/tests/edge-golden/cdnca-v7/scenarios" "${repo_root}/tests/edge-golden/cdnca-v7/expected" "${work}/golden/"
chmod -R a+rX "${work}"
# shellcheck disable=SC2086
${wrap} docker run --rm --init --network none ${CDNCA_D12_DOCKER_ARGS:-} \
	--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
	--volume "${work}:/d12:ro" --entrypoint /d12/check "${image}" \
	-lua /d12/lua -conf /d12/nginx.conf -golden /d12/golden -state /tmp/d12state -workers "${WORKERS:-2}" \
	-sites "${SITES:-10000}" -requests "${REQUESTS:-60000}" -only "${ONLY:-}"
