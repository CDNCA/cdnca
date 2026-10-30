#!/bin/sh
# Dynamic routing D3 acceptance on a real OpenResty (the node runtime image,
# one --rm --network none container): Host routing, wildcard/alias, not
# ready 503, generation switches under load, rollback, cold start rebuild,
# and with SCALE=<sites> the index size / build / lookup / rebuild numbers.
#   tests/dynroute-index/run.sh                 all checks
#   ONLY=routing,switch tests/dynroute-index/run.sh
#   SCALE=1000000 ONLY=scale tests/dynroute-index/run.sh
#   CDNCA_D3_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden,
#                    built from edge/openresty/native/Dockerfile --target runtime)
#   CDNCA_D3_WRAP    command prefix (e.g. the shared-machine queue script)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D3_IMAGE:-cdnca-native-runtime:edge-golden}
wrap=${CDNCA_D3_WRAP:-}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d3-index.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/siteindex/cmd/cdnca-site-index-check
# The node Lua tree exactly as the native Dockerfile installs it.
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
cp "${here}/nginx.conf" "${work}/nginx.conf"
chmod -R a+rX "${work}"
# shellcheck disable=SC2086
${wrap} docker run --rm --init --network none ${CDNCA_D3_DOCKER_ARGS:-} \
	--volume "${work}:/d3:ro" --entrypoint /d3/check "${image}" \
	-lua /d3/lua -conf /d3/nginx.conf -state /tmp/d3state -workers "${WORKERS:-2}" -scale "${SCALE:-0}" -only "${ONLY:-}"
