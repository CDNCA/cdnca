#!/bin/sh
# Dynamic routing D9/D10 acceptance on a real OpenResty (the node runtime
# image, one --rm --network none container): error pages by header/body
# filter against the v7 shape (raw h1 byte comparison, h2, h3), the
# header_filter slot order, upload limits from the site object over
# h1/h2/h3 (native patch 23), the package connection budget under
# concurrency, the traffic exceeded page.
#   tests/dynroute-filters/run.sh                     all checks
#   ONLY=errorpage,upload tests/dynroute-filters/run.sh
#   CDNCA_D9_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden,
#                    built from edge/openresty/native/Dockerfile --target runtime)
#   CDNCA_D9_WRAP    command prefix (e.g. the shared-machine queue script)
#   WORKERS          worker processes (default 2)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D9_IMAGE:-cdnca-native-runtime:edge-golden}
wrap=${CDNCA_D9_WRAP:-}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d9-filters.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/dynfilters/cmd/cdnca-dynfilters-check
# The h2/h3 client in its own module with the HTTP/3 client's pins.
mkdir -p "${work}/probe-src"
cp "${repo_root}/edge/openresty/http3/client/client.mod" "${work}/probe-src/go.mod"
cp "${repo_root}/edge/openresty/http3/client/client.sum" "${work}/probe-src/go.sum"
cp "${here}/probe/main.go" "${work}/probe-src/main.go"
GOWORK=off GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${work}/probe-src" build -trimpath -o "${work}/probe" .
rm -rf "${work}/probe-src"
# The node Lua tree exactly as the native Dockerfile installs it.
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
cp "${here}/nginx.conf" "${work}/nginx.conf"
chmod -R a+rX "${work}"
# MINUTE_RECORDS=<dir>: the market minutes also go the agent's way and the
# wire records land in <dir>/records.jsonl (tests/subscription-minutes).
records=""
if [ -n "${MINUTE_RECORDS:-}" ]; then
	CDNCA_D9_DOCKER_ARGS="${CDNCA_D9_DOCKER_ARGS:-} --volume ${MINUTE_RECORDS}:/out"
	records="-records /out/records.jsonl"
fi
# shellcheck disable=SC2086
${wrap} docker run --rm --init --network none ${CDNCA_D9_DOCKER_ARGS:-} \
	--volume "${work}:/d9:ro" --entrypoint /d9/check "${image}" \
	-lua /d9/lua -conf /d9/nginx.conf -probe /d9/probe -state /tmp/d9state -workers "${WORKERS:-2}" -only "${ONLY:-}" ${records}
