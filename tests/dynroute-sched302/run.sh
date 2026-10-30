#!/bin/sh
# HTTP 302 scheduling on the dynamic routing node: the node
# skeleton with Schedule302, cdnca_dynroute and site objects, on a real
# OpenResty (the node runtime image, --rm --network none). Same cases as the
# v7 renderer's TestRealOpenRestySchedule302*: carrier/region picks the node,
# landing served and never redirected again, node down moves within
# seconds, expired/tampered/foreign/forged refused, size threshold.
#   tests/dynroute-sched302/run.sh
#   CDNCA_S302_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
#   WORKERS           worker processes (default 2)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_S302_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-s302.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/edgegolden/goldendyn/cmd/cdnca-sched302-check
# the node Lua tree as the native Dockerfile installs it
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
chmod -R a+rX "${work}"
docker run --rm --init --network none -v "${work}:/s302:ro" --entrypoint /s302/check "${image}" \
	-lua /s302/lua -workers "${WORKERS:-2}"
