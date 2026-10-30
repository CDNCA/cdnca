#!/bin/sh
# Node storage (NODE_STORAGE v1, 节点设置 > 存储) acceptance on a real
# OpenResty: the agent runtime (agents/edge-agent/internal/dynroute) drives
# the node runtime image in one --rm --network none container and checks
# (cdnca-dynroute-agent-check -suite node-storage, nodestorage.go):
#   - a new cache directory takes effect on the reload: MISS then HIT there;
#   - a cache directory nginx -t refuses keeps the previous one running
#     (state failed, the same settings not tried again);
#   - a new log directory is restart_pending until the agent restarts, then
#     error.log and the telemetry logs are written there.
#   tests/node-storage/run.sh
#   CDNCA_D13_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D13_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-nodestorage.XXXXXX)
trap 'rm -rf "${work}"' EXIT
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-o "${work}/check" ./internal/dynroute/cmd/cdnca-dynroute-agent-check
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source target; do
		mkdir -p "${work}/lua$(dirname "${target#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${target#/usr/local/share/cdnca}"
	done
chmod -R a+rX "${work}"
docker run --rm --init --network none --tmpfs /run/cdnca:mode=0755 -v "${work}:/d13:ro" \
	--entrypoint /d13/check "${image}" -suite node-storage -lua /d13/lua -workers "${WORKERS:-2}"
