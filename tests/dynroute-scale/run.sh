#!/bin/sh
# D13-d dynamic routing scale benchmark (ADR 0009 §5 规模): the agent runtime
# over SITES sites on a real OpenResty (node runtime image, one --rm
# --network none container per size): cold start, incremental activation,
# reloads, agent/OpenResty memory, per request p50/p99, agent and node
# restart. Source: tests/dynroute-scale/main.go, compiled into the edge-agent
# module with go build -overlay (no product directory carries it).
#   tests/dynroute-scale/run.sh                    10000 and 100000 sites
#   SIZES=10000 REQUESTS=20000 tests/dynroute-scale/run.sh
#   CDNCA_D13D_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden)
#   CDNCA_D13D_WRAP    command prefix (the shared machine's queue script)
#   CDNCA_D13D_MEMORY  container memory limit (default 6g)
# Output: RESULT/PASS/FAIL lines; tests/dynroute-scale/results/<size>-<time>.log
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D13D_IMAGE:-cdnca-native-runtime:edge-golden}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
case "$(docker image inspect "${image}" --format '{{.Architecture}}')" in
	arm64|aarch64) go_arch=arm64 ;;
	*) go_arch=amd64 ;;
esac
work=$(mktemp -d /tmp/cdnca-d13d.XXXXXX)
trap 'rm -rf "${work}"' EXIT
target="${repo_root}/agents/edge-agent/internal/dynroute/cmd/cdnca-dynroute-scale/main.go"
printf '{"Replace":{"%s":"%s"}}' "${target}" "${here}/main.go" >"${work}/overlay.json"
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" go -C "${repo_root}/agents/edge-agent" build -trimpath \
	-overlay "${work}/overlay.json" -o "${work}/scale" ./internal/dynroute/cmd/cdnca-dynroute-scale
mkdir -p "${work}/lua"
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "${repo_root}/edge/openresty/native/Dockerfile" |
	while read -r _ source dest; do
		mkdir -p "${work}/lua$(dirname "${dest#/usr/local/share/cdnca}")"
		cp "${repo_root}/${source}" "${work}/lua${dest#/usr/local/share/cdnca}"
	done
chmod -R a+rX "${work}"
mkdir -p "${here}/results"
status=0
for size in ${SIZES:-10000 100000}; do
	log="${here}/results/${size}-$(date +%Y%m%d-%H%M%S).log"
	# SYS_PTRACE: the benchmark reads the nobody workers' smaps_rollup.
	# shellcheck disable=SC2086
	${CDNCA_D13D_WRAP:-} docker run --rm --init --network none --cap-add SYS_PTRACE --memory "${CDNCA_D13D_MEMORY:-6g}" \
		--tmpfs /run/cdnca:mode=0755 -v "${work}:/d13d:ro" --entrypoint /d13d/scale "${image}" \
		-lua /d13d/lua -workers "${WORKERS:-2}" -sites "${size}" -requests "${REQUESTS:-20000}" >"${log}" 2>&1 || status=1
	grep -E '^(RESULT|FAIL)' "${log}" || true
	echo "log: ${log}"
done
exit "${status}"
