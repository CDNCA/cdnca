#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
image=nats:2.11.4-alpine
suffix="${PPID}-$$-$(date +%s)"
container="cdnca-obs-nats-${suffix}"
network="cdnca-obs-nats-${suffix}"
output=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-nats.XXXXXX")
probe_binary=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-nats-probe.XXXXXX")
reconnect_url_file=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-nats-reconnect.XXXXXX")
probe_pid=""

obs_nats_cleanup() {
  if [[ -n "${probe_pid}" ]] && kill -0 "${probe_pid}" >/dev/null 2>&1; then
    kill "${probe_pid}" >/dev/null 2>&1 || true
    wait "${probe_pid}" >/dev/null 2>&1 || true
  fi
  docker rm -f -v "${container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -f "${output}" "${probe_binary}" "${reconnect_url_file}"
}

obs_nats_fail() {
  printf 'FAIL jetstream-smoke: %s\n' "$1" >&2
  [[ -r "${output}" ]] && sed -n '1,240p' "${output}" >&2
  if docker inspect "${container}" >/dev/null 2>&1; then
    printf '%s\n' 'NATS container log tail:' >&2
    docker logs --tail 120 "${container}" 2>&1 >&2 || true
  fi
  exit 1
}

trap obs_nats_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for dependency in docker go; do
  if ! command -v "${dependency}" >/dev/null 2>&1; then
    printf 'SKIP jetstream-smoke: %s is unavailable\n' "${dependency}" >&2
    exit 77
  fi
done
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'SKIP jetstream-smoke: Docker daemon is unavailable' >&2
  exit 77
fi
if ! docker image inspect "${image}" >/dev/null 2>&1 && ! docker pull "${image}" >/dev/null; then
  printf 'SKIP jetstream-smoke: fixed image %s is unavailable\n' "${image}" >&2
  exit 77
fi

docker network create "${network}" >/dev/null
docker run -d --name "${container}" --network "${network}" \
  -p 127.0.0.1::4222 "${image}" -js -sd /data >/dev/null
for _ in {1..100}; do
  docker logs "${container}" 2>&1 | rg -q 'Server is ready' && break
  sleep 0.1
done
docker logs "${container}" 2>&1 | rg -q 'Server is ready' || obs_nats_fail 'fixed NATS server did not become ready'

published=$(docker port "${container}" 4222/tcp | head -n 1)
nats_url="nats://${published}"
(cd "${repo_root}/services/control-api" && go build -o "${probe_binary}" "${script_dir}/jetstream_probe.go")
"${probe_binary}" "${nats_url}" "${reconnect_url_file}" >"${output}" 2>&1 &
probe_pid=$!

for _ in {1..300}; do
  rg -q '^OBS_NATS_READY_FOR_RESTART$' "${output}" && break
  if ! kill -0 "${probe_pid}" >/dev/null 2>&1; then
    wait "${probe_pid}" || true
    obs_nats_fail 'probe exited before restart barrier'
  fi
  sleep 0.1
done
rg -q '^OBS_NATS_READY_FOR_RESTART$' "${output}" || obs_nats_fail 'probe did not reach restart barrier'

docker stop -t 1 "${container}" >/dev/null
docker start "${container}" >/dev/null
restarted_address=$(docker port "${container}" 4222/tcp | head -n 1)
printf 'nats://%s\n' "${restarted_address}" >"${reconnect_url_file}"

if ! wait "${probe_pid}"; then
  probe_pid=""
  obs_nats_fail 'probe failed after server restart'
fi
probe_pid=""
rg -q '^jetstream-probe passed:' "${output}" || obs_nats_fail 'probe did not emit success evidence'
sed -n '/^jetstream-probe passed:/p' "${output}"

docker rm -f -v "${container}" >/dev/null
docker network rm "${network}" >/dev/null
if docker ps -a --format '{{.Names}}' | rg -q "^${container}$" || docker network ls --format '{{.Name}}' | rg -q "^${network}$"; then
  obs_nats_fail 'task container or network remained after cleanup'
fi
rm -f "${output}" "${probe_binary}" "${reconnect_url_file}"
trap - EXIT HUP INT TERM
