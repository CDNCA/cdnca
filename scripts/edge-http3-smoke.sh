#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/http3/versions.env"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *) echo "unsupported Docker architecture: ${docker_arch}" >&2; exit 69 ;;
esac

tmp_base="${TMPDIR:-/tmp}"
case "${tmp_base}" in
  /*) ;;
  *) echo "TMPDIR must be absolute" >&2; exit 64 ;;
esac
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-http3.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-http3\.//')"
server_container="cdnca-http3-server-${suffix}"
client_container="cdnca-http3-client-${suffix}"
proxy_container="cdnca-http3-proxy-${suffix}"
network_a="cdnca-http3-a-${suffix}"
network_b="cdnca-http3-b-${suffix}"
runtime_image="cdnca/openresty-runtime:http3-${suffix}"
client_image="cdnca/http3-client:${suffix}"
listen_port=18443
smoke_step=setup
reload_client_pid=
h2_reload_client_pid=
reload_apply_pid=

reload_apply_running() {
  reload_apply_state="$(ps -o stat= -p "${reload_apply_pid}" 2>/dev/null | tr -d '[:space:]')"
  case "${reload_apply_state}" in
    ''|Z*) return 1 ;;
    *) return 0 ;;
  esac
}

cleanup() {
  cleanup_status=$?
  if [ -n "${reload_apply_pid}" ] && kill -0 "${reload_apply_pid}" >/dev/null 2>&1; then
    kill "${reload_apply_pid}" >/dev/null 2>&1 || true
    wait "${reload_apply_pid}" >/dev/null 2>&1 || true
  fi
  if [ -n "${reload_client_pid}" ] && kill -0 "${reload_client_pid}" >/dev/null 2>&1; then
    kill "${reload_client_pid}" >/dev/null 2>&1 || true
    wait "${reload_client_pid}" >/dev/null 2>&1 || true
  fi
  if [ -n "${h2_reload_client_pid}" ] && kill -0 "${h2_reload_client_pid}" >/dev/null 2>&1; then
    kill "${h2_reload_client_pid}" >/dev/null 2>&1 || true
    wait "${h2_reload_client_pid}" >/dev/null 2>&1 || true
  fi
  docker rm -f "${proxy_container}" >/dev/null 2>&1 || true
  docker rm -f "${client_container}" >/dev/null 2>&1 || true
  docker rm -f "${server_container}" >/dev/null 2>&1 || true
  docker network rm "${network_b}" >/dev/null 2>&1 || true
  docker network rm "${network_a}" >/dev/null 2>&1 || true
  docker image rm "${client_image}" >/dev/null 2>&1 || true
  docker image rm "${runtime_image}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-http3.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
  if [ "${cleanup_status}" -ne 0 ]; then
    printf 'edge HTTP/3 smoke failed during %s\n' "${smoke_step}" >&2
  fi
}
trap cleanup EXIT HUP INT TERM

mkdir -m 0700 "${workdir}/state"
mkdir -m 0777 "${workdir}/client-evidence"
smoke_step=build-agent
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/edge-http3-smoke" ./internal/http3runtime/cmd/edge-http3-smoke
)

smoke_step=build-runtime
if ! "${repo_root}/scripts/edge-runtime-build.sh" "${runtime_image}" >"${workdir}/runtime-build.log" 2>&1; then
  cat "${workdir}/runtime-build.log" >&2
  exit 1
fi
smoke_step=build-client
if ! docker build \
  --provenance=false \
  --build-arg 'GOPROXY=https://goproxy.cn,direct' \
  --tag "${client_image}" \
  --file "${repo_root}/edge/openresty/http3/client/Dockerfile" \
  "${repo_root}/edge/openresty/http3/client" >"${workdir}/client-build.log" 2>&1; then
  cat "${workdir}/client-build.log" >&2
  exit 1
fi

client_user="$(docker image inspect "${client_image}" --format '{{.Config.User}}')"
test "${client_user}" = '65532:65532'
runtime_image_id="$(docker image inspect "${runtime_image}" --format '{{.Id}}')"
client_image_id="$(docker image inspect "${client_image}" --format '{{.Id}}')"

smoke_step=setup-containers
# The server's agent-side health probe is the image's own /usr/local/bin/h3probe
# (the same build the node package ships), not a copy of the client image's.

docker network create --label cdnca.smoke=edge-http3 "${network_a}" >/dev/null
docker network create --label cdnca.smoke=edge-http3 "${network_b}" >/dev/null

docker run --detach --init \
  --name "${server_container}" \
  --network "${network_a}" \
  --cap-add BPF \
  --cap-add NET_ADMIN \
  --cap-add PERFMON \
  --env QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true \
  --volume "${workdir}/state:/var/lib/cdnca-edge-http3" \
  --volume "${workdir}/edge-http3-smoke:/usr/local/bin/edge-http3-smoke:ro" \
  --entrypoint /bin/sh \
  "${runtime_image}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null
docker network connect "${network_b}" "${server_container}"

docker run --detach --init \
  --name "${client_container}" \
  --network "${network_a}" \
  --env QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true \
  --volume "${workdir}/client-evidence:/evidence" \
  "${client_image}" wait >/dev/null
docker network connect "${network_b}" "${client_container}"

server_ip_a="$(docker inspect --format "{{(index .NetworkSettings.Networks \"${network_a}\").IPAddress}}" "${server_container}")"
client_ip_a="$(docker inspect --format "{{(index .NetworkSettings.Networks \"${network_a}\").IPAddress}}" "${client_container}")"
client_ip_b="$(docker inspect --format "{{(index .NetworkSettings.Networks \"${network_b}\").IPAddress}}" "${client_container}")"
for address in "${server_ip_a}" "${client_ip_a}" "${client_ip_b}"; do
  case "${address}" in
    *.*.*.*) ;;
    *) echo "Docker did not assign an IPv4 smoke address: ${address}" >&2; exit 1 ;;
  esac
done
test "${client_ip_a}" != "${client_ip_b}"

smoke_step=init
docker exec "${server_container}" /usr/local/bin/edge-http3-smoke \
  -mode init -state-root /var/lib/cdnca-edge-http3 -port "${listen_port}" \
  >"${workdir}/init.json"
grep -F '"active_version": "http3-v1"' "${workdir}/init.json" >/dev/null
grep -F '"dual_protocol_health": true' "${workdir}/init.json" >/dev/null

smoke_step=baseline-protocols
docker exec "${client_container}" /h3probe request \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test \
  >"${workdir}/h3-v1.json"
grep -F '"protocol": "HTTP/3.0"' "${workdir}/h3-v1.json" >/dev/null
grep -F '"tls_version": "TLSv1.3"' "${workdir}/h3-v1.json" >/dev/null
grep -F '"version_header": "http3-v1"' "${workdir}/h3-v1.json" >/dev/null
grep -F '"alt_svc": "h3=\":18443\"; ma=300"' "${workdir}/h3-v1.json" >/dev/null
grep -F '"retry_received": true' "${workdir}/h3-v1.json" >/dev/null
grep -F '"used_0rtt": false' "${workdir}/h3-v1.json" >/dev/null
grep -F '"did_resume": false' "${workdir}/h3-v1.json" >/dev/null

docker run --rm --network "${network_a}" "${HTTP3_FALLBACK_CLIENT}" \
  --insecure --silent --show-error --http2 \
  --resolve "h3.test:${listen_port}:${server_ip_a}" \
  --dump-header - --output /dev/null --write-out 'http_version=%{http_version}\n' \
  "https://h3.test:${listen_port}/healthz" >"${workdir}/h2.txt"
tr -d '\r' <"${workdir}/h2.txt" >"${workdir}/h2.clean"
grep -Fx 'http_version=2' "${workdir}/h2.clean" >/dev/null
grep -Fi 'alt-svc: h3=":18443"; ma=300' "${workdir}/h2.clean" >/dev/null

docker exec "${client_container}" /h3probe h2-attack \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test --mode injection \
  >"${workdir}/h2-injection.json"
grep -F '"rejected": true' "${workdir}/h2-injection.json" >/dev/null
docker exec "${client_container}" /h3probe h2-attack \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test --mode bomb \
  >"${workdir}/h2-bomb.json"
grep -F '"rejected": true' "${workdir}/h2-bomb.json" >/dev/null

docker run --rm --network "${network_a}" "${HTTP3_FALLBACK_CLIENT}" \
  --insecure --silent --show-error --http1.1 \
  --resolve "h3.test:${listen_port}:${server_ip_a}" \
  --dump-header - --output /dev/null --write-out 'http_version=%{http_version}\n' \
  "https://h3.test:${listen_port}/healthz" >"${workdir}/h1.txt"
tr -d '\r' <"${workdir}/h1.txt" >"${workdir}/h1.clean"
grep -Fx 'http_version=1.1' "${workdir}/h1.clean" >/dev/null
grep -Fi 'alt-svc: h3=":18443"; ma=300' "${workdir}/h1.clean" >/dev/null

smoke_step=protocol-boundaries
docker exec "${client_container}" /h3probe request \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test --header-bytes 3000 \
  >"${workdir}/header-within.json"
if docker exec "${client_container}" /h3probe request \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test --header-bytes 8192 \
  >"${workdir}/header-over.out" 2>&1; then
  echo "request header above the configured boundary was accepted" >&2
  exit 1
fi

docker exec "${client_container}" /h3probe concurrency \
  --url "https://${server_ip_a}:${listen_port}/hold" --server-name h3.test --count 4 --timeout 15s \
  >"${workdir}/stream-limit.json"
grep -F '"200": 4' "${workdir}/stream-limit.json" >/dev/null
stream_elapsed="$(sed -n 's/.*"elapsed_ms": \([0-9][0-9]*\).*/\1/p' "${workdir}/stream-limit.json")"
if [ -z "${stream_elapsed}" ] || [ "${stream_elapsed}" -lt 3500 ]; then
  echo "HTTP/3 stream limit did not serialize four held requests into two waves" >&2
  cat "${workdir}/stream-limit.json" >&2
  exit 1
fi

docker exec "${client_container}" /h3probe migration \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test \
  --initial-bind "${client_ip_a}:0" --migration-bind "${client_ip_b}:0" --timeout 15s \
  >"${workdir}/migration.json"
grep -F '"same_connection": true' "${workdir}/migration.json" >/dev/null
grep -F '"initial_protocol": "HTTP/3.0"' "${workdir}/migration.json" >/dev/null
grep -F '"migrated_protocol": "HTTP/3.0"' "${workdir}/migration.json" >/dev/null
grep -F "${client_ip_a}:" "${workdir}/migration.json" >/dev/null
grep -F "${client_ip_b}:" "${workdir}/migration.json" >/dev/null

docker run --detach --init \
  --name "${proxy_container}" --network "${network_a}" \
  "${client_image}" tcp-proxy --listen "0.0.0.0:${listen_port}" --target "${server_ip_a}:${listen_port}" >/dev/null
proxy_ip="$(docker inspect --format "{{(index .NetworkSettings.Networks \"${network_a}\").IPAddress}}" "${proxy_container}")"
docker exec "${client_container}" /h3probe fallback \
  --url "https://${proxy_ip}:${listen_port}/healthz" --server-name h3.test --h3-timeout 800ms --timeout 10s \
  >"${workdir}/fallback.json"
grep -F '"h3_failed": true' "${workdir}/fallback.json" >/dev/null
grep -F '"fallback_protocol": "HTTP/2.0"' "${workdir}/fallback.json" >/dev/null
grep -F '"fallback_status": 200' "${workdir}/fallback.json" >/dev/null

smoke_step=reload
master_pid_before="$(docker exec "${server_container}" sh -eu -c 'cat /var/lib/cdnca-edge-http3/run/nginx.pid')"
old_workers="$(docker exec "${server_container}" sh -eu -c '
  master="$(cat /var/lib/cdnca-edge-http3/run/nginx.pid)"
  cat "/proc/${master}/task/${master}/children"
')"
# /proc children is a whitespace-separated PID list.
# shellcheck disable=SC2086
set -- ${old_workers}
if [ "$#" -ne 1 ]; then
  echo "expected one HTTP/3 worker before reload, got: ${old_workers}" >&2
  exit 1
fi
old_worker_pid="$1"
quic_host_key_before="$(docker exec "${server_container}" sha256sum /var/lib/cdnca-edge-http3/state/quic-host.key | awk '{print $1}')"
active_quic_host_key_before="$(docker exec "${server_container}" sh -eu -c '
  release="$(readlink -f /var/lib/cdnca-edge-http3/current)"
  sha256sum "${release}/quic-host.key" | awk "{print \$1}"
')"
test "${quic_host_key_before}" = "${active_quic_host_key_before}"

docker exec "${client_container}" /h3probe h2-hold \
  --url "https://${server_ip_a}:${listen_port}/hold" --server-name h3.test \
  --ready-file /evidence/h2-reload-ready --expected-version http3-v1 --timeout 20s \
  >"${workdir}/h2-reload.json" 2>"${workdir}/h2-reload.err" &
h2_reload_client_pid=$!
docker exec "${client_container}" /h3probe reload-survival \
  --baseline-url "https://${server_ip_a}:${listen_port}/healthz" \
  --hold-url "https://${server_ip_a}:${listen_port}/hold" \
  --server-name h3.test --ready-file /evidence/reload-ready --count 2 --timeout 20s \
  >"${workdir}/reload-survival.json" 2>"${workdir}/reload-survival.err" &
reload_client_pid=$!
attempt=0
while [ ! -f "${workdir}/client-evidence/reload-ready" ] || [ ! -f "${workdir}/client-evidence/h2-reload-ready" ]; do
  if ! kill -0 "${reload_client_pid}" >/dev/null 2>&1 &&
    [ ! -f "${workdir}/client-evidence/reload-ready" ]; then
    wait "${reload_client_pid}" || true
    cat "${workdir}/reload-survival.err" >&2
    echo "reload client exited before the held stream was sent" >&2
    exit 1
  fi
  if ! kill -0 "${h2_reload_client_pid}" >/dev/null 2>&1 &&
    [ ! -f "${workdir}/client-evidence/h2-reload-ready" ]; then
    wait "${h2_reload_client_pid}" || true
    cat "${workdir}/h2-reload.err" >&2
    echo "HTTP/2 reload client exited before its held request was sent" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 100 ]; then
    echo "reload client did not send a held stream within 5 seconds" >&2
    exit 1
  fi
  sleep 0.05
done

docker exec "${server_container}" /usr/local/bin/edge-http3-smoke \
  -mode reload -state-root /var/lib/cdnca-edge-http3 -port "${listen_port}" \
  >"${workdir}/reload.json" 2>"${workdir}/reload.err" &
reload_apply_pid=$!

attempt=0
new_worker_pid=
while [ -z "${new_worker_pid}" ]; do
  if ! reload_apply_running; then
    wait "${reload_apply_pid}" >/dev/null 2>&1 || true
    reload_apply_pid=
    cat "${workdir}/reload.err" >&2
    echo "HTTP/3 reload Apply returned before old/new worker overlap was observed" >&2
    exit 1
  fi
  workers_during_reload="$(docker exec "${server_container}" sh -eu -c '
    master="$(cat /var/lib/cdnca-edge-http3/run/nginx.pid)"
    cat "/proc/${master}/task/${master}/children"
  ')"
  # /proc children is a whitespace-separated PID list.
  # shellcheck disable=SC2086
  set -- ${workers_during_reload}
  if [ "$#" -gt 0 ]; then
    case " ${workers_during_reload} " in
      *" ${old_worker_pid} "*) ;;
      *) echo "old HTTP/3 worker exited before old/new overlap was observed" >&2; exit 1 ;;
    esac
  fi
  if [ "$#" -gt 2 ]; then
    echo "unexpected HTTP/3 worker fanout during reload: ${workers_during_reload}" >&2
    exit 1
  fi
  if [ "$#" -eq 2 ]; then
    # shellcheck disable=SC2086
    for worker_pid in ${workers_during_reload}; do
      if [ "${worker_pid}" != "${old_worker_pid}" ]; then
        new_worker_pid="${worker_pid}"
      fi
    done
    if [ -n "${new_worker_pid}" ] && ! reload_apply_running; then
      new_worker_pid=
    fi
  fi
  if [ -z "${new_worker_pid}" ]; then
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge 100 ]; then
      echo "old/new HTTP/3 worker overlap was not observed within 5 seconds" >&2
      exit 1
    fi
    sleep 0.05
  fi
done

if ! wait "${reload_apply_pid}"; then
  reload_apply_pid=
  cat "${workdir}/reload.err" >&2
  echo "HTTP/3 reload Apply failed after worker overlap" >&2
  exit 1
fi
reload_apply_pid=
grep -F '"active_version": "http3-v2"' "${workdir}/reload.json" >/dev/null
grep -F '"master_pid_stable": true' "${workdir}/reload.json" >/dev/null
grep -F "\"master_pid\": ${master_pid_before}" "${workdir}/reload.json" >/dev/null

workers_after_apply="$(docker exec "${server_container}" sh -eu -c '
  master="$(cat /var/lib/cdnca-edge-http3/run/nginx.pid)"
  cat "/proc/${master}/task/${master}/children"
')"
# /proc children is a whitespace-separated PID list.
# shellcheck disable=SC2086
set -- ${workers_after_apply}
if [ "$#" -ne 1 ] || [ "$1" != "${new_worker_pid}" ]; then
  echo "reload Apply returned before the old worker drained or after the new worker exited: ${workers_after_apply}" >&2
  exit 1
fi

quic_host_key_after="$(docker exec "${server_container}" sha256sum /var/lib/cdnca-edge-http3/state/quic-host.key | awk '{print $1}')"
active_quic_host_key_after="$(docker exec "${server_container}" sh -eu -c '
  release="$(readlink -f /var/lib/cdnca-edge-http3/current)"
  sha256sum "${release}/quic-host.key" | awk "{print \$1}"
')"
test "${quic_host_key_before}" = "${quic_host_key_after}"
test "${quic_host_key_after}" = "${active_quic_host_key_after}"

if ! wait "${h2_reload_client_pid}"; then
  cat "${workdir}/h2-reload.err" >&2
  exit 1
fi
h2_reload_client_pid=
grep -F '"protocol": "HTTP/2.0"' "${workdir}/h2-reload.json" >/dev/null
grep -F '"version_header": "http3-v1"' "${workdir}/h2-reload.json" >/dev/null

if ! wait "${reload_client_pid}"; then
  cat "${workdir}/reload-survival.err" >&2
  exit 1
fi
reload_client_pid=
grep -F '"count": 2' "${workdir}/reload-survival.json" >/dev/null
grep -F '"old_connection_dials": 1' "${workdir}/reload-survival.json" >/dev/null
grep -F '"old_connection_unredialed": true' "${workdir}/reload-survival.json" >/dev/null
grep -F '"fresh_attempt_limit": 3' "${workdir}/reload-survival.json" >/dev/null
grep -F '"fresh_version": "http3-v2"' "${workdir}/reload-survival.json" >/dev/null
reload_completed="$(sed -n 's/.*"completed_on_old_connection": \([0-9][0-9]*\).*/\1/p' "${workdir}/reload-survival.json")"
reload_resets="$(sed -n 's/.*"stateless_resets": \([0-9][0-9]*\).*/\1/p' "${workdir}/reload-survival.json")"
if [ -z "${reload_completed}" ] || [ -z "${reload_resets}" ] || [ "$((reload_completed + reload_resets))" -ne 2 ]; then
  echo "HTTP/3 reload outcomes were not fully accounted for" >&2
  cat "${workdir}/reload-survival.json" >&2
  exit 1
fi

docker exec "${client_container}" /h3probe connections \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test \
  --count 16 --timeout 15s >"${workdir}/h3-v2-connections.json"
grep -F '"200": 16' "${workdir}/h3-v2-connections.json" >/dev/null
grep -F '"http3-v2": 16' "${workdir}/h3-v2-connections.json" >/dev/null

smoke_step=fence
docker exec "${server_container}" /usr/local/bin/edge-http3-smoke \
  -mode fence -state-root /var/lib/cdnca-edge-http3 -port "${listen_port}" \
  >"${workdir}/fence.json"
grep -F '"identity_record_owned": true' "${workdir}/fence.json" >/dev/null
grep -F '"pidfd_no_leak": true' "${workdir}/fence.json" >/dev/null
grep -F '"substitute_signal_rejected": true' "${workdir}/fence.json" >/dev/null
grep -F '"dual_protocol_health": true' "${workdir}/fence.json" >/dev/null

smoke_step=bad-candidate
docker exec "${server_container}" /usr/local/bin/edge-http3-smoke \
  -mode bad -state-root /var/lib/cdnca-edge-http3 -port "${listen_port}" \
  >"${workdir}/bad.json"
grep -F '"active_version": "http3-v2"' "${workdir}/bad.json" >/dev/null
grep -F '"error_code": "PRECHECK_FAILED"' "${workdir}/bad.json" >/dev/null
grep -F '"running_version_unchanged": true' "${workdir}/bad.json" >/dev/null

docker exec "${client_container}" /h3probe request \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test \
  >"${workdir}/h3-after-bad.json"
grep -F '"version_header": "http3-v2"' "${workdir}/h3-after-bad.json" >/dev/null

smoke_step=disable
docker exec "${server_container}" /usr/local/bin/edge-http3-smoke \
  -mode disable -state-root /var/lib/cdnca-edge-http3 -port "${listen_port}" \
  >"${workdir}/disable.json"
grep -F '"active_version": "http3-v3-off"' "${workdir}/disable.json" >/dev/null
grep -F '"http3_enabled": false' "${workdir}/disable.json" >/dev/null
docker run --rm --network "${network_a}" "${HTTP3_FALLBACK_CLIENT}" \
  --insecure --silent --show-error --http2 \
  --resolve "h3.test:${listen_port}:${server_ip_a}" \
  --dump-header - --output /dev/null --write-out 'http_version=%{http_version}\n' \
  "https://h3.test:${listen_port}/healthz" >"${workdir}/h2-disabled.txt"
tr -d '\r' <"${workdir}/h2-disabled.txt" >"${workdir}/h2-disabled.clean"
grep -Fx 'http_version=2' "${workdir}/h2-disabled.clean" >/dev/null
if grep -Fi 'alt-svc:' "${workdir}/h2-disabled.clean" >/dev/null; then
  echo "HTTP/3-disabled response retained Alt-Svc" >&2
  exit 1
fi
if docker exec "${client_container}" /h3probe request \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test --timeout 2s \
  >"${workdir}/h3-disabled.out" 2>&1; then
  echo "HTTP/3 remained reachable after disable" >&2
  exit 1
fi

smoke_step=enable
docker exec "${server_container}" /usr/local/bin/edge-http3-smoke \
  -mode enable -state-root /var/lib/cdnca-edge-http3 -port "${listen_port}" \
  >"${workdir}/enable.json"
grep -F '"active_version": "http3-v4-on"' "${workdir}/enable.json" >/dev/null
grep -F '"http3_enabled": true' "${workdir}/enable.json" >/dev/null
docker exec "${client_container}" /h3probe request \
  --url "https://${server_ip_a}:${listen_port}/healthz" --server-name h3.test \
  >"${workdir}/h3-enabled.json"
grep -F '"protocol": "HTTP/3.0"' "${workdir}/h3-enabled.json" >/dev/null
grep -F '"version_header": "http3-v4-on"' "${workdir}/h3-enabled.json" >/dev/null
grep -F '"retry_received": true' "${workdir}/h3-enabled.json" >/dev/null
grep -F '"used_0rtt": false' "${workdir}/h3-enabled.json" >/dev/null

smoke_step=runtime-version
docker exec "${server_container}" /usr/local/openresty/bin/openresty -V >"${workdir}/runtime-version.txt" 2>&1
grep -Fx "nginx version: openresty/${OPENRESTY_VERSION}" "${workdir}/runtime-version.txt" >/dev/null
grep -F -- '--with-http_v3_module' "${workdir}/runtime-version.txt" >/dev/null

printf 'runtime_image_id=%s\nclient_image_id=%s\nclient_user=%s\nopenresty_version=%s\nopenresty_quic_module=true\n' \
  "${runtime_image_id}" "${client_image_id}" "${client_user}" "${OPENRESTY_VERSION}"
printf 'h3_v1=%s\nh2_fallback=http_version=2\nh1_fallback=http_version=1.1\n' "$(tr -d '\n' <"${workdir}/h3-v1.json")"
printf 'header_within_limit=true\nheader_over_limit_rejected=true\nstream_limit=%s\n' "$(tr -d '\n' <"${workdir}/stream-limit.json")"
printf 'h2_injection=%s\nh2_hpack_bomb=%s\nquic_retry_verified=true\nzero_rtt_used=false\n' \
  "$(tr -d '\n' <"${workdir}/h2-injection.json")" "$(tr -d '\n' <"${workdir}/h2-bomb.json")"
printf 'migration=%s\nudp_unreachable_fallback=%s\n' "$(tr -d '\n' <"${workdir}/migration.json")" "$(tr -d '\n' <"${workdir}/fallback.json")"
printf 'linux_pidfd_fencing=true\nreload=%s\nreload_existing_h2=%s\nreload_existing_quic=%s\nreload_new_connections=%s\nreload_workers=old:%s,new:%s\nquic_host_key_stable=%s\nfence=%s\nbad_policy=%s\nh3_after_bad=%s\n' \
  "$(tr -d '\n' <"${workdir}/reload.json")" "$(tr -d '\n' <"${workdir}/h2-reload.json")" \
  "$(tr -d '\n' <"${workdir}/reload-survival.json")" \
  "$(tr -d '\n' <"${workdir}/h3-v2-connections.json")" "${old_worker_pid}" "${new_worker_pid}" \
  "${quic_host_key_after}" \
  "$(tr -d '\n' <"${workdir}/fence.json")" "$(tr -d '\n' <"${workdir}/bad.json")" \
  "$(tr -d '\n' <"${workdir}/h3-after-bad.json")"
printf 'http3_disable=%s\nhttp3_enable=%s\nh3_after_enable=%s\n' \
  "$(tr -d '\n' <"${workdir}/disable.json")" "$(tr -d '\n' <"${workdir}/enable.json")" \
  "$(tr -d '\n' <"${workdir}/h3-enabled.json")"
