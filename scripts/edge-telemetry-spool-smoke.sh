#!/bin/sh
set -eu

umask 077
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
tmp_base="${TMPDIR:-/tmp}"
case "${tmp_base}" in
  /*) ;;
  *) echo "TMPDIR must be absolute" >&2; exit 64 ;;
esac
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-telemetry-spool.XXXXXX")"
workdir="$(CDPATH='' cd -- "${workdir}" && pwd -P)"
container_name="cdnca-edge-telemetry-smoke-$$"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-telemetry-spool.*|/private"${tmp_base%/}"/cdnca-edge-telemetry-spool.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
  exit "${status}"
}
trap cleanup EXIT HUP INT TERM

chmod 0700 "${workdir}"
mkdir "${workdir}/logs"
chmod 0700 "${workdir}/logs"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
docker run --rm --name "${container_name}" --network none \
  --volume "${repo_root}/edge/openresty/telemetry:/telemetry:ro" \
  --volume "${workdir}/logs:/tmp/logs" \
  --entrypoint /bin/sh \
  "${OPENRESTY_IMAGE}" \
  -c '
    set -eu
    openresty=/usr/local/openresty/bin/openresty
    "${openresty}" -t -p /tmp -c /telemetry/syntax-test.conf
    "${openresty}" -p /tmp -c /telemetry/syntax-test.conf

    request_statuses() {
      port=$1
      statuses=
      for path in "/ok?token=secret-value" /missing /error /waf-block; do
        status="$(curl --silent --output /dev/null --write-out "%{http_code}" \
          --header "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01" \
          --header "X-Cdnca-Tenant-Id: attacker-tenant" \
          --header "X-Cdnca-Site-Id: attacker-site" \
          "http://127.0.0.1:${port}${path}")"
        statuses="${statuses}${statuses:+ }${status}"
      done
      printf "%s\n" "${statuses}"
    }

    request_statuses 18080 > /tmp/logs/statuses-normal.txt
    request_statuses 18081 > /tmp/logs/statuses-telemetry-failure.txt
    benchmark_requests=2000
    benchmark_index=0
    while test "${benchmark_index}" -lt "${benchmark_requests}"; do
      curl --silent --fail --output /dev/null "http://127.0.0.1:18082/ok"
      benchmark_index=$((benchmark_index + 1))
    done
    master_pid="$(cat /tmp/logs/cdnca-event-telemetry.pid)"
    "${openresty}" -p /tmp -c /telemetry/syntax-test.conf -s quit
    attempts=0
    while kill -0 "${master_pid}" 2>/dev/null; do
      attempts=$((attempts + 1))
      test "${attempts}" -lt 100
      sleep 0.01
    done
  '

expected_statuses='204 404 500 403'
test "$(cat "${workdir}/logs/statuses-normal.txt")" = "${expected_statuses}"
test "$(cat "${workdir}/logs/statuses-telemetry-failure.txt")" = "${expected_statuses}"
test "$(wc -l < "${workdir}/logs/access.jsonl" | tr -d ' ')" = 4
test "$(wc -l < "${workdir}/logs/security.jsonl" | tr -d ' ')" = 1
test "$(wc -l < "${workdir}/logs/benchmark.jsonl" | tr -d ' ')" = 2000
if grep -F 'secret-value' "${workdir}/logs/access.jsonl"; then
  exit 1
fi

jq -e -s '
  length == 4 and
  map(.status_code) == [204, 404, 500, 403] and
  map(.path) == ["/ok", "/missing", "/error", "/waf-block"] and
  all(.[];
    .schema_version == 1 and
    .type == "access.v1" and
    .tenant_id == "11111111-1111-4111-8111-111111111111" and
    .site_id == "33333333-3333-4333-8333-333333333333" and
    .node_id == "44444444-4444-4444-8444-444444444444" and
    .config_version_id == "55555555-5555-4555-8555-555555555555" and
    (.occurred_at | type == "string" and length > 0) and
    (.request_id | type == "string" and length > 0) and
    .trace_id == "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01" and
    .method == "GET" and
    .protocol == "HTTP/1.1" and
    .cache_status == "BYPASS" and
    (.request_bytes | type == "number" and . > 0) and
    (.response_bytes | type == "number" and . >= 0)
  )
' "${workdir}/logs/access.jsonl" >/dev/null

jq -e -s '
  length == 1 and
  .[0].schema_version == 1 and
  .[0].type == "security.v1" and
  .[0].tenant_id == "11111111-1111-4111-8111-111111111111" and
  .[0].site_id == "33333333-3333-4333-8333-333333333333" and
  .[0].node_id == "44444444-4444-4444-8444-444444444444" and
  .[0].config_version_id == "55555555-5555-4555-8555-555555555555" and
  .[0].path == "/waf-block" and
  .[0].status_code == 403 and
  .[0].security_type == "waf" and
  .[0].action == "block" and
  .[0].severity == "high" and
  .[0].rule_id == "rule-test"
' "${workdir}/logs/security.jsonl" >/dev/null

grep -Eq '(/dev/full|No space left on device)' "${workdir}/logs/error.log"
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go test -race ./internal/eventspool/...
  GOWORK=off go vet ./internal/eventspool/...
  CDNCA_TELEMETRY_BENCH_SOURCE="${workdir}/logs/benchmark.jsonl" \
    GOWORK=off go test ./internal/eventspool -run '^$' \
      -bench '^BenchmarkTelemetryTransport$' -benchmem -benchtime=1x -count=10
  GOWORK=off go build -trimpath -o "${workdir}/event-spool-smoke" ./internal/eventspool/cmd/event-spool-smoke
)
"${workdir}/event-spool-smoke" -mode run -root "${workdir}/run"
