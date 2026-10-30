#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
example_dir="${repo_root}/examples/plugins/webhook-audit-sink"
task_dir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-plugin-example.XXXXXX")
receiver_pid=""
base_url=""
current_secret="example-current-secret-32-bytes-long"
previous_secret="example-previous-secret-32-bytes-long"
tenant_id="019b143c-7e64-7cc6-b886-a1354a006283"
journal_path="${task_dir}/events.jsonl"
previous_valid_until=$(node -e 'process.stdout.write(new Date(Math.floor(Date.now() / 1000) * 1000 + 3600000).toISOString().replace(".000Z", "Z"))')

stop_receiver() {
  if [[ -n "${receiver_pid}" ]] && kill -0 "${receiver_pid}" 2>/dev/null; then
    kill -TERM "${receiver_pid}" 2>/dev/null || true
    for _ in {1..50}; do
      if ! kill -0 "${receiver_pid}" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "${receiver_pid}" 2>/dev/null; then
      kill -KILL "${receiver_pid}" 2>/dev/null || true
    fi
    wait "${receiver_pid}" 2>/dev/null || true
  fi
  receiver_pid=""
}

cleanup() {
  stop_receiver
  case "${task_dir}" in
    "${TMPDIR:-/tmp}"/cdnca-plugin-example.*) rm -rf "${task_dir}" ;;
  esac
}
trap cleanup EXIT INT TERM

start_receiver() {
  local previous=${1:-}
  local valid_until=${2:-}
  stop_receiver
  rm -f "${task_dir}/ready"
  CDNCA_WEBHOOK_SECRET_CURRENT="${current_secret}" \
    CDNCA_WEBHOOK_SECRET_PREVIOUS="${previous}" \
    CDNCA_WEBHOOK_SECRET_PREVIOUS_VALID_UNTIL="${valid_until}" \
    CDNCA_WEBHOOK_TENANT_ID="${tenant_id}" \
    CDNCA_WEBHOOK_JOURNAL="${journal_path}" \
    CDNCA_WEBHOOK_LISTEN_ADDR="127.0.0.1:0" \
    CDNCA_WEBHOOK_READY_FILE="${task_dir}/ready" \
    "${task_dir}/webhook-audit-sink" >>"${task_dir}/receiver.log" 2>&1 &
  receiver_pid=$!
  for _ in {1..100}; do
    if [[ -s "${task_dir}/ready" ]]; then
      break
    fi
    if ! kill -0 "${receiver_pid}" 2>/dev/null; then
      echo "receiver exited before readiness" >&2
      return 1
    fi
    sleep 0.1
  done
  if [[ ! -s "${task_dir}/ready" ]]; then
    echo "receiver readiness timeout" >&2
    return 1
  fi
  base_url=$(tr -d '\n' <"${task_dir}/ready")
  curl --fail --silent --show-error --max-time 2 "${base_url}/health/ready" >/dev/null
}

expect_receiver_start_failure() {
  stop_receiver
  rm -f "${task_dir}/ready"
  CDNCA_WEBHOOK_SECRET_CURRENT="${current_secret}" \
    CDNCA_WEBHOOK_TENANT_ID="${tenant_id}" \
    CDNCA_WEBHOOK_JOURNAL="${journal_path}" \
    CDNCA_WEBHOOK_LISTEN_ADDR="127.0.0.1:0" \
    CDNCA_WEBHOOK_READY_FILE="${task_dir}/ready" \
    "${task_dir}/webhook-audit-sink" >>"${task_dir}/receiver-failure.log" 2>&1 &
  receiver_pid=$!
  for _ in {1..50}; do
    if ! kill -0 "${receiver_pid}" 2>/dev/null; then
      wait "${receiver_pid}" 2>/dev/null || true
      receiver_pid=""
      if [[ -e "${task_dir}/ready" ]]; then
        echo "invalid journal reached readiness" >&2
        return 1
      fi
      if ! rg -q "invalid journal record" "${task_dir}/receiver-failure.log"; then
        echo "receiver failed for an unexpected reason" >&2
        return 1
      fi
      return 0
    fi
    sleep 0.1
  done
  echo "receiver accepted invalid journal" >&2
  return 1
}

send_event() {
  local expected=$1
  local secret=$2
  local event_id=$3
  local sequence=$4
  shift 4
  CDNCA_PLUGIN_EXAMPLE_URL="${base_url}" \
    CDNCA_PLUGIN_EXAMPLE_SIGNING_SECRET="${secret}" \
    CDNCA_PLUGIN_EXAMPLE_EXPECT_STATUS="${expected}" \
    CDNCA_PLUGIN_EXAMPLE_EVENT_ID="${event_id}" \
    CDNCA_PLUGIN_EXAMPLE_SEQUENCE="${sequence}" \
    "$@" node "${repo_root}/tests/plugin-example/webhook-client.mjs"
}

node "${repo_root}/scripts/validate-marketplace-contracts.mjs"
node "${repo_root}/tests/plugin-example/validate-contracts.mjs"
(
  cd "${example_dir}"
  GOWORK=off go test -count=1 ./...
  GOWORK=off go build -o "${task_dir}/webhook-audit-sink" .
)

touch "${journal_path}"
chmod 0644 "${journal_path}"
start_receiver "${previous_secret}" "${previous_valid_until}"
journal_mode=$(stat -f '%Lp' "${journal_path}" 2>/dev/null || stat -c '%a' "${journal_path}")
if [[ "${journal_mode}" != "600" ]]; then
  echo "journal mode was not tightened to 0600: ${journal_mode}" >&2
  exit 1
fi
send_event 202 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006281" 17
send_event 200 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006281" 17
send_event 409 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006281" 18
send_event 202 "${previous_secret}" "019b143c-7e64-7cc6-b886-a1354a006282" 16
CDNCA_PLUGIN_EXAMPLE_TENANT_ID="019b143c-7e64-7cc6-b886-a1354a006284" \
  send_event 403 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006283" 1
CDNCA_PLUGIN_EXAMPLE_TIMESTAMP_OFFSET=-360 \
  send_event 401 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006284" 1
CDNCA_PLUGIN_EXAMPLE_TAMPER=1 \
  send_event 401 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006285" 1
CDNCA_PLUGIN_EXAMPLE_CONTENT_TYPE="application/json" \
  send_event 415 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006286" 1

concurrent_pids=()
for index in {1..12}; do
  CDNCA_PLUGIN_EXAMPLE_URL="${base_url}" \
    CDNCA_PLUGIN_EXAMPLE_SIGNING_SECRET="${current_secret}" \
    CDNCA_PLUGIN_EXAMPLE_EVENT_ID="019b143c-7e64-7cc6-b886-a1354a006290" \
    CDNCA_PLUGIN_EXAMPLE_SEQUENCE=15 \
    node "${repo_root}/tests/plugin-example/webhook-client.mjs" >"${task_dir}/concurrent-${index}.out" &
  concurrent_pids+=("$!")
done
for pid in "${concurrent_pids[@]}"; do
  wait "${pid}"
done
accepted=$(awk '$1 == 202 {count++} END {print count+0}' "${task_dir}"/concurrent-*.out)
replayed=$(awk '$1 == 200 {count++} END {print count+0}' "${task_dir}"/concurrent-*.out)
if [[ "${accepted}" != "1" || "${replayed}" != "11" ]]; then
  echo "concurrent result mismatch: accepted=${accepted} replayed=${replayed}" >&2
  exit 1
fi

kill -KILL "${receiver_pid}"
wait "${receiver_pid}" 2>/dev/null || true
receiver_pid=""
start_receiver "${previous_secret}" "${previous_valid_until}"
send_event 200 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006281" 17
start_receiver
send_event 401 "${previous_secret}" "019b143c-7e64-7cc6-b886-a1354a006291" 1
send_event 202 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006291" 1

if rg -F "sensitive-fixture-value-must-not-appear-in-journal" "${journal_path}" "${task_dir}/receiver.log"; then
  echo "sensitive event field leaked into journal or logs" >&2
  exit 1
fi
for secret in "${current_secret}" "${previous_secret}"; do
  if rg -F "${secret}" "${journal_path}" "${task_dir}/receiver.log"; then
    echo "webhook secret leaked into journal or logs" >&2
    exit 1
  fi
done

stop_receiver
no_newline_path="${task_dir}/no-newline.jsonl"
printf '%s' '{"event_id":"019b143c-7e64-7cc6-b886-a1354a006298","body_sha256":"3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","received_at":"2026-07-23T08:30:00Z"}' >"${no_newline_path}"
journal_path="${no_newline_path}"
start_receiver
send_event 202 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006297" 1
start_receiver
send_event 200 "${current_secret}" "019b143c-7e64-7cc6-b886-a1354a006297" 1

stop_receiver
cp "${journal_path}" "${task_dir}/partial-tail.jsonl"
printf '{"event_id":' >>"${task_dir}/partial-tail.jsonl"
journal_path="${task_dir}/partial-tail.jsonl"
expect_receiver_start_failure

echo "plugin example smoke: real HTTP, 0600, SIGKILL restart, partial-tail fail-closed, concurrency, rotation, revocation, and redaction passed"
