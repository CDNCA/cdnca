#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
control_api_dir="${repo_root}/services/control-api"
temporary_base=${PLUGIN_WEBHOOK_RUNTIME_TMPDIR:-/tmp}
task_prefix="cdnca-plugin-webhook-runtime-${PPID}-$$"
task_root=$(mktemp -d "${temporary_base%/}/${task_prefix}.XXXXXX")
postgres_data="${task_root}/postgres-data"
postgres_socket="${task_root}/postgres-socket"
postgres_log="${task_root}/postgres.log"
nats_data="${task_root}/nats-data"
nats_log="${task_root}/nats.log"
postgres_bin=${POSTGRES_17_BIN:-}
nats_server=${NATS_SERVER_BIN:-}
postgres_port=''
nats_port=''
nats_monitor_port=''
nats_pid=''

tcp_listener_count() {
	{ lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null || true; } |
		awk 'NR > 1 { count++ } END { print count + 0 }'
}

cleanup() {
	local status=$?
	local streams=unknown
	local process_residual=0
	local listener_residual=0
	local socket_residual=0
	local orphan_residual=0
	trap - EXIT INT TERM

	if [[ -n "${nats_pid}" ]] && kill -0 "${nats_pid}" 2>/dev/null; then
		if curl --fail --silent --show-error \
			"http://127.0.0.1:${nats_monitor_port}/jsz" >"${task_root}/nats-jsz.json" 2>/dev/null; then
			streams=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("streams", -1))' \
				<"${task_root}/nats-jsz.json")
		fi
		kill "${nats_pid}" 2>/dev/null || true
		for _ in {1..100}; do
			kill -0 "${nats_pid}" 2>/dev/null || break
			sleep 0.05
		done
		if kill -0 "${nats_pid}" 2>/dev/null; then
			status=1
		else
			wait "${nats_pid}" 2>/dev/null || true
		fi
	fi
	if [[ -n "${postgres_bin}" && -x "${postgres_bin}/pg_ctl" && -d "${postgres_data}" ]] &&
		"${postgres_bin}/pg_ctl" -D "${postgres_data}" status >/dev/null 2>&1; then
		"${postgres_bin}/pg_ctl" -D "${postgres_data}" -m fast -w stop >/dev/null 2>&1 || status=1
	fi

	if pgrep -f "${task_root}" >/dev/null 2>&1; then
		process_residual=$(pgrep -f "${task_root}" | wc -l | tr -d ' ')
	fi
	if [[ -n "${postgres_port}" ]]; then
		listener_residual=$((listener_residual + $(tcp_listener_count "${postgres_port}")))
	fi
	if [[ -n "${nats_port}" ]]; then
		listener_residual=$((listener_residual + $(tcp_listener_count "${nats_port}")))
	fi
	if [[ -n "${nats_monitor_port}" ]]; then
		listener_residual=$((listener_residual + $(tcp_listener_count "${nats_monitor_port}")))
	fi
	if [[ -d "${postgres_socket}" ]]; then
		socket_residual=$(find "${postgres_socket}" -type s -print | wc -l | tr -d ' ')
	fi
	orphan_residual=$(ps -axo pid=,ppid=,command= | awk -v marker="${task_root}" \
		'$2 == 1 && index($0, marker) > 0 { count++ } END { print count + 0 }')

	if [[ "${streams}" != unknown && "${streams}" != 0 ]]; then
		status=1
	fi
	if ((process_residual != 0 || listener_residual != 0 || socket_residual != 0 || orphan_residual != 0)); then
		status=1
	fi
	if [[ "${task_root}" == "${temporary_base%/}/${task_prefix}."* ]]; then
		trash "${task_root}" || status=1
	else
		printf 'refusing to clean unsafe task root: %s\n' "${task_root}" >&2
		status=1
	fi
	printf 'plugin webhook runtime cleanup: streams=%s process=%s listener=%s socket=%s PPID1=%s\n' \
		"${streams}" "${process_residual}" "${listener_residual}" "${socket_residual}" "${orphan_residual}"
	exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command_name in python3 curl lsof trash; do
	if ! command -v "${command_name}" >/dev/null 2>&1; then
		printf 'missing required command: %s\n' "${command_name}" >&2
		exit 1
	fi
done
if [[ -z "${postgres_bin}" ]]; then
	if ! command -v brew >/dev/null 2>&1; then
		printf '%s\n' 'Homebrew PostgreSQL 17.9 is required' >&2
		exit 1
	fi
	postgres_bin="$(brew --prefix postgresql@17)/bin"
fi
for command_name in initdb pg_ctl pg_isready postgres psql; do
	if [[ ! -x "${postgres_bin}/${command_name}" ]]; then
		printf 'missing PostgreSQL command: %s/%s\n' "${postgres_bin}" "${command_name}" >&2
		exit 1
	fi
done
postgres_version=$("${postgres_bin}/postgres" --version)
if [[ ! "${postgres_version}" =~ ^postgres\ \(PostgreSQL\)\ 17\.9([[:space:]].*)?$ ]]; then
	printf '%s\n' 'PostgreSQL 17.9 is required' >&2
	exit 1
fi
if [[ -z "${nats_server}" ]]; then
	nats_server=$(command -v nats-server || true)
fi
if [[ -z "${nats_server}" || ! -x "${nats_server}" ]]; then
	printf '%s\n' 'NATS_SERVER_BIN must identify a nats-server binary' >&2
	exit 1
fi

free_port() {
	python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
postgres_port=$(free_port)
nats_port=$(free_port)
while [[ "${nats_port}" == "${postgres_port}" ]]; do nats_port=$(free_port); done
nats_monitor_port=$(free_port)
while [[ "${nats_monitor_port}" == "${postgres_port}" || "${nats_monitor_port}" == "${nats_port}" ]]; do
	nats_monitor_port=$(free_port)
done

mkdir -p "${postgres_socket}" "${nats_data}"
"${postgres_bin}/initdb" -D "${postgres_data}" -U postgres --auth=trust --encoding=UTF8 --no-locale >/dev/null
{
	printf "listen_addresses = ''\n"
	printf "unix_socket_directories = '%s'\n" "${postgres_socket}"
	printf 'port = %s\n' "${postgres_port}"
	printf 'max_connections = 20\n'
	printf 'max_locks_per_transaction = 512\n'
} >>"${postgres_data}/postgresql.conf"
if ! "${postgres_bin}/pg_ctl" -D "${postgres_data}" -l "${postgres_log}" -w start >/dev/null; then
	tail -n 80 "${postgres_log}" >&2
	exit 1
fi
if ! "${postgres_bin}/pg_isready" -h "${postgres_socket}" -p "${postgres_port}" -U postgres -d postgres >/dev/null; then
	tail -n 80 "${postgres_log}" >&2
	exit 1
fi
database_url="postgres://postgres@/postgres?host=${postgres_socket}&port=${postgres_port}&sslmode=disable"
settings=$("${postgres_bin}/psql" "${database_url}" -AtX -F '|' -c \
	"SELECT current_setting('server_version'),current_setting('listen_addresses'),current_setting('max_connections'),current_setting('max_locks_per_transaction'),current_setting('unix_socket_directories')")
IFS='|' read -r server_version listen_addresses max_connections max_locks socket_setting <<<"${settings}"
if [[ "${server_version}" != '17.9 (Homebrew)' || -n "${listen_addresses}" ||
	"${max_connections}" != 20 || "${max_locks}" != 512 || "${socket_setting}" != "${postgres_socket}" ||
	"$(tcp_listener_count "${postgres_port}")" != 0 ]]; then
	printf 'invalid PostgreSQL gate: version=%s listen=%q connections=%s locks=%s socket=%s tcp=%s\n' \
		"${server_version}" "${listen_addresses}" "${max_connections}" "${max_locks}" "${socket_setting}" \
		"$(tcp_listener_count "${postgres_port}")" >&2
	exit 1
fi

"${nats_server}" -js -sd "${nats_data}" -a 127.0.0.1 -p "${nats_port}" -m "${nats_monitor_port}" \
	>"${nats_log}" 2>&1 &
nats_pid=$!
nats_ready=0
for _ in {1..100}; do
	if ! kill -0 "${nats_pid}" 2>/dev/null; then break; fi
	if curl --fail --silent --show-error \
		"http://127.0.0.1:${nats_monitor_port}/healthz?js-enabled-only=true" 2>/dev/null |
		grep -Fq '"status":"ok"'; then
		nats_ready=1
		break
	fi
	sleep 0.05
done
if [[ "${nats_ready}" != 1 ]]; then
	tail -n 80 "${nats_log}" >&2
	exit 1
fi
exec 3<>"/dev/tcp/127.0.0.1/${nats_port}"
IFS= read -r -t 5 nats_info <&3
if [[ "${nats_info}" != INFO\ * ]]; then
	printf 'invalid NATS INFO line: %s\n' "${nats_info}" >&2
	exit 1
fi
printf 'CONNECT {"verbose":false,"pedantic":true}\r\nPING\r\n' >&3
nats_response=''
for _ in 1 2 3; do
	IFS= read -r -t 5 nats_response <&3
	nats_response="${nats_response%$'\r'}"
	[[ "${nats_response}" == PONG ]] && break
done
exec 3>&-
if [[ "${nats_response}" != PONG ]]; then
	printf 'NATS protocol readiness failed: %s\n' "${nats_response}" >&2
	exit 1
fi

cd "${control_api_dir}"
env GOWORK=off \
	CDNCA_PLUGIN_WEBHOOK_RUNTIME_DATABASE_URL="${database_url}" \
	CDNCA_PLUGIN_WEBHOOK_RUNTIME_NATS_URL="nats://127.0.0.1:${nats_port}" \
	go test -tags=integration ./internal/pluginwebhookruntime \
	-run '^(TestEnsureJetStreamRequiresPrecreatedResources|TestRuntimePG(SocketNATSFileLifecycle|TwoConnectionLockOrdering))$' -count=1

printf '%s\n' 'plugin webhook runtime smoke passed'
