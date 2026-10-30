#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
failures=0

obs_static_fail() {
  printf 'FAIL static-contract: %s\n' "$1" >&2
  failures=$((failures + 1))
}

obs_static_require() {
  local pattern=$1
  local path=$2
  local label=$3
  if ! rg -q --glob '!**/*_test.go' --glob '!tests/analytics-observability/**' "${pattern}" "${path}"; then
    obs_static_fail "${label}"
  fi
}

obs_static_require_raw_time_bounds() {
  local query_name=$1
  local index_table=$2
  local payload_table=$3
  local query
  local candidate_scan
  local latest_scan

  query=$(sed -n "/^const ${query_name} = /,/FORMAT JSONEachRow/p" "${log_client}" | \
    sed '1s/^[^=]*= .//' | sed '$s/.$//')
  candidate_scan=$(printf '%s' "${query}" | perl -0777 -ne \
    "if (/candidate_event_ids\\s+AS\\s*\\(\\s*SELECT\\s+event_id\\s+FROM\\s+${index_table}\\s+(.*?)GROUP\\s+BY\\s+event_id\\s*\\)/s) { print \$1 }")
  latest_scan=$(printf '%s' "${query}" | perl -0777 -ne \
    "if (/SELECT\\s+event_id\\s*,\\s*latest_filter_state\\s*,\\s*version_pair_state\\s*,\\s*ingested_at_state\\s+FROM\\s+${index_table}\\s+(.*?)\\)\\s+AS\\s+[a-z_]+\\s+INNER\\s+JOIN\\s+candidate_event_ids\\s+USING\\s*\\(event_id\\)/s) { print \$1 }")
  if [[ -z ${candidate_scan} || -z ${latest_scan} ]]; then
    obs_static_fail "cannot extract ${index_table} candidate/latest-state scans from ${query_name}"
    return
  fi
  if ! rg -q 'occurred_at[[:space:]]*>=[[:space:]]*fromUnixTimestamp64Milli\(\{from_ms:Int64\}' <<<"${candidate_scan}" ||
    ! rg -q 'occurred_at[[:space:]]*<[[:space:]]*fromUnixTimestamp64Milli\(\{to_ms:Int64\}' <<<"${candidate_scan}" ||
    ! rg -q 'ingested_at[[:space:]]*<=[[:space:]]*snapshot_at' <<<"${candidate_scan}"; then
    obs_static_fail "${query_name} candidate scan does not bind occurred_at and snapshot"
  fi
  if ! rg -q 'ingested_at[[:space:]]*<=[[:space:]]*snapshot_at' <<<"${latest_scan}" ||
    ! rg -q 'INNER[[:space:]]+JOIN[[:space:]]+candidate_event_ids[[:space:]]+USING[[:space:]]*\(event_id\)' <<<"${query}"; then
    obs_static_fail "${query_name} latest-state scan is not candidate- and snapshot-bound"
  fi
  if rg -q 'occurred_at[[:space:]]*(>=|<)[[:space:]]*fromUnixTimestamp64Milli\(\{(from|to)_ms:Int64\}' <<<"${latest_scan}"; then
    obs_static_fail "${query_name} incorrectly applies the mutable occurred_at window before latest resolution"
  fi
  if ! rg -q 'tupleElement\(latest_filter,[[:space:]]*1\)[[:space:]]*>=[[:space:]]*fromUnixTimestamp64Milli\(\{from_ms:Int64\}' <<<"${query}" ||
    ! rg -q 'tupleElement\(latest_filter,[[:space:]]*1\)[[:space:]]*<[[:space:]]*fromUnixTimestamp64Milli\(\{to_ms:Int64\}' <<<"${query}"; then
    obs_static_fail "${query_name} does not reapply the occurrence window to latest rows"
  fi
  if ! rg -q "FROM[[:space:]]+${payload_table}" <<<"${query}" ||
    ! rg -q 'event_id[[:space:]]+IN[[:space:]]*\(SELECT[[:space:]]+event_id[[:space:]]+FROM[[:space:]]+selected_rows\)' <<<"${query}"; then
    obs_static_fail "${query_name} payload scan is not bounded by selected_rows"
  fi
}

for dependency in perl rg; do
  if ! command -v "${dependency}" >/dev/null 2>&1; then
    printf 'SKIP static-contract: %s is unavailable\n' "${dependency}" >&2
    exit 77
  fi
done

compose_file="${repo_root}/compose.yaml"
migration_dir="${repo_root}/infra/clickhouse/migrations"
edge_publication="${repo_root}/agents/edge-agent/internal/eventspool/publication.go"
gateway_validation="${repo_root}/services/agent-gateway/telemetry_validation.go"
control_ingest="${repo_root}/services/control-api/internal/analytics/ingest_nats.go"
log_client="${repo_root}/services/control-api/internal/analyticslog/client.go"

for required in "${compose_file}" "${migration_dir}/001_analytics.up.sql" \
  "${edge_publication}" "${gateway_validation}" "${control_ingest}" "${log_client}"; do
  if [[ ! -r "${required}" ]]; then
    obs_static_fail "required production input is unreadable: ${required#"${repo_root}/"}"
  fi
done

if ! rg -q 'image:[[:space:]]*clickhouse/clickhouse-server:25\.3\.6\.56-alpine([[:space:]]|$)' "${compose_file}"; then
  obs_static_fail 'compose does not pin ClickHouse 25.3.6.56-alpine'
fi

migration_files=()
while IFS= read -r migration; do
  migration_files+=("${migration}")
done < <(find "${migration_dir}" -maxdepth 1 -type f \
  -name '[0-9][0-9][0-9]_*.up.sql' -print | LC_ALL=C sort)
if [[ ${#migration_files[@]} -eq 0 || ${migration_files[0]} != "${migration_dir}/001_analytics.up.sql" ]]; then
  obs_static_fail 'ordered ClickHouse migration set does not begin with 001_analytics.up.sql'
fi

migration_text=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-static.XXXXXX")
trap 'rm -f "${migration_text}"' EXIT HUP INT TERM
for migration in "${migration_files[@]}"; do
  printf '\n-- %s\n' "${migration##*/}" >>"${migration_text}"
  sed -E '/^[[:space:]]*--/d' "${migration}" >>"${migration_text}"
done

for table in access_events security_events; do
  if ! rg -qi "CREATE[[:space:]]+TABLE[[:space:]]+(IF[[:space:]]+NOT[[:space:]]+EXISTS[[:space:]]+)?${table}([[:space:](]|$)" "${migration_text}"; then
    obs_static_fail "missing raw ClickHouse table ${table}"
  fi
done

partition_count=$( (rg -oi 'PARTITION[[:space:]]+BY[[:space:]]+toYYYYMM\([[:space:]]*occurred_at[[:space:]]*\)' "${migration_text}" || true) | wc -l | tr -d ' ')
if [[ ${partition_count} -lt 2 ]]; then
  obs_static_fail "monthly raw partition clauses=${partition_count}, want at least 2"
fi
if ! rg -qi 'TTL[[:space:]].*occurred_at.*INTERVAL[[:space:]]+30[[:space:]]+DAY[[:space:]]+DELETE' "${migration_text}"; then
  obs_static_fail 'access raw TTL is not 30 days'
fi
if ! rg -qi 'TTL[[:space:]].*occurred_at.*INTERVAL[[:space:]]+90[[:space:]]+DAY[[:space:]]+DELETE' "${migration_text}"; then
  obs_static_fail 'security raw TTL is not 90 days'
fi
replacing_count=$( (rg -oi 'ReplacingMergeTree' "${migration_text}" || true) | wc -l | tr -d ' ')
if [[ ${replacing_count} -lt 2 ]]; then
  obs_static_fail 'raw tables are not both retry-deduplicating ReplacingMergeTree tables'
fi

for field in request_id task_id trace_id config_version_id node_id tenant_id site_id installation_id; do
  if ! rg -qi "(^|[^a-z0-9_])${field}([^a-z0-9_]|$)" "${migration_text}"; then
    obs_static_fail "raw schema is missing correlation field ${field}"
  fi
done

for header in Nats-Msg-Id Cdnca-Node-Id Cdnca-Tenant-Id Cdnca-Site-Id \
  Cdnca-Config-Version-Id Cdnca-Installation-Id; do
  if [[ ${header} == Nats-Msg-Id ]] && rg -q 'MsgIdHdr|Nats-Msg-Id' "${control_ingest}" "${repo_root}/services/agent-gateway"; then
    continue
  fi
  if ! rg -q "${header}" "${control_ingest}" "${repo_root}/services/agent-gateway"; then
    obs_static_fail "authoritative NATS header is missing from control/gateway sources: ${header}"
  fi
done
if ! rg -q 'cdnca\.analytics\.ingest\.v1' "${edge_publication}" "${repo_root}/services/agent-gateway" "${control_ingest}"; then
  obs_static_fail 'authoritative analytics v1 subject is missing'
fi

obs_static_require 'occurred_at' "${log_client}" 'analytics log query does not reference occurred_at'
obs_static_require 'event_id' "${log_client}" 'analytics log query does not reference event_id'
obs_static_require 'snapshot' "${log_client}" 'analytics log query does not bind a snapshot'
obs_static_require_raw_time_bounds accessPageSQL access_event_query_index_state_v1 access_event_query_payload_state_v1
obs_static_require_raw_time_bounds blockEventPageSQL security_event_query_index_state_v1 security_event_query_payload_state_v1

# Downstream strict-v1 publication and validation must carry already-redacted,
# allowlisted capture fields. Authoritative EdgeConfig/OpenResty source capture
# remains a separate mandatory finding in authority_capture_source_red.sh.
for field in request_headers response_headers request_body response_body; do
  if ! rg -Fq "json:\"${field}" "${edge_publication}"; then
    obs_static_fail "BLOCKED_CAPTURE_WIRE edge analytics v1 publication drops ${field}"
  fi
  if ! rg -Fq "json:\"${field}" "${gateway_validation}"; then
    obs_static_fail "BLOCKED_CAPTURE_WIRE gateway strict analytics v1 rejects ${field}"
  fi
done

postgres_paths=("${repo_root}/services/control-api/migrations")
[[ -d "${repo_root}/infra/postgres" ]] && postgres_paths+=("${repo_root}/infra/postgres")
if rg -ni --glob '*.sql' \
  'CREATE[[:space:]]+TABLE[[:space:]]+(IF[[:space:]]+NOT[[:space:]]+EXISTS[[:space:]]+)?([^[:space:](]+\.)?"?(access_events|security_events|access_logs|block_logs|analytics_access_events|analytics_security_events)"?([[:space:](]|$)' \
  "${postgres_paths[@]}"; then
  obs_static_fail 'PostgreSQL migration creates a forbidden high-cardinality access/security log table'
fi

rm -f "${migration_text}"
trap - EXIT HUP INT TERM

if [[ ${failures} -ne 0 ]]; then
  printf 'static-contract failed: findings=%d migrations=%d\n' "${failures}" "${#migration_files[@]}" >&2
  exit 1
fi

printf 'static-contract passed: migrations=%d postgres_high_cardinality_tables=0 capture_wire=allowlisted_and_redacted raw_partition_bounds=verified\n' \
  "${#migration_files[@]}"
