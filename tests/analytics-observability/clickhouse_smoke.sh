#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
image=clickhouse/clickhouse-server:25.3.6.56-alpine
capacity_rows=${OBS_CAPACITY_ROWS:-100000}
query_samples=${OBS_QUERY_SAMPLES:-100}
query_concurrency=${OBS_QUERY_CONCURRENCY:-8}
page_size=${OBS_PAGE_SIZE:-137}
query_timeout_seconds=${OBS_QUERY_TIMEOUT_SECONDS:-30}

for numeric_value in "${capacity_rows}" "${query_samples}" "${query_concurrency}" "${page_size}" "${query_timeout_seconds}"; do
  if [[ ! ${numeric_value} =~ ^[1-9][0-9]*$ ]]; then
    printf '%s\n' 'FAIL clickhouse-smoke: row/sample/concurrency/page values must be positive integers' >&2
    exit 2
  fi
done
if [[ ${query_concurrency} -gt 20 ]]; then
  printf '%s\n' 'FAIL clickhouse-smoke: OBS_QUERY_CONCURRENCY must not exceed 20' >&2
  exit 2
fi
query_deadline_seconds=$((query_timeout_seconds + 5))

obs_pg_high_cardinality_audit() {
	local postgres_dsn=${OBS_POSTGRES_DSN:-}
	local postgres_schema=${OBS_POSTGRES_SCHEMA:-public}
	local catalog_result database_name migration_head table_count suspect_count suspect_tables

	if [[ -z ${postgres_dsn} ]]; then
		printf '%s\n' 'FAIL clickhouse-smoke-postgres: OBS_POSTGRES_DSN is required' >&2
		return 2
	fi
	if [[ ! ${postgres_schema} =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
		printf '%s\n' 'FAIL clickhouse-smoke-postgres: OBS_POSTGRES_SCHEMA is invalid' >&2
		return 2
	fi
	if ! command -v psql >/dev/null 2>&1; then
		printf '%s\n' 'SKIP clickhouse-smoke-postgres: psql is unavailable' >&2
		return 77
	fi

	catalog_result=$(PGCONNECT_TIMEOUT="${OBS_POSTGRES_CONNECT_TIMEOUT_SECONDS:-5}" \
		psql "${postgres_dsn}" -qAtX -F $'\t' -v ON_ERROR_STOP=1 \
		--set="obs_schema=${postgres_schema}" <<'SQL'
WITH base_tables AS (
    SELECT
        namespace.nspname AS schema_name,
        relation.relname AS table_name,
        array_agg(attribute.attname ORDER BY attribute.attname) AS columns
    FROM pg_namespace AS namespace
    JOIN pg_class AS relation ON relation.relnamespace = namespace.oid
    JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
    WHERE namespace.nspname = :'obs_schema'
      AND relation.relkind IN ('r', 'p')
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
    GROUP BY namespace.nspname, relation.relname
), suspicious_tables AS (
    SELECT schema_name, table_name
    FROM base_tables
    WHERE lower(table_name) ~ '^(access_events|security_events|access_logs|block_logs|analytics_access_events|analytics_security_events)$'
       OR (
            columns @> ARRAY['tenant_id','event_id','occurred_at','site_id','node_id']::text[]
            AND columns && ARRAY[
                'host','path','client_ip','request_headers','response_headers','request_body','response_body',
                'event_type','severity','status_code','request_bytes','response_bytes'
            ]::text[]
       )
), result AS (
    SELECT
        current_database() AS database_name,
        (SELECT COALESCE(max(version), 0) FROM :"obs_schema".schema_migrations) AS migration_head,
        (SELECT count(*) FROM base_tables) AS table_count,
        count(*) AS suspect_count,
        COALESCE(string_agg(format('%I.%I', schema_name, table_name), ',' ORDER BY schema_name, table_name), '-') AS suspect_tables
    FROM suspicious_tables
)
SELECT database_name, migration_head, table_count, suspect_count, suspect_tables
FROM result;
SQL
	) || {
		printf '%s\n' 'FAIL clickhouse-smoke-postgres: physical catalog query failed' >&2
		return 1
	}

	IFS=$'\t' read -r database_name migration_head table_count suspect_count suspect_tables <<<"${catalog_result}"
	if [[ -z ${database_name} || ! ${migration_head} =~ ^[1-9][0-9]*$ ||
		! ${table_count} =~ ^[1-9][0-9]*$ || ! ${suspect_count} =~ ^[0-9]+$ || -z ${suspect_tables} ]]; then
		printf '%s\n' 'FAIL clickhouse-smoke-postgres: physical catalog result is incomplete' >&2
		return 1
	fi
	if [[ ${suspect_count} -ne 0 || ${suspect_tables} != - ]]; then
		printf 'FAIL clickhouse-smoke-postgres: forbidden raw event tables=%s names=%s\n' \
			"${suspect_count}" "${suspect_tables}" >&2
		return 1
	fi

	printf 'clickhouse-smoke-postgres passed: database=%s schema=%s migration_head=%s base_tables=%s postgres_high_cardinality_tables=0\n' \
		"${database_name}" "${postgres_schema}" "${migration_head}" "${table_count}"
}

if [[ ${1:-} == --postgres-high-cardinality ]]; then
	[[ $# -eq 1 ]] || {
		printf '%s\n' 'FAIL clickhouse-smoke-postgres: unexpected arguments' >&2
		exit 2
	}
	obs_pg_high_cardinality_audit
	exit $?
fi

if [[ ${1:-} == --static-contract ]]; then
  failures=0
  source="${repo_root}/services/control-api/internal/analyticslog/client.go"
	integration_source="${repo_root}/services/control-api/internal/analyticslog/clickhouse_integration_test.go"
  production_queries=''
  for dependency in perl rg sed sort; do
    if ! command -v "${dependency}" >/dev/null 2>&1; then
      printf 'SKIP clickhouse-smoke-static: %s is unavailable\n' "${dependency}" >&2
      exit 77
    fi
  done
	for query_spec in 'accessPageSQL access_event_query_index_state_v1 access_event_query_payload_state_v1' \
		'blockEventPageSQL security_event_query_index_state_v1 security_event_query_payload_state_v1'; do
		read -r query_name table _payload_table <<<"${query_spec}"
    query=$(sed -n "/^const ${query_name} = /,/FORMAT JSONEachRow/p" "${source}" | \
      sed '1s/^[^=]*= .//' | sed '$s/.$//')
    if [[ ${query} != *candidate_event_ids* || ${query} != *"FROM ${table}"* ]]; then
      printf 'FAIL clickhouse-smoke-static: cannot extract production two-stage query %s\n' "${query_name}" >&2
      failures=$((failures + 1))
    fi
		candidate=$(printf '%s' "${query}" | perl -0777 -ne '
			if (/candidate_event_ids\s+AS\s*\(\s*SELECT\s+candidate\.event_id.*?FROM\s*\(\s*(SELECT\s+event_id.*?GROUP\s+BY\s+event_id)\s*\)\s+AS\s+candidate/s) { print $1 }
			elsif (/candidate_event_ids\s+AS\s*\(\s*(SELECT\s+event_id.*?GROUP\s+BY\s+event_id)\s*\)\s*(?:,|SELECT)/s) { print $1 }')
    if [[ -z ${candidate} ]]; then
      printf 'FAIL clickhouse-smoke-static: cannot extract production candidate scan %s\n' "${query_name}" >&2
			failures=$((failures + 1))
		fi
		if [[ ${query_name} == accessPageSQL ]]; then
			for required in access_event_query_payload_state_v1 'argMaxMerge(latest_filter_state)' 'argMaxMerge(latest_payload_state)' \
				'uniqExactMerge(version_pair_state)' 'uniqExactMerge(ingested_at_state)'; do
				if [[ ${query} != *"${required}"* ]]; then
					printf 'FAIL clickhouse-smoke-static: access state query is missing %s\n' "${required}" >&2
					failures=$((failures + 1))
				fi
			done
			if rg -q 'FROM[[:space:]]+access_events([[:space:]]|$)' <<<"${query}"; then
				printf '%s\n' 'FAIL clickhouse-smoke-static: access page SQL still scans raw access_events' >&2
				failures=$((failures + 1))
			fi
		else
			for required in security_event_query_payload_state_v1 'argMaxMerge(latest_filter_state)' 'argMaxMerge(latest_payload_state)' \
				'uniqExactMerge(version_pair_state)' 'uniqExactMerge(ingested_at_state)'; do
				if [[ ${query} != *"${required}"* ]]; then
					printf 'FAIL clickhouse-smoke-static: security state query is missing %s\n' "${required}" >&2
					failures=$((failures + 1))
				fi
			done
			if rg -q 'FROM[[:space:]]+security_events([[:space:]]|$)' <<<"${query}"; then
				printf '%s\n' 'FAIL clickhouse-smoke-static: security page SQL still scans raw security_events' >&2
				failures=$((failures + 1))
			fi
		fi
    production_queries+=$'\n'
    production_queries+="${query}"
	done
	integration_fixture=$(sed -n '/func (database \*integrationDatabase) create/,/^}/p' "${integration_source}")
	if ! perl -0777 -ne 'exit((/"001_analytics\.up\.sql".*"002_analytics_authority_capture\.up\.sql".*"003_analytics_hourly_rollup\.up\.sql".*"004_analytics_version_evidence\.up\.sql".*"005_package_monitor_metrics\.up\.sql".*"006_access_event_state\.up\.sql".*"007_connections_ingest_receipts\.up\.sql".*"008_security_event_state\.up\.sql".*"012_analytics_log_query_projection\.up\.sql"/s) ? 0 : 1)' <<<"${integration_fixture}"; then
		printf '%s\n' 'FAIL clickhouse-smoke-static: integration fixture does not apply analytics state and query projection migrations in order' >&2
		failures=$((failures + 1))
	fi
  parameter_builder=$(sed -n '/^obs_ch_set_production_query_params()/,/^}/p' "${BASH_SOURCE[0]}")
  while IFS= read -r parameter; do
    if ! rg -Fq -- "--param_${parameter}" <<<"${parameter_builder}"; then
      printf 'FAIL clickhouse-smoke-static: production parameter is unbound: %s\n' "${parameter}" >&2
      failures=$((failures + 1))
    fi
  done < <(printf '%s' "${production_queries}" | rg -o '\{[^}:]+:' | tr -d '{:' | LC_ALL=C sort -u)
  pagination_helper=obs_ch_paginate_production
  latency_helper=obs_ch_measure_production_latency
  for kind in access security; do
    if ! rg -q "${pagination_helper}[[:space:]]+${kind}([[:space:]]|$)" "${BASH_SOURCE[0]}"; then
      printf 'FAIL clickhouse-smoke-static: production %s pagination is not wired\n' "${kind}" >&2
      failures=$((failures + 1))
    fi
    if ! rg -q "${latency_helper}[[:space:]]+${kind}([[:space:]]|$)" "${BASH_SOURCE[0]}"; then
      printf 'FAIL clickhouse-smoke-static: production %s capacity latency is not wired\n' "${kind}" >&2
      failures=$((failures + 1))
    fi
  done
  legacy_pagination='SELECT toUnixTimestamp64Milli(occurred_at),event_id FROM access_events'
  legacy_pagination+=' FINAL'
  legacy_latency='--data-binary "SELECT count(),sum(response_bytes) FROM access_events'
  legacy_latency+=' FINAL'
  if rg -Fq -- "${legacy_pagination}" "${BASH_SOURCE[0]}"; then
    printf '%s\n' 'FAIL clickhouse-smoke-static: alternate FINAL pagination query remains' >&2
    failures=$((failures + 1))
  fi
  if rg -Fq -- "${legacy_latency}" "${BASH_SOURCE[0]}"; then
    printf '%s\n' 'FAIL clickhouse-smoke-static: alternate FINAL capacity query remains' >&2
    failures=$((failures + 1))
  fi
  pagination_datasets=$(rg -c 'FROM numbers\(5000\)' "${BASH_SOURCE[0]}" || true)
  if [[ ${pagination_datasets} -lt 2 ]] ||
    ! rg -q '^access_page_pid=\$!$' "${BASH_SOURCE[0]}" ||
    ! rg -q '^security_page_pid=\$!$' "${BASH_SOURCE[0]}"; then
    printf '%s\n' 'FAIL clickhouse-smoke-static: concurrent access/security 5000-row pagination is not wired' >&2
    failures=$((failures + 1))
  fi
  if ! rg -q 'launched.*query_concurrency' "${BASH_SOURCE[0]}"; then
    printf '%s\n' 'FAIL clickhouse-smoke-static: production latency concurrency bound is missing' >&2
    failures=$((failures + 1))
  fi
  if ! rg -q '^obs_ch_candidate_query\(\)' "${BASH_SOURCE[0]}" ||
    ! rg -q 'EXPLAIN indexes=1 \$\{candidate_query\}' "${BASH_SOURCE[0]}"; then
    printf '%s\n' 'FAIL clickhouse-smoke-static: EXPLAIN is not bound to the extracted candidate scan' >&2
    failures=$((failures + 1))
  fi
	executor=$(sed -n '/^obs_ch_exec()/,/^}/p' "${BASH_SOURCE[0]}")
	deadline_executor=$(sed -n '/^obs_ch_with_deadline()/,/^}/p' "${BASH_SOURCE[0]}")
	if rg -Fq -- 'docker exec -i "${container}"' <<<"${executor}"; then
		printf '%s\n' 'FAIL clickhouse-smoke-static: query executor keeps task stdin open unconditionally' >&2
		failures=$((failures + 1))
	fi
	for required in 'local -a docker_exec_args=(docker exec)' "[[ \${argument} == --multiquery ]]" \
		'docker_exec_args+=(-i)' "\"\${docker_exec_args[@]}\""; do
		if ! rg -Fq -- "${required}" <<<"${executor}"; then
			printf 'FAIL clickhouse-smoke-static: query executor stdin policy is missing %s\n' "${required}" >&2
			failures=$((failures + 1))
		fi
	done
	if ! rg -Fq -- '--max_execution_time "${query_timeout_seconds}"' <<<"${executor}" ||
		! rg -Fq -- '--timeout_overflow_mode throw' <<<"${executor}"; then
    printf '%s\n' 'FAIL clickhouse-smoke-static: ClickHouse client timeout is not fail-closed' >&2
    failures=$((failures + 1))
  fi
	for required in "--connect_timeout \"\${query_timeout_seconds}\"" "--send_timeout \"\${query_timeout_seconds}\"" \
		"--receive_timeout \"\${query_timeout_seconds}\"" "obs_ch_with_deadline \"\${query_deadline_seconds}\""; do
		if ! rg -Fq -- "${required}" <<<"${executor}"; then
			printf 'FAIL clickhouse-smoke-static: ClickHouse client deadline is missing %s\n' "${required}" >&2
			failures=$((failures + 1))
		fi
	done
	for required in "kill -TERM \"\${command_pid}\"" "kill -KILL \"\${command_pid}\"" \
		"wait \"\${command_pid}\"" 'clickhouse client deadline exceeded'; do
		if ! rg -Fq -- "${required}" <<<"${deadline_executor}"; then
			printf 'FAIL clickhouse-smoke-static: external deadline is missing %s\n' "${required}" >&2
			failures=$((failures + 1))
		fi
	done
	if ! perl -0777 -ne 'exit(/if kill -TERM "\$\{command_pid\}".*?then\s+timed_out=1/s ? 0 : 1)' \
		<<<"${deadline_executor}"; then
		printf '%s\n' 'FAIL clickhouse-smoke-static: deadline marks timeout before TERM is delivered' >&2
		failures=$((failures + 1))
	fi
	for required in 'local signal_failed=0' 'signal_failed=1' \
		'clickhouse client deadline could not signal running process'; do
		if ! rg -Fq -- "${required}" <<<"${deadline_executor}"; then
			printf 'FAIL clickhouse-smoke-static: deadline signal failure contract is missing %s\n' "${required}" >&2
			failures=$((failures + 1))
		fi
	done
	postgres_audit=$(sed -n '/^obs_pg_high_cardinality_audit()/,/^}/p' "${BASH_SOURCE[0]}")
	for required in "pg_namespace" "pg_class" "pg_attribute" 'schema_migrations' \
		'count(*)' \
		'access_events|security_events|access_logs|block_logs' \
		"ARRAY['tenant_id','event_id','occurred_at','site_id','node_id']" \
		"postgres_high_cardinality_tables=0"; do
		if ! rg -Fq -- "${required}" <<<"${postgres_audit}"; then
			printf 'FAIL clickhouse-smoke-static: PostgreSQL physical catalog audit is missing %s\n' "${required}" >&2
			failures=$((failures + 1))
		fi
	done
	runtime_evidence=$(sed -n '/^tenant=/,$p' "${BASH_SOURCE[0]}")
	for required in "security-aggregate-replacement" "security_raw_aggregate" \
		"security_view_aggregate" "security_aggregate_count_error" \
		"security_aggregate_bytes_error"; do
		if ! rg -Fq -- "${required}" <<<"${runtime_evidence}"; then
			printf 'FAIL clickhouse-smoke-static: security aggregate replay evidence is missing %s\n' "${required}" >&2
			failures=$((failures + 1))
		fi
	done
	if rg -Fq -- 'if ((command_status == 0)); then' <<<"${deadline_executor}"; then
		printf '%s\n' 'FAIL clickhouse-smoke-static: delivered deadline signal does not return canonical 124' >&2
		failures=$((failures + 1))
	fi
	if perl -0777 -ne 'exit(/\(\s*sleep\b.*?\)\s*&/s ? 0 : 1)' <<<"${deadline_executor}" ||
		rg -Fq -- 'watchdog_pid' <<<"${deadline_executor}"; then
		printf '%s\n' 'FAIL clickhouse-smoke-static: external deadline uses an orphan-prone background watchdog' >&2
		failures=$((failures + 1))
	fi
	for required in "deadline_at=\$((SECONDS + deadline_seconds))" \
		"while kill -0 \"\${command_pid}\"" 'sleep 0.1'; do
		if ! rg -Fq -- "${required}" <<<"${deadline_executor}"; then
			printf 'FAIL clickhouse-smoke-static: parent-shell deadline cleanup is missing %s\n' "${required}" >&2
			failures=$((failures + 1))
		fi
	done
	for phase in 'migration file=' 'seed kind=' 'integration kind=analyticslog' 'production-query kind=access operation=pagination' \
    'production-query kind=security operation=pagination' 'capacity-insert kind=access' \
    'capacity-insert kind=security' "production-query kind=\${label} operation=latency" 'cleanup'; do
    if ! rg -Fq -- "obs_ch_phase \"${phase}" "${BASH_SOURCE[0]}"; then
      printf 'FAIL clickhouse-smoke-static: missing phase evidence %s\n' "${phase}" >&2
      failures=$((failures + 1))
    fi
  done
  if [[ ${failures} -ne 0 ]]; then
    printf 'clickhouse-smoke-static failed: findings=%d\n' "${failures}" >&2
    exit 1
  fi
  printf '%s\n' 'clickhouse-smoke-static passed: production_access=extracted production_security=extracted candidate_explain=bound parameters=bound pagination=5000x2-concurrent capacity=production-p95-p99'
  exit 0
fi

suffix="${PPID}-$$-$(date +%s)"
container="cdnca-obs-clickhouse-${suffix}"
network="cdnca-obs-clickhouse-${suffix}"
database="obs_analytics_${PPID}_$$_$(date +%s)"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-obs-clickhouse.XXXXXX")
client_user=obs_probe
client_password=obs_probe_local_only

obs_ch_cleanup() {
  obs_ch_phase "cleanup"
  docker rm -f -v "${container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -rf "${tmp_dir}"
}

obs_ch_phase() {
  printf 'clickhouse-smoke phase=%s\n' "$1" >&2
}

obs_ch_fail() {
  printf 'FAIL clickhouse-smoke: %s\n' "$1" >&2
  if docker inspect "${container}" >/dev/null 2>&1; then
    printf '%s\n' 'ClickHouse container log tail:' >&2
    docker logs --tail 120 "${container}" 2>&1 >&2 || true
  fi
  exit 1
}

obs_ch_with_deadline() {
  local deadline_seconds=$1
  shift
  local command_pid command_status deadline_at grace_at
  local timed_out=0
	local signal_failed=0

  "$@" <&0 &
  command_pid=$!
  deadline_at=$((SECONDS + deadline_seconds))
  while kill -0 "${command_pid}" 2>/dev/null; do
    if ((SECONDS >= deadline_at)); then
			if kill -TERM "${command_pid}" 2>/dev/null; then
				timed_out=1
				grace_at=$((SECONDS + 2))
				while kill -0 "${command_pid}" 2>/dev/null && ((SECONDS < grace_at)); do
					sleep 0.1
				done
				if kill -0 "${command_pid}" 2>/dev/null; then
					kill -KILL "${command_pid}" 2>/dev/null || true
				fi
			elif kill -0 "${command_pid}" 2>/dev/null; then
				signal_failed=1
				kill -KILL "${command_pid}" 2>/dev/null || true
			fi
      break
    fi
    sleep 0.1
  done

  set +e
  wait "${command_pid}"
  command_status=$?
  set -e
	if ((signal_failed)); then
		printf 'FAIL clickhouse-smoke: clickhouse client deadline could not signal running process client_exit=%d\n' \
			"${command_status}" >&2
		return 125
	fi
  if ((timed_out)); then
    printf 'FAIL clickhouse-smoke: clickhouse client deadline exceeded after %ss client_exit=%d\n' \
      "${deadline_seconds}" "${command_status}" >&2
		return 124
  fi
  return "${command_status}"
}

obs_ch_exec() {
	local -a docker_exec_args=(docker exec)
	local argument

	for argument in "$@"; do
		if [[ ${argument} == --multiquery ]]; then
			docker_exec_args+=(-i)
			break
		fi
	done
	docker_exec_args+=("${container}" clickhouse-client)

	obs_ch_with_deadline "${query_deadline_seconds}" "${docker_exec_args[@]}" \
		--user "${client_user}" --password "${client_password}" \
		--connect_timeout "${query_timeout_seconds}" --send_timeout "${query_timeout_seconds}" \
    --receive_timeout "${query_timeout_seconds}" \
    --max_execution_time "${query_timeout_seconds}" --timeout_overflow_mode throw "$@"
}

obs_ch_production_query() {
  local query_name=$1
  local source="${repo_root}/services/control-api/internal/analyticslog/client.go"
  local query

  query=$(sed -n "/^const ${query_name} = /,/FORMAT JSONEachRow/p" "${source}" | \
    sed '1s/^[^=]*= .//' | sed '$s/.$//')
  [[ ${query} == *$'\nFORMAT JSONEachRow' ]] || obs_ch_fail "cannot extract production query ${query_name}"
  printf '%s' "${query%$'\nFORMAT JSONEachRow'}"
}

obs_ch_candidate_query() {
  local production_query=$1
  local candidate

	candidate=$(printf '%s' "${production_query}" | perl -0777 -ne \
		'if (/candidate_event_ids\s+AS\s*\(\s*SELECT\s+candidate\.event_id.*?FROM\s*\(\s*(SELECT\s+event_id.*?GROUP\s+BY\s+event_id)\s*\)\s+AS\s+candidate/s) { print $1 }
		 elsif (/candidate_event_ids\s+AS\s*\(\s*(SELECT\s+event_id.*?GROUP\s+BY\s+event_id)\s*\)\s*(?:,|SELECT)/s) { print $1 }')
  [[ -n ${candidate} ]] || obs_ch_fail 'cannot extract candidate_event_ids scan from production query'
  printf "WITH fromUnixTimestamp64Milli({snapshot_ms:Int64}, 'UTC') AS snapshot_at\n%s" "${candidate}"
}

obs_ch_set_production_query_params() {
  local tenant_id=$1
  local from_ms=$2
  local to_ms=$3
  local has_snapshot=$4
  local snapshot_ms=$5
  local has_cursor=$6
  local cursor_ms=$7
  local cursor_event=$8
  local row_limit=$9

  production_query_params=(
    --param_has_snapshot "${has_snapshot}" --param_snapshot_ms "${snapshot_ms}"
    --param_tenant_id "${tenant_id}" --param_from_ms "${from_ms}" --param_to_ms "${to_ms}"
    --param_has_site 0 --param_site_id "00000000-0000-0000-0000-000000000000"
    --param_has_node 0 --param_node_id "00000000-0000-0000-0000-000000000000"
    --param_has_ip 0 --param_client_ip "::" --param_has_uri_path 0 --param_uri_path "/"
    --param_has_status 0 --param_status_code 0 --param_has_method 0 --param_method GET
    --param_has_protocol 0 --param_protocol "HTTP/2" --param_has_cache 0 --param_cache_status HIT
    --param_has_upstream_result 0 --param_upstream_result success
    --param_has_content_type 0 --param_content_type application/json
    --param_has_user_agent 0 --param_user_agent cdnca-observability-smoke
    --param_has_request_bytes_min 0 --param_request_bytes_min 0
    --param_has_request_bytes_max 0 --param_request_bytes_max 0
    --param_has_response_bytes_min 0 --param_response_bytes_min 0
    --param_has_response_bytes_max 0 --param_response_bytes_max 0
    --param_has_country 0 --param_country_code CN --param_has_carrier 0 --param_carrier probe-carrier
    --param_has_ja4 0 --param_ja4 "" --param_has_origin_connect_min 0 --param_origin_connect_us_min 0
    --param_has_origin_connect_max 0 --param_origin_connect_us_max 0
    --param_has_origin_first_byte_min 0 --param_origin_first_byte_us_min 0
    --param_has_origin_first_byte_max 0 --param_origin_first_byte_us_max 0
    --param_has_origin_total_min 0 --param_origin_total_us_min 0
    --param_has_origin_total_max 0 --param_origin_total_us_max 0
    --param_has_cursor "${has_cursor}" --param_cursor_occurred_at_ms "${cursor_ms}"
    --param_cursor_event_id "${cursor_event}" --param_row_limit "${row_limit}"
  )
}

obs_ch_paginate_production() {
  local label=$1
  local query=$2
  local tenant_id=$3
  local from_ms=$4
  local to_ms=$5
  local ids_file=$6
  local snapshot_ms=0
  local has_snapshot=0
  local cursor_ms=0
  local cursor_event=''
  local has_cursor=0
  local page_number=0
  local page_file
  local rows

  : >"${ids_file}"
  while :; do
    page_file="${tmp_dir}/${label}-production-page-${page_number}.tsv"
    obs_ch_set_production_query_params "${tenant_id}" "${from_ms}" "${to_ms}" \
      "${has_snapshot}" "${snapshot_ms}" "${has_cursor}" "${cursor_ms}" "${cursor_event}" "${page_size}"
    obs_ch_exec --database "${database}" --format TSVRaw "${production_query_params[@]}" \
      --query "${query}" >"${page_file}"
    rows=$(wc -l <"${page_file}" | tr -d ' ')
    [[ ${rows} -gt 0 ]] || break
    cut -f1 "${page_file}" >>"${ids_file}"
    snapshot_ms=$(head -n 1 "${page_file}" | awk -F '\t' '{print $NF}')
    cursor_event=$(tail -n 1 "${page_file}" | cut -f1)
    cursor_ms=$(tail -n 1 "${page_file}" | cut -f2)
    has_snapshot=1
    has_cursor=1
    if [[ ${page_number} -eq 0 ]]; then
      if [[ ${label} == access ]]; then
        obs_ch_exec --database "${database}" --query "INSERT INTO access_events
          (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,
           cache_status,status_code,request_bytes,response_bytes,duration_us)
          SELECT 1,concat('access-page-late-',toString(number)),now64(3,'UTC')-INTERVAL 10 SECOND,
           fromUnixTimestamp64Milli(${snapshot_ms},'UTC')+INTERVAL 1 SECOND,toUUID('${tenant_id}'),toUUID('${site}'),
           toUUID('${node}'),'late.example.test','/late',toIPv6('2001:db8::5'),'GET','HTTP/2','MISS',200,1,1,1
          FROM numbers(100)" >/dev/null
      else
        obs_ch_exec --database "${database}" --query "INSERT INTO security_events
          (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,event_type,action,
           severity,status_code,request_bytes,response_bytes)
          SELECT 1,concat('security-page-late-',toString(number)),now64(3,'UTC')-INTERVAL 10 SECOND,
           fromUnixTimestamp64Milli(${snapshot_ms},'UTC')+INTERVAL 1 SECOND,toUUID('${tenant_id}'),toUUID('${site}'),
           toUUID('${node}'),'late.example.test','/late',toIPv6('2001:db8::5'),'waf','block','high',403,1,1
          FROM numbers(100)" >/dev/null
      fi
    fi
    page_number=$((page_number + 1))
    [[ ${page_number} -le 1000 ]] || obs_ch_fail "production ${label} keyset pagination did not terminate"
  done
  printf '%d\n' "${page_number}" >"${ids_file}.pages"
}

obs_ch_measure_production_latency() {
  local label=$1
  local query=$2
  local tenant_id=$3
  local from_ms=$4
  local to_ms=$5
  local output_file=$6
  local sample=0
  local launched
  local pid
  local started
  local finished
  local latency
  local -a pids

  obs_ch_phase "production-query kind=${label} operation=latency samples=${query_samples} concurrency=${query_concurrency}"
  : >"${output_file}"
  while [[ ${sample} -lt ${query_samples} ]]; do
    launched=0
    pids=()
    while [[ ${launched} -lt ${query_concurrency} && ${sample} -lt ${query_samples} ]]; do
      (
        obs_ch_set_production_query_params "${tenant_id}" "${from_ms}" "${to_ms}" 0 0 0 0 '' 101
        started=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
        obs_ch_exec --database "${database}" --format Null "${production_query_params[@]}" \
          --query "${query}" >/dev/null
        finished=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
        latency=$(awk -v start="${started}" -v finish="${finished}" 'BEGIN {printf "%.6f", finish-start}')
        printf '%s\n' "${latency}" >>"${output_file}"
      ) &
      pids+=("$!")
      sample=$((sample + 1))
      launched=$((launched + 1))
    done
    for pid in "${pids[@]}"; do
      wait "${pid}" || obs_ch_fail "production ${label} capacity query failed"
    done
  done
}

trap obs_ch_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for dependency in docker go rg perl awk sort; do
  if ! command -v "${dependency}" >/dev/null 2>&1; then
    printf 'SKIP clickhouse-smoke: %s is unavailable\n' "${dependency}" >&2
    exit 77
  fi
done
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'SKIP clickhouse-smoke: Docker daemon is unavailable' >&2
  exit 77
fi
if ! docker image inspect "${image}" >/dev/null 2>&1 && ! docker pull "${image}" >/dev/null; then
  printf 'SKIP clickhouse-smoke: fixed image %s is unavailable\n' "${image}" >&2
  exit 77
fi

docker network create "${network}" >/dev/null
docker run -d --name "${container}" --network "${network}" \
  --ulimit nofile=262144:262144 -p 127.0.0.1::8123 \
  -e CLICKHOUSE_DB=default -e CLICKHOUSE_USER="${client_user}" \
  -e CLICKHOUSE_PASSWORD="${client_password}" -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  "${image}" >/dev/null
ready_streak=0
for _ in {1..300}; do
  if obs_ch_exec --query 'SELECT 1' >/dev/null 2>&1; then
    ready_streak=$((ready_streak + 1))
    if [[ ${ready_streak} -ge 3 ]]; then
      break
    fi
  else
    ready_streak=0
  fi
  sleep 0.2
done
[[ ${ready_streak} -ge 3 ]] || obs_ch_fail 'fixed ClickHouse server did not become stably ready'

version=$(obs_ch_exec --format TSVRaw --query 'SELECT version()')
[[ ${version} == 25.3.6.56 ]] || obs_ch_fail "server version=${version}, want 25.3.6.56"
obs_ch_exec --query "CREATE DATABASE ${database}" >/dev/null

migration_count=0
while IFS= read -r migration; do
  obs_ch_phase "migration file=${migration##*/}"
  obs_ch_exec --database "${database}" --multiquery <"${migration}" >/dev/null
  migration_count=$((migration_count + 1))
done < <(find "${repo_root}/infra/clickhouse/migrations" -maxdepth 1 -type f \
  -name '[0-9][0-9][0-9]_*.up.sql' -print | LC_ALL=C sort)
[[ ${migration_count} -ge 1 ]] || obs_ch_fail 'no ClickHouse up migration was applied'

schema=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT name, engine, partition_key, sorting_key FROM system.tables WHERE database='${database}' AND name IN ('access_events','security_events') ORDER BY name")
[[ $(printf '%s\n' "${schema}" | wc -l | tr -d ' ') -eq 2 ]] || obs_ch_fail 'raw access/security tables are missing'
while IFS=$'\t' read -r table engine partition sorting; do
  [[ ${engine} == ReplacingMergeTree ]] || obs_ch_fail "${table} engine=${engine}"
  [[ ${partition} == 'toYYYYMM(occurred_at)' ]] || obs_ch_fail "${table} partition=${partition}"
  [[ ${sorting//[()]/} == 'tenant_id, event_id' ]] || obs_ch_fail "${table} sorting_key=${sorting}"
done <<<"${schema}"

access_ttl=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT create_table_query FROM system.tables WHERE database='${database}' AND name='access_events'")
security_ttl=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT create_table_query FROM system.tables WHERE database='${database}' AND name='security_events'")
rg -qi '(INTERVAL 30 DAY|toIntervalDay\(30\))' <<<"${access_ttl}" || obs_ch_fail 'access TTL is not 30 days'
rg -qi '(INTERVAL 90 DAY|toIntervalDay\(90\))' <<<"${security_ttl}" || obs_ch_fail 'security TTL is not 90 days'

tenant="10000000-0000-4000-8000-000000000001"
site="20000000-0000-4000-8000-000000000001"
node="30000000-0000-4000-8000-000000000001"

obs_ch_phase "seed kind=partition"
obs_ch_exec --database "${database}" --query 'SYSTEM STOP MERGES access_events' >/dev/null
obs_ch_exec --database "${database}" --query 'SYSTEM STOP MERGES security_events' >/dev/null
obs_ch_exec --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,request_id,trace_id,config_version_id,
   host,path,client_ip,country_code,carrier,method,protocol,cache_status,upstream_result,status_code,
   request_bytes,response_bytes,duration_us)
  SELECT 1, concat('partition-', toString(number)),
    if(number=0, toDateTime64(toStartOfMonth(now()) - INTERVAL 1 DAY,3,'UTC'), toDateTime64(now(),3,'UTC')),
    now64(3,'UTC'), toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),concat('request-',toString(number)),
    concat('trace-',toString(number)),'40000000-0000-4000-8000-000000000001','partition.example.test','/partition',
    toIPv6('2001:db8::1'),'CN','probe-carrier','GET','HTTP/2','HIT','ok',200,1,1,1 FROM numbers(2)" >/dev/null
obs_ch_exec --database "${database}" --query "INSERT INTO security_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,request_id,trace_id,config_version_id,
   host,path,client_ip,country_code,carrier,event_type,action,severity,rule_id,status_code,request_bytes,response_bytes)
  SELECT 1, concat('security-partition-', toString(number)),
    if(number=0, toDateTime64(toStartOfMonth(now()) - INTERVAL 1 DAY,3,'UTC'), toDateTime64(now(),3,'UTC')),
    now64(3,'UTC'), toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),concat('security-request-',toString(number)),
    concat('security-trace-',toString(number)),'40000000-0000-4000-8000-000000000001','partition.example.test','/partition',
    toIPv6('2001:db8::1'),'CN','probe-carrier','waf','block','high','partition-rule',403,1,1 FROM numbers(2)" >/dev/null

explain=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "EXPLAIN indexes=1 SELECT count() FROM access_events WHERE toYYYYMM(occurred_at) = toYYYYMM(now())")
printf '%s\n' "${explain}" >"${tmp_dir}/partition-explain.txt"
rg -q 'Partition' "${tmp_dir}/partition-explain.txt" || obs_ch_fail 'EXPLAIN did not expose the partition index'
pruned_ratio=$(rg -o 'Parts:[[:space:]]*[0-9]+/[0-9]+' "${tmp_dir}/partition-explain.txt" | \
  awk '{split($2,parts,"/"); if(parts[1] < parts[2]) {print parts[1] "/" parts[2]; exit}}')
[[ -n ${pruned_ratio} ]] || obs_ch_fail "EXPLAIN did not prune parts: $(tr '\n' ' ' <"${tmp_dir}/partition-explain.txt")"
selected_parts=${pruned_ratio%/*}
total_parts=${pruned_ratio#*/}

production_from_ms=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT toUnixTimestamp64Milli(toDateTime64(toStartOfMonth(now()),3,'UTC'))")
production_to_ms=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT toUnixTimestamp64Milli(toDateTime64(toStartOfMonth(now()) + INTERVAL 1 MONTH,3,'UTC'))")
production_query_params=(
  --param_has_snapshot 0 --param_snapshot_ms "${production_to_ms}"
  --param_tenant_id "${tenant}" --param_from_ms "${production_from_ms}" --param_to_ms "${production_to_ms}"
  --param_has_site 0 --param_site_id "00000000-0000-0000-0000-000000000000"
  --param_has_node 0 --param_node_id "00000000-0000-0000-0000-000000000000"
  --param_has_ip 0 --param_client_ip "::" --param_has_uri_path 0 --param_uri_path "/"
  --param_has_status 0 --param_status_code 0 --param_has_method 0 --param_method GET
  --param_has_protocol 0 --param_protocol "HTTP/2" --param_has_cache 0 --param_cache_status HIT
  --param_has_country 0 --param_country_code CN --param_has_carrier 0 --param_carrier probe-carrier
  --param_has_ja4 0 --param_ja4 "" --param_has_origin_connect_min 0 --param_origin_connect_us_min 0
  --param_has_origin_connect_max 0 --param_origin_connect_us_max 0
  --param_has_origin_first_byte_min 0 --param_origin_first_byte_us_min 0
  --param_has_origin_first_byte_max 0 --param_origin_first_byte_us_max 0
  --param_has_origin_total_min 0 --param_origin_total_us_min 0
  --param_has_origin_total_max 0 --param_origin_total_us_max 0
  --param_has_cursor 0 --param_cursor_occurred_at_ms 0 --param_cursor_event_id "" --param_row_limit 101
)
production_access_query=$(obs_ch_production_query accessPageSQL)
production_block_query=$(obs_ch_production_query blockEventPageSQL)
printf '%s\n' "${production_access_query}" >"${tmp_dir}/production-access.sql"
printf '%s\n' "${production_block_query}" >"${tmp_dir}/production-security.sql"

production_access_parts=unverified
production_security_parts=unverified
for production_spec in "access:${production_access_query}" "security:${production_block_query}"; do
  label=${production_spec%%:*}
  query=${production_spec#*:}
  candidate_query=$(obs_ch_candidate_query "${query}")
  explain_file="${tmp_dir}/production-${label}-explain.txt"
  printf '%s\n' "${candidate_query}" >"${tmp_dir}/production-${label}-candidate.sql"
  obs_ch_exec --database "${database}" --format TSVRaw "${production_query_params[@]}" \
    --query "EXPLAIN indexes=1 ${candidate_query}" >"${explain_file}"
  rg -q 'Partition' "${explain_file}" || obs_ch_fail "production ${label} EXPLAIN did not expose the partition index"
  ratio=$(rg -o 'Parts:[[:space:]]*[0-9]+/[0-9]+' "${explain_file}" | \
    awk '{split($2,parts,"/"); if(parts[1] < parts[2]) {print parts[1] "/" parts[2]; exit}}')
  [[ -n ${ratio} ]] || obs_ch_fail "production ${label} candidate scan did not prune partitions"
  production_selected=${ratio%/*}
  production_total=${ratio#*/}
  [[ ${production_selected} -lt ${production_total} ]] || \
    obs_ch_fail "production ${label} query did not prune partitions: Parts ${ratio}"
  printf -v "production_${label}_parts" '%s' "${ratio}"
done
obs_ch_exec --database "${database}" --query 'SYSTEM START MERGES security_events' >/dev/null

dedup_payload="INSERT INTO access_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,
   cache_status,status_code,request_bytes,response_bytes,duration_us)
  VALUES (1,'response-loss-retry',now64(3,'UTC'),now64(3,'UTC'),toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),
   'retry.example.test','/retry',toIPv6('2001:db8::2'),'POST','HTTP/1.1','MISS',202,10,20,30)"
obs_ch_exec --database "${database}" --insert_deduplication_token obs-response-loss-v1 --query "${dedup_payload}" >/dev/null
obs_ch_exec --database "${database}" --insert_deduplication_token obs-response-loss-v1 --query "${dedup_payload}" >/dev/null
dedup_count=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT count() FROM access_events WHERE event_id='response-loss-retry'")
[[ ${dedup_count} -eq 1 ]] || obs_ch_fail "retry token physical rows=${dedup_count}, want 1"

obs_ch_exec --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,
   cache_status,status_code,request_bytes,response_bytes,duration_us)
  VALUES (1,'replacement-event',now64(3,'UTC')-INTERVAL 2 SECOND,now64(3,'UTC')-INTERVAL 2 SECOND,toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),'replace.example.test','/old',toIPv6('2001:db8::3'),'GET','HTTP/2','MISS',500,1,10,10)" >/dev/null
obs_ch_exec --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,
   cache_status,status_code,request_bytes,response_bytes,duration_us)
  VALUES (1,'replacement-event',now64(3,'UTC')-INTERVAL 2 SECOND,now64(3,'UTC')-INTERVAL 1 SECOND,toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),'replace.example.test','/new',toIPv6('2001:db8::3'),'GET','HTTP/2','MISS',200,1,20,10)" >/dev/null
physical_replacement=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT count() FROM access_events WHERE event_id='replacement-event'")
logical_replacement=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT count() FROM access_events FINAL WHERE event_id='replacement-event'")
replacement_path=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT path FROM access_events FINAL WHERE event_id='replacement-event'")
[[ ${physical_replacement} -eq 2 && ${logical_replacement} -eq 1 && ${replacement_path} == /new ]] || \
  obs_ch_fail "ReplacingMergeTree physical=${physical_replacement} logical=${logical_replacement} path=${replacement_path}"
obs_ch_exec --database "${database}" --query 'SYSTEM START MERGES access_events' >/dev/null

clickhouse_http_port=$(docker port "${container}" 8123/tcp | awk -F: 'NR == 1 {print $NF}')
[[ ${clickhouse_http_port} =~ ^[1-9][0-9]*$ ]] || obs_ch_fail 'cannot resolve task ClickHouse HTTP port'
obs_ch_phase "integration kind=analyticslog scenarios=replacement,equal-time,historical-conflict"
if ! (
  cd "${repo_root}/services/control-api"
  TEST_CLICKHOUSE_URL="http://127.0.0.1:${clickhouse_http_port}" \
    TEST_CLICKHOUSE_REQUIRED=1 TEST_CLICKHOUSE_USERNAME="${client_user}" \
    TEST_CLICKHOUSE_PASSWORD="${client_password}" \
    go test ./internal/analyticslog -run '^TestClickHouseAnalyticsLogIntegration$' -count=1
); then
  obs_ch_fail 'analyticslog ClickHouse integration failed'
fi

access_page_tenant="10000000-0000-4000-8000-000000000010"
security_page_tenant="10000000-0000-4000-8000-000000000011"
obs_ch_exec --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,country_code,carrier,
   method,protocol,cache_status,status_code,request_bytes,response_bytes,duration_us)
  SELECT 1,concat('access-page-',leftPad(toString(number),6,'0')),
   toDateTime64(toStartOfMinute(now()),3,'UTC') + toIntervalMillisecond(number % 1000),
   now64(3,'UTC')-INTERVAL 1 SECOND,toUUID('${access_page_tenant}'),toUUID('${site}'),toUUID('${node}'),
   'page.example.test',concat('/page/',toString(number)),toIPv6('2001:db8::4'),'CN','probe-carrier',
   'GET','HTTP/2','HIT',200,10,100,100 FROM numbers(5000)" >/dev/null
obs_ch_exec --database "${database}" --query "INSERT INTO security_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,country_code,carrier,
   event_type,action,severity,rule_id,status_code,request_bytes,response_bytes)
  SELECT 1,concat('security-page-',leftPad(toString(number),6,'0')),
   toDateTime64(toStartOfMinute(now()),3,'UTC') + toIntervalMillisecond(number % 1000),
   now64(3,'UTC')-INTERVAL 1 SECOND,toUUID('${security_page_tenant}'),toUUID('${site}'),toUUID('${node}'),
   'page.example.test',concat('/page/',toString(number)),toIPv6('2001:db8::4'),'CN','probe-carrier',
   'waf','block','high','page-rule',403,10,100 FROM numbers(5000)" >/dev/null
access_page_ids="${tmp_dir}/access-page-ids.txt"
security_page_ids="${tmp_dir}/security-page-ids.txt"
obs_ch_phase "production-query kind=access operation=pagination rows=5000 page_size=${page_size}"
obs_ch_paginate_production access "${production_access_query}" "${access_page_tenant}" \
  "${production_from_ms}" "${production_to_ms}" "${access_page_ids}" &
access_page_pid=$!
obs_ch_phase "production-query kind=security operation=pagination rows=5000 page_size=${page_size}"
obs_ch_paginate_production security "${production_block_query}" "${security_page_tenant}" \
  "${production_from_ms}" "${production_to_ms}" "${security_page_ids}" &
security_page_pid=$!
wait "${access_page_pid}" || obs_ch_fail 'production access pagination failed'
wait "${security_page_pid}" || obs_ch_fail 'production security pagination failed'
access_paged_total=$(wc -l <"${access_page_ids}" | tr -d ' ')
access_paged_unique=$(LC_ALL=C sort -u "${access_page_ids}" | wc -l | tr -d ' ')
security_paged_total=$(wc -l <"${security_page_ids}" | tr -d ' ')
security_paged_unique=$(LC_ALL=C sort -u "${security_page_ids}" | wc -l | tr -d ' ')
[[ ${access_paged_total} -eq 5000 && ${access_paged_unique} -eq 5000 ]] || \
  obs_ch_fail "production access keyset total=${access_paged_total} unique=${access_paged_unique}, want 5000/5000"
[[ ${security_paged_total} -eq 5000 && ${security_paged_unique} -eq 5000 ]] || \
  obs_ch_fail "production security keyset total=${security_paged_total} unique=${security_paged_unique}, want 5000/5000"
access_page_count=$(<"${access_page_ids}.pages")
security_page_count=$(<"${security_page_ids}.pages")

obs_ch_exec --database "${database}" --query "INSERT INTO security_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,event_type,action,
   severity,rule_id,status_code,request_bytes,response_bytes)
  VALUES
  (1,'security-aggregate-replacement',now64(3,'UTC')-INTERVAL 2 SECOND,now64(3,'UTC')-INTERVAL 2 SECOND,
   toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),'aggregate.example.test','/old',toIPv6('2001:db8::9'),
   'waf','block','high','aggregate-rule',403,10,20),
  (1,'security-aggregate-replacement',now64(3,'UTC')-INTERVAL 2 SECOND,now64(3,'UTC')-INTERVAL 1 SECOND,
   toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),'aggregate.example.test','/new',toIPv6('2001:db8::9'),
   'waf','allow','low','aggregate-rule',200,30,40)" >/dev/null

access_raw_aggregate=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT count(),sum(response_bytes) FROM access_events FINAL WHERE tenant_id=toUUID('${tenant}') AND toStartOfHour(occurred_at,'UTC')=toStartOfHour(now(),'UTC')")
access_view_aggregate=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT sum(request_count),sum(response_bytes) FROM access_hourly_v1 WHERE tenant_id=toUUID('${tenant}') AND hour=toStartOfHour(now(),'UTC')")
raw_count=$(cut -f1 <<<"${access_raw_aggregate}")
raw_bytes=$(cut -f2 <<<"${access_raw_aggregate}")
view_count=$(cut -f1 <<<"${access_view_aggregate}")
view_bytes=$(cut -f2 <<<"${access_view_aggregate}")
aggregate_count_error=$((view_count - raw_count))
aggregate_bytes_error=$((view_bytes - raw_bytes))
[[ ${aggregate_count_error} -lt 0 ]] && aggregate_count_error=$((-aggregate_count_error))
[[ ${aggregate_bytes_error} -lt 0 ]] && aggregate_bytes_error=$((-aggregate_bytes_error))
security_raw_aggregate=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT count(),sum(response_bytes) FROM security_events FINAL WHERE tenant_id=toUUID('${tenant}') AND toStartOfHour(occurred_at,'UTC')=toStartOfHour(now(),'UTC')")
security_view_aggregate=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT sum(event_count),sum(response_bytes) FROM security_hourly_v1 WHERE tenant_id=toUUID('${tenant}') AND hour=toStartOfHour(now(),'UTC')")
security_raw_count=$(cut -f1 <<<"${security_raw_aggregate}")
security_raw_bytes=$(cut -f2 <<<"${security_raw_aggregate}")
security_view_count=$(cut -f1 <<<"${security_view_aggregate}")
security_view_bytes=$(cut -f2 <<<"${security_view_aggregate}")
security_aggregate_count_error=$((security_view_count - security_raw_count))
security_aggregate_bytes_error=$((security_view_bytes - security_raw_bytes))
[[ ${security_aggregate_count_error} -lt 0 ]] && security_aggregate_count_error=$((-security_aggregate_count_error))
[[ ${security_aggregate_bytes_error} -lt 0 ]] && security_aggregate_bytes_error=$((-security_aggregate_bytes_error))
aggregate_max_absolute_error=0
if [[ ${aggregate_count_error} -gt ${aggregate_max_absolute_error} || ${aggregate_bytes_error} -gt ${aggregate_max_absolute_error} ]]; then
  obs_ch_fail "access aggregate/raw absolute error count=${aggregate_count_error} bytes=${aggregate_bytes_error}, threshold=${aggregate_max_absolute_error}"
fi
if [[ ${security_aggregate_count_error} -gt ${aggregate_max_absolute_error} || ${security_aggregate_bytes_error} -gt ${aggregate_max_absolute_error} ]]; then
  obs_ch_fail "security aggregate/raw absolute error count=${security_aggregate_count_error} bytes=${security_aggregate_bytes_error}, threshold=${aggregate_max_absolute_error}"
fi

obs_ch_exec --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,tenant_id,site_id,node_id,host,path,client_ip,method,protocol,cache_status,status_code,request_bytes,response_bytes,duration_us)
  VALUES (1,'ttl-access-expired',now64(3,'UTC')-INTERVAL 31 DAY,toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),'ttl.example.test','/expired',toIPv6('2001:db8::6'),'GET','HTTP/2','MISS',200,1,1,1)" >/dev/null
obs_ch_exec --database "${database}" --query "INSERT INTO security_events
  (metric_version,event_id,occurred_at,tenant_id,site_id,node_id,host,path,client_ip,event_type,action,severity,status_code,request_bytes,response_bytes)
  VALUES
  (1,'ttl-security-retained',now64(3,'UTC')-INTERVAL 60 DAY,toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),'ttl.example.test','/retained',toIPv6('2001:db8::7'),'waf','block','high',403,1,1),
  (1,'ttl-security-expired',now64(3,'UTC')-INTERVAL 91 DAY,toUUID('${tenant}'),toUUID('${site}'),toUUID('${node}'),'ttl.example.test','/expired',toIPv6('2001:db8::8'),'cc','block','high',429,1,1)" >/dev/null
obs_ch_exec --database "${database}" --query 'OPTIMIZE TABLE access_events FINAL' >/dev/null
obs_ch_exec --database "${database}" --query 'OPTIMIZE TABLE security_events FINAL' >/dev/null
access_expired=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT count() FROM access_events FINAL WHERE event_id='ttl-access-expired'")
security_ttl_counts=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT countIf(event_id='ttl-security-retained'),countIf(event_id='ttl-security-expired') FROM security_events FINAL")
[[ ${access_expired} -eq 0 && ${security_ttl_counts} == $'1\t0' ]] || \
  obs_ch_fail "TTL semantics access=${access_expired} security=${security_ttl_counts}"

capacity_started=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
access_capacity_tenant="10000000-0000-4000-8000-000000000099"
security_capacity_tenant="10000000-0000-4000-8000-000000000098"
obs_ch_phase "capacity-insert kind=access rows=${capacity_rows}"
obs_ch_exec --database "${database}" --query "INSERT INTO access_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,country_code,carrier,
   method,protocol,cache_status,upstream_result,status_code,request_bytes,response_bytes,duration_us)
  SELECT 1,concat('capacity-',toString(number)),now64(3,'UTC')-toIntervalMillisecond(number%3600000),now64(3,'UTC'),
   toUUID('${access_capacity_tenant}'),toUUID('20000000-0000-4000-8000-000000000099'),
   toUUID('30000000-0000-4000-8000-000000000099'),'capacity.example.test',concat('/capacity/',toString(number)),
   toIPv6('2001:db8::99'),'CN','capacity-carrier','GET','HTTP/2',if(number%4=0,'MISS','HIT'),'ok',
   if(number%20=0,503,200),100,512+number%4096,1000+number%10000 FROM numbers(${capacity_rows})" >/dev/null
obs_ch_phase "capacity-insert kind=security rows=${capacity_rows}"
obs_ch_exec --database "${database}" --query "INSERT INTO security_events
  (metric_version,event_id,occurred_at,ingested_at,tenant_id,site_id,node_id,host,path,client_ip,country_code,carrier,
   event_type,action,severity,rule_id,status_code,request_bytes,response_bytes)
  SELECT 1,concat('security-capacity-',toString(number)),now64(3,'UTC')-toIntervalMillisecond(number%3600000),
   now64(3,'UTC'),toUUID('${security_capacity_tenant}'),toUUID('20000000-0000-4000-8000-000000000098'),
   toUUID('30000000-0000-4000-8000-000000000098'),'capacity.example.test',concat('/capacity/',toString(number)),
   toIPv6('2001:db8::98'),'CN','capacity-carrier','waf','block','high','capacity-rule',
   if(number%20=0,429,403),100,512+number%4096 FROM numbers(${capacity_rows})" >/dev/null
capacity_finished=$(perl -MTime::HiRes=time -e 'printf "%.6f", time')
capacity_seconds=$(awk -v start="${capacity_started}" -v finish="${capacity_finished}" 'BEGIN {printf "%.6f", finish-start}')
capacity_total_rows=$((capacity_rows * 2))
rows_per_second=$(awk -v rows="${capacity_total_rows}" -v seconds="${capacity_seconds}" 'BEGIN {printf "%.2f", rows/seconds}')
access_capacity_count=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT count() FROM access_events WHERE tenant_id=toUUID('${access_capacity_tenant}')")
security_capacity_count=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT count() FROM security_events WHERE tenant_id=toUUID('${security_capacity_tenant}')")
[[ ${access_capacity_count} -eq ${capacity_rows} && ${security_capacity_count} -eq ${capacity_rows} ]] || \
  obs_ch_fail "capacity rows access=${access_capacity_count} security=${security_capacity_count}, want ${capacity_rows} each"

capacity_from_ms=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT toUnixTimestamp64Milli(now64(3,'UTC')-INTERVAL 2 HOUR)")
capacity_to_ms=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT toUnixTimestamp64Milli(now64(3,'UTC')+INTERVAL 1 MINUTE)")
access_latencies="${tmp_dir}/production-access-latencies.txt"
security_latencies="${tmp_dir}/production-security-latencies.txt"
obs_ch_measure_production_latency access "${production_access_query}" "${access_capacity_tenant}" \
  "${capacity_from_ms}" "${capacity_to_ms}" "${access_latencies}"
obs_ch_measure_production_latency security "${production_block_query}" "${security_capacity_tenant}" \
  "${capacity_from_ms}" "${capacity_to_ms}" "${security_latencies}"
[[ $(wc -l <"${access_latencies}" | tr -d ' ') -eq ${query_samples} ]] || \
  obs_ch_fail 'production access latency sample count mismatch'
[[ $(wc -l <"${security_latencies}" | tr -d ' ') -eq ${query_samples} ]] || \
  obs_ch_fail 'production security latency sample count mismatch'
LC_ALL=C sort -n "${access_latencies}" >"${tmp_dir}/production-access-latencies-sorted.txt"
LC_ALL=C sort -n "${security_latencies}" >"${tmp_dir}/production-security-latencies-sorted.txt"
access_p95=$(awk 'BEGIN{p=.95} {a[NR]=$1} END{i=int(NR*p); if(i<NR*p)i++; if(i<1)i=1; printf "%.6f",a[i]}' "${tmp_dir}/production-access-latencies-sorted.txt")
access_p99=$(awk 'BEGIN{p=.99} {a[NR]=$1} END{i=int(NR*p); if(i<NR*p)i++; if(i<1)i=1; printf "%.6f",a[i]}' "${tmp_dir}/production-access-latencies-sorted.txt")
security_p95=$(awk 'BEGIN{p=.95} {a[NR]=$1} END{i=int(NR*p); if(i<NR*p)i++; if(i<1)i=1; printf "%.6f",a[i]}' "${tmp_dir}/production-security-latencies-sorted.txt")
security_p99=$(awk 'BEGIN{p=.99} {a[NR]=$1} END{i=int(NR*p); if(i<NR*p)i++; if(i<1)i=1; printf "%.6f",a[i]}' "${tmp_dir}/production-security-latencies-sorted.txt")
awk -v value="${access_p95}" 'BEGIN {exit !(value <= 2.0)}' || obs_ch_fail "production access p95=${access_p95}s exceeds 2s"
awk -v value="${access_p99}" 'BEGIN {exit !(value <= 5.0)}' || obs_ch_fail "production access p99=${access_p99}s exceeds 5s"
awk -v value="${security_p95}" 'BEGIN {exit !(value <= 2.0)}' || obs_ch_fail "production security p95=${security_p95}s exceeds 2s"
awk -v value="${security_p99}" 'BEGIN {exit !(value <= 5.0)}' || obs_ch_fail "production security p99=${security_p99}s exceeds 5s"

compressed_bytes=$(obs_ch_exec --database "${database}" --format TSVRaw --query \
  "SELECT sum(bytes_on_disk) FROM system.parts WHERE active AND database='${database}'")
printf 'clickhouse-smoke passed: version=%s migrations=%d partition_parts=%s/%s production_access_parts=%s production_security_parts=%s ttl_access=30d ttl_security=90d retry_physical=%s replacement=%s/%s access_pages=%s access_paged=%s/%s security_pages=%s security_paged=%s/%s aggregate_count_abs_error=%s aggregate_bytes_abs_error=%s security_aggregate_count_abs_error=%s security_aggregate_bytes_abs_error=%s capacity_rows_per_table=%s insert_seconds=%s rows_per_second=%s query_samples_per_kind=%s concurrency=%s access_p95_seconds=%s access_p99_seconds=%s security_p95_seconds=%s security_p99_seconds=%s compressed_bytes=%s\n' \
  "${version}" "${migration_count}" "${selected_parts}" "${total_parts}" "${production_access_parts}" "${production_security_parts}" "${dedup_count}" \
  "${physical_replacement}" "${logical_replacement}" "${access_page_count}" "${access_paged_total}" "${access_paged_unique}" \
	"${security_page_count}" "${security_paged_total}" "${security_paged_unique}" "${aggregate_count_error}" \
	"${aggregate_bytes_error}" "${security_aggregate_count_error}" "${security_aggregate_bytes_error}" \
	"${capacity_rows}" "${capacity_seconds}" "${rows_per_second}" "${query_samples}" \
  "${query_concurrency}" "${access_p95}" "${access_p99}" "${security_p95}" "${security_p99}" "${compressed_bytes}"

obs_ch_exec --query "DROP DATABASE ${database} SYNC" >/dev/null
docker rm -f -v "${container}" >/dev/null
docker network rm "${network}" >/dev/null
if docker ps -a --format '{{.Names}}' | rg -q "^${container}$" || docker network ls --format '{{.Name}}' | rg -q "^${network}$"; then
  obs_ch_fail 'task container or network remained after cleanup'
fi
rm -rf "${tmp_dir}"
trap - EXIT HUP INT TERM
