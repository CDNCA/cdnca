#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-waftelemetry.XXXXXX")"
task_marker="cdnca-waftelemetry-$(basename "${workdir}")"
main_container="${task_marker}-main"
missing_container="${task_marker}-missing"

waftelemetry_cleanup() {
    cleanup_status=0
    docker rm -f "${main_container}" "${missing_container}" >/dev/null 2>&1 || true
    for owned_container in "${main_container}" "${missing_container}"; do
        if remaining_ids="$(docker ps -aq --filter "name=^/${owned_container}$" 2>/dev/null)"; then
            if [ -n "${remaining_ids}" ]; then
                echo "cleanup: task container remains: ${owned_container}" >&2
                cleanup_status=1
            fi
        else
            echo "cleanup: could not verify task container removal: ${owned_container}" >&2
            cleanup_status=1
        fi
    done
    case "${workdir}" in
        "${tmp_base%/}"/cdnca-waftelemetry.*) rm -rf -- "${workdir}" || cleanup_status=1 ;;
        *)
            echo "cleanup: refusing unexpected workdir ${workdir}" >&2
            cleanup_status=1
            ;;
    esac
    if [ -e "${workdir}" ]; then
        echo "cleanup: task workdir remains: ${workdir}" >&2
        cleanup_status=1
    fi
    if process_table="$(ps -axo ppid=,command= 2>/dev/null)"; then
        if printf '%s\n' "${process_table}" | awk -v marker="${task_marker}" '
            ($1 + 0) == 1 && index($0, marker) > 0 { found = 1 }
            END { exit(found ? 0 : 1) }
        '; then
            echo "cleanup: PPID=1 process retains task marker: ${task_marker}" >&2
            cleanup_status=1
        fi
    else
        echo "cleanup: could not verify PPID=1 task processes" >&2
        cleanup_status=1
    fi
    return "${cleanup_status}"
}

waftelemetry_on_exit() {
    original_status="$1"
    trap - EXIT HUP INT TERM
    cleanup_status=0
    waftelemetry_cleanup || cleanup_status=$?
    if [ "${original_status}" -ne 0 ]; then
        exit "${original_status}"
    fi
    exit "${cleanup_status}"
}

waftelemetry_on_signal() {
    signal_status="$1"
    trap - EXIT HUP INT TERM
    waftelemetry_cleanup || true
    exit "${signal_status}"
}

waftelemetry_wait_ready() {
    ready_container="$1"
    ready_port="$2"
    attempt=0
    while [ "${attempt}" -lt 50 ]; do
        if docker exec "${ready_container}" curl --fail --silent --show-error \
            "http://127.0.0.1:${ready_port}/ready" >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.1
    done
    docker logs "${ready_container}" >&2 || true
    echo "${ready_container}: OpenResty did not become ready" >&2
    return 1
}

waftelemetry_request() {
    request_container="$1"
    request_port="$2"
    request_path="$3"
    expected_status="$4"
    request_label="$5"
    actual_status="$(docker exec "${request_container}" curl --silent --show-error \
        --output /dev/null --write-out '%{http_code}' \
        "http://127.0.0.1:${request_port}${request_path}")"
    if [ "${actual_status}" != "${expected_status}" ]; then
        echo "${request_label}: expected HTTP ${expected_status}, got ${actual_status}" >&2
        return 1
    fi
}

waftelemetry_assert_event() {
    event_path="$1"
    event_action="$2"
    event_severity="$3"
    event_rule_id="$4"
    jq --exit-status --slurp \
        --arg path "${event_path}" \
        --arg action "${event_action}" \
        --arg severity "${event_severity}" \
        --arg rule_id "${event_rule_id}" '
        [.[] | select(.path == $path)] | last |
        .emit == 1 and .type == "waf" and .action == $action and
        .severity == $severity and .rule_id == $rule_id
    ' "${workdir}/main/security.jsonl" >/dev/null
}

trap 'waftelemetry_on_exit $?' EXIT
trap 'waftelemetry_on_signal 129' HUP
trap 'waftelemetry_on_signal 130' INT
trap 'waftelemetry_on_signal 143' TERM

mkdir -p "${workdir}/main/logs" "${workdir}/missing/logs" "${workdir}/policy"
cp "${repo_root}/edge/openresty/waftelemetry/fixtures/nginx-main.conf" "${workdir}/main/nginx.conf"
cp "${repo_root}/edge/openresty/waftelemetry/fixtures/nginx-missing-vars.conf" "${workdir}/missing/nginx.conf"
cp "${repo_root}/edge/openresty/waftelemetry/fixtures/policy-v1.json" "${workdir}/policy/current.json"
: >"${workdir}/main/error.log"
: >"${workdir}/main/security.jsonl"
: >"${workdir}/missing/error.log"

docker run --detach --name "${main_container}" --network none --read-only \
    --security-opt no-new-privileges \
    --volume "${workdir}/main:/runtime" \
    --volume "${workdir}/policy:/policy:ro" \
    --volume "${repo_root}/edge/openresty/lua/cdnca_waf.lua:/opt/cdnca-waf/cdnca_waf.lua:ro" \
    --entrypoint /usr/local/openresty/bin/openresty \
    "${OPENRESTY_IMAGE}" -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

docker run --detach --name "${missing_container}" --network none --read-only \
    --security-opt no-new-privileges \
    --volume "${workdir}/missing:/runtime" \
    --volume "${workdir}/policy:/policy:ro" \
    --volume "${repo_root}/edge/openresty/lua/cdnca_waf.lua:/opt/cdnca-waf/cdnca_waf.lua:ro" \
    --entrypoint /usr/local/openresty/bin/openresty \
    "${OPENRESTY_IMAGE}" -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

waftelemetry_wait_ready "${main_container}" 18080
waftelemetry_wait_ready "${missing_container}" 18081

# Invalid telemetry must fail closed before touching undeclared nginx variables.
docker exec "${missing_container}" sh -c ': > /runtime/error.log'
waftelemetry_request "${missing_container}" 18081 /invalid-telemetry 403 invalid-telemetry
grep -F 'cdnca_waf decision action=block reason=policy_unavailable rule_id=- policy_version=0' \
    "${workdir}/missing/error.log" >/dev/null
if grep -F 'cdnca_waf reason=telemetry_unavailable' "${workdir}/missing/error.log" >/dev/null; then
    echo "invalid-telemetry: attempted telemetry export" >&2
    exit 1
fi

# Missing variables are best effort for both pass-through and blocking decisions.
docker exec "${missing_container}" sh -c ': > /runtime/error.log'
waftelemetry_request "${missing_container}" 18081 /missing-vars-allow 204 missing-vars-allow
waftelemetry_request "${missing_container}" 18081 /missing-vars-block 403 missing-vars-block
grep -F 'cdnca_waf reason=telemetry_unavailable' "${workdir}/missing/error.log" >/dev/null

waftelemetry_request "${main_container}" 18080 /allow 204 allow
waftelemetry_assert_event /allow allow info allow.match
waftelemetry_request "${main_container}" 18080 /log 204 log
waftelemetry_assert_event /log log info log.match
waftelemetry_request "${main_container}" 18080 /block 403 block
waftelemetry_assert_event /block block high block.match

# The same server policy applies only on its configured access port.
waftelemetry_request "${main_container}" 18080 /access-port 403 access-port-match
waftelemetry_assert_event /access-port block high access-port-block
grep -F 'cdnca_waf reason=rule_block rule_id=access-port-block policy_version=1' \
    "${workdir}/main/error.log" >/dev/null
access_port_event_count="$(wc -l <"${workdir}/main/security.jsonl" | tr -d ' ')"
waftelemetry_request "${main_container}" 18082 /access-port 204 access-port-mismatch
access_port_event_count_after="$(wc -l <"${workdir}/main/security.jsonl" | tr -d ' ')"
test "${access_port_event_count_after}" = "${access_port_event_count}" || {
    echo "access-port-mismatch: emitted a security event" >&2
    exit 1
}

# Continue reaches the later block; stop prevents a later block from overriding allow.
waftelemetry_request "${main_container}" 18080 /continue-stop 403 continue-stop
waftelemetry_assert_event /continue-stop block high continue.block
waftelemetry_request "${main_container}" 18080 /stop 204 stop
waftelemetry_assert_event /stop allow info stop.allow

event_count_before="$(wc -l <"${workdir}/main/security.jsonl" | tr -d ' ')"
waftelemetry_request "${main_container}" 18080 /no-match 204 no-match
waftelemetry_request "${main_container}" 18080 /disabled-block 403 telemetry-disabled
waftelemetry_request "${main_container}" 18080 /legacy-block 403 telemetry-omitted
event_count_after="$(wc -l <"${workdir}/main/security.jsonl" | tr -d ' ')"
test "${event_count_after}" = "${event_count_before}" || {
    echo "no-match or disabled telemetry emitted a security event" >&2
    exit 1
}

waftelemetry_request "${main_container}" 18080 /policy-unavailable 403 policy-unavailable
waftelemetry_assert_event /policy-unavailable block high -

request_query=""
query_index=1
while [ "${query_index}" -le 101 ]; do
    if [ -n "${request_query}" ]; then
        request_query="${request_query}&"
    fi
    request_query="${request_query}f${query_index}=x"
    query_index=$((query_index + 1))
done
waftelemetry_request "${main_container}" 18080 "/request-limit?${request_query}" 403 request-limit
waftelemetry_assert_event /request-limit block high -

# A corrupt candidate keeps the loaded v1 policy; a valid higher version recovers.
cp "${repo_root}/edge/openresty/waftelemetry/fixtures/policy-corrupt.json" "${workdir}/policy/current.json"
sleep 1
waftelemetry_request "${main_container}" 18080 /block 403 corrupt-candidate-lkg
waftelemetry_assert_event /block block high block.match
waftelemetry_request "${main_container}" 18080 /access-port 403 corrupt-candidate-access-port-lkg
waftelemetry_assert_event /access-port block high access-port-block
grep -F 'cdnca_waf reason=policy_rejected rule_id=- policy_version=1' "${workdir}/main/error.log" >/dev/null

cp "${repo_root}/edge/openresty/waftelemetry/fixtures/policy-v2.json" "${workdir}/policy/current.json"
sleep 1
waftelemetry_request "${main_container}" 18080 /recovery 403 higher-version-recovery
waftelemetry_assert_event /recovery block high recovery.block
grep -F 'cdnca_waf reason=policy_loaded rule_id=- policy_version=2' "${workdir}/main/error.log" >/dev/null

# Nginx owns access_log sink errors; they must not alter the WAF response.
waftelemetry_request "${main_container}" 18080 /sink-block 403 security-log-write-failure
grep -F 'write() to "/dev/full" failed' "${workdir}/main/error.log" >/dev/null

concurrent_before="$(wc -l <"${workdir}/main/security.jsonl" | tr -d ' ')"
docker exec "${main_container}" sh -ceu '
    seq 1 64 | xargs -P 8 -I{} sh -ceu '\''
        case $(($1 % 4)) in
            0) path=/allow; expected=204 ;;
            1) path=/log; expected=204 ;;
            2) path=/block; expected=403 ;;
            3) path=/no-match; expected=204 ;;
        esac
        actual=$(curl --silent --show-error --output /dev/null --write-out "%{http_code}" "http://127.0.0.1:18080${path}")
        test "${actual}" = "${expected}"
    '\'' waftelemetry-concurrent {}
'
concurrent_after="$(wc -l <"${workdir}/main/security.jsonl" | tr -d ' ')"
concurrent_delta=$((concurrent_after - concurrent_before))
test "${concurrent_delta}" -eq 48 || {
    echo "concurrency: expected 48 emitted events, got ${concurrent_delta}" >&2
    exit 1
}
tail -n "${concurrent_delta}" "${workdir}/main/security.jsonl" | jq --exit-status --slurp '
    length == 48 and
    ([.[] | select(.action == "allow")] | length) == 16 and
    ([.[] | select(.action == "log")] | length) == 16 and
    ([.[] | select(.action == "block")] | length) == 16
' >/dev/null

jq --exit-status --slurp '
    all(.[];
        .emit == 1 and .type == "waf" and
        (.action == "allow" or .action == "log" or .action == "block") and
        (.severity == "info" or .severity == "high") and
        (.rule_id == "-" or (.rule_id | test("^[A-Za-z0-9._:-]{1,128}$")))
    )
' "${workdir}/main/security.jsonl" >/dev/null

trap - EXIT HUP INT TERM
waftelemetry_cleanup
printf 'WAF_TELEMETRY_SMOKE={"openresty_version":"%s","invalid_options_fail_closed":true,"matched_allow_log_block":true,"access_port_isolation":true,"no_match_suppressed":true,"continue_stop":true,"lkg_rollback":true,"higher_version_recovery":true,"missing_variables_best_effort":true,"sink_failure_best_effort":true,"concurrent_requests":64,"task_containers_remaining":0,"task_ppid1_remaining":0}\n' \
    "${OPENRESTY_VERSION}"
