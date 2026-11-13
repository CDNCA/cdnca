#!/bin/sh
# 用法: [NP_SCRIPT=capture_diff.lua EXTRA_MOUNT=<改前树>:/old:ro] capture_bench.sh [迭代次数]   环境变量 LUA_ROOT 指向被测 edge/openresty（对比改前改后）
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
vars="cdnca_telemetry cdnca_telemetry_client_ip cdnca_tenant_id cdnca_config_version_id cdnca_node_id cdnca_ja4_log cdnca_access_telemetry_json cdnca_security_telemetry_json cdnca_security_policy_id cdnca_security_detector cdnca_security_matched cdnca_security_body cdnca_security_aggregate cdnca_security_user_agent cdnca_security_request_class cdnca_site_tenant cdnca_site_id cdnca_site_port cdnca_telemetry_cache_status cdnca_duration_us cdnca_client_browser cdnca_client_os cdnca_site_generation cdnca_site_scope cdnca_site_digest cdnca_security_path"
extra=""
for v in $vars; do extra="$extra set \$$v \"\";"; done
NP_SERVER_EXTRA="$extra" exec "$here/run.sh" "$here/${NP_SCRIPT:-capture_bench.lua}" "${1:-200000}"
