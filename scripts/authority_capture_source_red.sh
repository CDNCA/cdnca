#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/.." && pwd)
telemetry_go="${repo_root}/libs/edgeconfig/telemetry.go"
access_format="${repo_root}/edge/openresty/telemetry/access-json.conf"
security_format="${repo_root}/edge/openresty/telemetry/security-json.conf"

manifest_block=$(sed -n '/^type TelemetryIdentityManifest struct/,/^}/p' "${telemetry_go}")
render_block=$(sed -n '/^func renderTelemetryFormats/,/^}/p' "${telemetry_go}")
openresty_formats=$(printf '%s\n%s\n' "$(<"${access_format}")" "$(<"${security_format}")")
findings=0

if ! rg -Fq 'capture_policy' <<<"${manifest_block}"; then
  printf '%s\n' 'RED SOURCE_MANIFEST: signed telemetry identity has no versioned capture policy' >&2
  findings=$((findings + 1))
fi

for field in request_headers response_headers request_body response_body installation_id task_id ja4 \
  origin_connect_us origin_first_byte_us origin_total_us; do
  if ! rg -Fq "${field}" <<<"${render_block}"; then
    printf 'RED SOURCE_EDGE_CONFIG: rendered source does not emit %s\n' "${field}" >&2
    findings=$((findings + 1))
  fi
  if ! rg -Fq "${field}" <<<"${openresty_formats}"; then
    printf 'RED SOURCE_OPENRESTY: pinned source does not emit %s\n' "${field}" >&2
    findings=$((findings + 1))
  fi
done

printf 'OBS12_SOURCE_AUDIT={"findings":%d,"expected":21}\n' "${findings}"
if [[ ${findings} -ne 0 ]]; then
  exit 1
fi
