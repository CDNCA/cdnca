#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
telemetry_go="${repo_root}/libs/edgeconfig/telemetry.go"
composition_go="${repo_root}/libs/edgeconfig/config.go"
access_format="${repo_root}/edge/openresty/telemetry/access-json.conf"
security_format="${repo_root}/edge/openresty/telemetry/security-json.conf"

for source in "${telemetry_go}" "${composition_go}" "${access_format}" "${security_format}"; do
  [[ -r ${source} ]] || {
    printf 'FAIL authority-capture-source-red: unreadable source %s\n' "${source#"${repo_root}/"}" >&2
    exit 2
  }
done

render_block=$(sed -n '/^func renderTelemetryFormats/,/^}/p' "${telemetry_go}")
manifest_block=$(sed -n '/^type TelemetryIdentityManifest struct/,/^}/p' "${telemetry_go}")
composition_block=$(sed -n '/^func render(spec normalizedSpec)/,/^}/p' "${composition_go}")
openresty_formats=$(printf '%s\n%s\n' "$(<"${access_format}")" "$(<"${security_format}")")
findings=0

if ! rg -Fq 'renderTelemetryFormats(&output)' "${composition_go}"; then
  printf '%s\n' 'RED SOURCE_COMPOSITION: signed bundle does not call renderTelemetryFormats' >&2
  findings=$((findings + 1))
fi
if ! rg -Fq 'access_log ' <<<"${composition_block}" || ! rg -Fq 'cdnca_access_json' <<<"${composition_block}"; then
  printf '%s\n' 'RED SOURCE_COMPOSITION: site config does not mount the production access format' >&2
  findings=$((findings + 1))
fi
if ! rg -Fq 'access_log ' <<<"${composition_block}" || ! rg -Fq 'cdnca_security_json' <<<"${composition_block}"; then
  printf '%s\n' 'RED SOURCE_COMPOSITION: site config does not mount the production security format' >&2
  findings=$((findings + 1))
fi
if ! rg -Fq 'capture_policy' <<<"${manifest_block}"; then
  printf '%s\n' 'RED SOURCE_MANIFEST: signed telemetry identity has no versioned capture policy' >&2
  findings=$((findings + 1))
fi

for field in request_headers response_headers request_body response_body installation_id task_id ja4 \
  origin_connect_us origin_first_byte_us origin_total_us; do
  if ! rg -Fq "${field}" <<<"${render_block}"; then
    printf 'RED SOURCE_EDGE_CONFIG: production rendered log format does not emit %s\n' "${field}" >&2
    findings=$((findings + 1))
  fi
  if ! rg -Fq "${field}" <<<"${openresty_formats}"; then
    printf 'RED SOURCE_OPENRESTY: pinned access/security JSONL does not emit %s\n' "${field}" >&2
    findings=$((findings + 1))
  fi
done

printf 'authority-capture-source evidence: telemetry_sha=%s config_sha=%s access_format_sha=%s security_format_sha=%s findings=%d\n' \
  "$(shasum -a 256 "${telemetry_go}" | awk '{print $1}')" \
  "$(shasum -a 256 "${composition_go}" | awk '{print $1}')" \
  "$(shasum -a 256 "${access_format}" | awk '{print $1}')" \
  "$(shasum -a 256 "${security_format}" | awk '{print $1}')" \
  "${findings}"

if [[ ${findings} -ne 0 ]]; then
	printf 'FAIL authority-capture-source-red: authoritative capture source is incomplete\n' >&2
	exit 1
fi

printf '%s\n' 'authority-capture-source passed: signed formats, site sinks, capture policy, and fields are production-wired'
