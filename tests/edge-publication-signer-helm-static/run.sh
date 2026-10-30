#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
chart="$root/infra/helm/cdnca"
values="$chart/values.yaml"
production="$chart/values-production.yaml"
schema="$chart/values.schema.json"
template="$chart/templates/control-api.yaml"
validation="$chart/templates/validation.yaml"

failures=0
require_text() {
  local file="$1" needle="$2"
  if ! rg -Fq -- "$needle" "$file"; then
    printf 'FAIL: %s missing %s\n' "$file" "$needle" >&2
    failures=$((failures + 1))
  fi
}

require_text "$values" 'provider: file'
require_text "$values" '    signer:'
require_text "$schema" '"edgePublishSigner"'
require_text "$template" 'EDGE_PUBLISH_SIGNER_PROVIDER'
require_text "$template" 'EDGE_PUBLISH_SIGNER_REMOTE_ENDPOINT'
require_text "$template" 'EDGE_PUBLISH_SIGNER_REMOTE_CA_FILE'
require_text "$template" 'EDGE_PUBLISH_SIGNER_REMOTE_BEARER_TOKEN_FILE'
require_text "$template" 'EDGE_PUBLISH_SIGNING_PUBLIC_KEY_FILE'
require_text "$template" 'mode: 0600'
require_text "$template" 'eq .Values.controlApi.securityActivation.signer.provider "file"'
require_text "$template" 'eq .Values.controlApi.securityActivation.signer.provider "remote"'
require_text "$validation" 'controlApi.securityActivation.signer.remote.endpoint must be one HTTPS URL'
require_text "$production" '    signer:'

if rg -n '^kind: Secret$|^[[:space:]]+kind: Secret$' "$template" >/dev/null; then
  printf 'FAIL: control-api chart must not create a Secret\n' >&2
  failures=$((failures + 1))
fi

if (( failures > 0 )); then
  printf 'edge publication signer Helm contract: RED (%d failures)\n' "$failures" >&2
  exit 1
fi
printf 'edge publication signer Helm contract: PASS\n'
