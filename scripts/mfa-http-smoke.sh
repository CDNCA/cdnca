#!/bin/sh
set -eu

required='MFA_BASE_URL MFA_BEARER_TOKEN MFA_ACCOUNT_LABEL MFA_TENANT_ID MFA_AUDIENCE MFA_ACTION'
for name in $required; do
  eval "value=\${$name-}"
  if [ -z "$value" ]; then
    echo "$name is required" >&2
    exit 2
  fi
done

case "${MFA_TERMINAL_ACTION:-disable}" in
  disable|reset) ;;
  *) echo 'MFA_TERMINAL_ACTION must be disable or reset' >&2; exit 2 ;;
esac

for command in curl jq openssl python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 2
  fi
done

smoke_tmp=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-mfa-http-smoke.XXXXXX")
chmod 700 "$smoke_tmp"
trap 'rm -rf "$smoke_tmp"' EXIT HUP INT TERM

curl_config="$smoke_tmp/curl.conf"
umask 077
{
  echo 'silent'
  echo 'show-error'
  echo 'fail-with-body'
  printf 'header = "Authorization: Bearer %s"\n' "$MFA_BEARER_TOKEN"
} >"$curl_config"
unset MFA_BEARER_TOKEN

request_id() {
  printf 'mfa-smoke-%s' "$(openssl rand -hex 12)"
}

traceparent() {
  printf '00-%s-%s-01' "$(openssl rand -hex 16)" "$(openssl rand -hex 8)"
}

call_api() {
  method=$1
  path=$2
  output=$3
  expected=$4
  body=${5-}
  idempotency=${6-}
  set -- --config "$curl_config" --request "$method" --output "$output" \
    --header "X-Request-ID: $(request_id)" --header "Traceparent: $(traceparent)"
  if [ -n "$idempotency" ]; then
    set -- "$@" --header "Idempotency-Key: $idempotency"
  fi
  if [ -n "$body" ]; then
    set -- "$@" --header 'Content-Type: application/json' --data-binary "@$body"
  fi
  status=$(curl "$@" --write-out '%{http_code}' "${MFA_BASE_URL%/}$path")
  if [ "$status" != "$expected" ]; then
    echo "unexpected HTTP status for $method $path: $status" >&2
    exit 1
  fi
}

status_file="$smoke_tmp/status.json"
call_api GET /v1/account/mfa "$status_file" 200
jq -e '.status == "inactive" or .status == "enrollment_pending" or .status == "active"' \
  "$status_file" >/dev/null

enroll_key="mfa-smoke-enroll-$(openssl rand -hex 12)"
enroll_body="$smoke_tmp/enroll-request.json"
enroll_response="$smoke_tmp/enroll-response.json"
jq -n --arg account_label "$MFA_ACCOUNT_LABEL" '{account_label:$account_label}' >"$enroll_body"
unset MFA_ACCOUNT_LABEL
call_api POST /v1/account/mfa/enrollments "$enroll_response" 201 "$enroll_body" "$enroll_key"
jq -e '.replayed == false and (.credential_id | type == "string") and
  (.secret | type == "string") and (.provisioning_uri | type == "string")' \
  "$enroll_response" >/dev/null
credential_id=$(jq -er '.credential_id' "$enroll_response")

enroll_replay="$smoke_tmp/enroll-replay.json"
call_api POST /v1/account/mfa/enrollments "$enroll_replay" 200 "$enroll_body" "$enroll_key"
jq -e '.replayed == true and has("secret") == false and has("provisioning_uri") == false' \
  "$enroll_replay" >/dev/null

activate_key="mfa-smoke-activate-$(openssl rand -hex 12)"
activate_body="$smoke_tmp/activate-request.json"
activate_response="$smoke_tmp/activate-response.json"
totp_file="$smoke_tmp/totp-code"
python3 - "$enroll_response" "$totp_file" <<'PY'
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time

try:
    with open(sys.argv[1], "r", encoding="utf-8") as source:
        secret = json.load(source)["secret"]
    if not isinstance(secret, str) or not secret:
        raise ValueError
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    descriptor = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, f"{binary % 1000000:06d}".encode("ascii"))
    finally:
        os.close(descriptor)
except Exception:
    raise SystemExit("failed to derive enrollment TOTP")
PY
jq -n --rawfile code "$totp_file" '{code:$code}' >"$activate_body"
rm -f "$totp_file"
call_api POST "/v1/account/mfa/enrollments/$credential_id/activate" \
	"$activate_response" 201 "$activate_body" "$activate_key"
jq -e '.replayed == false and (.recovery_codes | length == 10)' "$activate_response" >/dev/null

activate_replay="$smoke_tmp/activate-replay.json"
call_api POST "/v1/account/mfa/enrollments/$credential_id/activate" \
	"$activate_replay" 200 "$activate_body" "$activate_key"
jq -e '.replayed == true and has("recovery_codes") == false' "$activate_replay" >/dev/null

proof_key="mfa-smoke-proof-$(openssl rand -hex 12)"
proof_body="$smoke_tmp/proof-request.json"
proof_response="$smoke_tmp/proof-response.json"
proof_code_file="$smoke_tmp/proof-code"
jq -j -e -r '.recovery_codes[0]' "$activate_response" >"$proof_code_file"
jq -n --arg tenant_id "$MFA_TENANT_ID" --arg audience "$MFA_AUDIENCE" \
	--arg action "$MFA_ACTION" --rawfile code "$proof_code_file" \
	'{tenant_id:$tenant_id,audience:$audience,action:$action,
    authentication:{method:"recovery_code",code:$code},ttl_seconds:60,max_uses:1}' >"$proof_body"
rm -f "$proof_code_file"
unset MFA_TENANT_ID MFA_AUDIENCE MFA_ACTION
call_api POST /v1/account/mfa/step-up-proofs "$proof_response" 201 "$proof_body" "$proof_key"
jq -e '.replayed == false and (.token | type == "string")' "$proof_response" >/dev/null

proof_replay="$smoke_tmp/proof-replay.json"
call_api POST /v1/account/mfa/step-up-proofs "$proof_replay" 200 "$proof_body" "$proof_key"
jq -e '.replayed == true and has("token") == false' "$proof_replay" >/dev/null

terminal_key="mfa-smoke-${MFA_TERMINAL_ACTION:-disable}-$(openssl rand -hex 12)"
terminal_body="$smoke_tmp/terminal-request.json"
terminal_response="$smoke_tmp/terminal-response"
terminal_code_file="$smoke_tmp/terminal-code"
jq -j -e -r '.recovery_codes[1]' "$activate_response" >"$terminal_code_file"
jq -n --rawfile code "$terminal_code_file" \
	'{authentication:{method:"recovery_code",code:$code},reason:"mfa HTTP smoke"}' >"$terminal_body"
rm -f "$terminal_code_file"
call_api POST "/v1/account/mfa/${MFA_TERMINAL_ACTION:-disable}" \
	"$terminal_response" 204 "$terminal_body" "$terminal_key"
if [ -s "$terminal_response" ]; then
  echo 'terminal response unexpectedly contained a body' >&2
  exit 1
fi
call_api POST "/v1/account/mfa/${MFA_TERMINAL_ACTION:-disable}" \
	"$terminal_response" 204 "$terminal_body" "$terminal_key"

call_api GET /v1/account/mfa "$status_file" 200
jq -e '.status == "inactive" and has("credential_id") == false and has("method") == false' \
  "$status_file" >/dev/null

echo 'MFA HTTP smoke passed; sensitive response files were not printed.'
