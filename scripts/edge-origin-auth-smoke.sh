#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
case "${tmp_base}" in
  /*) ;;
  *) echo "TMPDIR must be absolute" >&2; exit 64 ;;
esac
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-origin-auth.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-origin-auth\.//')"
container="cdnca-edge-origin-auth-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-origin-auth.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for command in docker curl openssl; do
  command -v "${command}" >/dev/null 2>&1 || { echo "missing command: ${command}" >&2; exit 69; }
done

install -d -m 0700 "${workdir}/credentials" "${workdir}/policy" "${workdir}/runtime" "${workdir}/runtime/logs"
now="$(date +%s)"
not_before=$((now - 60))
expires_at=$((now + 3600))

s3_access='S3_SMOKE_ACCESS'
s3_secret='S3_SMOKE_SECRET'
s3_token='S3_SMOKE_TOKEN'
oss_access='OSS_SMOKE_ACCESS'
oss_secret='OSS_SMOKE_SECRET'
oss_token='OSS_SMOKE_TOKEN'
cos_access='COS_SMOKE_ACCESS'
cos_secret='COS_SMOKE_SECRET'
cos_token='COS_SMOKE_TOKEN'

write_credential() {
  credential_file="$1"
  credential_provider="$2"
  credential_access="$3"
  credential_secret="$4"
  credential_token="$5"
  printf '%s\n' "{\"schema_version\":\"cdnca.edge.originauth.credential/v1\",\"provider\":\"${credential_provider}\",\"access_key_id\":\"${credential_access}\",\"secret_access_key\":\"${credential_secret}\",\"session_token\":\"${credential_token}\",\"not_before_unix\":${not_before},\"expires_at_unix\":${expires_at}}" >"${credential_file}"
  chmod 0600 "${credential_file}"
}

write_credential "${workdir}/credentials/s3.json" s3 "${s3_access}" "${s3_secret}" "${s3_token}"
write_credential "${workdir}/credentials/oss.json" oss "${oss_access}" "${oss_secret}" "${oss_token}"
write_credential "${workdir}/credentials/cos.json" cos "${cos_access}" "${cos_secret}" "${cos_token}"

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go build -trimpath -o "${workdir}/origin-auth-policy" ./internal/originauth/cmd/origin-auth-policy
)

publish_policy() {
  publish_version="$1"
  "${workdir}/origin-auth-policy" "${workdir}/policy" <<EOF
{
  "schema_version": "cdnca.edge.originauth/v1",
  "policy_version": ${publish_version},
  "rules": [
    {
      "rule_id": "cos-rule",
      "provider": "cos",
      "algorithm": "cos-hmac-sha1",
      "endpoint": "https://smoke-1250000000.cos.ap-guangzhou.myqcloud.com",
      "bucket": "",
      "path_prefix": "/cos/",
      "region": "ap-guangzhou",
      "service": "cos",
      "signature_ttl_seconds": 300,
      "current_key": {"key_id":"cos-current","secret_file":"${workdir}/credentials/cos.json"},
      "activate_current_at_unix": 0
    },
    {
      "rule_id": "oss-rule",
      "provider": "oss",
      "algorithm": "oss4-hmac-sha256",
      "endpoint": "https://smoke-bucket.oss-cn-hangzhou.aliyuncs.com",
      "bucket": "smoke-bucket",
      "path_prefix": "/oss/",
      "region": "cn-hangzhou",
      "service": "oss",
      "signature_ttl_seconds": 300,
      "current_key": {"key_id":"oss-current","secret_file":"${workdir}/credentials/oss.json"},
      "activate_current_at_unix": 0
    },
    {
      "rule_id": "s3-rule",
      "provider": "s3",
      "algorithm": "aws4-hmac-sha256",
      "endpoint": "https://s3-origin.test",
      "bucket": "",
      "path_prefix": "/s3/",
      "region": "test-region-1",
      "service": "s3",
      "signature_ttl_seconds": 300,
      "current_key": {"key_id":"s3-current","secret_file":"${workdir}/credentials/s3.json"},
      "activate_current_at_unix": 0
    }
  ]
}
EOF
}

publish_policy 1 >"${workdir}/publish-v1.log"
test -f "${workdir}/policy/fallback.json"
if grep -F -e "${s3_access}" -e "${s3_secret}" -e "${s3_token}" \
  -e "${oss_access}" -e "${oss_secret}" -e "${oss_token}" \
  -e "${cos_access}" -e "${cos_secret}" -e "${cos_token}" \
  "${workdir}/policy/fallback.json" >/dev/null; then
  echo "origin auth fallback exposed credential material" >&2
  exit 1
fi

cat >"${workdir}/openssl.cnf" <<'EOF'
[req]
distinguished_name = subject
x509_extensions = extensions
prompt = no
[subject]
CN = s3-origin.test
[extensions]
subjectAltName = @names
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
[names]
DNS.1 = s3-origin.test
DNS.2 = smoke-bucket.oss-cn-hangzhou.aliyuncs.com
DNS.3 = smoke-1250000000.cos.ap-guangzhou.myqcloud.com
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -config "${workdir}/openssl.cnf" \
  -keyout "${workdir}/runtime/origin.key" \
  -out "${workdir}/runtime/origin.crt" >/dev/null 2>&1
chmod 0600 "${workdir}/runtime/origin.key" "${workdir}/runtime/origin.crt"

cat >"${workdir}/runtime/nginx.conf" <<EOF
worker_processes 4;
pid ${workdir}/runtime/nginx.pid;
error_log ${workdir}/runtime/error.log notice;

events { worker_connections 1024; }

http {
    access_log off;
    lua_package_path '${repo_root}/edge/openresty/originauth/?.lua;;';
    lua_shared_dict origin_auth_smoke 2m;

    init_worker_by_lua_block {
        require("engine").init({
            policy_path = "${workdir}/policy/current.json",
            reload_interval = 0.05,
        })
    }

    server {
        listen 18443 ssl;
        server_name s3-origin.test smoke-bucket.oss-cn-hangzhou.aliyuncs.com smoke-1250000000.cos.ap-guangzhou.myqcloud.com;
        ssl_certificate ${workdir}/runtime/origin.crt;
        ssl_certificate_key ${workdir}/runtime/origin.key;

        location / {
            content_by_lua_block {
                local raw_headers = ngx.req.get_headers(128, true)
                local headers = {}
                for name, value in pairs(raw_headers) do headers[string.lower(name)] = value end
                local host = headers.host or ngx.var.host
                local authorization = headers.authorization
                local provider
                local prefix
                local token_header
                local expected_token
                local expected_access
                if host == "s3-origin.test" then
                    provider = "s3"
                    prefix = "AWS4-HMAC-SHA256 "
                    token_header = "x-amz-security-token"
                    expected_token = "${s3_token}"
                    expected_access = "${s3_access}"
                elseif host == "smoke-bucket.oss-cn-hangzhou.aliyuncs.com" then
                    provider = "oss"
                    prefix = "OSS4-HMAC-SHA256 "
                    token_header = "x-oss-security-token"
                    expected_token = "${oss_token}"
                    expected_access = "${oss_access}"
                elseif host == "smoke-1250000000.cos.ap-guangzhou.myqcloud.com" then
                    provider = "cos"
                    prefix = "q-sign-algorithm=sha1&"
                    token_header = "x-cos-security-token"
                    expected_token = "${cos_token}"
                    expected_access = "${cos_access}"
                end
                local args = string.lower(ngx.var.args or "")
                local safe_query = not args:find("authorization", 1, true) and not args:find("signature", 1, true)
                    and not args:find("x-amz-", 1, true) and not args:find("x-oss-", 1, true)
                    and not args:find("q-ak", 1, true) and not args:find("security-token", 1, true)
                if not provider or type(authorization) ~= "string" or authorization:sub(1, #prefix) ~= prefix
                    or not authorization:find(expected_access, 1, true) or headers[token_header] ~= expected_token or not safe_query then
                    ngx.status = 502
                    ngx.say("origin-auth-invalid")
                    return
                end
                local metrics = ngx.shared.origin_auth_smoke
                metrics:incr("hits", 1, 0)
                metrics:set(provider .. ":authorization", true)
                metrics:set(provider .. ":token", true)
                if headers.range == "bytes=0-31" then metrics:set(provider .. ":range", true) end
                ngx.header["Cache-Control"] = "no-store"
                ngx.say("origin-ok:" .. provider)
            }
        }
    }

    server {
        listen 18094;

        location /s3/ {
            access_by_lua_block {
                return require("engine").access({rule_id = "s3-rule", endpoint = "https://s3-origin.test"})
            }
            proxy_set_header Host s3-origin.test;
            proxy_ssl_server_name on;
            proxy_ssl_name s3-origin.test;
            proxy_ssl_verify on;
            proxy_ssl_trusted_certificate ${workdir}/runtime/origin.crt;
            proxy_pass https://s3-origin.test:18443;
        }

        location /oss/ {
            access_by_lua_block {
                return require("engine").access({rule_id = "oss-rule", endpoint = "https://smoke-bucket.oss-cn-hangzhou.aliyuncs.com"})
            }
            proxy_set_header Host smoke-bucket.oss-cn-hangzhou.aliyuncs.com;
            proxy_ssl_server_name on;
            proxy_ssl_name smoke-bucket.oss-cn-hangzhou.aliyuncs.com;
            proxy_ssl_verify on;
            proxy_ssl_trusted_certificate ${workdir}/runtime/origin.crt;
            proxy_pass https://smoke-bucket.oss-cn-hangzhou.aliyuncs.com:18443;
        }

        location /cos/ {
            access_by_lua_block {
                return require("engine").access({rule_id = "cos-rule", endpoint = "https://smoke-1250000000.cos.ap-guangzhou.myqcloud.com"})
            }
            proxy_set_header Host smoke-1250000000.cos.ap-guangzhou.myqcloud.com;
            proxy_ssl_server_name on;
            proxy_ssl_name smoke-1250000000.cos.ap-guangzhou.myqcloud.com;
            proxy_ssl_verify on;
            proxy_ssl_trusted_certificate ${workdir}/runtime/origin.crt;
            proxy_pass https://smoke-1250000000.cos.ap-guangzhou.myqcloud.com:18443;
        }
    }

    server {
        listen 18095;
        location = /version {
            content_by_lua_block { ngx.say(ngx.worker.pid(), ":", require("engine").policy_version()) }
        }
        location = /metrics {
            content_by_lua_block {
                local cjson = require("cjson.safe")
                local metrics = ngx.shared.origin_auth_smoke
                ngx.header["Content-Type"] = "application/json"
                ngx.say(cjson.encode({
                    hits = metrics:get("hits") or 0,
                    s3_authorization = metrics:get("s3:authorization") == true,
                    s3_token = metrics:get("s3:token") == true,
                    s3_range = metrics:get("s3:range") == true,
                    oss_authorization = metrics:get("oss:authorization") == true,
                    oss_token = metrics:get("oss:token") == true,
                    oss_range = metrics:get("oss:range") == true,
                    cos_authorization = metrics:get("cos:authorization") == true,
                    cos_token = metrics:get("cos:token") == true,
                    cos_range = metrics:get("cos:range") == true,
                }))
            }
        }
    }
}
EOF

docker run --detach --init \
  --name "${container}" \
  --user "$(id -u):$(id -g)" \
  --add-host s3-origin.test:127.0.0.1 \
  --add-host smoke-bucket.oss-cn-hangzhou.aliyuncs.com:127.0.0.1 \
  --add-host smoke-1250000000.cos.ap-guangzhou.myqcloud.com:127.0.0.1 \
  --publish 127.0.0.1::18094 \
  --publish 127.0.0.1::18095 \
  --volume "${repo_root}/edge/openresty/originauth:${repo_root}/edge/openresty/originauth:ro" \
  --volume "${workdir}:${workdir}" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" \
  -p "${workdir}/runtime/" -c nginx.conf -g 'daemon off;' >/dev/null

edge_published="$(docker port "${container}" 18094/tcp | tail -n 1)"
admin_published="$(docker port "${container}" 18095/tcp | tail -n 1)"
case "${edge_published}:${admin_published}" in
  127.0.0.1:*:127.0.0.1:*) ;;
  *) echo "origin auth smoke ports were not loopback-only: ${edge_published} ${admin_published}" >&2; exit 1 ;;
esac
edge_url="http://${edge_published}"
admin_url="http://${admin_published}"

wait_version() {
  expected_version="$1"
  attempts=0
  : >"${workdir}/worker-pids"
  while [ "${attempts}" -lt 240 ]; do
    value="$(curl --silent --show-error "${admin_url}/version" 2>/dev/null || true)"
    case "${value}" in
      *:"${expected_version}")
        worker_pid="${value%%:*}"
        if ! grep -Fx "${worker_pid}" "${workdir}/worker-pids" >/dev/null; then
          printf '%s\n' "${worker_pid}" >>"${workdir}/worker-pids"
        fi
        if [ "$(wc -l <"${workdir}/worker-pids" | tr -d ' ')" -ge 4 ]; then return 0; fi
        ;;
    esac
    if ! docker inspect --format '{{.State.Running}}' "${container}" 2>/dev/null | grep -Fx true >/dev/null; then
      docker logs "${container}" >&2 || true
      return 1
    fi
    attempts=$((attempts + 1))
    sleep 0.05
  done
  echo "origin auth policy version did not become ${expected_version}" >&2
  cat "${workdir}/runtime/error.log" >&2 2>/dev/null || true
  docker logs "${container}" >&2 || true
  return 1
}

request() {
  request_name="$1"
  shift
  curl --globoff --silent --show-error --fail \
    --dump-header "${workdir}/${request_name}.headers" \
    --output "${workdir}/${request_name}.body" "$@"
}

assert_client_safe() {
  for file in "${workdir}"/*.headers "${workdir}"/*.body; do
    [ -f "${file}" ] || continue
    if grep -F -e "${s3_access}" -e "${s3_secret}" -e "${s3_token}" \
      -e "${oss_access}" -e "${oss_secret}" -e "${oss_token}" \
      -e "${cos_access}" -e "${cos_secret}" -e "${cos_token}" \
      -e 'AWS4-HMAC-SHA256 Credential=' -e 'OSS4-HMAC-SHA256 Credential=' -e 'q-sign-algorithm=sha1' "${file}" >/dev/null; then
      echo "client-visible response exposed origin credential material: ${file}" >&2
      exit 1
    fi
  done
}

wait_version 1
request s3 -H 'Range: bytes=0-31' "${edge_url}/s3/object.txt?versionId=one&response-content-type=text%2Fplain"
request oss -I -H 'Range: bytes=0-31' "${edge_url}/oss/object.txt?acl&versionId=one"
request cos -H 'Range: bytes=0-31' "${edge_url}/cos/object.txt?versionId=one"
grep -Fx 'origin-ok:s3' "${workdir}/s3.body" >/dev/null
grep -Fx 'origin-ok:cos' "${workdir}/cos.body" >/dev/null
assert_client_safe

metrics="$(curl --fail --silent --show-error "${admin_url}/metrics")"
for required in \
  '"s3_authorization":true' '"s3_token":true' '"s3_range":true' \
  '"oss_authorization":true' '"oss_token":true' '"oss_range":true' \
  '"cos_authorization":true' '"cos_token":true' '"cos_range":true'
do
  case "${metrics}" in *"${required}"*) ;; *) echo "missing smoke evidence ${required}: ${metrics}" >&2; exit 1 ;; esac
done

hits_before="$(printf '%s\n' "${metrics}" | sed -n 's/.*"hits":\([0-9][0-9]*\).*/\1/p')"
duplicate_status="$(curl --globoff --silent --show-error --output "${workdir}/duplicate.body" --write-out '%{http_code}' "${edge_url}/s3/object.txt?a=1&%61=2")"
test "${duplicate_status}" = 403
hits_after="$(curl --fail --silent --show-error "${admin_url}/metrics" | sed -n 's/.*"hits":\([0-9][0-9]*\).*/\1/p')"
test "${hits_before}" = "${hits_after}"

cp "${workdir}/policy/current.json" "${workdir}/policy/current.good"
sed 's/"algorithm":"aws4-hmac-sha256"/"algorithm":"aws4-hmac-sha1"/' \
  "${workdir}/policy/current.good" >"${workdir}/policy/current.bad"
chmod 0600 "${workdir}/policy/current.bad"
mv "${workdir}/policy/current.bad" "${workdir}/policy/current.json"
sleep 0.2
wait_version 1
request lkg "${edge_url}/s3/lkg.txt"
grep -Fx 'origin-ok:s3' "${workdir}/lkg.body" >/dev/null

docker kill --signal HUP "${container}" >/dev/null
wait_version 1
request hup-fallback "${edge_url}/cos/hup-fallback.txt"
grep -Fx 'origin-ok:cos' "${workdir}/hup-fallback.body" >/dev/null

docker restart "${container}" >/dev/null
wait_version 1
request restart-fallback "${edge_url}/s3/restart-fallback.txt"
grep -Fx 'origin-ok:s3' "${workdir}/restart-fallback.body" >/dev/null

publish_policy 1 >"${workdir}/restore-v1.log"
wait_version 1

concurrent=0
while [ "${concurrent}" -lt 48 ]; do
  curl --silent --show-error --fail "${edge_url}/s3/concurrent-${concurrent}.txt?part=${concurrent}" \
    >"${workdir}/concurrent-${concurrent}.body" &
  concurrent=$((concurrent + 1))
done
wait
for file in "${workdir}"/concurrent-*.body; do grep -Fx 'origin-ok:s3' "${file}" >/dev/null; done
assert_client_safe

if grep -F -e "${s3_secret}" -e "${s3_token}" -e "${oss_secret}" -e "${oss_token}" \
  -e "${cos_secret}" -e "${cos_token}" "${workdir}/runtime/error.log" >/dev/null 2>&1; then
  echo "OpenResty error log exposed origin credential material" >&2
  exit 1
fi

final_metrics="$(curl --fail --silent --show-error "${admin_url}/metrics")"
printf 'openresty_version=%s\npolicy_version=1\nproviders=s3,oss,cos\ntls_verified=true\nrange_signed=true\nclient_secret_exposure=false\nbad_policy_lkg=true\ndurable_fallback=true\nhup_bad_current_fallback=true\nrestart_bad_current_fallback=true\nconcurrent_requests=48\nEDGE_ORIGIN_AUTH_EVIDENCE=%s\n' \
  "${OPENRESTY_VERSION}" "${final_metrics}"
