#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-http-policy.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-http-policy\.//')"
container="cdnca-http-policy-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-http-policy.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/state" "${workdir}/bad-state" "${workdir}/divergent-state" \
  "${workdir}/client-body" "${workdir}/concurrent"
chmod 0700 "${workdir}/state" "${workdir}/bad-state" "${workdir}/divergent-state" \
  "${workdir}/client-body" "${workdir}/concurrent"

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/http-policy" ./internal/httppolicy/cmd/http-policy
)

cat >"${workdir}/policy-v1.json" <<'EOF'
{
  "schema_version": "cdnca.edge.http-policy/v1",
  "policy_version": 1,
  "sites": [{
    "site_id": "site-a",
    "max_upload_bytes": 16,
    "request_headers": [
      {"kind":"add","name":"X-Multi","values":["edge-a","edge-b"]},
      {"kind":"set","name":"X-Set","values":["fixed-a","fixed-b"]},
      {"kind":"delete","name":"X-Delete","values":[]}
    ],
    "response_headers": [
      {"kind":"add","name":"X-Response-Multi","values":["edge-a","edge-b"]},
      {"kind":"set","name":"X-Response-Set","values":["fixed-a","fixed-b"]},
      {"kind":"delete","name":"X-Response-Delete","values":[]}
    ],
    "rewrites": [
      {"rule_id":"chain-1","priority":1,"match_kind":"exact","match_path":"/start","target_path":"/middle","preserve_query":true,"preserve_cookie":true},
      {"rule_id":"chain-2","priority":2,"match_kind":"exact","match_path":"/middle","target_path":"/origin/final","preserve_query":true,"preserve_cookie":true},
      {"rule_id":"drop","priority":3,"match_kind":"exact","match_path":"/drop","target_path":"/origin/drop","preserve_query":false,"preserve_cookie":false},
      {"rule_id":"loop-a","priority":4,"match_kind":"exact","match_path":"/loop-a","target_path":"/loop-b","preserve_query":true,"preserve_cookie":true},
      {"rule_id":"loop-b","priority":5,"match_kind":"exact","match_path":"/loop-b","target_path":"/loop-a","preserve_query":true,"preserve_cookie":true}
    ],
    "redirect_allowed_hosts": ["127.0.0.1:18082","[::1]:18082"],
    "redirects": [
      {"rule_id":"redirect-v4","priority":1,"match_kind":"exact","match_path":"/go","status":307,"target_url":"http://127.0.0.1:18082/landing","preserve_query":true},
      {"rule_id":"redirect-v6","priority":2,"match_kind":"exact","match_path":"/go-v6","status":308,"target_url":"http://[::1]:18082/landing-v6","preserve_query":false}
    ],
    "cors": {
      "allowed_origins": ["https://app.example.test"],
      "allowed_methods": ["GET","POST"],
      "allowed_headers": ["x-token"],
      "exposed_headers": ["x-response-set"],
      "allow_credentials": true,
      "max_age_seconds": 600
    },
    "referer_check": {
      "allow_empty": true,
      "allow_same_domain": true,
      "allowed_domains": ["*.partner.example.test", "cdn.friend.example.test"],
      "denied_domains": ["bad.partner.example.test"],
      "check_origin": true,
      "extensions": ["jpg", "png"]
    }
  }]
}
EOF

sed 's/"policy_version": 1/"policy_version": 2/' "${workdir}/policy-v1.json" >"${workdir}/policy-v2.json"
sed -e 's/"policy_version": 1/"policy_version": 2/' \
  -e 's/"max_upload_bytes": 16/"max_upload_bytes": 15/' \
  "${workdir}/policy-v1.json" >"${workdir}/policy-v2-divergent.json"
cat >"${workdir}/invalid-crlf.json" <<'EOF'
{"schema_version":"cdnca.edge.http-policy/v1","policy_version":2,"sites":[{"site_id":"site-a","max_upload_bytes":16,"request_headers":[{"kind":"set","name":"x-test","values":["ok\r\nInjected: yes"]}],"response_headers":[],"rewrites":[],"redirect_allowed_hosts":[],"redirects":[],"cors":null,"referer_check":null}]}
EOF
cat >"${workdir}/invalid-identity.json" <<'EOF'
{"schema_version":"cdnca.edge.http-policy/v1","policy_version":2,"sites":[{"site_id":"site-a","max_upload_bytes":16,"request_headers":[{"kind":"set","name":"x-cdnca-tenant-id","values":["forged"]}],"response_headers":[],"rewrites":[],"redirect_allowed_hosts":[],"redirects":[],"cors":null,"referer_check":null}]}
EOF
cat >"${workdir}/invalid-redirect.json" <<'EOF'
{"schema_version":"cdnca.edge.http-policy/v1","policy_version":2,"sites":[{"site_id":"site-a","max_upload_bytes":16,"request_headers":[],"response_headers":[],"rewrites":[],"redirect_allowed_hosts":["safe.example.test"],"redirects":[{"rule_id":"open","priority":1,"match_kind":"exact","match_path":"/go","status":302,"target_url":"https://evil.example.test/","preserve_query":true}],"cors":null,"referer_check":null}]}
EOF
cat >"${workdir}/invalid-referer.json" <<'EOF'
{"schema_version":"cdnca.edge.http-policy/v1","policy_version":2,"sites":[{"site_id":"site-a","max_upload_bytes":16,"request_headers":[],"response_headers":[],"rewrites":[],"redirect_allowed_hosts":[],"redirects":[],"cors":null,"referer_check":{"allow_empty":true,"allow_same_domain":false,"allowed_domains":[],"denied_domains":[],"check_origin":false,"extensions":[]}}]}
EOF
cat >"${workdir}/invalid-cors.json" <<'EOF'
{"schema_version":"cdnca.edge.http-policy/v1","policy_version":2,"sites":[{"site_id":"site-a","max_upload_bytes":16,"request_headers":[],"response_headers":[],"rewrites":[],"redirect_allowed_hosts":[],"redirects":[],"cors":{"allowed_origins":["*"],"allowed_methods":["GET"],"allowed_headers":[],"exposed_headers":[],"allow_credentials":true,"max_age_seconds":60},"referer_check":null}]}
EOF

"${workdir}/http-policy" -input "${workdir}/policy-v1.json" -state-root "${workdir}/state" >"${workdir}/publish-v1.txt"
"${workdir}/http-policy" -input "${workdir}/policy-v2-divergent.json" \
  -state-root "${workdir}/divergent-state" >"${workdir}/publish-divergent.txt"
before_invalid="$(shasum -a 256 "${workdir}/state/committed.json" | awk '{print $1}')"
for invalid in invalid-crlf invalid-identity invalid-redirect invalid-cors invalid-referer; do
  if "${workdir}/http-policy" -input "${workdir}/${invalid}.json" -state-root "${workdir}/state" \
    >"${workdir}/${invalid}.out" 2>"${workdir}/${invalid}.err"; then
    echo "${invalid} policy was accepted" >&2
    exit 1
  fi
done
after_invalid="$(shasum -a 256 "${workdir}/state/committed.json" | awk '{print $1}')"
test "${before_invalid}" = "${after_invalid}"
mkdir "${workdir}/bad-state/versions"
chmod 0700 "${workdir}/bad-state/versions"
cp "${workdir}/state/versions/00000000000000000001.json" "${workdir}/bad-state/versions/"
sed 's/"sha256":"[0-9a-f]*"/"sha256":"0000000000000000000000000000000000000000000000000000000000000000"/' \
  "${workdir}/state/committed.json" >"${workdir}/bad-state/committed.json"
chmod 0600 "${workdir}/bad-state/versions/00000000000000000001.json" \
  "${workdir}/bad-state/committed.json"

printf '1234567890123456' >"${workdir}/body-16"
printf '12345678901234567' >"${workdir}/body-17"

cat >"${workdir}/nginx.conf" <<'EOF'
worker_processes 1;
error_log /work/error.log notice;
pid /work/nginx.pid;

events { worker_connections 2048; }

http {
  lua_package_path "/opt/cdnca/httppolicy/?.lua;;";
  lua_shared_dict origin_metrics 1m;
  access_log off;
  server_tokens off;
  client_body_temp_path /work/client-body;

  upstream smoke_origin { server 127.0.0.1:18082; }

  server {
    listen 127.0.0.1:18082;
    listen [::1]:18082 ipv6only=on;
    server_name _;

    location = /_count {
      content_by_lua_block {
        local dict = ngx.shared.origin_metrics
        ngx.say("count=" .. tostring(dict:get("count") or 0) .. " bytes=" .. tostring(dict:get("bytes") or 0))
      }
    }

    location / {
      content_by_lua_block {
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if not body then
          local path = ngx.req.get_body_file()
          if path then
            local file = io.open(path, "rb")
            body = file and file:read("*a") or ""
            if file then file:close() end
          end
        end
        body = body or ""
        local dict = ngx.shared.origin_metrics
        dict:incr("count", 1, 0)
        dict:incr("bytes", #body, 0)
        local headers = ngx.req.get_headers()
        local function joined(value)
          if type(value) == "table" then return table.concat(value, "|") end
          return value or ""
        end
        ngx.header["X-Seen-Multi"] = joined(headers["x-multi"])
        ngx.header["X-Seen-Set"] = joined(headers["x-set"])
        ngx.header["X-Seen-Delete"] = joined(headers["x-delete"])
        ngx.header["X-Response-Multi"] = {"origin-a", "origin-b"}
        ngx.header["X-Response-Set"] = "origin"
        ngx.header["X-Response-Delete"] = "secret"
        ngx.header["X-Origin-Body-Bytes"] = tostring(#body)
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("uri=" .. (ngx.var.uri or ""))
        ngx.say("args=" .. (ngx.var.args or ""))
        ngx.say("cookie=" .. (headers["cookie"] or ""))
        ngx.say("bytes=" .. tostring(#body))
      }
    }
  }

  server {
    listen 18081;
    listen [::]:18081 ipv6only=on;
    server_name _;
    location / {
      client_max_body_size 16;
      client_body_buffer_size 8;
      proxy_request_buffering on;
      access_by_lua_block {
        return require("engine").access({
          state_root = "/work/state",
          site_id = "site-a",
        })
      }
      header_filter_by_lua_block { return require("engine").header_filter() }
      proxy_pass http://smoke_origin;
    }
  }

  server {
    listen 18083;
    http2 on;
    server_name _;
    location / {
      client_max_body_size 16;
      client_body_buffer_size 8;
      proxy_request_buffering on;
      access_by_lua_block {
        return require("engine").access({
          state_root = "/work/state",
          site_id = "site-a",
        })
      }
      header_filter_by_lua_block { return require("engine").header_filter() }
      proxy_pass http://smoke_origin;
    }
  }

  server {
    listen 18084;
    server_name _;
    location / {
      client_max_body_size 16;
      proxy_request_buffering on;
      access_by_lua_block {
        return require("engine").access({
          state_root = "/work/bad-state",
          site_id = "site-a",
        })
      }
      proxy_pass http://smoke_origin;
    }
  }
}
EOF

docker run --detach \
  --name "${container}" \
  --volume "${workdir}:/work" \
  --volume "${repo_root}/edge/openresty/httppolicy:/opt/cdnca/httppolicy:ro" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" \
  -g 'daemon off;' -p /work/ -c nginx.conf >/dev/null

attempt=0
while ! docker exec "${container}" curl --noproxy '*' --silent --fail http://127.0.0.1:18081/ready >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 50 ]; then
    docker logs "${container}" >&2 || true
    cat "${workdir}/error.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done

status_request() {
  output="$1"
  shift
  status="$(docker exec "${container}" curl --noproxy '*' --silent --show-error \
    --dump-header "/work/${output}.headers" --output "/work/${output}.body" \
    --write-out '%{http_code}' "$@")"
  tr -d '\r' <"${workdir}/${output}.headers" >"${workdir}/${output}.headers.clean"
  mv "${workdir}/${output}.headers.clean" "${workdir}/${output}.headers"
  printf '%s' "${status}"
}

origin_count() {
  docker exec "${container}" curl --noproxy '*' --silent --fail http://127.0.0.1:18082/_count
}

test "$(status_request headers -H 'X-Multi: client-a' -H 'x-multi: client-b' \
  -H 'X-Set: client' -H 'X-Delete: secret' http://127.0.0.1:18081/headers)" = 200
grep -Fx 'X-Seen-Multi: client-a|client-b|edge-a|edge-b' "${workdir}/headers.headers" >/dev/null
grep -Fx 'X-Seen-Set: fixed-a|fixed-b' "${workdir}/headers.headers" >/dev/null
if grep -Fqi 'X-Seen-Delete:' "${workdir}/headers.headers"; then
  echo "deleted request header reached the origin" >&2
  exit 1
fi
test "$(grep -Fic 'X-Response-Multi:' "${workdir}/headers.headers")" = 4
grep -Fqi 'X-Response-Multi: origin-a' "${workdir}/headers.headers"
grep -Fqi 'X-Response-Multi: origin-b' "${workdir}/headers.headers"
grep -Fqi 'X-Response-Multi: edge-a' "${workdir}/headers.headers"
grep -Fqi 'X-Response-Multi: edge-b' "${workdir}/headers.headers"
test "$(grep -Fic 'X-Response-Set:' "${workdir}/headers.headers")" = 2
if grep -Fqi 'X-Response-Delete:' "${workdir}/headers.headers"; then
  echo "deleted response header reached the client" >&2
  exit 1
fi
grep -Fqi 'X-CDNCA-HTTP-Policy-Version: 1' "${workdir}/headers.headers"

test "$(status_request rewrite -H 'Cookie: session=abc' 'http://127.0.0.1:18081/start?token=1')" = 200
grep -Fx 'uri=/origin/final' "${workdir}/rewrite.body" >/dev/null
grep -Fx 'args=token=1' "${workdir}/rewrite.body" >/dev/null
grep -Fx 'cookie=session=abc' "${workdir}/rewrite.body" >/dev/null
test "$(status_request drop -H 'Cookie: session=abc' 'http://127.0.0.1:18081/drop?token=1')" = 200
grep -Fx 'uri=/origin/drop' "${workdir}/drop.body" >/dev/null
grep -Fx 'args=' "${workdir}/drop.body" >/dev/null
grep -Fx 'cookie=' "${workdir}/drop.body" >/dev/null

before_loop="$(origin_count)"
test "$(status_request loop http://127.0.0.1:18081/loop-a)" = 508
test "$(origin_count)" = "${before_loop}"

test "$(status_request redirect-v4 'http://127.0.0.1:18081/go?token=1')" = 307
grep -Fqi 'Location: http://127.0.0.1:18082/landing?token=1' "${workdir}/redirect-v4.headers"
test "$(status_request redirect-v6 http://127.0.0.1:18081/go-v6)" = 308
grep -Fqi 'Location: http://[::1]:18082/landing-v6' "${workdir}/redirect-v6.headers"
test "$(status_request encoded-query 'http://127.0.0.1:18081/headers?next=%250d%250aInjected')" = 400
test "$(status_request encoded-path 'http://127.0.0.1:18081/safe/%252e%252e/private')" = 400

before_cors="$(origin_count)"
test "$(status_request preflight -X OPTIONS -H 'Origin: https://app.example.test' \
  -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: X-Token' \
  http://127.0.0.1:18081/cors)" = 204
grep -Fqi 'Access-Control-Allow-Origin: https://app.example.test' "${workdir}/preflight.headers"
grep -Fqi 'Access-Control-Allow-Credentials: true' "${workdir}/preflight.headers"
grep -Fqi 'Access-Control-Allow-Methods: GET, POST' "${workdir}/preflight.headers"
grep -Fqi 'Access-Control-Allow-Headers: x-token' "${workdir}/preflight.headers"
test "$(origin_count)" = "${before_cors}"
test "$(status_request cors-denied -X OPTIONS -H 'Origin: https://evil.example.test' \
  -H 'Access-Control-Request-Method: POST' http://127.0.0.1:18081/cors)" = 403
test "$(origin_count)" = "${before_cors}"
test "$(status_request cors-actual -H 'Origin: https://app.example.test' http://127.0.0.1:18081/cors)" = 200
grep -Fqi 'Access-Control-Expose-Headers: x-response-set' "${workdir}/cors-actual.headers"

# Hotlink protection (ge-waf S8): only .jpg/.png are checked.
before_hotlink="$(origin_count | sed 's/^count=\([0-9]*\).*/\1/')"
test "$(status_request hotlink-empty http://127.0.0.1:18081/a.jpg)" = 200
test "$(status_request hotlink-same -H 'Host: img.example.test' -H 'Referer: https://img.example.test/page' http://127.0.0.1:18081/a.jpg)" = 200
test "$(status_request hotlink-wildcard -H 'Referer: https://www.partner.example.test/x' http://127.0.0.1:18081/a.PNG)" = 200
test "$(status_request hotlink-exact -H 'Referer: http://cdn.friend.example.test:8080/' http://127.0.0.1:18081/a.jpg)" = 200
test "$(status_request hotlink-apex -H 'Referer: https://partner.example.test/' http://127.0.0.1:18081/a.jpg)" = 403
test "$(status_request hotlink-denied -H 'Referer: https://bad.partner.example.test/' http://127.0.0.1:18081/a.jpg)" = 403
test "$(status_request hotlink-other -H 'Referer: https://evil.example.test/' http://127.0.0.1:18081/a.jpg)" = 403
grep -Fqi 'X-Cdnca-Referer-Check: rejected' "${workdir}/hotlink-other.headers"
test "$(status_request hotlink-origin -H 'Origin: https://evil.example.test' http://127.0.0.1:18081/a.jpg)" = 403
test "$(status_request hotlink-garbage -H 'Referer: not a url' http://127.0.0.1:18081/a.jpg)" = 403
test "$(status_request hotlink-suffix-trick -H 'Referer: https://evilpartner.example.test/' http://127.0.0.1:18081/a.jpg)" = 403
test "$(status_request hotlink-page -H 'Referer: https://evil.example.test/' http://127.0.0.1:18081/page.html)" = 200
after_hotlink="$(origin_count | sed 's/^count=\([0-9]*\).*/\1/')"
test "${after_hotlink}" = "$((before_hotlink + 5))"

test "$(status_request upload-boundary -X POST --data-binary @/work/body-16 http://127.0.0.1:18081/upload)" = 200
grep -Fx 'bytes=16' "${workdir}/upload-boundary.body" >/dev/null
before_over="$(origin_count)"
test "$(status_request upload-over -X POST --data-binary @/work/body-17 http://127.0.0.1:18081/upload)" = 413
test "$(origin_count)" = "${before_over}"
test "$(status_request upload-chunked -X POST -H 'Transfer-Encoding: chunked' \
  --data-binary @/work/body-17 http://127.0.0.1:18081/upload)" = 413
test "$(origin_count)" = "${before_over}"
test "$(status_request upload-no-length -X POST -H 'Content-Length:' http://127.0.0.1:18081/upload)" = 200
grep -Fx 'bytes=0' "${workdir}/upload-no-length.body" >/dev/null

before_framing="$(origin_count)"
printf 'POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n11\r\n12345678901234567\r\n0\r\n\r\n' \
  | docker exec -i "${container}" nc 127.0.0.1 18081 >"${workdir}/forged-framing.raw"
grep -Eq '^HTTP/1\.[01] 400 ' "${workdir}/forged-framing.raw"
test "$(origin_count)" = "${before_framing}"

before_h2="$(origin_count)"
test "$(status_request upload-h2 --http2-prior-knowledge -X POST --data-binary @/work/body-17 \
  http://127.0.0.1:18083/upload)" = 413
test "$(origin_count)" = "${before_h2}"
test "$(status_request ipv6 -g 'http://[::1]:18081/ipv6')" = 200
before_bad_commit="$(origin_count)"
test "$(status_request bad-commit http://127.0.0.1:18084/cold-start)" = 503
test "$(origin_count)" = "${before_bad_commit}"

index=0
while [ "${index}" -lt 20 ]; do
  index=$((index + 1))
  (
    status_request "concurrent/${index}" http://127.0.0.1:18081/concurrent >"${workdir}/concurrent/${index}.status"
  ) &
done
"${workdir}/http-policy" -input "${workdir}/policy-v2.json" -state-root "${workdir}/state" >"${workdir}/publish-v2.txt"
docker exec "${container}" /usr/local/openresty/bin/openresty -s reload -p /work/ -c nginx.conf -e /work/error.log
wait
for status_file in "${workdir}"/concurrent/*.status; do
  test "$(cat "${status_file}")" = 200
done
for headers_file in "${workdir}"/concurrent/*.headers; do
  grep -Eqi 'X-CDNCA-HTTP-Policy-Version: (1|2)' "${headers_file}"
done

attempt=0
while :; do
  test "$(status_request version-v2 http://127.0.0.1:18081/version)" = 200
  if grep -Fqi 'X-CDNCA-HTTP-Policy-Version: 2' "${workdir}/version-v2.headers"; then
    break
  fi
  attempt=$((attempt + 1))
  test "${attempt}" -lt 40
  sleep 0.1
done

cp "${workdir}/state/committed.json" "${workdir}/committed-v2.backup"
printf '%s\n' '{"broken":true}' >"${workdir}/state/committed.json"
chmod 0600 "${workdir}/state/committed.json"
sleep 0.2
test "$(status_request memory-lkg http://127.0.0.1:18081/lkg)" = 200
grep -Fqi 'X-CDNCA-HTTP-Policy-Version: 2' "${workdir}/memory-lkg.headers"
cp "${workdir}/committed-v2.backup" "${workdir}/state/committed.json"
chmod 0600 "${workdir}/state/committed.json"
cp "${workdir}/state/versions/00000000000000000002.json" "${workdir}/state/current.json"
cp "${workdir}/divergent-state/versions/00000000000000000002.json" "${workdir}/state/lkg.json"
chmod 0600 "${workdir}/state/current.json" "${workdir}/state/lkg.json"
docker exec "${container}" /usr/local/openresty/bin/openresty -s reload -p /work/ -c nginx.conf -e /work/error.log
sleep 0.2
test "$(status_request disk-lkg http://127.0.0.1:18081/lkg-after-reload)" = 200
grep -Fqi 'X-CDNCA-HTTP-Policy-Version: 2' "${workdir}/disk-lkg.headers"

"${workdir}/http-policy" -input "${workdir}/policy-v2.json" -state-root "${workdir}/state" >"${workdir}/repair-v2.txt"
grep -Fx 'durability_confirmed=true' "${workdir}/repair-v2.txt" >/dev/null

printf '%s\n' \
  'EDGE_HTTP_POLICY_SMOKE_EVIDENCE={"headers":true,"header_case_and_multivalue":true,"invalid_headers_rejected":true,"upload_boundary":true,"chunked_zero_origin":true,"http2_zero_origin":true,"forged_framing_zero_origin":true,"rewrite_chain":true,"rewrite_loop_blocked":true,"query_cookie_rules":true,"redirect_allowlist":true,"redirect_ipv4_ipv6":true,"cors_preflight_credentials":true,"concurrent_reload":true,"single_commit_manifest":true,"cold_start_bad_commit_closed":true,"same_version_legacy_divergence_ignored":true,"memory_lkg":true,"disk_lkg":true,"referer_check":true}'
