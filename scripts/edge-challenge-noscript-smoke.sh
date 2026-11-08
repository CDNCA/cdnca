#!/bin/sh
# Real OpenResty check that the built-in challenge modes (delay, click, slider,
# captcha) cannot be passed by a client that parses the page but never runs
# its JavaScript (scripts/edge-challenge-scraper.py), while a client that
# does what the page script does (proof of work + puzzle answer) passes and
# every wrong, missing or early proof is rejected.
#
#   scripts/edge-challenge-noscript-smoke.sh            scraper must fail on all four modes
#   CDNCA_NOSCRIPT_EXPECT=bypass scripts/...            scraper must pass on all four (pre-fix proof)
#   CDNCA_CHALLENGE_CHROME=/path/to/chrome scripts/...  also pass all four in real headless Chrome,
#       1x and 6x CPU throttling, Workers and main thread (scripts/edge-challenge-browser-check.mjs);
#       CDNCA_CHALLENGE_BROWSER_OUT keeps its screenshots and JSON report
set -eu

expect="${CDNCA_NOSCRIPT_EXPECT:-blocked}"
case "${expect}" in
  blocked|bypass) ;;
  *) echo "CDNCA_NOSCRIPT_EXPECT must be blocked or bypass" >&2; exit 2 ;;
esac

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="$(CDPATH='' cd -- "${TMPDIR:-/tmp}" && pwd -P)"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-noscript.XXXXXX")"
container="cdnca-edge-noscript-$(basename "${workdir}" | sed 's/^cdnca-edge-noscript\.//')"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-noscript.*) chmod -R u+w "${workdir}" 2>/dev/null || true; rm -rf -- "${workdir}" ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

fail() {
  echo "edge challenge noscript smoke: $*" >&2
  docker logs "${container}" 2>&1 | tail -n 40 >&2 || true
  [ -f "${workdir}/runtime/logs/error.log" ] && tail -n 60 "${workdir}/runtime/logs/error.log" >&2
  exit 1
}

mkdir -p "${workdir}/keys" "${workdir}/policy" "${workdir}/runtime/logs"
chmod 0700 "${workdir}/keys" "${workdir}/policy"
umask 077
openssl rand -hex 48 | tr -d '\n' >"${workdir}/keys/key-1"
chmod 0600 "${workdir}/keys/key-1"
key_sha="$(openssl dgst -sha256 -r "${workdir}/keys/key-1" | cut -d' ' -f1)"

# Compiled policy (the form the agent publishes; see agents/edge-agent/internal/challenge).
jq -n --arg key_file "${workdir}/keys/key-1" --arg key_sha "${key_sha}" '
  def rule($id; $prio; $site; $host; $mode; $delay):
    {rule_id:$id,priority:$prio,tenant_id:"tenant-a",site_id:$site,host:$host,mode:$mode,
     min_delay_seconds:$delay,challenge_ttl_seconds:60,pass_ttl_seconds:60,clock_skew_seconds:1,
     attempts_per_nonce:1,failure_window_seconds:60,max_failures_per_window:20,
     ip_binding:"exact",bind_user_agent:true};
  {schema_version:"cdnca.edge.challenge/v1",policy_version:1,algorithm:"hmac-sha256",
   cookie_name:"__Host-cdnca_challenge",trusted_proxies:[],bypass_routes:[],
   current_key:{key_id:"key-1",key_file:$key_file,key_sha256:$key_sha},
   rules:[rule("delay-gate";10;"site-a";"delay.test";"delay";5),
          rule("click-gate";20;"site-b";"click.test";"click";0),
          rule("slider-gate";30;"site-c";"slider.test";"slider";0),
          rule("captcha-gate";40;"site-d";"captcha.test";"captcha";0)]}' >"${workdir}/policy/current.json"
chmod 0600 "${workdir}/policy/current.json"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=delay.test' \
  -keyout "${workdir}/runtime/tls.key" -out "${workdir}/runtime/tls.crt" >/dev/null 2>&1

cat >"${workdir}/runtime/nginx.conf" <<'EOF'
worker_processes 1;
pid /tmp/cdnca-noscript-nginx.pid;
error_log /runtime/logs/error.log notice;
events { worker_connections 256; }
http {
    lua_package_path '/opt/cdnca-challenge/?.lua;;';
    lua_shared_dict cdnca_challenge_state 1m;
    map $host $challenge_site {
        default "";
        delay.test site-a;
        click.test site-b;
        slider.test site-c;
        captcha.test site-d;
    }
    init_worker_by_lua_block {
        require("engine").init({ policy_path = "/policy/current.json", state_dict = "cdnca_challenge_state" })
    }
    server {
        listen 8443 ssl;
        ssl_certificate /runtime/tls.crt;
        ssl_certificate_key /runtime/tls.key;
        server_name _;
        location / {
            access_by_lua_block {
                return require("engine").access({ tenant_id = "tenant-a", site_id = ngx.var.challenge_site })
            }
            content_by_lua_block { ngx.say("origin-ok") }
        }
    }
    # Test-only: the puzzle answer of a pending nonce (a human reads the picture).
    server {
        listen 8082;
        location = /answer {
            content_by_lua_block {
                local digest = require("crypto").sha256_hex(ngx.var.arg_nonce or "")
                local dict = ngx.shared.cdnca_challenge_state
                for _, key in ipairs(dict:get_keys(0)) do
                    if key:sub(-#digest - 9) == ":pending:" .. digest then
                        ngx.say(require("cjson.safe").decode(dict:get(key)).answer)
                        return
                    end
                end
                ngx.exit(404)
            }
        }
    }
}
EOF

docker run --detach --name "${container}" --publish 127.0.0.1::8443 --publish 127.0.0.1::8082 \
  --volume "${repo_root}/edge/openresty/challenge:/opt/cdnca-challenge:ro" \
  --volume "${workdir}/policy:/policy:ro" \
  --volume "${workdir}/runtime:/runtime" \
  --volume "${workdir}:${workdir}:ro" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" -p /runtime/ -c nginx.conf -g 'daemon off;' >/dev/null
port="$(docker port "${container}" 8443/tcp | tail -n 1)"
port="${port##*:}"
admin_port="$(docker port "${container}" 8082/tcp | tail -n 1)"
admin_port="${admin_port##*:}"

attempt=0
until curl --noproxy '*' --silent --insecure --output /dev/null \
  --resolve "click.test:${port}:127.0.0.1" "https://click.test:${port}/"; do
  attempt=$((attempt + 1))
  [ "${attempt}" -lt 50 ] || fail "OpenResty did not start"
  sleep 0.1
done

scrape="$(python3 -I "${repo_root}/scripts/edge-challenge-scraper.py" "${port}" \
  delay.test:delay click.test:click slider.test:slider captcha.test:captcha)" || fail "scraper failed"
printf '%s\n' "${scrape}" >"${workdir}/scrape.json"
for host in delay.test click.test slider.test captcha.test; do
  passed="$(printf '%s' "${scrape}" | jq -r --arg h "${host}" '.[$h].passed')"
  tries="$(printf '%s' "${scrape}" | jq -c --arg h "${host}" '[.[$h].attempts[] | {guess, status}]')"
  if [ "${expect}" = blocked ] && [ "${passed}" != false ]; then
    fail "${host}: a client that never runs JavaScript passed the challenge: ${tries}"
  fi
  if [ "${expect}" = bypass ] && [ "${passed}" != true ]; then
    fail "${host}: expected the pre-fix bypass, got ${tries}"
  fi
  echo "noscript ${expect}: ${host} passed=${passed} attempts=${tries}"
done
[ "${expect}" = blocked ] || { echo "edge challenge noscript smoke: PASS (${expect})"; exit 0; }

# The browser path: right proof passes and reaches origin; each wrong part fails.
solve="$(python3 -I "${repo_root}/scripts/edge-challenge-scraper.py" --solve "${port}" "${admin_port}" \
  delay.test:delay:ok,bad_pow,no_pow,early \
  click.test:click:ok,bad_pow,no_pow,bad_answer \
  slider.test:slider:ok,tolerance_in,tolerance_out,bad_answer,bad_pow,alt,alt_early \
  captcha.test:captcha:ok,bad_answer,no_pow,alt,alt_early)" || fail "solver failed"
printf '%s\n' "${solve}" >"${workdir}/solve.json"
cases=0
for host in delay.test click.test slider.test captcha.test; do
  for row in $(printf '%s' "${solve}" | jq -c --arg h "${host}" '.[$h][]'); do
    case_name="$(printf '%s' "${row}" | jq -r .case)"
    status="$(printf '%s' "${row}" | jq -r .status)"
    case "${case_name}" in
      ok|tolerance_in|alt) want=303 ;;
      *) want=403 ;;
    esac
    [ "${status}" = "${want}" ] || fail "${host} ${case_name}: status ${status}, want ${want}: ${row}"
    [ "$(printf '%s' "${row}" | jq '.problems | length')" = 0 ] || fail "${host} ${case_name}: page problems ${row}"
    if [ "${want}" = 303 ]; then
      [ "$(printf '%s' "${row}" | jq -r .origin)" = true ] || fail "${host} ${case_name}: pass cookie did not reach origin"
    fi
    cases=$((cases + 1))
  done
done
echo "solver: ${cases} cases as expected"

if [ -n "${CDNCA_CHALLENGE_CHROME:-}" ]; then
  browser_out="${CDNCA_CHALLENGE_BROWSER_OUT:-${workdir}/browser}"
  mkdir -p "${browser_out}"
  node "${repo_root}/scripts/edge-challenge-browser-check.mjs" "${CDNCA_CHALLENGE_CHROME}" "${port}" "${admin_port}" \
    "${browser_out}" "${CDNCA_CHALLENGE_BROWSER_RUNS:-3}" 1 6 >"${browser_out}/browser.json" || fail "real browser check failed"
  # Every proof of work (Workers or main thread, 6x throttled) under one second.
  slow="$(jq -c '[.summary | to_entries[] | select(.key | test("-alt") | not) | select(.value.powMs | max > 1000) | .key]' "${browser_out}/browser.json")"
  [ "${slow}" = '[]' ] || fail "browser proof of work over one second: ${slow}"
  echo "browser: $(jq -c '{chrome, workers, summary: (.summary | map_values({pow_ms_max: (.powMs | max), total_ms_max: (.totalMs | max)}))}' "${browser_out}/browser.json")"
fi
echo "edge challenge noscript smoke: PASS (${expect})"
