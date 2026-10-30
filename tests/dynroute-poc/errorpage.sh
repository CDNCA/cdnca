#!/bin/sh
# ADR 0009 §8.5 item 4: error page replacement by header/body filter compared
# with v7 (error_page + proxy_intercept_errors) on the same OpenResty, byte
# framing included: HEAD, gzip (origin- and edge-compressed), chunked, empty
# and partial origin bodies, edge-generated errors.
. "$(dirname -- "$0")/lib.sh"
build_probe
cp -R "${poc_dir}/errorpage" "${work}/errorpage"
start_container
probe certs -out /poc/certs
docker exec -d "${container}" /poc/probe errorigin -listen 127.0.0.1:9000
nginx_start errorpage
sleep 0.5
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'

# normalised raw HTTP/1.1 exchange: status, framing, headers (volatile ones
# and the filter variant's X-Edge marker removed), body digest
norm() { # port path method [gzip]
  extra=""; [ "${4:-}" = gzip ] && extra="-H Accept-Encoding:gzip"
  # shellcheck disable=SC2086
  probe get -url "http://127.0.0.1:$1$2" -method "$3" -raw ${extra} 2>/dev/null | tail -1 | jq -c '{
    status, framing: (.framing // "" | sub(" length=[0-9]+"; " length")),
    len: .body_len, gzip_magic: ((.raw // "") | test("\r\n\r\n\u001f")),
    body: (if (.headers["Content-Encoding"] // "") == "gzip" then "(gzip)" else .body end),
    headers: ((.headers // {}) | with_entries(select(.key | ascii_downcase | IN("date","server","connection","x-edge","keep-alive") | not)))}'
}
known_count=0
paths="/ok /404 /404empty /404chunked /404gzip /404partial /404chunkcut /410 /500 /200partial /edge403 /dead"
for path in ${paths}; do
  for method in GET HEAD; do
    for enc in plain gzip; do
      v7="$(norm 8081 "${path}" "${method}" "${enc}")"
      dyn="$(norm 8082 "${path}" "${method}" "${enc}")"
      naive="$(norm 8083 "${path}" "${method}" "${enc}")"
      name="$(printf '%s-%s-%s' "${path#/}" "${method}" "${enc}")"
      # Known, benign difference: a replaced page answering HEAD with
      # Accept-Encoding: gzip. v7's content handler marks HEAD header-only
      # before the header filters (ngx_http_lua_util.c:585), so gzip skips it
      # and Content-Length stays; on the filter path gzip still runs, as for
      # the GET. Everything except those two headers and the framing is equal.
      known="$(jq -nc --argjson a "${v7}" --argjson b "${dyn}" '
        def strip: del(.headers["Content-Length"], .headers["Content-Encoding"], .framing, .body);
        ($a.headers["X-Error-Page"] != null) and ($a|strip) == ($b|strip) and
        $a.headers["Content-Length"] != null and $b.headers["Content-Encoding"] == "gzip"')"
      if [ "${v7}" = "${dyn}" ]; then
        printf 'PASS EQ %s  %s\n' "${name}" "$(printf '%s' "${v7}" | jq -c '{status,framing,len,body}')"
      elif [ "${method}-${enc}" = HEAD-gzip ] && [ "${known}" = true ]; then
        printf 'KNOWN %s  v7 Content-Length=%s, filter Content-Encoding=gzip; status/其余头/空体相同\n' "${name}" "$(printf '%s' "${v7}" | jq -r '.headers["Content-Length"]')"
        known_count=$((known_count + 1))
      else
        printf 'FAIL EQ %s\n  v7 : %s\n  dyn: %s\n' "${name}" "${v7}" "${dyn}"
        failures=$((failures + 1))
      fi
      if [ "${naive}" != "${v7}" ]; then
        printf '  naive differs (%s): %s\n' "${name}" "$(printf '%s' "${naive}" | jq -c '{status,framing,len,body,ce:.headers["Content-Encoding"],cookie:.headers["Set-Cookie"],etag:.headers["Etag"]}')"
      fi
    done
  done
done
echo "known HEAD+gzip differences: ${known_count}"
echo "== HTTP/2 (same servers over TLS): status, body digest, stream outcome"
h2() { # port path method
  probe get -url "https://127.0.0.1:$1$2" -proto h2 -sni a.test -method "$3" 2>/dev/null | tail -1 |
    jq -c '{status, len: .body_len, sha: .body_sha, stream: (if .body_err then "reset" else "complete" end), err: (.err // null | if . then "error" else null end)}'
}
for path in /404 /404chunked /404partial /404chunkcut /200partial /dead /410; do
  for method in GET HEAD; do
    v7="$(h2 8441 "${path}" "${method}")"; dyn="$(h2 8442 "${path}" "${method}")"
    check "H2-${path#/}-${method}" "${v7}" "${dyn}" "h2 上 v7 与过滤器方式一致"
  done
done
echo "== pass-through of statuses without a page"
line="$(norm 8082 /410 GET)"
check PASSTHROUGH-BODY "origin-410-body-passthrough" "$(printf '%s' "${line}" | jq -r '.body' | tr -d '\n')" "无页的状态码透传源站体"
check PASSTHROUGH-COOKIE "origin=1; Path=/" "$(printf '%s' "${line}" | jq -r '.headers["Set-Cookie"]')" "无页的状态码保留源站头"
in_c 'grep -cE "\[(alert|crit|emerg)\]" /poc/errorpage/logs/error.log' | sed 's/^/error.log alert|crit|emerg lines: /'
in_c 'grep -cE "upstream prematurely closed" /poc/errorpage/logs/error.log' | sed 's/^/error.log "upstream prematurely closed" lines (the partial fixtures): /'
finish
