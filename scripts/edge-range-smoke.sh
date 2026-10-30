#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

docker_arch="$(docker info --format '{{.Architecture}}')"
case "${docker_arch}" in
  arm64|aarch64) go_arch=arm64 ;;
  amd64|x86_64) go_arch=amd64 ;;
  *)
    echo "unsupported Docker architecture: ${docker_arch}" >&2
    exit 69
    ;;
esac

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-range.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-range\.//')"
network="cdnca-edge-range-${suffix}"
origin_container="cdnca-range-origin-${suffix}"
runtime_container="cdnca-range-runtime-${suffix}"

cleanup() {
  docker rm -f "${runtime_container}" >/dev/null 2>&1 || true
  docker rm -f "${origin_container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-range.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/policy" "${workdir}/runtime" "${workdir}/data"
chmod 0700 "${workdir}/policy" "${workdir}/runtime" "${workdir}/data"
dd if=/dev/urandom of="${workdir}/data/payload.bin" bs=1048576 count=3 2>/dev/null
payload_size="$(wc -c <"${workdir}/data/payload.bin" | tr -d ' ')"

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/range-origin" ./internal/rangecache/cmd/range-origin
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/range-policy" ./internal/rangecache/cmd/range-policy
)

docker network create "${network}" >/dev/null
docker run --detach \
  --name "${origin_container}" \
  --network "${network}" \
  --network-alias range-origin \
  --publish 127.0.0.1::18090 \
  --volume "${workdir}/data:/data:ro" \
  --volume "${workdir}/range-origin:/usr/local/bin/range-origin:ro" \
  --entrypoint /usr/local/bin/range-origin \
  "${OPENRESTY_IMAGE}" \
  -fixture /data/payload.bin >/dev/null

docker run --detach \
  --name "${runtime_container}" \
  --network "${network}" \
  --publish 127.0.0.1::18086 \
  --publish 127.0.0.1::18087 \
  --volume "${workdir}/policy:/policy" \
  --volume "${workdir}/runtime:/runtime" \
  --volume "${workdir}/range-policy:/usr/local/bin/range-policy:ro" \
  --volume "${repo_root}/edge/openresty/range:/opt/cdnca-range:ro" \
  --entrypoint /bin/sh \
  "${OPENRESTY_IMAGE}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null

origin_published="$(docker port "${origin_container}" 18090/tcp | tail -n 1)"
edge_one_published="$(docker port "${runtime_container}" 18086/tcp | tail -n 1)"
edge_two_published="$(docker port "${runtime_container}" 18087/tcp | tail -n 1)"
case "${origin_published}:${edge_one_published}:${edge_two_published}" in
  127.0.0.1:*:127.0.0.1:*:127.0.0.1:*) ;;
  *)
    echo "smoke ports were not bound to random loopback ports" >&2
    exit 1
    ;;
esac
origin_url="http://${origin_published}"
edge_one_url="http://${edge_one_published}"
edge_two_url="http://${edge_two_published}"

publish_policy() {
  publish_version="$1"
  publish_slice="$2"
  docker exec -i "${runtime_container}" /usr/local/bin/range-policy \
    -policy-root /policy \
    -state-root /runtime \
    -lua-root /opt/cdnca-range <<EOF
{"schema_version":"cdnca.edge.range-cache/v1","policy_version":${publish_version},"slice_bytes":${publish_slice},"cache_max_bytes":134217728,"cache_inactive_seconds":300,"cache_valid_seconds":300,"max_range_header_bytes":1024,"max_if_range_header_bytes":1024,"max_response_header_bytes":8192,"sites":[{"site_id":"primary","listen_address":"0.0.0.0","listen_port":18086,"hosts":["edge-a.example.test","edge-b.example.test"],"origin_host":"range-origin","origin_port":18090},{"site_id":"port-isolation","listen_address":"0.0.0.0","listen_port":18087,"hosts":["edge-a.example.test"],"origin_host":"range-origin","origin_port":18090}]}
EOF
}

publish_policy 1 65536 >"${workdir}/publish-v1.log"

wait_version() {
  wait_expected="$1"
  wait_attempt=0
  while [ "${wait_attempt}" -lt 100 ]; do
    wait_value="$(curl --silent --show-error -H 'Host: edge-a.example.test' "${edge_one_url}/_cdnca/range-healthz" 2>/dev/null || true)"
    if [ "${wait_value}" = "ok:${wait_expected}" ]; then
      return 0
    fi
    if ! docker inspect --format '{{.State.Running}}' "${runtime_container}" 2>/dev/null | grep -Fx true >/dev/null; then
      docker logs "${runtime_container}" >&2 || true
      return 1
    fi
    wait_attempt=$((wait_attempt + 1))
    sleep 0.05
  done
  echo "range cache version did not become ${wait_expected}" >&2
  docker exec "${runtime_container}" sh -c 'test ! -f /runtime/error.log || tail -n 100 /runtime/error.log' >&2 || true
  return 1
}

origin_count() {
  count_path="$1"
  count_json="$(curl --fail --silent --show-error "${origin_url}/counts")"
  count_value="$(printf '%s\n' "${count_json}" | sed -n "s|.*\"${count_path}\":\([0-9][0-9]*\).*|\1|p")"
  printf '%s\n' "${count_value:-0}"
}

header_value() {
  header_file="$1"
  header_name="$2"
  awk -v name="${header_name}" 'tolower($0) ~ "^" tolower(name) ":" { sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }' "${header_file}"
}

request() {
  request_label="$1"
  request_url="$2"
  request_host="$3"
  request_path="$4"
  shift 4
  if ! curl --silent --show-error \
    --dump-header "${workdir}/${request_label}.headers" \
    --output "${workdir}/${request_label}.body" \
    --write-out '%{http_code}' \
    -H "Host: ${request_host}" "$@" "${request_url}${request_path}" >"${workdir}/${request_label}.status"; then
    echo "${request_label}: request failed" >&2
    docker exec "${runtime_container}" sh -c 'test ! -f /runtime/error.log || tail -n 100 /runtime/error.log' >&2 || true
    return 1
  fi
}

expect_status() {
  status_label="$1"
  status_expected="$2"
  status_actual="$(cat "${workdir}/${status_label}.status")"
  if [ "${status_actual}" != "${status_expected}" ]; then
    echo "${status_label}: status ${status_actual}, want ${status_expected}" >&2
    cat "${workdir}/${status_label}.headers" >&2 || true
    docker exec "${runtime_container}" sh -c 'test ! -f /runtime/error.log || tail -n 80 /runtime/error.log' >&2 || true
    exit 1
  fi
}

expect_cache() {
  cache_label="$1"
  cache_expected="$2"
  cache_actual="$(header_value "${workdir}/${cache_label}.headers" X-CDNCA-Range-Cache)"
  if [ "${cache_actual}" != "${cache_expected}" ]; then
    echo "${cache_label}: cache status ${cache_actual:-<empty>}, want ${cache_expected}" >&2
    cat "${workdir}/${cache_label}.headers" >&2 || true
    curl --fail --silent --show-error "${origin_url}/counts" >&2 || true
    docker exec "${runtime_container}" sh -c 'test ! -f /runtime/error.log || tail -n 80 /runtime/error.log' >&2 || true
    exit 1
  fi
}

expect_config() {
  config_label="$1"
  config_expected="$2"
  config_actual="$(header_value "${workdir}/${config_label}.headers" X-CDNCA-Range-Config-Version)"
  test "${config_actual}" = "${config_expected}"
}

expect_bytes() {
  bytes_label="$1"
  bytes_start="$2"
  bytes_count="$3"
  dd if="${workdir}/data/payload.bin" of="${workdir}/${bytes_label}.expected" bs=1 skip="${bytes_start}" count="${bytes_count}" 2>/dev/null
  cmp "${workdir}/${bytes_label}.expected" "${workdir}/${bytes_label}.body"
}

expect_origin_rejection() {
  rejection_path="$1"
  rejection_before="$(origin_count "/${rejection_path}")"
  for rejection_attempt in one two; do
    if curl --silent --show-error \
      --dump-header "${workdir}/${rejection_path}-${rejection_attempt}.headers" \
      --output "${workdir}/${rejection_path}-${rejection_attempt}.body" \
      --write-out '%{http_code}' \
      -H 'Host: edge-a.example.test' \
      -H 'Range: bytes=0-99' \
      "${edge_one_url}/${rejection_path}" >"${workdir}/${rejection_path}-${rejection_attempt}.status" \
      2>"${workdir}/${rejection_path}-${rejection_attempt}.error"; then
      test "$(cat "${workdir}/${rejection_path}-${rejection_attempt}.status")" = 502
    else
      case "$(cat "${workdir}/${rejection_path}-${rejection_attempt}.status")" in 000|206|502) ;; *) return 1 ;; esac
    fi
  done
  rejection_after="$(origin_count "/${rejection_path}")"
  test $((rejection_after - rejection_before)) -eq 2
}

wait_version 1

# Cold fill fetches one complete slice. An overlapping request is served from it.
before="$(origin_count /payload)"
request cold "${edge_one_url}" edge-a.example.test '/payload' -H 'Range: bytes=1000-1999'
expect_status cold 206
expect_cache cold MISS
expect_config cold 1
test "$(header_value "${workdir}/cold.headers" Content-Range)" = "bytes 1000-1999/${payload_size}"
expect_bytes cold 1000 1000
request overlap-hit "${edge_one_url}" edge-a.example.test '/payload' -H 'Range: bytes=1500-1599'
expect_status overlap-hit 206
expect_cache overlap-hit HIT
expect_bytes overlap-hit 1500 100
after="$(origin_count /payload)"
test $((after - before)) -eq 1

# Suffix and open-ended forms are normalized by Nginx against the same exact object.
suffix_start=$((payload_size - 257))
request suffix "${edge_one_url}" edge-a.example.test '/payload?shape=suffix' -H 'Range: bytes=-257'
expect_status suffix 206
test "$(header_value "${workdir}/suffix.headers" Content-Range)" = "bytes ${suffix_start}-$((payload_size - 1))/${payload_size}"
expect_bytes suffix "${suffix_start}" 257
open_start=$((payload_size - 777))
request open-ended "${edge_one_url}" edge-a.example.test '/payload?shape=open' -H "Range: bytes=${open_start}-"
expect_status open-ended 206
test "$(header_value "${workdir}/open-ended.headers" Content-Range)" = "bytes ${open_start}-$((payload_size - 1))/${payload_size}"
expect_bytes open-ended "${open_start}" 777

# Query, host, listener port, and policy version are independent key dimensions.
before="$(origin_count /payload)"
request query-one "${edge_one_url}" edge-a.example.test '/payload?variant=one' -H 'Range: bytes=0-99'
request query-one-hit "${edge_one_url}" edge-a.example.test '/payload?variant=one' -H 'Range: bytes=0-99'
request query-two "${edge_one_url}" edge-a.example.test '/payload?variant=two' -H 'Range: bytes=0-99'
request host-two "${edge_one_url}" edge-b.example.test '/payload?variant=one' -H 'Range: bytes=0-99'
request port-two "${edge_two_url}" edge-a.example.test '/payload?variant=one' -H 'Range: bytes=0-99'
expect_cache query-one MISS
expect_cache query-one-hit HIT
expect_cache query-two MISS
expect_cache host-two MISS
expect_cache port-two MISS
after="$(origin_count /payload)"
test $((after - before)) -eq 4

# Cache lock collapses concurrent requests for the same overlapping slice.
before="$(origin_count /payload)"
concurrent_index=1
concurrent_pids=""
while [ "${concurrent_index}" -le 12 ]; do
  if [ $((concurrent_index % 2)) -eq 0 ]; then
    concurrent_start=70500
  else
    concurrent_start=70000
  fi
  curl --silent --show-error \
    --output "${workdir}/concurrent-${concurrent_index}.body" \
    --write-out '%{http_code}' \
    -H 'Host: edge-a.example.test' \
    -H "Range: bytes=${concurrent_start}-$((concurrent_start + 999))" \
    "${edge_one_url}/payload?concurrent=one" >"${workdir}/concurrent-${concurrent_index}.status" &
  concurrent_pids="${concurrent_pids} $!"
  concurrent_index=$((concurrent_index + 1))
done
for concurrent_pid in ${concurrent_pids}; do
  wait "${concurrent_pid}"
done
concurrent_index=1
while [ "${concurrent_index}" -le 12 ]; do
  if [ $((concurrent_index % 2)) -eq 0 ]; then
    concurrent_start=70500
  else
    concurrent_start=70000
  fi
  test "$(cat "${workdir}/concurrent-${concurrent_index}.status")" = 206
  dd if="${workdir}/data/payload.bin" of="${workdir}/concurrent.expected" bs=1 skip="${concurrent_start}" count=1000 2>/dev/null
  cmp "${workdir}/concurrent.expected" "${workdir}/concurrent-${concurrent_index}.body"
  concurrent_index=$((concurrent_index + 1))
done
after="$(origin_count /payload)"
test $((after - before)) -eq 1

# Valid bounded multi-range returns exact multipart bytes and reuses its isolated exact-range cache entry.
multi_ranges='bytes=0-9,65536-65545'
before="$(origin_count /payload)"
request multi-cold "${edge_one_url}" edge-a.example.test '/payload?multi=valid' -H "Range: ${multi_ranges}"
expect_status multi-cold 206
expect_cache multi-cold MISS
test -z "$(header_value "${workdir}/multi-cold.headers" Content-Range)"
multi_content_type="$(header_value "${workdir}/multi-cold.headers" Content-Type)"
cp "${workdir}/multi-cold.body" "${workdir}/data/multi-cold.body"
docker exec "${origin_container}" /usr/local/bin/range-origin \
  -fixture /data/payload.bin -verify-multipart /data/multi-cold.body \
  -verify-content-type "${multi_content_type}" -verify-ranges "${multi_ranges}"
request multi-hit "${edge_one_url}" edge-a.example.test '/payload?multi=valid' -H "Range: ${multi_ranges}"
expect_status multi-hit 206
expect_cache multi-hit HIT
multi_hit_content_type="$(header_value "${workdir}/multi-hit.headers" Content-Type)"
cp "${workdir}/multi-hit.body" "${workdir}/data/multi-hit.body"
docker exec "${origin_container}" /usr/local/bin/range-origin \
  -fixture /data/payload.bin -verify-multipart /data/multi-hit.body \
  -verify-content-type "${multi_hit_content_type}" -verify-ranges "${multi_ranges}"
after="$(origin_count /payload)"
test $((after - before)) -eq 1

# Overlapping, excessive, malformed, duplicate, overflow, and oversized ranges never reach origin.
before="$(origin_count /payload)"
request overlap "${edge_one_url}" edge-a.example.test '/payload?reject=overlap' -H 'Range: bytes=0-9,5-14'
expect_status overlap 416
request too-many "${edge_one_url}" edge-a.example.test '/payload?reject=count' -H 'Range: bytes=0-0,2-2,4-4,6-6,8-8,10-10,12-12,14-14,16-16,18-18,20-20,22-22,24-24,26-26,28-28,30-30,32-32'
expect_status too-many 416
request over-budget "${edge_one_url}" edge-a.example.test '/payload?reject=budget' -H 'Range: bytes=0-67108864'
expect_status over-budget 416
request reversed "${edge_one_url}" edge-a.example.test '/payload?reject=reversed' -H 'Range: bytes=20-10'
expect_status reversed 416
request overflow "${edge_one_url}" edge-a.example.test '/payload?reject=overflow' -H 'Range: bytes=999999999999999999999-'
expect_status overflow 416
request duplicate "${edge_one_url}" edge-a.example.test '/payload?reject=duplicate' -H 'Range: bytes=0-9' -H 'Range: bytes=20-29'
expect_status duplicate 400
long_range="bytes=0-$(awk 'BEGIN { for (i = 0; i < 1100; i++) printf "9" }')"
request oversized "${edge_one_url}" edge-a.example.test '/payload?reject=oversized' -H "Range: ${long_range}"
expect_status oversized 431
after="$(origin_count /payload)"
test $((after - before)) -eq 0

# Vary responses stay origin-only so one request header cannot poison another representation.
curl --fail --silent --show-error --output "${workdir}/vary-en.expected" \
  -H 'Accept-Language: en-US' -H 'Range: bytes=0-99' "${origin_url}/vary"
curl --fail --silent --show-error --output "${workdir}/vary-zh.expected" \
  -H 'Accept-Language: zh-CN' -H 'Range: bytes=0-99' "${origin_url}/vary"
before="$(origin_count /vary)"
request vary-en "${edge_one_url}" edge-a.example.test '/vary' -H 'Accept-Language: en-US' -H 'Range: bytes=0-99'
expect_status vary-en 206
expect_cache vary-en MISS
cmp "${workdir}/vary-en.expected" "${workdir}/vary-en.body"
request vary-zh "${edge_one_url}" edge-a.example.test '/vary' -H 'Accept-Language: zh-CN' -H 'Range: bytes=0-99'
expect_status vary-zh 206
expect_cache vary-zh MISS
cmp "${workdir}/vary-zh.expected" "${workdir}/vary-zh.body"
request vary-en-again "${edge_one_url}" edge-a.example.test '/vary' -H 'Accept-Language: en-US' -H 'Range: bytes=0-99'
expect_status vary-en-again 206
expect_cache vary-en-again MISS
cmp "${workdir}/vary-en.expected" "${workdir}/vary-en-again.body"
after="$(origin_count /vary)"
test $((after - before)) -eq 3

# A syntactically valid out-of-bounds range is answered as 416 and never cached.
out_start=$((payload_size + 1024))
before="$(origin_count /payload)"
request out-one "${edge_one_url}" edge-a.example.test '/payload?reject=out' -H "Range: bytes=${out_start}-"
expect_status out-one 416
test "$(header_value "${workdir}/out-one.headers" Content-Range)" = "bytes */${payload_size}"
request out-two "${edge_one_url}" edge-a.example.test '/payload?reject=out' -H "Range: bytes=${out_start}-"
expect_status out-two 416
after="$(origin_count /payload)"
test $((after - before)) -eq 2

# If-Range uses the downstream validators; it is not forwarded to internal slice requests.
request validator-fill "${edge_one_url}" edge-a.example.test '/payload?validator=one' -H 'Range: bytes=2000-2999'
etag="$(header_value "${workdir}/validator-fill.headers" ETag)"
modified="$(header_value "${workdir}/validator-fill.headers" Last-Modified)"
test "${etag}" = '"range-v1"'
test -n "${modified}"
request validator-etag-hit "${edge_one_url}" edge-a.example.test '/payload?validator=one' -H 'Range: bytes=2100-2199' -H "If-Range: ${etag}"
expect_status validator-etag-hit 206
expect_bytes validator-etag-hit 2100 100
request validator-etag-miss "${edge_one_url}" edge-a.example.test '/payload?validator=one' -H 'Range: bytes=2100-2199' -H 'If-Range: "different"'
expect_status validator-etag-miss 200
cmp "${workdir}/data/payload.bin" "${workdir}/validator-etag-miss.body"
request validator-date-hit "${edge_one_url}" edge-a.example.test '/payload?validator=one' -H 'Range: bytes=2200-2299' -H "If-Range: ${modified}"
expect_status validator-date-hit 206
expect_bytes validator-date-hit 2200 100

# HEAD shares GET's representation metadata and never emits a body.
curl --silent --show-error --head \
  --dump-header "${workdir}/head.headers" \
  --output "${workdir}/head.body" \
  --write-out '%{http_code}' \
  -H 'Host: edge-a.example.test' \
  -H 'Range: bytes=1000-1999' \
  "${edge_one_url}/payload" >"${workdir}/head.status"
head_status="$(cat "${workdir}/head.status")"
head_length="$(header_value "${workdir}/head.headers" Content-Length)"
case "${head_status}" in
  200) test "${head_length}" = "${payload_size}" ;;
  206)
    test "${head_length}" = 1000
    test "$(header_value "${workdir}/head.headers" Content-Range)" = "bytes 1000-1999/${payload_size}"
    ;;
  *) exit 1 ;;
esac

# An origin that ignores Range is safely ranged downstream, but its 200 is never stored as a slice.
before="$(origin_count /ignore)"
request ignore-one "${edge_one_url}" edge-a.example.test '/ignore' -H 'Range: bytes=0-99'
expect_status ignore-one 206
expect_cache ignore-one MISS
expect_bytes ignore-one 0 100
request ignore-two "${edge_one_url}" edge-a.example.test '/ignore' -H 'Range: bytes=0-99'
expect_status ignore-two 206
expect_cache ignore-two MISS
expect_bytes ignore-two 0 100
after="$(origin_count /ignore)"
test $((after - before)) -eq 2

# Unknown-length 200 responses remain complete pass-through responses and are never cached as slices.
before="$(origin_count /unknown)"
request unknown-one "${edge_one_url}" edge-a.example.test '/unknown' -H 'Range: bytes=0-99'
expect_status unknown-one 200
expect_cache unknown-one MISS
cmp "${workdir}/data/payload.bin" "${workdir}/unknown-one.body"
request unknown-two "${edge_one_url}" edge-a.example.test '/unknown' -H 'Range: bytes=0-99'
expect_status unknown-two 200
expect_cache unknown-two MISS
cmp "${workdir}/data/payload.bin" "${workdir}/unknown-two.body"
after="$(origin_count /unknown)"
test $((after - before)) -eq 2

# Encoded representations fail closed and never hit cache.
before="$(origin_count /encoded)"
request unsafe-encoded-one "${edge_one_url}" edge-a.example.test '/encoded' -H 'Range: bytes=0-99'
expect_status unsafe-encoded-one 502
request unsafe-encoded-two "${edge_one_url}" edge-a.example.test '/encoded' -H 'Range: bytes=0-99'
expect_status unsafe-encoded-two 502
after="$(origin_count /encoded)"
test $((after - before)) -eq 2

# Duplicate/conflicting Content-Range, conflicting Content-Length, and oversized headers never become cache entries.
expect_origin_rejection conflict
expect_origin_rejection bad-length
expect_origin_rejection large-header

# A validator change between slices aborts the mixed response. The valid first slice remains safe LKG.
before="$(origin_count /changing)"
if curl --silent --show-error \
  --dump-header "${workdir}/changing-bad.headers" \
  --output "${workdir}/changing-bad.body" \
  --write-out '%{http_code}' \
  -H 'Host: edge-a.example.test' \
  -H 'Range: bytes=64000-66000' \
  "${edge_one_url}/changing" >"${workdir}/changing-bad.status" 2>"${workdir}/changing-bad.error"; then
  test "$(cat "${workdir}/changing-bad.status")" = 502
else
  case "$(cat "${workdir}/changing-bad.status")" in 000|206|502) ;; *) exit 1 ;; esac
fi
request changing-good "${edge_one_url}" edge-a.example.test '/changing' -H 'Range: bytes=64000-66000'
expect_status changing-good 206
expect_bytes changing-good 64000 2001
request changing-hit "${edge_one_url}" edge-a.example.test '/changing' -H 'Range: bytes=64500-64599'
expect_status changing-hit 206
expect_cache changing-hit HIT
expect_bytes changing-hit 64500 100
after="$(origin_count /changing)"
test $((after - before)) -eq 3

# A truncated 206 is observable as a failed client read, is not cached, and a later valid retry can fill safely.
before="$(origin_count /truncate)"
if curl --silent --show-error \
  --dump-header "${workdir}/truncate-bad.headers" \
  --output "${workdir}/truncate-bad.body" \
  --write-out '%{http_code}' \
  -H 'Host: edge-a.example.test' \
  -H 'Range: bytes=64000-65000' \
  "${edge_one_url}/truncate" >"${workdir}/truncate-bad.status" 2>"${workdir}/truncate-bad.error"; then
  echo "truncated response unexpectedly completed" >&2
  exit 1
fi
test "$(cat "${workdir}/truncate-bad.status")" = 206
request truncate-good "${edge_one_url}" edge-a.example.test '/truncate' -H 'Range: bytes=64000-65000'
expect_status truncate-good 206
expect_cache truncate-good MISS
expect_bytes truncate-good 64000 1001
request truncate-hit "${edge_one_url}" edge-a.example.test '/truncate' -H 'Range: bytes=64500-64599'
expect_status truncate-hit 206
expect_cache truncate-hit HIT
expect_bytes truncate-hit 64500 100
after="$(origin_count /truncate)"
test $((after - before)) -eq 2

# Policy version changes produce a cold key. A rejected v3 leaves current and LKG on v2.
before="$(origin_count /payload)"
publish_policy 2 65536 >"${workdir}/publish-v2.log"
wait_version 2
request version-two "${edge_one_url}" edge-a.example.test '/payload' -H 'Range: bytes=1000-1999'
expect_status version-two 206
expect_cache version-two MISS
expect_config version-two 2
expect_bytes version-two 1000 1000
request version-two-hit "${edge_one_url}" edge-a.example.test '/payload' -H 'Range: bytes=1000-1999'
expect_cache version-two-hit HIT
after="$(origin_count /payload)"
test $((after - before)) -eq 1

current_before="$(docker exec "${runtime_container}" readlink /policy/current)"
lkg_before="$(docker exec "${runtime_container}" readlink /policy/lkg)"
if publish_policy 3 1 >"${workdir}/publish-v3.log" 2>&1; then
  echo "invalid v3 policy was accepted" >&2
  exit 1
fi
test "$(docker exec "${runtime_container}" readlink /policy/current)" = "${current_before}"
test "$(docker exec "${runtime_container}" readlink /policy/lkg)" = "${lkg_before}"
wait_version 2
request lkg-hit "${edge_one_url}" edge-a.example.test '/payload' -H 'Range: bytes=1000-1999'
expect_cache lkg-hit HIT
expect_config lkg-hit 2

final_counts="$(curl --fail --silent --show-error "${origin_url}/counts")"
printf 'EDGE_RANGE_SMOKE_EVIDENCE={"openresty_version":"%s","payload_bytes":%s,"single_cold_hit":true,"suffix_open_ended":true,"bounded_multi_range":true,"overlap_count_budget_rejected":true,"invalid_ranges_rejected":true,"if_range_etag":true,"if_range_last_modified":true,"head_semantics":true,"vary_origin_only":true,"origin_200_passthrough_not_cached":true,"content_encoding_rejected":true,"unknown_length_passthrough_not_cached":true,"response_headers_bounded":true,"conflicting_content_range_rejected":true,"conflicting_content_length_rejected":true,"cross_slice_validator_lkg":true,"truncation_not_cached":true,"concurrent_lock":true,"host_port_query_version_isolated":true,"bad_policy_lkg_version":2,"origin_counts":%s}\n' \
  "${OPENRESTY_VERSION}" "${payload_size}" "${final_counts}"
