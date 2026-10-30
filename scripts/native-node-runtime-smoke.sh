#!/usr/bin/env bash
# Candidate-only runtime evidence. This does not authenticate a release or install a node.
# Inputs: PAYLOAD_DIR, SOURCE_COMMIT, SOURCE_TREE, EVIDENCE_DIR (new). HTTP/3 is requested with the
# payload's own runtime/bin/h3probe, the probe the Agent runs (openresty.http3_probe).
set -Eeuo pipefail

cleanup_smoke() {
  local result=$? _attempt
  trap - EXIT
  if [[ -n ${SMOKE_RUNNER:-} ]]; then
    if jobs -pr | grep -Fx "$SMOKE_RUNNER" >/dev/null; then kill -TERM "$SMOKE_RUNNER" 2>/dev/null || true; fi
    wait "$SMOKE_RUNNER" 2>/dev/null || true
  fi
  if [[ $$ == 1 && -n ${SMOKE_MASTER:-} ]]; then
    kill -QUIT "$SMOKE_MASTER" 2>/dev/null || true
    for _attempt in {1..20}; do kill -0 "$SMOKE_MASTER" 2>/dev/null || break; sleep 0.1; done
    kill -TERM "$SMOKE_MASTER" 2>/dev/null || true
    wait "$SMOKE_MASTER" 2>/dev/null || true
  elif [[ ${SMOKE_INSIDE:-0} == 0 && ${SMOKE_WORK:-} =~ ^/tmp/cdnca-native-runtime-smoke\.[A-Za-z0-9]{8}$ ]]; then rm -r -- "$SMOKE_WORK"; fi
  exit "$result"
}

write_smoke_config() {
  local version=$1 file
  : > "$SMOKE_WORK/nginx.conf"
  while IFS= read -r file; do printf 'load_module "%s";\n' "$file"; done < "$SMOKE_WORK/modules" >> "$SMOKE_WORK/nginx.conf"
  cat >> "$SMOKE_WORK/nginx.conf" <<CONFIG
user nobody nogroup;
worker_processes 1;
worker_shutdown_timeout 2s;
pid $SMOKE_WORK/nginx.pid;
error_log $EVIDENCE_DIR/nginx-error.log notice;
events { worker_connections 128; }
http {
  access_log $EVIDENCE_DIR/nginx-access.log;
  client_body_temp_path $SMOKE_WORK/temp/client;
  proxy_temp_path $SMOKE_WORK/temp/proxy;
  fastcgi_temp_path $SMOKE_WORK/temp/fastcgi;
  uwsgi_temp_path $SMOKE_WORK/temp/uwsgi;
  scgi_temp_path $SMOKE_WORK/temp/scgi;
  lua_package_path '/usr/local/share/cdnca/?.lua;/usr/local/share/cdnca/security/?.lua;/usr/local/openresty/lualib/?.lua;/usr/local/openresty/lualib/?/init.lua;;';
  lua_package_cpath '/usr/local/openresty/lualib/?.so;;';
  server { listen 127.0.0.1:18080; location / { return 200 '$version'; } }
  server {
    listen 127.0.0.1:18443 ssl;
    listen 127.0.0.1:18443 quic reuseport;
    http2 on; http3 on; quic_retry on;
    server_name native-smoke.invalid;
    ssl_protocols TLSv1.3;
    ssl_certificate $SMOKE_WORK/server.crt;
    ssl_certificate_key $SMOKE_WORK/server.key;
    add_header X-CDNCA-HTTP3-Version $version always;
    location / { content_by_lua_file $SMOKE_WORK/check.lua; }
  }
}
stream { server { listen 127.0.0.1:18444; proxy_pass 127.0.0.1:18080; } }
CONFIG
  cp "$SMOKE_WORK/nginx.conf" "$EVIDENCE_DIR/fixture-$version.conf"
}

smoke_requests() {
  local version=$1 protocol
  protocol=$(curl --noproxy '*' -fsS --max-time 5 --http1.1 -o "$EVIDENCE_DIR/http1-$version.txt" -w '%{http_version}' http://127.0.0.1:18080/) || return 1
  [[ $protocol == 1.1 && $(< "$EVIDENCE_DIR/http1-$version.txt") == "$version" ]] || return 1
  protocol=$(curl --noproxy '*' -fsS --max-time 5 --http2 --cacert "$SMOKE_WORK/server.crt" -o "$EVIDENCE_DIR/http2-$version.json" -w '%{http_version}' https://127.0.0.1:18443/) || return 1
  [[ $protocol == 2 ]] || return 1; jq -e '.lua == "ok" and .files >= 12' "$EVIDENCE_DIR/http2-$version.json" >/dev/null || return 1
  [[ $(curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:18444/) == "$version" ]] || return 1
  "${SMOKE_H3PROBE:-/opt/cdnca-node/current/runtime/bin/h3probe}" request --url https://127.0.0.1:18443/ --server-name native-smoke.invalid --bind 127.0.0.1:0 --timeout 8s > "$EVIDENCE_DIR/http3-$version.json" || return 1
  jq -e --arg version "$version" '.protocol == "HTTP/3.0" and .status == 200 and .tls_version == "TLSv1.3" and .version_header == $version and (.body | fromjson | .lua == "ok" and .files >= 12)' "$EVIDENCE_DIR/http3-$version.json" >/dev/null
}

smoke_namespace() {
  [[ $$ == 1 && -n ${SMOKE_OUTER_MNT:-} && -n ${SMOKE_OUTER_NET:-} && -n ${SMOKE_OUTER_PID:-} && $(readlink /proc/self/ns/mnt) != "$SMOKE_OUTER_MNT" && $(readlink /proc/self/ns/net) != "$SMOKE_OUTER_NET" && $(readlink /proc/self/ns/pid) != "$SMOKE_OUTER_PID" ]] || { printf '%s\n' 'fresh mount, network and PID namespaces required' >&2; return 2; }
  SMOKE_INSIDE=1
  trap cleanup_smoke EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
  local file _attempt worker_before worker_after master_start worker_uid worker_gid
  mount --make-rprivate / # Never propagate fixture mounts back to the host.
  mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /opt
  mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /usr/local
  mkdir -p /opt/cdnca-node/current /opt/cdnca /usr/local/share
  chmod 0755 /opt/cdnca-node /opt/cdnca-node/current /opt/cdnca /usr/local/share
  mount --bind "$PAYLOAD_DIR" /opt/cdnca-node/current
  mount -o remount,bind,ro /opt/cdnca-node/current
  ln -s /opt/cdnca-node/current/runtime/openresty /usr/local/openresty
  ln -s /opt/cdnca-node/current/lua/share/cdnca /usr/local/share/cdnca
  ln -s /opt/cdnca-node/current/lua/l4geo /opt/cdnca/l4geo
  ip link set lo up
  chmod 0755 "$SMOKE_WORK"; mkdir "$SMOKE_WORK/temp" "$SMOKE_WORK/logs"; chown nobody:nogroup "$SMOKE_WORK/temp"; chmod 0700 "$SMOKE_WORK/temp"
  local runtime=/opt/cdnca-node/current/runtime
  local -a nginx=("$runtime/lib/ld-musl-x86_64.so.1" --library-path "$runtime/openresty/luajit/lib:$runtime/openresty/openssl3/lib:$runtime/openresty/pcre2/lib:$runtime/lib:$runtime/usr/lib" "$runtime/openresty/nginx/sbin/nginx")
  "${nginx[@]}" -V > "$EVIDENCE_DIR/loader.log" 2>&1
  for file in --with-http_v2_module --with-http_v3_module --with-stream_realip_module; do grep -F -- "$file" "$EVIDENCE_DIR/loader.log" >/dev/null; done
  printf 'native_loader\n' >> "$EVIDENCE_DIR/checks.passed"
  for file in ngx_http_geoip_module.so ngx_http_image_filter_module.so ngx_http_xslt_filter_module.so; do [[ -f $runtime/openresty/nginx/modules/$file ]] || return 1; done
  find "$runtime/openresty/nginx/modules" -maxdepth 1 -type f -name 'ngx_*_module.so' | sort > "$SMOKE_WORK/modules"
  [[ -s $SMOKE_WORK/modules ]] || return 1
  cat > "$SMOKE_WORK/check.lua" <<'LUA_CHECK'
require('resty.core'); local cjson=require('cjson'); local count=0
local cc=require('cc'); assert(type(cc.init)=='function' and type(cc.access)=='function' and type(cc.metrics)=='function' and type(cc.log)=='function')
local http=require('httppolicy.engine'); assert(type(http.access)=='function' and type(http.header_filter)=='function')
local firewall=require('firewallaction.engine'); assert(type(firewall.handle)=='function')
LUA_CHECK
  while IFS= read -r file; do printf 'assert(loadfile("/opt/cdnca-node/current/%s")); count=count+1\n' "$file"; done < <(jq -r '.[] | select(.path | startswith("lua/") and endswith(".lua")) | .path' "$EVIDENCE_DIR/files.json") >> "$SMOKE_WORK/check.lua"
  printf "assert(count>=12); ngx.say(cjson.encode({lua='ok',files=count}))\n" >> "$SMOKE_WORK/check.lua"; chmod 0644 "$SMOKE_WORK/check.lua"
  cp "$SMOKE_WORK/check.lua" "$EVIDENCE_DIR/lua-check.lua"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=native-smoke.invalid -addext subjectAltName=IP:127.0.0.1,DNS:native-smoke.invalid -keyout "$SMOKE_WORK/server.key" -out "$SMOKE_WORK/server.crt" > "$EVIDENCE_DIR/certificate.log" 2>&1
  write_smoke_config v1; "${nginx[@]}" -t -p "$SMOKE_WORK/" -c "$SMOKE_WORK/nginx.conf" > "$EVIDENCE_DIR/config-v1.log" 2>&1
  printf 'dynamic_modules\n' >> "$EVIDENCE_DIR/checks.passed"
  "${nginx[@]}" -p "$SMOKE_WORK/" -c "$SMOKE_WORK/nginx.conf" -g 'daemon off;' > "$EVIDENCE_DIR/launch.log" 2>&1 & SMOKE_MASTER=$!
  for _attempt in {1..40}; do curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:18080/ >/dev/null 2>&1 && break; sleep 0.1; done
  master_start=$(awk '{print $22}' "/proc/$SMOKE_MASTER/stat")
  worker_before=$(ps -o pid=,args= --ppid "$SMOKE_MASTER" | awk '/nginx: worker process$/ {print $1}'); [[ $worker_before =~ ^[0-9]+$ ]] || return 1
  worker_uid=$(id -u nobody); worker_gid=$(getent group nogroup | cut -d: -f3)
  [[ $(awk '/^Uid:/ {print $3}' "/proc/$worker_before/status") == "$worker_uid" && $(awk '/^Gid:/ {print $3}' "/proc/$worker_before/status") == "$worker_gid" ]] || return 1
  smoke_requests v1; printf 'http1\nhttp2\nhttp3\nstream_tcp\nlua\n' >> "$EVIDENCE_DIR/checks.passed"
  write_smoke_config v2; "${nginx[@]}" -t -p "$SMOKE_WORK/" -c "$SMOKE_WORK/nginx.conf" > "$EVIDENCE_DIR/config-v2.log" 2>&1; kill -HUP "$SMOKE_MASTER"
  for _attempt in {1..50}; do [[ $(curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:18080/ 2>/dev/null) == v2 ]] && break; sleep 0.1; done
  # After HUP the old worker can still be listed (graceful exit) next to the
  # new one: wait until exactly one worker, different from the old, remains.
  for _attempt in {1..100}; do
    worker_after=$(ps -o pid=,args= --ppid "$SMOKE_MASTER" | awk '/nginx: worker process$/ {print $1}')
    [[ $worker_after =~ ^[0-9]+$ && $worker_after != "$worker_before" ]] && break
    sleep 0.1
  done
  [[ $worker_after =~ ^[0-9]+$ && $worker_after != "$worker_before" && $(awk '{print $22}' "/proc/$SMOKE_MASTER/stat") == "$master_start" ]] || return 1
  [[ $(awk '/^Uid:/ {print $3}' "/proc/$worker_after/status") == "$worker_uid" && $(awk '/^Gid:/ {print $3}' "/proc/$worker_after/status") == "$worker_gid" ]] || return 1
  smoke_requests v2; printf 'same_master_reload\nnew_worker\nhttp3_after_reload\n' >> "$EVIDENCE_DIR/checks.passed"
  jq -n --arg master "$SMOKE_MASTER" --arg start "$master_start" --arg before "$worker_before" --arg after "$worker_after" --arg uid "$worker_uid" --arg gid "$worker_gid" '{master_pid:$master,master_start:$start,worker_before:$before,worker_after:$after,worker_uid:$uid,worker_gid:$gid}' > "$EVIDENCE_DIR/processes.json"
}

main() {
  if [[ ${1:-} == --namespace && $# == 1 ]]; then smoke_namespace; return; fi
  [[ $# == 0 && $(uname -s) == Linux && $(id -u) == 0 ]] || { printf '%s\n' 'Linux root is required (environment inputs only)' >&2; return 2; }
  [[ ${SOURCE_COMMIT:-} =~ ^[0-9a-f]{40}$ && ${SOURCE_TREE:-} =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' '40 lowercase hex source commit and tree are required' >&2; return 2; }
  local file command status=FAIL
  for file in "${PAYLOAD_DIR:-}" "${EVIDENCE_DIR:-}"; do
    [[ $file =~ ^/[A-Za-z0-9_./-]+$ && $file != /opt && $file != /opt/* && $file != /usr/local && $file != /usr/local/* ]] || { printf '%s\n' 'absolute safe paths outside /opt and /usr/local are required' >&2; return 2; }
  done
  [[ -d $PAYLOAD_DIR && ! -L $PAYLOAD_DIR && ! -e $EVIDENCE_DIR && ! -L $EVIDENCE_DIR ]] || { printf '%s\n' 'real inputs and a new evidence directory are required' >&2; return 2; }
  [[ -f $PAYLOAD_DIR/runtime/bin/h3probe && ! -L $PAYLOAD_DIR/runtime/bin/h3probe && -x $PAYLOAD_DIR/runtime/bin/h3probe ]] || { printf '%s\n' 'the packaged runtime/bin/h3probe is required' >&2; return 2; }
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin
  for command in unshare timeout mount ip curl openssl jq python3 readelf realpath find sort ps getent; do command -v "$command" >/dev/null || { printf 'missing dependency: %s\n' "$command" >&2; return 2; }; done
  PAYLOAD_DIR=$(realpath -e "$PAYLOAD_DIR"); EVIDENCE_DIR="$(realpath -e "$(dirname "$EVIDENCE_DIR")")/$(basename "$EVIDENCE_DIR")"
  for file in "$PAYLOAD_DIR" "$EVIDENCE_DIR"; do [[ $file != /opt/* && $file != /usr/local/* && $file =~ ^/[A-Za-z0-9_./-]+$ ]] || return 2; done
  [[ $EVIDENCE_DIR != "$PAYLOAD_DIR"/* && $(id -u nobody) != 0 && $(getent group nogroup | cut -d: -f3) =~ ^[1-9][0-9]*$ ]] || return 2
  curl --version | grep -w HTTP2 >/dev/null
  for file in "$PAYLOAD_DIR/runtime/bin/h3probe" "$PAYLOAD_DIR/runtime/lib/ld-musl-x86_64.so.1" "$PAYLOAD_DIR/runtime/openresty/nginx/sbin/nginx"; do readelf -h "$file" | grep -E 'Machine:.*Advanced Micro Devices X86-64' >/dev/null; done
  umask 077; mkdir "$EVIDENCE_DIR"; SMOKE_WORK=$(mktemp -d /tmp/cdnca-native-runtime-smoke.XXXXXXXX)
  SMOKE_INSIDE=0; SMOKE_RUNNER=; SMOKE_MASTER=; trap cleanup_smoke EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
  cat > "$SMOKE_WORK/inventory.py" <<'INVENTORY'
import hashlib, json, os, pathlib, re, stat, sys
root = pathlib.Path(sys.argv[1]); files = []
for prefix in ('runtime', 'lua'):
    base = root / prefix
    if not base.is_dir() or base.is_symlink(): raise ValueError('ordinary payload files and directories required')
    for directory, dirs, names in os.walk(base, followlinks=False):
        for name in dirs + names:
            path = pathlib.Path(directory) / name; mode = path.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)): raise ValueError('ordinary payload files and directories required')
            relative = path.relative_to(root).as_posix()
            if not re.fullmatch(r'[A-Za-z0-9_./+-]+', relative): raise ValueError('unsafe payload path')
            if stat.S_ISREG(mode): files.append(dict(path=relative, sha256=hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()))
if not files or not any(f['path'].startswith('lua/') for f in files): raise ValueError('runtime and Lua inventory required')
print(json.dumps(sorted(files, key=lambda f: f['path']), separators=(',', ':')))
INVENTORY
  python3 "$SMOKE_WORK/inventory.py" "$PAYLOAD_DIR" > "$EVIDENCE_DIR/files.json"
  : > "$EVIDENCE_DIR/checks.passed"; printf '{}\n' > "$EVIDENCE_DIR/processes.json"
  SMOKE_OUTER_MNT=$(readlink /proc/self/ns/mnt); SMOKE_OUTER_NET=$(readlink /proc/self/ns/net); SMOKE_OUTER_PID=$(readlink /proc/self/ns/pid)
  export PAYLOAD_DIR EVIDENCE_DIR SMOKE_WORK SMOKE_OUTER_MNT SMOKE_OUTER_NET SMOKE_OUTER_PID
  timeout --signal=TERM --kill-after=5s 90s unshare --mount --net --pid --fork --mount-proc --kill-child=KILL --propagation private bash "$(realpath -e "${BASH_SOURCE[0]}")" --namespace > "$EVIDENCE_DIR/namespace.log" 2>&1 & SMOKE_RUNNER=$!
  if wait "$SMOKE_RUNNER"; then status=PASS; fi; SMOKE_RUNNER=
  if ! python3 "$SMOKE_WORK/inventory.py" "$PAYLOAD_DIR" > "$EVIDENCE_DIR/files.after.json" || ! cmp -s "$EVIDENCE_DIR/files.json" "$EVIDENCE_DIR/files.after.json"; then status=FAIL; fi
  jq -Rn '[inputs | {key:.,value:"PASS"}] | from_entries' < "$EVIDENCE_DIR/checks.passed" > "$EVIDENCE_DIR/checks.json"
  if ! jq -e 'keys == ["dynamic_modules","http1","http2","http3","http3_after_reload","lua","native_loader","new_worker","same_master_reload","stream_tcp"]' "$EVIDENCE_DIR/checks.json" >/dev/null; then status=FAIL; fi
  jq -n --arg status "$status" --arg commit "$SOURCE_COMMIT" --arg tree "$SOURCE_TREE" --slurpfile files "$EVIDENCE_DIR/files.json" --slurpfile checks "$EVIDENCE_DIR/checks.json" --slurpfile processes "$EVIDENCE_DIR/processes.json" '{schema:"cdnca.native-node.runtime-smoke/v1",status:$status,source:{commit:$commit,tree:$tree},checks:$checks[0],files:$files[0],processes:$processes[0],scope:"isolated runtime only; source authentication and security review are separate"}' > "$EVIDENCE_DIR/result.json"
  cat "$EVIDENCE_DIR/result.json"; [[ $status == PASS ]]
}
main "$@"
