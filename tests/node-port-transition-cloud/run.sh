#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Run an already-built Linux test binary with an isolated, loopback-only broker.
test_binary=${1:?usage: run.sh /absolute/path/to/transport.test}
[[ $test_binary = /* && -x $test_binary ]] || exit 64
command -v nats-server >/dev/null
command -v python3 >/dev/null
work_dir=$(mktemp -d /data/cdnca-port-transport.XXXXXX)
nats_pid=''
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n $nats_pid ]] && kill -0 "$nats_pid" 2>/dev/null; then
    if tr '\0' ' ' <"/proc/$nats_pid/cmdline" | grep -Fq -- "$work_dir/jetstream"; then
      kill -TERM "$nats_pid"
      wait "$nats_pid" || true
    else
      status=1
    fi
  fi
  if ! python3 - "$work_dir" <<'PY'
import pathlib, sys
marker = sys.argv[1].encode()
owned = orphans = 0
for entry in pathlib.Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    try:
        cmd = (entry / 'cmdline').read_bytes()
        # Our scanner names the directory, so restrict ownership to NATS.
        if marker + b'/jetstream' not in cmd:
            continue
        owned += 1
        status = (entry / 'status').read_text()
        orphans += any(line.split() == ['PPid:', '1'] for line in status.splitlines())
    except FileNotFoundError:
        continue
print(f'PORT_TRANSPORT_CLEANUP processes={owned} ppid1_orphans={orphans}')
sys.exit(bool(owned or orphans))
PY
  then status=1; fi
  if [[ $status -eq 0 || $status -eq 1 ]]; then
    case "$work_dir" in /data/cdnca-port-transport.??????) rm -rf -- "$work_dir" ;; *) status=1 ;; esac
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

port=$(python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    print(s.getsockname()[1])
PY
)
nats-server -a 127.0.0.1 -p "$port" -js -sd "$work_dir/jetstream" >"$work_dir/nats.log" 2>&1 &
nats_pid=$!
python3 - "$port" <<'PY'
import socket, sys, time
for _ in range(50):
    try:
        with socket.create_connection(('127.0.0.1', int(sys.argv[1])), .2):
            break
    except OSError:
        time.sleep(.1)
else:
    sys.exit('owned NATS did not start')
PY
nats-server --version
sha256sum "$test_binary"
TMPDIR="$work_dir" PORT_TRANSITION_TEST_NATS_URL="nats://127.0.0.1:$port" \
  "$test_binary" -test.v -test.timeout=40s
