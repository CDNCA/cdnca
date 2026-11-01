#!/usr/bin/env bash
# Disaster-recovery acceptance for the recovery kit (recovery-optional):
# the old host exports a kit without a passphrase (default) and one with a
# passphrase, takes a backup, and is "lost"; an empty new host restores the
# copied bundle with each kit. The kit without a passphrase restores with
# stdin closed (no prompt); the sealed one refuses a wrong passphrase and
# restores with the right one. Reuses the control-migrate-e2e image/fixture.
#   bash tests/control-migrate-e2e/recovery-kit.sh
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/tests/control-migrate-e2e"
PREFIX=cdnca-recovery-kit
OLD=$PREFIX-old NEW=$PREFIX-new NEW2=$PREFIX-new2 IMAGE=cdnca-g10-e2e:ubuntu24
WORK=$(mktemp -d "${TMPDIR:-/tmp}/$PREFIX.XXXXXX")
failures=0
cleanup() { docker rm -f "$OLD" "$NEW" "$NEW2" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
say() { printf '[recovery-kit] %s\n' "$*"; }
check() { local name=$1; shift; if "$@"; then say "PASS $name"; else say "FAIL $name"; failures=$((failures + 1)); fi; }
on() { local host=$1; shift; docker exec "$host" bash -c "$*"; }

arch=$(docker info --format '{{.Architecture}}' 2>/dev/null)
case "$arch" in aarch64|arm64) goarch=arm64 ;; x86_64|amd64) goarch=amd64 ;; *) echo "unsupported docker arch $arch" >&2; exit 2 ;; esac
say "building control-api linux/$goarch"
GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go -C "$ROOT/services/control-api" build -trimpath \
  -ldflags "-X main.controlVersion=1.0.35" -o "$WORK/control-api" ./cmd/control-api
docker build -q -t "$IMAGE" "$HERE" >/dev/null
for host in "$OLD" "$NEW" "$NEW2"; do
  docker run -d --rm --name "$host" --hostname "$host" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$IMAGE" >/dev/null
done
for host in "$OLD" "$NEW" "$NEW2"; do
  for _ in $(seq 60); do
    state=$(docker exec "$host" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 1
  done
  docker cp "$HERE/fixture.sh" "$host:/opt/fixture/fixture.sh"
  docker cp "$WORK/control-api" "$host:/root/control-api"
done
docker cp "$WORK/control-api" "$OLD:/opt/fixture/control-api"
on "$OLD" "bash /opt/fixture/fixture.sh old" | tail -1
CTL=/data/cdnca-native-root/cdnca/current/bin/control-api
signer=$(on "$OLD" "$CTL native-backup fingerprint")

say "exporting kits on the old host"
on "$OLD" "$CTL native-backup export-recovery-kit --output /root/kit-plain.json </dev/null" 2>"$WORK/export-plain.err"
check "default export warns the file is the credential" grep -q '这个文件就是恢复凭据' "$WORK/export-plain.err"
check "default kit has no passphrase" on "$OLD" "jq -e '.has_passphrase==false and (.identity|startswith(\"AGE-SECRET-KEY-\")) and (has(\"sealed_identity\")|not)' /root/kit-plain.json >/dev/null"
check "default kit is owner-only" test "$(on "$OLD" "stat -c %a /root/kit-plain.json")" = 600
printf 'recovery kit passphrase 2026\n' | docker exec -i "$OLD" "$CTL" native-backup export-recovery-kit --passphrase --output /root/kit-sealed.json
check "opt-in kit is sealed" on "$OLD" "jq -e '.has_passphrase==true and (.sealed_identity|length>0) and (has(\"identity\")|not)' /root/kit-sealed.json >/dev/null"
check "short passphrase refused" bash -c "! printf 'short\n' | docker exec -i '$OLD' '$CTL' native-backup export-recovery-kit --passphrase --output /root/kit-weak.json >/dev/null 2>&1"

say "backing up, then losing the old host"
backup_id=$(on "$OLD" "$CTL native-backup create --reason manual" | jq -r .backup_id)
sites=$(on "$OLD" "runuser -u postgres -- psql -XAtq -d cdnca -c 'SELECT count(*) FROM sites'")
for name in plain sealed; do docker cp "$OLD:/root/kit-$name.json" "$WORK/kit-$name.json"; done
docker cp "$OLD:/var/lib/cdnca-control-backup/bundles/$backup_id" "$WORK/bundle"
deps=$(on "$OLD" "cat /usr/local/cdnca-control/support/install-ubuntu-dependencies.sh")
docker rm -f "$OLD" >/dev/null
bundle=/var/lib/cdnca-control-backup/bundles/$backup_id
for host in "$NEW" "$NEW2"; do
  on "$host" "mkdir -p /var/lib/cdnca-control-backup/bundles"
  docker cp "$WORK/bundle" "$host:$bundle"
  printf '%s\n' "$deps" | docker exec -i "$host" bash -c 'cat >/tmp/deps.sh && bash /tmp/deps.sh install'
done
docker cp "$WORK/kit-plain.json" "$NEW:/root/cdnca-recovery-kit.json"
docker cp "$WORK/kit-sealed.json" "$NEW2:/root/cdnca-recovery-kit.json"

say "restoring with the kit without a passphrase (stdin closed: no prompt possible)"
if docker exec "$NEW" /root/control-api native-backup restore --bundle "$bundle" --recovery-kit /root/cdnca-recovery-kit.json \
    </dev/null >"$WORK/restore-plain.json" 2>"$WORK/restore-plain.log"; then
  say "PASS restore with the kit alone"
else
  say "FAIL restore with the kit alone"; tail -20 "$WORK/restore-plain.log"; failures=$((failures + 1))
fi
check "no passphrase prompt was printed" bash -c "! grep -q '恢复口令' '$WORK/restore-plain.log'"
check "restored data matches ($sites sites)" test "$(on "$NEW" "runuser -u postgres -- psql -XAtq -d cdnca -c 'SELECT count(*) FROM sites'")" = "$sites"
check "restored host signs with the original identity" test "$(on "$NEW" "/root/control-api native-backup fingerprint")" = "$signer"

say "restoring with the sealed kit"
check "wrong passphrase refused" bash -c "! printf 'a wrong passphrase 2026\n' | docker exec -i '$NEW2' /root/control-api native-backup verify --bundle '$bundle' --recovery-kit /root/cdnca-recovery-kit.json >/dev/null 2>&1"
check "sealed kit does not open without its passphrase" bash -c "! docker exec '$NEW2' /root/control-api native-backup verify --bundle '$bundle' --recovery-kit /root/cdnca-recovery-kit.json </dev/null >/dev/null 2>&1"
if printf 'recovery kit passphrase 2026\n' | docker exec -i "$NEW2" /root/control-api native-backup restore --bundle "$bundle" \
    --recovery-kit /root/cdnca-recovery-kit.json >"$WORK/restore-sealed.json" 2>"$WORK/restore-sealed.log"; then
  say "PASS restore with the sealed kit and its passphrase"
else
  say "FAIL restore with the sealed kit and its passphrase"; tail -20 "$WORK/restore-sealed.log"; failures=$((failures + 1))
fi
check "sealed restore data matches" test "$(on "$NEW2" "runuser -u postgres -- psql -XAtq -d cdnca -c 'SELECT count(*) FROM sites'")" = "$sites"

if [ "$failures" -eq 0 ]; then say "RESULT PASS"; else say "RESULT FAIL ($failures)"; exit 1; fi
