#!/usr/bin/env bash
# Two-container migration acceptance for control-api native-backup:
#   old host (populated native layout, writers running) --migrate-to over SSH--> empty new host
# Real: systemd units, freeze/hold/unfreeze, PostgreSQL pg_dump/roles/restore,
# NATS JetStream cold copy, object store ownership remap, age encryption,
# Ed25519 signing, SSH + SFTP with a pinned host key, verify-migration.
# Stand-ins: control-api/agent-gateway/object store processes, ClickHouse
# (absent), dependency installer (see fixture.sh). Requires docker; uses 2
# containers, removed on exit.
#   bash tests/control-migrate-e2e/run.sh
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/tests/control-migrate-e2e"
PREFIX=cdnca-g10-e2e
OLD=$PREFIX-old NEW=$PREFIX-new NET=$PREFIX-net IMAGE=$PREFIX:ubuntu24
WORK=$(mktemp -d "${TMPDIR:-/tmp}/$PREFIX.XXXXXX")
failures=0
cleanup() {
  docker rm -f "$OLD" "$NEW" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
say() { printf '[migrate-e2e] %s\n' "$*"; }
check() { # check NAME COMMAND...
  local name=$1; shift
  if "$@"; then say "PASS $name"; else say "FAIL $name"; failures=$((failures + 1)); fi
}
on() { local host=$1; shift; docker exec "$host" bash -c "$*"; }

arch=$(docker info --format '{{.Architecture}}' 2>/dev/null)
case "$arch" in aarch64|arm64) goarch=arm64 ;; x86_64|amd64) goarch=amd64 ;; *) echo "unsupported docker arch $arch" >&2; exit 2 ;; esac
say "building control-api linux/$goarch"
GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go -C "$ROOT/services/control-api" build -trimpath \
  -ldflags "-X main.controlVersion=1.0.35" -o "$WORK/control-api" ./cmd/control-api
say "building image $IMAGE"
docker build -q -t "$IMAGE" "$HERE" >/dev/null
docker network create "$NET" >/dev/null
for host in "$OLD" "$NEW"; do
  docker run -d --rm --name "$host" --hostname "$host" --network "$NET" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$IMAGE" >/dev/null
done
for host in "$OLD" "$NEW"; do
  for _ in $(seq 60); do
    state=$(docker exec "$host" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 1
  done
  docker cp "$HERE/fixture.sh" "$host:/opt/fixture/fixture.sh"
done
docker cp "$WORK/control-api" "$OLD:/opt/fixture/control-api"
on "$OLD" "bash /opt/fixture/fixture.sh old" | tail -1
on "$NEW" "bash /opt/fixture/fixture.sh target"

CTL=/data/cdnca-native-root/cdnca/current/bin/control-api
psql_old() { on "$OLD" "runuser -u postgres -- psql -XAtq -d cdnca -c \"$1\""; }
psql_new() { on "$NEW" "runuser -u postgres -- psql -XAtq -d cdnca -c \"$1\""; }
nats_messages() { on "$1" "curl -fsS 'http://127.0.0.1:8222/jsz?streams=true' | jq '[.account_details[].stream_detail[] | select(.name==\"AGENT_COMMANDS\") | .state.messages] | add // 0'"; }
sleep 2
check "source writes are flowing" test "$(psql_old 'SELECT count(*) > 0 FROM writes')" = t
check "source JetStream holds 250 messages" test "$(nats_messages "$OLD")" = 250
before_sha=$(on "$OLD" "sha256sum /var/lib/cdnca-objectstore/cdnca-assets/brand-logo.bin | cut -d' ' -f1")
source_signer=$(on "$OLD" "$CTL native-backup fingerprint")

say "pinning the new host's SSH key"
host_key=$(on "$OLD" "$CTL native-backup host-key --host $NEW --port 22")
say "migrating $OLD -> $NEW"
if ! printf 'migrate-e2e-root\n' | docker exec -i "$OLD" "$CTL" native-backup migrate-to --host "$NEW" --port 22 --user root \
    --host-key "$host_key" --password-stdin >"$WORK/migrate.out" 2>"$WORK/migrate.log"; then
  say "migrate-to failed:"; tail -40 "$WORK/migrate.log"; failures=$((failures + 1))
fi
tail -6 "$WORK/migrate.log" | sed 's/^/    /'
check "migration log carries no credential" bash -c "! grep -q 'migrate-e2e-root' '$WORK/migrate.log'"

for unit in cdnca-control-api cdnca-agent-gateway; do
  check "old $unit stopped and disabled (hold)" test "$(on "$OLD" "systemctl is-active $unit; systemctl is-enabled $unit" | tr '\n' ' ')" = "inactive disabled "
  check "new $unit running" test "$(on "$NEW" "systemctl is-active $unit")" = active
done
last_old=$(psql_old 'SELECT max(id) FROM writes')
sleep 3
check "no write reaches the frozen source" test "$(psql_old 'SELECT max(id) FROM writes')" = "$last_old"
check "sites restored (2000 rows)" test "$(psql_new 'SELECT count(*) FROM sites')" = 2000
check "schema version restored" test "$(psql_new 'SELECT max(version) FROM schema_migrations')" = 302
check "role grant restored" test "$(psql_new "SELECT has_table_privilege('cdnca_control_app','sites','SELECT')")" = t
check "new host keeps every source write captured at freeze" test "$(psql_new "SELECT count(*) FROM writes WHERE id <= $last_old")" -ge 1
check "DATABASE_URL password still authenticates" on "$NEW" \
  'psql "$(sed -n "s/^DATABASE_URL=//p" /etc/cdnca-control/control.env)" -XAtqc "select 1" | grep -qx 1'
check "JetStream messages restored (250)" test "$(nats_messages "$NEW")" = 250
check "object store bytes restored" test "$(on "$NEW" "sha256sum /var/lib/cdnca-objectstore/cdnca-assets/brand-logo.bin | cut -d' ' -f1")" = "$before_sha"
check "object store owner remapped by name" test "$(on "$NEW" "stat -c %U /var/lib/cdnca-objectstore/cdnca-assets/brand-logo.bin")" = cdnca-objectstore
check "secret key file restored owner-only" test "$(on "$NEW" "stat -c %a /etc/cdnca-control/keys/pki/node-ca-key.pem")" = 600
check "new host signs with the same backup identity" test "$(on "$NEW" "$CTL native-backup fingerprint")" = "$source_signer"
check "new host backup agent units enabled" test "$(on "$NEW" "systemctl is-enabled cdnca-control-backup.timer")" = enabled
check "one-time identity removed from the new host" on "$NEW" "test ! -e /var/lib/cdnca-control-backup/migrate-in/identity"

say "simulating node reconnect to the new Gateway (DNS switched)"
on "$OLD" "curl -fsS http://$NEW:8082/agent/connect >/dev/null"
bundle=$(on "$NEW" "ls -d /var/lib/cdnca-control-backup/bundles/2*" | tail -1)
on "$NEW" "$CTL native-backup verify-migration --bundle $bundle" >"$WORK/verify.json" 2>"$WORK/verify.log" || true
check "verify-migration: version/schema/health and 1/1 nodes" \
  jq -e '.version=="1.0.35" and .schema_version==302 and .control_ready and .gateway_ready and .online_nodes==1 and .active_nodes==1' "$WORK/verify.json"

say "rollback: unfreeze the old host"
on "$OLD" "$CTL native-backup unfreeze"
check "old control-api serving again after unfreeze" test "$(on "$OLD" "systemctl is-active cdnca-control-api; systemctl is-enabled cdnca-control-api" | tr '\n' ' ')" = "active enabled "

say "restore refuses a populated target"
check "second restore onto the new host is refused" bash -c "! docker exec '$NEW' '$CTL' native-backup restore --bundle '$bundle' --signer '$source_signer' --identity /etc/cdnca-control/keys/backup/identity.age-key >/dev/null 2>&1"

if [ "$failures" -eq 0 ]; then say "RESULT PASS"; else say "RESULT FAIL ($failures)"; exit 1; fi
