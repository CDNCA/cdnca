#!/usr/bin/env bash
# Two-container migration acceptance for control-api native-backup:
#   old host (populated native layout, writers running) --migrate-to over SSH--> empty new host
# Real: systemd units, freeze/hold/unfreeze, PostgreSQL pg_dump/roles/restore,
# NATS JetStream cold copy, object store ownership remap, age encryption,
# Ed25519 signing, SSH + SFTP with a pinned host key, verify-migration.
# migrate-ip: the Gateway is published by IP and is the production Connect
# service; a third container runs two production gatewayclient nodes. One
# stays online through the migration and must follow the new IP on its own
# (announce-gateway -> GatewayHello list -> failover); the other is offline
# during the migration and is moved with `edge-agent set-gateway`.
# Stand-ins: control-api/object store processes, ClickHouse (absent),
# dependency installer (see fixture.sh), node deployments. Requires docker;
# uses 3 containers, removed on exit.
#   bash tests/control-migrate-e2e/run.sh
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/tests/control-migrate-e2e"
PREFIX=cdnca-g10-e2e
OLD=$PREFIX-old NEW=$PREFIX-new NODE=$PREFIX-node NET=$PREFIX-net IMAGE=$PREFIX:ubuntu24
WORK=$(mktemp -d "${TMPDIR:-/tmp}/$PREFIX.XXXXXX")
failures=0
cleanup() {
  if [ "${MIGRATE_E2E_KEEP:-}" = 1 ]; then echo "[migrate-e2e] kept containers and $WORK" >&2; return; fi
  docker rm -f "$OLD" "$NEW" "$NODE" >/dev/null 2>&1 || true
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
say "building agent-gateway (Connect service) and edge-agent linux/$goarch"
GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go -C "$ROOT/services/agent-gateway" test -c -o "$WORK/agent-gateway.test" .
GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go -C "$ROOT/agents/edge-agent" test -c -o "$WORK/agent.test" ./cmd/edge-agent
GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go -C "$ROOT/agents/edge-agent" build -trimpath -o "$WORK/edge-agent" ./cmd/edge-agent
say "building image $IMAGE"
docker build -q -t "$IMAGE" "$HERE" >/dev/null
docker network create "$NET" >/dev/null
for host in "$OLD" "$NEW" "$NODE"; do
  docker run -d --rm --name "$host" --hostname "$host" --network "$NET" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$IMAGE" >/dev/null
done
for host in "$OLD" "$NEW" "$NODE"; do
  for _ in $(seq 60); do
    state=$(docker exec "$host" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running|degraded) break ;; esac
    sleep 1
  done
  docker cp "$HERE/fixture.sh" "$host:/opt/fixture/fixture.sh"
done
ip_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }
OLD_IP=$(ip_of "$OLD") NEW_IP=$(ip_of "$NEW")
say "old host $OLD_IP, new host $NEW_IP (Gateway by IP)"
docker cp "$WORK/control-api" "$OLD:/opt/fixture/control-api"
docker cp "$WORK/agent-gateway.test" "$OLD:/opt/fixture/agent-gateway.test"
on "$OLD" "bash /opt/fixture/fixture.sh old $OLD_IP" | tail -1
on "$NEW" "bash /opt/fixture/fixture.sh target"

CTL=/data/cdnca-native-root/cdnca/current/bin/control-api
NODE_A=11111111-1111-4111-8111-111111111111 NODE_B=22222222-2222-4222-8222-222222222222
# Nodes: identities issued by the old host's root, config.json dialing the old IP.
docker cp "$OLD:/opt/fixture/nodes" "$WORK/nodes"
docker cp "$WORK/nodes" "$NODE:/opt/fixture/nodes"
docker cp "$WORK/agent.test" "$NODE:/opt/fixture/agent.test"
docker cp "$WORK/edge-agent" "$NODE:/usr/local/bin/edge-agent"
for node in $NODE_A $NODE_B; do
  on "$NODE" "MIGRATE_IP_E2E_AGENT_CONFIG=/opt/fixture/nodes/$node/config.json MIGRATE_IP_E2E_NODE_ID=$node \
    MIGRATE_IP_E2E_GATEWAY=$OLD_IP:19444 MIGRATE_IP_E2E_STATE=/var/lib/e2e-nodes/$node \
    /opt/fixture/agent.test -test.run '^TestMigrateIPAgentConfig\$' -test.count=1 >/dev/null"
done
node_start() {
  docker exec -d "$NODE" bash -c "echo \$\$ >/opt/fixture/nodes/$1/pid; MIGRATE_IP_E2E_AGENT_CONFIG=/opt/fixture/nodes/$1/config.json \
    exec /opt/fixture/agent.test -test.run '^TestMigrateIPAgentProcess\$' -test.count=1 -test.v -test.timeout 0 >>/opt/fixture/nodes/$1/agent.log 2>&1"
}
node_stop() { on "$NODE" "kill -TERM \$(cat /opt/fixture/nodes/$1/pid); for _ in \$(seq 50); do kill -0 \$(cat /opt/fixture/nodes/$1/pid) 2>/dev/null || exit 0; sleep 0.2; done; exit 1"; }
presence() { # presence HOST NODE -> online|offline
  on "$1" "runuser -u postgres -- psql -XAtq -d cdnca -c \"SELECT status FROM node_presence WHERE node_id='$2'\""
}
wait_online() { # wait_online HOST NODE SECONDS
  for _ in $(seq "$3"); do [ "$(presence "$1" "$2" 2>/dev/null)" = online ] && return 0; sleep 1; done; return 1
}
# node_presence was copied from the source; a session on the new host is
# proven by that host's Gateway, which logs every authenticated session.
sessions_on() { on "$1" "journalctl -u cdnca-agent-gateway --no-pager | grep -c 'node $2 online'" || true; }
wait_session() { # wait_session HOST NODE SECONDS
  for _ in $(seq "$3"); do [ "$(sessions_on "$1" "$2")" -gt 0 ] && return 0; sleep 1; done; return 1
}
psql_old() { on "$OLD" "runuser -u postgres -- psql -XAtq -d cdnca -c \"$1\""; }
psql_new() { on "$NEW" "runuser -u postgres -- psql -XAtq -d cdnca -c \"$1\""; }
nats_messages() { on "$1" "curl -fsS 'http://127.0.0.1:8222/jsz?streams=true' | jq '[.account_details[].stream_detail[] | select(.name==\"AGENT_COMMANDS\") | .state.messages] | add // 0'"; }
node_start $NODE_A
node_start $NODE_B
check "node A online on the old Gateway (by IP)" wait_online "$OLD" $NODE_A 60
check "node B online on the old Gateway (by IP)" wait_online "$OLD" $NODE_B 60
say "node B goes offline before the migration"
node_stop $NODE_B
check "node B offline" test "$(presence "$OLD" $NODE_B)" = offline
check "source writes are flowing" test "$(psql_old 'SELECT count(*) > 0 FROM writes')" = t
check "source JetStream holds 250 messages" test "$(nats_messages "$OLD")" = 250
before_sha=$(on "$OLD" "sha256sum /var/lib/cdnca-objectstore/cdnca-assets/brand-logo.bin | cut -d' ' -f1")
source_signer=$(on "$OLD" "$CTL native-backup fingerprint")

say "pinning the new host's SSH key"
host_key=$(on "$OLD" "$CTL native-backup host-key --host $NEW_IP --port 22")
say "migrating $OLD ($OLD_IP) -> $NEW ($NEW_IP)"
if ! printf 'migrate-e2e-root\n' | docker exec -i "$OLD" "$CTL" native-backup migrate-to --host "$NEW_IP" --port 22 --user root \
    --host-key "$host_key" --password-stdin >"$WORK/migrate.out" 2>"$WORK/migrate.log"; then
  say "migrate-to failed:"; tail -40 "$WORK/migrate.log"; failures=$((failures + 1))
fi
grep -E 'announce|gateway:' "$WORK/migrate.log" | sed 's/^/    /'
tail -4 "$WORK/migrate.log" | sed 's/^/    /'
check "announce: the online node reconnected and learned the new IP" grep -q "announce: 1/1 online nodes reconnected and learned $NEW_IP:19444" "$WORK/migrate.log"
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

say "online node A follows the new IP with no DNS and no node-side action"
check "new Gateway certificate names the new IP (same root)" on "$NEW" \
  "openssl x509 -in /etc/cdnca-control/keys/pki/gateway-server.pem -noout -ext subjectAltName | grep -q 'IP Address:$NEW_IP' && \
   openssl verify -CAfile /etc/cdnca-control/keys/pki/root-ca-cert.pem /etc/cdnca-control/keys/pki/gateway-server.pem >/dev/null"
check "new host gateway.env publishes the new IP" on "$NEW" "grep -qx 'CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=$NEW_IP:19444' /etc/cdnca-control/gateway.env"
check "node A has a session on the new Gateway with its original certificate" wait_session "$NEW" $NODE_A 90
check "node A persisted the new IP in its endpoint list" on "$NODE" \
  "jq -e --arg a $NEW_IP:19444 '[.endpoints[].Address] | index(\$a) != null' /var/lib/e2e-nodes/$NODE_A/gateway-journal/gateway-endpoints.json >/dev/null"
bundle=$(on "$NEW" "ls -d /var/lib/cdnca-control-backup/bundles/2*" | tail -1)
on "$NEW" "$CTL native-backup verify-migration --bundle $bundle" >"$WORK/verify.json" 2>"$WORK/verify.log" || true
check "verify-migration: version/schema/health, 1 online of 2 nodes, set-gateway hint" \
  jq -e --arg ip "$NEW_IP:19444" '.version=="1.0.35" and .schema_version==302 and .control_ready and .gateway_ready and .online_nodes==1 and .active_nodes==2
    and ([.warnings[]? | select(contains("set-gateway --address " + $ip))] | length == 1)' "$WORK/verify.json"

say "offline node B: back online, it only knows the old IP"
node_start $NODE_B
sleep 8
check "node B does not reach the new Gateway on its own" test "$(sessions_on "$NEW" $NODE_B)" = 0
node_stop $NODE_B
say "edge-agent set-gateway on node B"
on "$NODE" "/usr/local/bin/edge-agent set-gateway --config /opt/fixture/nodes/$NODE_B/config.json --address $NEW_IP:19444" | sed 's/^/    /'
check "node B config points at the new IP" on "$NODE" \
  "jq -e --arg a $NEW_IP:19444 --arg s $NEW_IP '.gateway.address==\$a and .gateway.server_name==\$s and .node_id==\"$NODE_B\"' /opt/fixture/nodes/$NODE_B/config.json >/dev/null"
node_start $NODE_B
check "node B has a session on the new Gateway after set-gateway" wait_session "$NEW" $NODE_B 60

say "rollback: unfreeze the old host"
on "$OLD" "$CTL native-backup unfreeze"
check "old control-api serving again after unfreeze" test "$(on "$OLD" "systemctl is-active cdnca-control-api; systemctl is-enabled cdnca-control-api" | tr '\n' ' ')" = "active enabled "

say "restore refuses a populated target"
check "second restore onto the new host is refused" bash -c "! docker exec '$NEW' '$CTL' native-backup restore --bundle '$bundle' --signer '$source_signer' --identity /etc/cdnca-control/keys/backup/identity.age-key >/dev/null 2>&1"

if [ "$failures" -eq 0 ]; then say "RESULT PASS"; else say "RESULT FAIL ($failures)"; exit 1; fi
