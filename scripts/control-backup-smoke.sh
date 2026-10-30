#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly ROOT
readonly TOOL="$ROOT/tools/control-backup/control-backup"
readonly MIGRATIONS="$ROOT/services/control-api/migrations"
readonly APP_VERSION="smoke-2026.07.28"
readonly SOURCE_CLUSTER_ID="ops12a-empty-restore-drill"
readonly SIGNING_KEY_ID="ops12a-offline-ed25519"
readonly PG_IMAGE="postgres:17.9-bookworm@sha256:47f917f7409eacd22fc5dfb1dee634e1b55cf0c01d1a7eb701be2227a03e0641"
readonly CLICKHOUSE_IMAGE="clickhouse/clickhouse-server:25.3.6.56-alpine@sha256:157423fca52f596b62a1bf301b037b9f74bfca38089aa57d1bd36c9025f7ecef"
readonly MINIO_IMAGE="minio/minio@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"
readonly AWS_CLI_IMAGE="amazon/aws-cli@sha256:7cbd2e4d2c469c5c448dc249c7c8109ada7fa6ae57a1dc3f348fa39d19b6c689"

report_error() {
  printf 'error: control-backup smoke failed at line %s\n' "$1" >&2
}
trap 'report_error "$LINENO"' ERR

for command in docker openssl age age-keygen jq go tee truncate; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required smoke command not found: %s\n' "$command" >&2
    exit 1
  }
done
docker image inspect "$PG_IMAGE" >/dev/null 2>&1 || {
  printf 'error: pinned PostgreSQL 17.9 image is unavailable\n' >&2
  exit 1
}
docker image inspect "$CLICKHOUSE_IMAGE" >/dev/null 2>&1 || {
  printf 'error: pinned ClickHouse image is unavailable\n' >&2
  exit 1
}
docker image inspect "$MINIO_IMAGE" >/dev/null 2>&1 || {
  printf 'error: pinned MinIO image is unavailable for immutable remote smoke\n' >&2
  exit 1
}
docker image inspect "$AWS_CLI_IMAGE" >/dev/null 2>&1 || {
  printf 'error: pinned AWS CLI image is unavailable for immutable remote smoke\n' >&2
  exit 1
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-control-backup-smoke.XXXXXX")
tmp=$(cd "$tmp" && pwd -P)
chmod 700 "$tmp"
task_suffix=$(openssl rand -hex 6)
readonly POSTGRES_CONTAINER="ops12a-pg-$task_suffix"
readonly CLICKHOUSE_CONTAINER="ops12a-ch-$task_suffix"
readonly MINIO_CONTAINER="cbdr1-minio-$task_suffix"
readonly TASK_NETWORK="ops12a-backup-$task_suffix"
readonly POSTGRES_VOLUME="ops12a-pgdata-$task_suffix"
readonly POSTGRES_SOCKET_VOLUME="ops12a-pgsocket-$task_suffix"
readonly MINIO_VOLUME="cbdr1-minio-data-$task_suffix"
readonly POSTGRES_SOCKET="/var/run/postgresql"
readonly AWS_OWNER="cbdr1-aws-$task_suffix"
readonly DOCKER_MARKER_WAIT_ATTEMPTS=1200
pg_password=$(openssl rand -hex 24)
clickhouse_password=$(openssl rand -hex 24)
minio_access_key="cbdr1${task_suffix}"
minio_secret_key=$(openssl rand -hex 24)
readonly pg_user=ops12a
readonly clickhouse_user=ops12a
backup_pid=""
hard_interrupt_pid=""

cleanup() {
  local status=$?
  local cleanup_failed=0
  local orphan_count aws_container child_pid
  trap - EXIT
  for child_pid in "${backup_pid:-}" "${hard_interrupt_pid:-}"; do
    [[ "$child_pid" =~ ^[0-9]+$ ]] || continue
    if kill -0 "$child_pid" >/dev/null 2>&1; then
      kill -CONT "$child_pid" >/dev/null 2>&1 || true
      kill -TERM "$child_pid" >/dev/null 2>&1 || true
      for _ in $(seq 1 50); do
        kill -0 "$child_pid" >/dev/null 2>&1 || break
        sleep 0.1
      done
      if kill -0 "$child_pid" >/dev/null 2>&1; then
        kill -KILL "$child_pid" >/dev/null 2>&1 || true
      fi
    fi
    wait "$child_pid" >/dev/null 2>&1 || true
  done
  backup_pid=""
  hard_interrupt_pid=""
  while IFS= read -r aws_container; do
    [[ -z "$aws_container" ]] || docker container rm --force "$aws_container" >/dev/null 2>&1 || true
  done < <(docker container ls --all --quiet \
    --filter "label=cdnca.control-backup-smoke=$AWS_OWNER")
  docker container inspect "$POSTGRES_CONTAINER" >/dev/null 2>&1 &&
    docker container rm --force "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
  docker container inspect "$CLICKHOUSE_CONTAINER" >/dev/null 2>&1 &&
    docker container rm --force "$CLICKHOUSE_CONTAINER" >/dev/null 2>&1 || true
  docker container inspect "$MINIO_CONTAINER" >/dev/null 2>&1 &&
    docker container rm --force "$MINIO_CONTAINER" >/dev/null 2>&1 || true
  docker network inspect "$TASK_NETWORK" >/dev/null 2>&1 &&
    docker network rm "$TASK_NETWORK" >/dev/null 2>&1 || true
  docker volume inspect "$POSTGRES_VOLUME" >/dev/null 2>&1 &&
    docker volume rm "$POSTGRES_VOLUME" >/dev/null 2>&1 || true
  docker volume inspect "$POSTGRES_SOCKET_VOLUME" >/dev/null 2>&1 &&
    docker volume rm "$POSTGRES_SOCKET_VOLUME" >/dev/null 2>&1 || true
  docker volume inspect "$MINIO_VOLUME" >/dev/null 2>&1 &&
    docker volume rm "$MINIO_VOLUME" >/dev/null 2>&1 || true
  rm -rf -- "$tmp"
  docker container inspect "$POSTGRES_CONTAINER" >/dev/null 2>&1 && cleanup_failed=1
  docker container inspect "$CLICKHOUSE_CONTAINER" >/dev/null 2>&1 && cleanup_failed=1
  docker container inspect "$MINIO_CONTAINER" >/dev/null 2>&1 && cleanup_failed=1
  docker network inspect "$TASK_NETWORK" >/dev/null 2>&1 && cleanup_failed=1
  docker volume inspect "$POSTGRES_VOLUME" >/dev/null 2>&1 && cleanup_failed=1
  docker volume inspect "$POSTGRES_SOCKET_VOLUME" >/dev/null 2>&1 && cleanup_failed=1
  docker volume inspect "$MINIO_VOLUME" >/dev/null 2>&1 && cleanup_failed=1
  [[ -z $(docker container ls --all --quiet \
    --filter "label=cdnca.control-backup-smoke=$AWS_OWNER") ]] || cleanup_failed=1
  orphan_count=$(ps -Ao ppid=,command= | awk -v pg="$POSTGRES_CONTAINER" -v ch="$CLICKHOUSE_CONTAINER" \
    -v minio="$MINIO_CONTAINER" \
    '$1 == 1 && (index($0, pg) || index($0, ch) || index($0, minio)) {count++} END {print count + 0}')
  unset pg_password clickhouse_password minio_access_key minio_secret_key PGPASSWORD CLICKHOUSE_PASSWORD
  if ((orphan_count != 0)); then
    printf 'error: task-owned PPID=1 orphans remain after cleanup: %s\n' "$orphan_count" >&2
    cleanup_failed=1
  fi
  if ((cleanup_failed != 0)); then
    printf 'error: task-owned resources remain after cleanup\n' >&2
    exit 1
  fi
  if ((status == 0)); then
    printf 'cleanup_residual_containers=0\n'
    printf 'cleanup_residual_networks=0\n'
    printf 'cleanup_residual_volumes=0\n'
    printf 'cleanup_ppid1_orphans=%s\n' "$orphan_count"
  fi
  exit "$status"
}
trap cleanup EXIT

docker network create "$TASK_NETWORK" >/dev/null
docker volume create "$POSTGRES_VOLUME" >/dev/null
docker volume create "$POSTGRES_SOCKET_VOLUME" >/dev/null
docker volume create "$MINIO_VOLUME" >/dev/null
mkdir "$tmp/bin"
tee "$tmp/bin/aws" >/dev/null <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail

[[ -n "${AWS_SHARED_CREDENTIALS_FILE:-}" && -f "$AWS_SHARED_CREDENTIALS_FILE" ]]
[[ -n "${CONTROL_BACKUP_AWS_NETWORK:-}" && -n "${CONTROL_BACKUP_AWS_IMAGE:-}" &&
  -n "${CONTROL_BACKUP_AWS_OWNER:-}" ]]
arguments=("$@")
rewritten=()
mounts=(--mount "type=bind,src=$AWS_SHARED_CREDENTIALS_FILE,dst=/aws/credentials,readonly")
action="" output_host=""
for ((index = 0; index < ${#arguments[@]}; index++)); do
  if [[ "${arguments[index]}" == "s3api" && $((index + 1)) -lt ${#arguments[@]} ]]; then
    action=${arguments[index + 1]}
    break
  fi
done
for ((index = 0; index < ${#arguments[@]}; index++)); do
  argument=${arguments[index]}
  if [[ "$argument" == "--body" && $((index + 1)) -lt ${#arguments[@]} ]]; then
    rewritten+=("$argument")
    index=$((index + 1))
    body=${arguments[index]}
    mounts+=(--mount "type=bind,src=$(dirname "$body"),dst=/aws/body,readonly")
    rewritten+=("/aws/body/$(basename "$body")")
  elif [[ "$action" == "get-object" && $index -eq $((${#arguments[@]} - 1)) ]]; then
    output_host=$argument
    mounts+=(--mount "type=bind,src=$(dirname "$output_host"),dst=/aws/output")
    rewritten+=("/aws/output/$(basename "$output_host")")
  else
    rewritten+=("$argument")
  fi
done
docker run --rm --network "$CONTROL_BACKUP_AWS_NETWORK" \
  --label "cdnca.control-backup-smoke=$CONTROL_BACKUP_AWS_OWNER" "${mounts[@]}" \
  -e AWS_SHARED_CREDENTIALS_FILE=/aws/credentials -e AWS_PROFILE=default \
  -e AWS_CONFIG_FILE=/dev/null -e AWS_EC2_METADATA_DISABLED=true \
  -e AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
  -e AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
  "$CONTROL_BACKUP_AWS_IMAGE" "${rewritten[@]}"
[[ -z "$output_host" ]] || chmod 600 "$output_host"
SH
chmod 700 "$tmp/bin/aws"
printf 'MINIO_ROOT_USER=%s\nMINIO_ROOT_PASSWORD=%s\n' "$minio_access_key" "$minio_secret_key" \
  > "$tmp/minio.env"
printf '[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n' \
  "$minio_access_key" "$minio_secret_key" > "$tmp/remote-credentials"
chmod 0400 "$tmp/minio.env" "$tmp/remote-credentials"
export PATH="$tmp/bin:$PATH"
export CONTROL_BACKUP_AWS_NETWORK="$TASK_NETWORK" CONTROL_BACKUP_AWS_IMAGE="$AWS_CLI_IMAGE"
export CONTROL_BACKUP_AWS_OWNER="$AWS_OWNER"
export CONTROL_BACKUP_ENABLE_TEST_HOOKS=1
export AWS_SHARED_CREDENTIALS_FILE="$tmp/remote-credentials"
readonly REMOTE_BUCKET="cbdr1-$task_suffix"
readonly REMOTE_ENDPOINT="http://$MINIO_CONTAINER:9000"
remote_args=(--remote-endpoint "$REMOTE_ENDPOINT" --remote-region us-east-1 \
  --remote-bucket "$REMOTE_BUCKET" --remote-prefix control \
  --remote-credentials-file "$tmp/remote-credentials" \
  --remote-retention-mode COMPLIANCE --remote-retention-days 7)
docker run --detach --name "$MINIO_CONTAINER" --network "$TASK_NETWORK" \
  --env-file "$tmp/minio.env" --mount "type=volume,src=$MINIO_VOLUME,dst=/data" \
  "$MINIO_IMAGE" server /data --console-address :9001 >/dev/null
for _ in $(seq 1 60); do
  aws --no-cli-pager --endpoint-url "$REMOTE_ENDPOINT" --region us-east-1 \
    s3api list-buckets >/dev/null 2>&1 && break
  sleep 1
done
aws --no-cli-pager --endpoint-url "$REMOTE_ENDPOINT" --region us-east-1 \
  s3api list-buckets >/dev/null 2>&1 || {
  printf 'error: task MinIO did not become ready\n' >&2
  exit 1
}
aws --no-cli-pager --endpoint-url "$REMOTE_ENDPOINT" --region us-east-1 s3api create-bucket \
  --bucket "$REMOTE_BUCKET" --object-lock-enabled-for-bucket >/dev/null
aws --no-cli-pager --endpoint-url "$REMOTE_ENDPOINT" --region us-east-1 \
  s3api put-bucket-versioning --bucket "$REMOTE_BUCKET" \
  --versioning-configuration Status=Enabled >/dev/null
aws --no-cli-pager --endpoint-url "$REMOTE_ENDPOINT" --region us-east-1 \
  s3api put-object-lock-configuration --bucket "$REMOTE_BUCKET" \
  --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":7}}}' \
  >/dev/null
docker run --rm --network none \
  --mount "type=volume,src=$POSTGRES_SOCKET_VOLUME,dst=$POSTGRES_SOCKET" \
  --entrypoint sh "$PG_IMAGE" -ceu \
  'chown postgres:postgres "$1"; chmod 3775 "$1"' -- "$POSTGRES_SOCKET"
docker run --detach --name "$POSTGRES_CONTAINER" --network "$TASK_NETWORK" \
  --mount "type=volume,src=$POSTGRES_VOLUME,dst=/var/lib/postgresql/data" \
  --mount "type=volume,src=$POSTGRES_SOCKET_VOLUME,dst=$POSTGRES_SOCKET" \
  -e POSTGRES_USER="$pg_user" -e POSTGRES_PASSWORD="$pg_password" -e POSTGRES_DB=postgres \
  -e PGHOST="$POSTGRES_SOCKET" \
  --health-cmd 'pg_isready -h /var/run/postgresql -U "$POSTGRES_USER" -d postgres' \
  --health-interval 1s --health-timeout 2s --health-retries 60 \
  "$PG_IMAGE" -c listen_addresses='' -c unix_socket_directories="$POSTGRES_SOCKET" \
  -c max_connections=20 -c max_locks_per_transaction=512 >/dev/null
docker run --detach --name "$CLICKHOUSE_CONTAINER" --network "$TASK_NETWORK" \
  -e CLICKHOUSE_USER="$clickhouse_user" -e CLICKHOUSE_PASSWORD="$clickhouse_password" \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  --health-cmd 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT 1"' \
  --health-interval 1s --health-timeout 2s --health-retries 60 \
  "$CLICKHOUSE_IMAGE" >/dev/null

for _ in $(seq 1 90); do
  [[ $(docker inspect "$POSTGRES_CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null) == "healthy" &&
    $(docker inspect "$CLICKHOUSE_CONTAINER" --format '{{.State.Health.Status}}' 2>/dev/null) == "healthy" ]] && break
  sleep 1
done
[[ $(docker inspect "$POSTGRES_CONTAINER" --format '{{.State.Health.Status}}') == "healthy" ]] || {
  printf 'error: task PostgreSQL container did not become healthy\n' >&2
  exit 1
}
[[ $(docker inspect "$CLICKHOUSE_CONTAINER" --format '{{.State.Health.Status}}') == "healthy" ]] || {
  printf 'error: task ClickHouse container did not become healthy\n' >&2
  exit 1
}

pg_settings=$(docker exec "$POSTGRES_CONTAINER" psql -X -Atq -U "$pg_user" -d postgres -c \
  "SELECT current_setting('server_version') || '|' || current_setting('listen_addresses') || '|' || current_setting('max_connections') || '|' || current_setting('max_locks_per_transaction')")
[[ "$pg_settings" == 17.9\|\|20\|512 ]]
[[ $(docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --user "$clickhouse_user" \
  --password "$clickhouse_password" --query 'SELECT version()') == 25.3.6.56 ]]

cp -R "$MIGRATIONS" "$tmp/migrations"
readonly SMOKE_MIGRATIONS="$tmp/migrations"
latest_migration=$(find "$SMOKE_MIGRATIONS" -maxdepth 1 -type f -name '*.up.sql' | sort | tail -n 1)
latest_migration=${latest_migration##*/}
latest_migration=${latest_migration%%_*}
latest_migration=$((10#$latest_migration))
source_db="control_backup_source_$(openssl rand -hex 6)"
restore_db="control_backup_restore_$(openssl rand -hex 6)"
nonempty_db="control_backup_nonempty_$(openssl rand -hex 6)"
compensation_db="control_backup_compensation_$(openssl rand -hex 6)"
clickhouse_source="control_backup_ch_source_$(openssl rand -hex 6)"
clickhouse_restore="control_backup_ch_restore_$(openssl rand -hex 6)"
clickhouse_compensation="control_backup_ch_compensation_$(openssl rand -hex 6)"
printf '%s\n' "$pg_password" > "$tmp/pgpassword"
chmod 600 "$tmp/pgpassword"
age-keygen -o "$tmp/age-identity" >/dev/null 2>"$tmp/age-keygen.out"
age_recipient=$(age-keygen -y "$tmp/age-identity")
openssl genpkey -algorithm ED25519 -out "$tmp/signing-private.pem" >/dev/null 2>&1
openssl pkey -in "$tmp/signing-private.pem" -pubout -out "$tmp/signing-public.pem" >/dev/null 2>&1
openssl genpkey -algorithm ED25519 -out "$tmp/wrong-signing-private.pem" >/dev/null 2>&1
openssl pkey -in "$tmp/wrong-signing-private.pem" -pubout -out "$tmp/wrong-signing-public.pem" >/dev/null 2>&1
age-keygen -o "$tmp/wrong-age-identity" >/dev/null 2>"$tmp/wrong-age-keygen.out"
chmod 600 "$tmp/age-identity" "$tmp/wrong-age-identity" "$tmp/signing-private.pem" \
  "$tmp/wrong-signing-private.pem" "$tmp/pgpassword"
mkdir "$tmp/backups"

docker exec "$POSTGRES_CONTAINER" createdb -U "$pg_user" -T template0 "$source_db"
docker exec "$POSTGRES_CONTAINER" createdb -U "$pg_user" -T template0 "$restore_db"
docker exec "$POSTGRES_CONTAINER" createdb -U "$pg_user" -T template0 "$nonempty_db"
docker exec "$POSTGRES_CONTAINER" createdb -U "$pg_user" -T template0 "$compensation_db"
docker exec "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d postgres -c \
  'CREATE ROLE cdnca_control_app NOLOGIN'
docker exec "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d postgres -c \
  'CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN'
docker exec "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d "$source_db" -c \
  'ALTER SCHEMA public OWNER TO CURRENT_USER'
docker exec "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d "$source_db" -c \
  'REVOKE USAGE ON SCHEMA public FROM PUBLIC'
docker exec -e TASK_DATABASE="$clickhouse_source" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "CREATE DATABASE $TASK_DATABASE"'
docker exec -e TASK_DATABASE="$clickhouse_restore" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "CREATE DATABASE $TASK_DATABASE"'
docker exec -e TASK_DATABASE="$clickhouse_compensation" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "CREATE DATABASE $TASK_DATABASE"'

docker exec -i -e TASK_DATABASE="$clickhouse_source" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$TASK_DATABASE" --multiquery' <<'SQL'
CREATE TABLE access_events (
  event_time DateTime64(3, 'UTC'),
  tenant_id UUID,
  site_id UUID,
  status UInt16,
  bytes UInt64,
  path String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, site_id, event_time);

CREATE TABLE security_events (
  event_time DateTime64(3, 'UTC'),
  tenant_id UUID,
  action LowCardinality(String),
  client_ip IPv6,
  rule_id String,
  score UInt16
) ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, event_time, client_ip);

INSERT INTO access_events VALUES
  ('2026-07-01 00:00:00.001', '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000011', 200, 1200, '/index'),
  ('2026-07-15 12:30:00.002', '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000011', 403, 64, '/blocked'),
  ('2026-08-01 00:00:00.003', '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000012', 206, 512, '/video');

INSERT INTO security_events VALUES
  ('2026-07-02 01:00:00.001', '00000000-0000-4000-8000-000000000001', 'allowed', '2001:db8::1', 'acl-allow', 1),
  ('2026-07-16 02:00:00.002', '00000000-0000-4000-8000-000000000001', 'blocked', '2001:db8::2', 'waf-sqli', 90),
  ('2026-08-02 03:00:00.003', '00000000-0000-4000-8000-000000000001', 'challenged', '2001:db8::3', 'cc-rate', 60);
SQL

postgres_arch=$(docker image inspect "$PG_IMAGE" --format '{{.Architecture}}')
case "$postgres_arch" in
  amd64 | arm64) ;;
  *)
    printf 'error: unsupported PostgreSQL image architecture: %s\n' "$postgres_arch" >&2
    exit 1
    ;;
esac
migration_binary="$tmp/control-api-migrate"
(
  cd "$ROOT/services/control-api"
  GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$postgres_arch" \
    go build -trimpath -ldflags='-s -w' -o "$migration_binary" ./cmd/control-api
)
chmod 700 "$migration_binary"
docker cp "$migration_binary" "$POSTGRES_CONTAINER:/tmp/control-api-migrate"
docker exec \
  -e DATABASE_URL="postgresql://$pg_user@/$source_db?host=$POSTGRES_SOCKET&sslmode=disable" \
  "$POSTGRES_CONTAINER" /tmp/control-api-migrate migrate up

tee "$tmp/password-hash.go" >/dev/null <<'GO'
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

func main() {
	password := os.Getenv("SMOKE_LOGIN_PASSWORD")
	salt := make([]byte, 16)
	if len(password) < 12 {
		panic("smoke password is too short")
	}
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	fmt.Printf("$argon2id$v=%d$m=65536,t=3,p=2$%s$%s\n", argon2.Version,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))
}
GO
BOOTSTRAP_PASSWORD='Backup-smoke-password-2026!'
export SMOKE_LOGIN_PASSWORD="$BOOTSTRAP_PASSWORD"
login_password_hash=$(cd "$ROOT/services/control-api" && go run "$tmp/password-hash.go")
unset BOOTSTRAP_PASSWORD SMOKE_LOGIN_PASSWORD
[[ "$login_password_hash" =~ ^\$argon2id\$v=19\$m=65536,t=3,p=2\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$ ]]

docker exec -i "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d "$source_db" \
  -v password_hash="$login_password_hash" <<'SQL'
BEGIN;
INSERT INTO tenants (id, display_name, created_at, updated_at)
VALUES ('00000000-0000-4000-8000-000000000003', 'Backup smoke tenant', '2026-07-22T00:00:00Z', '2026-07-22T00:00:00Z');
INSERT INTO access_scopes (id, kind) VALUES ('00000000-0000-4000-8000-000000000001', 'platform');
INSERT INTO access_scopes (id, kind, tenant_id)
VALUES ('00000000-0000-4000-8000-000000000004', 'tenant', '00000000-0000-4000-8000-000000000003');
INSERT INTO users (id, username, display_name, password_hash)
VALUES ('00000000-0000-4000-8000-000000000002', 'backup-smoke', 'Backup smoke', :'password_hash');
INSERT INTO memberships (scope_id, user_id)
VALUES ('00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002');
INSERT INTO audit_events (
  id, scope_id, stream_position, actor_user_id, action, resource_type,
  resource_id, request_id, result, payload, previous_hash, event_hash, occurred_at
) VALUES
  ('00000000-0000-7000-8000-000000000001', '00000000-0000-4000-8000-000000000001', 1,
   '00000000-0000-4000-8000-000000000002', 'smoke.created', 'smoke', 'one', 'smoke-1',
   'success', '{}', NULL, decode(repeat('11', 32), 'hex'), '2026-07-22T00:00:00Z'),
  ('00000000-0000-7000-8000-000000000002', '00000000-0000-4000-8000-000000000001', 2,
   '00000000-0000-4000-8000-000000000002', 'smoke.verified', 'smoke', 'two', 'smoke-2',
   'success', '{}', decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'), '2026-07-22T00:00:01Z');
INSERT INTO billing_accounts (id, scope_id, kind, balance_minor, revision, created_at, updated_at) VALUES
  ('00000000-0000-4000-8000-000000000004', '00000000-0000-4000-8000-000000000004', 'tenant_liability', 2500, 2, '2026-07-22T00:00:02Z', '2026-07-22T00:00:02Z'),
  ('00000000-0000-4000-8000-000000000005', '00000000-0000-4000-8000-000000000001', 'platform_clearing', -2500, 2, '2026-07-22T00:00:02Z', '2026-07-22T00:00:02Z');
INSERT INTO billing_transactions (id, target_scope_id, operation, direction, amount_minor, reason, created_by_user_id, created_at)
VALUES ('00000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000004', 'manual_adjustment', 'credit', 2500, 'Backup restore drill', '00000000-0000-4000-8000-000000000002', '2026-07-22T00:00:02Z');
INSERT INTO billing_postings (id, transaction_id, account_id, side, amount_minor, balance_after_minor, created_at) VALUES
  ('00000000-0000-4000-8000-000000000007', '00000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000004', 'credit', 2500, 2500, '2026-07-22T00:00:02Z'),
  ('00000000-0000-4000-8000-000000000008', '00000000-0000-4000-8000-000000000006', '00000000-0000-4000-8000-000000000005', 'debit', 2500, -2500, '2026-07-22T00:00:02Z');
COMMIT;
SQL

export PGHOST="$POSTGRES_SOCKET" PGPORT=5432 PGUSER="$pg_user" PGSSLMODE=disable
export PGPASSWORD_FILE="$tmp/pgpassword" CONTROL_BACKUP_CLIENT_MODE=docker
export CLICKHOUSE_HOST="$CLICKHOUSE_CONTAINER" CLICKHOUSE_PORT=9000 CLICKHOUSE_USER="$clickhouse_user"
export CLICKHOUSE_PASSWORD="$clickhouse_password" CLICKHOUSE_SECURE=false
export CONTROL_BACKUP_CLICKHOUSE_CLIENT_MODE=docker CONTROL_BACKUP_DOCKER_NETWORK="$TASK_NETWORK"
export CONTROL_BACKUP_POSTGRES_SOCKET_VOLUME="$POSTGRES_SOCKET_VOLUME"

backup_started=$(date +%s)
snapshot_ready="$tmp/snapshot-ready"
CONTROL_BACKUP_ENABLE_TEST_HOOKS=1 CONTROL_BACKUP_TEST_STOP_AFTER_SNAPSHOT_FILE="$snapshot_ready" \
  PGDATABASE="$source_db" "$TOOL" backup --output-dir "$tmp/backups" \
  --app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --source-cluster-id "$SOURCE_CLUSTER_ID" --age-recipient "$age_recipient" \
  --signing-private-key-file "$tmp/signing-private.pem" --signing-key-id "$SIGNING_KEY_ID" \
  --clickhouse-database "$clickhouse_source" "${remote_args[@]}" \
  > "$tmp/backup.out" 2> "$tmp/backup.err" &
backup_pid=$!
for _ in $(seq 1 "$DOCKER_MARKER_WAIT_ATTEMPTS"); do
  [[ -f "$snapshot_ready" ]] && break
  if ! kill -0 "$backup_pid" >/dev/null 2>&1; then
    wait "$backup_pid" >/dev/null 2>&1 || true
    backup_pid=""
    cat "$tmp/backup.err" >&2
    printf 'error: backup exited before exported snapshot stop\n' >&2
    exit 1
  fi
  sleep 0.1
done
[[ -f "$snapshot_ready" ]] || {
  cat "$tmp/backup.err" >&2
  printf 'error: backup did not reach exported snapshot stop\n' >&2
  exit 1
}
docker exec "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d "$source_db" -c \
  "INSERT INTO tenants (id, display_name, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000009', 'Concurrent tenant', '2026-07-22T00:00:03Z', '2026-07-22T00:00:03Z')"
kill -CONT "$backup_pid"
if wait "$backup_pid"; then
  backup_pid=""
else
  backup_pid=""
  cat "$tmp/backup.err" >&2
  exit 1
fi
backup_finished=$(date +%s)
bundle=$(find "$tmp/backups" -mindepth 1 -maxdepth 1 -type d | head -n 1)
[[ -n "$bundle" ]]
backup_id=$(sed -n 's/^backup_id=//p' "$tmp/backup.out")
manifest_sha=$(sed -n 's/^manifest_sha256=//p' "$tmp/backup.out")
[[ "$backup_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ &&
  "$manifest_sha" =~ ^[0-9a-f]{64}$ ]]
grep -Eq '^control_backup_remote_last_success_timestamp_seconds=[0-9]+$' "$tmp/backup.out"
[[ $(shasum -a 256 "$bundle/manifest.json" | awk '{print $1}') == "$manifest_sha" ]]
jq -S -c '.' "$bundle/manifest.json" > "$tmp/canonical-manifest.json"
cmp -s "$bundle/manifest.json" "$tmp/canonical-manifest.json"
openssl pkeyutl -verify -rawin -pubin -inkey "$tmp/signing-public.pem" \
  -in "$bundle/manifest.json" -sigfile "$bundle/manifest.sig" >/dev/null
[[ -z $(find "$bundle" -type f \( -name 'database.dump' -o -name '*.native' -o -name '*.schema.sql' \) -print -quit) ]]
if ! jq -e --argjson latest_migration "$latest_migration" '
  .schema == "cdnca.control-backup/v3" and .format_version == 3 and
  .source.cluster_id == "ops12a-empty-restore-drill" and
  .tool == {name: "control-backup", version: "3.0.0"} and
  .consistency.required_components == ["postgresql", "clickhouse"] and
  .components.postgresql.migration.schema_version == $latest_migration and
  .components.postgresql.migration.applied_versions == [range(1; $latest_migration + 1)] and
  (.components.postgresql.migration.fingerprint_sha256 | test("^[0-9a-f]{64}$")) and
  (.components.postgresql.artifact.sha256 | test("^[0-9a-f]{64}$")) and
  .components.postgresql.artifact.size_bytes > 0 and
  .components.postgresql.logical_contents.tenants.row_count == 1 and
  .components.clickhouse.table_count == 2 and
  [.components.clickhouse.tables[].name] == ["access_events", "security_events"] and
  [.components.clickhouse.tables[].row_count] == [3, 3] and
  [.components.clickhouse.tables[].partition_count] == [2, 2] and
  (all(.components.clickhouse.tables[]; (.schema.sha256 | test("^[0-9a-f]{64}$")))) and
  (all(.components.clickhouse.tables[]; (.data.sha256 | test("^[0-9a-f]{64}$")))) and
  .encryption.state == "encrypted" and .encryption.method == "age" and
  (.encryption.recipients | length) == 1 and
  .signing.algorithm == "Ed25519" and .signing.key_id == "ops12a-offline-ed25519" and
  .components.postgresql.logical_contents.billing_ledger == {
    transaction_count: 1, transaction_amount_minor: 2500,
    posting_count: 2, debit_amount_minor: 2500, credit_amount_minor: 2500
  } and
  .components.postgresql.consistency.method == "pg-exported-snapshot" and
  .components.postgresql.consistency.single_transaction_snapshot == true and
  .components.postgresql.consistency.dump_snapshot_bound == true and
  (.components.postgresql.consistency.snapshot_identifier_sha256 | test("^[0-9a-f]{64}$"))
' "$bundle/manifest.json" >/dev/null; then
  jq '{schema, required_components: .consistency.required_components,
    pg_schema: .components.postgresql.migration.schema_version,
    clickhouse: (.components.clickhouse | {table_count, tables: [.tables[] | {name, row_count, partition_count}]})}' \
    "$bundle/manifest.json" >&2
  exit 1
fi

mkdir "$tmp/encryption-failure"
if PGDATABASE="$source_db" "$TOOL" backup --output-dir "$tmp/encryption-failure" \
  --app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --source-cluster-id "$SOURCE_CLUSTER_ID" \
  --age-recipient age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq \
  --signing-private-key-file "$tmp/signing-private.pem" --signing-key-id "$SIGNING_KEY_ID" \
  > "$tmp/encryption.out" 2>&1; then
  printf 'error: invalid/unavailable age encryption unexpectedly succeeded\n' >&2
  exit 1
fi
[[ -z $(find "$tmp/encryption-failure" -mindepth 1 -maxdepth 1 -print -quit) ]]

mkdir "$tmp/component-failure"
missing_clickhouse="control_backup_ch_missing_$(openssl rand -hex 6)"
if PGDATABASE="$source_db" "$TOOL" backup --output-dir "$tmp/component-failure" \
  --app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --source-cluster-id "$SOURCE_CLUSTER_ID" --age-recipient "$age_recipient" \
  --signing-private-key-file "$tmp/signing-private.pem" --signing-key-id "$SIGNING_KEY_ID" \
  --clickhouse-database "$missing_clickhouse" > "$tmp/component-failure.out" 2>&1; then
  printf 'error: missing required ClickHouse component unexpectedly succeeded\n' >&2
  exit 1
fi
[[ -z $(find "$tmp/component-failure" -mindepth 1 -maxdepth 1 -print -quit) ]]

mkdir "$tmp/parent-fsync-failure"
if CONTROL_BACKUP_ENABLE_TEST_HOOKS=1 CONTROL_BACKUP_TEST_FAIL_PARENT_FSYNC_ONCE=1 \
  PGDATABASE="$source_db" \
  "$TOOL" backup --output-dir "$tmp/parent-fsync-failure" \
  --app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --source-cluster-id "$SOURCE_CLUSTER_ID" --age-recipient "$age_recipient" \
  --signing-private-key-file "$tmp/signing-private.pem" --signing-key-id "$SIGNING_KEY_ID" \
  > "$tmp/parent-fsync.out" 2>&1; then
  printf 'error: injected parent fsync failure unexpectedly published a backup\n' >&2
  exit 1
fi
grep -Fq 'backup parent directory fsync failed; unpublished bundle was removed' "$tmp/parent-fsync.out"
[[ -z $(find "$tmp/parent-fsync-failure" -mindepth 1 -maxdepth 1 -print -quit) ]]

mkdir -p "$tmp/hard-interrupt-output" "$tmp/hard-interrupt-scratch"
hard_interrupt_ready="$tmp/hard-interrupt-ready"
TMPDIR="$tmp/hard-interrupt-scratch" \
  CONTROL_BACKUP_ENABLE_TEST_HOOKS=1 \
  CONTROL_BACKUP_TEST_STOP_AFTER_DUMP_FILE="$hard_interrupt_ready" \
  PGDATABASE="$source_db" "$TOOL" backup --output-dir "$tmp/hard-interrupt-output" \
  --app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --source-cluster-id "$SOURCE_CLUSTER_ID" --age-recipient "$age_recipient" \
  --signing-private-key-file "$tmp/signing-private.pem" --signing-key-id "$SIGNING_KEY_ID" \
  > "$tmp/hard-interrupt.out" 2>&1 &
hard_interrupt_pid=$!
for _ in $(seq 1 "$DOCKER_MARKER_WAIT_ATTEMPTS"); do
  [[ -f "$hard_interrupt_ready" ]] && break
  if ! kill -0 "$hard_interrupt_pid" >/dev/null 2>&1; then
    wait "$hard_interrupt_pid" >/dev/null 2>&1 || true
    hard_interrupt_pid=""
    cat "$tmp/hard-interrupt.out" >&2
    printf 'error: backup exited before hard-interruption stop\n' >&2
    exit 1
  fi
  sleep 0.1
done
[[ -f "$hard_interrupt_ready" ]] || {
  cat "$tmp/hard-interrupt.out" >&2
  printf 'error: backup did not reach hard-interruption stop\n' >&2
  exit 1
}
[[ -n $(find "$tmp/hard-interrupt-scratch" -type f -name 'database.dump' -size +0 -print -quit) ]]
[[ -z $(find "$tmp/hard-interrupt-output" -type f -print -quit) ]]
kill -KILL "$hard_interrupt_pid"
if wait "$hard_interrupt_pid" 2>/dev/null; then
  printf 'error: SIGKILL backup unexpectedly succeeded\n' >&2
  exit 1
fi
hard_interrupt_pid=""
[[ -z $(find "$tmp/hard-interrupt-output" -type f \( -name 'database.dump' -o -name '*.native' -o -name '*.schema.sql' \) -print -quit) ]]
[[ -z $(find "$tmp/hard-interrupt-output" -mindepth 1 -maxdepth 1 -type d -name 'control-backup-*' -print -quit) ]]
find "$tmp/hard-interrupt-output" -mindepth 1 -maxdepth 1 -type d -name '.control-backup.tmp.*' \
  -exec rm -rf -- {} +
rm -rf -- "$tmp/hard-interrupt-scratch"

verify_args=(--expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id "$SOURCE_CLUSTER_ID" --expected-backup-id "$backup_id" \
  --expected-manifest-sha256 "$manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id "$SIGNING_KEY_ID")
"$TOOL" verify --bundle "$bundle" "${verify_args[@]}" > "$tmp/verify.out"

cp -R "$bundle" "$tmp/tampered"
truncate -s -1 "$tmp/tampered/database.dump.age"
if "$TOOL" verify --bundle "$tmp/tampered" "${verify_args[@]}" > "$tmp/tamper.out" 2>&1; then
  printf 'error: tampered archive was accepted\n' >&2
  exit 1
fi
grep -Fq 'backup artifact hash mismatch' "$tmp/tamper.out"

cp -R "$bundle" "$tmp/tampered-clickhouse"
truncate -s -1 "$tmp/tampered-clickhouse/clickhouse/access_events.native.age"
if "$TOOL" verify --bundle "$tmp/tampered-clickhouse" "${verify_args[@]}" > "$tmp/tamper-clickhouse.out" 2>&1; then
  printf 'error: tampered ClickHouse Native artifact was accepted\n' >&2
  exit 1
fi
grep -Fq 'ClickHouse data artifact hash mismatch' "$tmp/tamper-clickhouse.out"

cp -R "$bundle" "$tmp/bad-signature"
dd if=/dev/zero of="$tmp/bad-signature/manifest.sig" bs=64 count=1 conv=notrunc 2>/dev/null
if "$TOOL" verify --bundle "$tmp/bad-signature" "${verify_args[@]}" > "$tmp/bad-signature.out" 2>&1; then
  printf 'error: bad manifest signature was accepted\n' >&2
  exit 1
fi
grep -Fq 'manifest signature verification failed' "$tmp/bad-signature.out"

wrong_signing_args=(--expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id "$SOURCE_CLUSTER_ID" --expected-backup-id "$backup_id" \
  --expected-manifest-sha256 "$manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/wrong-signing-public.pem" --expected-signing-key-id "$SIGNING_KEY_ID")
if "$TOOL" verify --bundle "$bundle" "${wrong_signing_args[@]}" > "$tmp/wrong-signing.out" 2>&1; then
  printf 'error: wrong manifest signing key was accepted\n' >&2
  exit 1
fi
grep -Fq 'manifest signature verification failed' "$tmp/wrong-signing.out"

wrong_age_args=(--expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id "$SOURCE_CLUSTER_ID" --expected-backup-id "$backup_id" \
  --expected-manifest-sha256 "$manifest_sha" --age-identity-file "$tmp/wrong-age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id "$SIGNING_KEY_ID")
if "$TOOL" verify --bundle "$bundle" "${wrong_age_args[@]}" > "$tmp/wrong-age.out" 2>&1; then
  printf 'error: wrong age identity was accepted\n' >&2
  exit 1
fi
grep -Fq 'no identity matched' "$tmp/wrong-age.out"

replay_args=(--expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id "$SOURCE_CLUSTER_ID" \
  --expected-backup-id 00000000-0000-4000-8000-000000000099 \
  --expected-manifest-sha256 "$manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id "$SIGNING_KEY_ID")
if "$TOOL" verify --bundle "$bundle" "${replay_args[@]}" > "$tmp/replay.out" 2>&1; then
  printf 'error: replayed backup ID was accepted\n' >&2
  exit 1
fi
grep -Fq 'backup ID does not match expected backup ID' "$tmp/replay.out"

cluster_args=(--expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id another-cluster --expected-backup-id "$backup_id" \
  --expected-manifest-sha256 "$manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id "$SIGNING_KEY_ID")
if "$TOOL" verify --bundle "$bundle" "${cluster_args[@]}" > "$tmp/cluster.out" 2>&1; then
  printf 'error: wrong source cluster binding was accepted\n' >&2
  exit 1
fi
grep -Fq 'backup source cluster does not match expected cluster' "$tmp/cluster.out"

digest_args=(--expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id "$SOURCE_CLUSTER_ID" --expected-backup-id "$backup_id" \
  --expected-manifest-sha256 2222222222222222222222222222222222222222222222222222222222222222 \
  --age-identity-file "$tmp/age-identity" --signing-public-key-file "$tmp/signing-public.pem" \
  --expected-signing-key-id "$SIGNING_KEY_ID")
if "$TOOL" verify --bundle "$bundle" "${digest_args[@]}" > "$tmp/digest.out" 2>&1; then
  printf 'error: wrong immutable manifest digest was accepted\n' >&2
  exit 1
fi
grep -Fq 'manifest digest does not match expected digest' "$tmp/digest.out"

rm -rf -- "$tmp/backups"
mkdir "$tmp/backups"
"$TOOL" remote-fetch --output-dir "$tmp/backups" "${remote_args[@]}" \
  --expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id "$SOURCE_CLUSTER_ID" --expected-backup-id "$backup_id" \
  --expected-manifest-sha256 "$manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id "$SIGNING_KEY_ID" \
  > "$tmp/remote-fetch.out"
bundle=$(sed -n 's/^bundle_path=//p' "$tmp/remote-fetch.out")
[[ -d "$bundle" && "$bundle" == "$tmp/backups/"* ]]
[[ $(shasum -a 256 "$bundle/manifest.json" | awk '{print $1}') == "$manifest_sha" ]]

restore_args=(--expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id "$SOURCE_CLUSTER_ID" --expected-backup-id "$backup_id" \
  --expected-manifest-sha256 "$manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id "$SIGNING_KEY_ID" \
  --postgresql-target-free-bytes 1099511627776)

if PGDATABASE="$restore_db" "$TOOL" restore --bundle "$bundle" \
  --target-database "$restore_db" --confirm-empty-target "$restore_db" \
  --clickhouse-target-database "$clickhouse_restore" \
  --confirm-empty-clickhouse-target "$clickhouse_restore" \
  --expected-app-version "$APP_VERSION" --migrations-dir "$SMOKE_MIGRATIONS" \
  --expected-source-cluster-id "$SOURCE_CLUSTER_ID" --expected-backup-id "$backup_id" \
  --expected-manifest-sha256 "$manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id "$SIGNING_KEY_ID" \
  --postgresql-target-free-bytes 1 > "$tmp/capacity.out" 2>&1; then
  printf 'error: restore accepted insufficient PostgreSQL capacity\n' >&2
  exit 1
fi
grep -Fq 'insufficient PostgreSQL target capacity' "$tmp/capacity.out"
[[ $(docker exec "$POSTGRES_CONTAINER" psql -X -Atq -U "$pg_user" -d "$restore_db" -c \
  "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'") == "0" ]]
[[ $(docker exec -e TASK_DATABASE="$clickhouse_restore" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT count() FROM system.tables WHERE database = '\''$TASK_DATABASE'\''"') == "0" ]]

docker exec "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d "$nonempty_db" -c \
  'CREATE TABLE must_not_be_overwritten (id bigint PRIMARY KEY)'
if PGDATABASE="$nonempty_db" "$TOOL" restore --bundle "$bundle" \
  --target-database "$nonempty_db" --confirm-empty-target "$nonempty_db" \
  --clickhouse-target-database "$clickhouse_restore" \
  --confirm-empty-clickhouse-target "$clickhouse_restore" \
  "${restore_args[@]}" > "$tmp/nonempty.out" 2>&1; then
  printf 'error: restore accepted a non-empty target\n' >&2
  exit 1
fi
grep -Fq 'target database is not empty' "$tmp/nonempty.out"
[[ $(docker exec "$POSTGRES_CONTAINER" psql -X -Atq -U "$pg_user" -d "$nonempty_db" -c "SELECT to_regclass('public.must_not_be_overwritten') IS NOT NULL") == "t" ]]

docker exec -e TASK_DATABASE="$clickhouse_restore" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$TASK_DATABASE" --query "CREATE TABLE must_not_be_overwritten (id UInt64) ENGINE = TinyLog"'
if PGDATABASE="$restore_db" "$TOOL" restore --bundle "$bundle" \
  --target-database "$restore_db" --confirm-empty-target "$restore_db" \
  --clickhouse-target-database "$clickhouse_restore" \
  --confirm-empty-clickhouse-target "$clickhouse_restore" \
  "${restore_args[@]}" > "$tmp/nonempty-clickhouse.out" 2>&1; then
  printf 'error: restore accepted a non-empty ClickHouse target\n' >&2
  exit 1
fi
grep -Fq 'ClickHouse target database is not empty' "$tmp/nonempty-clickhouse.out"
[[ $(docker exec "$POSTGRES_CONTAINER" psql -X -Atq -U "$pg_user" -d "$restore_db" -c \
  "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'") == "0" ]]
docker exec -e TASK_DATABASE="$clickhouse_restore" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$TASK_DATABASE" --query "DROP TABLE must_not_be_overwritten SYNC"'

docker exec "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d postgres -c \
  "ALTER DATABASE $compensation_db SET default_transaction_read_only=on"
if PGDATABASE="$compensation_db" "$TOOL" restore --bundle "$bundle" \
  --target-database "$compensation_db" --confirm-empty-target "$compensation_db" \
  --clickhouse-target-database "$clickhouse_compensation" \
  --confirm-empty-clickhouse-target "$clickhouse_compensation" \
  "${restore_args[@]}" > "$tmp/compensation.out" 2>&1; then
  printf 'error: read-only PostgreSQL target unexpectedly restored\n' >&2
  exit 1
fi
grep -Fq 'PostgreSQL restore failed and its single transaction was rolled back' "$tmp/compensation.out"
docker exec "$POSTGRES_CONTAINER" psql -X -v ON_ERROR_STOP=1 -q -U "$pg_user" -d postgres -c \
  "ALTER DATABASE $compensation_db RESET default_transaction_read_only"
[[ $(docker exec "$POSTGRES_CONTAINER" psql -X -Atq -U "$pg_user" -d "$compensation_db" -c \
  "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'") == "0" ]]
[[ $(docker exec -e TASK_DATABASE="$clickhouse_compensation" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT count() FROM system.tables WHERE database = '\''$TASK_DATABASE'\''"') == "0" ]]

restore_started=$(date +%s)
PGDATABASE="$restore_db" "$TOOL" restore --bundle "$bundle" \
  --target-database "$restore_db" --confirm-empty-target "$restore_db" \
  --clickhouse-target-database "$clickhouse_restore" \
  --confirm-empty-clickhouse-target "$clickhouse_restore" \
  "${restore_args[@]}" > "$tmp/restore.out"
restore_finished=$(date +%s)

source_counts=$(docker exec "$POSTGRES_CONTAINER" psql -X -Atq -U "$pg_user" -d "$source_db" -c \
  "SELECT (SELECT count(*) FROM schema_migrations) || ',' || (SELECT count(*) FROM access_scopes) || ',' || (SELECT count(*) FROM tenants) || ',' || (SELECT count(*) FROM users) || ',' || (SELECT count(*) FROM audit_events) || ',' || (SELECT count(*) FROM billing_transactions) || ',' || (SELECT count(*) FROM billing_postings)")
restore_counts=$(docker exec "$POSTGRES_CONTAINER" psql -X -Atq -U "$pg_user" -d "$restore_db" -c \
  "SELECT (SELECT count(*) FROM schema_migrations) || ',' || (SELECT count(*) FROM access_scopes) || ',' || (SELECT count(*) FROM tenants) || ',' || (SELECT count(*) FROM users) || ',' || (SELECT count(*) FROM audit_events) || ',' || (SELECT count(*) FROM billing_transactions) || ',' || (SELECT count(*) FROM billing_postings)")
[[ "$source_counts" == "$latest_migration,2,2,1,2,1,2" ]]
[[ "$restore_counts" == "$latest_migration,2,1,1,2,1,2" ]]

clickhouse_source_aggregate=$(docker exec -e TASK_DATABASE="$clickhouse_source" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$TASK_DATABASE" --query "SELECT '\''access'\'', count(), sum(bytes), countIf(status >= 400) FROM access_events UNION ALL SELECT '\''security'\'', count(), countIf(action = '\''blocked'\''), uniqExact(client_ip) FROM security_events ORDER BY 1 FORMAT TSVRaw"')
clickhouse_restore_aggregate=$(docker exec -e TASK_DATABASE="$clickhouse_restore" "$CLICKHOUSE_CONTAINER" sh -ceu \
  'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --database "$TASK_DATABASE" --query "SELECT '\''access'\'', count(), sum(bytes), countIf(status >= 400) FROM access_events UNION ALL SELECT '\''security'\'', count(), countIf(action = '\''blocked'\''), uniqExact(client_ip) FROM security_events ORDER BY 1 FORMAT TSVRaw"')
[[ "$clickhouse_source_aggregate" == "$clickhouse_restore_aggregate" ]]
[[ "$clickhouse_restore_aggregate" == $'access\t3\t1776\t1\nsecurity\t3\t1\t3' ]]

if PGDATABASE="$restore_db" "$TOOL" restore --bundle "$bundle" \
  --target-database "$restore_db" --confirm-empty-target "$restore_db" \
  --clickhouse-target-database "$clickhouse_restore" \
  --confirm-empty-clickhouse-target "$clickhouse_restore" \
  "${restore_args[@]}" > "$tmp/repeat.out" 2>&1; then
  printf 'error: repeated restore was accepted\n' >&2
  exit 1
fi
grep -Fq 'target database is not empty' "$tmp/repeat.out"

manifest_epoch=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$(jq -r '.created_at' "$bundle/manifest.json")" '+%s' 2>/dev/null ||
  date -u -d "$(jq -r '.created_at' "$bundle/manifest.json")" '+%s')
printf 'control-backup smoke: PASS\n'
printf 'backup_duration_seconds=%d\n' "$((backup_finished - backup_started))"
printf 'restore_duration_seconds=%d\n' "$((restore_finished - restore_started))"
printf 'recovery_point_age_seconds=%d\n' "$((restore_finished - manifest_epoch))"
printf 'postgresql_runtime=17.9,listen_addresses-empty,max_connections-20,max_locks_per_transaction-512\n'
printf 'clickhouse_runtime=25.3.6.56\n'
printf 'reconciled_counts=migrations,scopes,tenants,users,audit-events,billing-transactions,billing-postings:%s\n' "$restore_counts"
printf 'clickhouse_reconciled=access:3/1776/1,security:3/1/3\n'
printf 'covered=exported-snapshot-concurrent-write,ephemeral-plaintext-hard-interruption,parent-fsync-unpublish,canonical-signature,wrong-signing-key,wrong-age-key,truncation,replay-binding,cluster-binding,digest-binding,immutable-s3-object-lock,remote-commit-readback,local-pvc-loss-fetch,capacity,nonempty,component-failure-cleanup,single-transaction-rollback,cross-database-compensation,restore-reconciliation,repeat-rejection\n'
