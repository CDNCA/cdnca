#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
readonly ROOT
readonly TOOL="$ROOT/tools/control-backup/control-backup"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local expected=$1
  shift
  local output
  if output=$("$@" 2>&1); then
    fail "command unexpectedly succeeded: $*"
  fi
  [[ "$output" == *"$expected"* ]] || fail "missing error '$expected'; got: $output"
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-control-backup-test.XXXXXX")
tmp=$(cd "$tmp" && pwd -P)
trap 'rm -rf -- "$tmp"' EXIT
chmod 700 "$tmp"
mkdir "$tmp/output" "$tmp/migrations" "$tmp/bundle"
printf '%s\n' 'SELECT 1;' > "$tmp/migrations/001_test.up.sql"
openssl genpkey -algorithm ED25519 -out "$tmp/signing-private.pem" >/dev/null 2>&1
openssl pkey -in "$tmp/signing-private.pem" -pubout -out "$tmp/signing-public.pem" >/dev/null 2>&1
printf '%s\n' 'AGE-SECRET-KEY-TEST-ONLY' > "$tmp/age-identity"
chmod 600 "$tmp/signing-private.pem" "$tmp/age-identity"

readonly RECIPIENT='age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
readonly BACKUP_ID='00000000-0000-4000-8000-000000000001'
readonly MANIFEST_SHA='1111111111111111111111111111111111111111111111111111111111111111'
backup_args=(--app-version test-1 --migrations-dir "$tmp/migrations" --source-cluster-id test-cluster \
  --age-recipient "$RECIPIENT" --signing-private-key-file "$tmp/signing-private.pem" \
  --signing-key-id backup-signing-test)
verify_args=(--expected-app-version test-1 --migrations-dir "$tmp/migrations" \
  --expected-source-cluster-id test-cluster --expected-backup-id "$BACKUP_ID" \
  --expected-manifest-sha256 "$MANIFEST_SHA" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id backup-signing-test)

expect_failure "output directory must be an absolute path" \
  "$TOOL" backup --output-dir relative "${backup_args[@]}"

expect_failure "invalid app version" \
  "$TOOL" backup --output-dir "$tmp/output" --app-version 'bad version' \
  --migrations-dir "$tmp/migrations" --source-cluster-id test-cluster --age-recipient "$RECIPIENT" \
  --signing-private-key-file "$tmp/signing-private.pem" --signing-key-id backup-signing-test

expect_failure "reserved ClickHouse database is not allowed" \
  "$TOOL" backup --output-dir "$tmp/output" "${backup_args[@]}" --clickhouse-database system

expect_failure "invalid source cluster ID" \
  "$TOOL" backup --output-dir "$tmp/output" --app-version test-1 \
  --migrations-dir "$tmp/migrations" --source-cluster-id 'bad cluster' --age-recipient "$RECIPIENT" \
  --signing-private-key-file "$tmp/signing-private.pem" --signing-key-id backup-signing-test

attack_target="$tmp/injection-ran"
attack='$'
attack+="(touch $attack_target)"
expect_failure "only a standard age X25519 recipient" \
  "$TOOL" backup --output-dir "$tmp/output" --app-version test-1 \
  --migrations-dir "$tmp/migrations" --source-cluster-id test-cluster --age-recipient "$attack" \
  --signing-private-key-file "$tmp/signing-private.pem" --signing-key-id backup-signing-test
[[ ! -e "$attack_target" ]] || fail "age recipient was evaluated as shell code"

ln -s "$tmp/bundle" "$tmp/bundle-link"
expect_failure "symlink path component is not allowed" \
  "$TOOL" verify --bundle "$tmp/bundle-link" "${verify_args[@]}"

expect_failure "invalid backup ID" \
  "$TOOL" verify --bundle "$tmp/bundle" --expected-app-version test-1 \
  --migrations-dir "$tmp/migrations" --expected-source-cluster-id test-cluster \
  --expected-backup-id replay --expected-manifest-sha256 "$MANIFEST_SHA" \
  --age-identity-file "$tmp/age-identity" --signing-public-key-file "$tmp/signing-public.pem" \
  --expected-signing-key-id backup-signing-test

expect_failure "PostgreSQL target free bytes is invalid" \
  "$TOOL" restore --bundle "$tmp/bundle" --target-database restore_test \
  --confirm-empty-target restore_test --postgresql-target-free-bytes invalid "${verify_args[@]}"

printf '%s\n' 'localhost:5432:*:user:secret' > "$tmp/pgpass"
chmod 0644 "$tmp/pgpass"
expect_failure "must not be accessible by group/world" env \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=test PGPASSFILE="$tmp/pgpass" \
  "$TOOL" backup --output-dir "$tmp/output" "${backup_args[@]}"

printf '%s\n' 'secret' > "$tmp/pgpassword"
chmod 0600 "$tmp/pgpassword"
expect_failure "required command not found: age" env PATH=/usr/local/bin:/usr/bin:/bin \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=test PGPASSWORD_FILE="$tmp/pgpassword" \
  "$TOOL" backup --output-dir "$tmp/output" "${backup_args[@]}"

mkdir "$tmp/fake-native-bin" "$tmp/native-output"
native_log="$tmp/native.log"
export FAKE_NATIVE_LOG="$native_log"
tee "$tmp/fake-native-bin/psql" >/dev/null <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
query=""
while (($#)); do
  if [[ "$1" == "-c" && $# -ge 2 ]]; then
    query=$2
    break
  fi
  shift
done
if [[ -n "$query" ]]; then
  case "$query" in
    *"current_setting('server_version_num')"*) printf '170009\n' ;;
    *"string_agg(version::text"*) printf '1\n' ;;
    *"audit_events_append_only"*) printf '1\n' ;;
    *"max(occurred_at)"*) printf '2026-07-22T00:00:01.000000Z\n' ;;
    *"max(stream_position)"*) printf '2\n' ;;
    *"sum(amount_minor) FILTER (WHERE side='debit')"*) printf '2500\n' ;;
    *"sum(amount_minor) FILTER (WHERE side='credit')"*) printf '2500\n' ;;
    *"sum(amount_minor)"*) printf '2500\n' ;;
    *"count(*) FROM pg_class"*"relkind"*) printf '7\n' ;;
    *"count(*) FROM schema_migrations"*) printf '1\n' ;;
    *"count(*) FROM tenants"*) printf '1\n' ;;
    *"count(*) FROM users"*) printf '1\n' ;;
    *"count(*) FROM audit_events"*) printf '2\n' ;;
    *"count(*) FROM billing_transactions"*) printf '1\n' ;;
    *"count(*) FROM billing_postings"*) printf '2\n' ;;
    *) printf '0\n' ;;
  esac
  exit 0
fi
printf 'psql_app=%s\n' "${PGAPPNAME:-}" >> "$FAKE_NATIVE_LOG"
printf '00000003-0000001B-1\n'
printf '{"database":"%s","server_version_num":"170009","server_version":"17.9","database_size":4096,"missing_required":0,"migration_versions":"1","public_table_count":7,"migration_row_count":1,"tenant_count":1,"user_count":1,"audit_count":2,"audit_max_position":2,"audit_max_occurred_at":"2026-07-22T00:00:01.000000Z","transaction_count":1,"transaction_amount":2500,"posting_count":2,"posting_debit":2500,"posting_credit":2500}\n' "$PGDATABASE"
cat >/dev/null
SH
tee "$tmp/fake-native-bin/pg_dump" >/dev/null <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
output=""
snapshot=""
for argument in "$@"; do
  case "$argument" in
    --file=*) output=${argument#--file=} ;;
    --snapshot=*) snapshot=${argument#--snapshot=} ;;
  esac
done
[[ -n "$output" && -n "$snapshot" ]]
printf 'pg_dump_snapshot=%s\n' "$snapshot" >> "$FAKE_NATIVE_LOG"
printf 'fake custom archive bound to %s\n' "$snapshot" > "$output"
SH
tee "$tmp/fake-native-bin/pg_restore" >/dev/null <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == "--version" ]]; then
  printf 'pg_restore (PostgreSQL) 17.9\n'
elif [[ "${1:-}" == "--list" ]]; then
  printf '1; 0 0 TABLE public tenants owner\n'
else
  printf 'pg_restore_database=success\n' >> "$FAKE_NATIVE_LOG"
fi
SH
tee "$tmp/fake-native-bin/age" >/dev/null <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
output=""
input=""
while (($#)); do
  case "$1" in
    --encrypt | --decrypt) shift ;;
    --recipient | --identity) shift 2 ;;
    --output) output=$2; shift 2 ;;
    *) input=$1; shift ;;
  esac
done
if [[ -n "$output" ]]; then
  cp "$input" "$output"
else
  printf 'age fixture\n'
fi
SH
tee "$tmp/fake-native-bin/aws" >/dev/null <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail

printf '%s\n' "$*" >> "$FAKE_AWS_LOG"
[[ -n "${AWS_SHARED_CREDENTIALS_FILE:-}" && -r "$AWS_SHARED_CREDENTIALS_FILE" ]]
[[ -z "${AWS_ACCESS_KEY_ID:-}${AWS_SECRET_ACCESS_KEY:-}${AWS_SESSION_TOKEN:-}" ]]
while (($#)); do
  case "$1" in
    --no-cli-pager) shift ;;
    --endpoint-url | --region) shift 2 ;;
    s3api) shift; break ;;
    *) exit 64 ;;
  esac
done
action=${1:-}
shift || true

object_metadata_path() {
  local bucket=$1 key=$2 token
  token=$(printf '%s' "$bucket/$key" | shasum -a 256 | awk '{print $1}')
  printf '%s/object-%s.json\n' "$FAKE_AWS_METADATA_ROOT" "$token"
}

write_object_metadata() {
  local bucket=$1 key=$2 mode=$3 retain_until=$4 metadata version_id last_modified
  metadata=$(object_metadata_path "$bucket" "$key")
  version_id="fixture-$(basename "$metadata" .json)"
  last_modified=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  jq -n --arg version_id "$version_id" --arg mode "$mode" \
    --arg retain_until "$retain_until" --arg last_modified "$last_modified" \
    '{VersionId: $version_id, ObjectLockMode: $mode,
      ObjectLockRetainUntilDate: $retain_until, LastModified: $last_modified}' > "$metadata"
}

case "$action" in
  get-bucket-versioning)
    [[ "${FAKE_AWS_PREFLIGHT:-}" != "versioning" ]] || { printf '{"Status":"Suspended"}\n'; exit 0; }
    printf '{"Status":"Enabled"}\n'
    ;;
  get-object-lock-configuration)
    [[ "${FAKE_AWS_PREFLIGHT:-}" != "lock" ]] || { printf '{"ObjectLockConfiguration":{"ObjectLockEnabled":"Disabled"}}\n'; exit 0; }
    [[ "${FAKE_AWS_PREFLIGHT:-}" != "retention" ]] || {
      printf '{"ObjectLockConfiguration":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":1}}}}\n'
      exit 0
    }
    printf '{"ObjectLockConfiguration":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":30}}}}\n'
    ;;
  put-object)
    bucket="" key="" body="" mode="" retain_until=""
    while (($#)); do
      case "$1" in
        --bucket) bucket=$2; shift 2 ;;
        --key) key=$2; shift 2 ;;
        --body) body=$2; shift 2 ;;
        --if-none-match) [[ "$2" == '*' ]]; shift 2 ;;
        --object-lock-mode) mode=$2; shift 2 ;;
        --object-lock-retain-until-date) retain_until=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    [[ "$mode" == "COMPLIANCE" && -n "$retain_until" ]] || exit 65
    target="$FAKE_S3_ROOT/$bucket/$key"
    mkdir -p "$(dirname "$target")"
    if [[ -n "${FAKE_AWS_CONFLICT_SUFFIX:-}" && "$key" == *"$FAKE_AWS_CONFLICT_SUFFIX" ]]; then
      printf 'wrong immutable bytes\n' > "$target"
      write_object_metadata "$bucket" "$key" "$mode" "$retain_until"
      exit 75
    fi
    if [[ -n "${FAKE_AWS_FAIL_ONCE_SUFFIX:-}" && "$key" == *"$FAKE_AWS_FAIL_ONCE_SUFFIX" &&
      ! -e "$FAKE_AWS_STATE/fail-once" ]]; then
      : > "$FAKE_AWS_STATE/fail-once"
      exit 75
    fi
    [[ ! -e "$target" ]] || exit 75
    cp "$body" "$target"
    write_object_metadata "$bucket" "$key" "$mode" "$retain_until"
    if [[ -n "${FAKE_AWS_UNKNOWN_SUFFIX:-}" && "$key" == *"$FAKE_AWS_UNKNOWN_SUFFIX" &&
      ! -e "$FAKE_AWS_STATE/unknown-once" ]]; then
      : > "$FAKE_AWS_STATE/unknown-once"
      exit 75
    fi
    if [[ -n "${FAKE_AWS_PUT_MISSING_VERSION_SUFFIX:-}" &&
      "$key" == *"$FAKE_AWS_PUT_MISSING_VERSION_SUFFIX" ]]; then
      printf '{}\n'
    else
      jq '{VersionId}' "$(object_metadata_path "$bucket" "$key")"
    fi
    ;;
  head-object)
    bucket="" key="" requested_version=""
    while (($#)); do
      case "$1" in
        --bucket) bucket=$2; shift 2 ;;
        --key) key=$2; shift 2 ;;
        --version-id) requested_version=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    target="$FAKE_S3_ROOT/$bucket/$key"
    [[ -f "$target" ]] || exit 44
    metadata=$(object_metadata_path "$bucket" "$key")
    [[ -f "$metadata" ]] || exit 44
    stored_version=$(jq -r '.VersionId' "$metadata")
    [[ -z "$requested_version" || "$requested_version" == "$stored_version" ]] || exit 45
    if stat -f '%z' "$target" >/dev/null 2>&1; then size=$(stat -f '%z' "$target"); else size=$(stat -c '%s' "$target"); fi
    retain_until=$(jq -r '.ObjectLockRetainUntilDate' "$metadata")
    if [[ -n "${FAKE_AWS_SHORT_RETENTION_SUFFIX:-}" && "$key" == *"$FAKE_AWS_SHORT_RETENTION_SUFFIX" ]]; then
      retain_until='2000-01-01T00:00:00Z'
    fi
    if [[ -n "${FAKE_AWS_VERSION_RACE_SUFFIX:-}" && "$key" == *"$FAKE_AWS_VERSION_RACE_SUFFIX" ]]; then
      : > "$FAKE_AWS_STATE/version-race"
    fi
    jq -n --argjson size "$size" --arg retain_until "$retain_until" --slurpfile metadata "$metadata" \
      '$metadata[0] + {ContentLength: $size, ObjectLockRetainUntilDate: $retain_until}'
    ;;
  get-object)
    bucket="" key="" output="" requested_version=""
    while (($#)); do
      case "$1" in
        --bucket) bucket=$2; shift 2 ;;
        --key) key=$2; shift 2 ;;
        --version-id) requested_version=$2; shift 2 ;;
        --*) shift ;;
        *) output=$1; shift ;;
      esac
    done
    [[ -n "$output" ]]
    if [[ -n "${FAKE_AWS_GET_FAIL_SUFFIX:-}" && "$key" == *"$FAKE_AWS_GET_FAIL_SUFFIX" ]]; then
      exit 74
    fi
    metadata=$(object_metadata_path "$bucket" "$key")
    stored_version=$(jq -r '.VersionId' "$metadata")
    [[ -z "$requested_version" || "$requested_version" == "$stored_version" ]] || exit 45
    if [[ -z "$requested_version" && -e "$FAKE_AWS_STATE/version-race" &&
      -n "${FAKE_AWS_VERSION_RACE_SUFFIX:-}" && "$key" == *"$FAKE_AWS_VERSION_RACE_SUFFIX" ]]; then
      printf 'new latest version raced after HEAD\n' > "$output"
    else
      cp "$FAKE_S3_ROOT/$bucket/$key" "$output"
    fi
    jq '{VersionId, ObjectLockMode, ObjectLockRetainUntilDate}' "$metadata"
    ;;
  *) exit 64 ;;
esac
SH
chmod 700 "$tmp/fake-native-bin/psql" "$tmp/fake-native-bin/pg_dump" \
  "$tmp/fake-native-bin/pg_restore" "$tmp/fake-native-bin/age" "$tmp/fake-native-bin/aws"

mkdir "$tmp/fake-s3" "$tmp/fake-aws-state" "$tmp/fake-aws-metadata" "$tmp/remote-output"
export FAKE_S3_ROOT="$tmp/fake-s3" FAKE_AWS_STATE="$tmp/fake-aws-state"
export FAKE_AWS_METADATA_ROOT="$tmp/fake-aws-metadata"
export FAKE_AWS_LOG="$tmp/fake-aws.log"
remote_secret='remote-test-secret-must-not-leak'
printf '[default]\naws_access_key_id = fixture-access\naws_secret_access_key = %s\n' "$remote_secret" \
  > "$tmp/remote-credentials"
chmod 0400 "$tmp/remote-credentials"
remote_args=(--remote-endpoint https://backup.example.test:9000 --remote-region test-1 \
  --remote-bucket test-bucket --remote-prefix control --remote-credentials-file "$tmp/remote-credentials" \
  --remote-retention-mode COMPLIANCE --remote-retention-days 7)
http_remote_args=(--remote-endpoint http://127.0.0.1:9000 --remote-region test-1 \
  --remote-bucket test-bucket --remote-prefix control --remote-credentials-file "$tmp/remote-credentials" \
  --remote-retention-mode COMPLIANCE --remote-retention-days 7)

chmod 0600 "$tmp/remote-credentials"
expect_failure "remote credentials file must have mode 0400" \
  "$TOOL" backup --output-dir "$tmp/native-output" "${backup_args[@]}" "${remote_args[@]}"
chmod 0400 "$tmp/remote-credentials"
ln -s "$tmp/remote-credentials" "$tmp/remote-credentials-link"
symlink_remote_args=(--remote-endpoint https://backup.example.test:9000 --remote-region test-1 \
  --remote-bucket test-bucket --remote-prefix control --remote-credentials-file "$tmp/remote-credentials-link" \
  --remote-retention-mode COMPLIANCE --remote-retention-days 7)
expect_failure "symlink path component is not allowed" \
  "$TOOL" backup --output-dir "$tmp/native-output" "${backup_args[@]}" "${symlink_remote_args[@]}"
expect_failure "remote options must be supplied together" \
  "$TOOL" backup --output-dir "$tmp/native-output" "${backup_args[@]}" --remote-bucket test-bucket
expect_failure "remote endpoint must use HTTPS outside test hooks" \
  "$TOOL" backup --output-dir "$tmp/native-output" "${backup_args[@]}" "${http_remote_args[@]}"

mkdir "$tmp/preflight-output"
expect_failure "remote bucket versioning must be Enabled" env PATH="$tmp/fake-native-bin:$PATH" \
  CONTROL_BACKUP_CLIENT_MODE=native FAKE_AWS_PREFLIGHT=versioning \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=native_fixture PGPASSWORD=fake \
  "$TOOL" backup --output-dir "$tmp/preflight-output" "${backup_args[@]}" "${remote_args[@]}"
expect_failure "remote Object Lock with default COMPLIANCE retention must be Enabled" env \
  PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native FAKE_AWS_PREFLIGHT=lock \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=native_fixture PGPASSWORD=fake \
  "$TOOL" backup --output-dir "$tmp/preflight-output" "${backup_args[@]}" "${remote_args[@]}"
expect_failure "remote default COMPLIANCE retention is shorter than the configured minimum" env \
  PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native FAKE_AWS_PREFLIGHT=retention \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=native_fixture PGPASSWORD=fake \
  "$TOOL" backup --output-dir "$tmp/preflight-output" "${backup_args[@]}" "${remote_args[@]}"

rm -f "$FAKE_AWS_STATE"/*
PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native \
  CONTROL_BACKUP_ENABLE_TEST_HOOKS=1 \
  FAKE_AWS_FAIL_ONCE_SUFFIX=database.dump.age FAKE_AWS_UNKNOWN_SUFFIX=manifest.sig \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=native_fixture PGPASSWORD=fake \
  "$TOOL" backup --output-dir "$tmp/native-output" "${backup_args[@]}" "${http_remote_args[@]}" \
  > "$tmp/native-backup.out" 2> "$tmp/native-backup.err"
native_bundle=$(find "$tmp/native-output" -mindepth 1 -maxdepth 1 -type d -name 'control-backup-*' | head -n 1)
[[ -n "$native_bundle" ]] || fail "native snapshot fixture did not publish a bundle"
grep -Fqx 'psql_app=cdnca-control-backup-snapshot' "$native_log" ||
  fail "native snapshot session did not use its dedicated application name"
grep -Fqx 'pg_dump_snapshot=00000003-0000001B-1' "$native_log" ||
  fail "native pg_dump was not bound to the exported snapshot"
snapshot_hash=$(printf '%s\n' '00000003-0000001B-1' | shasum -a 256 | awk '{print $1}')
jq -e --arg snapshot_hash "$snapshot_hash" '
  .components.postgresql.consistency == {
    method: "pg-exported-snapshot",
    single_transaction_snapshot: true,
    dump_snapshot_bound: true,
    snapshot_identifier_sha256: $snapshot_hash
  }
' "$native_bundle/manifest.json" >/dev/null || fail "native manifest snapshot binding is invalid"
[[ -z $(find "$native_bundle" -type f -name 'database.dump' -print -quit) ]] ||
  fail "native bundle contains a plaintext PostgreSQL dump"

native_backup_id=$(sed -n 's/^backup_id=//p' "$tmp/native-backup.out")
native_manifest_sha=$(sed -n 's/^manifest_sha256=//p' "$tmp/native-backup.out")
[[ "$native_backup_id" =~ ^[0-9a-f-]{36}$ && "$native_manifest_sha" =~ ^[0-9a-f]{64}$ ]] ||
  fail "remote backup did not report immutable bindings"
grep -Eq '^control_backup_remote_last_success_timestamp_seconds=[0-9]+$' "$tmp/native-backup.out" ||
  fail "remote backup did not emit the last-success metric after commit"
if rg -F "$remote_secret" "$tmp/native-backup.out" "$tmp/native-backup.err" "$FAKE_AWS_LOG" >/dev/null; then
  fail "remote credential leaked to command output or client arguments"
fi
staging_last=$(awk '/s3api put-object/ && /\/staging\// {line=NR} END {print line+0}' "$FAKE_AWS_LOG")
canonical_first=$(awk '/s3api put-object/ && /\/bundles\// {print NR; exit}' "$FAKE_AWS_LOG")
manifest_sig_line=$(awk '/s3api put-object/ && /\/bundles\// && /manifest.sig/ {line=NR} END {print line+0}' "$FAKE_AWS_LOG")
manifest_line=$(awk '/s3api put-object/ && /\/bundles\// && /manifest.json/ {line=NR} END {print line+0}' "$FAKE_AWS_LOG")
commit_line=$(awk '/s3api put-object/ && /\/bundles\// && /commit.json/ {line=NR} END {print line+0}' "$FAKE_AWS_LOG")
((staging_last < canonical_first && manifest_sig_line < manifest_line && manifest_line < commit_line)) ||
  fail "remote staging/canonical/manifest/commit publication order is invalid"
if awk '/s3api put-object/ && ($0 !~ /--object-lock-mode COMPLIANCE/ ||
  $0 !~ /--object-lock-retain-until-date [^ ]+/) {bad=1} END {exit bad ? 0 : 1}' "$FAKE_AWS_LOG"; then
  fail "remote immutable PUT omitted explicit COMPLIANCE retention"
fi
[[ -f "$FAKE_S3_ROOT/test-bucket/control/bundles/$native_backup_id/commit.json" ]] ||
  fail "canonical commit marker was not published"

mkdir "$tmp/missing-version-output"
rm -f "$FAKE_AWS_STATE"/*
expect_failure "remote put-object success response did not contain a VersionId" env \
  PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native \
  FAKE_AWS_PUT_MISSING_VERSION_SUFFIX=manifest.sig \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=native_fixture PGPASSWORD=fake \
  "$TOOL" backup --output-dir "$tmp/missing-version-output" "${backup_args[@]}" "${remote_args[@]}"

mkdir "$tmp/conflict-output"
rm -f "$FAKE_AWS_STATE"/*
expect_failure "remote object conflict or uncertain upload outcome" env PATH="$tmp/fake-native-bin:$PATH" \
  CONTROL_BACKUP_CLIENT_MODE=native FAKE_AWS_CONFLICT_SUFFIX=database.dump.age \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=native_fixture PGPASSWORD=fake \
  "$TOOL" backup --output-dir "$tmp/conflict-output" "${backup_args[@]}" "${remote_args[@]}"

remote_verify_args=(--expected-app-version test-1 --migrations-dir "$tmp/migrations" \
  --expected-source-cluster-id test-cluster --expected-backup-id "$native_backup_id" \
  --expected-manifest-sha256 "$native_manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id backup-signing-test)
rm -rf -- "$native_bundle"
PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native \
  FAKE_AWS_VERSION_RACE_SUFFIX=manifest.json \
  "$TOOL" remote-fetch --output-dir "$tmp/remote-output" "${remote_args[@]}" \
  "${remote_verify_args[@]}" > "$tmp/remote-fetch.out"
fetched_bundle=$(sed -n 's/^bundle_path=//p' "$tmp/remote-fetch.out")
[[ -d "$fetched_bundle" ]] || fail "remote fetch did not atomically publish a local bundle"
unversioned_get=$(awk '/s3api get-object --bucket/ && $0 !~ /--version-id / {print; exit}' "$FAKE_AWS_LOG")
[[ -z "$unversioned_get" ]] ||
  fail "remote readback was not bound to the VersionId returned by HEAD: $unversioned_get"

mkdir "$tmp/fetch-short-retention"
expect_failure "remote object download failed digest/size/immutability verification: manifest.json" env \
  PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native \
  FAKE_AWS_SHORT_RETENTION_SUFFIX=manifest.json \
  "$TOOL" remote-fetch --output-dir "$tmp/fetch-short-retention" "${remote_args[@]}" \
  "${remote_verify_args[@]}"
[[ -z $(find "$tmp/fetch-short-retention" -mindepth 1 -print -quit) ]] ||
  fail "short-retention remote fetch polluted the local output"

PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native \
  PGHOST=127.0.0.1 PGPORT=5432 PGUSER=user PGDATABASE=restore_fixture PGPASSWORD=fake \
  "$TOOL" restore --bundle "$fetched_bundle" --target-database restore_fixture \
  --confirm-empty-target restore_fixture --postgresql-target-free-bytes 20000000 \
  "${remote_verify_args[@]}" > "$tmp/remote-restore.out"
grep -Fqx 'restored_backup_id='"$native_backup_id" "$tmp/remote-restore.out" ||
  fail "fetched bundle did not enter the unchanged empty-target restore path"

canonical_root="$FAKE_S3_ROOT/test-bucket/control/bundles/$native_backup_id"
mkdir "$tmp/tamper-backup"
for object in commit.json manifest.json database.dump.age; do
  cp "$canonical_root/$object" "$tmp/tamper-backup/$object"
done
for object in commit.json manifest.json database.dump.age; do
  printf 'tamper\n' >> "$canonical_root/$object"
  mkdir "$tmp/fetch-tamper-$object"
  expect_failure "remote" env PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native \
    "$TOOL" remote-fetch --output-dir "$tmp/fetch-tamper-$object" "${remote_args[@]}" \
    "${remote_verify_args[@]}"
  [[ -z $(find "$tmp/fetch-tamper-$object" -mindepth 1 -print -quit) ]] ||
    fail "tampered remote $object polluted the local output"
  cp "$tmp/tamper-backup/$object" "$canonical_root/$object"
done

mkdir "$tmp/fetch-interrupted"
expect_failure "remote object download failed" env PATH="$tmp/fake-native-bin:$PATH" \
  CONTROL_BACKUP_CLIENT_MODE=native FAKE_AWS_GET_FAIL_SUFFIX=manifest.sig \
  "$TOOL" remote-fetch --output-dir "$tmp/fetch-interrupted" "${remote_args[@]}" \
  "${remote_verify_args[@]}"
[[ -z $(find "$tmp/fetch-interrupted" -mindepth 1 -print -quit) ]] ||
  fail "interrupted remote fetch polluted the local output"

wrong_id_args=(--expected-app-version test-1 --migrations-dir "$tmp/migrations" \
  --expected-source-cluster-id test-cluster \
  --expected-backup-id 00000000-0000-4000-8000-000000000099 \
  --expected-manifest-sha256 "$native_manifest_sha" --age-identity-file "$tmp/age-identity" \
  --signing-public-key-file "$tmp/signing-public.pem" --expected-signing-key-id backup-signing-test)
mkdir "$tmp/fetch-wrong-id"
expect_failure "remote commit marker is unavailable" env PATH="$tmp/fake-native-bin:$PATH" \
  CONTROL_BACKUP_CLIENT_MODE=native "$TOOL" remote-fetch --output-dir "$tmp/fetch-wrong-id" \
  "${remote_args[@]}" "${wrong_id_args[@]}"
wrong_digest_args=(--expected-app-version test-1 --migrations-dir "$tmp/migrations" \
  --expected-source-cluster-id test-cluster --expected-backup-id "$native_backup_id" \
  --expected-manifest-sha256 2222222222222222222222222222222222222222222222222222222222222222 \
  --age-identity-file "$tmp/age-identity" --signing-public-key-file "$tmp/signing-public.pem" \
  --expected-signing-key-id backup-signing-test)
mkdir "$tmp/fetch-wrong-digest"
expect_failure "remote commit manifest digest does not match expected digest" env \
  PATH="$tmp/fake-native-bin:$PATH" CONTROL_BACKUP_CLIENT_MODE=native \
  "$TOOL" remote-fetch --output-dir "$tmp/fetch-wrong-digest" "${remote_args[@]}" \
  "${wrong_digest_args[@]}"

printf 'control-backup tests: PASS\n'
