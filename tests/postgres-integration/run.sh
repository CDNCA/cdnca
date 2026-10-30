#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "${script_dir}/../.." && pwd)
postgres_image=${POSTGRES_INTEGRATION_IMAGE:-postgres:17.5}
postgres_container="cdnca-postgres-integration-$$-${RANDOM}"
postgres_password="cdnca-integration-only"
passed=0
failed=0

cleanup() {
  docker rm -f "${postgres_container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

run_gate() {
  local name=$1
  local directory=$2
  shift 2

  printf 'RUN %s\n' "${name}"
  if (cd "${directory}" && "$@"); then
    passed=$((passed + 1))
    printf 'PASS %s\n' "${name}"
  else
    failed=$((failed + 1))
    printf 'FAIL %s\n' "${name}" >&2
  fi
}

docker run -d --name "${postgres_container}" \
  --label cdnca.test-owner=postgres-integration \
  -e POSTGRES_USER=cdnca \
  -e POSTGRES_PASSWORD="${postgres_password}" \
  -e POSTGRES_DB=postgres \
  -p 127.0.0.1::5432 \
  "${postgres_image}" >/dev/null

ready=0
for _ in {1..60}; do
  if docker exec "${postgres_container}" pg_isready -U cdnca -d postgres >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ ${ready} -ne 1 ]]; then
  printf 'PostgreSQL did not become ready\n' >&2
  exit 1
fi

docker exec -i "${postgres_container}" psql -X -v ON_ERROR_STOP=1 -U cdnca -d postgres <<'SQL'
CREATE ROLE cdnca_control_app
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_retention_cleanup
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT cdnca_retention_cleanup TO cdnca;
CREATE DATABASE cdnca_integration OWNER cdnca TEMPLATE template0;
REVOKE CREATE ON DATABASE cdnca_integration FROM PUBLIC;
REVOKE ALL ON DATABASE cdnca_integration
  FROM cdnca_control_app, cdnca_plugin_webhook_runtime;
SQL

docker exec -i "${postgres_container}" psql -X -v ON_ERROR_STOP=1 -U cdnca -d cdnca_integration <<'SQL'
CREATE SCHEMA postgres_integration_baseline AUTHORIZATION cdnca;
SET search_path TO postgres_integration_baseline;
DO $$
DECLARE
  control_role oid := to_regrole('cdnca_control_app');
  runtime_role oid := to_regrole('cdnca_plugin_webhook_runtime');
BEGIN
  IF control_role IS NULL OR runtime_role IS NULL OR
     current_user::regrole IN (control_role, runtime_role) OR
     (SELECT nspowner FROM pg_namespace
      WHERE oid = current_schema()::regnamespace) <> current_user::regrole OR
     (SELECT COALESCE(nspacl, acldefault('n', nspowner)) IS DISTINCT FROM
             acldefault('n', nspowner)
      FROM pg_namespace WHERE oid = current_schema()::regnamespace) OR
     EXISTS (
       SELECT 1 FROM pg_roles role
       WHERE role.oid IN (to_regrole('cdnca_control_app'),
                          to_regrole('cdnca_plugin_webhook_runtime'))
         AND (role.rolcanlogin OR role.rolsuper OR role.rolcreatedb OR
              role.rolcreaterole OR role.rolreplication OR role.rolbypassrls)
     ) OR
     EXISTS (
       SELECT 1 FROM pg_default_acl default_acl
       WHERE default_acl.defaclrole = current_user::regrole
         AND default_acl.defaclnamespace IN (0, current_schema()::regnamespace)
         AND default_acl.defaclobjtype IN ('r', 'S', 'f', 'T')
     ) OR
     has_schema_privilege(control_role, current_schema(), 'CREATE') OR
     has_schema_privilege(runtime_role, current_schema(), 'CREATE') OR
     has_database_privilege(control_role, current_database(), 'CREATE') OR
     has_database_privilege(runtime_role, current_database(), 'CREATE') OR
     pg_has_role(control_role, runtime_role, 'MEMBER') OR
     pg_has_role(runtime_role, control_role, 'MEMBER') OR
     EXISTS (
       SELECT 1
       FROM pg_namespace namespace
       CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl
       WHERE namespace.oid = current_schema()::regnamespace
         AND acl.grantee IN (control_role, runtime_role)
     ) THEN
    RAISE EXCEPTION 'unsafe PostgreSQL integration role baseline';
  END IF;
END $$;
DROP SCHEMA postgres_integration_baseline;
SQL

postgres_port=$(docker port "${postgres_container}" 5432/tcp | sed -n '1s/.*://p')
case ${postgres_port} in
  ''|*[!0-9]*)
    printf 'Invalid PostgreSQL port %q\n' "${postgres_port}" >&2
    exit 1
    ;;
esac
database_url="postgres://cdnca:${postgres_password}@127.0.0.1:${postgres_port}/cdnca_integration?sslmode=disable"

run_gate control-acme-runtime "${repo_dir}/services/control-api" \
  env TEST_DATABASE_URL="${database_url}" \
  go test -tags=integration ./internal/acmeruntime \
  -run '^TestACMERuntimePostgreSQL17$' -count=1 -timeout=10m -v

run_gate control-api-acme "${repo_dir}/services/control-api" \
  env TEST_DATABASE_URL="${database_url}" \
  go test -tags=integration ./cmd/control-api \
  -run '^(TestConfiguredACMEProcessRuntimeLeavesSiteScopedOverlayBacklogNetworkZero|TestConfiguredACMERunnerRejectsSuccessBeforeIssuedDatabaseFact|TestConfiguredACMERuntimeFailsClosedWithoutHTTP01ProductionProvider|TestConfiguredACMEDNSStartupFailsClosedWhenOutstandingSourceIsUnreadable)$' \
  -count=1 -timeout=10m -v

run_gate license-installation-reactivation "${repo_dir}/services/license-service" \
  env GOWORK=off LICENSE_TEST_DATABASE_URL="${database_url}" \
  go test ./internal/licensing \
  -run '^(TestInstallationMigrationReinstallProofIdempotencyAndNoPrivateKeyPersistence|TestInstallationReactivationCredentialMetadataAndRevocation|TestInstallationReactivationCredentialRevocationIdempotencyAuditAndMutationZero|TestInstallationReactivationCredentialConsumeAndRevokeSerialize)$' \
  -count=1 -timeout=10m -v

run_gate notification-control-round4 "${repo_dir}/services/control-api" \
  env TEST_DATABASE_URL="${database_url}" \
  go test ./internal/notificationcontrol \
  -run '^TestNotificationControlPlatformWritesAuthenticateBeforeScopeDenial091$' \
  -count=1 -timeout=10m -v

printf 'postgres-integration summary: passed=%d failed=%d omitted_nats=1\n' \
  "${passed}" "${failed}"
[[ ${failed} -eq 0 ]]
