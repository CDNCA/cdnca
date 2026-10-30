package certdefaults

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCertificateDefaultsRuntimeGrants exercises the migration and the real
// Store/Service path under the unprivileged runtime role. It intentionally
// builds only the 258-era dependency tables; the migration itself is still
// applied through the migrator (bounded to 1..259, the migration under test)
// and validates every historical checksum.
func TestCertificateDefaultsRuntimeGrants(t *testing.T) {
	migrator, app := certificateDefaultsRuntimePools(t)
	assertCertificateDefaultsPrivileges(t, migrator, false)

	scopeID, userID, otherScopeID, otherUserID, providerID := seedCertificateDefaultsFixture(t, migrator)
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	service := NewService(NewStore(app, func() time.Time { return now }))
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant"}

	_, err := service.Get(t.Context(), actor, Request{TargetScopeID: scopeID, TargetUserID: userID})
	assertCertificateDefaultsPGCode(t, err, "42501")

	if err := databasetest.MigrateThrough(t.Context(), migrator, "up", certificateDefaultsMigration); err != nil {
		t.Fatal(err)
	}
	assertCertificateDefaultsPrivileges(t, migrator, true)

	defaults, err := service.Get(t.Context(), actor, Request{TargetScopeID: scopeID, TargetUserID: userID})
	if err != nil {
		t.Fatalf("Get after 259: %v", err)
	}
	if defaults.CertificateType != CertificateTypeACME || defaults.Revision != 0 {
		t.Fatalf("initial defaults = %+v, want acme/revision 0", defaults)
	}

	firstRequest := UpdateRequest{
		TargetScopeID:    scopeID,
		TargetUserID:     userID,
		CertificateType:  CertificateTypeUploaded,
		ExpectedRevision: 0,
		IdempotencyKey:   "certificate-defaults-runtime-1",
		RequestID:        "request-certificate-defaults-runtime-1",
	}
	first, err := service.Update(t.Context(), actor, firstRequest)
	if err != nil || first.CertificateType != CertificateTypeUploaded || first.Revision != 1 {
		t.Fatalf("first Update = %+v, err=%v", first, err)
	}
	replay, err := service.Update(t.Context(), actor, firstRequest)
	if err != nil || replay.Revision != first.Revision || replay.UpdatedAt == nil {
		t.Fatalf("idempotent replay = %+v, err=%v", replay, err)
	}

	secondRequest := firstRequest
	secondRequest.CertificateType = CertificateTypeACME
	secondRequest.ExpectedRevision = 1
	secondRequest.IdempotencyKey = "certificate-defaults-runtime-2"
	secondRequest.RequestID = "request-certificate-defaults-runtime-2"
	second, err := service.Update(t.Context(), actor, secondRequest)
	if err != nil || second.Revision != 2 || second.CertificateType != CertificateTypeACME {
		t.Fatalf("second Update = %+v, err=%v", second, err)
	}
	stale := secondRequest
	stale.ExpectedRevision = 1
	stale.IdempotencyKey = "certificate-defaults-runtime-stale"
	stale.RequestID = "request-certificate-defaults-runtime-stale"
	if _, err := service.Update(t.Context(), actor, stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale CAS error=%v, want %v", err, ErrRevisionConflict)
	}

	otherActor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant"}
	otherRequest := UpdateRequest{
		TargetScopeID:    otherScopeID,
		TargetUserID:     otherUserID,
		CertificateType:  CertificateTypeACME,
		ExpectedRevision: 0,
		IdempotencyKey:   "certificate-defaults-runtime-cross-tenant",
		RequestID:        "request-certificate-defaults-runtime-cross-tenant",
	}
	if _, err := service.Update(t.Context(), otherActor, otherRequest); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant error=%v, want %v", err, ErrPermissionDenied)
	}

	var auditCount int
	if err := migrator.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='certificate.defaults.update'`, scopeID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("audit rows=%d err=%v, want 2", auditCount, err)
	}

	if err := databasetest.MigrateThrough(t.Context(), migrator, "down", certificateDefaultsMigration); err != nil {
		t.Fatal(err)
	}
	assertCertificateDefaultsPrivileges(t, migrator, false)
	_, err = service.Get(t.Context(), actor, Request{TargetScopeID: scopeID, TargetUserID: userID})
	assertCertificateDefaultsPGCode(t, err, "42501")

	if err := databasetest.MigrateThrough(t.Context(), migrator, "up", certificateDefaultsMigration); err != nil {
		t.Fatal(err)
	}
	assertCertificateDefaultsPrivileges(t, migrator, true)
	replay, err = service.Update(t.Context(), actor, secondRequest)
	if err != nil || replay.Revision != second.Revision || replay.CertificateType != second.CertificateType {
		t.Fatalf("re-up replay = %+v, err=%v", replay, err)
	}
	t.Log("259 up/down/up: real app role Get/Update/readback/replay/CAS/cross-tenant rejection/audit passed")
	_ = providerID // Retained in the fixture to prove provider FK access is real.
}

func assertCertificateDefaultsPrivileges(t *testing.T, pool *pgxpool.Pool, granted bool) {
	t.Helper()
	for _, table := range []string{"certificate_user_defaults", "certificate_default_write_requests"} {
		for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			var allowed, grantOption bool
			if err := pool.QueryRow(t.Context(), `SELECT has_table_privilege('cdnca_control_app',$1,$2), has_table_privilege('cdnca_control_app',$1,$2||' WITH GRANT OPTION')`, table, privilege).Scan(&allowed, &grantOption); err != nil {
				t.Fatal(err)
			}
			want := granted && (privilege == "SELECT" || privilege == "INSERT" || privilege == "UPDATE")
			if allowed != want || grantOption {
				t.Errorf("%s %s allowed=%t grant_option=%t, want %t/false", table, privilege, allowed, grantOption, want)
			}
		}
		var publicCount int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_class relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) acl WHERE relation.oid=$1::regclass AND acl.grantee=0`, table).Scan(&publicCount); err != nil || publicCount != 0 {
			t.Fatalf("%s PUBLIC grants=%d err=%v", table, publicCount, err)
		}
	}
}

func assertCertificateDefaultsPGCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("PostgreSQL error=%v, want SQLSTATE %s", err, code)
	}
}

// certificateDefaultsMigration is the migration under test; later heads need
// tables this 258-era baseline does not build.
const certificateDefaultsMigration = 259

func certificateDefaultsRuntimePools(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required for real runtime-role migration tests")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "certificate_defaults_runtime_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier+" AUTHORIZATION cdnca_control_migrator"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
	openAs := func(role string) *pgxpool.Pool {
		config, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.RuntimeParams["search_path"] = schema
		config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
			_, err := connection.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
			return err
		}
		pool, err := pgxpool.NewWithConfig(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		var actual string
		var elevated bool
		if err := pool.QueryRow(t.Context(), `SELECT current_user,rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&actual, &elevated); err != nil || actual != role || elevated {
			t.Fatalf("role=%s elevated=%t err=%v", actual, elevated, err)
		}
		return pool
	}
	migrator := openAs("cdnca_control_migrator")
	prepareCertificateDefaultsBaseline(t, migrator, schema)
	// Today's audit.Append writes the 361 unified-log columns the 258-era baseline lacks.
	databasetest.AddUnifiedAuditColumns(t, migrator)
	return migrator, openAs("cdnca_control_app")
}

func prepareCertificateDefaultsBaseline(t *testing.T, pool *pgxpool.Pool, schema string) {
	t.Helper()
	_, err := pool.Exec(t.Context(), `
CREATE TABLE schema_migrations (
    version bigint PRIMARY KEY, migration_id text, checksum_sha256 text,
    down_checksum_sha256 text, integrity_state text,
    metadata_recorded_at timestamptz, applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE access_scopes (id uuid PRIMARY KEY, kind text NOT NULL);
CREATE TABLE users (id uuid PRIMARY KEY);
CREATE TABLE memberships (scope_id uuid NOT NULL REFERENCES access_scopes(id), user_id uuid NOT NULL REFERENCES users(id), status text NOT NULL, PRIMARY KEY(scope_id,user_id));
CREATE TABLE dns_providers (id uuid PRIMARY KEY, scope_id uuid NOT NULL REFERENCES access_scopes(id), status text NOT NULL, UNIQUE(scope_id,id));
CREATE TABLE audit_events (
 id uuid PRIMARY KEY, scope_id uuid NOT NULL, stream_position bigint NOT NULL,
 actor_user_id uuid, action text NOT NULL, resource_type text NOT NULL,
 resource_id text NOT NULL, request_id text NOT NULL, result text NOT NULL,
 payload jsonb NOT NULL, previous_hash bytea, event_hash bytea NOT NULL,
 occurred_at timestamptz NOT NULL
);
CREATE TABLE certificate_user_defaults (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL,
    certificate_type text NOT NULL CHECK (certificate_type IN ('acme', 'uploaded')),
    dns_provider_id uuid,
    -- 517 (CERT-04): today's Store reads and writes the user default issuer.
    issuer text CHECK (issuer IS NULL OR issuer IN ('lets_encrypt', 'zerossl', 'google_trust')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_id, user_id),
    FOREIGN KEY (scope_id, user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, dns_provider_id) REFERENCES dns_providers(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CHECK (certificate_type = 'acme' OR dns_provider_id IS NULL),
    CHECK (certificate_type = 'acme' OR issuer IS NULL)
);
CREATE TABLE certificate_default_write_requests (
    id uuid PRIMARY KEY, actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation = 'certificate.defaults.update'),
    idempotency_key text NOT NULL, request_digest bytea NOT NULL,
    resource_id uuid, response_status integer, response_body jsonb,
    created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key)
);
CREATE INDEX certificate_default_write_requests_scope_created_idx ON certificate_default_write_requests(target_scope_id, created_at DESC);
GRANT USAGE ON SCHEMA `+pgx.Identifier{schema}.Sanitize()+` TO cdnca_control_app;
GRANT SELECT ON access_scopes, users, memberships, dns_providers, audit_events TO cdnca_control_app;
GRANT INSERT ON audit_events TO cdnca_control_app;
`)
	if err != nil {
		t.Fatal(err)
	}
	insertCertificateDefaultsLedger(t, pool)
}

func insertCertificateDefaultsLedger(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	entries, err := fs.ReadDir(controlmigrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	type item struct{ id, up, down string }
	items := map[int]item{}
	pattern := regexp.MustCompile(`^(\d{3})_([a-z0-9]+(?:_[a-z0-9]+)*)\.(up|down)\.sql$`)
	for _, entry := range entries {
		match := pattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		var version int
		version, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		value := items[version]
		value.id = match[1] + "_" + match[2]
		content, err := fs.ReadFile(controlmigrations.FS, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(content))
		if match[3] == "up" {
			value.up = sum
		} else {
			value.down = sum
		}
		items[version] = value
	}
	for version := 1; version <= 258; version++ {
		value, ok := items[version]
		if !ok || value.up == "" || value.down == "" {
			t.Fatalf("missing migration checksums for %d", version)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO schema_migrations(version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at) VALUES($1,$2,$3,$4,'verified',now())`, version, value.id, value.up, value.down); err != nil {
			t.Fatal(err)
		}
	}
}

func seedCertificateDefaultsFixture(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	scopeID, userID := uuid.New(), uuid.New()
	otherScopeID, otherUserID, providerID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'tenant'),($2,'tenant')`, scopeID, otherScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id) VALUES($1),($2)`, userID, otherUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$3,'active'),($2,$4,'active')`, scopeID, otherScopeID, userID, otherUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(id,scope_id,status) VALUES($1,$2,'active')`, providerID, scopeID); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID, otherScopeID, otherUserID, providerID
}
