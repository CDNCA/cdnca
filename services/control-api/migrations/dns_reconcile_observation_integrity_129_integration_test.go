//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDNSReconcileObservationIntegrity129Contract(t *testing.T) {
	up := readDNSReconcileObservation129(t, "129_dns_reconcile_observation_integrity.up.sql")
	down := readDNSReconcileObservation129(t, "129_dns_reconcile_observation_integrity.down.sql")
	for _, fragment := range []string{
		"7a6e8595c4487e733b1033c308878f1a8a4c413a6b05c998960c87638434622d",
		"32001dbf6ae3021288c9dcbae1d0f256ef8a7372d72b6e4fa7cf13223e471915",
		"dns_reconcile_check_result_valid_129",
		"'nodata'",
		"'authoritative'",
		"'public_recursive'",
		"NOT VALID",
		"ERRCODE='P1290'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("129 up missing %q", fragment)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(up)))
	for _, fragment := range []string{
		upSHA,
		"rollback would discard NODATA propagation facts",
		"ERRCODE='P1291'",
		"DROP FUNCTION dns_reconcile_check_result_valid_129(jsonb,uuid,text)",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("129 down missing %q", fragment)
		}
	}
}

func TestDNSReconcileObservationIntegrity129RoundTrip(t *testing.T) {
	pool := openDNSReconcileObservation129Pool(t)
	up := readDNSReconcileObservation129(t, "129_dns_reconcile_observation_integrity.up.sql")
	down := readDNSReconcileObservation129(t, "129_dns_reconcile_observation_integrity.down.sql")
	applyDNSReconcileObservation129(t, pool, up, down)

	if _, err := pool.Exec(t.Context(), `CREATE TEMP TABLE dns_reconcile_observation_probe_129
		(LIKE dns_reconcile_propagation_attempts INCLUDING CONSTRAINTS)`); err != nil {
		t.Fatal(err)
	}
	tenantID := uuid.New()
	checkedAt := time.Date(2026, 8, 7, 10, 11, 12, 0, time.UTC)
	insertDNSReconcileObservationProbe129(t, pool, tenantID, "nodata", checkedAt,
		`{"status":"nodata"}`)
	insertDNSReconcileObservationProbe129(t, pool, tenantID, "healthy", checkedAt,
		validDNSReconcileObservation129(tenantID, "healthy", checkedAt, true, true))

	invalid := []struct {
		name           string
		classification string
		result         string
	}{
		{name: "summary status drift", classification: "nodata", result: `{"status":"healthy"}`},
		{name: "tenant drift", classification: "healthy", result: validDNSReconcileObservation129(uuid.New(), "healthy", checkedAt, true, true)},
		{name: "typed status drift", classification: "nodata", result: validDNSReconcileObservation129(tenantID, "healthy", checkedAt, true, true)},
		{name: "missing authoritative", classification: "healthy", result: validDNSReconcileObservation129(tenantID, "healthy", checkedAt, false, true)},
		{name: "missing public", classification: "healthy", result: validDNSReconcileObservation129(tenantID, "healthy", checkedAt, true, false)},
		{name: "malformed observations", classification: "healthy", result: fmt.Sprintf(
			`{"TenantID":%q,"Status":"healthy","CheckedAt":%q,"RepairPlan":{},"Observations":{}}`,
			tenantID.String(), checkedAt.Format(time.RFC3339Nano))},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, err := insertDNSReconcileObservationProbe129Result(
				t, pool, tenantID, test.classification, checkedAt, test.result,
			)
			assertDNSReconcileObservationCode129(t, err, "23514")
		})
	}
	if _, err := pool.Exec(t.Context(), `DROP TABLE dns_reconcile_observation_probe_129`); err != nil {
		t.Fatal(err)
	}

	t.Run("down rejects NODATA facts", func(t *testing.T) {
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_propagation_attempts(
			tenant_id,job_id,job_attempt,lease_id,worker_id,attempt_number,classification,
			consecutive_healthy,check_result,checked_at,recorded_at
		) VALUES($1,$2,1,$3,'dns-129-worker',1,'nodata',0,$4,$5,$5)`,
			tenantID, uuid.New(), uuid.New(), []byte(`{"status":"nodata"}`), checkedAt); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), down)
		assertDNSReconcileObservationCode129(t, err, "P1291")
	})

	rollbackDNSReconcileObservation129(t, pool, down)
	if functionExistsDNSReconcileObservation129(t, pool) {
		t.Fatal("129 validator survived rollback")
	}
	if _, err := pool.Exec(t.Context(), `CREATE TEMP TABLE dns_reconcile_observation_probe_129
		(LIKE dns_reconcile_propagation_attempts INCLUDING CONSTRAINTS)`); err != nil {
		t.Fatal(err)
	}
	if _, err := insertDNSReconcileObservationProbe129Result(
		t, pool, tenantID, "nodata", checkedAt, `{"status":"nodata"}`,
	); err == nil {
		t.Fatal("legacy 076 classification accepted nodata after rollback")
	} else {
		assertDNSReconcileObservationCode129(t, err, "23514")
	}
	applyDNSReconcileObservation129(t, pool, up, down)
}

func openDNSReconcileObservation129Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dns_reconcile_observation_129_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^dns_reconcile_observation_129_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop migration 129 schema: %v", err)
		}
		admin.Close()
	})
	if _, err := pool.Exec(t.Context(), dnsReconcileObservation129BaselineSQL); err != nil {
		t.Fatal(err)
	}
	return pool
}

const dnsReconcileObservation129BaselineSQL = `
CREATE TABLE schema_migrations(
    version bigint PRIMARY KEY,
    migration_id text,
    checksum_sha256 text,
    down_checksum_sha256 text,
    integrity_state text,
    metadata_recorded_at timestamptz,
    applied_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations(
    version,migration_id,checksum_sha256,down_checksum_sha256,
    integrity_state,metadata_recorded_at
)
SELECT version,'fixture_'||version,repeat('a',64),repeat('b',64),'verified',now()
FROM generate_series(1,127) version;
INSERT INTO schema_migrations(
    version,migration_id,checksum_sha256,down_checksum_sha256,
    integrity_state,metadata_recorded_at
) VALUES(
    128,'128_notification_outbox_settlement_constraint',
    '7a6e8595c4487e733b1033c308878f1a8a4c413a6b05c998960c87638434622d',
    '32001dbf6ae3021288c9dcbae1d0f256ef8a7372d72b6e4fa7cf13223e471915',
    'verified',now()
);
CREATE TABLE dns_reconcile_propagation_attempts(
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    job_attempt integer NOT NULL CHECK(job_attempt>0),
    lease_id uuid NOT NULL,
    worker_id text NOT NULL CHECK(
        octet_length(worker_id) BETWEEN 1 AND 128 AND
        worker_id=btrim(worker_id) AND worker_id !~ '[[:cntrl:]]'
    ),
    attempt_number integer NOT NULL CHECK(attempt_number>0),
    classification text NOT NULL CHECK(classification IN(
        'healthy','missing_record','wrong_value','cname_chain','cname_loop',
        'cname_depth_exceeded','nxdomain','servfail','timeout',
        'authority_inconsistent','public_propagating','public_propagation_failed',
        'resolver_failure','malformed_response'
    )),
    consecutive_healthy integer NOT NULL CHECK(
        consecutive_healthy BETWEEN 0 AND attempt_number
    ),
    check_result jsonb NOT NULL CHECK(
        jsonb_typeof(check_result)='object' AND
        octet_length(check_result::text) BETWEEN 2 AND 1048576
    ),
    checked_at timestamptz NOT NULL CHECK(isfinite(checked_at)),
    recorded_at timestamptz NOT NULL CHECK(isfinite(recorded_at)),
    PRIMARY KEY(job_id,job_attempt,attempt_number),
    UNIQUE(tenant_id,job_id,job_attempt,attempt_number),
    CHECK(checked_at<=recorded_at)
);`

func validDNSReconcileObservation129(
	tenantID uuid.UUID,
	classification string,
	checkedAt time.Time,
	authoritative, public bool,
) string {
	observations := make([]string, 0, 2)
	if authoritative {
		observations = append(observations, `{"Role":"authoritative","Resolver":"ns1.example.test","Status":"healthy"}`)
	}
	if public {
		observations = append(observations, `{"Role":"public_recursive","Resolver":"public-a","Status":"healthy"}`)
	}
	return fmt.Sprintf(
		`{"TenantID":%q,"Status":%q,"CheckedAt":%q,"RepairPlan":{},"Observations":[%s]}`,
		tenantID.String(), classification, checkedAt.Format(time.RFC3339Nano), strings.Join(observations, ","),
	)
}

func insertDNSReconcileObservationProbe129(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID uuid.UUID,
	classification string,
	checkedAt time.Time,
	result string,
) {
	t.Helper()
	if _, err := insertDNSReconcileObservationProbe129Result(
		t, pool, tenantID, classification, checkedAt, result,
	); err != nil {
		t.Fatal(err)
	}
}

func insertDNSReconcileObservationProbe129Result(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID uuid.UUID,
	classification string,
	checkedAt time.Time,
	result string,
) (int64, error) {
	t.Helper()
	command, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_observation_probe_129(
		tenant_id,job_id,job_attempt,lease_id,worker_id,attempt_number,classification,
		consecutive_healthy,check_result,checked_at,recorded_at
	) VALUES($1,$2,1,$3,'dns-129-worker',1,$4,0,$5,$6,$6)`,
		tenantID, uuid.New(), uuid.New(), classification, []byte(result), checkedAt)
	return command.RowsAffected(), err
}

func applyDNSReconcileObservation129(t *testing.T, pool *pgxpool.Pool, up, down string) {
	t.Helper()
	upDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(up)))
	downDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(down)))
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), up); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO schema_migrations(
			version,migration_id,checksum_sha256,down_checksum_sha256,
			integrity_state,metadata_recorded_at
		) VALUES(129,'129_dns_reconcile_observation_integrity',$1,$2,'verified',clock_timestamp())`,
			upDigest, downDigest)
		return err
	}); err != nil {
		t.Fatalf("apply migration 129: %v", err)
	}
}

func rollbackDNSReconcileObservation129(t *testing.T, pool *pgxpool.Pool, down string) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), down); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=129`)
		return err
	}); err != nil {
		t.Fatalf("rollback migration 129: %v", err)
	}
}

func functionExistsDNSReconcileObservation129(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT
		to_regprocedure('dns_reconcile_check_result_valid_129(jsonb,uuid,text)') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func readDNSReconcileObservation129(t *testing.T, name string) string {
	t.Helper()
	payload, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func assertDNSReconcileObservationCode129(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("SQLSTATE=%s: expected error", want)
	}
	postgresError, ok := err.(*pgconn.PgError)
	if !ok || postgresError.Code != want {
		t.Fatalf("error=%v code=%q, want %s", err, postgresErrorCode129(err), want)
	}
}

func postgresErrorCode129(err error) string {
	if postgresError, ok := err.(*pgconn.PgError); ok {
		return postgresError.Code
	}
	return ""
}
