//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"regexp"
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

func TestNotificationOutboxSettlementConstraint128Up(t *testing.T) {
	fixture := openNotificationConstraint128Fixture(t)
	applyMigration128(t, fixture.pool, fixture.up)
	assertConstraint128Count(t, fixture.pool, "notification_outbox_check2", 0)

	for _, row := range []struct {
		status, failure string
		completed       bool
	}{
		{status: "accepted"},
		{status: "unknown", failure: "provider_outcome_unknown"},
	} {
		insertNotificationOutbox128(t, fixture.pool, row.status, row.failure, row.completed)
	}

	for _, row := range []struct {
		name, status, failure string
		completed             bool
	}{
		{name: "accepted failure", status: "accepted", failure: "unexpected"},
		{name: "unknown failure", status: "unknown", failure: "unexpected"},
		{name: "succeeded incomplete", status: "succeeded"},
		{name: "cancelled without failure", status: "cancelled", completed: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := insertNotificationOutbox128Result(
				t, fixture.pool, row.status, row.failure, row.completed,
			)
			assertSQLState128(t, err, "23514")
		})
	}
}

func TestNotificationOutboxSettlementConstraint128FailsClosed(t *testing.T) {
	t.Run("non 127 head", func(t *testing.T) {
		fixture := openNotificationConstraint128Fixture(t)
		if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=127`); err != nil {
			t.Fatal(err)
		}
		_, err := fixture.pool.Exec(t.Context(), fixture.up)
		assertSQLState128(t, err, "P1280")
		assertConstraint128Count(t, fixture.pool, "notification_outbox_check2", 1)
	})

	t.Run("unexpected legacy constraint", func(t *testing.T) {
		fixture := openNotificationConstraint128Fixture(t)
		if _, err := fixture.pool.Exec(t.Context(), `ALTER TABLE notification_outbox
			DROP CONSTRAINT notification_outbox_check2,
			ADD CONSTRAINT notification_outbox_check2 CHECK(status<>'unexpected')`); err != nil {
			t.Fatal(err)
		}
		_, err := fixture.pool.Exec(t.Context(), fixture.up)
		assertSQLState128(t, err, "P1280")
		assertConstraint128Count(t, fixture.pool, "notification_outbox_check2", 1)
	})

	t.Run("unexpected 108 named constraint", func(t *testing.T) {
		fixture := openNotificationConstraint128Fixture(t)
		if _, err := fixture.pool.Exec(t.Context(), `ALTER TABLE notification_outbox
			DROP CONSTRAINT notification_outbox_failure_shape_108,
			ADD CONSTRAINT notification_outbox_failure_shape_108 CHECK(last_failure_code IS NULL)`); err != nil {
			t.Fatal(err)
		}
		_, err := fixture.pool.Exec(t.Context(), fixture.up)
		assertSQLState128(t, err, "P1280")
		assertConstraint128Count(t, fixture.pool, "notification_outbox_check2", 1)
	})
}

func TestNotificationOutboxSettlementConstraint128Down(t *testing.T) {
	t.Run("safe exact rollback", func(t *testing.T) {
		fixture := openNotificationConstraint128Fixture(t)
		applyMigration128(t, fixture.pool, fixture.up)
		insertNotificationOutbox128(t, fixture.pool, "pending", "", false)
		recordMigration128(t, fixture)
		applyMigration128(t, fixture.pool, fixture.down)
		assertConstraint128Count(t, fixture.pool, "notification_outbox_check2", 1)
		_, err := insertNotificationOutbox128Result(t, fixture.pool, "accepted", "", false)
		assertSQLState128(t, err, "23514")
	})

	unsafe := []struct {
		name string
		seed func(*testing.T, *migration128Fixture)
	}{
		{name: "accepted", seed: func(t *testing.T, fixture *migration128Fixture) {
			insertNotificationOutbox128(t, fixture.pool, "accepted", "", false)
		}},
		{name: "unknown", seed: func(t *testing.T, fixture *migration128Fixture) {
			insertNotificationOutbox128(t, fixture.pool, "unknown", "provider_outcome_unknown", false)
		}},
		{name: "cancelled", seed: func(t *testing.T, fixture *migration128Fixture) {
			insertNotificationOutbox128(t, fixture.pool, "cancelled", "cancelled", true)
		}},
		{name: "delivery fact", seed: func(t *testing.T, fixture *migration128Fixture) {
			if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO notification_delivery_facts_108 VALUES(1)`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "settlement", seed: func(t *testing.T, fixture *migration128Fixture) {
			if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO notification_delivery_settlements_108 VALUES(1)`); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range unsafe {
		t.Run(test.name, func(t *testing.T) {
			fixture := openNotificationConstraint128Fixture(t)
			applyMigration128(t, fixture.pool, fixture.up)
			test.seed(t, fixture)
			recordMigration128(t, fixture)
			_, err := fixture.pool.Exec(t.Context(), fixture.down)
			assertSQLState128(t, err, "P1281")
			assertConstraint128Count(t, fixture.pool, "notification_outbox_check2", 0)
		})
	}
}

type migration128Fixture struct {
	pool     *pgxpool.Pool
	up, down string
	upSHA    string
	downSHA  string
}

func openNotificationConstraint128Fixture(t *testing.T) *migration128Fixture {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "notification_constraint_128_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^notification_constraint_128_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop migration 128 schema: %v", err)
		}
		admin.Close()
	})
	if _, err := pool.Exec(ctx, notificationConstraint128BaselineSQL); err != nil {
		t.Fatal(err)
	}
	up := readMigration128(t, "128_notification_outbox_settlement_constraint.up.sql")
	down := readMigration128(t, "128_notification_outbox_settlement_constraint.down.sql")
	return &migration128Fixture{
		pool: pool, up: up, down: down,
		upSHA:   fmt.Sprintf("%x", sha256.Sum256([]byte(up))),
		downSHA: fmt.Sprintf("%x", sha256.Sum256([]byte(down))),
	}
}

func recordMigration128(t *testing.T, fixture *migration128Fixture) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,
		integrity_state,metadata_recorded_at
	) VALUES(128,'128_notification_outbox_settlement_constraint',$1,$2,'verified',now())`,
		fixture.upSHA, fixture.downSHA); err != nil {
		t.Fatal(err)
	}
}

func applyMigration128(t *testing.T, pool *pgxpool.Pool, source string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), source); err != nil {
		t.Fatal(err)
	}
}

func insertNotificationOutbox128(
	t *testing.T,
	pool *pgxpool.Pool,
	status, failure string,
	completed bool,
) {
	t.Helper()
	if _, err := insertNotificationOutbox128Result(t, pool, status, failure, completed); err != nil {
		t.Fatal(err)
	}
}

func insertNotificationOutbox128Result(
	t *testing.T,
	pool *pgxpool.Pool,
	status, failure string,
	completed bool,
) (int64, error) {
	t.Helper()
	var failureValue any
	if failure != "" {
		failureValue = failure
	}
	var completedValue any
	if completed {
		completedValue = time.Now().UTC()
	}
	command, err := pool.Exec(t.Context(), `INSERT INTO notification_outbox(
		id,status,last_failure_code,completed_at
	) VALUES($1,$2,$3,$4)`, uuid.New(), status, failureValue, completedValue)
	return command.RowsAffected(), err
}

func assertConstraint128Count(t *testing.T, pool *pgxpool.Pool, name string, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_constraint
		WHERE conrelid='notification_outbox'::regclass AND conname=$1`, name).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("constraint %s count=%d, want %d", name, count, want)
	}
}

func assertSQLState128(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("SQL error=%v state=%q, want %s", err, pgErrCode128(pgErr), want)
	}
}

func pgErrCode128(err *pgconn.PgError) string {
	if err == nil {
		return ""
	}
	return err.Code
}

func readMigration128(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

const notificationConstraint128BaselineSQL = `
CREATE TABLE schema_migrations (
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
SELECT version, lpad(version::text,3,'0')||'_verified_predecessor',
       repeat('a',64),repeat('b',64),'verified',now()
FROM generate_series(1,127) AS version;

CREATE TABLE notification_outbox (
    id uuid PRIMARY KEY,
    status text NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending','leased','succeeded','accepted','unknown',
                   'permanent_failed','exhausted','cancelled')
    ),
    lease_token uuid,
    lease_expires_at timestamptz,
    last_failure_code text,
    completed_at timestamptz,
    generation integer NOT NULL DEFAULT 1,
    replay_of_outbox_id uuid,
    CONSTRAINT notification_outbox_check2 CHECK (
        (status = 'succeeded' AND last_failure_code IS NULL) OR
        (status IN ('permanent_failed', 'exhausted') AND last_failure_code IS NOT NULL) OR
        status IN ('pending', 'leased')
    ),
    CONSTRAINT notification_outbox_state_shape_108 CHECK (
        (status='pending' AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR
        (status='leased' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR
        (status IN ('accepted','unknown') AND lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL) OR
        (status IN ('succeeded','permanent_failed','exhausted','cancelled') AND
         lease_token IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
    ),
    CONSTRAINT notification_outbox_failure_shape_108 CHECK (
        (status IN ('succeeded','accepted') AND last_failure_code IS NULL) OR
        (status='unknown' AND last_failure_code='provider_outcome_unknown') OR
        (status IN ('permanent_failed','exhausted','cancelled') AND last_failure_code IS NOT NULL) OR
        status IN ('pending','leased')
    )
);
CREATE TABLE notification_delivery_settlements_108(marker integer);
CREATE TABLE notification_delivery_facts_108(marker integer);
CREATE TABLE notification_delivery_command_receipts_108(marker integer);
`
