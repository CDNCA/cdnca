package database

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var migrationTestSchemaSequence atomic.Uint64

func TestMigrateFreshUpDownUpRecordsMetadata(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (id integer PRIMARY KEY); INSERT INTO migration_probe VALUES (1);",
		down: "DROP TABLE migration_probe;",
	}})

	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("migrateFS(up) error = %v", err)
	}
	assertVerifiedLedgerRow(t, pool, 1, "001_probe", files["001_probe.up.sql"].Data, files["001_probe.down.sql"].Data)

	if err := migrateFS(t.Context(), pool, "down", files); err != nil {
		t.Fatalf("migrateFS(down) error = %v", err)
	}
	var tableExists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('migration_probe') IS NOT NULL`).Scan(&tableExists); err != nil {
		t.Fatalf("check rolled back table: %v", err)
	}
	if tableExists {
		t.Fatal("migration_probe still exists after down migration")
	}

	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("migrateFS(second up) error = %v", err)
	}
	assertVerifiedLedgerRow(t, pool, 1, "001_probe", files["001_probe.up.sql"].Data, files["001_probe.down.sql"].Data)
}

func TestMigrateRejectsLowVersionBackfill(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{
		{name: "001_first", up: "CREATE TABLE migration_events (version integer PRIMARY KEY); INSERT INTO migration_events VALUES (1);", down: "DELETE FROM migration_events WHERE version=1;"},
		{name: "002_second", up: "INSERT INTO migration_events VALUES (2);", down: "DELETE FROM migration_events WHERE version=2;"},
		{name: "003_third", up: "INSERT INTO migration_events VALUES (3);", down: "DELETE FROM migration_events WHERE version=3;"},
	})
	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("initial migrateFS(up) error = %v", err)
	}
	if _, err := pool.Exec(t.Context(), "DELETE FROM schema_migrations WHERE version=2"); err != nil {
		t.Fatalf("create ledger gap: %v", err)
	}

	err := migrateFS(t.Context(), pool, "up", files)
	if err == nil || !strings.Contains(err.Error(), "applied migration gap") {
		t.Fatalf("migrateFS(up) error = %v, want applied migration gap", err)
	}
	var executions int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM migration_events WHERE version=2").Scan(&executions); err != nil {
		t.Fatalf("count migration executions: %v", err)
	}
	if executions != 1 {
		t.Fatalf("migration 2 execution count = %d, want 1", executions)
	}
}

func TestMigrateRejectsAppliedSQLDrift(t *testing.T) {
	pool := migrationTestPool(t)
	original := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (value text);",
		down: "DROP TABLE migration_probe;",
	}})
	if err := migrateFS(t.Context(), pool, "up", original); err != nil {
		t.Fatalf("initial migrateFS(up) error = %v", err)
	}
	drifted := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (value bigint);",
		down: "DROP TABLE migration_probe;",
	}})

	err := migrateFS(t.Context(), pool, "up", drifted)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("migrateFS(up) error = %v, want checksum mismatch", err)
	}
}

func TestMigrateRejectsDownSQLDriftBeforeNoopOrRollback(t *testing.T) {
	pool := migrationTestPool(t)
	original := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (value text);",
		down: "DROP TABLE migration_probe;",
	}})
	if err := migrateFS(t.Context(), pool, "up", original); err != nil {
		t.Fatalf("initial migrateFS(up) error = %v", err)
	}
	drifted := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (value text);",
		down: "DROP TABLE migration_probe; CREATE TABLE unexpected_side_effect (id integer);",
	}})

	for _, direction := range []string{"up", "down"} {
		err := migrateFS(t.Context(), pool, direction, drifted)
		if err == nil || !strings.Contains(err.Error(), "down checksum mismatch") {
			t.Fatalf("migrateFS(%s) error = %v, want down checksum mismatch", direction, err)
		}
	}
	var tableExists, unexpectedExists bool
	if err := pool.QueryRow(t.Context(), `
		SELECT to_regclass('migration_probe') IS NOT NULL,
			to_regclass('unexpected_side_effect') IS NOT NULL`).Scan(&tableExists, &unexpectedExists); err != nil {
		t.Fatalf("check failed-closed schema state: %v", err)
	}
	if !tableExists || unexpectedExists {
		t.Fatalf("after rejected rollback migration_probe=%v unexpected_side_effect=%v", tableExists, unexpectedExists)
	}
	var ledgerRows int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM schema_migrations WHERE version=1`).Scan(&ledgerRows); err != nil {
		t.Fatalf("count ledger after rejected rollback: %v", err)
	}
	if ledgerRows != 1 {
		t.Fatalf("ledger rows after rejected rollback = %d, want 1", ledgerRows)
	}

	if err := migrateFS(t.Context(), pool, "down", original); err != nil {
		t.Fatalf("migrateFS(down) after restoring script error = %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('migration_probe') IS NOT NULL`).Scan(&tableExists); err != nil {
		t.Fatalf("check restored rollback: %v", err)
	}
	if tableExists {
		t.Fatal("migration_probe still exists after restoring and executing original down script")
	}
}

func TestMigrateDownBlocksVersionOnlyLegacyLedger(t *testing.T) {
	pool := migrationTestPool(t)
	if _, err := pool.Exec(t.Context(), `
		CREATE TABLE migration_probe (id integer);
		CREATE TABLE schema_migrations (
			version bigint PRIMARY KEY,
			installed_at timestamptz NOT NULL DEFAULT now()
		);
		INSERT INTO schema_migrations(version) VALUES (1)`); err != nil {
		t.Fatalf("create version-only legacy state: %v", err)
	}
	files := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (id integer);",
		down: "DROP TABLE migration_probe;",
	}})

	err := migrateFS(t.Context(), pool, "down", files)
	assertLegacyRollbackBlocked(t, err, 1)
	assertMigrationAndLedgerRemain(t, pool, "migration_probe", 1)
}

func TestMigrateMarksLegacyLedgerUnverified(t *testing.T) {
	pool := migrationTestPool(t)
	if _, err := pool.Exec(t.Context(), `
		CREATE TABLE schema_migrations (
			version bigint PRIMARY KEY,
			installed_at timestamptz NOT NULL DEFAULT now()
		);
		INSERT INTO schema_migrations(version) VALUES (1)`); err != nil {
		t.Fatalf("create legacy ledger: %v", err)
	}
	files := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (id integer);",
		down: "DROP TABLE migration_probe;",
	}, {
		name: "002_pending",
		up:   "CREATE TABLE migration_pending (id integer);",
		down: "DROP TABLE migration_pending;",
	}})

	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("migrateFS(up) compatibility upgrade error = %v", err)
	}
	var identifier, upChecksum, downChecksum, state string
	var recorded bool
	if err := pool.QueryRow(t.Context(), `
		SELECT migration_id, checksum_sha256, down_checksum_sha256,
			integrity_state, metadata_recorded_at IS NOT NULL
		FROM schema_migrations WHERE version=1`).Scan(&identifier, &upChecksum, &downChecksum, &state, &recorded); err != nil {
		t.Fatalf("read upgraded legacy ledger: %v", err)
	}
	if identifier != "001_probe" || len(upChecksum) != 64 || len(downChecksum) != 64 || state != "legacy_unverified" || !recorded {
		t.Fatalf("legacy metadata = %q %q %q %q recorded=%v", identifier, upChecksum, downChecksum, state, recorded)
	}
	assertVerifiedLedgerRow(t, pool, 2, "002_pending", files["002_pending.up.sql"].Data, files["002_pending.down.sql"].Data)
	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("second migrateFS(up) error = %v", err)
	}

	drifted := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (id bigint);",
		down: "DROP TABLE migration_probe;",
	}, {
		name: "002_pending",
		up:   "CREATE TABLE migration_pending (id integer);",
		down: "DROP TABLE migration_pending;",
	}})
	if err := migrateFS(t.Context(), pool, "up", drifted); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("migrateFS(up) after legacy baseline drift error = %v, want checksum mismatch", err)
	}
}

func TestMigrateDownBlocksUpOnlyLedgerAfterRecordingDownBaseline(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{{
		name: "001_probe",
		up:   "CREATE TABLE migration_probe (id integer);",
		down: "DROP TABLE migration_probe;",
	}})
	if _, err := pool.Exec(t.Context(), `
		CREATE TABLE schema_migrations (
			version bigint PRIMARY KEY,
			migration_id text,
			checksum_sha256 text,
			integrity_state text,
			metadata_recorded_at timestamptz,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create up-only ledger: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO schema_migrations (
			version, migration_id, checksum_sha256, integrity_state, metadata_recorded_at
		) VALUES (1, '001_probe', $1, 'verified', now())`, sha256Hex(files["001_probe.up.sql"].Data)); err != nil {
		t.Fatalf("insert up-only ledger row: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TABLE migration_probe (id integer)`); err != nil {
		t.Fatalf("create applied migration schema: %v", err)
	}

	err := migrateFS(t.Context(), pool, "down", files)
	assertLegacyRollbackBlocked(t, err, 1)
	var downChecksum, state string
	if err := pool.QueryRow(t.Context(), `
		SELECT down_checksum_sha256, integrity_state
		FROM schema_migrations WHERE version=1`).Scan(&downChecksum, &state); err != nil {
		t.Fatalf("read upgraded up-only ledger: %v", err)
	}
	if downChecksum != sha256Hex(files["001_probe.down.sql"].Data) || state != "legacy_unverified" {
		t.Fatalf("upgraded up-only ledger down checksum=%q state=%q", downChecksum, state)
	}
	assertMigrationAndLedgerRemain(t, pool, "migration_probe", 1)
}

func TestMigrateDownBlocksMixedChainWithUnverifiedHead(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{
		{name: "001_first", up: "CREATE TABLE migration_first (id integer);", down: "DROP TABLE migration_first;"},
		{name: "002_second", up: "CREATE TABLE migration_second (id integer);", down: "DROP TABLE migration_second;"},
	})
	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("migrateFS(up) error = %v", err)
	}
	if _, err := pool.Exec(t.Context(), `
		UPDATE schema_migrations
		SET integrity_state='legacy_unverified'
		WHERE version=2`); err != nil {
		t.Fatalf("mark head migration unverified: %v", err)
	}

	err := migrateFS(t.Context(), pool, "down", files)
	assertLegacyRollbackBlocked(t, err, 2)
	assertMigrationAndLedgerRemain(t, pool, "migration_second", 2)
}

func TestLegacyMetadataPlanningFailureLeavesLedgerUnchanged(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{
		{name: "001_first", up: "SELECT 1;", down: "SELECT 1;"},
		{name: "002_second", up: "SELECT 2;", down: "SELECT 2;"},
	})
	if _, err := pool.Exec(t.Context(), `
		CREATE TABLE schema_migrations (
			version bigint PRIMARY KEY,
			migration_id text,
			checksum_sha256 text,
			down_checksum_sha256 text,
			integrity_state text,
			metadata_recorded_at timestamptz,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create migration ledger: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO schema_migrations(version) VALUES(1)`); err != nil {
		t.Fatalf("insert version-only row: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO schema_migrations (
			version, migration_id, checksum_sha256, down_checksum_sha256,
			integrity_state, metadata_recorded_at
		) VALUES (2, '002_second', 'wrong-up-checksum', $1, 'verified', now())`,
		sha256Hex(files["002_second.down.sql"].Data)); err != nil {
		t.Fatalf("insert drifted row: %v", err)
	}

	err := migrateFS(t.Context(), pool, "up", files)
	if err == nil || !strings.Contains(err.Error(), "migration 2 up checksum mismatch") {
		t.Fatalf("migrateFS(up) error = %v, want migration 2 up checksum mismatch", err)
	}
	var untouched bool
	if err := pool.QueryRow(t.Context(), `
		SELECT migration_id IS NULL AND checksum_sha256 IS NULL AND
			down_checksum_sha256 IS NULL AND integrity_state IS NULL AND
			metadata_recorded_at IS NULL
		FROM schema_migrations WHERE version=1`).Scan(&untouched); err != nil {
		t.Fatalf("read planned legacy row: %v", err)
	}
	if !untouched {
		t.Fatal("version 1 legacy metadata changed before version 2 validation failed")
	}
}

func TestCanceledLegacyMetadataUpgradeRollsBackAllRows(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{
		{name: "001_first", up: "SELECT 1;", down: "SELECT 1;"},
		{name: "002_second", up: "SELECT 2;", down: "SELECT 2;"},
	})
	if _, err := pool.Exec(t.Context(), `
		CREATE TABLE schema_migrations (
			version bigint PRIMARY KEY,
			installed_at timestamptz NOT NULL DEFAULT now()
		);
		INSERT INTO schema_migrations(version) VALUES(1), (2);
		CREATE FUNCTION delay_second_legacy_update() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF OLD.version = 2 THEN
				PERFORM pg_sleep(5);
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER delay_second_legacy_update
		BEFORE UPDATE ON schema_migrations
		FOR EACH ROW EXECUTE FUNCTION delay_second_legacy_update()`); err != nil {
		t.Fatalf("create delayed legacy ledger: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := migrateFS(ctx, pool, "up", files)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("migrateFS(up) error = %v, want context deadline exceeded", err)
	}
	var changed int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM schema_migrations
		WHERE migration_id IS NOT NULL OR checksum_sha256 IS NOT NULL OR
			down_checksum_sha256 IS NOT NULL OR integrity_state IS NOT NULL OR
			metadata_recorded_at IS NOT NULL`).Scan(&changed); err != nil {
		t.Fatalf("count changed legacy rows: %v", err)
	}
	if changed != 0 {
		t.Fatalf("changed legacy rows after canceled upgrade = %d, want 0", changed)
	}
}

func TestMigrateDownFailureRollsBackDDLAndLedger(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{{
		name: "001_failed_down",
		up:   "CREATE TABLE migration_probe (id integer);",
		down: "DROP TABLE migration_probe; SELECT * FROM table_that_does_not_exist;",
	}})
	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("migrateFS(up) error = %v", err)
	}

	err := migrateFS(t.Context(), pool, "down", files)
	if err == nil || !strings.Contains(err.Error(), "rollback migration 1") {
		t.Fatalf("migrateFS(down) error = %v, want rollback migration 1", err)
	}
	assertMigrationAndLedgerRemain(t, pool, "migration_probe", 1)
}

func TestConcurrentMigrateExecutesOnce(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{{
		name: "001_concurrent",
		up: `CREATE TABLE migration_execution_count (id integer PRIMARY KEY);
			INSERT INTO migration_execution_count VALUES (1);
			SELECT pg_sleep(0.2);`,
		down: "DROP TABLE migration_execution_count;",
	}})

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- migrateFS(context.Background(), pool, "up", files)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrateFS(up) error = %v", err)
		}
	}
	var rows, ledgerRows int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM migration_execution_count").Scan(&rows); err != nil {
		t.Fatalf("count migration side effects: %v", err)
	}
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM schema_migrations WHERE version=1").Scan(&ledgerRows); err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	if rows != 1 || ledgerRows != 1 {
		t.Fatalf("side effect rows=%d ledger rows=%d, want 1 and 1", rows, ledgerRows)
	}
}

func TestConcurrentMigrateDownExecutesOnce(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{{
		name: "001_concurrent_down",
		up: `CREATE TABLE migration_probe (id integer);
			CREATE TABLE rollback_execution_count (executions integer NOT NULL);
			INSERT INTO rollback_execution_count VALUES (0);`,
		down: `UPDATE rollback_execution_count SET executions=executions+1;
			DROP TABLE migration_probe;
			SELECT pg_sleep(0.2);`,
	}})
	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("migrateFS(up) error = %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- migrateFS(context.Background(), pool, "down", files)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrateFS(down) error = %v", err)
		}
	}

	var executions, ledgerRows int
	if err := pool.QueryRow(t.Context(), `SELECT executions FROM rollback_execution_count`).Scan(&executions); err != nil {
		t.Fatalf("read rollback executions: %v", err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM schema_migrations`).Scan(&ledgerRows); err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	if executions != 1 || ledgerRows != 0 {
		t.Fatalf("rollback executions=%d ledger rows=%d, want 1 and 0", executions, ledgerRows)
	}
}

func TestCanceledMigrateDownWhileWaitingForLockHasNoSideEffects(t *testing.T) {
	pool := migrationTestPool(t)
	files := sqlMigrationFiles([]testMigration{{
		name: "001_cancel_down",
		up:   "CREATE TABLE migration_probe (id integer);",
		down: "DROP TABLE migration_probe;",
	}})
	if err := migrateFS(t.Context(), pool, "up", files); err != nil {
		t.Fatalf("migrateFS(up) error = %v", err)
	}

	holder, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatalf("acquire lock holder: %v", err)
	}
	t.Cleanup(holder.Release)
	if _, err := holder.Exec(t.Context(), `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		t.Fatalf("hold migration lock: %v", err)
	}
	locked := true
	t.Cleanup(func() {
		if locked {
			_, _ = holder.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- migrateFS(ctx, pool, "down", files)
	}()
	waitForMigrationLockWaiter(t, pool)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled migrateFS(down) error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled migrateFS(down) did not return")
	}
	assertMigrationAndLedgerRemain(t, pool, "migration_probe", 1)

	if _, err := holder.Exec(t.Context(), `SELECT pg_advisory_unlock($1)`, migrationLockID); err != nil {
		t.Fatalf("release migration lock: %v", err)
	}
	locked = false
	if err := migrateFS(t.Context(), pool, "down", files); err != nil {
		t.Fatalf("migrateFS(down) after cancellation error = %v", err)
	}
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('migration_probe') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("check rollback after cancellation: %v", err)
	}
	if exists {
		t.Fatal("migration_probe still exists after verified rollback")
	}
}

type testMigration struct {
	name string
	up   string
	down string
}

func sqlMigrationFiles(items []testMigration) fstest.MapFS {
	result := make(fstest.MapFS, len(items)*2)
	for _, item := range items {
		result[item.name+".up.sql"] = &fstest.MapFile{Data: []byte(item.up)}
		result[item.name+".down.sql"] = &fstest.MapFile{Data: []byte(item.down)}
	}
	return result
}

func migrationTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open test database admin pool: %v", err)
	}
	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("migration_loader_%d_%d", os.Getpid(), migrationTestSchemaSequence.Add(1))
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
	})

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	config.MaxConns = 4
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open isolated test pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping isolated test pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func assertVerifiedLedgerRow(t *testing.T, pool *pgxpool.Pool, version int64, identifier string, upScript, downScript []byte) {
	t.Helper()
	var gotIdentifier, upChecksum, downChecksum, state string
	if err := pool.QueryRow(t.Context(), `
		SELECT migration_id, checksum_sha256, down_checksum_sha256, integrity_state
		FROM schema_migrations WHERE version=$1`, version).Scan(&gotIdentifier, &upChecksum, &downChecksum, &state); err != nil {
		t.Fatalf("read schema_migrations version %d: %v", version, err)
	}
	if gotIdentifier != identifier || upChecksum != sha256Hex(upScript) || downChecksum != sha256Hex(downScript) || state != "verified" {
		t.Fatalf(
			"ledger row = %q %q %q %q, want %q %q %q verified",
			gotIdentifier, upChecksum, downChecksum, state,
			identifier, sha256Hex(upScript), sha256Hex(downScript),
		)
	}
}

func assertLegacyRollbackBlocked(t *testing.T, err error, version int64) {
	t.Helper()
	if err == nil {
		t.Fatalf("migrateFS(down) error = nil, want legacy rollback block for version %d", version)
	}
	for _, want := range []string{
		fmt.Sprintf("rollback migration %d", version),
		`integrity state "legacy_unverified"`,
		"restore the exact archived migration artifacts",
		"manual review/recovery",
		"no override",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("migrateFS(down) error = %q, want containing %q", err, want)
		}
	}
}

func assertMigrationAndLedgerRemain(t *testing.T, pool *pgxpool.Pool, table string, version int64) {
	t.Helper()
	var tableExists bool
	var ledgerRows int
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&tableExists); err != nil {
		t.Fatalf("check table %s: %v", table, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM schema_migrations WHERE version=$1`, version).Scan(&ledgerRows); err != nil {
		t.Fatalf("count ledger version %d: %v", version, err)
	}
	if !tableExists || ledgerRows != 1 {
		t.Fatalf("after blocked rollback table %s exists=%v ledger rows=%d, want true and 1", table, tableExists, ledgerRows)
	}
}

func waitForMigrationLockWaiter(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `
			SELECT EXISTS (
				SELECT 1 FROM pg_locks
				WHERE locktype='advisory' AND NOT granted
				  AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
			)`).Scan(&waiting); err != nil {
			t.Fatalf("check migration lock waiter: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("migrateFS did not wait for the advisory lock")
}
