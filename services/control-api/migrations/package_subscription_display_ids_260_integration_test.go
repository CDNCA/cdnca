//go:build integration

package migrations_test

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPackageSubscriptionDisplayIDs260BackfillRuntimeAndRollback(t *testing.T) {
	pool, schema := packageSubscriptionDisplayPool260(t)
	ids := []uuid.UUID{
		uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		uuid.MustParse("11111111-1111-4111-8111-111111111112"),
		uuid.MustParse("11111111-1111-4111-8111-111111111113"),
	}
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_subscriptions(id,created_at) VALUES($3,$5),($2,$4),($1,$4)`, ids[0], ids[1], ids[2], now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 260); err != nil {
		t.Fatalf("259 -> 260: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 260)
	for index, id := range ids {
		assertPackageSubscriptionDisplay260(t, pool, id, int64(index+1))
	}

	// The runtime can insert subscriptions but cannot mutate mapping or sequence.
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), "SET LOCAL ROLE cdnca_control_app"); err != nil {
		t.Fatal(err)
	}
	// A same-name temporary table cannot redirect the definer function.
	if _, err := tx.Exec(t.Context(), `CREATE TEMP TABLE package_subscription_display_ids(subscription_id uuid,display_id bigint) ON COMMIT DROP`); err != nil {
		t.Fatal(err)
	}
	newID := uuid.New()
	if _, err := tx.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{schema, "package_subscriptions"}.Sanitize()+"(id,created_at) VALUES($1,$2)", newID, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("runtime insert: %v", err)
	}
	var shadowRows int
	if err := tx.QueryRow(t.Context(), "SELECT count(*) FROM pg_temp.package_subscription_display_ids").Scan(&shadowRows); err != nil || shadowRows != 0 {
		t.Fatalf("shadow table rows = (%d,%v), want 0", shadowRows, err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPackageSubscriptionDisplay260(t, pool, newID, 4)

	var read, write, sequence, execute bool
	if err := pool.QueryRow(t.Context(), `SELECT
		has_table_privilege('cdnca_control_app',$1,'SELECT'),
		has_table_privilege('cdnca_control_app',$1,'INSERT,UPDATE,DELETE,TRUNCATE'),
		has_sequence_privilege('cdnca_control_app',$2,'USAGE,SELECT,UPDATE'),
		has_function_privilege('cdnca_control_app',$3,'EXECUTE')`,
		schema+".package_subscription_display_ids", schema+".package_subscription_display_ids_display_id_seq",
		schema+".assign_package_subscription_display_id_260()").Scan(&read, &write, &sequence, &execute); err != nil || !read || write || sequence || execute {
		t.Fatalf("runtime grants read/write/sequence/execute = (%v,%v,%v,%v,%v)", read, write, sequence, execute, err)
	}
	denied, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Exec(t.Context(), "SET LOCAL ROLE cdnca_control_app"); err != nil {
		t.Fatal(err)
	}
	var runtimeID int64
	if err := denied.QueryRow(t.Context(), "SELECT display_id FROM package_subscription_display_ids WHERE subscription_id=$1", newID).Scan(&runtimeID); err != nil || runtimeID != 4 {
		t.Fatalf("runtime read = (%d,%v), want 4", runtimeID, err)
	}
	_, err = denied.Exec(t.Context(), "DELETE FROM package_subscription_display_ids WHERE subscription_id=$1", newID)
	assertPackageSubscriptionCode260(t, err, "42501")
	if err := denied.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), "UPDATE package_subscription_display_ids SET display_id=99")
	assertPackageSubscriptionCode260(t, err, "428C9")
	for _, sql := range []string{
		"UPDATE package_subscription_display_ids SET display_id=DEFAULT",
		"UPDATE package_subscription_display_ids SET subscription_id=subscription_id",
		"DELETE FROM package_subscription_display_ids",
		"TRUNCATE package_subscription_display_ids",
	} {
		_, err := pool.Exec(t.Context(), sql)
		assertPackageSubscriptionCode260(t, err, "P2601")
	}
	_, err = pool.Exec(t.Context(), "DELETE FROM package_subscriptions WHERE id=$1", ids[0])
	assertPackageSubscriptionCode260(t, err, "23503")

	down, err := controlmigrations.FS.ReadFile("260_package_subscription_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	fenced, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fenced.Exec(t.Context(), "UPDATE schema_migrations SET checksum_sha256=repeat('0',64) WHERE version=259"); err != nil {
		t.Fatal(err)
	}
	_, err = fenced.Exec(t.Context(), string(down))
	assertPackageSubscriptionCode260(t, err, "P2602")
	if err := fenced.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 260); err != nil {
		t.Fatalf("260 -> 259: %v", err)
	}
	var count int
	var absent bool
	if err := pool.QueryRow(t.Context(), `SELECT count(*),to_regclass($1) IS NULL FROM package_subscriptions`, schema+".package_subscription_display_ids").Scan(&count, &absent); err != nil || count != 4 || !absent {
		t.Fatalf("rollback subscription count/mapping absent = (%d,%v,%v)", count, absent, err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 260); err != nil {
		t.Fatalf("260 reapply: %v", err)
	}
	assertPackageSubscriptionDisplay260(t, pool, newID, 4)
}

func TestPackageSubscriptionDisplayIDs260ConcurrentAllocationAndAtomicity(t *testing.T) {
	pool, _ := packageSubscriptionDisplayPool260(t)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 260); err != nil {
		t.Fatal(err)
	}
	const workers = 12
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
				if _, err := tx.Exec(t.Context(), "SET LOCAL ROLE cdnca_control_app"); err != nil {
					return err
				}
				_, err := tx.Exec(t.Context(), "INSERT INTO package_subscriptions(id) VALUES($1)", uuid.New())
				return err
			})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent subscription insert: %v", err)
		}
	}
	var count, unique, minimum, maximum int
	if err := pool.QueryRow(t.Context(), "SELECT count(*),count(DISTINCT display_id),min(display_id),max(display_id) FROM package_subscription_display_ids").Scan(&count, &unique, &minimum, &maximum); err != nil || count != workers || unique != workers || minimum != 1 || maximum != workers {
		t.Fatalf("concurrent allocation = (%d,%d,%d,%d,%v)", count, unique, minimum, maximum, err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := uuid.New()
	if _, err := tx.Exec(t.Context(), "INSERT INTO package_subscriptions(id) VALUES($1)", rolledBack); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM package_subscription_display_ids WHERE subscription_id=$1", rolledBack).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled back mapping count = (%d,%v)", count, err)
	}
	// Failure to allocate must also reject the subscription insert.
	if _, err := pool.Exec(t.Context(), "ALTER SEQUENCE package_subscription_display_ids_display_id_seq MAXVALUE 13"); err != nil {
		t.Fatal(err)
	}
	failedID := uuid.New()
	_, err = pool.Exec(t.Context(), "INSERT INTO package_subscriptions(id) VALUES($1)", failedID)
	assertPackageSubscriptionCode260(t, err, "2200H")
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM package_subscriptions WHERE id=$1", failedID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed allocation subscription count = (%d,%v)", count, err)
	}
}

func TestPackageSubscriptionDisplayIDs260FullMigrationRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 259)
	_, _, subscriptionID := seedL4DisplayIdentity214(t, pool, "subscription-260", time.Now().UTC())
	up, err := controlmigrations.FS.ReadFile("260_package_subscription_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	fenced, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fenced.Exec(t.Context(), "UPDATE schema_migrations SET down_checksum_sha256=repeat('0',64) WHERE version=259"); err != nil {
		t.Fatal(err)
	}
	_, err = fenced.Exec(t.Context(), string(up))
	assertPackageSubscriptionCode260(t, err, "P2600")
	if err := fenced.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 260); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 260)
	assertPackageSubscriptionDisplay260(t, pool, subscriptionID, 1)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 260); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 259)
}

func packageSubscriptionDisplayPool260(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "package_display_260_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+quotedSchema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop task schema: %v", err)
		}
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 16
	pool, err = pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations(
		version bigint PRIMARY KEY,migration_id text,checksum_sha256 text,down_checksum_sha256 text,
		integrity_state text,metadata_recorded_at timestamptz,applied_at timestamptz NOT NULL DEFAULT now());
		CREATE TABLE package_subscriptions(id uuid PRIMARY KEY,created_at timestamptz NOT NULL DEFAULT now());
		GRANT INSERT,SELECT ON package_subscriptions TO cdnca_control_app;
		GRANT USAGE ON SCHEMA `+quotedSchema+` TO cdnca_control_app;`); err != nil {
		t.Fatal(err)
	}
	batch := &pgx.Batch{}
	for version := int64(1); version <= 259; version++ {
		migration, err := loadPackageCommerceRBAC079Migration(version)
		if err != nil {
			t.Fatal(err)
		}
		batch.Queue(`INSERT INTO schema_migrations VALUES($1,$2,$3,$4,'verified',now(),now())`, version, migration.identifier, migration.upChecksum, migration.downChecksum)
	}
	if err := pool.SendBatch(t.Context(), batch).Close(); err != nil {
		t.Fatal(err)
	}
	return pool, schema
}

func assertPackageSubscriptionDisplay260(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), "SELECT display_id FROM package_subscription_display_ids WHERE subscription_id=$1", id).Scan(&got); err != nil || got != want {
		t.Fatalf("subscription %s display ID = (%d,%v), want %d", id, got, err, want)
	}
}

func assertPackageSubscriptionCode260(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error = %v, want %s", err, want)
	}
}
