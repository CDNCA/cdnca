//go:build integration

package migrations_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Most tests here need "a fresh schema migrated through N". Migrating 001..N
// per test and dropping the schema object by object took 30-60s each, which
// pushed the package past 600s. The first request for N migrates one snapshot
// database (schema "migrated"); every request then gets its own file_copy
// clone of it, which takes about a second. Snapshots belong to this test
// process and are dropped by TestMain.

const snapshotSchema = "migrated"

// maxMigrationSnapshots bounds disk use; tests in one file share versions, so
// the least recently used snapshot is the one to drop.
const maxMigrationSnapshots = 8

var migrationSnapshots = struct {
	sync.Mutex
	run   string
	names map[int64]string
	order []int64
}{run: strings.ReplaceAll(uuid.NewString(), "-", "")[:12], names: map[int64]string{}}

func TestMain(m *testing.M) {
	code := m.Run()
	dropMigrationSnapshots()
	os.Exit(code)
}

// migrationSnapshotPool returns a pool on a private database whose schema
// "migrated" is migrated through exactly version.
func migrationSnapshotPool(t *testing.T, version int64) *pgxpool.Pool {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := migrationSnapshot(ctx, admin, base, version)
	if err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("migration snapshot %03d: %v", version, err)
	}
	clone := "mig_clone_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+clone+" TEMPLATE "+snapshot+" STRATEGY file_copy"); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("clone migration snapshot %03d: %v", version, err)
	}
	t.Cleanup(func() {
		dropCtx, dropCancel := databasetest.CleanupContext()
		defer dropCancel()
		if _, err := admin.Exec(dropCtx, "DROP DATABASE IF EXISTS "+clone+" WITH (FORCE)"); err != nil {
			t.Logf("drop migration clone %s (left behind): %v", clone, err)
		}
		_ = admin.Close(dropCtx)
	})
	pool, err := snapshotDatabasePool(ctx, base, clone)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func migrationSnapshot(ctx context.Context, admin *pgx.Conn, base string, version int64) (string, error) {
	migrationSnapshots.Lock()
	defer migrationSnapshots.Unlock()
	if name, ok := migrationSnapshots.names[version]; ok {
		touchMigrationSnapshot(version)
		return name, nil
	}
	name := fmt.Sprintf("mig_snap_%s_%03d", migrationSnapshots.run, version)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" TEMPLATE template0"); err != nil {
		return "", err
	}
	built := false
	defer func() {
		if !built {
			_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		}
	}()
	// Same database baseline as pg-native-test.sh: PUBLIC may not create.
	if _, err := admin.Exec(ctx, "REVOKE CREATE ON DATABASE "+name+" FROM PUBLIC"); err != nil {
		return "", err
	}
	owner, err := snapshotDatabasePool(ctx, base, name)
	if err != nil {
		return "", err
	}
	_, err = owner.Exec(ctx, "CREATE SCHEMA "+snapshotSchema)
	if err == nil {
		err = migrateVersionIsolated(ctx, owner, "up", version)
	}
	// A template must have no open connections when it is cloned.
	owner.Close()
	if err != nil {
		return "", err
	}
	built = true
	migrationSnapshots.names[version] = name
	touchMigrationSnapshot(version)
	for len(migrationSnapshots.order) > maxMigrationSnapshots {
		oldest := migrationSnapshots.order[0]
		migrationSnapshots.order = migrationSnapshots.order[1:]
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+migrationSnapshots.names[oldest]+" WITH (FORCE)")
		delete(migrationSnapshots.names, oldest)
	}
	return name, nil
}

func touchMigrationSnapshot(version int64) {
	order := migrationSnapshots.order[:0]
	for _, item := range migrationSnapshots.order {
		if item != version {
			order = append(order, item)
		}
	}
	migrationSnapshots.order = append(order, version)
}

func snapshotDatabasePool(ctx context.Context, base, database string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(base)
	if err != nil {
		return nil, err
	}
	config.ConnConfig.Database = database
	config.ConnConfig.RuntimeParams["search_path"] = snapshotSchema
	return pgxpool.NewWithConfig(ctx, config)
}

func dropMigrationSnapshots() {
	base := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	migrationSnapshots.Lock()
	defer migrationSnapshots.Unlock()
	if base == "" || len(migrationSnapshots.names) == 0 {
		return
	}
	ctx, cancel := databasetest.CleanupContext()
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drop migration snapshots: %v\n", err)
		return
	}
	defer admin.Close(ctx)
	for _, name := range migrationSnapshots.names {
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			fmt.Fprintf(os.Stderr, "drop migration snapshot %s: %v\n", name, err)
		}
	}
}
