//go:build integration

package apikeyusage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresRuntimeMergeBoundaryAndFieldIsolation(t *testing.T) {
	fixture := newUsageIntegrationFixture(t)
	keyID := fixture.insertKey(t, nil)
	before := fixture.nonUsageDigest(t, keyID)
	runtime := fixture.runtime(t)

	first := fixture.createdAt.Add(10 * time.Minute)
	if !runtime.TryRecord(keyID, first) {
		t.Fatal("first usage rejected")
	}
	fixture.waitLastUsed(t, keyID, first)
	for index, observedAt := range []time.Time{
		first, first.Add(-time.Minute), first.Add(5*time.Minute - time.Microsecond),
	} {
		if !runtime.TryRecord(keyID, observedAt) {
			t.Fatal("duplicate, out-of-order, or in-window usage rejected")
		}
		wantFiltered := uint64(index + 1)
		waitFor(t, 2*time.Second, func() bool { return runtime.Counters().Filtered >= wantFiltered })
	}
	fixture.assertLastUsed(t, keyID, first)

	boundary := first.Add(5 * time.Minute)
	if !runtime.TryRecord(keyID, boundary) {
		t.Fatal("boundary usage rejected")
	}
	fixture.waitLastUsed(t, keyID, boundary)
	crossWindow := boundary.Add(6 * time.Minute)
	if !runtime.TryRecord(keyID, crossWindow) {
		t.Fatal("cross-window usage rejected")
	}
	fixture.waitLastUsed(t, keyID, crossWindow)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if before != fixture.nonUsageDigest(t, keyID) {
		t.Fatal("usage worker changed an API key field other than last_used_at")
	}
	snapshot := runtime.Counters()
	if snapshot.Updated != 3 || snapshot.Filtered != 3 || snapshot.DBFailures != 0 {
		t.Fatalf("counters = %#v", snapshot)
	}
}

func TestPostgresRuntimeLockFailureRecoveryAndRevocationRace(t *testing.T) {
	fixture := newUsageIntegrationFixture(t)

	t.Run("database pool outage recovers", func(t *testing.T) {
		keyID := fixture.insertKey(t, nil)
		before := fixture.nonUsageDigest(t, keyID)
		connections := make([]*pgxpool.Conn, 0, fixture.pool.Config().MaxConns)
		for range fixture.pool.Config().MaxConns {
			connection, err := fixture.pool.Acquire(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			connections = append(connections, connection)
		}
		runtime := fixture.runtime(t)
		observedAt := fixture.createdAt.Add(15 * time.Minute)
		if !runtime.TryRecord(keyID, observedAt) {
			t.Fatal("usage rejected during database outage")
		}
		waitFor(t, 2*time.Second, func() bool { return runtime.Counters().DBFailures > 0 })
		for _, connection := range connections {
			connection.Release()
		}
		fixture.waitLastUsed(t, keyID, observedAt)
		if before != fixture.nonUsageDigest(t, keyID) {
			t.Fatal("failed and recovered transaction changed non-usage fields")
		}
		if err := runtime.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("authorization-held row lock is invisible until release", func(t *testing.T) {
		keyID := fixture.insertKey(t, nil)
		before := fixture.nonUsageDigest(t, keyID)
		lock := fixture.lockKey(t, keyID)
		runtime := fixture.runtime(t)
		observedAt := fixture.createdAt.Add(20 * time.Minute)
		if !runtime.TryRecord(keyID, observedAt) {
			t.Fatal("usage rejected while row was locked")
		}
		waitFor(t, 2*time.Second, func() bool { return runtime.Counters().DBFailures > 0 })
		if !errorsAreStable(runtime) {
			t.Fatalf("failure=%v ready=%v", runtime.Failure(), runtime.Ready())
		}
		fixture.assertLastUsedNull(t, keyID)
		if before != fixture.nonUsageDigest(t, keyID) {
			t.Fatal("timed-out usage transaction changed non-usage fields")
		}
		if err := lock.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		fixture.waitLastUsed(t, keyID, observedAt)
		waitFor(t, 2*time.Second, func() bool { return runtime.Failure() == nil })
		if before != fixture.nonUsageDigest(t, keyID) {
			t.Fatal("recovered usage transaction changed non-usage fields")
		}
		if err := runtime.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("revocation wins after worker lock timeout", func(t *testing.T) {
		keyID := fixture.insertKey(t, nil)
		before := fixture.nonUsageDigest(t, keyID)
		lock := fixture.lockKey(t, keyID)
		runtime := fixture.runtime(t)
		if !runtime.TryRecord(keyID, fixture.createdAt.Add(30*time.Minute)) {
			t.Fatal("usage rejected")
		}
		waitFor(t, 2*time.Second, func() bool { return runtime.Counters().DBFailures > 0 })
		if _, err := lock.Exec(context.Background(), `
			UPDATE api_keys
			SET status='revoked', revoked_at=transaction_timestamp(), revoked_by_user_id=user_id,
			    revision=revision+1, updated_at=transaction_timestamp()
			WHERE id=$1`, keyID); err != nil {
			t.Fatal(err)
		}
		if err := lock.Commit(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 2*time.Second, func() bool { return runtime.Counters().Filtered > 0 })
		fixture.assertLastUsedNull(t, keyID)
		if before == fixture.nonUsageDigest(t, keyID) {
			t.Fatal("revocation control mutation was not observed")
		}
		var status string
		var revision int64
		if err := fixture.pool.QueryRow(t.Context(), `SELECT status,revision FROM api_keys WHERE id=$1`, keyID).
			Scan(&status, &revision); err != nil {
			t.Fatal(err)
		}
		if status != "revoked" || revision != 2 {
			t.Fatalf("status/revision = %s/%d", status, revision)
		}
		if err := runtime.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPostgresRuntimeExpirationConcurrencyAndRestart(t *testing.T) {
	fixture := newUsageIntegrationFixture(t)

	t.Run("expired while blocked is filtered", func(t *testing.T) {
		expiresAt := time.Now().UTC().Add(250 * time.Millisecond)
		keyID := fixture.insertKey(t, &expiresAt)
		lock := fixture.lockKey(t, keyID)
		runtime := fixture.runtime(t)
		if !runtime.TryRecord(keyID, time.Now().UTC().Add(-time.Millisecond)) {
			t.Fatal("usage rejected")
		}
		waitFor(t, 2*time.Second, func() bool { return runtime.Counters().DBFailures > 0 })
		time.Sleep(time.Until(expiresAt) + 20*time.Millisecond)
		if err := lock.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 2*time.Second, func() bool { return runtime.Counters().Filtered > 0 })
		fixture.assertLastUsedNull(t, keyID)
		if err := runtime.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("concurrent runtimes and restart remain monotonic", func(t *testing.T) {
		keyID := fixture.insertKey(t, nil)
		earlier := fixture.createdAt.Add(10 * time.Minute)
		later := fixture.createdAt.Add(25 * time.Minute)
		first, second := fixture.runtime(t), fixture.runtime(t)
		var group sync.WaitGroup
		group.Add(2)
		go func() { defer group.Done(); first.TryRecord(keyID, later) }()
		go func() { defer group.Done(); second.TryRecord(keyID, earlier) }()
		group.Wait()
		fixture.waitLastUsed(t, keyID, later)
		if err := first.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := second.Close(context.Background()); err != nil {
			t.Fatal(err)
		}

		restarted := fixture.runtime(t)
		if !restarted.TryRecord(keyID, earlier) || !restarted.TryRecord(keyID, later) {
			t.Fatal("restart rejected valid immutable observations")
		}
		waitFor(t, 2*time.Second, func() bool { return restarted.Counters().Filtered >= 1 })
		if err := restarted.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		fixture.assertLastUsed(t, keyID, later)
	})
}

func TestPostgresRuntimeMixedBatchFutureGuardAndUsageFirstRevocation(t *testing.T) {
	fixture := newUsageIntegrationFixture(t)

	t.Run("mixed batch isolates invalid identities", func(t *testing.T) {
		activeID := fixture.insertKey(t, nil)
		revokedID := fixture.insertKey(t, nil)
		if _, err := fixture.pool.Exec(t.Context(), `
			UPDATE api_keys
			SET status='revoked', revoked_at=transaction_timestamp(), revoked_by_user_id=user_id,
			    revision=revision+1, updated_at=transaction_timestamp()
			WHERE id=$1`, revokedID); err != nil {
			t.Fatal(err)
		}
		observedAt := fixture.createdAt.Add(35 * time.Minute)
		store := newPostgresStore(fixture.pool, time.Second)
		updated, filtered, err := store.update(t.Context(), map[uuid.UUID]time.Time{
			activeID: observedAt, revokedID: observedAt, uuid.New(): observedAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		if updated != 1 || filtered != 2 {
			t.Fatalf("mixed batch result = updated:%d filtered:%d, want 1/2", updated, filtered)
		}
		fixture.assertLastUsed(t, activeID, observedAt)
		fixture.assertLastUsedNull(t, revokedID)
	})

	t.Run("future observation is filtered before trigger", func(t *testing.T) {
		keyID := fixture.insertKey(t, nil)
		store := newPostgresStore(fixture.pool, time.Second)
		updated, filtered, err := store.update(t.Context(), map[uuid.UUID]time.Time{
			keyID: time.Now().UTC().Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		if updated != 0 || filtered != 1 {
			t.Fatalf("future batch result = updated:%d filtered:%d, want 0/1", updated, filtered)
		}
		fixture.assertLastUsedNull(t, keyID)
	})

	t.Run("usage first preserves history and does not block revocation", func(t *testing.T) {
		keyID := fixture.insertKey(t, nil)
		observedAt := fixture.createdAt.Add(40 * time.Minute)
		store := newPostgresStore(fixture.pool, time.Second)
		updated, filtered, err := store.update(t.Context(), map[uuid.UUID]time.Time{keyID: observedAt})
		if err != nil || updated != 1 || filtered != 0 {
			t.Fatalf("usage-first result = updated:%d filtered:%d err:%v", updated, filtered, err)
		}
		if _, err := fixture.pool.Exec(t.Context(), `
			UPDATE api_keys
			SET status='revoked', revoked_at=transaction_timestamp(), revoked_by_user_id=user_id,
			    revision=revision+1, updated_at=transaction_timestamp()
			WHERE id=$1`, keyID); err != nil {
			t.Fatal(err)
		}
		var status string
		var revision int64
		var lastUsed time.Time
		if err := fixture.pool.QueryRow(t.Context(), `
			SELECT status,revision,last_used_at FROM api_keys WHERE id=$1`, keyID).
			Scan(&status, &revision, &lastUsed); err != nil {
			t.Fatal(err)
		}
		if status != "revoked" || revision != 2 || !lastUsed.Equal(observedAt) {
			t.Fatalf("usage-first revoke facts = status:%s revision:%d last_used:%s",
				status, revision, lastUsed)
		}
	})
}

func errorsAreStable(runtime *Runtime) bool {
	return runtime.Failure() == ErrDatabaseUnavailable && runtime.Ready() == ErrDatabaseUnavailable
}

type usageIntegrationFixture struct {
	pool      *pgxpool.Pool
	tenantID  uuid.UUID
	scopeID   uuid.UUID
	userID    uuid.UUID
	createdAt time.Time
}

func newUsageIntegrationFixture(t *testing.T) *usageIntegrationFixture {
	t.Helper()
	pool := isolatedUsagePool(t)
	fixture := &usageIntegrationFixture{
		pool: pool, tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(),
		createdAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond),
	}
	if _, err := pool.Exec(t.Context(), `
		WITH new_tenant AS (
			INSERT INTO tenants(id,display_name,created_at,updated_at) VALUES($1,'usage tenant',$4,$4)
		), new_scope AS (
			INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($2,'tenant',$1,$4)
		), new_user AS (
			INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
			VALUES($3,$5,'Usage User','test-hash',$4,$4)
		)
		INSERT INTO memberships(scope_id,user_id,created_at) VALUES($2,$3,$4)`,
		fixture.tenantID, fixture.scopeID, fixture.userID, fixture.createdAt,
		"usage-"+strings.ReplaceAll(uuid.NewString(), "-", "")[:12]); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *usageIntegrationFixture) runtime(t *testing.T) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(f.pool, Config{
		QueueCapacity: 16, BatchSize: 8, FlushInterval: 5 * time.Millisecond,
		RetryInterval:    5 * time.Millisecond,
		OperationTimeout: 25 * time.Millisecond, ShutdownTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func (f *usageIntegrationFixture) insertKey(t *testing.T, expiresAt *time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	keyID := "cfk_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:22]
	if _, err := f.pool.Exec(t.Context(), `
		INSERT INTO api_keys(
			id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,secret_digest,status,
			expires_at,activated_at,created_by_user_id,created_at,updated_at
		) VALUES($1,$2,$2||'.',$3,$4,$5,'usage key',ARRAY['sites.read'],
			decode(repeat('42',32),'hex'),'active',$6,$7,$5,$7,$7)`,
		id, keyID, f.scopeID, f.tenantID, f.userID, expiresAt, f.createdAt); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *usageIntegrationFixture) lockKey(t *testing.T, id uuid.UUID) pgx.Tx {
	t.Helper()
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SELECT id FROM api_keys WHERE id=$1 FOR UPDATE`, id); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	return tx
}

func (f *usageIntegrationFixture) nonUsageDigest(t *testing.T, id uuid.UUID) [sha256.Size]byte {
	t.Helper()
	var value string
	if err := f.pool.QueryRow(t.Context(), `
		SELECT (to_jsonb(api_keys)-'last_used_at')::text FROM api_keys WHERE id=$1`, id).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256([]byte(value))
}

func (f *usageIntegrationFixture) waitLastUsed(t *testing.T, id uuid.UUID, expected time.Time) {
	t.Helper()
	waitFor(t, 2*time.Second, func() bool {
		var actual *time.Time
		if err := f.pool.QueryRow(t.Context(), `SELECT last_used_at FROM api_keys WHERE id=$1`, id).Scan(&actual); err != nil {
			return false
		}
		return actual != nil && actual.Equal(expected)
	})
}

func (f *usageIntegrationFixture) assertLastUsed(t *testing.T, id uuid.UUID, expected time.Time) {
	t.Helper()
	var actual *time.Time
	if err := f.pool.QueryRow(t.Context(), `SELECT last_used_at FROM api_keys WHERE id=$1`, id).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual == nil || !actual.Equal(expected) {
		t.Fatalf("last_used_at = %v, want %v", actual, expected)
	}
}

func (f *usageIntegrationFixture) assertLastUsedNull(t *testing.T, id uuid.UUID) {
	t.Helper()
	var used bool
	if err := f.pool.QueryRow(t.Context(), `SELECT last_used_at IS NOT NULL FROM api_keys WHERE id=$1`, id).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used {
		t.Fatal("last_used_at unexpectedly advanced")
	}
}

func isolatedUsagePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	var serverVersion, listenAddresses, maxConnectionsText, maxLocksText string
	var unixSocket bool
	if err := admin.QueryRow(ctx, `
		SELECT current_setting('server_version'), current_setting('listen_addresses'),
		       current_setting('max_connections'), current_setting('max_locks_per_transaction'),
		       inet_server_addr() IS NULL`).Scan(
		&serverVersion, &listenAddresses, &maxConnectionsText, &maxLocksText, &unixSocket,
	); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	maxConnections, connectionsErr := strconv.Atoi(maxConnectionsText)
	maxLocks, locksErr := strconv.Atoi(maxLocksText)
	if !strings.HasPrefix(serverVersion, "17.") || listenAddresses != "" || !unixSocket ||
		connectionsErr != nil || maxConnections > 20 || locksErr != nil || maxLocks != 512 {
		admin.Close()
		t.Fatalf("unsafe PostgreSQL fixture: version=%q listen=%q unix=%v max_connections=%q max_locks=%q",
			serverVersion, listenAddresses, unixSocket, maxConnectionsText, maxLocksText)
	}
	schema := "apikey_usage_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^apikey_usage_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop API key usage schema: %v", err)
		}
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = min(config.MaxConns, 6)
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 25; version++ {
		matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(matches) != 1 {
			t.Fatalf("resolve migration %03d: matches=%v err=%v", version, matches, err)
		}
		script, err := fs.ReadFile(controlmigrations.FS, matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, string(script))
			return err
		}); err != nil {
			t.Fatalf("apply migration %03d: %v", version, err)
		}
	}
	return pool
}
