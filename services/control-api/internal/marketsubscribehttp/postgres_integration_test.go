//go:build integration

package marketsubscribehttp

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buyerTestPool needs a database migrated through 296
// (MARKET_BUYER_TEST_DATABASE_URL); each test adds its own rows only.
func buyerTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("MARKET_BUYER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("MARKET_BUYER_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var ok bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('plugin_security_advisory_acks') IS NOT NULL`).Scan(&ok); err != nil || !ok {
		t.Skip("database is not migrated through 296")
	}
	return pool
}

func platformScope(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var scope uuid.UUID
	err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&scope)
	if errors.Is(err, pgx.ErrNoRows) {
		scope = uuid.New()
		_, err = pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope)
	}
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func tenantScope(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	tenant, scope := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'buyer tenant')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant); err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestPostgresAdvisoriesAcknowledgedPerScope(t *testing.T) {
	pool := buyerTestPool(t)
	store := NewPostgresStore(pool)
	ctx := t.Context()
	platform, tenant := platformScope(t, pool), tenantScope(t, pool)
	// Other tests' advisories in the shared database are withdrawn by the
	// replace below; scope every assertion to this test's plugin.
	plugin := "m7.p" + uuid.NewString()[:8]
	published := Advisory{ID: uuid.New(), PluginID: plugin, AffectedVersions: "<1.4.2", FixedVersion: "1.4.2", Severity: "high",
		Action: "disable", Title: "远程代码执行", Body: "升级到 1.4.2", PublishedAt: time.Now().UTC().Truncate(time.Second)}
	later := published
	later.ID, later.Title = uuid.New(), "第二条"
	if err := store.ReplaceDelivered(ctx, []Advisory{published, later}); err != nil {
		t.Fatal(err)
	}
	bad := published
	bad.ID, bad.Severity = uuid.New(), "urgent"
	if err := store.ReplaceDelivered(ctx, []Advisory{bad}); !errors.Is(err, ErrStoreInvalid) {
		t.Fatalf("bad severity: %v", err)
	}
	items, err := store.Advisories(ctx, platform, plugin)
	if err != nil || len(items) != 2 || items[0].Acknowledgement != nil {
		t.Fatalf("list: %+v %v", items, err)
	}

	admin, operator := uuid.New(), uuid.New()
	first, err := store.Acknowledge(ctx, platform, published.ID, admin, "disabled", "先停用")
	if err != nil || first.Disposition != "disabled" || first.AcknowledgedBy != admin {
		t.Fatalf("ack: %+v %v", first, err)
	}
	// A repeat (another admin, another choice) keeps the first acknowledgement.
	again, err := store.Acknowledge(ctx, platform, published.ID, operator, "accepted_risk", "")
	if err != nil || again != first {
		t.Fatalf("repeat: %+v %v", again, err)
	}
	// The tenant acknowledges on its own and is never reported upstream.
	items, _ = store.Advisories(ctx, tenant, plugin)
	if len(items) != 2 || items[0].Acknowledgement != nil || items[1].Acknowledgement != nil {
		t.Fatalf("tenant sees platform ack: %+v", items)
	}
	if _, err := store.Acknowledge(ctx, tenant, later.ID, uuid.New(), "upgraded", ""); err != nil {
		t.Fatal(err)
	}
	pending, err := store.UnreportedPlatformAcks(ctx)
	if err != nil || !contains(pending, published.ID) || contains(pending, later.ID) {
		t.Fatalf("pending platform acks: %v %v", pending, err)
	}
	if err := store.MarkReported(ctx, published.ID); err != nil {
		t.Fatal(err)
	}
	if pending, _ = store.UnreportedPlatformAcks(ctx); contains(pending, published.ID) {
		t.Fatalf("reported ack still pending: %v", pending)
	}
	if err := store.MarkReported(ctx, published.ID); err != nil {
		t.Fatalf("second MarkReported must be a no-op: %v", err)
	}

	// The license service stops delivering "later": it is withdrawn, hidden,
	// cannot be acknowledged again, and the tenant's acknowledgement survives.
	if err := store.ReplaceDelivered(ctx, []Advisory{published}); err != nil {
		t.Fatal(err)
	}
	items, _ = store.Advisories(ctx, platform, plugin)
	if len(items) != 1 || items[0].ID != published.ID || items[0].Acknowledgement == nil {
		t.Fatalf("after withdrawal: %+v", items)
	}
	if _, err := store.Acknowledge(ctx, platform, later.ID, admin, "disabled", ""); !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("ack withdrawn: %v", err)
	}
	var tenantAcks int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM plugin_security_advisory_acks WHERE advisory_id=$1`, later.ID).Scan(&tenantAcks); err != nil ||
		tenantAcks != 1 {
		t.Fatalf("tenant ack after withdrawal: %d %v", tenantAcks, err)
	}
	// Redelivery republishes it.
	if err := store.ReplaceDelivered(ctx, []Advisory{published, later}); err != nil {
		t.Fatal(err)
	}
	if items, _ = store.Advisories(ctx, tenant, plugin); len(items) != 2 {
		t.Fatalf("redelivered: %+v", items)
	}

	// Concurrent first acknowledgements of one scope settle on one row.
	other := tenantScope(t, pool)
	var wg sync.WaitGroup
	results := make([]Acknowledgement, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = store.Acknowledge(ctx, other, published.ID, uuid.New(), "not_affected", "")
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		if r != results[0] || r.Disposition != "not_affected" {
			t.Fatalf("concurrent acks diverged: %+v", results)
		}
	}
}

func contains(ids []uuid.UUID, id uuid.UUID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func TestPostgresPluginLibrary(t *testing.T) {
	pool := buyerTestPool(t)
	var ok bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('plugin_providers') IS NOT NULL`).Scan(&ok); err != nil || !ok {
		t.Skip("database is not migrated through 397")
	}
	plugin := "pa27.lib" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	now := time.Now().UTC()
	if _, err := pool.Exec(t.Context(), `INSERT INTO market_data_pack_sources (artifact_id, kind, plugin_id, version, revision, sha256,
		local_name, status, materialized_at, updated_at) VALUES ('market_theme/'||$1,'market_theme',$1,'1.0.0',1,$2,'market.'||$1,'withdrawn',$3,$3)`,
		plugin, strings.Repeat("a", 64), now); err != nil {
		t.Fatal(err)
	}
	items, err := NewPostgresStore(pool).Library(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.PluginID == plugin {
			if item.Installed || item.Enabled || !item.Withdrawn {
				t.Fatalf("library item=%+v", item)
			}
			return
		}
	}
	t.Fatalf("plugin %s missing from %+v", plugin, items)
}
