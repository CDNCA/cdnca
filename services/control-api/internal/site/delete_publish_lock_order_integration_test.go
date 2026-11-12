package site

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// sitedel-500: DELETE /v1/sites/{id} returned 500 "deadlock detected (40P01)"
// while an edge publication of the same scope was running. The publication
// holds the scope's edge_configuration_scopes row and then inserts
// site_ipv6_rollout_targets, whose foreign key takes FOR KEY SHARE on the site
// row. The delete used to take the site row FOR UPDATE first and only then
// reach the scope row (through the sites trigger), the reverse order.
// The delete must take the scope row first, like every other site write.
func TestSiteDeleteDoesNotDeadlockWithPublicationLockOrder(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	dsn = databasetest.FreshDatabaseURL(t, dsn, "site_delete_lock_order")
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "site_delete_lock_order_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, "lock-order-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin",
		"sites.manage")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Lock order tenant", "lock-order-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage")
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	platform := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform", SessionID: manager.SessionID}
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	created, err := service.Create(t.Context(), platform, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		Fields: SiteFields{Domains: []string{"lock-order.example.com"}, HTTPPorts: []string{"80"},
			Origins: []string{"192.0.2.9:8080"}, Enabled: false, Status: StatusDisabled},
		IdempotencyKey: "lock-order-create", RequestID: "lock-order-create"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// The publication: scope row first, then the foreign key's KEY SHARE on the site.
	publish, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer publish.Rollback(context.Background())
	var publishPID int
	if err := publish.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&publishPID); err != nil {
		t.Fatal(err)
	}
	if err := lockEdgeConfigurationScope(t.Context(), publish, tenant.scopeID); err != nil {
		t.Fatal(err)
	}

	deleted := make(chan error, 1)
	go func() {
		_, err := service.Delete(context.Background(), owner, DeleteRequest{ID: created.Site.ID,
			ExpectedRevision: created.Site.Revision, IdempotencyKey: "lock-order-delete", RequestID: "lock-order-delete"})
		deleted <- err
	}()
	// Wait until the delete is blocked on a lock (the scope row held above).
	waiting := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline) && !waiting; time.Sleep(50 * time.Millisecond) {
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND wait_event_type='Lock' AND pid<>$1)`, publishPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	if !waiting {
		t.Fatal("delete never blocked behind the publication's scope lock")
	}
	// Pre-fix the delete holds the site row FOR UPDATE here, so this waits for the delete,
	// which waits for us: PostgreSQL aborts one of them with 40P01.
	if _, err := publish.Exec(t.Context(), `SELECT 1 FROM sites WHERE id=$1 FOR KEY SHARE`, created.Site.ID); err != nil {
		t.Fatalf("publication foreign key lock on the site: %v", err)
	}
	if err := publish.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("delete did not finish after the publication committed")
	}
	var deletedAt *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT deleted_at FROM sites WHERE id=$1`, created.Site.ID).Scan(&deletedAt); err != nil || deletedAt == nil {
		t.Fatalf("site deleted_at = %v (%v)", deletedAt, err)
	}
}
