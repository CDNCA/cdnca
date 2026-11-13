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

// sitedel-500 同类：锁定/解锁站点与条件回源保存也要先锁 scope 行再锁站点行，
// 与边缘发布（先 scope 行，再经外键对站点行 FOR KEY SHARE）同序，否则会 40P01 死锁。
type siteWriteLockOrderFixture struct {
	pool     *pgxpool.Pool
	service  *Service
	platform Actor
	owner    Actor
	scopeID  uuid.UUID
	site     Site
}

func newSiteWriteLockOrderFixture(t *testing.T, prefix string) *siteWriteLockOrderFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	dsn = databasetest.FreshDatabaseURL(t, dsn, prefix)
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := prefix + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	label := strings.ReplaceAll(prefix, "_", "-")
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, label+"-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin", "sites.manage")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, label+" tenant", label+"-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage")
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	platform := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform", SessionID: manager.SessionID}
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	created, err := service.Create(t.Context(), platform, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		Fields: SiteFields{Domains: []string{label + ".example.com"}, HTTPPorts: []string{"80"},
			Origins: []string{"192.0.2.9:8080"}, Enabled: false, Status: StatusDisabled},
		IdempotencyKey: prefix + "-create", RequestID: prefix + "-create"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return &siteWriteLockOrderFixture{pool: pool, service: service, platform: platform, owner: owner, scopeID: tenant.scopeID, site: created.Site}
}

// run holds the scope row like a publication, starts op, waits until op blocks, then takes the
// publication's foreign-key KEY SHARE on the site: pre-fix op already holds the site row FOR UPDATE and
// the two deadlock (40P01); fixed, op waits on the scope row only and finishes after the commit.
func (f *siteWriteLockOrderFixture) run(t *testing.T, op func(context.Context) error) {
	t.Helper()
	publish, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer publish.Rollback(context.Background())
	var publishPID int
	if err := publish.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&publishPID); err != nil {
		t.Fatal(err)
	}
	if err := lockEdgeConfigurationScope(t.Context(), publish, f.scopeID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- op(context.Background()) }()
	waiting := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline) && !waiting; time.Sleep(50 * time.Millisecond) {
		if err := f.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND wait_event_type='Lock' AND pid<>$1)`, publishPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	if !waiting {
		t.Fatal("the write never blocked behind the publication's scope lock")
	}
	if _, err := publish.Exec(t.Context(), `SELECT 1 FROM sites WHERE id=$1 FOR KEY SHARE`, f.site.ID); err != nil {
		t.Fatalf("publication foreign key lock on the site: %v", err)
	}
	if err := publish.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the write did not finish after the publication committed")
	}
}

func TestSiteLockDoesNotDeadlockWithPublicationLockOrder(t *testing.T) {
	f := newSiteWriteLockOrderFixture(t, "site_lock_order")
	f.run(t, func(ctx context.Context) error {
		_, err := f.service.Lock(ctx, f.platform, LockRequest{ID: f.site.ID, ExpectedRevision: f.site.Revision,
			Reason: "lock order", IdempotencyKey: "lock-order-lock", RequestID: "lock-order-lock"})
		return err
	})
	var lockedAt *time.Time
	if err := f.pool.QueryRow(t.Context(), `SELECT locked_at FROM sites WHERE id=$1`, f.site.ID).Scan(&lockedAt); err != nil || lockedAt == nil {
		t.Fatalf("site locked_at = %v (%v)", lockedAt, err)
	}
}

func TestSiteConditionalOriginSaveDoesNotDeadlockWithPublicationLockOrder(t *testing.T) {
	f := newSiteWriteLockOrderFixture(t, "site_cond_order")
	f.run(t, func(ctx context.Context) error {
		_, err := f.service.UpdateConditionalOrigin(ctx, f.owner, UpdateConditionalOriginRequest{ID: f.site.ID,
			ExpectedRevision: f.site.Revision, Document: validConditionalOriginDocument(),
			IdempotencyKey: "cond-order-save", RequestID: "cond-order-save"})
		return err
	})
	var revision int64
	if err := f.pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, f.site.ID).Scan(&revision); err != nil || revision <= f.site.Revision {
		t.Fatalf("site revision after the save = %d (%v), was %d", revision, err, f.site.Revision)
	}
}
