package site

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-transfer: a platform administrator moves a site from user A (tenant A)
// to user B (tenant B). The old site is deleted, a new one with the same
// domains and origins is created in B's tenant with a new CNAME intent, the
// old CNAME is retired with a one-day grace, and site.transfer is audited.
func TestSiteTransferToAnotherTenantUser(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "site_transfer_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "transfer-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin", "sites.manage")
	from := addonSiteInsertSubscriptionTenant(t, pool, "Transfer from", "transfer-from")
	addonSiteAssignSubscriptionRole(t, pool, from.scopeID, from.userID, "site-owner", "sites.manage")
	to := addonSiteInsertSubscriptionTenant(t, pool, "Transfer to", "transfer-to")
	addonSiteAssignSubscriptionRole(t, pool, to.scopeID, to.userID, "site-owner", "sites.manage")
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	platform := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform", SessionID: manager.SessionID}

	created, err := service.Create(t.Context(), platform, CreateRequest{TargetScopeID: from.scopeID, OwnerUserID: from.userID,
		Fields: SiteFields{Domains: []string{"move.example.com", "www.move.example.com"}, HTTPPorts: []string{"80", "8080"},
			Origins: []string{"192.0.2.9:8080"}, Enabled: false, Status: StatusDisabled},
		IdempotencyKey: "transfer-create", RequestID: "transfer-create"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	old := created.Site

	if _, err := service.Transfer(t.Context(), platform, TransferRequest{ID: old.ID, ExpectedRevision: old.Revision,
		TargetUserID: from.userID, IdempotencyKey: "transfer-same", RequestID: "transfer-same"}); !errors.Is(err, ErrTransferTarget) {
		t.Fatalf("transfer to current owner: %v", err)
	}
	tenantActor := Actor{UserID: from.userID, ScopeID: from.scopeID, ScopeKind: "tenant"}
	if _, err := service.Transfer(t.Context(), tenantActor, TransferRequest{ID: old.ID, ExpectedRevision: old.Revision,
		TargetUserID: to.userID, IdempotencyKey: "transfer-tenant", RequestID: "transfer-tenant"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant transfer: %v", err)
	}

	request := TransferRequest{ID: old.ID, ExpectedRevision: old.Revision, TargetUserID: to.userID,
		IdempotencyKey: "transfer-1", RequestID: "transfer-1"}
	moved, err := service.Transfer(t.Context(), platform, request)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if moved.Site.ID == old.ID || moved.Site.ScopeID != to.scopeID || moved.Site.Owner == nil ||
		moved.FromSiteID != old.ID || moved.Site.CNAMETaskID == nil || moved.Site.PackageSubscriptionID != nil {
		t.Fatalf("moved site: %+v", moved)
	}
	if strings.Join(moved.Site.Domains, ",") != strings.Join(old.Domains, ",") ||
		strings.Join(moved.Site.HTTPPorts, ",") != "80,8080" || strings.Join(moved.Site.Origins, ",") != "192.0.2.9:8080" {
		t.Fatalf("settings not copied: domains=%v ports=%v origins=%v", moved.Site.Domains, moved.Site.HTTPPorts, moved.Site.Origins)
	}
	var deletedAt *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT deleted_at FROM sites WHERE id=$1`, old.ID).Scan(&deletedAt); err != nil || deletedAt == nil {
		t.Fatalf("old site not deleted: %v %v", deletedAt, err)
	}
	var audited int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='site.transfer'
		AND scope_id=$1 AND actor_user_id=$2 AND resource_id=$3`, to.scopeID, manager.UserID, moved.Site.ID.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("site.transfer audit = %d, %v", audited, err)
	}
	var retiredEarly int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM cname_record_retirements
		WHERE site_id=$1 AND eligible_at < $2`, old.ID, now.Add(cnameallocation.TransferGrace)).Scan(&retiredEarly); err != nil || retiredEarly != 0 {
		t.Fatalf("old CNAME retired without grace: %d %v", retiredEarly, err)
	}

	replayed, err := service.Transfer(t.Context(), platform, request)
	if err != nil || !replayed.Replayed || replayed.Site.ID != moved.Site.ID {
		t.Fatalf("replay: %+v %v", replayed, err)
	}
}
