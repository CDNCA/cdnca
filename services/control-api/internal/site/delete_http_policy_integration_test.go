package site

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// deleting a site (single, by a tenant owner without
// http_policies.manage, and site.batch.delete) deletes its HTTP policy in the
// same tx, so no enabled policy is left on a deleted site (the orphan that
// failed every publication of the scope with "HTTP policy site is absent from
// the source revision").
func TestSiteDeleteDeletesItsHTTPPolicy(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	dsn = databasetest.FreshDatabaseURL(t, dsn, "site_delete_http_policy")
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "site_delete_http_policy_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "orphan-policy-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin",
		"sites.manage", "http_policies.manage")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Orphan policy tenant", "orphan-policy-owner")
	// The owner may delete sites but not manage HTTP policies.
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage")
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	platform := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform", SessionID: manager.SessionID}
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	policyConfig, err := httppolicycontrol.NewSitePolicyConfig(4<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	sites := make([]Site, 3)
	for index, domain := range []string{"single.orphan.example.com", "batch-a.orphan.example.com", "batch-b.orphan.example.com"} {
		created, err := service.Create(t.Context(), platform, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			Fields: SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.9:8080"},
				Enabled: false, Status: StatusDisabled},
			IdempotencyKey: "orphan-create-" + domain, RequestID: "orphan-create-" + domain})
		if err != nil {
			t.Fatalf("create %s: %v", domain, err)
		}
		sites[index] = created.Site
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := httppolicycontrol.CreateForNewSiteTx(t.Context(), tx, manager.ScopeID, manager.UserID, tenant.scopeID,
				tenantID, created.Site.ID, tenant.userID, policyConfig, now)
			return err
		}); err != nil {
			t.Fatalf("create HTTP policy %s: %v", domain, err)
		}
	}
	// orphans counts the live policies on deleted sites (the facts the edge
	// publication cannot place).
	orphans := func() int {
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM http_policies policy JOIN sites site ON site.id=policy.site_id
			WHERE policy.tenant_scope_id=$1 AND site.deleted_at IS NOT NULL
			  AND (NOT policy.current_deleted OR policy.deleted_at IS NULL)`, tenant.scopeID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	deletedRevision := func(siteID uuid.UUID) (string, bool, bool) {
		var action string
		var enabled, deleted bool
		if err := pool.QueryRow(t.Context(), `SELECT revision.action,revision.enabled,revision.deleted
			FROM http_policies policy JOIN http_policy_revisions revision
			  ON revision.policy_id=policy.id AND revision.revision=policy.current_revision
			WHERE policy.site_id=$1`, siteID).Scan(&action, &enabled, &deleted); err != nil {
			t.Fatal(err)
		}
		return action, enabled, deleted
	}

	if _, err := service.Delete(t.Context(), owner, DeleteRequest{ID: sites[0].ID, ExpectedRevision: sites[0].Revision,
		IdempotencyKey: "orphan-delete-single", RequestID: "orphan-delete-single"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if action, enabled, deleted := deletedRevision(sites[0].ID); action != "delete" || enabled || !deleted {
		t.Fatalf("single delete left the policy at %s enabled=%v deleted=%v", action, enabled, deleted)
	}
	if got := orphans(); got != 0 {
		t.Fatalf("single delete left %d orphan HTTP policies", got)
	}
	var audits int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='http_policy.delete'
		AND actor_user_id=$2 AND payload->>'site_request_id'='orphan-delete-single'`, tenant.scopeID, tenant.userID).
		Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("http_policy.delete audits = %d (%v)", audits, err)
	}

	result, err := service.BatchAction(t.Context(), platform, BatchActionRequest{Action: BatchActionDelete,
		Items:          []BatchActionItem{{ID: sites[1].ID, ExpectedRevision: sites[1].Revision}, {ID: sites[2].ID, ExpectedRevision: sites[2].Revision}},
		IdempotencyKey: "orphan-delete-batch", RequestID: "orphan-delete-batch"})
	if err != nil {
		t.Fatalf("batch delete: %v", err)
	}
	for _, item := range result.Items {
		if item.Status != "deleted" {
			t.Fatalf("batch item = %+v", item)
		}
	}
	for _, item := range sites[1:] {
		if action, enabled, deleted := deletedRevision(item.ID); action != "delete" || enabled || !deleted {
			t.Fatalf("batch delete left the policy at %s enabled=%v deleted=%v", action, enabled, deleted)
		}
	}
	if got := orphans(); got != 0 {
		t.Fatalf("batch delete left %d orphan HTTP policies", got)
	}
}
