//go:build integration

package httppolicycontrol

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// fix-mktsiteconf3 ③: the system site write creates, updates, leaves alone,
// re-creates a disabled policy enabled and deletes the site's HTTP policy,
// each revision with its system-actor audit event the trigger requires.
func TestSetSiteSystemKeepsTheSitePolicyEqual(t *testing.T) {
	fixture := newIntegrationFixture(t, allowTestGate())
	ctx := context.Background()
	store := fixture.service.store
	write := func(config *Config, request string) bool {
		t.Helper()
		changed, err := store.SetSiteSystem(ctx, SystemSiteWrite{ScopeID: fixture.tenantA, SiteID: fixture.siteA,
			OwnerUserID: fixture.ownerA.UserID, Config: config, RequestID: request, ActorRef: "job:market_leaf_sync"})
		if err != nil {
			t.Fatalf("%s: %v", request, err)
		}
		return changed
	}
	live := func() (int, bool) {
		t.Helper()
		var count int
		var enabled bool
		if err := fixture.pool.QueryRow(ctx, `SELECT count(*), coalesce(bool_and(current_enabled), false) FROM http_policies
			WHERE tenant_scope_id=$1 AND site_id=$2 AND deleted_at IS NULL`, fixture.tenantA, fixture.siteA).Scan(&count, &enabled); err != nil {
			t.Fatal(err)
		}
		return count, enabled
	}
	config := validTestConfig()
	if !write(&config, "sys-create") || write(&config, "sys-same") {
		t.Fatal("create / unchanged write")
	}
	config.MaxUploadBytes = 32
	if !write(&config, "sys-update") {
		t.Fatal("update not written")
	}
	var policyID string
	if err := fixture.pool.QueryRow(ctx, `SELECT id::text FROM http_policies WHERE site_id=$1 AND deleted_at IS NULL`,
		fixture.siteA).Scan(&policyID); err != nil {
		t.Fatal(err)
	}
	var systemEvents int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND resource_id=$2
		AND actor_kind='system' AND actor_ref='job:market_leaf_sync' AND action IN ('http_policy.create','http_policy.update')`,
		fixture.tenantA, policyID).Scan(&systemEvents); err != nil || systemEvents != 2 {
		t.Fatalf("system audit events=%d err=%v", systemEvents, err)
	}
	policy, err := fixture.service.Get(ctx, fixture.ownerA, fixture.tenantA, uuid.MustParse(policyID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.SetEnabled(ctx, fixture.ownerA, StateRequest{TargetScopeID: fixture.tenantA, ID: policy.ID,
		ExpectedRevision: policy.Revision, Enabled: false, WriteMetadata: testMetadata("owner-disable")}); err != nil {
		t.Fatal(err)
	}
	if !write(&config, "sys-reenable") {
		t.Fatal("disabled policy not re-created")
	}
	if count, enabled := live(); count != 1 || !enabled {
		t.Fatalf("after re-create live=%d enabled=%v", count, enabled)
	}
	if !write(nil, "sys-delete") || write(nil, "sys-delete-again") {
		t.Fatal("delete / repeated delete")
	}
	if count, _ := live(); count != 0 {
		t.Fatalf("policy left after delete: %d", count)
	}
}
