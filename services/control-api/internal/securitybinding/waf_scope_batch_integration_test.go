//go:build integration

package securitybinding

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// SEC-ACCOUNT-04（待出包前全量跑，需 PG）: WAF libraries filter by scope on
// the server (global = own and unbound, site = own and bound to a site,
// system = platform library copy); batch enable/disable/delete is per item
// CAS with per item results, and system libraries are refused.
func TestWAFLibraryScopeFilterAndBatch(t *testing.T) {
	fixture := newBindingFixture(t)
	pool, tenant := fixture.pool, fixture.tenantB
	ctx := context.Background()
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, func() time.Time { return bindingTestNow }))
	actor := tenantActor(tenant)

	// tenant.policyID (WAF) is bound to tenant.siteID; global is unbound.
	if _, err := pool.Exec(ctx, `INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,
		created_at,updated_at) VALUES($1,$2,$3,$4,'waf',now(),now())`, uuid.New(), tenant.scopeID, tenant.siteID, tenant.policyID); err != nil {
		t.Fatal(err)
	}
	global := insertPolicy(t, pool, tenant, securitypolicy.KindWAF, "waf-global", 1)
	copied, err := service.UpsertLicensedWAF(ctx, actor, securitypolicy.LicensedWAFDefinition{
		LibraryID: uuid.NewString(), Revision: 1, Name: "平台库", Description: "platform", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{{
			Name: "block admin", Priority: 10, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}},
		}},
	}, "scope-batch-subscribe", "scope-batch-subscribe")
	if err != nil {
		t.Fatal(err)
	}
	ids := func(scope string) []uuid.UUID {
		t.Helper()
		page, err := service.List(ctx, actor, securitypolicy.ListFilter{Page: 1, Limit: 10, Kind: securitypolicy.KindWAF, Scope: scope})
		if err != nil {
			t.Fatalf("List(%s): %v", scope, err)
		}
		out := []uuid.UUID{}
		for _, item := range page.Items {
			out = append(out, item.ID)
		}
		if page.Total != int64(len(out)) {
			t.Fatalf("scope %s total %d items %d", scope, page.Total, len(out))
		}
		return out
	}
	for scope, want := range map[string]uuid.UUID{
		securitypolicy.ScopeSite: tenant.policyID, securitypolicy.ScopeGlobal: global, securitypolicy.ScopeSystem: copied.ID,
	} {
		if got := ids(scope); len(got) != 1 || got[0] != want {
			t.Fatalf("scope %s = %v want %v", scope, got, want)
		}
	}

	batch := func(key, action string, items ...securitypolicy.BatchItem) []securitypolicy.BatchItemResult {
		t.Helper()
		results, err := service.Batch(ctx, actor, securitypolicy.BatchRequest{
			Action: action, Items: items, IdempotencyKey: key, RequestID: key,
		})
		if err != nil || len(results) != len(items) {
			t.Fatalf("Batch(%s) = %+v, %v", action, results, err)
		}
		return results
	}
	disable := []securitypolicy.BatchItem{{ID: global, Version: 1}, {ID: copied.ID, Version: copied.Revision},
		{ID: tenant.policyID, Version: 99}}
	first := batch("scope-batch-disable", securitypolicy.BatchDisable, disable...)
	if first[0].Status != "ok" || first[0].Version != 2 || first[1].Status != "system_protected" ||
		first[2].Status != "version_conflict" {
		t.Fatalf("disable = %+v", first)
	}
	replay := batch("scope-batch-disable", securitypolicy.BatchDisable, disable...)
	if replay[0].Status != "ok" || !replay[0].Replayed || replay[0].Version != 2 {
		t.Fatalf("replay = %+v", replay)
	}
	if again := batch("scope-batch-disable-2", securitypolicy.BatchDisable, securitypolicy.BatchItem{ID: global, Version: 2}); again[0].Status != "unchanged" {
		t.Fatalf("already disabled = %+v", again)
	}
	// Another tenant cannot reach these libraries.
	other, err := service.Batch(ctx, tenantActor(fixture.tenantA), securitypolicy.BatchRequest{
		Action: securitypolicy.BatchDelete, Items: []securitypolicy.BatchItem{{ID: global, Version: 2}},
		IdempotencyKey: "scope-batch-other", RequestID: "scope-batch-other",
	})
	if err != nil || other[0].Status != "not_found" {
		t.Fatalf("other tenant = %+v, %v", other, err)
	}
	deleted := batch("scope-batch-delete", securitypolicy.BatchDelete,
		securitypolicy.BatchItem{ID: global, Version: 2}, securitypolicy.BatchItem{ID: copied.ID, Version: copied.Revision})
	if deleted[0].Status != "ok" || deleted[1].Status != "system_protected" {
		t.Fatalf("delete = %+v", deleted)
	}
	if replayed := batch("scope-batch-delete", securitypolicy.BatchDelete,
		securitypolicy.BatchItem{ID: global, Version: 2}, securitypolicy.BatchItem{ID: copied.ID, Version: copied.Revision}); replayed[0].Status != "ok" || !replayed[0].Replayed {
		t.Fatalf("delete replay = %+v", replayed)
	}
	if got := ids(securitypolicy.ScopeGlobal); len(got) != 0 {
		t.Fatalf("global after delete = %v", got)
	}
}
