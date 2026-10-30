//go:build integration

package securitybinding

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// tp-b4b: the security policy list counts every page (all/enabled/disabled
// under every filter but status) inside the tenant, and a subscribed WAF copy
// names its platform library by ID.
func TestSecurityPolicyListCountsAndLibraryID(t *testing.T) {
	fixture := newBindingFixture(t)
	pool, tenant := fixture.pool, fixture.tenantA
	ctx := context.Background()
	// tenantA has one enabled CC policy from the fixture; add one more enabled
	// and two disabled.
	insertPolicy(t, pool, tenant, securitypolicy.KindCC, "cc-on-2", 1)
	for _, name := range []string{"cc-off-1", "cc-off-2"} {
		id := insertPolicy(t, pool, tenant, securitypolicy.KindCC, name, 1)
		if _, err := pool.Exec(ctx, `UPDATE security_policies SET enabled=false WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, func() time.Time { return bindingTestNow }))
	actor := tenantActor(tenant)
	list := func(actor securitypolicy.Actor, filter securitypolicy.ListFilter) securitypolicy.ListResult {
		t.Helper()
		filter.Page, filter.Limit = 1, 1
		result, err := service.List(ctx, actor, filter)
		if err != nil {
			t.Fatalf("List(%+v): %v", filter, err)
		}
		return result
	}
	all := list(actor, securitypolicy.ListFilter{Kind: securitypolicy.KindCC})
	want := securitypolicy.ListCounts{All: 4, Enabled: 2, Disabled: 2}
	if all.Counts != want || all.Total != 4 || len(all.Items) != 1 {
		t.Fatalf("counts = %+v total %d", all.Counts, all.Total)
	}
	disabled := list(actor, securitypolicy.ListFilter{Kind: securitypolicy.KindCC, Status: "disabled"})
	if disabled.Counts != want || disabled.Total != 2 || disabled.Items[0].Enabled {
		t.Fatalf("disabled = %+v total %d", disabled.Counts, disabled.Total)
	}
	named := list(actor, securitypolicy.ListFilter{Kind: securitypolicy.KindCC, Name: "cc-off"})
	if named.Counts != (securitypolicy.ListCounts{All: 2, Disabled: 2}) {
		t.Fatalf("named = %+v", named.Counts)
	}
	// Tenant B (one WAF policy) never sees A's.
	other := list(tenantActor(fixture.tenantB), securitypolicy.ListFilter{})
	if other.Counts != (securitypolicy.ListCounts{All: 1, Enabled: 1}) || other.Items[0].ScopeID != fixture.tenantB.scopeID {
		t.Fatalf("tenant b = %+v", other)
	}
	if cc := list(tenantActor(fixture.tenantB), securitypolicy.ListFilter{Kind: securitypolicy.KindCC}); cc.Counts.All != 0 {
		t.Fatalf("tenant b cc = %+v", cc.Counts)
	}

	// A subscribed platform library copy carries library_id; own ones do not.
	libraryID := uuid.NewString()
	copied, err := service.UpsertLicensedWAF(ctx, tenantActor(fixture.tenantB), securitypolicy.LicensedWAFDefinition{
		LibraryID: libraryID, Revision: 3, Name: "平台库", Description: "platform", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{{
			Name: "block admin", Priority: 10, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}},
		}},
	}, "library-subscribe", "library-subscribe")
	if err != nil {
		t.Fatalf("UpsertLicensedWAF: %v", err)
	}
	if copied.LibraryID != libraryID || !copied.Protected {
		t.Fatalf("copy = %+v", copied)
	}
	page, err := service.List(ctx, tenantActor(fixture.tenantB), securitypolicy.ListFilter{Page: 1, Limit: 10, Kind: securitypolicy.KindWAF})
	if err != nil || page.Counts.All != 2 {
		t.Fatalf("waf list = %+v, %v", page, err)
	}
	for _, item := range page.Items {
		if (item.ID == copied.ID) != (item.LibraryID == libraryID) || item.ID != copied.ID && item.LibraryID != "" {
			t.Fatalf("library_id of %s = %q", item.Name, item.LibraryID)
		}
	}
}
