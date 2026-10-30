//go:build integration

package securitybinding

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/jackc/pgx/v5"
)

// 区域屏蔽预设（无默认 WAF 库时）在建站事务里新建一条只含该区域规则的
// 新站 WAF 库并以 revision 0 绑定，等激活 worker rebind 下发。待出包前全量跑（PG）。
func TestSiteDefaultRegionBlockJoinsNewSiteWAF(t *testing.T) {
	fixture := newBindingFixture(t)
	site := fixture.tenantB
	sub := insertFeatureSubscription(t, fixture.pool, site.scopeID, site.userID, bindingTestNow, false, true)
	linkFeatureSubscription(t, fixture.pool, site.siteID, sub)
	var policy securitypolicy.Policy
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if err := CheckSitePolicyFeature(t.Context(), tx, site.scopeID, site.siteID,
			securitypolicy.Policy{Kind: securitypolicy.KindWAF, Enabled: true}, bindingTestNow); err != nil {
			return err
		}
		var err error
		policy, err = securitypolicy.CopyForSiteTx(t.Context(), tx, tenantActor(site), securitypolicy.SiteCopyRequest{
			ScopeID: site.scopeID, OwnerID: site.userID, Kind: securitypolicy.KindWAF, SiteID: site.siteID, SiteName: "b.example.test",
			Extra: securitypolicy.RegionBlockRules(securitypolicy.RegionBlockChina)}, bindingTestNow)
		if err != nil {
			return err
		}
		return AttachNewSiteTx(t.Context(), tx, site.scopeID, site.siteID, policy.ID, securitypolicy.KindWAF, bindingTestNow)
	}); err != nil {
		t.Fatal(err)
	}
	if len(policy.Rules) != 1 || policy.Rules[0].Conditions[0].Field != "country" || policy.Rules[0].Conditions[0].Operator != "in" ||
		len(policy.Rules[0].Conditions[0].Values) != 4 {
		t.Fatalf("rules: %+v", policy.Rules)
	}
	var revision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT revision FROM security_policy_site_bindings
		WHERE site_id=$1 AND policy_kind='waf' AND policy_id=$2`, site.siteID, policy.ID).Scan(&revision); err != nil || revision != 0 {
		t.Fatalf("binding revision %d err %v", revision, err)
	}
}
