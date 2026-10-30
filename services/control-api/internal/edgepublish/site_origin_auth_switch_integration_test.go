//go:build integration

package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
)

// tp-b3a-be (migration 490): a site whose origin auth switch is off has its
// rules left out of the site objects; another site's stay, and switching it
// back on brings them back. The publication snapshot is not changed.
func TestSiteOriginAuthSwitchFiltersRules(t *testing.T) {
	fixture := newPublishFixture(t)
	on := fixture.createSiteWithPortSets(t, "auth-switch-on.example.test", []string{"80"}, []string{}, false)
	off := fixture.createSiteWithPortSets(t, "auth-switch-off.example.test", []string{"80"}, []string{}, false)
	snapshot := &originauthcontrol.PublicationSnapshot{PublicationRevision: 1, Rules: []originauthcontrol.PublicationRule{
		{RuleID: uuid.New(), SiteID: on.Site.ID}, {RuleID: uuid.New(), SiteID: off.Site.ID}}}
	sites := func() []uuid.UUID {
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		kept, err := withoutOriginAuthDisabledSites(t.Context(), tx, fixture.scopeID, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		result := make([]uuid.UUID, 0, len(kept.Rules))
		for _, rule := range kept.Rules {
			result = append(result, rule.SiteID)
		}
		return result
	}
	if got := sites(); len(got) != 2 {
		t.Fatalf("both switches on (default): %v", got)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE site_origin_pools SET origin_auth_enabled=false WHERE site_id=$1`, off.Site.ID); err != nil {
		t.Fatal(err)
	}
	if got := sites(); len(got) != 1 || got[0] != on.Site.ID || len(snapshot.Rules) != 2 {
		t.Fatalf("switch off: %v (snapshot %d rules)", got, len(snapshot.Rules))
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE site_origin_pools SET origin_auth_enabled=true WHERE site_id=$1`, off.Site.ID); err != nil {
		t.Fatal(err)
	}
	if got := sites(); len(got) != 2 {
		t.Fatalf("switched back on: %v", got)
	}
}
