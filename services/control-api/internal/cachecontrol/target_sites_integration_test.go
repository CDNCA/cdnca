//go:build integration

package cachecontrol

import (
	"context"
	"testing"
	"time"
)

// fix-cachedlg: URLs resolve to the scope's sites by primary, alias and
// "*." names; another tenant's sites are never matched for a tenant actor.
func TestResolveTargetSitesMatchesOwnScopeOnly(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	own := seedCacheFixture(t, pool, "resolve-own", 1)
	other := seedCacheFixture(t, pool, "resolve-other", 1)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO site_domain_facts(
			scope_id,site_id,site_revision,action,canonical_domain,
			actor_scope_id,actor_user_id,request_id,occurred_at
		) VALUES
			($1,$2,1,'activate',$3,$1,$4,'resolve-own',$9),
			($1,$2,1,'activate','alias-resolve.example',$1,$4,'resolve-own',$9),
			($1,$2,1,'activate','*.wild-resolve.example',$1,$4,'resolve-own',$9),
			($5,$6,1,'activate',$7,$5,$8,'resolve-other',$9)`,
		own.actor.ScopeID, own.siteID, own.domain, own.actor.UserID,
		other.actor.ScopeID, other.siteID, other.domain, other.actor.UserID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	result, err := store.ResolveTargetSites(ctx, own.actor, false, ResolveTargetSitesRequest{
		Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{
			"https://" + own.domain + "/a", "https://alias-resolve.example/b",
			"https://x.wild-resolve.example/c", "https://" + other.domain + "/d",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Groups) != 1 || result.Groups[0].Site.SiteID != own.siteID ||
		len(result.Groups[0].Ordinals) != 3 {
		t.Fatalf("groups = %+v", result.Groups)
	}
	if len(result.Unmatched) != 1 || result.Unmatched[0].Ordinal != 4 || result.Unmatched[0].Reason != TargetReasonNoSite {
		t.Fatalf("another tenant's site must stay unmatched: %+v", result.Unmatched)
	}
}
