package site

import "testing"

// ge36: origin redirect following, 1..10 hops (0 = default 3), audited.
func TestNormalizeOriginFollowRedirect(t *testing.T) {
	pool := forwardingPool()
	pool.FollowRedirect = &OriginFollowRedirect{Enabled: true}
	if err := normalizeOriginPool(&pool); err != nil || pool.FollowRedirect.MaxHops != DefaultFollowRedirectHops {
		t.Fatalf("default hops: %+v %v", pool.FollowRedirect, err)
	}
	for _, hops := range []int{-1, 6} {
		bad := forwardingPool()
		bad.FollowRedirect = &OriginFollowRedirect{Enabled: true, MaxHops: hops}
		if normalizeOriginPool(&bad) == nil {
			t.Errorf("max_hops %d accepted", hops)
		}
	}
	after := forwardingPool()
	after.FollowRedirect = &OriginFollowRedirect{Enabled: true, MaxHops: 5, CrossOrigin: true}
	changes := originForwardingChanges(forwardingPool(), after)
	found := false
	for _, change := range changes {
		if change.Field == "follow_redirect" {
			found = change.Before == "off" && change.After == "on:5:cross_origin"
		}
	}
	if !found {
		t.Fatalf("audit changes %+v", changes)
	}
}
