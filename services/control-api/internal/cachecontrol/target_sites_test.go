package cachecontrol

import (
	"reflect"
	"slices"
	"testing"

	"github.com/google/uuid"
)

func TestGroupTargetsBySiteMatchesPrimaryAliasWildcardAndUnmatched(t *testing.T) {
	primary := TargetSiteCandidate{SiteID: uuid.New(), Domain: "a.test", Domains: []string{"a.test", "www.a.test"}}
	wide := TargetSiteCandidate{SiteID: uuid.New(), Domain: "*.b.test", Domains: []string{"*.b.test"}}
	narrow := TargetSiteCandidate{SiteID: uuid.New(), Domain: "*.x.b.test", Domains: []string{"*.x.b.test"}}
	// A site without domain facts serves its primary domain alone.
	bare := TargetSiteCandidate{SiteID: uuid.New(), Domain: "c.test"}
	targets := []string{
		"https://a.test/1.png",     // primary
		"https://www.a.test/2.png", // alias
		"https://y.b.test/3.png",   // wildcard
		"https://z.x.b.test/4.png", // narrowest wildcard wins
		"https://c.test/5.png",     // primary without facts
		"https://unknown.test/6",   // no site
		"https://b.test/7",         // the bare suffix is not under *.b.test
		"not a url",                // invalid
		"http://a.test:8080/8.png", // port does not change the host
	}
	result := GroupTargetsBySite(targets, ActionPurge, TargetExactURL, []TargetSiteCandidate{primary, wide, narrow, bare})
	want := map[uuid.UUID][]int{
		primary.SiteID: {1, 2, 9},
		wide.SiteID:    {3},
		narrow.SiteID:  {4},
		bare.SiteID:    {5},
	}
	got := map[uuid.UUID][]int{}
	for _, group := range result.Groups {
		got[group.Site.SiteID] = group.Ordinals
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}
	if !slices.Equal(groupSiteOrder(result), []uuid.UUID{primary.SiteID, wide.SiteID, narrow.SiteID, bare.SiteID}) {
		t.Fatal("groups must follow the first target of each site")
	}
	wantUnmatched := []UnmatchedTarget{
		{Ordinal: 6, Reason: TargetReasonNoSite},
		{Ordinal: 7, Reason: TargetReasonNoSite},
		{Ordinal: 8, Reason: TargetReasonInvalidURL},
	}
	if !reflect.DeepEqual(result.Unmatched, wantUnmatched) {
		t.Fatalf("unmatched = %+v, want %+v", result.Unmatched, wantUnmatched)
	}
}

func TestGroupTargetsBySiteWildcardPurgeGoesToEverySiteUnderIt(t *testing.T) {
	one := TargetSiteCandidate{SiteID: uuid.New(), Domain: "m.d.test", Domains: []string{"m.d.test"}}
	two := TargetSiteCandidate{SiteID: uuid.New(), Domain: "*.d.test", Domains: []string{"*.d.test"}}
	other := TargetSiteCandidate{SiteID: uuid.New(), Domain: "e.test", Domains: []string{"e.test"}}
	result := GroupTargetsBySite([]string{"https://*.d.test/"}, ActionPurge, TargetDirectoryPrefix,
		[]TargetSiteCandidate{one, two, other})
	if len(result.Groups) != 2 || len(result.Unmatched) != 0 {
		t.Fatalf("wildcard purge = %+v", result)
	}
	// A prewarm only fetches concrete hosts.
	result = GroupTargetsBySite([]string{"https://*.d.test/a"}, ActionPrewarm, TargetExactURL,
		[]TargetSiteCandidate{one, two})
	if len(result.Groups) != 0 || !reflect.DeepEqual(result.Unmatched,
		[]UnmatchedTarget{{Ordinal: 1, Reason: TargetReasonWildcardPrewarm}}) {
		t.Fatalf("wildcard prewarm = %+v", result)
	}
}

func TestTargetSiteCandidateNamesCoverHostAndParents(t *testing.T) {
	exact, under := targetSiteCandidateNames([]string{"https://a.b.test/x", "https://*.c.test/", "bad"})
	for _, name := range []string{"a.b.test", "*.b.test", "*.test", "*.c.test"} {
		if !slices.Contains(exact, name) {
			t.Errorf("candidate names %v miss %q", exact, name)
		}
	}
	if !slices.Equal(under, []string{"c.test"}) {
		t.Fatalf("wildcard suffixes = %v", under)
	}
}

func groupSiteOrder(result TargetSiteGrouping) []uuid.UUID {
	ids := make([]uuid.UUID, len(result.Groups))
	for index, group := range result.Groups {
		ids[index] = group.Site.SiteID
	}
	return ids
}
