package errorpage

import (
	"slices"
	"testing"
)

// The global-only categories (no_host, unknown_site: a
// theme publishes both) are not site statuses. Before, a theme's
// unknown_site 404 made every site intercept its origin's 404 and answer
// with the generic fallback text. The unknown_site page is the default
// servers' (domain mismatch), reported separately.
func TestReadActiveRuntimeKeepsGlobalOnlyPagesOutOfSites(t *testing.T) {
	publisher, _ := testPublisher(t)
	const site = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
	policy := testPolicy(
		testRule("unknown-site", CategoryUnknownSite, StatusMatch{Codes: []int{421}}, "text/html", "<p>not here</p>"),
		testRule("no-host", CategoryNoHost, StatusMatch{Codes: []int{400}}, "text/plain", "no host"),
		testRule("global-502", CategoryEdgeConnect, StatusMatch{Codes: []int{502}}, "text/plain", "down"),
	)
	policy.Sites = []SiteScope{{SiteKey: site, Rules: []Rule{
		testRule("site-404", CategoryOriginResponse, StatusMatch{Codes: []int{404}}, "text/plain", "site 404"),
	}}}
	if _, err := publisher.Apply(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	active, found, err := ReadActiveRuntime(publisher.stateRoot)
	if err != nil || !found {
		t.Fatalf("active found=%v err=%v", found, err)
	}
	if got := active.SiteStatuses(site); !slices.Equal(got, []int{404, 502}) {
		t.Fatalf("site statuses = %v, want 404 502 (no 400, no 421)", got)
	}
	if got := active.SiteStatuses("018f47a2-5b9c-7d31-8a60-104c9c0b7199"); !slices.Equal(got, []int{502}) {
		t.Fatalf("other site statuses = %v", got)
	}
	if active.UnknownSiteStatus != 421 {
		t.Fatalf("unknown site status = %d, want 421", active.UnknownSiteStatus)
	}
}

func TestUnknownSiteStatusChoices(t *testing.T) {
	for _, status := range []int{403, 404, 410, 421} {
		if !categoryAllowsStatus(CategoryUnknownSite, status) {
			t.Errorf("unknown_site %d refused", status)
		}
	}
	for _, status := range []int{400, 444, 500, 502} {
		if categoryAllowsStatus(CategoryUnknownSite, status) {
			t.Errorf("unknown_site %d accepted", status)
		}
	}
}

func TestUnknownSiteSingleStatus(t *testing.T) {
	publisher, _ := testPublisher(t)
	policy := testPolicy(testRule("unknown-site", CategoryUnknownSite, StatusMatch{Codes: []int{404, 421}}, "text/plain", "x"))
	if _, err := publisher.Apply(t.Context(), policy); err == nil {
		t.Fatal("two unknown_site statuses accepted")
	}
}
