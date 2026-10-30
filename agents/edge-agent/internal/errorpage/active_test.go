package errorpage

import (
	"slices"
	"testing"
)

// FX43: the site runtime renders error_page only for statuses that have a
// page, reading the current release while the publisher may hold its lock.
func TestReadActiveRuntimeListsBoundStatusesPerSite(t *testing.T) {
	publisher, _ := testPublisher(t)
	if _, found, err := ReadActiveRuntime(publisher.stateRoot); err != nil || found {
		t.Fatalf("empty state: found=%v err=%v", found, err)
	}
	const site = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
	policy := testPolicy(testRule("global-404", CategoryOriginResponse, StatusMatch{Codes: []int{404}}, "text/plain", "global"))
	policy.Sites = []SiteScope{{SiteKey: site, Rules: []Rule{
		testRule("site-5xx", CategoryEdgeConnect, StatusMatch{Codes: []int{502}}, "text/html", "<p>down</p>"),
		testRule("site-503", CategoryOriginResponse, StatusMatch{Codes: []int{503}}, "text/plain", "busy"),
	}}}
	result, err := publisher.Apply(t.Context(), policy)
	if err != nil {
		t.Fatal(err)
	}
	publisher.mu.Lock() // the reader must not need the publisher's lock
	active, found, err := ReadActiveRuntime(publisher.stateRoot)
	publisher.mu.Unlock()
	if err != nil || !found || active.Digest != result.Digest || len(active.RuntimeLua) == 0 {
		t.Fatalf("active = %+v found=%v err=%v", active, found, err)
	}
	if got := active.SiteStatuses(site); !slices.Equal(got, []int{404, 502, 503}) {
		t.Fatalf("site statuses = %v", got)
	}
	if got := active.SiteStatuses("018f47a2-5b9c-7d31-8a60-104c9c0b7199"); !slices.Equal(got, []int{404}) {
		t.Fatalf("other site statuses = %v, want the global 404", got)
	}
}

// Node pages (no Host, unknown site; a theme publishes them) are for the
// node's default server only: their statuses (400, 404) must not join a
// site's intercepted statuses, or every origin 400/404 of every site would
// be replaced by the built-in text page (no origin_response page exists).
func TestReadActiveRuntimeKeepsNodePagesOutOfSiteStatuses(t *testing.T) {
	publisher, _ := testPublisher(t)
	const site = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
	policy := testPolicy(
		testRule("theme.no_host.400", CategoryNoHost, StatusMatch{Codes: []int{400}}, "text/plain", "no host"),
		testRule("theme.unknown_site.404", CategoryUnknownSite, StatusMatch{Codes: []int{404}}, "text/plain", "unknown"),
		testRule("theme.edge_connect.502", CategoryEdgeConnect, StatusMatch{Codes: []int{502}}, "text/plain", "down"),
	)
	policy.Sites = []SiteScope{{SiteKey: site, Rules: []Rule{
		testRule("site-503", CategoryOriginResponse, StatusMatch{Codes: []int{503}}, "text/plain", "busy"),
	}}}
	if _, err := publisher.Apply(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	active, found, err := ReadActiveRuntime(publisher.stateRoot)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if got := active.SiteStatuses(site); !slices.Equal(got, []int{502, 503}) {
		t.Fatalf("site statuses = %v, want [502 503] (node pages excluded)", got)
	}
	if got := active.SiteStatuses("018f47a2-5b9c-7d31-8a60-104c9c0b7199"); !slices.Equal(got, []int{502}) {
		t.Fatalf("other site statuses = %v, want [502]", got)
	}
}
