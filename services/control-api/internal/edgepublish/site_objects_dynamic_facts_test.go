package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
)

// D13-b: a dynamic routing publication carries the scope's published error
// pages and origin auth bindings in its site objects (they were nil before).
func TestDynamicRoutingPublicationCarriesErrorPagesAndOriginAuth(t *testing.T) {
	v8 := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 2, 2)
	if sites := v8.runtimes(); len(sites) != 2 {
		t.Fatalf("%d sites", len(sites))
	}
	signed, other := uuid.MustParse("018f47a2-5b9c-7d31-8a60-000000200000"), uuid.MustParse("018f47a2-5b9c-7d31-8a60-000000200001")
	body := []byte("site 404 page")
	pages := &errorpagecontrol.ProductionSnapshotDocument{Schema: errorpagecontrol.ProductionSnapshotSchema,
		Global: errorpagecontrol.ProductionSnapshotScope{Rules: []errorpagecontrol.ProductionSnapshotRule{
			snapshotRule("global-502", "edge_connect", []int{502}, nil, "text/plain", []byte("global 502")),
			snapshotRule("theme.unknown_site.404", "unknown_site", []int{404}, nil, "text/plain", []byte("node page")),
		}},
		Sites: []errorpagecontrol.ProductionSnapshotSite{{SiteKey: signed.String(), Rules: []errorpagecontrol.ProductionSnapshotRule{
			snapshotRule("site-404", "origin_response", []int{404}, nil, "text/plain", body)}}}}
	rule := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	auth := &originauthcontrol.PublicationSnapshot{PublicationRevision: 4, Rules: []originauthcontrol.PublicationRule{
		{RuleID: rule, SiteID: signed, SourcePosition: 1, Endpoint: "https://bucket.cos.example.test"},
		{RuleID: uuid.New(), SiteID: other, SourcePosition: 2, Endpoint: "https://x.example.test"}, // not position 1: unsigned (v7)
	}}
	facts, err := dynamicRoutingFacts(v8, pages, auth)
	if err != nil {
		t.Fatal(err)
	}
	publication, _, err := buildDynamicRoutingPublication(v8, goldenTenant, facts, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, object := range publication.Objects {
		objects[object.SHA256] = object.Plaintext
	}
	found := map[string]edgesite.Site{}
	for _, raw := range objects {
		if site, err := edgesite.Decode(raw); err == nil {
			found[site.SiteID] = site
		}
	}
	site := found[signed.String()]
	if len(site.Errors) != 2 || site.Errors[1].Category != edgesite.ErrorOriginResponse || site.Errors[1].Status != 404 ||
		string(objects[site.Errors[1].Asset.SHA256]) != string(body) {
		t.Fatalf("site error pages %+v", site.Errors)
	}
	if len(site.Origin.Auth) != 1 || site.Origin.Auth[0].Secret.ID != rule.String() || site.Origin.Auth[0].Secret.Revision != 4 ||
		site.Origin.Auth[0].PoolID != "primary" {
		t.Fatalf("origin auth %+v", site.Origin.Auth)
	}
	if plain := found[other.String()]; len(plain.Errors) != 1 || len(plain.Origin.Auth) != 0 {
		t.Fatalf("other site %+v %+v", plain.Errors, plain.Origin.Auth)
	}
	if facts, err := dynamicRoutingFacts(v8, nil, nil); err != nil || facts != nil {
		t.Fatalf("no releases: %v %v", facts, err)
	}
}

// D13-b2: the snapshot's node pages (global no_host / unknown_site) ride on
// the v2 scope with their bodies among the scope objects; site objects do
// not get them.
func TestDynamicRoutingPublicationCarriesNodePages(t *testing.T) {
	v8 := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 2, 2)
	noHost, unknown := []byte("<style>p{}</style><p>400</p>"), []byte("node 404")
	snapshot := errorpagecontrol.ProductionSnapshotDocument{Schema: errorpagecontrol.ProductionSnapshotSchema,
		Global: errorpagecontrol.ProductionSnapshotScope{Rules: []errorpagecontrol.ProductionSnapshotRule{
			snapshotRule("theme.no_host.400", "no_host", []int{400}, nil, "text/html", noHost),
			snapshotRule("theme.unknown_site.404", "unknown_site", []int{404}, nil, "text/plain", unknown),
		}}}
	assets := map[string][]byte{}
	pages, err := nodePageFacts(snapshot, assets)
	if err != nil || len(pages) != 2 || len(assets) != 2 || pages[0].StyleHash != themepack.ThemeStyleHash(noHost) || pages[1].Status != 404 {
		t.Fatalf("%+v %v", pages, err)
	}
	publication, _, err := buildDynamicRoutingPublication(v8, goldenTenant, nil, pages, assets)
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, object := range publication.Objects {
		objects[object.SHA256] = object.Plaintext
	}
	var scope siteobject.ScopeV2
	for _, raw := range objects {
		if parsed, err := siteobject.ParseScopeV2(raw); err == nil {
			scope = parsed
		}
	}
	if len(scope.NodePages) != 2 || scope.NodePages[0].Category != "no_host" || scope.NodePages[0].Status != 400 ||
		string(objects[scope.NodePages[1].SHA256]) != string(unknown) {
		t.Fatalf("scope node pages %+v", scope.NodePages)
	}
	twice := snapshot
	twice.Global.Rules = append(twice.Global.Rules, snapshotRule("other.unknown_site.410", "unknown_site", []int{410}, nil, "text/plain", unknown))
	if _, err := nodePageFacts(twice, map[string][]byte{}); err == nil {
		t.Fatal("two unknown_site pages were accepted")
	}
}
