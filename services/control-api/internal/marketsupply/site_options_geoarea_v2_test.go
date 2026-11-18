package marketsupply

import (
	"fmt"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
)

func geoRoutesConfig(routes ...siteconf.Route) siteconf.Config {
	cfg := optionsConfig()
	cfg.OriginRoutes = &siteconf.OriginRoutes{
		Pools:         []siteconf.RoutePool{{ID: "default", Endpoints: []siteconf.RouteEndpoint{{ID: "o1", Host: "203.0.113.9", Port: 80, Weight: 1}}}},
		DefaultPoolID: "default", Routes: routes,
		Retry: siteconf.RouteRetry{Methods: []string{"GET"}, MaxAttempts: 1, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 33000},
	}
	return cfg
}

func geoRoute(id string, priority int, geos ...siteconf.NodeGeo) siteconf.Route {
	return siteconf.Route{ID: id, Priority: priority, NodeGeos: geos, PoolID: "default"}
}

// A continent geography matches leaf country regions in any of
// its regions, leaf regions on the continent itself and on its regions; a
// region geography does not match a leaf region on the whole continent (a node
// there is not known to be in that region).
func TestOriginRouteDocumentMapsContinents(t *testing.T) {
	cfg := geoRoutesConfig(geoRoute("asia", 1, siteconf.NodeGeo{Area: "asia"}),
		geoRoute("ea", 1, siteconf.NodeGeo{Area: "east_asia"}), geoRoute("oc", 1, siteconf.NodeGeo{Area: "oceania"}))
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	leaf := map[string]regioncatalog.CodeGeo{
		"jp": {Code: "jp", CountryCode: "JP"}, "in": {Code: "in", CountryCode: "IN"}, "de": {Code: "de", CountryCode: "DE"},
		"au": {Code: "au", CountryCode: "AU"}, "sea": {Code: "sea", AreaCode: "southeast_asia"},
		"asi": {Code: "asi", AreaCode: "asia"}, "eu": {Code: "eu", AreaCode: "northern_europe"},
	}
	doc, unmatched, err := originRouteDocument(cfg.OriginRoutes, leaf)
	if err != nil || len(unmatched) != 0 {
		t.Fatalf("err %v unmatched %v", err, unmatched)
	}
	want := map[string][]string{"asia": {"asi", "in", "jp", "sea"}, "ea": {"jp"}, "oc": {"au"}}
	for _, r := range doc.Routes {
		if !slices.Equal(r.NodeRegions, want[r.ID]) {
			t.Errorf("%s: %v, want %v", r.ID, r.NodeRegions, want[r.ID])
		}
		delete(want, r.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing routes %v", want)
	}
}

// A rule whose geographies match more leaf regions than one
// local rule may name (32) is split into consecutive local rules of at most
// 32 regions (same match and pools; the first keeps the ID, the next get
// ID.2, ID.3, ...), instead of the whole site being refused. A local document
// that names more than 32 regions in one rule is still refused.
func TestOriginRouteDocumentSplitsLargeGeoRules(t *testing.T) {
	leaf := map[string]regioncatalog.CodeGeo{}
	for i := range 70 {
		code := fmt.Sprintf("de%02d", i)
		leaf[code] = regioncatalog.CodeGeo{Code: code, CountryCode: "DE"}
	}
	leaf["jp"] = regioncatalog.CodeGeo{Code: "jp", CountryCode: "JP"}
	cfg := geoRoutesConfig(geoRoute("eu", 5, siteconf.NodeGeo{Area: "europe"}), geoRoute("jp", 5, siteconf.NodeGeo{Country: "JP"}))
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	doc, unmatched, err := originRouteDocument(cfg.OriginRoutes, leaf)
	if err != nil || len(unmatched) != 0 {
		t.Fatalf("err %v unmatched %v", err, unmatched)
	}
	var ids []string
	var all []string
	for _, r := range doc.Routes {
		ids = append(ids, r.ID)
		if r.ID != "jp" {
			if len(r.NodeRegions) > 32 || r.Priority != 5 || r.PoolID != "default" {
				t.Fatalf("chunk %+v", r)
			}
			all = append(all, r.NodeRegions...)
		}
	}
	if !slices.Equal(ids, []string{"eu", "eu.2", "eu.3", "jp"}) || len(all) != 70 || !slices.IsSorted(all) {
		t.Fatalf("ids %v, %d regions", ids, len(all))
	}
	// Another rule of equal rank may sort between the chunks (eu < eu-x <
	// eu.2): harmless when it shares no region with the later chunks, refused
	// when it does (a node there would meet it before its chunk).
	cfg = geoRoutesConfig(geoRoute("eu", 5, siteconf.NodeGeo{Area: "europe"}), geoRoute("eu-x", 5, siteconf.NodeGeo{Country: "JP"}))
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if doc, _, err := originRouteDocument(cfg.OriginRoutes, leaf); err != nil || len(doc.Routes) != 4 || doc.Routes[1].ID != "eu-x" {
		t.Fatalf("disjoint interleaved rule: %v %+v", err, doc.Routes)
	}
	cfg = geoRoutesConfig(geoRoute("eu", 5, siteconf.NodeGeo{Area: "europe"}), geoRoute("eu-x", 5, siteconf.NodeGeo{Country: "DE"}))
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := originRouteDocument(cfg.OriginRoutes, leaf); err == nil {
		t.Fatal("overlapping interleaved rule accepted")
	}
}
