package dynroute

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

const (
	selectionSiteA = "0d13c000-0000-4000-8000-00000000a501"
	selectionSiteB = "0d13c000-0000-4000-8000-00000000b501"
	selectionSiteC = "0d13c000-0000-4000-8000-00000000c501"
	// site B's own marks: a port no other site listens on, its certificate
	// version and its cache key prefix.
	selectionPortB        = 8443
	selectionCertificateB = "0d13c000-0000-4000-8000-0000000ce501"
	selectionTenant       = "7e000000-0000-4000-8000-000000000001"
)

func selectionSite(t *testing.T, siteID, host string, port int, certificate string, cached bool) (siteobject.BucketEntry, []byte) {
	t.Helper()
	listener := edgesite.Listener{Port: port, AddressFamily: edgesite.FamilyIPv4}
	if certificate != "" {
		listener.TLS = &edgesite.TLS{CertificateVersionID: certificate, Protocols: []string{"TLSv1.2", "TLSv1.3"}}
	}
	site := edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: testScopeA, TenantID: selectionTenant,
		SiteID: siteID, Revision: 1, Hosts: edgesite.Hosts{Primary: host, Aliases: []string{}},
		Listeners: []edgesite.Listener{listener},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "origin-0", Scheme: "http", Host: "192.0.2.1", Port: 80, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 10, ReadTimeoutMS: 10, TotalBudgetMS: 10}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
		Limits:   edgesite.Limits{MaxBodyBytes: 64 << 20},
	}
	if cached {
		site.Cache = &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(selectionTenant, siteID),
			Domain: host, KeyByHost: true, Policy: edgeconfig.CachePolicyDocument{SchemaVersion: edgeconfig.CachePolicyDocumentSchemaV2,
				Revision: 1, Mode: edgeconfig.CacheOverride, DiskQuotaBytes: 64 << 20,
				Rules: []edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".svg"}, Action: edgeconfig.CacheRuleActionCache,
					TTLSeconds: 600, BrowserTTLSeconds: 600}},
				QueryMode: edgeconfig.CacheQueryPreserve, QueryNames: []string{}, VaryHeaders: []string{}}}
		generation, err := edgesite.CacheGeneration(*site.Cache)
		if err != nil {
			t.Fatal(err)
		}
		site.Cache.Generation = generation
	}
	raw, err := edgesite.Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	return siteobject.BucketEntry{SiteID: siteID, Revision: 1, SHA256: edgesite.Digest(raw)}, raw
}

// A website the node's key document withholds is left out
// before anything is rendered. The skeleton of the release with website B
// withheld is byte for byte the one of a release that never carried B (the
// websites the node serves are unchanged), so is its routing index, and B's
// port, certificate and cache identity are in neither.
func TestWithheldSiteIsNotRendered(t *testing.T) {
	entryA, rawA := selectionSite(t, selectionSiteA, "a.sel.test", 80, "", false)
	entryB, rawB := selectionSite(t, selectionSiteB, "b.sel.test", selectionPortB, selectionCertificateB, true)
	entryC, rawC := selectionSite(t, selectionSiteC, "c.sel.test", 80, "", false)
	objects := map[string][]byte{entryA.SHA256: rawA, entryB.SHA256: rawB, entryC.SHA256: rawC}
	decode := func(digests []string) []edgesite.Site {
		sites := make([]edgesite.Site, 0, len(digests))
		for _, digest := range digests {
			object, err := siteindex.DecodeObject(digest, objects[digest])
			if err != nil {
				t.Fatal(err)
			}
			sites = append(sites, object.Site)
		}
		return sites
	}
	// short root: the control socket path has a length limit
	root, err := os.MkdirTemp("/tmp", "sitesel")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1, CacheMaxBytes: 10 << 30})
	if err != nil {
		t.Fatal(err)
	}
	render := func(sites []edgesite.Site) []byte {
		conf, err := runtime.render(sites, dynwaf.Result{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return conf
	}
	entries := []siteobject.BucketEntry{entryA, entryB, entryC}
	full, err := gatewayclient.SelectNodeSites(entries, nil)
	if err != nil || len(full) != 3 {
		t.Fatalf("nothing withheld = %v, %v", full, err)
	}
	selected, err := gatewayclient.SelectNodeSites(entries, siteobject.NewSiteBitmap([]string{selectionSiteA, selectionSiteB, selectionSiteC}, map[string]bool{selectionSiteB: true}))
	if err != nil {
		t.Fatal(err)
	}
	withheld := render(decode(selected))
	golden := render(decode([]string{entryA.SHA256, entryC.SHA256}))
	if !bytes.Equal(withheld, golden) {
		t.Fatal("the skeleton with website B withheld differs from the one without B")
	}
	// The skeleton carries the ports (host, certificate and cache are index
	// data): B's own port is in the full skeleton only.
	if !strings.Contains(string(render(decode(full))), ":8443") || strings.Contains(string(withheld), ":8443") {
		t.Fatal("website B's port: want it in the full skeleton only")
	}
	// The routing index (hosts, certificate, cache identity per request) is
	// the one of a release without B and routes to none of B's objects.
	objectsOf := func(digests []string) []siteindex.Object {
		result := make([]siteindex.Object, 0, len(digests))
		for _, digest := range digests {
			object, err := siteindex.DecodeObject(digest, objects[digest])
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, object)
		}
		return result
	}
	withheldIndex, err := siteindex.Build(7, objectsOf(selected))
	if err != nil {
		t.Fatal(err)
	}
	goldenIndex, err := siteindex.Build(7, objectsOf([]string{entryA.SHA256, entryC.SHA256}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(withheldIndex, goldenIndex) || slices.Contains(withheldIndex.Digests(), entryB.SHA256) {
		t.Fatal("the routing index with website B withheld differs from the one without B")
	}
	fullIndex, err := siteindex.Build(7, objectsOf(full))
	if err != nil || !slices.Contains(fullIndex.Digests(), entryB.SHA256) {
		t.Fatalf("fixture: the full index does not route to website B (%v)", err)
	}
	// The certificate sync and the cache pool read the same site list: B's
	// certificate version and cache identity are not in it.
	for _, site := range decode(selected) {
		if site.SiteID == selectionSiteB || site.Cache != nil {
			t.Fatalf("website %s (cache %v) reached the runtime input", site.SiteID, site.Cache)
		}
		for _, listener := range site.Listeners {
			if listener.TLS != nil {
				t.Fatalf("website %s references certificate %s", site.SiteID, listener.TLS.CertificateVersionID)
			}
		}
	}
}
