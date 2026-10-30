package cachetask

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// generationSite is a site runtime v2 site keyed by its cache generation in
// its stable namespace (ge-cache A).
func generationSite(version string, listeners ...ListenerContext) SiteContext {
	site := testSite("tenant-a", "site-a", version, "cache.example.test", 18080, 0, 1)
	site.CacheGeneration = "0123456789abcdef"
	site.CacheIdentity = edgeconfig.CacheSiteNamespaceID(site.TenantID, site.SiteID)
	site.Listeners = listeners
	return site
}

// A new config version keeps the namespace and the keys: a purge under the
// second version finds what the first version stored.
func TestGenerationSiteKeepsObjectsAcrossVersions(t *testing.T) {
	root := testStateRoot(t)
	first := generationSite("config-v1")
	path := putCacheEntry(t, root, first, "/a.css")
	second := generationSite("config-v2")
	manager := testManager(t, root, resolverFor(second), nil)
	result, err := manager.Execute(context.Background(), taskFor(second, "gen-purge", ActionPurgeExact, cacheURL(second, "/a.css")))
	if err != nil || result.Items[0].Code != CodePurged {
		t.Fatalf("purge under the new version = %+v, %v", result, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object stored under the first version remains: %v", err)
	}
	stale := second
	stale.CacheIdentity = CacheNamespaceID(second.TenantID, second.SiteID, second.ConfigVersionID)
	if _, valid := normalizeSiteContext(stale); valid {
		t.Fatal("a generation site accepted the per-version namespace")
	}
}

// A URL purge clears the object on every cache listener serving the host:
// http and https, any port (one submission covers both).
func TestPurgeCoversHTTPAndHTTPSListeners(t *testing.T) {
	root := testStateRoot(t)
	site := generationSite("config-v1",
		ListenerContext{Domain: "cache.example.test", Scheme: "http", ListenPort: 80, CacheEnabled: true},
		ListenerContext{Domain: "cache.example.test", Scheme: "https", ListenPort: 443, CacheEnabled: true})
	httpSite, httpsSite := site, site
	httpSite.ListenPort, httpsSite.ListenPort = 80, 443
	httpPath, httpsPath := putCacheEntry(t, root, httpSite, "/v.mp4"), putCacheEntry(t, root, httpsSite, "/v.mp4")
	manager := testManager(t, root, resolverFor(site), nil)
	result, err := manager.Execute(context.Background(), taskFor(site, "both-schemes", ActionPurgeExact, "https://cache.example.test/v.mp4"))
	if err != nil || result.Items[0].Affected != 2 {
		t.Fatalf("purge = %+v, %v", result, err)
	}
	for _, path := range []string{httpPath, httpsPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains: %v", path, err)
		}
	}
}

// A wildcard purge ("*.x.example") clears every host under it the site keys.
func TestWildcardPurgeClearsEveryHostUnder(t *testing.T) {
	root := testStateRoot(t)
	site := generationSite("config-v1",
		ListenerContext{Domain: "*.x.example", Scheme: "http", ListenPort: 18080, CacheEnabled: true})
	site.Domain, site.Domains, site.KeyByHost = "*.x.example", []string{"*.x.example"}, true
	var paths []string
	for _, host := range []string{"a.x.example", "b.deep.x.example"} {
		keyed := site
		keyed.Domain = host
		paths = append(paths, putCacheEntry(t, root, keyed, "/item"))
	}
	manager := testManager(t, root, resolverFor(site), nil)
	result, err := manager.Execute(context.Background(), taskFor(site, "wildcard", ActionPurgePrefix, "http://*.x.example:18080/"))
	if err != nil || result.Items[0].Affected != 2 {
		t.Fatalf("wildcard purge = %+v, %v", result, err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains: %v", path, err)
		}
	}
}

func TestPrewarmCacheStateFoldsExtendedStatuses(t *testing.T) {
	for value, want := range map[string]string{"MISS": "MISS", "EXPIRED": "MISS", "HIT": "HIT", "STALE": "HIT",
		"UPDATING": "HIT", "REVALIDATED": "HIT", "BYPASS": ""} {
		if got, ok := prewarmCacheState(value); got != want || ok != (want != "") {
			t.Errorf("%s -> %q %v", value, got, ok)
		}
	}
}
