package cachetask

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// A site runtime v2 cache keys each object by the
// request's own host unless the site shares one cache across its domains.

func hostKeyedSite(prewarmPort uint16) SiteContext {
	site := servedDomainsSite(prewarmPort)
	site.KeyByHost = true
	return site
}

// hostCacheEntry writes the object nginx keeps for host's visitors.
func hostCacheEntry(t *testing.T, root string, site SiteContext, host, uri string) string {
	t.Helper()
	keyed := site
	keyed.Domain = host
	return putCacheEntry(t, root, keyed, uri)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestPurgeOfAHostKeyedSiteRemovesOnlyThatHostsObject(t *testing.T) {
	root := testStateRoot(t)
	site := hostKeyedSite(0)
	manager := testManager(t, root, resolverFor(site), nil)
	for index, action := range []Action{ActionPurgeExact, ActionPurgePrefix} {
		target, other := hostCacheEntry(t, root, site, "a.x.example", "/dir/item"),
			hostCacheEntry(t, root, site, "b.x.example", "/dir/item")
		alias := hostCacheEntry(t, root, site, "alias.example.test", "/dir/item")
		url := servedURL("a.x.example", "/dir/item")
		if action == ActionPurgePrefix {
			url = servedURL("a.x.example", "/dir/")
		}
		result, err := manager.Execute(context.Background(), taskFor(site, fmt.Sprint("host-purge-", index), action, url))
		if err != nil {
			t.Fatal(err)
		}
		if result.Items[0].Code != CodePurged || result.Items[0].Affected != 1 {
			t.Fatalf("%s purge = %+v", action, result.Items[0])
		}
		if exists(target) || !exists(other) || !exists(alias) {
			t.Fatalf("%s purge of a.x.example: a=%v b=%v alias=%v", action, exists(target), exists(other), exists(alias))
		}
		for _, path := range []string{other, alias} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSitePurgeOfAHostKeyedSiteRemovesEveryHost(t *testing.T) {
	root := testStateRoot(t)
	site := hostKeyedSite(0)
	manager := testManager(t, root, resolverFor(site), nil)
	paths := []string{hostCacheEntry(t, root, site, "a.x.example", "/one"),
		hostCacheEntry(t, root, site, "deep.a.x.example", "/two"), hostCacheEntry(t, root, site, "alias.example.test", "/three")}
	result, err := manager.Execute(context.Background(), taskFor(site, "host-site-purge", ActionPurgeSite))
	if err != nil {
		t.Fatal(err)
	}
	if result.Items[0].Code != CodePurged || result.Items[0].Affected != len(paths) {
		t.Fatalf("site purge = %+v", result.Items[0])
	}
	for _, path := range paths {
		if exists(path) {
			t.Fatalf("site purge left %s", path)
		}
	}
}

// A shared cache keeps one object for every host: a purge under any host
// removes it (TestPurgeAcceptsHostsCoveredByTheSite), and an object keyed by
// a host is not the site's.
func TestPurgeOfASharedSiteIgnoresHostKeyedObjects(t *testing.T) {
	root := testStateRoot(t)
	site := servedDomainsSite(0)
	manager := testManager(t, root, resolverFor(site), nil)
	stray := hostCacheEntry(t, root, site, "a.x.example", "/item")
	result, err := manager.Execute(context.Background(), taskFor(site, "shared-purge", ActionPurgeSite))
	if err != nil {
		t.Fatal(err)
	}
	if result.Items[0].Affected != 0 || !exists(stray) {
		t.Fatalf("shared site purge took a host-keyed object: %+v", result.Items[0])
	}
}

// Prewarm of a host-keyed site sends the URL's host and verifies the object
// nginx stored under that host's key.
func TestPrewarmOfAHostKeyedSiteVerifiesTheHostsObject(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var seen sync.Map
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state := missThenHit(&seen, request.Host+request.URL.Path)
		if state == "HIT" {
			// prewarm sends Host without the port; nginx $host is that name.
			keyed := site
			keyed.Domain = request.Host
			if err := writeCacheEntryEvidence(root, keyed, request.URL.RequestURI()); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		_, _ = writer.Write([]byte("body"))
	}))
	site = hostKeyedSite(server.port())
	manager := testManager(t, root, resolverFor(site), nil)
	result, err := manager.Execute(context.Background(), taskFor(site, "host-prewarm", ActionPrewarm,
		servedURL("a.x.example", "/one"), servedURL("alias.example.test", "/one")))
	if err != nil {
		t.Fatal(err)
	}
	for index, item := range result.Items {
		if item.Code != CodePrewarmed {
			t.Fatalf("item %d = %+v", index, item)
		}
	}
}

// The manifest's key_by_host reaches the site context and the task journal.
func TestSiteRuntimeHostKeyedManifestReachesTheTaskBinding(t *testing.T) {
	listener := func(port uint16) edgeconfig.CacheListenerPolicy {
		value := productionListener(port)
		value.KeyByHost = true
		return value
	}
	manifest, err := edgeconfig.SiteRuntimeCacheManifest(productionVersionV1, 7, productionTenantID, []byte("# compiled\n"),
		[]edgeconfig.CacheListenerPolicy{listener(8080), listener(8443)})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := edgeconfig.ParseSiteRuntimeCacheRelease(manifest, []byte("# compiled\n"), edgeconfig.CachePolicyKeyModule())
	if err != nil {
		t.Fatal(err)
	}
	site, err := siteFromManifest(parsed, nil, strings.Repeat("a", sha256.Size*2), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil || !site.KeyByHost {
		t.Fatalf("site from a host-keyed manifest = %+v, %v", site, err)
	}
	task := taskMetadata{TenantID: site.TenantID, SiteID: site.SiteID, ConfigVersionID: site.ConfigVersionID, ConfigRevision: site.ConfigRevision}
	binding := siteBindingFromContext(site)
	if !binding.KeyByHost || !validSiteBinding(binding, task) || !siteContextFromBinding(binding, task).KeyByHost {
		t.Fatalf("journal binding = %+v", binding)
	}
	shared := binding
	shared.KeyByHost = false
	if validSiteBinding(shared, task) {
		t.Fatal("a binding whose key mode changed kept its digest")
	}
}
