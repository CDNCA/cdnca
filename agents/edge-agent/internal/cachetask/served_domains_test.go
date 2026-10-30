package cachetask

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
)

// servedDomainsSite is a site runtime v2 site whose primary domain is a
// wildcard with an alias: the cache key names the primary, every host the
// site serves shares it.
func servedDomainsSite(prewarmPort uint16) SiteContext {
	site := testSite("tenant-a", "site-a", "config-v1", "*.x.example", 18080, prewarmPort, 1)
	site.Domains = []string{"*.x.example", "alias.example.test"}
	return site
}

func servedURL(host, uri string) string {
	return fmt.Sprintf("http://%s:18080%s", host, uri)
}

// A wildcard site prewarms each URL under its own host: the request's Host
// is the URL's host (a concrete name under the wildcard or an alias), never
// the "*." primary, and the object lands in the site's shared key.
func TestPrewarmSendsTheTargetHostForWildcardAndAliasSites(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var mutex sync.Mutex
	hosts := map[string]string{}
	var seen sync.Map
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		hosts[request.URL.Path] = request.Host
		mutex.Unlock()
		state := missThenHit(&seen, request.URL.Path)
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, request.URL.RequestURI()); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		_, _ = writer.Write([]byte("body"))
	}))
	site = servedDomainsSite(server.port())
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "served-prewarm", ActionPrewarm,
		servedURL("a.x.example", "/one"), servedURL("alias.example.test", "/two"))
	result, err := manager.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	for index, item := range result.Items {
		if item.Code != CodePrewarmed {
			t.Fatalf("item %d = %+v", index, item)
		}
	}
	if hosts["/one"] != "a.x.example" || hosts["/two"] != "alias.example.test" {
		t.Fatalf("prewarm Host by path = %v", hosts)
	}
	if result.Items[0].Target != servedURL("a.x.example", "/one") {
		t.Fatalf("public target = %q, want the requested host", result.Items[0].Target)
	}
}

// Purge accepts any host the site serves and removes the site's shared entry.
func TestPurgeAcceptsHostsCoveredByTheSite(t *testing.T) {
	root := testStateRoot(t)
	site := servedDomainsSite(0)
	manager := testManager(t, root, resolverFor(site), nil)
	for index, host := range []string{"a.x.example", "deep.a.x.example", "alias.example.test"} {
		putCacheEntry(t, root, site, "/item")
		result, err := manager.Execute(context.Background(),
			taskFor(site, fmt.Sprint("served-purge-", index), ActionPurgeExact, servedURL(host, "/item")))
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if result.Items[0].Code != CodePurged {
			t.Fatalf("%s purge = %+v", host, result.Items[0])
		}
	}
}

// The bare suffix and hosts of other sites are refused; a purge may name the
// wildcard itself (ge-cache), a prewarm may not.
func TestCacheTaskRefusesHostsOutsideTheSite(t *testing.T) {
	root := testStateRoot(t)
	site := servedDomainsSite(0)
	manager := testManager(t, root, resolverFor(site), nil)
	if _, err := manager.Execute(context.Background(),
		taskFor(site, "served-refuse-prewarm-wildcard", ActionPrewarm, servedURL("*.x.example", "/item"))); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("prewarm of a wildcard: error = %v, want ErrInvalidTask", err)
	}
	for index, host := range []string{"*.other.example", "x.example", "other.example.test", "a.alias.example.test"} {
		_, err := manager.Execute(context.Background(),
			taskFor(site, fmt.Sprint("served-refuse-", index), ActionPurgeExact, servedURL(host, "/item")))
		if !errors.Is(err, ErrInvalidTask) {
			t.Fatalf("%s: error = %v, want ErrInvalidTask", host, err)
		}
	}
}
