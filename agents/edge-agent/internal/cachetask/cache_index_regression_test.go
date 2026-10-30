package cachetask

import (
	"context"
	"os"
	"testing"
)

func TestCacheIndexRejectsStaleTopLevelFallbackForDisabledListener(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	site.Listeners = []ListenerContext{{
		Domain: site.Domain, Scheme: site.Scheme, ListenPort: site.ListenPort, CacheEnabled: false,
	}}
	manager := testManager(t, root, resolverFor(site), nil)
	entry := putCacheEntry(t, root, site, "/disabled")

	result, err := manager.Execute(context.Background(), taskFor(site, "disabled-listener-cache", ActionPurgeSite))
	if err != nil || result.State != StateFailed || result.Items[0].Code != CodeCacheMetadataInvalid {
		t.Fatalf("disabled listener result=%+v error=%v", result, err)
	}
	if _, err := os.Stat(entry); err != nil {
		t.Fatalf("disabled listener cache entry changed: %v", err)
	}
}
