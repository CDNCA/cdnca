package cachetask

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestPrewarmRejectsHeaderOnlyHitWithoutValidatedCacheEntry(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var requests atomic.Int32
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		state := "MISS"
		if requests.Add(1) == 2 {
			state = "HIT"
		}
		cacheHeaders(writer, site, state)
		_, _ = writer.Write([]byte("header-only-response"))
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "header-only-hit", ActionPrewarm, cacheURL(site, "/object"))
	task.Budget.MaxAttempts = 1

	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.State != StateFailed || len(result.Items) != 1 ||
		result.Items[0].Code != CodePrewarmNotCacheable || requests.Load() != 2 {
		t.Fatalf("result=%+v requests=%d error=%v", result, requests.Load(), err)
	}
}

func TestPrewarmCacheEvidenceAcceptsValidatedEntryAndPreservesLKGOnLookupFailure(t *testing.T) {
	t.Run("validated target entry", func(t *testing.T) {
		root := testStateRoot(t)
		var site SiteContext
		var requests atomic.Int32
		writeErrors := make(chan error, 1)
		server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			state := "MISS"
			if requests.Add(1) == 2 {
				state = "HIT"
				if err := writeCacheEntryEvidence(root, site, "/object"); err != nil {
					writeErrors <- err
				}
			}
			cacheHeaders(writer, site, state)
			_, _ = writer.Write([]byte("validated-response"))
		}))
		site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
		manager := testManager(t, root, resolverFor(site), nil)
		task := taskFor(site, "validated-hit", ActionPrewarm, cacheURL(site, "/object"))
		task.Budget.MaxAttempts = 1

		result, err := manager.Execute(context.Background(), task)
		select {
		case writeErr := <-writeErrors:
			t.Fatal(writeErr)
		default:
		}
		if err != nil || result.State != StateSucceeded || len(result.Items) != 1 ||
			result.Items[0].Code != CodePrewarmed || requests.Load() != 2 {
			t.Fatalf("result=%+v requests=%d error=%v", result, requests.Load(), err)
		}
	})

	t.Run("lookup unavailable preserves lkg", func(t *testing.T) {
		root := testStateRoot(t)
		var site SiteContext
		var requests atomic.Int32
		server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			cacheHeaders(writer, site, "HIT")
			_, _ = writer.Write([]byte("unavailable-response"))
		}))
		site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
		path := putCacheEntry(t, root, site, "/object")
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		manager := testManager(t, root, resolverFor(site), nil)
		manager.exactEntry = func(context.Context, SiteContext, normalizedTarget, *cacheScanBudget) (*cacheEntry, error) {
			return nil, errors.New("cache index unavailable")
		}
		task := taskFor(site, "evidence-unavailable", ActionPrewarm, cacheURL(site, "/object"))
		task.Budget.MaxAttempts = 1

		result, err := manager.Execute(context.Background(), task)
		after, readErr := os.ReadFile(path)
		if err != nil || readErr != nil || result.State != StateFailed || len(result.Items) != 1 ||
			result.Items[0].Code != CodeRetryExhausted || result.Items[0].CauseCode != CodePrewarmUpstream ||
			requests.Load() != 0 || string(after) != string(before) {
			t.Fatalf("result=%+v requests=%d execute_error=%v read_error=%v lkg_changed=%t",
				result, requests.Load(), err, readErr, string(after) != string(before))
		}
	})
}

func TestPrewarmCacheEvidenceRejectsInvalidMetadataBeforeHTTP(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var requests atomic.Int32
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		cacheHeaders(writer, site, "HIT")
		_, _ = writer.Write([]byte("must-not-run"))
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	path := putCacheEntry(t, root, site, "/object")
	if err := os.WriteFile(path, []byte("\x00\x00\nKEY: not-the-target\ncache-body"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "invalid-evidence", ActionPrewarm, cacheURL(site, "/object"))
	task.Budget.MaxAttempts = 1

	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.State != StateFailed || len(result.Items) != 1 ||
		result.Items[0].Code != CodeCacheMetadataInvalid || requests.Load() != 0 {
		t.Fatalf("result=%+v requests=%d error=%v", result, requests.Load(), err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("invalid evidence changed active cache: %v", statErr)
	}
}

func writeCacheEntryEvidence(root string, site SiteContext, uri string) error {
	key := cacheKeyValue(site, uri)
	path := nginxCachePath(filepath.Join(root, "shared", "cache", site.CacheIdentity), key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("\x00\x00\nKEY: %s\ncache-body", key)), 0o600)
}
