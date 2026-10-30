package cachetask

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	edgeconfig "github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestCache03RuntimeSmokeEvidenceContract(t *testing.T) {
	sourcePath := smokeTestSourcePath(t)
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"PrewarmRateLimitElapsedMS",
		"RetryAttempts",
		"RetryPlanReused",
		"RetryKeptActiveCache",
		"VersionKeyPathsDiffer",
		"PurgeRemovedActiveVersionKey",
		"PurgeKeptPreviousVersionKey",
		"ListenerCacheIdentityBound",
	} {
		if !strings.Contains(string(source), marker) {
			t.Errorf("runtime smoke is missing CACHE-03 evidence %s", marker)
		}
	}

	runbookPath := filepath.Join(filepath.Dir(sourcePath), "..", "..", "..", "..", "docs", "runbooks", "cache-task-execution.md")
	runbook, err := os.ReadFile(runbookPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"timed prewarm rate bound",
		"original immutable purge plan",
		"physical cache keys across\nconfiguration versions",
	} {
		if !strings.Contains(string(runbook), statement) {
			t.Errorf("cache task runbook is missing CACHE-03 statement %q", statement)
		}
	}
}

func TestCache03PurgeRetryKeepsActiveEntryDuringBackoff(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	path := putCacheEntry(t, root, site, "/retry-active")
	manager := testManager(t, root, resolverFor(site), nil)
	manager.deleteEntries = func(context.Context, []cacheEntry) (int, error) {
		return 0, errors.New("transient cache storage failure")
	}
	sleepCalls := 0
	keptDuringBackoff := false
	manager.config.Sleep = func(ctx context.Context, _ time.Duration) error {
		sleepCalls++
		_, statErr := os.Stat(path)
		keptDuringBackoff = statErr == nil
		return ctx.Err()
	}
	task := taskFor(site, "retry-active", ActionPurgeExact, cacheURL(site, "/retry-active"))
	task.Budget.MaxAttempts = 2
	task.Budget.InitialRetryBackoff = time.Second
	task.Budget.MaximumRetryBackoff = time.Second
	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.State != StateSucceeded || result.Items[0].Code != CodePurged ||
		result.Items[0].Attempts != 2 || result.Items[0].Affected != 1 {
		t.Fatalf("purge retry result=%+v error=%v", result, err)
	}
	if sleepCalls != 1 || !keptDuringBackoff {
		t.Fatalf("retry backoff calls=%d kept_active=%t", sleepCalls, keptDuringBackoff)
	}
}

func TestCache03ProductionIdentityEvidenceAndPlanRetry(t *testing.T) {
	t.Run("cache evidence binds the indexed file identity", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		path := putCacheEntry(t, root, site, "/identity")
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		cacheRoot := filepath.Join(root, "shared", "cache", site.CacheIdentity)
		relative, err := filepath.Rel(cacheRoot, path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("\x00\x00\nKEY: "+cacheKeyValue(site, "/identity")+"\nreplacement-body"), 0o600); err != nil {
			t.Fatal(err)
		}
		digest, valid := cacheDigestFromPath(relative)
		if !valid {
			t.Fatalf("cache path %q is not a valid nginx layout", relative)
		}
		_, err = cacheEntryFromFile(context.Background(), path, cacheRoot, "", relative, digest, site,
			info, newCacheScanBudget(ResourceBudget{MaxScanEntries: 8, MaxScanBytes: 1 << 20, MaxScanDuration: time.Second}))
		var operation *operationError
		if !errors.As(err, &operation) || operation.code != CodeCacheEntryChanged {
			t.Fatalf("replacement evidence error=%v, want %s", err, CodeCacheEntryChanged)
		}
	})

	t.Run("plan cache entry change retries and then purges", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		path := putCacheEntry(t, root, site, "/retry-plan")
		manager := testManager(t, root, resolverFor(site), nil)
		calls := 0
		manager.exactEntry = func(ctx context.Context, candidate SiteContext, target normalizedTarget, budget *cacheScanBudget) (*cacheEntry, error) {
			calls++
			if calls == 1 {
				return nil, &operationError{code: CodeCacheEntryChanged, err: ErrInvalidState}
			}
			return manager.store.exactCacheEntry(ctx, candidate, target, budget)
		}
		manager.config.Sleep = func(context.Context, time.Duration) error { return nil }
		task := taskFor(site, "retry-plan", ActionPurgeExact, cacheURL(site, "/retry-plan"))
		task.Budget.MaxAttempts = 2
		result, err := manager.Execute(context.Background(), task)
		if err != nil || result.State != StateSucceeded || result.Items[0].Code != CodePurged ||
			result.Items[0].Attempts != 2 || result.Items[0].Affected != 1 || calls != 2 {
			t.Fatalf("retry result=%+v calls=%d error=%v", result, calls, err)
		}
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("retried purge left cache entry: %v", statErr)
		}
	})

	t.Run("plan cache entry change becomes retry exhausted", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		calls := 0
		manager.exactEntry = func(context.Context, SiteContext, normalizedTarget, *cacheScanBudget) (*cacheEntry, error) {
			calls++
			return nil, &operationError{code: CodeCacheEntryChanged, err: ErrInvalidState}
		}
		manager.config.Sleep = func(context.Context, time.Duration) error { return nil }
		task := taskFor(site, "retry-plan-exhausted", ActionPurgeExact, cacheURL(site, "/retry-plan-exhausted"))
		task.Budget.MaxAttempts = 2
		result, err := manager.Execute(context.Background(), task)
		if err != nil || result.State != StateFailed || result.Items[0].Code != CodeRetryExhausted ||
			result.Items[0].CauseCode != CodeCacheEntryChanged || result.Items[0].Attempts != 2 || calls != 2 {
			t.Fatalf("exhausted result=%+v calls=%d error=%v", result, calls, err)
		}
	})

	t.Run("listener host port query and version stay isolated", func(t *testing.T) {
		current := testSite("tenant-a", "site-a", "config-v2", "cache.example.test", 18080, 19080, 2)
		current.Listeners = []ListenerContext{
			{Domain: "cache.example.test", Scheme: "http", ListenPort: 18080, PrewarmPort: 19080, PrewarmPathPrefix: current.PrewarmPathPrefix, CacheEnabled: true},
			{Domain: "secure.example.test", Scheme: "https", ListenPort: 18443, PrewarmPort: 19443,
				PrewarmPathPrefix: edgeconfig.CachePrewarmPathPrefix(current.TenantID, current.SiteID, current.ConfigVersionID,
					"secure.example.test", 18443, edgeconfig.ProtocolHTTPS), CacheEnabled: true},
		}
		var valid bool
		current, valid = normalizeSiteContext(current)
		if !valid {
			t.Fatal("listener fixture is invalid")
		}
		if normalized, err := normalizeURL("https://secure.example.test:18443/asset?lang=zh", current, false); err != nil {
			t.Fatalf("listener target rejected: %v", err)
		} else {
			want := cacheKeyValue(current, "/asset?lang=zh")
			if normalized.Site.Domain != "secure.example.test" || normalized.Site.ListenPort != 18443 ||
				normalized.Site.CacheIdentity != current.CacheIdentity || want == cacheKeyValue(current, "/asset?lang=en") {
				t.Fatalf("listener/cache identity drift: target=%+v key=%q", normalized, want)
			}
		}
		previous := current
		previous.ConfigVersionID = "config-v1"
		previous.CacheIdentity = CacheNamespaceID(previous.TenantID, previous.SiteID, previous.ConfigVersionID)
		if cacheKeyValue(current, "/asset?lang=zh") == cacheKeyValue(previous, "/asset?lang=zh") {
			t.Fatal("configuration versions share a cache key")
		}
	})
}
