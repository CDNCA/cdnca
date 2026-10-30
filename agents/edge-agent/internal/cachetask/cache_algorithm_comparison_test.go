package cachetask

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheAlgorithmComparisonDedupeReplayAmplification(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("algorithm-tenant", "algorithm-site", "algorithm-config", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	putCacheEntry(t, root, site, "/dedupe")
	var effectCalls atomic.Int64
	deleteEntries := manager.deleteEntries
	manager.deleteEntries = func(ctx context.Context, entries []cacheEntry) (int, error) {
		effectCalls.Add(1)
		return deleteEntries(ctx, entries)
	}
	task := taskFor(site, "algorithm-dedupe", ActionPurgeExact, cacheURL(site, "/dedupe"))
	const deliveries = 32
	for index := 0; index < deliveries; index++ {
		result, err := manager.Execute(context.Background(), task)
		if err != nil || index == 0 && result.Replayed || index > 0 && !result.Replayed {
			t.Fatalf("delivery=%d result=%+v error=%v", index+1, result, err)
		}
	}
	currentEffects := effectCalls.Load()
	baselineEffects := int64(deliveries)
	if currentEffects != 1 {
		t.Fatalf("dedupe effect calls=%d, want 1", currentEffects)
	}
	t.Logf("CACHE_COMPARE dedupe_replay deliveries=%d current_effect_calls=%d baseline_no_dedupe_effect_calls=%d amplification_reduction=%dx",
		deliveries, currentEffects, baselineEffects, baselineEffects/currentEffects)
}

func TestCacheAlgorithmComparisonRateAndConcurrencyCost(t *testing.T) {
	bucket := newTokenBucket(200, 1)
	started := time.Now()
	for index := 0; index < 6; index++ {
		if err := bucket.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	rateWait := time.Since(started)
	if rateWait < 15*time.Millisecond || rateWait > time.Second {
		t.Fatalf("token bucket wait=%s, want bounded evidence window", rateWait)
	}

	const workers = 8
	manager := &Manager{globalSlots: make(chan struct{}, 2)}
	start := make(chan struct{})
	release := make(chan struct{})
	acquired := make(chan struct{}, workers)
	var active, maximum atomic.Int32
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if err := manager.acquireSlot(context.Background()); err != nil {
				t.Errorf("acquire slot: %v", err)
				return
			}
			current := active.Add(1)
			for observed := maximum.Load(); current > observed && !maximum.CompareAndSwap(observed, current); observed = maximum.Load() {
			}
			acquired <- struct{}{}
			<-release
			active.Add(-1)
			<-manager.globalSlots
		}()
	}
	close(start)
	for index := 0; index < cap(manager.globalSlots); index++ {
		select {
		case <-acquired:
		case <-time.After(time.Second):
			t.Fatal("bounded workers did not acquire initial slots")
		}
	}
	close(release)
	group.Wait()
	currentMaximum := maximum.Load()
	baselineMaximum := int32(workers)
	currentWaves := (workers + cap(manager.globalSlots) - 1) / cap(manager.globalSlots)
	if currentMaximum != int32(cap(manager.globalSlots)) || currentWaves != 4 {
		t.Fatalf("current maximum=%d waves=%d", currentMaximum, currentWaves)
	}
	t.Logf("CACHE_COMPARE rate_concurrency current_rate_wait_us=%d baseline_unlimited_wait_us=0 current_max_concurrency=%d baseline_max_concurrency=%d current_waves=%d baseline_waves=1",
		rateWait.Microseconds(), currentMaximum, baselineMaximum, currentWaves)
}

func TestCacheAlgorithmComparisonBoundedRetry(t *testing.T) {
	manager := &Manager{config: Config{Jitter: func(value time.Duration) time.Duration { return value }}}
	budget := ResourceBudget{InitialRetryBackoff: time.Second, MaximumRetryBackoff: 30 * time.Second}
	current := make([]time.Duration, 8)
	baseline := make([]time.Duration, 8)
	for index := range current {
		current[index] = manager.retryDelay(budget, index+1)
		baseline[index] = time.Second << index
	}
	if current[5] != 30*time.Second || current[7] != 30*time.Second || baseline[7] != 128*time.Second {
		t.Fatalf("retry current=%v baseline=%v", current, baseline)
	}
	t.Logf("CACHE_COMPARE edge_retry current=%v baseline_uncapped=%v current_max=%s baseline_max=%s",
		current, baseline, current[len(current)-1], baseline[len(baseline)-1])
}

func BenchmarkCacheAlgorithmComparisonDedupeReplay(b *testing.B) {
	root, manager, site := cacheAlgorithmBenchmarkManager(b)
	cacheAlgorithmPutEntry(b, root, site, "/benchmark")
	task := taskFor(site, "algorithm-benchmark", ActionPurgeExact, cacheURL(site, "/benchmark"))
	if _, err := manager.Execute(context.Background(), task); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		result, err := manager.Execute(context.Background(), task)
		if err != nil || !result.Replayed {
			b.Fatalf("replay=%t error=%v", result.Replayed, err)
		}
	}
}

func cacheAlgorithmBenchmarkManager(tb testing.TB) (string, *Manager, SiteContext) {
	tb.Helper()
	root := tb.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		tb.Fatal(err)
	}
	cacheRoot := filepath.Join(root, "shared", "cache")
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		tb.Fatal(err)
	}
	if err := os.Chmod(cacheRoot, 0o700); err != nil {
		tb.Fatal(err)
	}
	site := testSite("benchmark-tenant", "benchmark-site", "benchmark-config", "cache.example.test", 18080, 19080, 1)
	config := DefaultConfig()
	config.GlobalRequestsPerSecond = 100000
	config.SiteRequestsPerSecond = 100000
	config.GlobalBurst = 100
	config.SiteBurst = 100
	config.RequestTimeout = 100 * time.Millisecond
	config.MaxResponseBytes = 1 << 20
	config.MaxTaskBytes = 16 << 20
	manager, err := NewManager(root, resolverFor(site), config)
	if err != nil {
		tb.Fatal(err)
	}
	return root, manager, site
}

func cacheAlgorithmPutEntry(tb testing.TB, root string, site SiteContext, uri string) {
	tb.Helper()
	key := cacheKeyValue(site, uri)
	path := nginxCachePath(filepath.Join(root, "shared", "cache", site.CacheIdentity), key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf("\x00\x00\nKEY: %s\ncache-body", key)), 0o600); err != nil {
		tb.Fatal(err)
	}
}
