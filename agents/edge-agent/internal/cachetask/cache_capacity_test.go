package cachetask

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	cacheCapacityTargetCount = 16
	cacheCapacityEntryCount  = 65_536
)

func TestCacheTaskBulkTargetsBuildOneIndexAndInvalidateAll(t *testing.T) {
	tests := []struct {
		name             string
		configure        func(*SiteContext)
		action           Action
		entriesPerTarget int
		entryURI         func(int, int, SiteContext) string
		targetURI        func(int, SiteContext) string
	}{
		{
			name: "prefix", action: ActionPurgePrefix, entriesPerTarget: 32,
			entryURI: func(target, entry int, _ SiteContext) string {
				return fmt.Sprintf("/bulk/%02d/object-%03d?variant=%d", target, entry, entry%3)
			},
			targetURI: func(target int, _ SiteContext) string { return fmt.Sprintf("/bulk/%02d", target) },
		},
		{
			name: "advanced-exact", action: ActionPurgeExact, entriesPerTarget: 2,
			configure: func(site *SiteContext) {
				site.QueryMode = edgeconfig.CacheQueryInclude
				site.QueryNames = []string{"lang"}
				site.VaryHeaders = []string{"accept-language"}
			},
			entryURI: func(target, entry int, site SiteContext) string {
				raw := fmt.Sprintf("/asset/%02d?ignored=%d&lang=zh", target, entry)
				projected, err := cachePolicyKeyURI(site, raw, strings.Repeat(string(rune('a'+entry)), 64))
				if err != nil {
					panic(err)
				}
				return projected
			},
			targetURI: func(target int, _ SiteContext) string {
				return fmt.Sprintf("/asset/%02d?lang=zh&ignored=target", target)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := testStateRoot(t)
			site := testSite("capacity-tenant", "capacity-site", "capacity-config", "cache.example.test", 18080, 19080, 1)
			if test.configure != nil {
				test.configure(&site)
			}
			manager := testManager(t, root, resolverFor(site), nil)
			paths := make([]string, 0, cacheCapacityTargetCount*test.entriesPerTarget)
			targets := make([]string, 0, cacheCapacityTargetCount)
			for target := 0; target < cacheCapacityTargetCount; target++ {
				targets = append(targets, cacheURL(site, test.targetURI(target, site)))
				for entry := 0; entry < test.entriesPerTarget; entry++ {
					paths = append(paths, putCacheEntry(t, root, site, test.entryURI(target, entry, site)))
				}
			}
			var walks atomic.Int32
			walk := manager.walkEntries
			manager.walkEntries = func(ctx context.Context, resolved SiteContext, budget *cacheScanBudget,
				visit func(cacheEntry) error) error {
				walks.Add(1)
				return walk(ctx, resolved, budget, visit)
			}
			task := taskFor(site, "capacity-"+test.name, test.action, targets...)
			task.Budget.MaxPurgeEntries = len(paths) + 1
			task.Budget.MaxScanEntries = 100_000
			// 这里验证“一次建索引覆盖所有目标”，不是扫描速度；默认 5 秒扫描时限在高负载下会把后半批目标
			// 判为 TASK_DEADLINE_EXCEEDED，放宽时限以去掉对机器速度的依赖。
			task.Budget.MaxScanDuration = 30 * time.Second

			result, err := manager.Execute(context.Background(), task)
			if err != nil || result.State != StateSucceeded || len(result.Items) != cacheCapacityTargetCount || walks.Load() != 1 {
				t.Fatalf("bulk result=%+v walks=%d error=%v", result, walks.Load(), err)
			}
			for index := range result.Items {
				if result.Items[index].Affected != test.entriesPerTarget || result.Items[index].Code != CodePurged {
					t.Fatalf("item %d = %+v", index, result.Items[index])
				}
			}
			for _, path := range paths {
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("target cache entry remains: %s: %v", path, statErr)
				}
			}
		})
	}
}

func TestCacheTaskConcurrentBulkRefreshIsolationAndSingleIndexes(t *testing.T) {
	root := testStateRoot(t)
	siteA := testSite("capacity-tenant-a", "capacity-site-a", "capacity-config-a", "a.example.test", 18080, 19080, 1)
	siteB := testSite("capacity-tenant-b", "capacity-site-b", "capacity-config-b", "b.example.test", 18081, 19081, 1)
	manager := testManager(t, root, resolverFor(siteA, siteB), nil)
	var walks atomic.Int32
	walk := manager.walkEntries
	manager.walkEntries = func(ctx context.Context, site SiteContext, budget *cacheScanBudget,
		visit func(cacheEntry) error) error {
		walks.Add(1)
		return walk(ctx, site, budget, visit)
	}

	type workload struct {
		site    SiteContext
		id      string
		targets []string
		paths   []string
		keep    string
	}
	workloads := []*workload{{site: siteA, id: "a"}, {site: siteB, id: "b"}}
	for _, workload := range workloads {
		for target := 0; target < cacheCapacityTargetCount; target++ {
			prefix := fmt.Sprintf("/concurrent/%02d", target)
			workload.targets = append(workload.targets, cacheURL(workload.site, prefix))
			for entry := 0; entry < 4; entry++ {
				workload.paths = append(workload.paths, putCacheEntry(t, root, workload.site,
					fmt.Sprintf("%s/object-%03d", prefix, entry)))
			}
		}
		workload.keep = putCacheEntry(t, root, workload.site, "/keep/active")
	}

	start := make(chan struct{})
	results := make(chan error, len(workloads))
	var group sync.WaitGroup
	for _, workload := range workloads {
		workload := workload
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			task := taskFor(workload.site, "concurrent-capacity-"+workload.id, ActionPurgePrefix, workload.targets...)
			task.Budget.MaxPurgeEntries = len(workload.paths) + 1
			task.Budget.MaxScanEntries = 100_000
			result, err := manager.Execute(context.Background(), task)
			affected := 0
			for _, item := range result.Items {
				affected += item.Affected
			}
			if err == nil && (result.State != StateSucceeded || affected != len(workload.paths)) {
				err = fmt.Errorf("unexpected result: %+v", result)
			}
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if walks.Load() != int32(len(workloads)) {
		t.Fatalf("namespace walks=%d, want %d", walks.Load(), len(workloads))
	}
	for _, workload := range workloads {
		for _, path := range workload.paths {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("target entry remains: %s: %v", path, err)
			}
		}
		if _, err := os.Stat(workload.keep); err != nil {
			t.Fatalf("isolated active entry changed: %s: %v", workload.keep, err)
		}
	}
}

func TestCacheTaskScanFailureDoesNotMutateActiveCache(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("capacity-tenant", "capacity-site", "capacity-config", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	paths := []string{
		putCacheEntry(t, root, site, "/failure/a/one"),
		putCacheEntry(t, root, site, "/failure/b/two"),
		putCacheEntry(t, root, site, "/keep/active"),
	}
	before := make([][]byte, len(paths))
	for index, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[index] = content
	}
	walk := manager.walkEntries
	manager.walkEntries = func(ctx context.Context, resolved SiteContext, budget *cacheScanBudget,
		visit func(cacheEntry) error) error {
		visited := 0
		return walk(ctx, resolved, budget, func(entry cacheEntry) error {
			if err := visit(entry); err != nil {
				return err
			}
			visited++
			if visited == 2 {
				return &operationError{code: CodeCacheLayoutUnsafe, err: ErrInvalidState}
			}
			return nil
		})
	}
	task := taskFor(site, "capacity-scan-failure", ActionPurgePrefix,
		cacheURL(site, "/failure/a"), cacheURL(site, "/failure/b"))
	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.State != StateFailed {
		t.Fatalf("scan failure result=%+v error=%v", result, err)
	}
	for index, path := range paths {
		after, readErr := os.ReadFile(path)
		if readErr != nil || string(after) != string(before[index]) {
			t.Fatalf("active cache changed after scan failure: %s read=%v changed=%t", path, readErr, string(after) != string(before[index]))
		}
	}
}

func TestCacheTaskBulkPlanningResourceBounds(t *testing.T) {
	manager, task, record, walks := cacheCapacityPlanningFixture(cacheCapacityEntryCount)
	build := func() purgePlan {
		budget := newCacheScanBudget(task.Budget)
		plan, err := manager.buildPurgePlan(context.Background(), task, record, budget)
		if err != nil {
			t.Fatal(err)
		}
		if plan.entryCount != cacheCapacityEntryCount {
			t.Fatalf("planned entries=%d, want %d", plan.entryCount, cacheCapacityEntryCount)
		}
		return plan
	}
	build()
	walks.Store(0)
	runtime.GC()
	beforeGoroutines := runtime.NumGoroutine()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	plan := build()
	elapsed := time.Since(started)
	runtime.ReadMemStats(&after)
	if walks.Load() != 1 {
		t.Fatalf("planning walks=%d, want 1", walks.Load())
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 32<<20 {
		t.Fatalf("planning allocated=%d bytes, limit=%d", allocated, 32<<20)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("planning wall time=%s, limit=5s", elapsed)
	}
	if current := runtime.NumGoroutine(); current > beforeGoroutines+1 {
		t.Fatalf("planning goroutines before=%d after=%d", beforeGoroutines, current)
	}
	runtime.KeepAlive(plan)
}

func BenchmarkCacheTaskBulkPurgePlanning(b *testing.B) {
	manager, task, record, walks := cacheCapacityPlanningFixture(cacheCapacityEntryCount)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		plan, err := manager.buildPurgePlan(context.Background(), task, record, newCacheScanBudget(task.Budget))
		if err != nil || plan.entryCount != cacheCapacityEntryCount {
			b.Fatalf("plan entries=%d error=%v", plan.entryCount, err)
		}
		runtime.KeepAlive(plan)
	}
	b.StopTimer()
	b.ReportMetric(float64(cacheCapacityEntryCount), "entries/op")
	b.ReportMetric(float64(cacheCapacityTargetCount), "targets/op")
	b.ReportMetric(float64(walks.Load())/float64(b.N), "walks/op")
}

func cacheCapacityPlanningFixture(entryCount int) (*Manager, normalizedTask, *taskRecord, *atomic.Int64) {
	site := testSite("capacity-tenant", "capacity-site", "capacity-config", "cache.example.test", 18080, 19080, 1)
	targets := make([]normalizedTarget, cacheCapacityTargetCount)
	for index := range targets {
		targets[index] = normalizedTarget{Path: fmt.Sprintf("/capacity/%02d", index), Site: site}
	}
	task := normalizedTask{
		Task: Task{Action: ActionPurgePrefix, Budget: ResourceBudget{
			MaxPurgeEntries: entryCount + 1, MaxScanEntries: entryCount + 1,
			MaxScanBytes: int64(entryCount+1) * 64, MaxScanDuration: 30 * time.Second,
		}},
		Site: site, Targets: targets,
	}
	record := &taskRecord{Items: make([]itemRecord, len(targets))}
	entries := make([]cacheEntry, entryCount)
	for index := range entries {
		path := fmt.Sprintf("/capacity/%02d/object-%06d", index%len(targets), index)
		entries[index] = cacheEntry{relative: fmt.Sprintf("a/b/%032x", index), key: cacheKey{
			domain: site.Domain, port: site.ListenPort, uri: path, path: path,
		}}
	}
	walks := &atomic.Int64{}
	manager := &Manager{}
	manager.walkEntries = func(ctx context.Context, _ SiteContext, budget *cacheScanBudget,
		visit func(cacheEntry) error) error {
		walks.Add(1)
		for _, entry := range entries {
			if err := budget.chargeEntry(ctx); err != nil {
				return err
			}
			if err := budget.chargeBytes(ctx, 64); err != nil {
				return err
			}
			if err := visit(entry); err != nil {
				return err
			}
		}
		return nil
	}
	return manager, task, record, walks
}
