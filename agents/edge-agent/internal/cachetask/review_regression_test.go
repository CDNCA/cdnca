package cachetask

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"golang.org/x/sys/unix"
)

type observedDoneContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (ctx *observedDoneContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.observed) })
	return ctx.Context.Done()
}

func TestRunningResultPartialProgressAndOldDeliveryAttempt(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var seen sync.Map
	blockEntered := make(chan struct{}, 1)
	releaseBlock := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseBlock) }) }
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state := missThenHit(&seen, request.Host+request.URL.Path)
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, request.URL.RequestURI()); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		if request.URL.Path == "/block" {
			blockEntered <- struct{}{}
			<-releaseBlock
		}
		_, _ = writer.Write([]byte("ok"))
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "running-progress", ActionPrewarm, cacheURL(site, "/fast"), cacheURL(site, "/block"))
	task.Budget.MaxConcurrency = 2
	done := make(chan struct{})
	defer func() {
		release()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("prewarm goroutine did not finish during cleanup")
		}
	}()
	go func() {
		defer close(done)
		if _, err := manager.Execute(context.Background(), task); err != nil {
			t.Errorf("Execute error = %v", err)
		}
	}()
	select {
	case <-blockEntered:
	case <-time.After(time.Second):
		t.Fatal("blocking prewarm did not start")
	}

	var running Result
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		value, err := manager.Lookup(context.Background(), taskReference(task))
		if err == nil && value.State == StateRunning && value.Progress.Completed == 1 {
			running = value
			break
		}
		time.Sleep(time.Millisecond)
	}
	if running.State != StateRunning || running.Progress.Completed != 1 || running.Progress.Succeeded != 1 ||
		running.Progress.Failed != 0 || running.Items[0].Affected != 0 || running.Items[1].Status != ItemWorking ||
		!running.CompletedAt.IsZero() {
		t.Fatalf("running result = %+v", running)
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("prewarm did not finish")
	}

	purgeManager := testManager(t, root, resolverFor(site), nil)
	current := taskFor(site, "old-running", ActionPurgeExact, cacheURL(site, "/old"))
	current.DeliveryAttempt = 2
	normalized, err := normalizeTask(current, site, purgeManager.config, purgeManager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := purgeManager.store.prepare(context.Background(), normalized, purgeManager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record.Items[0].Status = recordWorking
	record.Items[0].Attempts = 1
	if err := purgeManager.store.update(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	old := current
	old.DeliveryAttempt = 1
	replayed, err := purgeManager.Execute(context.Background(), old)
	if err != nil || !replayed.Replayed || replayed.State != StateRunning || replayed.Attempt != 1 ||
		replayed.DeliveryAttempt != 2 || replayed.Progress.Completed != 0 || replayed.Items[0].Status != ItemWorking {
		t.Fatalf("old delivery replay = %+v, error = %v", replayed, err)
	}
	lookup, err := purgeManager.Lookup(context.Background(), taskReference(current))
	if err != nil || lookup.Attempt != 1 || lookup.State != StateRunning {
		t.Fatalf("lookup after old delivery = %+v, error = %v", lookup, err)
	}
}

func TestPurgeCancelSettlementIdentityAndAffected(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	paths := make([]string, 64)
	for index := range paths {
		paths[index] = putCacheEntry(t, root, site, fmt.Sprintf("/cancel/%02d", index))
	}
	originalDelete := manager.deleteEntries
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	manager.deleteEntries = func(ctx context.Context, entries []cacheEntry) (int, error) {
		once.Do(func() { close(entered) })
		deleted, err := originalDelete(context.Background(), entries)
		<-release
		if err != nil {
			return deleted, err
		}
		if ctx.Err() != nil {
			return deleted, ctx.Err()
		}
		return deleted, nil
	}
	originalWrite := manager.store.writeJSON
	var writes atomic.Int64
	manager.store.writeJSON = func(tmpDir, statePath string, value any) error {
		writes.Add(1)
		return originalWrite(tmpDir, statePath, value)
	}
	task := taskFor(site, "purge-cancel", ActionPurgePrefix, cacheURL(site, "/cancel"))
	executeResult := make(chan Result, 1)
	executeErr := make(chan error, 1)
	go func() {
		result, err := manager.Execute(context.Background(), task)
		executeResult <- result
		executeErr <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("delete did not enter")
	}

	wrong := taskReference(task)
	wrong.OperationID = "operation-wrong"
	if _, err := manager.Cancel(context.Background(), wrong); !errors.Is(err, ErrTaskNotFound) {
		t.Fatalf("wrong reference cancel error = %v", err)
	}
	select {
	case result := <-executeResult:
		t.Fatalf("wrong reference stopped task: %+v", result)
	default:
	}

	cancelResult := make(chan Result, 1)
	cancelErr := make(chan error, 1)
	go func() {
		result, err := manager.Cancel(context.Background(), taskReference(task))
		cancelResult <- result
		cancelErr <- err
	}()
	select {
	case result := <-cancelResult:
		t.Fatalf("Cancel returned before delete settlement: %+v", result)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	cancelled := <-cancelResult
	if err := <-cancelErr; err != nil || cancelled.State != StateCancelled || cancelled.Items[0].Affected != 1 ||
		cancelled.Items[0].Code != CodeTaskCancelled {
		t.Fatalf("cancelled = %+v, error = %v", cancelled, err)
	}
	if result, err := <-executeResult, <-executeErr; err != nil || result.State != StateCancelled || result.Items[0].Affected != 1 {
		t.Fatalf("execute result = %+v, error = %v", result, err)
	}
	remaining := 0
	var remainingParent string
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			remaining++
			remainingParent = filepath.Dir(path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	if remaining != len(paths)-1 {
		t.Fatalf("remaining cache entries=%d want=%d", remaining, len(paths)-1)
	}
	settledWrites := writes.Load()
	parentBefore, err := os.Stat(remainingParent)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if writes.Load() != settledWrites {
		t.Fatalf("journal changed after Cancel returned: before=%d after=%d", settledWrites, writes.Load())
	}
	parentAfter, err := os.Stat(remainingParent)
	if err != nil || !parentAfter.ModTime().Equal(parentBefore.ModTime()) {
		t.Fatalf("cache directory changed after Cancel returned: before=%v after=%v error=%v",
			parentBefore.ModTime(), parentAfter.ModTime(), err)
	}
	restarted := testManager(t, root, resolverFor(site), nil)
	lookup, err := restarted.Lookup(context.Background(), taskReference(task))
	if err != nil || lookup.State != StateCancelled || lookup.Items[0].Affected != 1 {
		t.Fatalf("restart lookup = %+v, error = %v", lookup, err)
	}
}

func TestCancelTimeoutDoesNotClaimTerminalState(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), func(config *Config) {
		config.CancelSettlementTimeout = 20 * time.Millisecond
	})
	putCacheEntry(t, root, site, "/slow-cancel")
	originalDelete := manager.deleteEntries
	entered := make(chan struct{})
	release := make(chan struct{})
	manager.deleteEntries = func(_ context.Context, entries []cacheEntry) (int, error) {
		close(entered)
		<-release
		return originalDelete(context.Background(), entries)
	}
	task := taskFor(site, "slow-cancel", ActionPurgeExact, cacheURL(site, "/slow-cancel"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = manager.Execute(context.Background(), task)
	}()
	<-entered
	result, err := manager.Cancel(context.Background(), taskReference(task))
	if err == nil || result.State == StateCancelled {
		t.Fatalf("timeout claimed cancellation: result=%+v error=%v", result, err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("execute did not settle after release")
	}
	lookup, err := manager.Lookup(context.Background(), taskReference(task))
	if err != nil || lookup.State != StateCancelled || lookup.Items[0].Affected != 1 {
		t.Fatalf("eventual terminal result=%+v error=%v", lookup, err)
	}
}

func TestPendingMixedAndSiteWaitCancellation(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "mixed-cancel", ActionPurgeExact, cacheURL(site, "/one"), cacheURL(site, "/two"))
	normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record.Items[0].Status = recordWorking
	record.Items[0].Attempts = 1
	if err := manager.store.update(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	cancelled, err := manager.Cancel(context.Background(), taskReference(task))
	if err != nil || cancelled.State != StateCancelled || cancelled.Items[0].Attempts != 1 ||
		cancelled.Items[1].Attempts != 0 || cancelled.Progress.Completed != 2 {
		t.Fatalf("mixed cancel = %+v, error = %v", cancelled, err)
	}
	restarted := testManager(t, root, resolverFor(site), nil)
	replayed, err := restarted.Execute(context.Background(), task)
	if err != nil || !replayed.Replayed || replayed.State != StateCancelled || replayed.Items[1].Attempts != 0 {
		t.Fatalf("cancel replay = %+v, error = %v", replayed, err)
	}

	waitRoot := testStateRoot(t)
	waitManager := testManager(t, waitRoot, resolverFor(site), nil)
	unlock, err := waitManager.lockLocal(context.Background(), "site:"+site.CacheIdentity)
	if err != nil {
		t.Fatal(err)
	}
	waitTask := taskFor(site, "site-wait", ActionPurgeExact, cacheURL(site, "/wait"))
	waitDone := make(chan Result, 1)
	go func() {
		result, _ := waitManager.Execute(context.Background(), waitTask)
		waitDone <- result
	}()
	waitForRunningLookup(t, waitManager, waitTask)
	waitCancelled, err := waitManager.Cancel(context.Background(), taskReference(waitTask))
	if err != nil || waitCancelled.State != StateCancelled || waitCancelled.Items[0].Attempts != 0 {
		t.Fatalf("site waiter cancel = %+v, error = %v", waitCancelled, err)
	}
	if result := <-waitDone; result.State != StateCancelled || result.Items[0].Attempts != 0 {
		t.Fatalf("site waiter execute = %+v", result)
	}
	deadlineTask := taskFor(site, "site-wait-deadline", ActionPurgeExact, cacheURL(site, "/deadline"))
	deadlineTask.Deadline = time.Now().Add(30 * time.Millisecond)
	deadlineResult, err := waitManager.Execute(context.Background(), deadlineTask)
	if err != nil || deadlineResult.State != StateFailed || deadlineResult.Items[0].Code != CodeTaskDeadlineExceeded ||
		deadlineResult.Items[0].Attempts != 0 {
		t.Fatalf("site waiter deadline = %+v, error = %v", deadlineResult, err)
	}
	unlock()

	held, err := waitManager.lockLocal(context.Background(), "waiter-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := waitManager.lockLocal(ctx, "waiter-cleanup"); !errors.Is(err, context.Canceled) {
				t.Errorf("waiter error = %v", err)
			}
		}()
	}
	wait.Wait()
	waitManager.locksMu.Lock()
	refs := waitManager.localLocks["waiter-cleanup"].refs
	waitManager.locksMu.Unlock()
	if refs != 1 {
		t.Fatalf("remaining waiter refs = %d", refs)
	}
	held()
	waitManager.locksMu.Lock()
	remainingLocks := len(waitManager.localLocks)
	waitManager.locksMu.Unlock()
	if remainingLocks != 0 {
		t.Fatalf("local lock registry not empty: %d", remainingLocks)
	}
}

func waitForRunningLookup(t *testing.T, manager *Manager, task Task) Result {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		result, err := manager.Lookup(context.Background(), taskReference(task))
		if err == nil && result.State == StateRunning {
			return result
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("task did not become queryable as running")
	return Result{}
}

func TestPurgeScanBudgetsAndExactDirectIndex(t *testing.T) {
	t.Run("exact-direct-index", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		path := putCacheEntry(t, root, site, "/exact")
		manager.walkEntries = func(context.Context, SiteContext, *cacheScanBudget, func(cacheEntry) error) error {
			return errors.New("exact purge walked namespace")
		}
		task := taskFor(site, "direct-index", ActionPurgeExact, cacheURL(site, "/exact"))
		task.Budget.MaxScanEntries = 1
		task.Budget.MaxScanBytes = maxCacheMetadataBytes
		result, err := manager.Execute(context.Background(), task)
		if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 {
			t.Fatalf("exact result = %+v, error = %v", result, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("exact cache remains: %v", err)
		}
	})

	t.Run("entry-byte-time-bounds", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		paths := make([]string, 0, 100)
		for index := 0; index < 100; index++ {
			paths = append(paths, putCacheEntry(t, root, site, fmt.Sprintf("/scan/%03d", index)))
		}
		originalWalk := manager.walkEntries
		var observed *cacheScanBudget
		manager.walkEntries = func(ctx context.Context, site SiteContext, budget *cacheScanBudget, visit func(cacheEntry) error) error {
			observed = budget
			return originalWalk(ctx, site, budget, visit)
		}
		entryTask := taskFor(site, "scan-entries", ActionPurgePrefix, cacheURL(site, "/scan"))
		entryTask.Budget.MaxScanEntries = 5
		result, err := manager.Execute(context.Background(), entryTask)
		if err != nil || result.Items[0].Code != CodePurgeScanBudgetExceeded || observed == nil || observed.entries != 5 {
			t.Fatalf("entry budget result=%+v observed=%+v error=%v", result, observed, err)
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("entry budget deleted %s: %v", path, err)
			}
		}

		byteTask := taskFor(site, "scan-bytes", ActionPurgeExact, cacheURL(site, "/scan/000"))
		byteTask.Budget.MaxScanBytes = 1
		result, err = manager.Execute(context.Background(), byteTask)
		if err != nil || result.Items[0].Code != CodePurgeScanBudgetExceeded {
			t.Fatalf("byte budget result=%+v error=%v", result, err)
		}

		manager.walkEntries = func(ctx context.Context, site SiteContext, budget *cacheScanBudget, visit func(cacheEntry) error) error {
			time.Sleep(3 * time.Millisecond)
			return originalWalk(ctx, site, budget, visit)
		}
		timeTask := taskFor(site, "scan-time", ActionPurgePrefix, cacheURL(site, "/scan"))
		timeTask.Budget.MaxScanDuration = time.Millisecond
		result, err = manager.Execute(context.Background(), timeTask)
		if err != nil || result.Items[0].Code != CodePurgeScanBudgetExceeded {
			t.Fatalf("time budget result=%+v error=%v", result, err)
		}
	})
}

func TestAdvancedExactPurgeDeletesAllHeaderVariantsForEffectiveQuery(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	site.QueryMode = edgeconfig.CacheQueryInclude
	site.QueryNames = []string{"lang"}
	site.VaryHeaders = []string{"accept-language"}
	manager := testManager(t, root, resolverFor(site), nil)

	matchingURI := "/asset?ignored=1&lang=zh&lang=zh"
	variantA, err := cachePolicyKeyURI(site, matchingURI, strings.Repeat("a", sha256.Size*2))
	if err != nil {
		t.Fatal(err)
	}
	variantB, err := cachePolicyKeyURI(site, matchingURI, strings.Repeat("b", sha256.Size*2))
	if err != nil {
		t.Fatal(err)
	}
	otherURI, err := cachePolicyKeyURI(site, "/asset?lang=en", strings.Repeat("c", sha256.Size*2))
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		putCacheEntry(t, root, site, variantA),
		putCacheEntry(t, root, site, variantB),
		putCacheEntry(t, root, site, otherURI),
	}
	task := taskFor(site, "advanced-exact-variants", ActionPurgeExact, cacheURL(site, matchingURI))
	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 2 {
		t.Fatalf("advanced exact purge result=%+v error=%v", result, err)
	}
	for index, path := range paths {
		_, statErr := os.Stat(path)
		if index < 2 && !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("matching variant %d remains: %v", index, statErr)
		}
		if index == 2 && statErr != nil {
			t.Fatalf("different effective query was deleted: %v", statErr)
		}
	}
}

func TestCachePolicyQueryProjectionIsStrictAndOrderPreserving(t *testing.T) {
	names := []string{"lang"}
	digest := func(uri string) string {
		t.Helper()
		value, err := cachePolicyQueryDigest(edgeconfig.CacheQueryInclude, names, uri)
		if err != nil {
			t.Fatalf("cachePolicyQueryDigest(%q) error = %v", uri, err)
		}
		return value
	}
	if digest("/asset?lang=zh&ignored=1") != digest("/asset?lang=zh&ignored=2") {
		t.Fatal("include mode retained an unselected query pair")
	}
	if digest("/asset?lang=zh&lang=en") == digest("/asset?lang=en&lang=zh") {
		t.Fatal("include mode lost selected raw pair order")
	}
	if digest("/asset?lang") == digest("/asset?lang=") {
		t.Fatal("query projection merged key-only and empty-value pairs")
	}
	if digest("/asset") == digest("/asset?") {
		t.Fatal("query projection merged absent and explicit-empty queries")
	}
	if digest("/asset?la%6Eg=zh&ignored=1") != digest("/asset?la%6Eg=zh&ignored=2") ||
		digest("/asset?la%6Eg=zh") == digest("/asset?ignored=zh") {
		t.Fatal("query name was not decoded exactly once while preserving selected raw bytes")
	}
	for _, invalid := range []string{"/asset?lang=%", "/asset?la%GGng=zh", "/asset?" + strings.Repeat("x", cachePolicyMaxRawQueryBytes+1)} {
		if _, err := cachePolicyQueryDigest(edgeconfig.CacheQueryInclude, names, invalid); err == nil {
			t.Fatalf("invalid query %q did not fail closed", invalid)
		}
	}
}

func TestJournalRestartPreservesAdvancedCachePolicyBinding(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	site.QueryMode = edgeconfig.CacheQueryInclude
	site.QueryNames = []string{"lang"}
	site.VaryHeaders = []string{"accept-language"}
	site.CacheRules = []edgeconfig.CacheRuleDocument{{
		Order: 1, PathPrefix: "/asset/", Extensions: []string{".js"}, StatusCodes: []int{200}, TTLSeconds: 60,
	}}
	manager := testManager(t, root, resolverFor(site), nil)
	matchingURI := "/asset/app.js?ignored=1&lang=zh"
	task := taskFor(site, "advanced-restart-binding", ActionPurgeExact, cacheURL(site, matchingURI))
	normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, replayed, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC()); err != nil || replayed {
		t.Fatalf("prepare replayed=%t error=%v", replayed, err)
	}
	variantA, err := cachePolicyKeyURI(site, matchingURI, strings.Repeat("a", sha256.Size*2))
	if err != nil {
		t.Fatal(err)
	}
	variantB, err := cachePolicyKeyURI(site, matchingURI, strings.Repeat("b", sha256.Size*2))
	if err != nil {
		t.Fatal(err)
	}
	otherURI, err := cachePolicyKeyURI(site, "/asset/app.js?lang=en", strings.Repeat("c", sha256.Size*2))
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		putCacheEntry(t, root, site, variantA),
		putCacheEntry(t, root, site, variantB),
		putCacheEntry(t, root, site, otherURI),
	}

	restarted := testManager(t, root, resolverFor(site), nil)
	journalSite, found, err := restarted.store.journalSite(context.Background(), task)
	if err != nil || !found || journalSite.QueryMode != site.QueryMode ||
		!slices.Equal(journalSite.QueryNames, site.QueryNames) || !slices.Equal(journalSite.VaryHeaders, site.VaryHeaders) ||
		len(journalSite.CacheRules) != 1 || journalSite.CacheRules[0].PathPrefix != "/asset/" {
		t.Fatalf("restarted journal site=%+v found=%t error=%v", journalSite, found, err)
	}
	result, err := restarted.Execute(context.Background(), task)
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 2 {
		t.Fatalf("restarted advanced purge=%+v error=%v", result, err)
	}
	for index, path := range paths {
		_, statErr := os.Stat(path)
		if index < 2 && !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("matching restarted variant %d remains: %v", index, statErr)
		}
		if index == 2 && statErr != nil {
			t.Fatalf("different restarted query was deleted: %v", statErr)
		}
	}
}

func TestJournalRejectsIncompleteAdvancedCachePolicyBinding(t *testing.T) {
	for _, field := range []string{"cache_policy_schema_version", "cache_policy_sha256", "query_mode", "query_names", "vary_headers", "cache_rules"} {
		t.Run(field, func(t *testing.T) {
			root := testStateRoot(t)
			site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
			site.QueryMode = edgeconfig.CacheQueryInclude
			site.QueryNames = []string{"lang"}
			site.VaryHeaders = []string{"accept-language"}
			site.CacheRules = []edgeconfig.CacheRuleDocument{{Order: 1, StatusCodes: []int{200}, TTLSeconds: 60}}
			manager := testManager(t, root, resolverFor(site), nil)
			task := taskFor(site, "incomplete-binding-"+strings.ReplaceAll(field, "_", "-"), ActionPurgeExact,
				cacheURL(site, "/asset?lang=zh"))
			normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC()); err != nil {
				t.Fatal(err)
			}
			path := manager.store.taskPath(task.TaskID)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(content, &document); err != nil {
				t.Fatal(err)
			}
			binding, ok := document["site_binding"].(map[string]any)
			if !ok {
				t.Fatal("journal site binding is not an object")
			}
			delete(binding, field)
			candidate, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, candidate, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewManager(root, resolverFor(site), manager.config); !errors.Is(err, ErrJournalCorrupt) {
				t.Fatalf("NewManager() error = %v, want ErrJournalCorrupt", err)
			}
		})
	}
}

func TestJournalRejectsSemanticallyMutatedAdvancedCachePolicyBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, binding map[string]any)
	}{
		{name: "query mode", mutate: func(t *testing.T, binding map[string]any) {
			binding["query_mode"] = string(edgeconfig.CacheQueryExclude)
		}},
		{name: "query names", mutate: func(t *testing.T, binding map[string]any) {
			binding["query_names"] = []any{"theme"}
		}},
		{name: "vary headers", mutate: func(t *testing.T, binding map[string]any) {
			binding["vary_headers"] = []any{"x-device"}
		}},
		{name: "cache rule", mutate: func(t *testing.T, binding map[string]any) {
			rules, ok := binding["cache_rules"].([]any)
			if !ok || len(rules) != 1 {
				t.Fatal("journal cache rules are not a one-element array")
			}
			rule, ok := rules[0].(map[string]any)
			if !ok {
				t.Fatal("journal cache rule is not an object")
			}
			rule["ttl_seconds"] = float64(61)
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := testStateRoot(t)
			site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
			site.QueryMode = edgeconfig.CacheQueryInclude
			site.QueryNames = []string{"lang"}
			site.VaryHeaders = []string{"accept-language"}
			site.CacheRules = []edgeconfig.CacheRuleDocument{{Order: 1, StatusCodes: []int{200}, TTLSeconds: 60}}
			manager := testManager(t, root, resolverFor(site), nil)
			task := taskFor(site, "semantic-binding-"+strings.ReplaceAll(testCase.name, " ", "-"), ActionPurgeExact,
				cacheURL(site, "/asset?lang=zh"))
			normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC()); err != nil {
				t.Fatal(err)
			}
			path := manager.store.taskPath(task.TaskID)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(content, &document); err != nil {
				t.Fatal(err)
			}
			binding, ok := document["site_binding"].(map[string]any)
			if !ok {
				t.Fatal("journal site binding is not an object")
			}
			testCase.mutate(t, binding)
			candidate, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, candidate, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewManager(root, resolverFor(site), manager.config); !errors.Is(err, ErrJournalCorrupt) {
				t.Fatalf("NewManager() error = %v, want ErrJournalCorrupt", err)
			}
		})
	}
}

func TestCachePolicyBindingDigestCoversCompletePopulatedSiteBinding(t *testing.T) {
	const (
		tenantID = "11111111-1111-4111-8111-111111111111"
		siteID   = "22222222-2222-4222-8222-222222222222"
		version  = "33333333-3333-4333-8333-333333333333"
	)
	site := testSite(tenantID, siteID, version, "cache.example.test", 18080, 19080, 47)
	site.ActiveReleaseSHA256 = strings.Repeat("a", sha256.Size*2)
	site.NginxSHA256 = strings.Repeat("b", sha256.Size*2)
	site.QueryMode = edgeconfig.CacheQueryInclude
	site.QueryNames = []string{"lang"}
	site.VaryHeaders = []string{"accept-language"}
	site.CacheRules = []edgeconfig.CacheRuleDocument{{Order: 1, PathPrefix: "/asset/", StatusCodes: []int{200}, TTLSeconds: 60}}
	site.Listeners = []ListenerContext{
		{Domain: site.Domain, Scheme: site.Scheme, ListenPort: site.ListenPort, PrewarmPort: site.PrewarmPort,
			PrewarmPathPrefix: site.PrewarmPathPrefix, CacheEnabled: true},
		{Domain: "static.example.test", Scheme: "http", ListenPort: 18081, PrewarmPort: 19080,
			PrewarmPathPrefix: edgeconfig.CachePrewarmPathPrefix(tenantID, siteID, version, "static.example.test", 18081, edgeconfig.ProtocolHTTP),
			CacheEnabled:      true},
	}
	binding := siteBindingFromContext(site)
	if len(binding.Listeners) != 2 || binding.CachePolicySHA256 != cachePolicyBindingSHA256(binding) {
		t.Fatalf("populated binding digest = %+v", binding)
	}
	mutations := map[string]func(*siteBinding){
		"release SHA": func(value *siteBinding) { value.ActiveReleaseSHA256 = strings.Repeat("c", sha256.Size*2) },
		"Nginx SHA":   func(value *siteBinding) { value.NginxSHA256 = strings.Repeat("d", sha256.Size*2) },
		"namespace":   func(value *siteBinding) { value.CacheIdentity = strings.Repeat("e", sha256.Size*2) },
		"listener domain": func(value *siteBinding) {
			value.Listeners[1].Domain = "other.example.test"
		},
		"listener path": func(value *siteBinding) {
			value.Listeners[1].PrewarmPathPrefix = "/.cdnca-internal/cache-task/v2/00000000000000000000000000000000/"
		},
		"listener port": func(value *siteBinding) { value.Listeners[1].ListenPort++ },
		"policy":        func(value *siteBinding) { value.QueryNames = []string{"theme"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := binding
			candidate.QueryNames = append([]string(nil), binding.QueryNames...)
			candidate.VaryHeaders = append([]string(nil), binding.VaryHeaders...)
			candidate.CacheRules = copyCacheRuleDocuments(binding.CacheRules)
			candidate.Listeners = append([]listenerBinding(nil), binding.Listeners...)
			mutate(&candidate)
			if digest := cachePolicyBindingSHA256(candidate); digest == binding.CachePolicySHA256 {
				t.Fatalf("%s is not covered by binding digest %s", name, digest)
			}
		})
	}
}

func TestJournalRejectsFullBindingMutationWithLegacySynchronizedDigest(t *testing.T) {
	const (
		tenantID = "11111111-1111-4111-8111-111111111111"
		siteID   = "22222222-2222-4222-8222-222222222222"
		version  = "33333333-3333-4333-8333-333333333333"
	)
	root := testStateRoot(t)
	site := testSite(tenantID, siteID, version, "cache.example.test", 18080, 19080, 47)
	site.QueryMode = edgeconfig.CacheQueryInclude
	site.QueryNames = []string{"lang"}
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "full-binding-synchronized-digest", ActionPurgeExact, cacheURL(site, "/asset?lang=zh"))
	normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC()); err != nil {
		t.Fatal(err)
	}
	path := manager.store.taskPath(task.TaskID)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	binding, ok := document["site_binding"].(map[string]any)
	if !ok {
		t.Fatal("journal site binding is not an object")
	}
	binding["active_release_sha256"] = strings.Repeat("a", sha256.Size*2)
	binding["nginx_sha256"] = strings.Repeat("b", sha256.Size*2)
	binding["cache_policy_sha256"] = legacyCachePolicyBindingDigest(t, binding)
	candidate, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, candidate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(root, resolverFor(site), manager.config); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("NewManager() error = %v, want ErrJournalCorrupt", err)
	}
}

func legacyCachePolicyBindingDigest(t *testing.T, binding map[string]any) string {
	t.Helper()
	document := struct {
		SchemaVersion any `json:"schema_version"`
		QueryMode     any `json:"query_mode"`
		QueryNames    any `json:"query_names"`
		VaryHeaders   any `json:"vary_headers"`
		CacheRules    any `json:"cache_rules"`
	}{
		SchemaVersion: binding["cache_policy_schema_version"], QueryMode: binding["query_mode"],
		QueryNames: binding["query_names"], VaryHeaders: binding["vary_headers"], CacheRules: binding["cache_rules"],
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func TestPurgeAffectedDurableAcrossRetryExhaustionAndRecovery(t *testing.T) {
	t.Run("partial-retry", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		putCacheEntry(t, root, site, "/partial/a")
		putCacheEntry(t, root, site, "/partial/b")
		original := manager.deleteEntries
		calls := 0
		manager.deleteEntries = func(ctx context.Context, entries []cacheEntry) (int, error) {
			calls++
			if calls == 2 {
				return 0, &operationError{code: CodeCacheDeleteFailed, err: errors.New("injected delete failure")}
			}
			return original(ctx, entries)
		}
		task := taskFor(site, "partial-retry", ActionPurgePrefix, cacheURL(site, "/partial"))
		result, err := manager.Execute(context.Background(), task)
		if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 2 || result.Items[0].Attempts != 2 {
			t.Fatalf("partial retry result=%+v calls=%d error=%v", result, calls, err)
		}
	})

	t.Run("fsync-error-then-recover", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		putCacheEntry(t, root, site, "/fsync")
		original := manager.deleteEntries
		first := true
		manager.deleteEntries = func(ctx context.Context, entries []cacheEntry) (int, error) {
			deleted, err := original(ctx, entries)
			if first {
				first = false
				return deleted, &operationError{code: CodeCacheDeleteFailed, err: errors.New("injected parent fsync failure")}
			}
			return deleted, err
		}
		result, err := manager.Execute(context.Background(), taskFor(site, "fsync-retry", ActionPurgeExact, cacheURL(site, "/fsync")))
		if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 || result.Items[0].Attempts != 2 {
			t.Fatalf("fsync retry result=%+v error=%v", result, err)
		}
	})

	t.Run("retry-exhausted", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		resolver := resolverFor(site)
		manager := testManager(t, root, resolver, nil)
		paths := []string{
			putCacheEntry(t, root, site, "/exhaust/a"),
			putCacheEntry(t, root, site, "/exhaust/b"),
		}
		original := manager.deleteEntries
		calls := 0
		manager.deleteEntries = func(ctx context.Context, entries []cacheEntry) (int, error) {
			calls++
			if calls > 1 {
				return 0, &operationError{code: CodeCacheDeleteFailed, err: errors.New("persistent delete failure")}
			}
			return original(ctx, entries)
		}
		task := taskFor(site, "affected-exhaust", ActionPurgePrefix, cacheURL(site, "/exhaust"))
		task.Budget.MaxAttempts = 2
		result, err := manager.Execute(context.Background(), task)
		if err != nil || result.State != StateSucceeded || result.Items[0].Code != CodePurged || result.Items[0].Affected != 2 {
			t.Fatalf("exhausted result=%+v calls=%d error=%v", result, calls, err)
		}
		remaining := 0
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				remaining++
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
		if remaining != 0 {
			t.Fatalf("remaining cache entries = %d", remaining)
		}
		restarted := testManager(t, root, resolver, nil)
		lookup, err := restarted.Lookup(context.Background(), taskReference(task))
		if err != nil || lookup.Items[0].Affected != 2 || lookup.Items[0].Code != CodePurged {
			t.Fatalf("restart lookup=%+v error=%v", lookup, err)
		}
	})

	t.Run("intent-recovery-without-retry-budget", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		resolver := resolverFor(site)
		manager := testManager(t, root, resolver, nil)
		path := putCacheEntry(t, root, site, "/intent-crash")
		task := taskFor(site, "intent-no-retry", ActionPurgeExact, cacheURL(site, "/intent-crash"))
		task.Budget.MaxAttempts = 1
		original := manager.store.writeJSON
		writes := 0
		manager.store.writeJSON = func(tmpDir, statePath string, value any) error {
			writes++
			if writes == 6 {
				return errors.New("injected affected checkpoint failure")
			}
			return original(tmpDir, statePath, value)
		}
		if _, err := manager.Execute(context.Background(), task); !errors.Is(err, ErrJournalWrite) {
			t.Fatalf("checkpoint failure error = %v", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("intent crash did not remove cache: %v", err)
		}
		restarted := testManager(t, root, resolver, nil)
		result, err := restarted.Execute(context.Background(), task)
		if err != nil || result.State != StateFailed || result.Items[0].Affected != 1 ||
			result.Items[0].Code != CodeRetryExhausted || result.Items[0].CauseCode != CodeCacheDeleteFailed ||
			result.Items[0].Attempts != 1 {
			t.Fatalf("intent recovery result=%+v error=%v", result, err)
		}
	})
}

func TestRegistryGCAndTombstoneCapacity(t *testing.T) {
	t.Run("retention-crash-and-restart", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		config := func(value *Config) {
			value.RetainCompletedTasks = 2
			value.MaxRegistryTasks = 4
			value.MaxTombstoneTasks = 10
		}
		manager := testManager(t, root, resolverFor(site), config)
		tasks := make([]Task, 4)
		for index := range tasks {
			tasks[index] = taskFor(site, fmt.Sprintf("gc-%d", index), ActionPurgeExact, cacheURL(site, fmt.Sprintf("/gc-%d", index)))
			if _, err := manager.Execute(context.Background(), tasks[index]); err != nil {
				t.Fatal(err)
			}
		}
		originalWrite := manager.store.writeJSON
		failRegistry := true
		manager.store.writeJSON = func(tmpDir, path string, value any) error {
			if failRegistry && path == manager.store.registryPath {
				return errors.New("injected registry compaction failure")
			}
			return originalWrite(tmpDir, path, value)
		}
		fifth := taskFor(site, "gc-4", ActionPurgeExact, cacheURL(site, "/gc-4"))
		if _, err := manager.Execute(context.Background(), fifth); !errors.Is(err, ErrJournalWrite) {
			t.Fatalf("compaction failure error = %v", err)
		}
		if replay, err := manager.Lookup(context.Background(), taskReference(tasks[0])); err != nil || replay.State != StateSucceeded {
			t.Fatalf("pre-registry-crash replay=%+v error=%v", replay, err)
		}
		failRegistry = false
		if _, err := manager.Execute(context.Background(), fifth); err != nil {
			t.Fatal(err)
		}
		for _, expired := range tasks[:2] {
			if _, err := manager.Lookup(context.Background(), taskReference(expired)); !errors.Is(err, ErrTaskExpired) {
				t.Fatalf("expired lookup error = %v", err)
			}
		}
		operationReuse := taskFor(site, "gc-operation-reuse", ActionPurgeExact, cacheURL(site, "/reuse"))
		operationReuse.OperationID = tasks[0].OperationID
		if _, err := manager.Execute(context.Background(), operationReuse); !errors.Is(err, ErrTaskExpired) {
			t.Fatalf("expired operation reuse error = %v", err)
		}
		restarted := testManager(t, root, resolverFor(site), config)
		if _, err := restarted.Lookup(context.Background(), taskReference(tasks[0])); !errors.Is(err, ErrTaskExpired) {
			t.Fatalf("restart expired lookup error = %v", err)
		}
		entries, err := os.ReadDir(restarted.store.tasksDir)
		if err != nil || len(entries) != 3 {
			t.Fatalf("retained task files=%d error=%v", len(entries), err)
		}
	})

	t.Run("registry-activated-before-reported-error", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		config := func(value *Config) {
			value.RetainCompletedTasks = 2
			value.MaxRegistryTasks = 4
			value.MaxTombstoneTasks = 10
		}
		manager := testManager(t, root, resolverFor(site), config)
		tasks := make([]Task, 4)
		for index := range tasks {
			tasks[index] = taskFor(site, fmt.Sprintf("gc-activated-%d", index), ActionPurgeExact,
				cacheURL(site, fmt.Sprintf("/gc-activated-%d", index)))
			if _, err := manager.Execute(context.Background(), tasks[index]); err != nil {
				t.Fatal(err)
			}
		}
		originalWrite := manager.store.writeJSON
		failAfterWrite := true
		manager.store.writeJSON = func(tmpDir, path string, value any) error {
			if path == manager.store.registryPath && failAfterWrite {
				failAfterWrite = false
				if err := originalWrite(tmpDir, path, value); err != nil {
					return err
				}
				return errors.New("injected post-registry-sync report failure")
			}
			return originalWrite(tmpDir, path, value)
		}
		fifth := taskFor(site, "gc-activated-4", ActionPurgeExact, cacheURL(site, "/gc-activated-4"))
		if _, err := manager.Execute(context.Background(), fifth); !errors.Is(err, ErrJournalWrite) {
			t.Fatalf("post-registry failure error = %v", err)
		}
		if _, err := manager.Lookup(context.Background(), taskReference(tasks[0])); !errors.Is(err, ErrTaskExpired) {
			t.Fatalf("activated registry old task error = %v", err)
		}
		beforeRestart, err := os.ReadDir(manager.store.tasksDir)
		if err != nil || len(beforeRestart) != 4 {
			t.Fatalf("pre-restart task files=%d error=%v", len(beforeRestart), err)
		}
		restarted := testManager(t, root, resolverFor(site), config)
		afterRestart, err := os.ReadDir(restarted.store.tasksDir)
		if err != nil || len(afterRestart) != 2 {
			t.Fatalf("post-restart task files=%d error=%v", len(afterRestart), err)
		}
		if _, err := restarted.Execute(context.Background(), fifth); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("tombstone-task-unit-capacity", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), func(value *Config) {
			value.RetainCompletedTasks = 1
			value.MaxRegistryTasks = 2
			value.MaxTombstoneTasks = 1
		})
		for index := 0; index < 3; index++ {
			if _, err := manager.Execute(context.Background(), taskFor(site, fmt.Sprintf("cap-%d", index),
				ActionPurgeExact, cacheURL(site, fmt.Sprintf("/cap-%d", index)))); err != nil {
				t.Fatal(err)
			}
		}
		fourth := taskFor(site, "cap-3", ActionPurgeExact, cacheURL(site, "/cap-3"))
		if _, err := manager.Execute(context.Background(), fourth); !errors.Is(err, ErrTaskCapacity) {
			t.Fatalf("tombstone capacity error = %v", err)
		}
	})
}

func TestTombstonePartialShardWriteRecovery(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	entries := []registryEntry{
		{
			TaskID:      idWithTombstonePrefix(t, "task", "partial-task-a", 0x11),
			OperationID: idWithTombstonePrefix(t, "operation", "partial-operation-a", 0x22),
			Digest:      strings.Repeat("a", 64),
		},
		{
			TaskID:      idWithTombstonePrefix(t, "task", "partial-task-b", 0x33),
			OperationID: idWithTombstonePrefix(t, "operation", "partial-operation-b", 0x44),
			Digest:      strings.Repeat("b", 64),
		},
	}
	original := manager.store.writeBytes
	writes := 0
	manager.store.writeBytes = func(tmpDir, path string, body []byte, maximum int) error {
		writes++
		if writes == 2 {
			return errors.New("injected second tombstone shard failure")
		}
		return original(tmpDir, path, body, maximum)
	}
	if err := manager.store.addTombstones(entries); !errors.Is(err, ErrJournalWrite) {
		t.Fatalf("partial shard error = %v", err)
	}
	manager.store.writeBytes = original
	if err := manager.store.addTombstones(entries); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		for _, identity := range []struct{ kind, id string }{{"task", entry.TaskID}, {"operation", entry.OperationID}} {
			found, err := manager.store.hasTombstone(identity.kind, identity.id)
			if err != nil || !found {
				t.Fatalf("recovered tombstone %s/%s found=%v error=%v", identity.kind, identity.id, found, err)
			}
		}
	}
}

func TestTargetEncodingBoundariesAndNoAdmissionOnOversize(t *testing.T) {
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)

	root := testStateRoot(t)
	manager := testManager(t, root, resolverFor(site), nil)
	targets := make([]string, 16)
	for index := range targets {
		targets[index] = fixedLengthTarget(t, site, 4096, fmt.Sprintf("%04d", index))
	}
	task := taskFor(site, "target-boundary", ActionPurgeExact, targets...)
	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.State != StateSucceeded {
		t.Fatalf("64KiB task result=%+v error=%v", result, err)
	}
	restarted := testManager(t, root, resolverFor(site), nil)
	if lookup, err := restarted.Lookup(context.Background(), taskReference(task)); err != nil || lookup.State != StateSucceeded {
		t.Fatalf("64KiB restart lookup=%+v error=%v", lookup, err)
	}

	singleRoot := testStateRoot(t)
	singleManager := testManager(t, singleRoot, resolverFor(site), nil)
	single := taskFor(site, "single-target-boundary", ActionPurgeExact, fixedLengthTarget(t, site, maxTargetLength, "tail"))
	if result, err := singleManager.Execute(context.Background(), single); err != nil || result.State != StateSucceeded {
		t.Fatalf("16KiB target result=%+v error=%v", result, err)
	}
	singleRestart := testManager(t, singleRoot, resolverFor(site), nil)
	if lookup, err := singleRestart.Lookup(context.Background(), taskReference(single)); err != nil || lookup.State != StateSucceeded {
		t.Fatalf("16KiB target restart=%+v error=%v", lookup, err)
	}

	overRoot := testStateRoot(t)
	over := testManager(t, overRoot, resolverFor(site), nil)
	// ge-cache: the task's target bytes are capped at 256 KiB (500 targets).
	overTargets := make([]string, 64)
	for index := range overTargets {
		overTargets[index] = fixedLengthTarget(t, site, 4096, fmt.Sprintf("o%03d", index))
	}
	overTargets[len(overTargets)-1] = fixedLengthTarget(t, site, 4097, "last")
	assertRejectedBeforeWrite(t, over, taskFor(site, "target-over", ActionPurgeExact, overTargets...))

	queryRoot := testStateRoot(t)
	queryManager := testManager(t, queryRoot, resolverFor(site), nil)
	queryTarget := fixedLengthTarget(t, site, maxTargetLength, "?x")
	assertRejectedBeforeWrite(t, queryManager, taskFor(site, "redaction-expands", ActionPurgeExact, queryTarget))

	batchRoot := testStateRoot(t)
	batchManager := testManager(t, batchRoot, resolverFor(site), nil)
	batch := make([]string, 1000)
	for index := range batch {
		batch[index] = cacheURL(site, fmt.Sprintf("/batch-%d", index))
	}
	assertRejectedBeforeWrite(t, batchManager, taskFor(site, "thousand-targets", ActionPurgeExact, batch...))
}

func fixedLengthTarget(t *testing.T, site SiteContext, length int, suffix string) string {
	t.Helper()
	prefix := cacheURL(site, "/")
	fill := length - len(prefix) - len(suffix)
	if fill < 0 {
		t.Fatalf("target length %d too small", length)
	}
	return prefix + strings.Repeat("a", fill) + suffix
}

func assertRejectedBeforeWrite(t *testing.T, manager *Manager, task Task) {
	t.Helper()
	original := manager.store.writeJSON
	var writes int
	manager.store.writeJSON = func(tmpDir, path string, value any) error {
		writes++
		return original(tmpDir, path, value)
	}
	if _, err := manager.Execute(context.Background(), task); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("oversize error = %v", err)
	}
	if writes != 0 {
		t.Fatalf("oversize task wrote %d journal records", writes)
	}
	if _, err := os.Stat(manager.store.registryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize task created registry: %v", err)
	}
}

func TestSiteLimiterBoundAndActiveRetention(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), func(config *Config) {
		config.GlobalConcurrency = 2
		config.MaxTaskConcurrency = 2
		config.MaxSiteLimiters = 2
	})
	active, releaseActive, err := manager.siteLimiter("active")
	if err != nil {
		t.Fatal(err)
	}
	_, releaseIdle, err := manager.siteLimiter("idle")
	if err != nil {
		t.Fatal(err)
	}
	releaseIdle()
	_, releaseThird, err := manager.siteLimiter("third")
	if err != nil {
		t.Fatal(err)
	}
	releaseThird()
	manager.ratesMu.Lock()
	activeStillPresent := manager.siteRates["active"] != nil && manager.siteRates["active"].limiter == active
	manager.ratesMu.Unlock()
	if !activeStillPresent {
		t.Fatal("active limiter was evicted")
	}
	releaseActive()
	for index := 0; index < 100; index++ {
		_, release, err := manager.siteLimiter(fmt.Sprintf("revision-%d", index))
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	manager.ratesMu.Lock()
	count := len(manager.siteRates)
	manager.ratesMu.Unlock()
	if count != 2 {
		t.Fatalf("site limiter count = %d", count)
	}
}

func TestPrewarmJournalWriteBoundAndCrossNamespaceProgress(t *testing.T) {
	t.Run("sixteen-items-five-attempts", func(t *testing.T) {
		var site SiteContext
		server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}))
		site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
		manager := testManager(t, testStateRoot(t), resolverFor(site), func(config *Config) {
			config.Sleep = func(context.Context, time.Duration) error { return nil }
		})
		targets := make([]string, 16)
		for index := range targets {
			targets[index] = cacheURL(site, fmt.Sprintf("/retry-%d", index))
		}
		task := taskFor(site, "journal-bound", ActionPrewarm, targets...)
		task.Budget.MaxAttempts = 5
		task.Budget.MaxConcurrency = 8
		task.Budget.MaxTotalBytes = 8 << 20
		original := manager.store.writeJSON
		writes, encodedBytes := 0, 0
		manager.store.writeJSON = func(tmpDir, path string, value any) error {
			encoded, err := json.Marshal(value)
			if err != nil {
				return err
			}
			writes++
			encodedBytes += len(encoded)
			return original(tmpDir, path, value)
		}
		result, err := manager.Execute(context.Background(), task)
		if err != nil || result.State != StateFailed || result.Progress.Failed != 16 {
			t.Fatalf("journal-bound result=%+v error=%v", result, err)
		}
		if writes != 163 {
			t.Fatalf("atomic journal writes=%d want=%d", writes, 163)
		}
		if encodedBytes <= 0 || encodedBytes > 2<<20 {
			t.Fatalf("encoded journal bytes=%d writes=%d", encodedBytes, writes)
		}
		t.Logf("journal_atomic_writes=%d journal_fsync_upper_bound=%d marshaled_bytes=%d", writes, writes*2, encodedBytes)
	})

	t.Run("other-namespace-progresses", func(t *testing.T) {
		root := testStateRoot(t)
		var siteA, siteB SiteContext
		var seen sync.Map
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		var blockOnce sync.Once
		server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			site := siteB
			if request.Host == siteA.Domain {
				site = siteA
				blockOnce.Do(func() {
					entered <- struct{}{}
					<-release
				})
			}
			state := missThenHit(&seen, request.Host+request.URL.Path)
			cacheHeaders(writer, site, state)
			if state == "HIT" {
				if err := writeCacheEntryEvidence(root, site, request.URL.RequestURI()); err != nil {
					t.Errorf("write cache evidence: %v", err)
				}
			}
			_, _ = writer.Write([]byte("ok"))
		}))
		port := server.port()
		siteA = testSite("tenant-a", "site-a", "config-v1", "a.example.test", 18080, port, 1)
		siteB = testSite("tenant-a", "site-b", "config-v1", "b.example.test", 18080, port, 1)
		manager := testManager(t, root, resolverFor(siteA, siteB), func(config *Config) {
			config.RequestTimeout = 5 * time.Second
		})
		targets := make([]string, 16)
		for index := range targets {
			targets[index] = cacheURL(siteA, fmt.Sprintf("/bulk-%d", index))
		}
		large := taskFor(siteA, "large-running", ActionPrewarm, targets...)
		large.Budget.MaxConcurrency = 1
		largeDone := make(chan error, 1)
		go func() {
			_, err := manager.Execute(context.Background(), large)
			largeDone <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("large task did not start")
		}
		quick := taskFor(siteB, "quick-other-site", ActionPrewarm, cacheURL(siteB, "/quick"))
		quickDone := make(chan error, 1)
		go func() {
			result, err := manager.Execute(context.Background(), quick)
			if err == nil && result.State != StateSucceeded {
				err = fmt.Errorf("quick state = %s", result.State)
			}
			quickDone <- err
		}()
		select {
		case err := <-quickDone:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("other namespace blocked for whole large task")
		}
		close(release)
		if err := <-largeDone; err != nil {
			t.Fatal(err)
		}
	})
}

func TestManagerRejectsUnprovableRegistryAndTombstoneCapacity(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	for name, mutate := range map[string]func(*Config){
		"registry":  func(config *Config) { config.MaxRegistryTasks = 8193 },
		"tombstone": func(config *Config) { config.MaxTombstoneTasks = 1000001 },
	} {
		t.Run(name, func(t *testing.T) {
			config := DefaultConfig()
			mutate(&config)
			if _, err := NewManager(root, resolverFor(site), config); !errors.Is(err, ErrInvalidTask) {
				t.Fatalf("capacity config error = %v", err)
			}
		})
	}

	config := DefaultConfig()
	worst := registry{
		SchemaVersion: SchemaVersion,
		Tasks:         make(map[string]registryEntry, config.MaxRegistryTasks),
		Operations:    make(map[string]registryEntry, config.MaxRegistryTasks),
	}
	for index := 0; index < config.MaxRegistryTasks; index++ {
		taskID := fmt.Sprintf("t%0127d", index)
		operationID := fmt.Sprintf("o%0127d", index)
		entry := registryEntry{TaskID: taskID, OperationID: operationID, Digest: strings.Repeat("a", 64)}
		worst.Tasks[taskID] = entry
		worst.Operations[operationID] = entry
	}
	encoded, err := json.Marshal(worst)
	if err != nil || len(encoded) > maxTaskStateBytes {
		t.Fatalf("worst registry bytes=%d limit=%d error=%v", len(encoded), maxTaskStateBytes, err)
	}
	tombstoneBytes := config.MaxTombstoneTasks * 2 * tombstoneRecordBytes
	tombstoneSegments := (tombstoneBytes + maxTombstoneShardBytes - 1) / maxTombstoneShardBytes
	if tombstoneSegments != 8 {
		t.Fatalf("tombstone guaranteed bytes=%d segments=%d", tombstoneBytes, tombstoneSegments)
	}
	t.Logf("worst_registry_bytes=%d tombstone_tasks=%d tombstone_records=%d tombstone_max_segments_per_bucket=%d",
		len(encoded), config.MaxTombstoneTasks, config.MaxTombstoneTasks*2, tombstoneSegments)
}

func TestTombstoneShardOverflowHasDeterministicCapacity(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	prefix := byte(0x5a)
	taskID := idWithTombstonePrefix(t, "task", "task-overflow", prefix)
	operationID := idWithTombstonePrefix(t, "operation", "operation-overflow", prefix)
	firstPath := manager.store.tombstonePath(prefix, 0)
	if err := manager.store.writeBytes(manager.store.tmpDir, firstPath, make([]byte, maxTombstoneShardBytes),
		maxTombstoneShardBytes); err != nil {
		t.Fatal(err)
	}
	entry := registryEntry{TaskID: taskID, OperationID: operationID, Digest: strings.Repeat("a", 64)}
	if err := manager.store.addTombstones([]registryEntry{entry}); err != nil {
		t.Fatal(err)
	}
	secondPath := manager.store.tombstonePath(prefix, 1)
	info, err := os.Stat(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 2*tombstoneRecordBytes {
		t.Fatalf("overflow shard size=%d", info.Size())
	}
	for _, identity := range []struct{ kind, id string }{{"task", taskID}, {"operation", operationID}} {
		found, err := manager.store.hasTombstone(identity.kind, identity.id)
		if err != nil || !found {
			t.Fatalf("tombstone %s/%s found=%v error=%v", identity.kind, identity.id, found, err)
		}
	}
}

func idWithTombstonePrefix(t *testing.T, kind, base string, prefix byte) string {
	t.Helper()
	for index := 0; index < 100000; index++ {
		candidate := fmt.Sprintf("%s-%d", base, index)
		if tombstoneDigest(kind, candidate)[0] == prefix {
			return candidate
		}
	}
	t.Fatalf("could not find %s tombstone prefix %02x", kind, prefix)
	return ""
}

func TestNoTaskOwnedUnexpectedFiles(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	if _, err := manager.Execute(context.Background(), taskFor(site, "file-layout", ActionPurgeExact, cacheURL(site, "/none"))); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"registry.json": true, "state.lock": true, "tasks": true, "locks": true, "tmp": true, "tombstones": true}
	entries, err := os.ReadDir(filepath.Join(root, "state", "cache-tasks"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			t.Fatalf("unexpected state entry %q", entry.Name())
		}
	}
}

func TestTaskAndSiteLockFilesHaveBoundedSafeLifecycle(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	path := manager.store.lockPath("task", "active-lock")

	unlockOwner, err := manager.store.lock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		unlockOwner()
		t.Fatalf("active lock path error = %v", err)
	}

	waiterContext := &observedDoneContext{Context: context.Background(), observed: make(chan struct{})}
	waiterAcquired := make(chan func(), 1)
	waiterErrors := make(chan error, 1)
	go func() {
		unlock, err := manager.store.lock(waiterContext, path)
		if err != nil {
			waiterErrors <- err
			return
		}
		waiterAcquired <- unlock
	}()
	select {
	case <-waiterContext.observed:
	case err := <-waiterErrors:
		unlockOwner()
		t.Fatalf("waiter error = %v", err)
	case <-time.After(time.Second):
		unlockOwner()
		t.Fatal("waiter did not observe the held flock")
	}
	unlockOwner()
	select {
	case unlock := <-waiterAcquired:
		unlock()
	case err := <-waiterErrors:
		t.Fatalf("waiter error = %v", err)
	case <-time.After(time.Second):
		t.Fatal("waiter did not acquire after owner released")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("released lock path error = %v, want not exist", err)
	}

	stalePath := manager.store.lockPath("site", "stale-lock")
	if err := os.WriteFile(stalePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unlockStale, err := manager.store.lock(context.Background(), stalePath)
	if err != nil {
		t.Fatal(err)
	}
	unlockStale()
	if _, err := os.Lstat(stalePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale lock path error = %v, want not exist", err)
	}

	for index := 0; index < 128; index++ {
		for _, kind := range []string{"task", "site"} {
			lockPath := manager.store.lockPath(kind, fmt.Sprintf("unique-%d", index))
			unlock, err := manager.store.lock(context.Background(), lockPath)
			if err != nil {
				t.Fatal(err)
			}
			unlock()
		}
	}
	entries, err := os.ReadDir(manager.store.locksDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("released lock files = %d, want 0", len(entries))
	}
}

func TestByteAllocatorWaitsForTemporaryConcurrentReservation(t *testing.T) {
	allocator := &byteAllocator{remaining: 64}
	first := allocator.reserveReplacing(64, 0)
	if first != 64 {
		t.Fatalf("first reservation = %d, want 64", first)
	}

	started := make(chan struct{})
	reserved := make(chan int64, 1)
	go func() {
		close(started)
		reserved <- allocator.reserveReplacing(64, 0)
	}()
	<-started
	select {
	case value := <-reserved:
		t.Fatalf("concurrent reservation returned %d before temporary reservation settled", value)
	case <-time.After(50 * time.Millisecond):
	}

	allocator.settle(first, 1)
	var second int64
	select {
	case second = <-reserved:
	case <-time.After(time.Second):
		t.Fatal("concurrent reservation did not resume after settlement")
	}
	if second != 63 {
		t.Fatalf("second reservation = %d, want 63", second)
	}
	allocator.settle(second, 1)
	allocator.mu.Lock()
	remaining := allocator.remaining
	allocator.mu.Unlock()
	if remaining != 62 {
		t.Fatalf("remaining bytes = %d, want 62", remaining)
	}
}

func TestManagerExecuteConcurrentByteReservationReleasesRecordLock(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	firstAttempt := make(chan struct{}, 1)
	releaseAttempt := make(chan struct{})
	manager.prewarmAttempt = func(ctx context.Context, _ normalizedTask, _ normalizedTarget,
		_ *tokenBucket, _ int64) prewarmOutcome {
		firstAttempt <- struct{}{}
		select {
		case <-releaseAttempt:
			return prewarmOutcome{status: ItemSuccess, code: CodePrewarmed, bytes: 1}
		case <-ctx.Done():
			return prewarmOutcome{status: ItemFailed, code: contextFailureCode(ctx)}
		}
	}
	task := taskFor(site, "concurrent-byte-boundary", ActionPrewarm,
		cacheURL(site, "/first"), cacheURL(site, "/second"))
	task.Budget.MaxAttempts = 1
	task.Budget.MaxConcurrency = 2
	task.Budget.MaxResourceBytes = 64
	task.Budget.MaxTotalBytes = 64

	result := make(chan Result, 1)
	errors := make(chan error, 1)
	go func() {
		value, err := manager.Execute(context.Background(), task)
		if err != nil {
			errors <- err
			return
		}
		result <- value
	}()
	select {
	case <-firstAttempt:
	case err := <-errors:
		t.Fatalf("Execute error = %v", err)
	case <-time.After(time.Second):
		t.Fatal("first prewarm worker did not start")
	}

	stack := make([]byte, 1<<20)
	deadline := time.Now().Add(time.Second)
	for {
		count := runtime.Stack(stack, true)
		if strings.Contains(string(stack[:count]), "(*byteAllocator).reserveReplacing") {
			break
		}
		if time.Now().After(deadline) {
			close(releaseAttempt)
			t.Fatal("second prewarm worker did not wait for the temporary reservation")
		}
		runtime.Gosched()
	}
	close(releaseAttempt)

	select {
	case value := <-result:
		if value.State != StateSucceeded || value.Progress.Bytes != 2 || len(value.Items) != 2 {
			t.Fatalf("result = %+v", value)
		}
		for index, item := range value.Items {
			if item.Status != ItemSuccess || item.Code != CodePrewarmed || item.Bytes != 1 {
				t.Fatalf("item %d = %+v", index, item)
			}
		}
	case err := <-errors:
		t.Fatalf("Execute error = %v", err)
	case <-time.After(time.Second):
		t.Fatal("Manager.Execute deadlocked at the exact concurrent byte boundary")
	}
}

func TestTombstoneLoadFailsClosedOnDerivedCapacity(t *testing.T) {
	t.Run("default ninth shard", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		for segment := 0; segment < 9; segment++ {
			path := manager.store.tombstonePath(0x2a, segment)
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(maxTombstoneShardBytes); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}
		id := idWithTombstonePrefix(t, "task", "capacity-load", 0x2a)
		if _, err := manager.store.hasTombstone("task", id); !errors.Is(err, ErrJournalCorrupt) {
			t.Fatalf("ninth shard error=%v", err)
		}
	})

	t.Run("low configured segments", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), func(config *Config) { config.MaxTombstoneTasks = 1 })
		path := manager.store.tombstonePath(0x01, 1)
		if err := os.WriteFile(path, make([]byte, tombstoneRecordBytes), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.store.listTombstoneFiles(); !errors.Is(err, ErrJournalCorrupt) {
			t.Fatalf("low segment error=%v", err)
		}
	})

	t.Run("global records before body reads", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), func(config *Config) { config.MaxTombstoneTasks = 1 })
		for prefix := byte(0); prefix < 3; prefix++ {
			if err := os.WriteFile(manager.store.tombstonePath(prefix, 0), make([]byte, tombstoneRecordBytes), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := manager.store.hasTombstone("task", "not-present"); !errors.Is(err, ErrJournalCorrupt) {
			t.Fatalf("global record error=%v", err)
		}
	})
}

func TestOldJournalBudgetValidationFailsClosedBeforeExecution(t *testing.T) {
	cases := []struct {
		name   string
		action Action
		mutate func(*taskRecord)
	}{
		{name: "purge affected overflow", action: ActionPurgeExact, mutate: func(record *taskRecord) {
			record.Items[0].Affected = int(^uint(0) >> 1)
		}},
		{name: "purge bytes contamination", action: ActionPurgeExact, mutate: func(record *taskRecord) {
			record.Items[0].Bytes = 1
		}},
		{name: "prewarm affected contamination", action: ActionPrewarm, mutate: func(record *taskRecord) {
			record.Items[0].Affected = 1
		}},
		{name: "prewarm delete intent contamination", action: ActionPrewarm, mutate: func(record *taskRecord) {
			record.Items[0].DeleteIntent = &deleteIntent{
				Relative: "a/aa/" + strings.Repeat("a", 32), Size: 1, Device: 1, Inode: 1,
			}
		}},
		{name: "prewarm bytes budget", action: ActionPrewarm, mutate: func(record *taskRecord) {
			record.Items[0].Bytes = record.Task.Budget.MaxTotalBytes
			record.Items[0].ReservedBytes = 1
		}},
		{name: "attempt overflow", action: ActionPurgeExact, mutate: func(record *taskRecord) {
			record.Items[0].Attempts = record.Task.Budget.MaxAttempts + 1
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := testStateRoot(t)
			site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
			manager := testManager(t, root, resolverFor(site), nil)
			task := taskFor(site, strings.ReplaceAll(testCase.name, " ", "-"), testCase.action, cacheURL(site, "/journal"))
			normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			testCase.mutate(record)
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manager.store.taskPath(task.TaskID), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			manager.deleteEntries = func(context.Context, []cacheEntry) (int, error) {
				t.Fatal("corrupt journal reached cache delete")
				return 0, nil
			}
			if _, err := manager.Lookup(context.Background(), taskReference(task)); !errors.Is(err, ErrJournalCorrupt) {
				t.Fatalf("lookup error=%v", err)
			}
		})
	}
}

func TestCorruptPrewarmJournalRejectsPerResourceByteOverflowBeforeHTTP(t *testing.T) {
	var requests atomic.Int32
	var site SiteContext
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		cacheHeaders(writer, site, "HIT")
		_, _ = writer.Write([]byte("ok"))
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	manager := testManager(t, testStateRoot(t), resolverFor(site), nil)
	task := taskFor(site, "resource-byte-overflow", ActionPrewarm,
		cacheURL(site, "/first"), cacheURL(site, "/second"))
	task.Budget.MaxAttempts = 1
	task.Budget.MaxConcurrency = 2
	task.Budget.MaxResourceBytes = 64
	task.Budget.MaxTotalBytes = 128

	normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record.Items[0].Bytes = 128
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.store.taskPath(task.TaskID), encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Execute(context.Background(), task); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("Execute error=%v, want ErrJournalCorrupt", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("corrupt journal issued %d HTTP requests, want 0", got)
	}
}

func TestPrewarmJournalEnforcesCombinedPerResourceByteLimitBeforeHTTP(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		bytes         int64
		reservedBytes int64
		wantCorrupt   bool
	}{
		{name: "exact boundary", bytes: 32, reservedBytes: 32},
		{name: "combined overflow", bytes: 32, reservedBytes: 33, wantCorrupt: true},
		{name: "limit plus reservation", bytes: 64, reservedBytes: 1, wantCorrupt: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := testStateRoot(t)
			var requests atomic.Int32
			var site SiteContext
			server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				cacheHeaders(writer, site, "HIT")
				if err := writeCacheEntryEvidence(root, site, "/resource"); err != nil {
					t.Errorf("write cache evidence: %v", err)
				}
				_, _ = writer.Write([]byte("ok"))
			}))
			site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
			manager := testManager(t, root, resolverFor(site), nil)
			task := taskFor(site, "combined-resource-bytes-"+strings.ReplaceAll(testCase.name, " ", "-"), ActionPrewarm,
				cacheURL(site, "/resource"))
			task.Budget.MaxAttempts = 2
			task.Budget.MaxConcurrency = 1
			task.Budget.MaxResourceBytes = 64
			task.Budget.MaxTotalBytes = 128

			normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record.Items[0].Status = recordWorking
			record.Items[0].Attempts = 1
			record.Items[0].Bytes = testCase.bytes
			record.Items[0].ReservedBytes = testCase.reservedBytes
			validRecord := validTaskRecord(record, task.TaskID, manager.config)
			if testCase.wantCorrupt && validRecord {
				t.Fatal("combined per-resource overflow passed journal validation")
			}
			if !testCase.wantCorrupt && !validRecord {
				t.Fatal("exact per-resource boundary failed journal validation")
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manager.store.taskPath(task.TaskID), encoded, 0o600); err != nil {
				t.Fatal(err)
			}

			result, err := manager.Execute(context.Background(), task)
			if testCase.wantCorrupt {
				if !errors.Is(err, ErrJournalCorrupt) {
					t.Fatalf("Execute error=%v, want ErrJournalCorrupt", err)
				}
				if got := requests.Load(); got != 0 {
					t.Fatalf("corrupt journal issued %d HTTP requests, want 0", got)
				}
				return
			}
			if err != nil || result.State != StateSucceeded || result.Items[0].Attempts != 2 || requests.Load() < 1 {
				t.Fatalf("boundary recovery result=%+v requests=%d error=%v", result, requests.Load(), err)
			}
		})
	}
}

func TestPrewarmRequiresSecondRequestHitReceipt(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var mu sync.Mutex
	requests := map[string]int{}
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests[request.URL.Path]++
		count := requests[request.URL.Path]
		mu.Unlock()
		state := "MISS"
		if request.URL.Path == "/public" && count > 1 {
			state = "HIT"
		}
		if request.URL.Path == "/no-store" {
			writer.Header().Set("Cache-Control", "private, no-store")
			writer.Header().Set("Set-Cookie", "session=secret")
			writer.Header().Set("Vary", "*")
		}
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, request.URL.RequestURI()); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		_, _ = writer.Write([]byte("body-not-journaled"))
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "second-hit-receipt", ActionPrewarm, cacheURL(site, "/public"), cacheURL(site, "/no-store"))
	task.Budget.MaxConcurrency = 1
	task.Budget.MaxAttempts = 1
	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.State != StatePartialFailed || result.Items[0].Code != CodePrewarmed ||
		result.Items[1].Code != CodePrewarmNotCacheable || result.Items[0].Affected != 0 {
		t.Fatalf("prewarm receipt result=%+v error=%v", result, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests["/public"] != 2 || requests["/no-store"] != 2 {
		t.Fatalf("prewarm request counts=%v", requests)
	}
}

func TestDeleteIntentRequiresParentFsyncSettlement(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	path := putCacheEntry(t, root, site, "/parent-fsync")
	var failures atomic.Int32
	manager.store.fsyncParent = func(fd int) error {
		if failures.CompareAndSwap(0, 1) {
			return errors.New("injected parent fsync failure")
		}
		return unix.Fsync(fd)
	}
	task := taskFor(site, "parent-fsync-settlement", ActionPurgeExact, cacheURL(site, "/parent-fsync"))
	task.Budget.MaxAttempts = 1
	first, err := manager.Execute(context.Background(), task)
	if err != nil || first.State != StateFailed || first.Items[0].Affected != 0 || first.Items[0].Code != CodeRetryExhausted {
		t.Fatalf("first result=%+v error=%v", first, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unlink result=%v", err)
	}
	record, err := manager.store.loadTask(task.TaskID)
	if err != nil || record.Items[0].DeleteIntent == nil {
		t.Fatalf("unsettled intent=%+v error=%v", record, err)
	}
	manager.store.fsyncParent = unix.Fsync
	settled, err := manager.Execute(context.Background(), task)
	if err != nil || settled.State != StateFailed || settled.Items[0].Affected != 1 || settled.Items[0].Code != CodeRetryExhausted {
		t.Fatalf("settled result=%+v error=%v", settled, err)
	}
	record, err = manager.store.loadTask(task.TaskID)
	if err != nil || record.Items[0].DeleteIntent != nil {
		t.Fatalf("settled intent=%+v error=%v", record, err)
	}
}

func TestCompactionContextStagesAndOrphanConvergence(t *testing.T) {
	newManager := func(t *testing.T) (*Manager, []Task) {
		t.Helper()
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), func(config *Config) {
			config.RetainCompletedTasks = 2
			config.MaxRegistryTasks = 4
			config.MaxTombstoneTasks = 10
		})
		tasks := make([]Task, 4)
		for index := range tasks {
			tasks[index] = taskFor(site, fmt.Sprintf("context-gc-%d", index), ActionPurgeExact, cacheURL(site, fmt.Sprintf("/context-gc-%d", index)))
			if _, err := manager.Execute(context.Background(), tasks[index]); err != nil {
				t.Fatal(err)
			}
		}
		return manager, tasks
	}

	t.Run("cancel before registry", func(t *testing.T) {
		manager, tasks := newManager(t)
		registryBefore, err := os.ReadFile(manager.store.registryPath)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		manager.store.writeBytes = func(tmpDir, path string, body []byte, maximum int) error {
			if err := writeStateBytes(tmpDir, path, body, maximum); err != nil {
				return err
			}
			cancel()
			return nil
		}
		registry, err := manager.store.loadRegistry()
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.store.compactRegistry(ctx, &registry); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-registry cancellation=%v", err)
		}
		registryAfter, err := os.ReadFile(manager.store.registryPath)
		if err != nil || string(registryAfter) != string(registryBefore) {
			t.Fatalf("registry changed before switch: %v", err)
		}
		if _, err := manager.Lookup(context.Background(), taskReference(tasks[0])); err != nil {
			t.Fatalf("old registry lookup=%v", err)
		}
	})

	t.Run("cancel after registry and converge", func(t *testing.T) {
		manager, tasks := newManager(t)
		ctx, cancel := context.WithCancel(context.Background())
		original := manager.store.writeJSON
		manager.store.writeJSON = func(tmpDir, path string, value any) error {
			if err := original(tmpDir, path, value); err != nil {
				return err
			}
			if path == manager.store.registryPath {
				cancel()
			}
			return nil
		}
		registry, err := manager.store.loadRegistry()
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.store.compactRegistry(ctx, &registry); !errors.Is(err, context.Canceled) {
			t.Fatalf("post-registry cancellation=%v", err)
		}
		if _, err := manager.Lookup(context.Background(), taskReference(tasks[0])); !errors.Is(err, ErrTaskExpired) {
			t.Fatalf("post-registry lookup=%v", err)
		}
		if err := manager.store.cleanupOrphanTasksContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(manager.store.tasksDir)
		if err != nil || len(entries) != 2 {
			t.Fatalf("orphan cleanup entries=%d error=%v", len(entries), err)
		}
	})

	t.Run("cancel during task deletion and converge", func(t *testing.T) {
		manager, tasks := newManager(t)
		ctx, cancel := context.WithCancel(context.Background())
		originalRemove := manager.store.removeFile
		removed := 0
		manager.store.removeFile = func(path string) error {
			if err := originalRemove(path); err != nil {
				return err
			}
			removed++
			if removed == 1 {
				cancel()
			}
			return nil
		}
		registry, err := manager.store.loadRegistry()
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.store.compactRegistry(ctx, &registry); !errors.Is(err, context.Canceled) {
			t.Fatalf("delete cancellation=%v", err)
		}
		if _, err := manager.Lookup(context.Background(), taskReference(tasks[0])); !errors.Is(err, ErrTaskExpired) {
			t.Fatalf("delete-stage lookup=%v", err)
		}
		manager.store.removeFile = originalRemove
		if err := manager.store.cleanupOrphanTasksContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(manager.store.tasksDir)
		if err != nil || len(entries) != 2 {
			t.Fatalf("delete-stage cleanup entries=%d error=%v", len(entries), err)
		}
	})
}

func TestTerminalDeleteIntentRecoversWithoutExecute(t *testing.T) {
	newFailedTask := func(t *testing.T) (*Manager, Task, string) {
		t.Helper()
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		path := putCacheEntry(t, root, site, "/terminal-recovery")
		var failed atomic.Bool
		manager.store.fsyncParent = func(fd int) error {
			if failed.CompareAndSwap(false, true) {
				return errors.New("injected parent fsync failure")
			}
			return unix.Fsync(fd)
		}
		task := taskFor(site, "terminal-recovery", ActionPurgeExact, cacheURL(site, "/terminal-recovery"))
		task.Budget.MaxAttempts = 1
		result, err := manager.Execute(context.Background(), task)
		record, loadErr := manager.store.loadTask(task.TaskID)
		if err != nil || result.State != StateFailed || loadErr != nil || record.Items[0].DeleteIntent == nil || record.Items[0].Affected != 0 {
			t.Fatalf("failed terminal result=%+v error=%v record=%+v load_error=%v", result, err, record, loadErr)
		}
		return manager, task, path
	}

	t.Run("lookup settles", func(t *testing.T) {
		manager, task, path := newFailedTask(t)
		manager.store.fsyncParent = unix.Fsync
		lookup, err := manager.Lookup(context.Background(), taskReference(task))
		if err != nil || lookup.State != StateFailed || lookup.Items[0].Affected != 1 {
			t.Fatalf("lookup settlement=%+v error=%v", lookup, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("settled path=%v", err)
		}
		record, err := manager.store.loadTask(task.TaskID)
		if err != nil || record.Items[0].DeleteIntent != nil || record.Items[0].Affected != 1 {
			t.Fatalf("settled record=%+v error=%v", record, err)
		}
	})

	t.Run("restart settles before lookup", func(t *testing.T) {
		manager, task, _ := newFailedTask(t)
		root := manager.store.stateRoot
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		restarted := testManager(t, root, resolverFor(site), nil)
		record, err := restarted.store.loadTask(task.TaskID)
		if err != nil || record.Items[0].DeleteIntent != nil || record.Items[0].Affected != 1 {
			t.Fatalf("startup settlement=%+v error=%v", record, err)
		}
		lookup, err := restarted.Lookup(context.Background(), taskReference(task))
		if err != nil || lookup.Items[0].Affected != 1 {
			t.Fatalf("restart lookup=%+v error=%v", lookup, err)
		}
	})

	t.Run("compaction settles and retains tombstone", func(t *testing.T) {
		manager, task, _ := newFailedTask(t)
		manager.store.fsyncParent = unix.Fsync
		manager.store.config.MaxRegistryTasks = 1
		manager.store.config.RetainCompletedTasks = 0
		registry, err := manager.store.loadRegistry()
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.store.compactRegistry(context.Background(), &registry); err != nil {
			t.Fatalf("compact error=%v", err)
		}
		if _, err := manager.Lookup(context.Background(), taskReference(task)); !errors.Is(err, ErrTaskExpired) {
			t.Fatalf("expired lookup=%v", err)
		}
		if _, err := os.Stat(manager.store.taskPath(task.TaskID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("task file remains=%v", err)
		}
	})
}

func TestTombstoneReadBindsFileIdentityAndSize(t *testing.T) {
	cases := []struct {
		name string
		hook func(string)
	}{
		{name: "replacement", hook: func(path string) {
			backup := path + ".old"
			if err := os.Rename(path, backup); err != nil {
				panic(err)
			}
			if err := os.WriteFile(path, make([]byte, tombstoneRecordBytes), 0o600); err != nil {
				panic(err)
			}
		}},
		{name: "extension", hook: func(path string) {
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				panic(err)
			}
			_, err = file.Write([]byte{0})
			_ = file.Close()
			if err != nil {
				panic(err)
			}
		}},
		{name: "truncate", hook: func(path string) {
			if err := os.Truncate(path, 0); err != nil {
				panic(err)
			}
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := testStateRoot(t)
			site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
			manager := testManager(t, root, resolverFor(site), nil)
			path := manager.store.tombstonePath(0x11, 0)
			if err := os.WriteFile(path, make([]byte, tombstoneRecordBytes), 0o600); err != nil {
				t.Fatal(err)
			}
			manager.store.beforeTombstoneRead = testCase.hook
			if _, err := manager.store.readTombstoneShardsContext(context.Background(), 0x11); !errors.Is(err, ErrJournalCorrupt) {
				t.Fatalf("race error=%v", err)
			}
		})
	}

	t.Run("oversized shard", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		path := manager.store.tombstonePath(0x11, 0)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maxTombstoneShardBytes + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.store.readTombstoneShardsContext(context.Background(), 0x11); !errors.Is(err, ErrJournalCorrupt) {
			t.Fatalf("oversized error=%v", err)
		}
	})
}

func TestReadStateJSONRejectsSpecialFilesPromptly(t *testing.T) {
	rejectPromptly := func(t *testing.T, path string) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			_, err := readStateJSON(path, &registry{})
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("special state file %q was accepted", path)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("special state file %q blocked", path)
		}
	}

	root, err := os.MkdirTemp("/tmp", "cdnca-cache-state-read-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	t.Run("fifo replacement", func(t *testing.T) {
		path := filepath.Join(root, "registry.json")
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		originalOpen := readStateOpen
		t.Cleanup(func() { readStateOpen = originalOpen })
		validated, open := make(chan struct{}), make(chan struct{})
		readStateOpen = func(path string, flag int, perm os.FileMode) (*os.File, error) {
			close(validated)
			<-open
			return os.OpenFile(path, flag, perm)
		}
		done := make(chan error, 1)
		go func() {
			_, err := readStateJSON(path, &registry{})
			done <- err
		}()
		<-validated
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		close(open)
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("post-validation FIFO replacement was accepted")
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatal("post-validation FIFO replacement blocked descriptor open")
		}
	})
	t.Run("unix socket", func(t *testing.T) {
		path := filepath.Join(root, "registry.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		rejectPromptly(t, path)
	})
	t.Run("device", func(t *testing.T) { rejectPromptly(t, "/dev/null") })
}

func TestTerminalRecordActionCodeCauseMatrix(t *testing.T) {
	cases := []struct {
		name   string
		action Action
		status recordItemStatus
		code   string
		cause  string
		valid  bool
	}{
		{name: "purge success", action: ActionPurgeExact, status: recordSuccess, code: CodePurged, valid: true},
		{name: "purge skipped", action: ActionPurgeExact, status: recordSkipped, code: CodeCacheEntryNotFound, valid: true},
		{name: "purge retry cause", action: ActionPurgeExact, status: recordFailed, code: CodeRetryExhausted, cause: CodeCacheDeleteFailed, valid: true},
		{name: "prewarm success", action: ActionPrewarm, status: recordSuccess, code: CodePrewarmed, valid: true},
		{name: "prewarm skipped", action: ActionPrewarm, status: recordSkipped, code: CodeAlreadyCached, valid: true},
		{name: "prewarm retry cause", action: ActionPrewarm, status: recordFailed, code: CodeRetryExhausted, cause: CodePrewarmTimeout, valid: true},
		{name: "purge success wrong code", action: ActionPurgeExact, status: recordSuccess, code: CodeAlreadyCached},
		{name: "purge success cause", action: ActionPurgeExact, status: recordSuccess, code: CodePurged, cause: CodeCacheDeleteFailed},
		{name: "purge failed success code", action: ActionPurgeExact, status: recordFailed, code: CodePurged},
		{name: "prewarm failed purge code", action: ActionPrewarm, status: recordFailed, code: CodePurged},
		{name: "retry missing cause", action: ActionPurgeExact, status: recordFailed, code: CodeRetryExhausted},
		{name: "retry wrong cause", action: ActionPrewarm, status: recordFailed, code: CodeRetryExhausted, cause: CodePurged},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := testStateRoot(t)
			site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
			manager := testManager(t, root, resolverFor(site), nil)
			task := taskFor(site, strings.ReplaceAll(testCase.name, " ", "-"), testCase.action, cacheURL(site, "/matrix"))
			normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record.State = recordDone
			record.CompletedAt = manager.now().UTC()
			item := &record.Items[0]
			item.Status = testCase.status
			item.Code = testCase.code
			item.CauseCode = testCase.cause
			item.Attempts = 1
			item.CompletedAt = manager.now().UTC()
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manager.store.taskPath(task.TaskID), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = manager.Lookup(context.Background(), taskReference(task))
			if testCase.valid {
				if err != nil {
					t.Fatalf("valid matrix error=%v", err)
				}
			} else if !errors.Is(err, ErrJournalCorrupt) {
				t.Fatalf("invalid matrix error=%v", err)
			}
		})
	}
}

func TestTombstoneRemovalRaceFailsClosedAcrossCallers(t *testing.T) {
	races := []struct {
		name string
		hook func(string) error
	}{
		{name: "unlink", hook: func(path string) error { return os.Remove(path) }},
		{name: "rename-away", hook: func(path string) error { return os.Rename(path, path+".away") }},
		{name: "directory-type", hook: func(path string) error {
			if err := os.Rename(path, path+".away"); err != nil {
				return err
			}
			return os.Mkdir(path, 0o700)
		}},
		{name: "symlink", hook: func(path string) error {
			if err := os.Rename(path, path+".away"); err != nil {
				return err
			}
			return os.Symlink("/dev/null", path)
		}},
		{name: "fifo", hook: func(path string) error {
			if err := os.Rename(path, path+".away"); err != nil {
				return err
			}
			return unix.Mkfifo(path, 0o600)
		}},
		{name: "notdir", hook: func(path string) error {
			directory := filepath.Dir(path)
			if err := os.Rename(directory, directory+".away"); err != nil {
				return err
			}
			return os.WriteFile(directory, []byte("not a directory"), 0o600)
		}},
	}
	callers := []string{"lookup", "execute", "gc"}
	runWithDeadline := func(t *testing.T, fn func(context.Context) error) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- fn(ctx) }()
		select {
		case err := <-done:
			return err
		case <-time.After(time.Second):
			t.Fatal("tombstone race call hung")
			return context.DeadlineExceeded
		}
	}
	t.Run("fifo during scan", func(t *testing.T) {
		root := testStateRoot(t)
		site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
		manager := testManager(t, root, resolverFor(site), nil)
		path := manager.store.tombstonePath(0x11, 0)
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runWithDeadline(t, func(ctx context.Context) error {
			_, err := manager.store.readTombstoneShardsContext(ctx, 0x11)
			return err
		}); !errors.Is(err, ErrJournalCorrupt) {
			t.Fatalf("scan fifo error=%v", err)
		}
	})
	for _, race := range races {
		for _, caller := range callers {
			t.Run(race.name+"/"+caller, func(t *testing.T) {
				goroutines := runtime.NumGoroutine()
				root := testStateRoot(t)
				site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
				manager := testManager(t, root, resolverFor(site), nil)
				const prefix = byte(0x11)
				taskID := idWithTombstonePrefix(t, "task", "removal-race", prefix)
				operationID := idWithTombstonePrefix(t, "operation", "removal-race-op", 0x22)
				path := manager.store.tombstonePath(prefix, 0)
				digest := tombstoneDigest("task", taskID)
				var hookCalls atomic.Int32
				if caller != "gc" {
					if err := os.WriteFile(path, digest[:], 0o600); err != nil {
						t.Fatal(err)
					}
				}
				manager.store.beforeTombstoneRead = func(value string) {
					hookCalls.Add(1)
					if err := race.hook(value); err != nil {
						t.Errorf("race hook: %v", err)
					}
				}

				switch caller {
				case "lookup":
					reference := TaskReference{SchemaVersion: SchemaVersion, TaskID: taskID, OperationID: operationID,
						TenantID: site.TenantID, SiteID: site.SiteID}
					if err := runWithDeadline(t, func(ctx context.Context) error {
						_, err := manager.Lookup(ctx, reference)
						return err
					}); !errors.Is(err, ErrJournalCorrupt) {
						t.Fatalf("lookup error=%v", err)
					}
					if _, err := os.Stat(manager.store.taskPath(taskID)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("lookup created task=%v", err)
					}
				case "execute":
					task := taskFor(site, taskID, ActionPurgeExact, cacheURL(site, "/removal-race"))
					task.TaskID = taskID
					task.OperationID = operationID
					if err := runWithDeadline(t, func(ctx context.Context) error {
						_, err := manager.Execute(ctx, task)
						return err
					}); !errors.Is(err, ErrJournalCorrupt) {
						t.Fatalf("execute error=%v", err)
					}
					if _, err := os.Stat(manager.store.taskPath(taskID)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("execute created task=%v", err)
					}
				case "gc":
					task := taskFor(site, taskID, ActionPurgeExact, cacheURL(site, "/removal-race"))
					task.TaskID = taskID
					task.OperationID = operationID
					manager.store.beforeTombstoneRead = nil
					if _, err := manager.Execute(context.Background(), task); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, digest[:], 0o600); err != nil {
						t.Fatal(err)
					}
					manager.store.beforeTombstoneRead = func(value string) {
						hookCalls.Add(1)
						if err := race.hook(value); err != nil {
							t.Errorf("race hook: %v", err)
						}
					}
					manager.store.config.MaxRegistryTasks = 1
					manager.store.config.RetainCompletedTasks = 0
					registryBefore, err := os.ReadFile(manager.store.registryPath)
					if err != nil {
						t.Fatal(err)
					}
					registry, err := manager.store.loadRegistry()
					if err != nil {
						t.Fatal(err)
					}
					if err := runWithDeadline(t, func(ctx context.Context) error {
						return manager.store.compactRegistry(ctx, &registry)
					}); !errors.Is(err, ErrJournalCorrupt) {
						t.Fatalf("gc error=%v", err)
					}
					registryAfter, err := os.ReadFile(manager.store.registryPath)
					if err != nil || !bytes.Equal(registryBefore, registryAfter) {
						t.Fatalf("gc changed registry error=%v", err)
					}
					if _, err := os.Stat(manager.store.taskPath(taskID)); err != nil {
						t.Fatalf("gc removed task=%v", err)
					}
				}
				if hookCalls.Load() == 0 {
					t.Fatal("tombstone race hook was not invoked")
				}
				if after := runtime.NumGoroutine(); after > goroutines+2 {
					t.Fatalf("goroutine leak before=%d after=%d", goroutines, after)
				}
			})
		}
	}
}

func TestTerminalActionStatusCodeCauseExhaustive(t *testing.T) {
	actions := []Action{ActionPurgeExact, ActionPurgePrefix, ActionPurgeSite, ActionPrewarm}
	statuses := []recordItemStatus{recordPending, recordWorking, recordSuccess, recordSkipped, recordFailed}
	codes := []string{
		"", CodePurged, CodePrewarmed, CodeCacheEntryNotFound, CodeAlreadyCached,
		CodeCacheLayoutUnsafe, CodeCacheMetadataInvalid, CodeCacheEntryChanged, CodeCacheDeleteFailed,
		CodePurgeBudgetExceeded, CodePurgeScanBudgetExceeded, CodeSiteContextStale,
		CodeTaskCancelled, CodeTaskDeadlineExceeded, CodeRetryExhausted,
		CodePrewarmTimeout, CodePrewarmRedirect, CodePrewarmResponseTooLarge,
		CodePrewarmTaskBytesExceeded, CodePrewarmUpstream, CodePrewarmStatus, CodePrewarmNotCacheable,
		"UNKNOWN",
	}
	causes := append([]string{""}, codes...)
	purgeFailure := map[string]bool{
		CodeCacheLayoutUnsafe: true, CodeCacheMetadataInvalid: true, CodeCacheEntryChanged: true,
		CodeCacheDeleteFailed: true, CodePurgeBudgetExceeded: true, CodePurgeScanBudgetExceeded: true,
		CodeSiteContextStale: true, CodeTaskCancelled: true, CodeTaskDeadlineExceeded: true,
		CodeRetryExhausted: true,
	}
		prewarmFailure := map[string]bool{
			CodePrewarmTimeout: true, CodePrewarmRedirect: true, CodePrewarmResponseTooLarge: true,
			CodePrewarmTaskBytesExceeded: true, CodePrewarmUpstream: true, CodePrewarmStatus: true,
			CodePrewarmNotCacheable: true, CodeCacheLayoutUnsafe: true, CodeCacheMetadataInvalid: true,
			CodeSiteContextStale: true, CodeTaskCancelled: true,
			CodeTaskDeadlineExceeded: true, CodeRetryExhausted: true,
		}
	isFailure := func(action Action, code string) bool {
		if action == ActionPrewarm {
			return prewarmFailure[code]
		}
		return purgeFailure[code]
	}
	expected := func(action Action, status recordItemStatus, code, cause string) bool {
		if status == recordSuccess {
			return cause == "" && ((action == ActionPrewarm && code == CodePrewarmed) ||
				(action != ActionPrewarm && code == CodePurged))
		}
		if status == recordSkipped {
			return cause == "" && ((action == ActionPrewarm && code == CodeAlreadyCached) ||
				(action != ActionPrewarm && code == CodeCacheEntryNotFound))
		}
		if status != recordFailed || !isFailure(action, code) {
			return false
		}
		if code != CodeRetryExhausted {
			return cause == ""
		}
		if action == ActionPrewarm {
			return cause == CodePrewarmTimeout || cause == CodePrewarmUpstream || cause == CodePrewarmStatus
		}
		return cause == CodeCacheDeleteFailed || cause == CodeCacheEntryChanged
	}
	for _, action := range actions {
		for _, status := range statuses {
			for _, code := range codes {
				for _, cause := range causes {
					want := expected(action, status, code, cause)
					if got := validTerminalItem(action, status, code, cause); got != want {
						t.Fatalf("matrix mismatch action=%s status=%s code=%s cause=%s got=%v want=%v", action, status, code, cause, got, want)
					}
				}
			}
		}
	}
}

func TestRunningJournalRetryCodeFailsClosedBeforeExecution(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		status recordItemStatus
		code   string
	}{
		{name: "purge pending metadata invalid", action: ActionPurgeExact, status: recordPending, code: CodeCacheMetadataInvalid},
		{name: "purge pending retry exhausted", action: ActionPurgeExact, status: recordPending, code: CodeRetryExhausted},
		{name: "purge working metadata invalid", action: ActionPurgeExact, status: recordWorking, code: CodeCacheMetadataInvalid},
		{name: "purge working retry exhausted", action: ActionPurgeExact, status: recordWorking, code: CodeRetryExhausted},
		{name: "prewarm pending not cacheable", action: ActionPrewarm, status: recordPending, code: CodePrewarmNotCacheable},
		{name: "prewarm pending retry exhausted", action: ActionPrewarm, status: recordPending, code: CodeRetryExhausted},
		{name: "prewarm working not cacheable", action: ActionPrewarm, status: recordWorking, code: CodePrewarmNotCacheable},
		{name: "prewarm working retry exhausted", action: ActionPrewarm, status: recordWorking, code: CodeRetryExhausted},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := testStateRoot(t)
			site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
			manager := testManager(t, root, resolverFor(site), nil)
			task := taskFor(site, strings.ReplaceAll(testCase.name, " ", "-"), testCase.action,
				cacheURL(site, "/journal-retry-code"))
			if testCase.action != ActionPrewarm {
				cachePath := putCacheEntry(t, root, site, "/journal-retry-code")
				defer func() {
					if _, err := os.Stat(cachePath); err != nil {
						t.Errorf("cache entry changed before valid execution: %v", err)
					}
				}()
			}
			normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record.Items[0].Status = testCase.status
			record.Items[0].Code = testCase.code
			record.Items[0].CauseCode = ""
			record.Items[0].CompletedAt = time.Time{}
			record.Items[0].NextAttemptAt = time.Time{}
			if testCase.status == recordWorking {
				record.Items[0].Attempts = 1
				if testCase.action == ActionPrewarm {
					record.Items[0].ReservedBytes = 1
				}
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manager.store.taskPath(task.TaskID), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Execute(context.Background(), task); !errors.Is(err, ErrJournalCorrupt) {
				t.Fatalf("Execute error=%v, want ErrJournalCorrupt", err)
			}
		})
	}
}

func TestPendingMaxAttemptsWithoutRetryCodeFailsClosed(t *testing.T) {
	for _, action := range []Action{ActionPurgeExact, ActionPrewarm} {
		t.Run(string(action), func(t *testing.T) {
			root := testStateRoot(t)
			site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
			manager := testManager(t, root, resolverFor(site), nil)
			task := taskFor(site, "pending-max-attempts-"+string(action), action, cacheURL(site, "/pending-max-attempts"))
			var cachePath string
			if action != ActionPrewarm {
				cachePath = putCacheEntry(t, root, site, "/pending-max-attempts")
			}
			normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			record.Items[0].Status = recordPending
			record.Items[0].Attempts = record.Task.Budget.MaxAttempts
			record.Items[0].Code = ""
			record.Items[0].CauseCode = ""
			record.Items[0].CompletedAt = time.Time{}
			record.Items[0].NextAttemptAt = time.Time{}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manager.store.taskPath(task.TaskID), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Execute(context.Background(), task); !errors.Is(err, ErrJournalCorrupt) {
				t.Fatalf("Execute error=%v, want ErrJournalCorrupt", err)
			}
			if cachePath != "" {
				if _, err := os.Stat(cachePath); err != nil {
					t.Fatalf("purge touched cache before journal rejection: %v", err)
				}
			}
		})
	}
}
