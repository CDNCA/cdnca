package dynroute

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// prewarmNode stands in for the node's shared server on loopback: the first
// fetch of a path is a MISS, later ones a HIT (the prewarm token is not
// checked). /slow/ blocks until the request's context ends.
type prewarmNode struct {
	siteID string
	size   int
	mu     sync.Mutex
	seen   map[string]int
	read   int64
}

func (node *prewarmNode) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	node.mu.Lock()
	node.seen[request.URL.Path]++
	first := node.seen[request.URL.Path] == 1
	node.mu.Unlock()
	if strings.HasPrefix(request.URL.Path, "/slow/") {
		<-request.Context().Done()
		return
	}
	writer.Header().Set("X-Cdnca-Site", node.siteID)
	writer.Header().Set("X-Cdnca-Cache-Key", "key"+request.URL.Path)
	writer.Header().Set("X-CDN-Cache", map[bool]string{true: "MISS", false: "HIT"}[first])
	written, _ := writer.Write([]byte(strings.Repeat("x", node.size)))
	node.mu.Lock()
	node.read += int64(written)
	node.mu.Unlock()
}

func (node *prewarmNode) fetches() int {
	node.mu.Lock()
	defer node.mu.Unlock()
	total := 0
	for _, count := range node.seen {
		total += count
	}
	return total
}

// newPrewarmRuntime: a runtime serving one cached site on the test server's
// port, prewarming through it.
func newPrewarmRuntime(t *testing.T, size int) (*Runtime, *prewarmNode, func(path string) string) {
	t.Helper()
	node := &prewarmNode{siteID: "0d130000-0000-4000-8000-000000000001", size: size, seen: map[string]int{}}
	server := httptest.NewServer(node)
	t.Cleanup(server.Close)
	_, rawPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	runtime := newTestRuntime(t, 0)
	runtime.sites = []edgesite.Site{{SiteID: node.siteID, TenantID: "t", Hosts: edgesite.Hosts{Primary: "warm.test"},
		Listeners: []edgesite.Listener{{Port: port}},
		Cache: &edgesite.Cache{KeyPrefix: "p", Domain: "warm.test", KeyByHost: true, Policy: edgeconfig.CachePolicyDocument{
			Mode: edgeconfig.CacheOverride, QueryMode: edgeconfig.CacheQueryPreserve}}}}
	runtime.prewarm = dyncache.Prewarmer{Token: "token", Address: "127.0.0.1", Timeout: 5 * time.Second, MaxBytes: 64 << 20}
	return runtime, node, func(path string) string { return "http://warm.test:" + rawPort + path }
}

func prewarmTask(siteID string, targets ...string) cachetask.Task {
	return cachetask.Task{SchemaVersion: cachetask.SchemaVersion, TaskID: "t", OperationID: "t", TenantID: "t", SiteID: siteID,
		DeliveryAttempt: 1, Action: cachetask.ActionPrewarm, Scope: cachetask.ScopeURL, Targets: targets}
}

// CACHEFLOW-E03: a task whose deadline passed while it was queued runs
// nothing; every target is TASK_DEADLINE_EXCEEDED.
func TestCacheTasksExpiredDeadlineRunsNothing(t *testing.T) {
	runtime, node, url := newPrewarmRuntime(t, 16)
	fixed := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	tasks := CacheTasks{Runtime: runtime, Now: func() time.Time { return fixed }}
	task := prewarmTask(node.siteID, url("/a.css"), url("/b.css"))
	task.Deadline = fixed.Add(-time.Second)
	result, err := tasks.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if node.fetches() != 0 || result.State != cachetask.StateFailed || len(result.Items) != 2 {
		t.Fatalf("fetches %d result %+v", node.fetches(), result)
	}
	for _, item := range result.Items {
		if item.Status != cachetask.ItemFailed || item.Code != cachetask.CodeTaskDeadlineExceeded {
			t.Fatalf("item %+v", item)
		}
	}
	purge := task
	purge.Action, purge.Scope, purge.Targets = cachetask.ActionPurgeSite, cachetask.ScopeSite, nil
	if result, err = tasks.Execute(context.Background(), purge); err != nil || result.State != cachetask.StateFailed ||
		len(result.Items) != 1 || result.Items[0].Code != cachetask.CodeTaskDeadlineExceeded {
		t.Fatalf("site purge %+v %v", result, err)
	}
}

// CACHEFLOW-E03: the deadline bounds the request in flight; the target
// already done keeps its result, the active one and the rest are
// TASK_DEADLINE_EXCEEDED (not an upstream failure).
func TestCacheTasksDeadlineStopsActiveRequest(t *testing.T) {
	runtime, node, url := newPrewarmRuntime(t, 16)
	tasks := CacheTasks{Runtime: runtime}
	task := prewarmTask(node.siteID, url("/a.css"), url("/slow/b.css"), url("/c.css"))
	task.Deadline = time.Now().Add(300 * time.Millisecond)
	started := time.Now()
	result, err := tasks.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the active request outlived the deadline: %v", elapsed)
	}
	if result.State != cachetask.StatePartialFailed || len(result.Items) != 3 || result.Items[0].Status != cachetask.ItemSuccess ||
		result.Items[1].Code != cachetask.CodeTaskDeadlineExceeded || result.Items[2].Code != cachetask.CodeTaskDeadlineExceeded ||
		node.seen["/c.css"] != 0 {
		t.Fatalf("result %+v seen %v", result, node.seen)
	}
}

// fakeClock: the task rate limiter sleeps on it (no real waiting).
type fakeClock struct {
	mu    sync.Mutex
	at    time.Time
	slept time.Duration
}

func (clock *fakeClock) now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.at
}

func (clock *fakeClock) sleep(ctx context.Context, value time.Duration) error {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.at = clock.at.Add(value)
	clock.slept += value
	return ctx.Err()
}

func prewarmBudget(object, total int64, rate float64, burst int) cachetask.ResourceBudget {
	return cachetask.ResourceBudget{MaxAttempts: 1, MaxConcurrency: 1, MaxResourceBytes: object, MaxTotalBytes: total,
		RequestsPerSecond: rate, Burst: burst}
}

// CACHEFLOW-E02: the node's per-object limit stops a larger object.
func TestCacheTasksPrewarmObjectLimit(t *testing.T) {
	runtime, node, url := newPrewarmRuntime(t, 2<<20)
	task := prewarmTask(node.siteID, url("/big.bin"))
	task.Budget = prewarmBudget(1<<20, 4<<20, 100, 10)
	result, err := CacheTasks{Runtime: runtime}.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != cachetask.StateFailed || result.Items[0].Code != cachetask.CodePrewarmResponseTooLarge || node.fetches() != 1 {
		t.Fatalf("result %+v fetches %d", result, node.fetches())
	}
}

// CACHEFLOW-E02: every read (the verifying GET too) spends the task's byte
// allowance; exactly the allowance passes, the target after it is not
// fetched.
func TestCacheTasksPrewarmTaskBytes(t *testing.T) {
	runtime, node, url := newPrewarmRuntime(t, 256<<10)
	task := prewarmTask(node.siteID, url("/1.bin"), url("/2.bin"), url("/3.bin"))
	task.Budget = prewarmBudget(1<<20, 1<<20, 100, 10)
	result, err := CacheTasks{Runtime: runtime}.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != cachetask.StatePartialFailed || result.Items[0].Status != cachetask.ItemSuccess ||
		result.Items[1].Status != cachetask.ItemSuccess || result.Items[2].Code != cachetask.CodePrewarmTaskBytesExceeded ||
		node.seen["/3.bin"] != 0 || node.read != 1<<20 {
		t.Fatalf("result %+v seen %v read %d", result, node.seen, node.read)
	}
	// the receipt still reports the object size, not the bytes read
	if result.Items[0].Bytes != 256<<10 {
		t.Fatalf("item bytes %d", result.Items[0].Bytes)
	}
}

// CACHEFLOW-E02: every request waits for the task's rate (burst 2 at
// 10/s: 6 requests need 4 more tokens, 400ms).
func TestCacheTasksPrewarmRate(t *testing.T) {
	runtime, node, url := newPrewarmRuntime(t, 16)
	clock := &fakeClock{at: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	task := prewarmTask(node.siteID, url("/1.css"), url("/2.css"), url("/3.css"))
	task.Budget = prewarmBudget(1<<20, 1<<20, 10, 2)
	result, err := CacheTasks{Runtime: runtime, Now: clock.now, Sleep: clock.sleep}.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != cachetask.StateSucceeded || node.fetches() != 6 || clock.slept < 390*time.Millisecond || clock.slept > 410*time.Millisecond {
		t.Fatalf("state %s fetches %d slept %v", result.State, node.fetches(), clock.slept)
	}
}

// CACHEFLOW-E02: the node's request timeout bounds one prewarm request.
func TestCacheTasksPrewarmRequestTimeout(t *testing.T) {
	runtime, node, url := newPrewarmRuntime(t, 16)
	started := time.Now()
	result, err := CacheTasks{Runtime: runtime, RequestTimeout: 200 * time.Millisecond}.Execute(context.Background(),
		prewarmTask(node.siteID, url("/slow/a.css")))
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 3*time.Second || result.Items[0].Code != cachetask.CodePrewarmTimeout {
		t.Fatalf("elapsed %v result %+v", time.Since(started), result)
	}
}

// CACHE-ADD-07 / CACHEFLOW-E04: cancelling the last target while its
// request is in flight is a cancellation (TASK_CANCELLED, task CANCELLED),
// not an upstream failure; the target done before keeps its success.
func TestCacheTasksCancelActiveLastTarget(t *testing.T) {
	runtime, node, url := newPrewarmRuntime(t, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for node.fetches() < 3 { // a.css twice, then the slow request
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	result, err := CacheTasks{Runtime: runtime}.Execute(ctx, prewarmTask(node.siteID, url("/a.css"), url("/slow/b.css")))
	if err != nil {
		t.Fatal(err)
	}
	if result.State != cachetask.StateCancelled || result.Items[0].Status != cachetask.ItemSuccess ||
		result.Items[1].Code != cachetask.CodeTaskCancelled {
		t.Fatalf("result %+v", result)
	}
}
