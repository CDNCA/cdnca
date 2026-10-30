package cachetask

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type staticResolver map[string]SiteContext

type resolveOnlyResolver struct {
	delegate SiteResolver
}

type closeErrorBody struct {
	io.Reader
	err error
}

func (body *closeErrorBody) Close() error {
	return body.err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func (resolver resolveOnlyResolver) ResolveSite(ctx context.Context, tenantID, siteID, versionID string,
	revision uint64) (SiteContext, error) {
	return resolver.delegate.ResolveSite(ctx, tenantID, siteID, versionID, revision)
}

func (resolver staticResolver) ResolveSite(_ context.Context, tenantID, siteID, versionID string, revision uint64) (SiteContext, error) {
	value, exists := resolver[tenantID+"\x00"+siteID+"\x00"+versionID+"\x00"+fmt.Sprint(revision)]
	if !exists {
		return SiteContext{}, ErrSiteNotFound
	}
	return value, nil
}

func (staticResolver) lockActiveRelease(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return func() {}, nil
}

func resolverFor(sites ...SiteContext) staticResolver {
	resolver := make(staticResolver, len(sites))
	for _, site := range sites {
		resolver[site.TenantID+"\x00"+site.SiteID+"\x00"+site.ConfigVersionID+"\x00"+fmt.Sprint(site.ConfigRevision)] = site
	}
	return resolver
}

func testStateRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "shared", "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "shared", "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func testSite(tenantID, siteID, version, domain string, port, prewarmPort uint16, revision uint64) SiteContext {
	prewarmPathPrefix := ""
	if prewarmPort != 0 {
		prewarmPathPrefix = edgeconfig.CachePrewarmPathPrefix(tenantID, siteID, version, domain, port, edgeconfig.ProtocolHTTP)
	}
	return SiteContext{
		TenantID: tenantID, SiteID: siteID, ConfigVersionID: version, ConfigRevision: revision,
		Domain: domain, ListenPort: port, Scheme: "http", CacheEnabled: true, PrewarmPort: prewarmPort,
		PrewarmPathPrefix: prewarmPathPrefix, CacheIdentity: CacheNamespaceID(tenantID, siteID, version),
	}
}

func testManager(t *testing.T, root string, resolver SiteResolver, mutate func(*Config)) *Manager {
	t.Helper()
	config := DefaultConfig()
	config.GlobalRequestsPerSecond = 100000
	config.SiteRequestsPerSecond = 100000
	config.GlobalBurst = 100
	config.SiteBurst = 100
	config.RequestTimeout = 100 * time.Millisecond
	config.MaxResponseBytes = 1 << 20
	config.MaxTaskBytes = 16 << 20
	if mutate != nil {
		mutate(&config)
	}
	manager, err := NewManager(root, resolver, config)
	if err != nil {
		t.Fatalf("NewManager error = %v", err)
	}
	return manager
}

func TestNewManagerRequiresActiveReleaseLease(t *testing.T) {
	_, err := NewManager(testStateRoot(t), resolveOnlyResolver{delegate: resolverFor()}, DefaultConfig())
	if !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("NewManager(resolve-only) error = %v, want ErrInvalidTask", err)
	}
}

func scopeFor(action Action) Scope {
	switch action {
	case ActionPurgePrefix:
		return ScopeDirectory
	case ActionPurgeSite:
		return ScopeSite
	default:
		return ScopeURL
	}
}

func taskFor(site SiteContext, id string, action Action, targets ...string) Task {
	budget := ResourceBudget{
		MaxAttempts: 3, MaxConcurrency: 1, MaxPurgeEntries: 100,
		MaxScanEntries: 10000, MaxScanBytes: 64 << 20, MaxScanDuration: 5 * time.Second,
		InitialRetryBackoff: time.Millisecond, MaximumRetryBackoff: 4 * time.Millisecond,
	}
	if action == ActionPrewarm {
		budget = ResourceBudget{
			MaxAttempts: 3, MaxConcurrency: 2, MaxTotalBytes: 4 << 20, MaxResourceBytes: 1 << 20,
			RequestsPerSecond: 100000, Burst: 10,
			InitialRetryBackoff: time.Millisecond, MaximumRetryBackoff: 4 * time.Millisecond,
		}
	}
	return Task{
		SchemaVersion: SchemaVersion, TaskID: "task-" + id, OperationID: "operation-" + id,
		TenantID: site.TenantID, SiteID: site.SiteID, Scope: scopeFor(action),
		ConfigVersionID: site.ConfigVersionID, ConfigRevision: site.ConfigRevision,
		DeliveryAttempt: 1, Deadline: time.Now().UTC().Add(time.Minute), Budget: budget,
		Action: action, Targets: targets,
	}
}

func taskReference(task Task) TaskReference {
	return TaskReference{
		SchemaVersion: SchemaVersion, TaskID: task.TaskID, OperationID: task.OperationID,
		TenantID: task.TenantID, SiteID: task.SiteID,
	}
}

func cacheURL(site SiteContext, uri string) string {
	return fmt.Sprintf("%s://%s:%d%s", site.Scheme, site.Domain, site.ListenPort, uri)
}

func putCacheEntry(t *testing.T, root string, site SiteContext, uri string) string {
	t.Helper()
	key := cacheKeyValue(site, uri)
	path := nginxCachePath(filepath.Join(root, "shared", "cache", site.CacheIdentity), key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("\x00\x00\nKEY: " + key + "\ncache-body")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func collectCacheEntries(t *testing.T, manager *Manager, site SiteContext) []cacheEntry {
	t.Helper()
	budget := newCacheScanBudget(ResourceBudget{
		MaxScanEntries:  1000000,
		MaxScanBytes:    256 << 20,
		MaxScanDuration: time.Minute,
	})
	entries := make([]cacheEntry, 0)
	if err := manager.store.walkCacheEntries(context.Background(), site, budget, func(entry cacheEntry) error {
		entries = append(entries, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestTaskModelRejectsAmbiguousUnsafeAndOverBudgetInput(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 7)
	manager := testManager(t, root, resolverFor(site), nil)
	valid := taskFor(site, "valid", ActionPurgeExact, cacheURL(site, "/asset?q=secret"))

	tests := map[string]func(*Task){
		"empty batch":          func(task *Task) { task.Targets = nil },
		"missing tenant":       func(task *Task) { task.TenantID = "" },
		"legacy identity":      func(task *Task) { task.IdempotencyKey = "legacy" },
		"wrong scope":          func(task *Task) { task.Scope = ScopeDirectory },
		"zero revision":        func(task *Task) { task.ConfigRevision = 0 },
		"zero attempt":         func(task *Task) { task.DeliveryAttempt = 0 },
		"missing deadline":     func(task *Task) { task.Deadline = time.Time{} },
		"far deadline":         func(task *Task) { task.Deadline = time.Now().Add(8 * 24 * time.Hour) },
		"too many attempts":    func(task *Task) { task.Budget.MaxAttempts = 6 },
		"purge with bytes":     func(task *Task) { task.Budget.MaxTotalBytes = 1 },
		"credential URL":       func(task *Task) { task.Targets[0] = "http://user:pass@cache.example.test:18080/a" },
		"local address":        func(task *Task) { task.Targets[0] = "http://127.0.0.1:18080/a" },
		"local path":           func(task *Task) { task.Targets[0] = "/var/cache/a" },
		"control":              func(task *Task) { task.Targets[0] = cacheURL(site, "/a\nsecret") },
		"traversal":            func(task *Task) { task.Targets[0] = cacheURL(site, "/../secret") },
		"encoded slash":        func(task *Task) { task.Targets[0] = cacheURL(site, "/a%2fb") },
		"wrong port":           func(task *Task) { task.Targets[0] = "http://cache.example.test:18081/a" },
		"directory with query": func(task *Task) { task.Action = ActionPurgePrefix; task.Scope = ScopeDirectory },
		"duplicate target":     func(task *Task) { task.Targets = append(task.Targets, task.Targets[0]) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			task := valid
			task.Targets = append([]string(nil), valid.Targets...)
			mutate(&task)
			if _, err := manager.Execute(context.Background(), task); !errors.Is(err, ErrInvalidTask) {
				t.Fatalf("error = %v, want ErrInvalidTask", err)
			}
		})
	}

	overBatch := valid
	overBatch.TaskID, overBatch.OperationID = "task-over-batch", "operation-over-batch"
	overBatch.Targets = make([]string, manager.config.MaxBatchItems+1)
	for index := range overBatch.Targets {
		overBatch.Targets[index] = cacheURL(site, fmt.Sprintf("/asset-%d", index))
	}
	if _, err := manager.Execute(context.Background(), overBatch); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("over batch error = %v", err)
	}

	staleNamespace := site
	staleNamespace.CacheIdentity = strings.Repeat("a", 64)
	staleManager := testManager(t, testStateRoot(t), resolverFor(staleNamespace), nil)
	if _, err := staleManager.Execute(context.Background(), taskFor(staleNamespace, "stale-namespace", ActionPurgeSite)); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("stale namespace error = %v", err)
	}
}

func TestPurgeExactDirectorySiteAndRevisionIsolation(t *testing.T) {
	root := testStateRoot(t)
	v1 := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	v2 := testSite("tenant-a", "site-a", "config-v2", "cache.example.test", 18080, 19080, 2)
	otherSite := testSite("tenant-a", "site-b", "config-v2", "cache.example.test", 18080, 19081, 2)
	otherTenant := testSite("tenant-b", "site-a", "config-v2", "cache.example.test", 18080, 19082, 2)
	manager := testManager(t, root, resolverFor(v1, v2, otherSite, otherTenant), nil)

	exact := putCacheEntry(t, root, v2, "/asset?q=1")
	queryOther := putCacheEntry(t, root, v2, "/asset?q=2")
	prefixA := putCacheEntry(t, root, v2, "/images/a")
	prefixB := putCacheEntry(t, root, v2, "/images/sub/b?q=1")
	prefixOther := putCacheEntry(t, root, v2, "/images-old/a")
	isolated := []string{
		putCacheEntry(t, root, v1, "/asset?q=1"),
		putCacheEntry(t, root, otherSite, "/asset?q=1"),
		putCacheEntry(t, root, otherTenant, "/asset?q=1"),
	}

	result, err := manager.Execute(context.Background(), taskFor(v2, "exact", ActionPurgeExact, cacheURL(v2, "/asset?q=1")))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 {
		t.Fatalf("exact result=%+v error=%v", result, err)
	}
	if _, err := os.Stat(exact); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact entry remains: %v", err)
	}
	if _, err := os.Stat(queryOther); err != nil {
		t.Fatalf("query-isolated entry removed: %v", err)
	}

	result, err = manager.Execute(context.Background(), taskFor(v2, "directory", ActionPurgePrefix, cacheURL(v2, "/images")))
	if err != nil || result.Items[0].Affected != 2 {
		t.Fatalf("directory result=%+v error=%v", result, err)
	}
	for _, path := range []string{prefixA, prefixB} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory entry remains: %s: %v", path, err)
		}
	}
	if _, err := os.Stat(prefixOther); err != nil {
		t.Fatalf("directory crossed segment boundary: %v", err)
	}

	result, err = manager.Execute(context.Background(), taskFor(v2, "site", ActionPurgeSite))
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 2 {
		t.Fatalf("site result=%+v error=%v", result, err)
	}
	for _, path := range isolated {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("revision/site/tenant isolation failed for %s: %v", path, err)
		}
	}
}

func TestPurgeBudgetAndUnsafeLayoutFailBeforeDeletion(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)
	first := putCacheEntry(t, root, site, "/a")
	second := putCacheEntry(t, root, site, "/b")
	task := taskFor(site, "budget", ActionPurgeSite)
	task.Budget.MaxPurgeEntries = 1
	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.Items[0].Code != CodePurgeBudgetExceeded {
		t.Fatalf("budget result=%+v error=%v", result, err)
	}
	for _, path := range []string{first, second} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("budget failure deleted %s: %v", path, err)
		}
	}

	link := filepath.Join(root, "shared", "cache", site.CacheIdentity, "unsafe-link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	result, err = manager.Execute(context.Background(), taskFor(site, "unsafe", ActionPurgeSite))
	if err != nil || result.Items[0].Code != CodeCacheLayoutUnsafe {
		t.Fatalf("unsafe result=%+v error=%v", result, err)
	}
	for _, path := range []string{first, second} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unsafe layout deleted %s: %v", path, err)
		}
	}
}

func TestDuplicateOutOfOrderConflictAndCrashRecovery(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	resolver := resolverFor(site)
	manager := testManager(t, root, resolver, nil)
	entry := putCacheEntry(t, root, site, "/replay?q=secret")
	task := taskFor(site, "replay", ActionPurgeExact, cacheURL(site, "/replay?q=secret"))
	task.DeliveryAttempt = 2
	first, err := manager.Execute(context.Background(), task)
	if err != nil || first.Replayed {
		t.Fatalf("first=%+v error=%v", first, err)
	}
	if _, err := os.Stat(entry); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry remains: %v", err)
	}
	duplicate, err := manager.Execute(context.Background(), task)
	if err != nil || !duplicate.Replayed || duplicate.Items[0].Affected != 1 {
		t.Fatalf("same-attempt replay=%+v error=%v", duplicate, err)
	}
	older := task
	older.DeliveryAttempt = 1
	replay, err := manager.Execute(context.Background(), older)
	if err != nil || !replay.Replayed || replay.Items[0].Affected != 1 {
		t.Fatalf("out-of-order replay=%+v error=%v", replay, err)
	}

	conflict := task
	conflict.Targets = []string{cacheURL(site, "/different")}
	if _, err := manager.Execute(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("payload conflict error=%v", err)
	}
	otherTask := task
	otherTask.TaskID = "task-other"
	if _, err := manager.Execute(context.Background(), otherTask); !errors.Is(err, ErrConflict) {
		t.Fatalf("operation conflict error=%v", err)
	}

	crashEntry := putCacheEntry(t, root, site, "/crash")
	crashTask := taskFor(site, "crash", ActionPurgeExact, cacheURL(site, "/crash"))
	normalized, err := normalizeTask(crashTask, site, manager.config, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record.Items[0].Status = recordWorking
	record.Items[0].Attempts = 1
	record.Items[0].DestructiveStarted = true
	if err := manager.store.update(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	entries := collectCacheEntries(t, manager, site)
	if deleted, err := deleteCacheEntries(context.Background(), purgeMatches(ActionPurgeExact, normalized.Targets[0], entries)); err != nil || deleted != 1 {
		t.Fatalf("simulated delete=%d error=%v", deleted, err)
	}
	if _, err := os.Stat(crashEntry); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("simulated crash did not delete entry: %v", err)
	}
	restarted := testManager(t, root, resolver, nil)
	recovered, err := restarted.Execute(context.Background(), crashTask)
	if err != nil || recovered.State != StateSucceeded || recovered.Attempt != 2 ||
		recovered.Items[0].Code != CodePurged || recovered.Items[0].Attempts != 2 {
		t.Fatalf("recovered=%+v error=%v", recovered, err)
	}
}

type testHTTPServer struct {
	listener net.Listener
	server   *http.Server
}

func startTestHTTPServer(t *testing.T, handler http.Handler) *testHTTPServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	value := &testHTTPServer{listener: listener, server: server}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return value
}

func startPrewarmHTTPServer(t *testing.T, handler http.Handler) *testHTTPServer {
	t.Helper()
	return startTestHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		const marker = "/.cdnca-internal/cache-task/v2/"
		path := strings.TrimPrefix(request.URL.Path, marker)
		separator := strings.IndexByte(path, '/')
		if request.Header.Get("X-CDNCA-Internal-Cache-Task") != CacheKeyVersion ||
			len(request.Header.Values("X-CDNCA-Cache-Namespace")) != 1 ||
			len(path) < 33 || separator != 32 || !lowerHex(path[:separator]) {
			http.NotFound(writer, request)
			return
		}
		cloned := request.Clone(request.Context())
		clonedURL := *request.URL
		clonedURL.Path = path[separator:]
		clonedURL.RawPath = ""
		cloned.URL = &clonedURL
		handler.ServeHTTP(writer, cloned)
	}))
}

func (s *testHTTPServer) port() uint16 {
	return uint16(s.listener.Addr().(*net.TCPAddr).Port)
}

func cacheHeaders(writer http.ResponseWriter, site SiteContext, state string) {
	writer.Header().Set("X-CDNCA-Config-Version", site.ConfigVersionID)
	writer.Header().Set("X-CDNCA-Cache-Namespace", site.CacheIdentity)
	writer.Header().Set("X-CDN-Cache", state)
}

func missThenHit(seen *sync.Map, key string) string {
	if _, loaded := seen.LoadOrStore(key, struct{}{}); loaded {
		return "HIT"
	}
	return "MISS"
}

func TestPrewarmSuccessLimitsSSRFRedirectAndSensitiveState(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var redirected atomic.Int32
	var seen sync.Map
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
			request.Header.Get("Range") != "" || request.Header.Get("Upgrade") != "" {
			t.Errorf("forbidden request header forwarded")
		}
		state := "MISS"
		if request.URL.Path == "/ok" {
			state = missThenHit(&seen, request.URL.Path)
		} else if request.URL.Path == "/hit" {
			state = "HIT"
		}
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, request.URL.RequestURI()); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		switch request.URL.Path {
		case "/hit":
		case "/redirect":
			writer.Header().Set("Location", "http://127.0.0.1/private")
			writer.WriteHeader(http.StatusFound)
		case "/private":
			redirected.Add(1)
		case "/large":
			_, _ = writer.Write(make([]byte, 65))
			return
		case "/bypass":
			writer.Header().Set("X-CDN-Cache", "BYPASS")
		case "/stale":
			writer.Header().Set("X-CDNCA-Config-Version", "other")
		case "/wrong-namespace":
			writer.Header().Set("X-CDNCA-Cache-Namespace", strings.Repeat("a", 64))
		}
		_, _ = io.WriteString(writer, "response-body-secret")
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	manager := testManager(t, root, resolverFor(site), func(config *Config) {
		config.MaxResponseBytes = 64
		config.MaxTaskBytes = 1024
		// The fake origin flips /ok from MISS to HIT on its first request. With
		// the 100ms default a slow first response on a loaded host times out,
		// is retried and sees HIT (ALREADY_CACHED); nothing here tests timeouts.
		config.RequestTimeout = 5 * time.Second
	})
	targets := []string{"/ok?token=query-secret", "/hit", "/redirect", "/large", "/bypass", "/stale", "/wrong-namespace"}
	urls := make([]string, len(targets))
	for index, target := range targets {
		urls[index] = cacheURL(site, target)
	}
	task := taskFor(site, "prewarm-codes", ActionPrewarm, urls...)
	task.Budget.MaxResourceBytes = 64
	task.Budget.MaxTotalBytes = 1024
	result, err := manager.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{CodePrewarmed, CodeAlreadyCached, CodePrewarmRedirect, CodePrewarmResponseTooLarge,
		CodePrewarmNotCacheable, CodeSiteContextStale, CodeSiteContextStale}
	for index, code := range want {
		if result.Items[index].Code != code {
			t.Errorf("item %d code=%s want=%s", index, result.Items[index].Code, code)
		}
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect was followed %d times", redirected.Load())
	}
	if !strings.Contains(result.Items[0].Target, targetHashMarker) || strings.Contains(result.Items[0].Target, "query-secret") {
		t.Fatalf("result target not redacted: %q", result.Items[0].Target)
	}

	_, ssrfErr := manager.Execute(context.Background(), taskFor(site, "ssrf", ActionPrewarm,
		fmt.Sprintf("http://127.0.0.1:%d/private", site.ListenPort)))
	if !errors.Is(ssrfErr, ErrInvalidTask) {
		t.Fatalf("SSRF error=%v", ssrfErr)
	}
	encodedResult, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, visible := range []string{string(encodedResult), ssrfErr.Error()} {
		for _, secret := range []string{"query-secret", "Authorization", "Cookie", "response-body-secret"} {
			if strings.Contains(visible, secret) {
				t.Fatalf("%q leaked in public result or error", secret)
			}
		}
	}
	stateRoot := filepath.Join(root, "state", "cache-tasks")
	err = filepath.WalkDir(stateRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, secret := range []string{"query-secret", "Authorization", "Cookie", "response-body-secret"} {
			if strings.Contains(string(body), secret) {
				return fmt.Errorf("%s leaked in %s", secret, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrewarmRetryBackoffTimeoutDeadlineAndByteBudget(t *testing.T) {
	var site SiteContext
	var failures atomic.Int32
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cacheHeaders(writer, site, "MISS")
		switch request.URL.Path {
		case "/retry":
			failures.Add(1)
			writer.WriteHeader(http.StatusBadGateway)
		case "/timeout":
			time.Sleep(80 * time.Millisecond)
		case "/bytes":
			_, _ = writer.Write(make([]byte, 50))
			return
		}
		_, _ = writer.Write([]byte("ok"))
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	var mu sync.Mutex
	var jittered, slept []time.Duration
	fixedNow := time.Now().UTC()
	manager := testManager(t, testStateRoot(t), resolverFor(site), func(config *Config) {
		config.RequestTimeout = 20 * time.Millisecond
		config.Now = func() time.Time { return fixedNow }
		config.Jitter = func(value time.Duration) time.Duration {
			mu.Lock()
			jittered = append(jittered, value)
			mu.Unlock()
			return value
		}
		config.Sleep = func(_ context.Context, value time.Duration) error {
			mu.Lock()
			slept = append(slept, value)
			mu.Unlock()
			return nil
		}
	})
	retryTask := taskFor(site, "retry", ActionPrewarm, cacheURL(site, "/retry"))
	retryTask.Deadline = fixedNow.Add(time.Minute)
	retry, err := manager.Execute(context.Background(), retryTask)
	if err != nil || retry.Items[0].Code != CodeRetryExhausted ||
		retry.Items[0].CauseCode != CodePrewarmStatus || retry.Items[0].Attempts != 3 || failures.Load() != 3 {
		t.Fatalf("retry=%+v failures=%d error=%v", retry, failures.Load(), err)
	}
	mu.Lock()
	if len(jittered) != 2 || jittered[0] != time.Millisecond || jittered[1] != 2*time.Millisecond || len(slept) != 2 {
		t.Fatalf("jittered=%v slept=%v", jittered, slept)
	}
	mu.Unlock()

	timeoutTask := taskFor(site, "timeout", ActionPrewarm, cacheURL(site, "/timeout"))
	timeoutTask.Deadline = fixedNow.Add(time.Minute)
	timeoutTask.Budget.MaxAttempts = 1
	timeout, err := manager.Execute(context.Background(), timeoutTask)
	if err != nil || timeout.Items[0].Code != CodeRetryExhausted || timeout.Items[0].CauseCode != CodePrewarmTimeout {
		t.Fatalf("timeout=%+v error=%v", timeout, err)
	}

	deadlineTask := taskFor(site, "deadline", ActionPrewarm, cacheURL(site, "/ok"))
	deadlineTask.Deadline = fixedNow.Add(-time.Second)
	deadline, err := manager.Execute(context.Background(), deadlineTask)
	if err != nil || deadline.Items[0].Code != CodeTaskDeadlineExceeded || deadline.State != StateFailed {
		t.Fatalf("deadline=%+v error=%v", deadline, err)
	}

	byteTask := taskFor(site, "bytes", ActionPrewarm, cacheURL(site, "/bytes"), cacheURL(site, "/bytes?second=1"))
	byteTask.Deadline = fixedNow.Add(time.Minute)
	byteTask.Budget.MaxConcurrency = 1
	byteTask.Budget.MaxAttempts = 1
	byteTask.Budget.MaxResourceBytes = 50
	byteTask.Budget.MaxTotalBytes = 50
	bytesResult, err := manager.Execute(context.Background(), byteTask)
	if err != nil || bytesResult.Items[0].Code != CodePrewarmResponseTooLarge || bytesResult.Items[1].Code != CodePrewarmTaskBytesExceeded ||
		bytesResult.Progress.Bytes != 50 {
		t.Fatalf("bytes result=%+v error=%v", bytesResult, err)
	}
}

func TestPrewarmMissToHitChargesExactResourceBodyOnce(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var requests atomic.Int32
	body := strings.Repeat("x", 50)
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		state := "MISS"
		if requests.Add(1) == 2 {
			state = "HIT"
		}
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, "/exact"); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = writer.Write([]byte(body))
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "miss-hit-byte-boundary", ActionPrewarm, cacheURL(site, "/exact"))
	task.Budget.MaxConcurrency = 1
	task.Budget.MaxAttempts = 1
	task.Budget.MaxResourceBytes = int64(len(body))
	task.Budget.MaxTotalBytes = int64(len(body))

	result, err := manager.Execute(context.Background(), task)
	if err != nil || result.State != StateSucceeded || len(result.Items) != 1 ||
		result.Items[0].Code != CodePrewarmed || result.Items[0].Bytes != int64(len(body)) ||
		result.Progress.Bytes != int64(len(body)) || requests.Load() != 2 {
		t.Fatalf("result=%+v requests=%d error=%v", result, requests.Load(), err)
	}
}

func TestPrewarmVerificationAccountingUsesMaximumBody(t *testing.T) {
	tests := []struct {
		name      string
		states    [2]string
		sizes     [2]int
		allowance int64
		wantCode  string
		wantState TaskState
		wantBytes int64
	}{
		{name: "unequal miss hit uses larger first body", states: [2]string{"MISS", "HIT"}, sizes: [2]int{41, 17}, allowance: 64,
			wantCode: CodePrewarmed, wantState: StateSucceeded, wantBytes: 41},
		{name: "unequal miss hit uses larger verification body", states: [2]string{"MISS", "HIT"}, sizes: [2]int{17, 41}, allowance: 64,
			wantCode: CodePrewarmed, wantState: StateSucceeded, wantBytes: 41},
		{name: "double miss charges combined bodies at exact boundary", states: [2]string{"MISS", "MISS"}, sizes: [2]int{23, 41}, allowance: 64,
			wantCode: CodePrewarmNotCacheable, wantState: StateFailed, wantBytes: 64},
		{name: "double miss exceeds total boundary", states: [2]string{"MISS", "MISS"}, sizes: [2]int{23, 42}, allowance: 64,
			wantCode: CodePrewarmResponseTooLarge, wantState: StateFailed, wantBytes: 64},
		{name: "equal miss and hit at resource boundary", states: [2]string{"MISS", "HIT"}, sizes: [2]int{64, 64}, allowance: 64,
			wantCode: CodePrewarmed, wantState: StateSucceeded, wantBytes: 64},
		{name: "second verification response 65 exceeds 64 byte limit", states: [2]string{"MISS", "HIT"}, sizes: [2]int{32, 65}, allowance: 64,
			wantCode: CodePrewarmResponseTooLarge, wantState: StateFailed, wantBytes: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := testStateRoot(t)
			var site SiteContext
			var requests atomic.Int32
			server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				index := int(requests.Add(1)) - 1
				if index < 0 || index >= len(test.states) {
					t.Fatalf("unexpected request index %d", index)
				}
				cacheHeaders(writer, site, test.states[index])
				if test.states[index] == "HIT" {
					if err := writeCacheEntryEvidence(root, site, "/object"); err != nil {
						t.Errorf("write cache evidence: %v", err)
					}
				}
				_, _ = writer.Write(make([]byte, test.sizes[index]))
			}))
			site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
			manager := testManager(t, root, resolverFor(site), nil)
			task := taskFor(site, "verification-accounting", ActionPrewarm, cacheURL(site, "/object"))
			task.Budget.MaxConcurrency = 1
			task.Budget.MaxAttempts = 1
			task.Budget.MaxResourceBytes = test.allowance
			task.Budget.MaxTotalBytes = test.allowance

			result, err := manager.Execute(context.Background(), task)
			if err != nil || result.State != test.wantState || len(result.Items) != 1 ||
				result.Items[0].Code != test.wantCode || result.Items[0].Bytes != test.wantBytes ||
				result.Progress.Bytes != test.wantBytes || requests.Load() != 2 {
				t.Fatalf("result=%+v requests=%d error=%v", result, requests.Load(), err)
			}
		})
	}
}

func TestPrewarmRequestRejectsBodyCloseFailure(t *testing.T) {
	closeErr := errors.New("close failed")
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 18081, 1)
	headers := make(http.Header)
	headers.Set("X-CDNCA-Config-Version", site.ConfigVersionID)
	headers.Set("X-CDNCA-Cache-Namespace", site.CacheIdentity)
	headers.Set("X-CDN-Cache", "HIT")
	called := false
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{
			StatusCode: http.StatusOK, Header: headers, Request: request,
			Body: &closeErrorBody{Reader: strings.NewReader("response"), err: closeErr},
		}, nil
	})}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://cache.example.test/internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome, state := executePrewarmRequest(context.Background(), request.Context(), client, request, site,
		map[int]struct{}{http.StatusOK: {}}, 64, 64)
	if !called || state != "HIT" || outcome.status != ItemFailed || outcome.code != CodePrewarmUpstream ||
		!outcome.retryable || outcome.bytes != 8 {
		t.Fatalf("called=%t state=%q outcome=%+v", called, state, outcome)
	}
}

func TestPrewarmCloseRetryChargesResourceOnce(t *testing.T) {
	for _, totalBytes := range []int64{64, 128} {
		t.Run(fmt.Sprintf("total-%d", totalBytes), func(t *testing.T) {
			site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 18081, 1)
			headers := make(http.Header)
			headers.Set("X-CDNCA-Config-Version", site.ConfigVersionID)
			headers.Set("X-CDNCA-Cache-Namespace", site.CacheIdentity)
			headers.Set("X-CDN-Cache", "HIT")
			var attempts atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				attempt := attempts.Add(1)
				var closeErr error
				if attempt == 1 {
					closeErr = errors.New("retryable close failure")
				}
				return &http.Response{
					StatusCode: http.StatusOK, Header: headers.Clone(), Request: request,
					Body: &closeErrorBody{Reader: strings.NewReader(strings.Repeat("x", 64)), err: closeErr},
				}, nil
			})}
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://cache.example.test/internal", nil)
			if err != nil {
				t.Fatal(err)
			}

			manager := testManager(t, testStateRoot(t), resolverFor(site), nil)
			manager.prewarmAttempt = func(ctx context.Context, _ normalizedTask, _ normalizedTarget,
				_ *tokenBucket, allowance int64) prewarmOutcome {
				outcome, _ := executePrewarmRequest(ctx, request.Context(), client, request.Clone(ctx), site,
					map[int]struct{}{http.StatusOK: {}}, allowance, allowance)
				return outcome
			}
			task := taskFor(site, fmt.Sprintf("close-retry-%d", totalBytes), ActionPrewarm, cacheURL(site, "/object"))
			task.Budget.MaxAttempts = 2
			task.Budget.MaxConcurrency = 1
			task.Budget.MaxResourceBytes = 64
			task.Budget.MaxTotalBytes = totalBytes

			result, err := manager.Execute(context.Background(), task)
			if err != nil || result.State != StateSucceeded || attempts.Load() != 2 ||
				result.Items[0].Status != ItemSkipped || result.Items[0].Code != CodeAlreadyCached ||
				result.Items[0].Attempts != 2 || result.Items[0].Bytes != 64 || result.Progress.Bytes != 64 {
				t.Fatalf("result=%+v attempts=%d error=%v", result, attempts.Load(), err)
			}
		})
	}
}

func TestPrewarmCancellationLookupAndCrashReservationRecovery(t *testing.T) {
	root := testStateRoot(t)
	var site SiteContext
	var seen sync.Map
	entered := make(chan struct{}, 1)
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state := "MISS"
		if request.URL.Path == "/ok" {
			state = missThenHit(&seen, request.URL.Path)
		}
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, request.URL.RequestURI()); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		if request.URL.Path == "/block" {
			entered <- struct{}{}
			<-request.Context().Done()
			return
		}
		_, _ = writer.Write([]byte("ok"))
	}))
	site = testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, server.port(), 1)
	manager := testManager(t, root, resolverFor(site), nil)
	task := taskFor(site, "cancel", ActionPrewarm, cacheURL(site, "/block"))
	resultCh := make(chan Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := manager.Execute(context.Background(), task)
		resultCh <- result
		errCh <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("prewarm did not start")
	}
	cancelled, err := manager.Cancel(context.Background(), taskReference(task))
	if err != nil || cancelled.State != StateCancelled || cancelled.Items[0].Code != CodeTaskCancelled {
		t.Fatalf("cancelled=%+v error=%v", cancelled, err)
	}
	if result := <-resultCh; result.State != StateCancelled {
		t.Fatalf("execute after cancel=%+v", result)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("execute cancel error=%v", err)
	}
	lookup, err := manager.Lookup(context.Background(), taskReference(task))
	if err != nil || lookup.State != StateCancelled {
		t.Fatalf("lookup=%+v error=%v", lookup, err)
	}

	crashTask := taskFor(site, "prewarm-crash", ActionPrewarm, cacheURL(site, "/ok"))
	normalized, err := normalizeTask(crashTask, site, manager.config, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := manager.store.prepare(context.Background(), normalized, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record.Items[0].Status = recordWorking
	record.Items[0].Attempts = 1
	record.Items[0].ReservedBytes = crashTask.Budget.MaxResourceBytes
	if err := manager.store.update(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	restarted := testManager(t, root, resolverFor(site), nil)
	recovered, err := restarted.Execute(context.Background(), crashTask)
	if err != nil || recovered.State != StateSucceeded || recovered.Items[0].Attempts != 2 ||
		recovered.Items[0].Bytes < crashTask.Budget.MaxResourceBytes {
		t.Fatalf("crash recovery=%+v error=%v", recovered, err)
	}
}

func TestJournalWriteFailureBeforeAndAfterDestructiveOperation(t *testing.T) {
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)

	beforeRoot := testStateRoot(t)
	beforeManager := testManager(t, beforeRoot, resolverFor(site), nil)
	beforePath := putCacheEntry(t, beforeRoot, site, "/before")
	original := beforeManager.store.writeJSON
	writes := 0
	beforeManager.store.writeJSON = func(tmpDir, path string, value any) error {
		writes++
		if writes == 3 {
			return errors.New("injected journal failure")
		}
		return original(tmpDir, path, value)
	}
	_, err := beforeManager.Execute(context.Background(), taskFor(site, "write-before", ActionPurgeExact, cacheURL(site, "/before")))
	if !errors.Is(err, ErrJournalWrite) {
		t.Fatalf("before error=%v", err)
	}
	if _, err := os.Stat(beforePath); err != nil {
		t.Fatalf("pre-operation journal failure deleted entry: %v", err)
	}

	afterRoot := testStateRoot(t)
	afterManager := testManager(t, afterRoot, resolverFor(site), nil)
	afterPath := putCacheEntry(t, afterRoot, site, "/after")
	original = afterManager.store.writeJSON
	writes = 0
	afterManager.store.writeJSON = func(tmpDir, path string, value any) error {
		writes++
		if writes == 6 {
			return errors.New("injected completion failure")
		}
		return original(tmpDir, path, value)
	}
	afterTask := taskFor(site, "write-after", ActionPurgeExact, cacheURL(site, "/after"))
	unknown, err := afterManager.Execute(context.Background(), afterTask)
	if !errors.Is(err, ErrJournalWrite) || unknown.State == StateSucceeded {
		t.Fatalf("completion failure result=%+v error=%v", unknown, err)
	}
	if _, err := os.Stat(afterPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected physical delete before journal failure: %v", err)
	}
	restarted := testManager(t, afterRoot, resolverFor(site), nil)
	recovered, err := restarted.Execute(context.Background(), afterTask)
	if err != nil || recovered.State != StateSucceeded || recovered.Items[0].Code != CodePurged ||
		recovered.Items[0].Affected != 1 {
		t.Fatalf("completion recovery=%+v error=%v", recovered, err)
	}
}

func TestPrewarmBoundedConcurrencyAndSiteIsolation(t *testing.T) {
	root := testStateRoot(t)
	var siteA, siteB SiteContext
	var mu sync.Mutex
	active := map[string]int{}
	maximum := map[string]int{}
	globalActive, globalMaximum := 0, 0
	withinGate := make(chan struct{})
	parallelGate := make(chan struct{})
	withinCount := 0
	parallelHosts := map[string]struct{}{}
	var seen sync.Map
	var withinOnce, parallelOnce sync.Once
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		active[request.Host]++
		globalActive++
		maximum[request.Host] = max(maximum[request.Host], active[request.Host])
		globalMaximum = max(globalMaximum, globalActive)
		if strings.HasPrefix(request.URL.Path, "/within-") {
			withinCount++
			if withinCount == 2 {
				withinOnce.Do(func() { close(withinGate) })
			}
		}
		if strings.HasPrefix(request.URL.Path, "/parallel-") {
			parallelHosts[request.Host] = struct{}{}
			if len(parallelHosts) == 2 {
				parallelOnce.Do(func() { close(parallelGate) })
			}
		}
		mu.Unlock()
		if strings.HasPrefix(request.URL.Path, "/within-") {
			select {
			case <-withinGate:
			case <-request.Context().Done():
			}
		} else if strings.HasPrefix(request.URL.Path, "/parallel-") {
			select {
			case <-parallelGate:
			case <-request.Context().Done():
			}
		} else {
			time.Sleep(30 * time.Millisecond)
		}
		site := siteA
		if request.Host == siteB.Domain {
			site = siteB
		}
		state := missThenHit(&seen, request.Host+request.URL.Path)
		cacheHeaders(writer, site, state)
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, request.URL.RequestURI()); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		_, _ = writer.Write([]byte("ok"))
		mu.Lock()
		active[request.Host]--
		globalActive--
		mu.Unlock()
	}))
	port := server.port()
	siteA = testSite("tenant-a", "site-a", "config-v1", "a.example.test", 18080, port, 1)
	siteB = testSite("tenant-a", "site-b", "config-v1", "b.example.test", 18080, port, 1)
	manager := testManager(t, root, resolverFor(siteA, siteB), func(config *Config) {
		config.GlobalConcurrency = 2
		config.MaxTaskConcurrency = 2
		config.RequestTimeout = 5 * time.Second
	})

	within := taskFor(siteA, "within-site", ActionPrewarm, cacheURL(siteA, "/within-one"), cacheURL(siteA, "/within-two"))
	within.Budget.MaxConcurrency = 2
	if result, err := manager.Execute(context.Background(), within); err != nil || result.State != StateSucceeded {
		t.Fatalf("within-site result=%+v error=%v", result, err)
	}
	mu.Lock()
	withinMaximum := maximum[siteA.Domain]
	mu.Unlock()
	if withinMaximum != 2 {
		t.Fatalf("within-site concurrency=%d want=2", withinMaximum)
	}

	mu.Lock()
	maximum = map[string]int{}
	globalMaximum = 0
	mu.Unlock()
	var wait sync.WaitGroup
	errorsCh := make(chan error, 2)
	for _, task := range []Task{
		taskFor(siteA, "site-a-parallel", ActionPrewarm, cacheURL(siteA, "/parallel-a")),
		taskFor(siteB, "site-b-parallel", ActionPrewarm, cacheURL(siteB, "/parallel-b")),
	} {
		wait.Add(1)
		go func(task Task) {
			defer wait.Done()
			_, err := manager.Execute(context.Background(), task)
			errorsCh <- err
		}(task)
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if globalMaximum != 2 || maximum[siteA.Domain] != 1 || maximum[siteB.Domain] != 1 {
		t.Fatalf("different-site concurrency global=%d sites=%v", globalMaximum, maximum)
	}
}

func TestCacheMetadataRejectsWrongVersionAndParentSwap(t *testing.T) {
	root := testStateRoot(t)
	site := testSite("tenant-a", "site-a", "config-v1", "cache.example.test", 18080, 19080, 1)
	manager := testManager(t, root, resolverFor(site), nil)

	wrong := site
	wrong.ConfigVersionID = "config-v2"
	wrong.CacheIdentity = site.CacheIdentity
	key := cacheKeyValue(wrong, "/wrong")
	path := nginxCachePath(filepath.Join(root, "shared", "cache", site.CacheIdentity), key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\nKEY: "+key+"\nbody"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Execute(context.Background(), taskFor(site, "wrong-key-version", ActionPurgeSite))
	if err != nil || result.Items[0].Code != CodeCacheMetadataInvalid {
		t.Fatalf("wrong version result=%+v error=%v", result, err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	entryPath := putCacheEntry(t, root, site, "/race")
	entries := collectCacheEntries(t, manager, site)
	if len(entries) != 1 {
		t.Fatalf("entries=%+v", entries)
	}
	parent := filepath.Dir(entryPath)
	moved := parent + ".moved"
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsidePath := filepath.Join(outside, filepath.Base(entryPath))
	if err := os.WriteFile(outsidePath, []byte("must-remain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, parent); err != nil {
		t.Fatal(err)
	}
	deleted, err := deleteCacheEntries(context.Background(), entries)
	var operation *operationError
	if deleted != 0 || !errors.As(err, &operation) || operation.code != CodeCacheEntryChanged {
		t.Fatalf("deleted=%d error=%v", deleted, err)
	}
	if body, err := os.ReadFile(outsidePath); err != nil || string(body) != "must-remain" {
		t.Fatalf("outside changed body=%q error=%v", body, err)
	}
}

func TestNginxCachePathMatchesNativeMD5Layout(t *testing.T) {
	key := "v2|tenant|site|1|cfg|example.test|443|/asset?q=1"
	digest := md5.Sum([]byte(key))
	hexDigest := hex.EncodeToString(digest[:])
	want := filepath.Join("/cache", hexDigest[31:], hexDigest[29:31], hexDigest)
	if got := nginxCachePath("/cache", key); got != want {
		t.Fatalf("path=%s want=%s", got, want)
	}
}
