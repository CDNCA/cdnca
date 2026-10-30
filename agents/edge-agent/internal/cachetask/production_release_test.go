package cachetask

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	productionTenantID       = "11111111-1111-4111-8111-111111111111"
	productionSiteID         = "22222222-2222-4222-8222-222222222222"
	productionVersionV1      = "33333333-3333-4333-8333-333333333333"
	productionVersionV2      = "44444444-4444-4444-8444-444444444444"
	productionVersionUnknown = "55555555-5555-4555-8555-555555555555"
)

type blockingFirstSiteResolver struct {
	delegate  SiteResolver
	resolved  chan SiteContext
	release   chan struct{}
	mu        sync.Mutex
	calls     int
	blockCall int
}

type fixedErrorReader struct {
	err error
}

func (reader fixedErrorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

type observedPrewarmBody struct {
	reader   io.Reader
	onRead   func()
	onClose  func()
	closeErr error
}

func (body *observedPrewarmBody) Read(buffer []byte) (int, error) {
	body.onRead()
	return body.reader.Read(buffer)
}

func (body *observedPrewarmBody) Close() error {
	body.onClose()
	return body.closeErr
}

func (r *blockingFirstSiteResolver) ResolveSite(
	ctx context.Context,
	tenantID, siteID, configVersionID string,
	configRevision uint64,
) (SiteContext, error) {
	site, err := r.delegate.ResolveSite(ctx, tenantID, siteID, configVersionID, configRevision)
	r.mu.Lock()
	r.calls++
	blocked := r.calls == r.blockCall
	r.mu.Unlock()
	if !blocked || err != nil {
		return site, err
	}
	select {
	case r.resolved <- site:
	case <-ctx.Done():
		return SiteContext{}, ctx.Err()
	}
	select {
	case <-r.release:
		return site, nil
	case <-ctx.Done():
		return SiteContext{}, ctx.Err()
	}
}

func (r *blockingFirstSiteResolver) lockActiveRelease(ctx context.Context) (func(), error) {
	resolver, ok := r.delegate.(activeReleaseLeaser)
	if !ok {
		return nil, ErrInvalidState
	}
	return resolver.lockActiveRelease(ctx)
}

func TestCacheIdentityMatchesCompilerAndIgnoresMutableRevision(t *testing.T) {
	first := testSite(productionTenantID, productionSiteID, productionVersionV1, "cache.example.test", 8080, 8080, 7)
	second := first
	second.ConfigRevision = 8

	wantNamespace := edgeconfig.CacheNamespaceID(first.TenantID, first.SiteID, first.ConfigVersionID)
	if first.CacheIdentity != wantNamespace || second.CacheIdentity != wantNamespace {
		t.Fatalf("cache namespace drifted with revision: first=%q second=%q want=%q", first.CacheIdentity, second.CacheIdentity, wantNamespace)
	}
	wantKey := edgeconfig.CacheKeyPrefix(first.TenantID, first.SiteID, first.ConfigVersionID, first.Domain, first.ListenPort) + "/asset?q=1"
	if got := cacheKeyValue(first, "/asset?q=1"); got != wantKey {
		t.Fatalf("cacheKeyValue() = %q, want compiler key %q", got, wantKey)
	}
	if cacheKeyValue(first, "/asset?q=1") != cacheKeyValue(second, "/asset?q=1") {
		t.Fatal("mutable config revision changed the cache key")
	}
	parsed, err := parseCacheKey(wantKey)
	if err != nil || parsed.configVersion != first.ConfigVersionID || parsed.domain != first.Domain || parsed.port != first.ListenPort {
		t.Fatalf("parseCacheKey(compiler key) = %+v, %v", parsed, err)
	}
}

func TestActiveReleaseResolverLoadsAllListenersAndRejectsStaleIdentity(t *testing.T) {
	root := activeReleaseRoot(t)
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{
		productionListener(8080), productionListener(8443),
	})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatalf("NewActiveReleaseResolver() error = %v", err)
	}

	site, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil || len(site.Listeners) != 2 || site.CacheIdentity != edgeconfig.CacheNamespaceID(productionTenantID, productionSiteID, productionVersionV1) {
		t.Fatalf("ResolveSite() = %+v, %v", site, err)
	}
	if site.Listeners[0].ListenPort != 8080 || site.Listeners[1].ListenPort != 8443 {
		t.Fatalf("listeners = %+v", site.Listeners)
	}
	for _, identity := range []struct {
		tenant, site, version string
		revision              uint64
	}{
		{productionTenantID, productionSiteID, productionVersionV1, 8},
		{productionTenantID, productionSiteID, productionVersionV2, 7},
		{productionTenantID, "55555555-5555-4555-8555-555555555555", productionVersionV1, 7},
		{"66666666-6666-4666-8666-666666666666", productionSiteID, productionVersionV1, 7},
	} {
		if _, err := resolver.ResolveSite(context.Background(), identity.tenant, identity.site, identity.version, identity.revision); !errors.Is(err, ErrSiteNotFound) {
			t.Fatalf("ResolveSite(%+v) error = %v, want ErrSiteNotFound", identity, err)
		}
	}

	activateCacheRelease(t, root, productionVersionV2, 8, []edgeconfig.CacheListenerPolicy{productionListenerForVersion(8080, productionVersionV2)})
	if _, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7); !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("old active version error = %v, want ErrSiteNotFound", err)
	}
	if _, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV2, 8); err != nil {
		t.Fatalf("new active version error = %v", err)
	}
}

func TestActiveReleaseResolverBindsProtocolAndDedicatedPrewarm(t *testing.T) {
	root := activeReleaseRoot(t)
	listener := productionListener(8443)
	listener.Protocol = edgeconfig.ProtocolHTTPS
	listener.PrewarmPort = 19443
	listener.PrewarmPathPrefix = edgeconfig.CachePrewarmPathPrefix(productionTenantID, productionSiteID,
		productionVersionV1, listener.Domain, listener.ListenPort, listener.Protocol)
	files := cacheReleaseFiles(t, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
	parsed, err := edgeconfig.ParseCachePolicyManifest(files[edgeconfig.CachePolicyManifestPath])
	if err != nil {
		t.Fatalf("%v: %s", err, files[edgeconfig.CachePolicyManifestPath])
	}
	if site, err := siteFromManifest(parsed, nil, strings.Repeat("a", sha256.Size*2),
		productionTenantID, productionSiteID, productionVersionV1, 7); err != nil {
		t.Fatalf("signed site parser = %+v/%v", site, err)
	}
	activateSiteRuntimeRelease(t, root, files)
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	site, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil || len(site.Listeners) != 1 || site.Listeners[0].Scheme != "https" || site.Listeners[0].PrewarmPort != 19443 {
		t.Fatalf("signed listener binding = %+v, %v", site, err)
	}
	bound := siteForListener(site, site.Listeners[0], site.Listeners[0].Scheme)
	httpsTask := taskFor(bound, "signed-https", ActionPrewarm, "https://cache.example.test:8443/asset")
	config := DefaultConfig()
	httpsTask.Budget.RequestsPerSecond = config.SiteRequestsPerSecond
	httpsTask.Budget.Burst = config.SiteBurst
	if _, err := normalizeTask(httpsTask, site, config, time.Now().UTC()); err != nil {
		t.Fatalf("signed HTTPS target rejected: %v", err)
	}
	httpTask := httpsTask
	httpTask.TaskID = "task-signed-http"
	httpTask.OperationID = "operation-signed-http"
	httpTask.Targets = []string{"http://cache.example.test:8443/asset"}
	if _, err := normalizeTask(httpTask, site, DefaultConfig(), time.Now().UTC()); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("transport reinterpretation error = %v, want ErrInvalidTask", err)
	}

	missingRoot := activeReleaseRoot(t)
	missingListener := listener
	missingListener.PrewarmPort = 0
	missingListener.PrewarmPathPrefix = ""
	activateSiteRuntimeRelease(t, missingRoot, cacheReleaseFiles(t, productionVersionV1, 7,
		[]edgeconfig.CacheListenerPolicy{missingListener}))
	missingResolver, err := NewActiveReleaseResolver(missingRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingResolver.ResolveSite(context.Background(), productionTenantID, productionSiteID,
		productionVersionV1, 7); !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("missing dedicated listener error = %v, want ErrSiteNotFound", err)
	}

	unsafeRoot := activeReleaseRoot(t)
	unsafeListener := listener
	unsafeListener.PrewarmPort = unsafeListener.ListenPort
	activateSiteRuntimeRelease(t, unsafeRoot, cacheReleaseFiles(t, productionVersionV1, 7,
		[]edgeconfig.CacheListenerPolicy{unsafeListener}))
	unsafeResolver, err := NewActiveReleaseResolver(unsafeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unsafeResolver.ResolveSite(context.Background(), productionTenantID, productionSiteID,
		productionVersionV1, 7); !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("public listener fallback error = %v, want ErrSiteNotFound", err)
	}
}

func TestActiveReleaseResolverCarriesAdvancedCachePolicy(t *testing.T) {
	root := activeReleaseRoot(t)
	listener := productionListener(8080)
	listener.Policy = edgeconfig.CachePolicyDocument{
		SchemaVersion: edgeconfig.CachePolicyDocumentSchemaV2, Revision: 1, Mode: edgeconfig.CacheOverride,
		QueryMode: edgeconfig.CacheQueryExclude, QueryNames: []string{"token", "utm_source"},
		VaryHeaders: []string{"accept-language", "x-device"}, DiskQuotaBytes: 64 << 20,
		Rules: []edgeconfig.CacheRuleDocument{
			{Order: 1, PathPrefix: "/assets/", StatusCodes: []int{200}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 11},
			{Order: 2, Extensions: []string{".css"}, StatusCodes: []int{200, 404}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 22},
		},
	}
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	site, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if site.QueryMode != edgeconfig.CacheQueryExclude ||
		!slices.Equal(site.QueryNames, []string{"token", "utm_source"}) ||
		!slices.Equal(site.VaryHeaders, []string{"accept-language", "x-device"}) || len(site.CacheRules) != 2 {
		t.Fatalf("advanced policy was lost by active resolver: %+v", site)
	}
}

func TestActiveReleaseResolverRejectsMissingDuplicateAndTamperedPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, root string)
	}{
		{name: "missing policy", mutate: func(t *testing.T, root string) {
			activateSiteRuntimeRelease(t, root, map[string][]byte{"nginx.conf": []byte("worker_processes 1;\n")})
		}},
		{name: "missing nginx", mutate: func(t *testing.T, root string) {
			files := cacheReleaseFiles(t, productionVersionV1, 7,
				[]edgeconfig.CacheListenerPolicy{productionListener(8080)})
			delete(files, "nginx.conf")
			activateSiteRuntimeRelease(t, root, files)
		}},
		{name: "duplicate listener", mutate: func(t *testing.T, root string) {
			listener := productionListener(8080)
			activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener, listener})
		}},
		{name: "wrong namespace", mutate: func(t *testing.T, root string) {
			listener := productionListener(8080)
			listener.NamespaceID = hex.EncodeToString(make([]byte, sha256.Size))
			activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
		}},
		{name: "content tamper", mutate: func(t *testing.T, root string) {
			derived := activateSiteRuntimeRelease(t, root, cacheReleaseFiles(t, productionVersionV1, 7,
				[]edgeconfig.CacheListenerPolicy{productionListener(8080)}))
			path := filepath.Join(derived, edgeconfig.CachePolicyManifestPath)
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("{}\n"), 0o440); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := activeReleaseRoot(t)
			test.mutate(t, root)
			resolver, err := NewActiveReleaseResolver(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7); !errors.Is(err, ErrSiteNotFound) {
				t.Fatalf("ResolveSite() error = %v, want ErrSiteNotFound", err)
			}
		})
	}
}

func TestManagerUsesAllActiveListenersAndKeepsRevisionAsMetadata(t *testing.T) {
	root := testStateRoot(t)
	first := testSite(productionTenantID, productionSiteID, productionVersionV1, "cache.example.test", 8080, 8080, 7)
	second := first
	second.ListenPort = 8081
	group := first
	group.Domain, group.ListenPort, group.Scheme, group.PrewarmPort = "", 0, "", 0
	group.Listeners = []ListenerContext{
		{Domain: first.Domain, Scheme: "http", ListenPort: first.ListenPort, CacheEnabled: true},
		{Domain: second.Domain, Scheme: "http", ListenPort: second.ListenPort, CacheEnabled: true},
	}
	manager := testManager(t, root, resolverFor(group), nil)
	firstPath := putCacheEntry(t, root, first, "/assets/a.css")
	secondPath := putCacheEntry(t, root, second, "/assets/b.css")

	// ge-cache: a URL purge covers every cache listener serving the host
	// (both ports here), as a visitor may have filled either.
	prefix := taskFor(first, "listener-prefix", ActionPurgePrefix, cacheURL(first, "/assets/"))
	result, err := manager.Execute(context.Background(), prefix)
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 2 {
		t.Fatalf("prefix result = %+v, %v", result, err)
	}
	for _, path := range []string{firstPath, secondPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("listener cache entry %s remains: %v", path, err)
		}
	}

	putCacheEntry(t, root, second, "/assets/c.css")
	secondTask := taskFor(second, "listener-site", ActionPurgeSite)
	result, err = manager.Execute(context.Background(), secondTask)
	if err != nil || result.State != StateSucceeded || result.Items[0].Affected != 1 {
		t.Fatalf("site result = %+v, %v", result, err)
	}

	revised := group
	revised.ConfigRevision = 8
	revisedManager := testManager(t, root, resolverFor(revised), nil)
	revisedTask := taskFor(first, "revision-metadata", ActionPurgeSite)
	revisedTask.ConfigRevision = 8
	if result, err := revisedManager.Execute(context.Background(), revisedTask); err != nil || result.ConfigRevision != 8 {
		t.Fatalf("revision metadata result = %+v, %v", result, err)
	}
}

func TestActiveReleaseManagerRestartKeepsJournalAndRejectsUnknownVersion(t *testing.T) {
	root := activeReleaseRoot(t)
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{productionListener(8080)})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	manager := testManager(t, root, resolver, nil)
	site, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil {
		t.Fatal(err)
	}
	task := taskFor(siteForListener(site, site.Listeners[0], "http"), "active-restart", ActionPurgeSite)
	first, err := manager.Execute(context.Background(), task)
	if err != nil || first.State != StateSucceeded {
		t.Fatalf("first Execute() = %+v, %v", first, err)
	}
	activateCacheRelease(t, root, productionVersionV2, 8, []edgeconfig.CacheListenerPolicy{
		productionListenerForVersion(8080, productionVersionV2),
	})
	restarted := testManager(t, root, resolver, nil)
	journalSite, found, err := restarted.store.journalSite(context.Background(), task)
	if err != nil || !found {
		t.Fatalf("journal binding = %+v/%t/%v", journalSite, found, err)
	}
	replayTask, err := normalizeTask(task, journalSite, restarted.config, restarted.now().UTC())
	if err != nil || replayTask.Digest != first.Digest {
		t.Fatalf("journal replay digest = %q/%v, want %q", replayTask.Digest, err, first.Digest)
	}
	replayed, err := restarted.Execute(context.Background(), task)
	if err != nil || !replayed.Replayed || replayed.Digest != first.Digest {
		t.Fatalf("restarted Execute() = %+v, %v", replayed, err)
	}
	unknown := task
	unknown.TaskID = "task-active-unknown"
	unknown.OperationID = "operation-active-unknown"
	unknown.ConfigVersionID = productionVersionUnknown
	if _, err := restarted.Execute(context.Background(), unknown); !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("unknown version error = %v, want ErrSiteNotFound", err)
	}
}

func TestActiveReleaseRunningJournalSurvivesCutoverCrashWindows(t *testing.T) {
	root := activeReleaseRoot(t)
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{productionListener(8080)})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	site, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil {
		t.Fatal(err)
	}
	bound := siteForListener(site, site.Listeners[0], site.Listeners[0].Scheme)
	manager := testManager(t, root, resolver, nil)

	pendingPath := putCacheEntry(t, root, bound, "/pending")
	pendingTask := taskFor(bound, "cutover-pending", ActionPurgeExact, cacheURL(bound, "/pending"))
	pending, err := normalizeTask(pendingTask, site, manager.config, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.store.prepare(context.Background(), pending, manager.now().UTC()); err != nil {
		t.Fatal(err)
	}

	crashPath := putCacheEntry(t, root, bound, "/crash-after-unlink")
	crashTask := taskFor(bound, "cutover-unlink", ActionPurgeExact, cacheURL(bound, "/crash-after-unlink"))
	crash, err := normalizeTask(crashTask, site, manager.config, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := manager.store.prepare(context.Background(), crash, manager.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(crashPath)
	if err != nil {
		t.Fatal(err)
	}
	cacheRoot := filepath.Join(root, "shared", "cache", bound.CacheIdentity)
	relative, err := filepath.Rel(cacheRoot, crashPath)
	if err != nil {
		t.Fatal(err)
	}
	device, inode, _ := fileIdentity(info)
	record.Items[0].Status = recordWorking
	record.Items[0].Attempts = 1
	record.Items[0].DestructiveStarted = true
	record.Items[0].DeleteIntent = &deleteIntent{
		Relative: filepath.ToSlash(relative), Size: info.Size(), Device: device, Inode: inode,
	}
	if err := manager.store.update(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(crashPath); err != nil {
		t.Fatal(err)
	}
	if err := syncDirectory(filepath.Dir(crashPath)); err != nil {
		t.Fatal(err)
	}

	activateCacheRelease(t, root, productionVersionV2, 8, []edgeconfig.CacheListenerPolicy{
		productionListenerForVersion(8080, productionVersionV2),
	})
	restarted := testManager(t, root, resolver, nil)
	pendingResult, err := restarted.Execute(context.Background(), pendingTask)
	if err != nil || pendingResult.State != StateSucceeded || pendingResult.Items[0].Affected != 1 {
		t.Fatalf("pending LKG recovery = %+v, %v", pendingResult, err)
	}
	if _, err := os.Stat(pendingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending LKG cache entry remains: %v", err)
	}
	crashResult, err := restarted.Execute(context.Background(), crashTask)
	if err != nil || crashResult.State != StateSucceeded || crashResult.Items[0].Affected != 1 {
		t.Fatalf("post-unlink LKG recovery = %+v, %v", crashResult, err)
	}
}

func TestActiveReleasePrewarmJournalRestartsOnlyOnExactActiveBinding(t *testing.T) {
	root := activeReleaseRoot(t)
	var site SiteContext
	var seen int
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen++
		state := "MISS"
		if seen%2 == 0 {
			state = "HIT"
		}
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, request.URL.RequestURI()); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		_, _ = writer.Write([]byte("ok"))
	}))
	listener := productionListener(8080)
	listener.PrewarmPort = server.port()
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	site, err = resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil {
		t.Fatal(err)
	}
	bound := siteForListener(site, site.Listeners[0], site.Listeners[0].Scheme)
	site = bound
	manager := testManager(t, root, resolver, nil)

	seedWorking := func(task Task) {
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
		record.Items[0].ReservedBytes = task.Budget.MaxResourceBytes
		if err := manager.store.update(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}

	same := taskFor(bound, "active-prewarm-restart", ActionPrewarm, cacheURL(bound, "/same"))
	seedWorking(same)
	restarted := testManager(t, root, resolver, nil)
	recovered, err := restarted.Execute(context.Background(), same)
	if err != nil || recovered.State != StateSucceeded || recovered.Items[0].Code != CodePrewarmed ||
		recovered.Items[0].Attempts != 2 || seen != 2 {
		t.Fatalf("same-release prewarm recovery = %+v, seen=%d, error=%v", recovered, seen, err)
	}

	digestCutover := taskFor(bound, "active-prewarm-digest-cutover", ActionPrewarm, cacheURL(bound, "/digest-cutover"))
	seedWorking(digestCutover)
	drifted := cacheReleaseFiles(t, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
	drifted["nginx.conf"] = append(drifted["nginx.conf"], []byte("# release digest changed\n")...)
	var driftedManifest edgeconfig.CachePolicyManifest
	if err := json.Unmarshal(drifted[edgeconfig.CachePolicyManifestPath], &driftedManifest); err != nil {
		t.Fatal(err)
	}
	driftedNginxDigest := sha256.Sum256(drifted["nginx.conf"])
	driftedManifest.NginxSHA256 = hex.EncodeToString(driftedNginxDigest[:])
	driftedPolicy, err := json.Marshal(driftedManifest)
	if err != nil {
		t.Fatal(err)
	}
	drifted[edgeconfig.CachePolicyManifestPath] = append(driftedPolicy, '\n')
	activateSiteRuntimeRelease(t, root, drifted)
	driftedSite, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil || driftedSite.ActiveReleaseSHA256 == site.ActiveReleaseSHA256 || driftedSite.NginxSHA256 == site.NginxSHA256 {
		t.Fatalf("drifted active identity = %+v, original = %+v, error=%v", driftedSite, site, err)
	}
	journalSite, found, err := manager.store.journalSite(context.Background(), digestCutover)
	if err != nil || !found || journalSite.ActiveReleaseSHA256 != site.ActiveReleaseSHA256 || journalSite.NginxSHA256 != site.NginxSHA256 {
		t.Fatalf("journal identity = %+v, original = %+v, found=%t, error=%v", journalSite, site, found, err)
	}
	digestResult, err := testManager(t, root, resolver, nil).Execute(context.Background(), digestCutover)
	if err != nil || digestResult.State != StateFailed || digestResult.Items[0].Code != CodeSiteContextStale || seen != 2 {
		t.Fatalf("digest cutover prewarm recovery = %+v, seen=%d, error=%v", digestResult, seen, err)
	}

	cutover := taskFor(bound, "active-prewarm-cutover", ActionPrewarm, cacheURL(bound, "/cutover"))
	seedWorking(cutover)
	activateCacheRelease(t, root, productionVersionV2, 8, []edgeconfig.CacheListenerPolicy{
		productionListenerForVersion(8080, productionVersionV2),
	})
	cutoverResult, err := testManager(t, root, resolver, nil).Execute(context.Background(), cutover)
	if err != nil || cutoverResult.State != StateFailed || cutoverResult.Items[0].Code != CodeSiteContextStale || seen != 2 {
		t.Fatalf("cutover prewarm recovery = %+v, seen=%d, error=%v", cutoverResult, seen, err)
	}
}

func TestActiveReleasePrewarmRechecksExactBindingImmediatelyBeforeHTTP(t *testing.T) {
	testActiveReleasePrewarmCutoverBeforeHTTP(t, 1)
}

func TestActiveReleasePrewarmClosesFinalBindingCheckTOCTOU(t *testing.T) {
	testActiveReleasePrewarmCutoverBeforeHTTP(t, 2)
}

func TestActiveReleasePrewarmHoldsDeploymentLeaseThroughHTTP(t *testing.T) {
	root := activeReleaseRoot(t)
	var site SiteContext
	var blocked atomic.Int32
	var acquired atomic.Int32
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		lock, err := os.OpenFile(filepath.Join(root, "state", "activation.lock"), os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			acquired.Add(1)
		} else {
			err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			switch {
			case err == nil:
				acquired.Add(1)
				_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			case errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EAGAIN):
				blocked.Add(1)
			default:
				acquired.Add(1)
			}
			_ = lock.Close()
		}
		state := "MISS"
		if blocked.Load() == 2 {
			state = "HIT"
		}
		if state == "HIT" {
			if err := writeCacheEntryEvidence(root, site, "/shared-lease"); err != nil {
				t.Errorf("write cache evidence: %v", err)
			}
		}
		cacheHeaders(writer, site, state)
		_, _ = writer.Write([]byte("ok"))
	}))
	listener := productionListener(8080)
	listener.PrewarmPort = server.port()
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil {
		t.Fatal(err)
	}
	site = siteForListener(resolved, resolved.Listeners[0], resolved.Listeners[0].Scheme)
	task := taskFor(site, "active-prewarm-shared-lease", ActionPrewarm, cacheURL(site, "/shared-lease"))
	result, err := testManager(t, root, resolver, nil).Execute(context.Background(), task)
	if err != nil || result.State != StateSucceeded || result.Items[0].Code != CodePrewarmed ||
		blocked.Load() != 2 || acquired.Load() != 0 {
		t.Fatalf("prewarm lease result=%+v blocked=%d acquired=%d error=%v", result, blocked.Load(), acquired.Load(), err)
	}
}

func TestActiveReleaseLeaseCoversResponseBodyAndReleasesOnEveryExit(t *testing.T) {
	root := activeReleaseRoot(t)
	listener := productionListener(8080)
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID,
		productionVersionV1, 7)
	if err != nil {
		t.Fatal(err)
	}
	site := siteForListener(resolved, resolved.Listeners[0], resolved.Listeners[0].Scheme)
	lockPath := filepath.Join(root, "state", "activation.lock")
	assertLeaseHeld := func(t *testing.T) {
		t.Helper()
		lock, err := os.OpenFile(lockPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			t.Fatal("activation lease was not held during HTTP processing")
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			t.Fatalf("probe activation lease error = %v", err)
		}
	}
	assertLeaseReleased := func(t *testing.T) {
		t.Helper()
		lock, err := os.OpenFile(lockPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("activation lease remained held: %v", err)
		}
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	}

	tests := []struct {
		name      string
		transport error
		readErr   error
		closeErr  error
		cancel    bool
		wantCode  string
	}{
		{name: "success", wantCode: CodePrewarmed},
		{name: "HTTP failure", transport: errors.New("transport failed"), wantCode: CodePrewarmUpstream},
		{name: "read failure", readErr: errors.New("read failed"), wantCode: CodePrewarmUpstream},
		{name: "close failure", closeErr: errors.New("close failed"), wantCode: CodePrewarmUpstream},
		{name: "cancellation", readErr: context.Canceled, cancel: true, wantCode: CodeTaskCancelled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := testManager(t, root, resolver, nil)
			task := taskFor(site, "lease-"+strings.ReplaceAll(test.name, " ", "-"), ActionPrewarm,
				cacheURL(site, "/lease"))
			normalized, err := normalizeTask(task, site, manager.config, manager.now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observedRead, observedClose, observedTransport := false, false, false
			outcome, _ := manager.withActiveReleaseLease(ctx, normalized, func() (prewarmOutcome, string) {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://cache.example.test/lease", nil)
				if err != nil {
					t.Fatal(err)
				}
				client := roundTripFunc(func(request *http.Request) (*http.Response, error) {
					if test.transport != nil {
						assertLeaseHeld(t)
						observedTransport = true
						return nil, test.transport
					}
					reader := io.Reader(strings.NewReader("ok"))
					if test.readErr != nil {
						reader = io.MultiReader(strings.NewReader("ok"), fixedErrorReader{err: test.readErr})
					}
					body := &observedPrewarmBody{
						reader: reader, closeErr: test.closeErr,
						onRead: func() {
							if test.cancel {
								cancel()
							}
							assertLeaseHeld(t)
							observedRead = true
						},
						onClose: func() {
							assertLeaseHeld(t)
							observedClose = true
						},
					}
					header := make(http.Header)
					header.Set("X-CDNCA-Config-Version", site.ConfigVersionID)
					header.Set("X-CDNCA-Cache-Namespace", site.CacheIdentity)
					header.Set("X-CDN-Cache", "MISS")
					return &http.Response{StatusCode: http.StatusOK, Header: header, Body: body, Request: request}, nil
				})
				return executePrewarmRequest(ctx, ctx, &http.Client{Transport: client}, request, site,
					manager.allowedStatuses, 64, 64)
			})
			if outcome.code != test.wantCode {
				t.Fatalf("outcome = %+v, want code %s", outcome, test.wantCode)
			}
			if test.transport != nil {
				if !observedTransport || observedRead || observedClose {
					t.Fatalf("observed transport/read/close = %t/%t/%t", observedTransport, observedRead, observedClose)
				}
			} else if !observedRead || !observedClose {
				t.Fatalf("observed read/close = %t/%t", observedRead, observedClose)
			}
			assertLeaseReleased(t)
		})
	}
}

func testActiveReleasePrewarmCutoverBeforeHTTP(t *testing.T, blockCall int) {
	t.Helper()
	root := activeReleaseRoot(t)
	var site SiteContext
	var seen int
	server := startPrewarmHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		seen++
		state := "MISS"
		if seen%2 == 0 {
			state = "HIT"
		}
		cacheHeaders(writer, site, state)
		_, _ = writer.Write([]byte("ok"))
	}))
	listener := productionListener(8080)
	listener.PrewarmPort = server.port()
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
	active, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &blockingFirstSiteResolver{
		delegate: active, resolved: make(chan SiteContext, 1), release: make(chan struct{}), blockCall: blockCall,
	}
	manager := testManager(t, root, resolver, nil)
	taskSite, err := active.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil {
		t.Fatal(err)
	}
	site = siteForListener(taskSite, taskSite.Listeners[0], taskSite.Listeners[0].Scheme)
	task := taskFor(site, "active-prewarm-before-http", ActionPrewarm, cacheURL(site, "/before-http"))
	done := make(chan struct {
		result Result
		err    error
	}, 1)
	go func() {
		result, executeErr := manager.Execute(context.Background(), task)
		done <- struct {
			result Result
			err    error
		}{result: result, err: executeErr}
	}()

	resolved := <-resolver.resolved
	drifted := cacheReleaseFiles(t, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{listener})
	drifted["nginx.conf"] = append(drifted["nginx.conf"], []byte("# release changed before HTTP\n")...)
	var manifest edgeconfig.CachePolicyManifest
	if err := json.Unmarshal(drifted[edgeconfig.CachePolicyManifestPath], &manifest); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(drifted["nginx.conf"])
	manifest.NginxSHA256 = hex.EncodeToString(digest[:])
	policy, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	drifted[edgeconfig.CachePolicyManifestPath] = append(policy, '\n')
	activateSiteRuntimeRelease(t, root, drifted)
	current, err := active.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil || equalSiteBinding(siteBindingFromContext(current), siteBindingFromContext(resolved)) {
		t.Fatalf("release did not change exact binding: before=%+v after=%+v error=%v", resolved, current, err)
	}
	close(resolver.release)

	completed := <-done
	if completed.err != nil || completed.result.State != StateFailed ||
		completed.result.Items[0].Code != CodeSiteContextStale || seen != 0 {
		t.Fatalf("prewarm after cutover = %+v, seen=%d, error=%v", completed.result, seen, completed.err)
	}
}

func activeReleaseRoot(t *testing.T) string {
	t.Helper()
	root := testStateRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "releases"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state", "activation.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func productionListener(port uint16) edgeconfig.CacheListenerPolicy {
	return productionListenerForVersion(port, productionVersionV1)
}

func productionListenerForVersion(port uint16, version string) edgeconfig.CacheListenerPolicy {
	return tenantListener(productionTenantID, productionSiteID, port, version)
}

func tenantListener(tenantID, siteID string, port uint16, version string) edgeconfig.CacheListenerPolicy {
	listener := edgeconfig.CacheListenerPolicy{
		SiteID: siteID, Domain: "cache.example.test", ListenPort: port,
		Protocol: edgeconfig.ProtocolHTTP, PrewarmPort: 19080,
		NamespaceID: edgeconfig.CacheNamespaceID(tenantID, siteID, version),
		KeyPrefix:   edgeconfig.CacheKeyPrefix(tenantID, siteID, version, "cache.example.test", port),
		Policy: edgeconfig.CachePolicyDocument{
			Revision: 1, Mode: edgeconfig.CacheFollowOrigin, QueryMode: edgeconfig.CacheQueryPreserve,
			DiskQuotaBytes: 64 << 20,
		},
	}
	listener.PrewarmPathPrefix = edgeconfig.CachePrewarmPathPrefix(tenantID, siteID, version,
		listener.Domain, listener.ListenPort, listener.Protocol)
	return listener
}

// activateCacheRelease activates a site runtime v2 release whose
// node-compiled derived release carries these cache listeners.
func activateCacheRelease(t *testing.T, root, version string, revision uint64, listeners []edgeconfig.CacheListenerPolicy) {
	t.Helper()
	activateSiteRuntimeRelease(t, root, cacheReleaseFiles(t, version, revision, listeners))
}

func cacheReleaseFiles(t *testing.T, version string, revision uint64,
	listeners []edgeconfig.CacheListenerPolicy) map[string][]byte {
	t.Helper()
	return cacheReleaseFilesFor(t, productionTenantID, version, revision, listeners)
}

func cacheReleaseFilesFor(t *testing.T, tenantID, version string, revision uint64,
	listeners []edgeconfig.CacheListenerPolicy) map[string][]byte {
	t.Helper()
	nginx := cacheReleaseNginx(version, listeners)
	nginxDigest := sha256.Sum256(nginx)
	content, err := json.Marshal(edgeconfig.CachePolicyManifest{
		SchemaVersion: "cdnca.edge.cache-policies/v2", ConfigVersionID: version,
		ConfigRevision: revision, TenantID: tenantID,
		NginxSHA256: hex.EncodeToString(nginxDigest[:]), KeyModuleSHA256: edgeconfig.CachePolicyKeyModuleSHA256,
		Listeners: listeners,
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		edgeconfig.CachePolicyManifestPath:  append(content, '\n'),
		edgeconfig.CachePolicyKeyModulePath: edgeconfig.CachePolicyKeyModule(),
		"nginx.conf":                        nginx,
	}
}

func cacheReleaseNginx(version string, listeners []edgeconfig.CacheListenerPolicy) []byte {
	var output strings.Builder
	prewarmPort := listeners[0].PrewarmPort
	output.WriteString("http {\n")
	output.WriteString("  map \"$cdnca_cache_safe_bypass:$upstream_cache_status\" $cdnca_cache_header { default BYPASS; \"0:HIT\" HIT; \"0:STALE\" HIT; \"0:UPDATING\" HIT; \"0:REVALIDATED\" HIT; \"0:MISS\" MISS; \"0:EXPIRED\" MISS; }\n")
	cachePaths := make(map[string]struct{}, len(listeners))
	for _, listener := range listeners {
		if _, exists := cachePaths[listener.NamespaceID]; exists {
			continue
		}
		cachePaths[listener.NamespaceID] = struct{}{}
		zone := "cdnca_cache_" + listener.NamespaceID[:32] + "_1m"
		fmt.Fprintf(&output, "  proxy_cache_path /var/lib/cdnca-edge/shared/cache/%s levels=1:2 keys_zone=%s:1m max_size=%dm inactive=1m use_temp_path=off;\n",
			listener.NamespaceID, zone, listener.Policy.DiskQuotaBytes/(1<<20))
	}
	fmt.Fprintf(&output, "  server {\n    listen 127.0.0.1:%d;\n    listen [::1]:%d ipv6only=on;\n    server_name _;\n", prewarmPort, prewarmPort)
	for index, listener := range listeners {
		zone := "cdnca_cache_" + listener.NamespaceID[:32] + "_1m"
		fmt.Fprintf(&output, "    location ^~ %s {\n", listener.PrewarmPathPrefix)
		output.WriteString("      if ($request_method != GET) { return 405; }\n")
		output.WriteString("      if ($http_x_cdnca_internal_cache_task != \"v2\") { return 404; }\n")
		fmt.Fprintf(&output, "      if ($http_x_cdnca_cache_namespace != \"%s\") { return 404; }\n", listener.NamespaceID)
		fmt.Fprintf(&output, "      rewrite ^%s(.*)$ /$1 break;\n", regexp.QuoteMeta(listener.PrewarmPathPrefix))
		fmt.Fprintf(&output, "      add_header X-CDNCA-Config-Version %s always;\n", version)
		fmt.Fprintf(&output, "      add_header X-CDNCA-Cache-Namespace %s always;\n", listener.NamespaceID)
		output.WriteString("      add_header X-CDN-Cache $cdnca_cache_header always;\n")
		fmt.Fprintf(&output, "      proxy_cache %s;\n", zone)
		fmt.Fprintf(&output, "      proxy_cache_key %q;\n", listener.KeyPrefix+"$uri$is_args$args")
		fmt.Fprintf(&output, "      proxy_pass http://site_%04d;\n", index+1)
		fmt.Fprintf(&output, "      proxy_set_header Host %s;\n", listener.Domain)
		output.WriteString("      proxy_set_header X-Forwarded-For \"\";\n")
		output.WriteString("      proxy_set_header X-CDNCA-Internal-Cache-Task \"\";\n")
		output.WriteString("      proxy_set_header X-CDNCA-Cache-Namespace \"\";\n")
		output.WriteString("      proxy_hide_header X-CDN-Cache;\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Internal-Cache-Task;\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Cache-Namespace;\n")
		output.WriteString("    }\n")
	}
	output.WriteString("  }\n")
	for _, listener := range listeners {
		zone := "cdnca_cache_" + listener.NamespaceID[:32] + "_1m"
		listenOptions := ""
		if listener.Protocol == edgeconfig.ProtocolHTTPS {
			listenOptions = " ssl"
		}
		fmt.Fprintf(&output, "  server {\n    listen 0.0.0.0:%d%s;\n    listen [::]:%d%s;\n    server_name %s;\n",
			listener.ListenPort, listenOptions, listener.ListenPort, listenOptions, listener.Domain)
		output.WriteString("    location / {\n")
		fmt.Fprintf(&output, "      proxy_cache %s;\n", zone)
		fmt.Fprintf(&output, "      proxy_cache_key %q;\n", listener.KeyPrefix+"$uri$is_args$args")
		output.WriteString("      proxy_set_header X-CDNCA-Internal-Cache-Task \"\";\n")
		output.WriteString("      proxy_set_header X-CDNCA-Cache-Namespace \"\";\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Internal-Cache-Task;\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Cache-Namespace;\n")
		output.WriteString("    }\n  }\n")
	}
	output.WriteString("}\n")
	return []byte(output.String())
}

func activateRawRelease(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	manifest := edgeconfig.Manifest{Files: make([]edgeconfig.FileManifest, 0, len(files))}
	for path, content := range files {
		digest := sha256.Sum256(content)
		manifest.Files = append(manifest.Files, edgeconfig.FileManifest{Path: path, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])})
	}
	normalized, err := edgeconfig.NormalizeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := edgeconfig.ManifestDigest(normalized)
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(root, "releases", digest)
	for path, content := range files {
		full := filepath.Join(release, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	manifestBytes, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, ".release-manifest.json"), manifestBytes, 0o440); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "current")
	temporary := current + ".new"
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("releases", digest), temporary); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, current); err != nil {
		t.Fatal(err)
	}
}

func siteForListener(site SiteContext, listener ListenerContext, scheme string) SiteContext {
	site.Domain = listener.Domain
	site.ListenPort = listener.ListenPort
	site.Scheme = scheme
	site.CacheEnabled = listener.CacheEnabled
	site.PrewarmPort = listener.PrewarmPort
	site.PrewarmPathPrefix = listener.PrewarmPathPrefix
	return site
}

func TestActiveReleaseResolverHonorsCancelledContext(t *testing.T) {
	root := activeReleaseRoot(t)
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{productionListener(8080)})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveSite(ctx, productionTenantID, productionSiteID, productionVersionV1, 7); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveSite(cancelled) error = %v", err)
	}
}

func TestActiveReleaseResolverDoesNotNeedControlPlaneAvailability(t *testing.T) {
	root := activeReleaseRoot(t)
	activateCacheRelease(t, root, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{productionListener(8080)})
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := resolver.ResolveSite(deadline, productionTenantID, productionSiteID, productionVersionV1, 7); err != nil {
		t.Fatalf("local active release resolution error = %v", err)
	}
}

func TestReadActiveRegularFileRejectsSpecialFilesPromptly(t *testing.T) {
	rejectPromptly := func(t *testing.T, path string) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			_, err := readActiveRegularFile(context.Background(), path, 1<<20)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("special active release file %q was accepted", path)
			}
		case <-time.After(250 * time.Millisecond):
			t.Fatalf("special active release file %q blocked", path)
		}
	}

	root, err := os.MkdirTemp("/tmp", "cdnca-active-release-read-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	t.Run("fifo replacement", func(t *testing.T) {
		path := filepath.Join(root, "manifest.json")
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		originalOpen := readActiveRegularOpen
		t.Cleanup(func() { readActiveRegularOpen = originalOpen })
		validated, open := make(chan struct{}), make(chan struct{})
		readActiveRegularOpen = func(path string, flag int, perm os.FileMode) (*os.File, error) {
			close(validated)
			<-open
			return os.OpenFile(path, flag, perm)
		}
		done := make(chan error, 1)
		go func() {
			_, err := readActiveRegularFile(context.Background(), path, 1<<20)
			done <- err
		}()
		<-validated
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
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
		path := filepath.Join(root, "manifest.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		rejectPromptly(t, path)
	})
	t.Run("device", func(t *testing.T) { rejectPromptly(t, "/dev/null") })
}
