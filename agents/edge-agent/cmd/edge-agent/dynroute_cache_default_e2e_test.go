package main

// N16 on the real node runtime: tests/dynroute-cache-default/run.sh runs it
// inside the node runtime image. The node is configured as install-node.sh
// writes it (dynamic_routing without cache_max_bytes); a site with a .svg
// cache rule (override) answers MISS then HIT. An origin Cache-Control:
// no-store (the live retest's favicon.svg) stays BYPASS origin_no_store:
// the cache never stores it, in every mode (edgecache Variants proxy_no_cache).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func TestDynRouteDefaultCacheRealRuntime(t *testing.T) {
	binary := os.Getenv("DYNROUTE_CACHE_DEFAULT_OPENRESTY")
	if binary == "" {
		t.Skip("DYNROUTE_CACHE_DEFAULT_OPENRESTY is not set; run tests/dynroute-cache-default/run.sh")
	}
	const (
		scopeID    = "0d160000-0000-4000-8000-000000000001"
		tenantID   = "0d160000-0000-4000-8000-000000000002"
		siteID     = "0d160000-0000-4000-8000-000000000003"
		host       = "n16.cache.test"
		sitePort   = 18580
		originPort = 18581
	)
	var originHits atomic.Int32
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", originPort))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "image/svg+xml")
			if request.URL.Path == "/no-store.svg" {
				writer.Header().Set("Cache-Control", "no-store")
			} else {
				originHits.Add(1)
			}
			_, _ = io.WriteString(writer, `<svg xmlns="http://www.w3.org/2000/svg"/>`)
		}))
	}()
	t.Cleanup(func() { listener.Close() })

	root, err := os.MkdirTemp("/tmp", "n16e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	deploymentRoot := filepath.Join(root, "deployments")
	if err := os.MkdirAll(deploymentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	// install-node.sh's dynamic_routing (no cache_max_bytes); the image's
	// worker group is nobody or nogroup
	group := "nobody"
	if _, err := lookupWorkerGID(group); err != nil {
		group = "nogroup"
	}
	var settings dynamicRoutingSettings
	if err := json.Unmarshal([]byte(`{"enabled":true,"worker_group":"`+group+`"}`), &settings); err != nil {
		t.Fatal(err)
	}
	config := fileConfig{DeploymentRoot: deploymentRoot, DynamicRouting: settings,
		OpenResty: openRestySettings{Binary: binary, HealthURL: "http://127.0.0.1:18582/healthz"}}
	if err := config.validateDynamicRouting(); err != nil {
		t.Fatal(err)
	}
	_, shared := dynamicRoutingRoots(config)
	budget, err := dynamicRoutingCacheMaxBytes(config.DynamicRouting, shared)
	if err != nil || budget <= 0 {
		t.Fatalf("default cache budget %d (%v), want > 0", budget, err)
	}
	t.Logf("default cache budget %d MiB", budget>>20)
	objects, err := openObjectStore(config)
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := certstore.NewManager(certstore.RuntimeConfig{StateRoot: filepath.Join(root, "certificates"),
		ListenAddress: "127.0.0.1", ListenPort: 18583}, dynRouteNoCertificateRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := assembleDynamicRouting(config, "0d160000-0000-4000-8000-0000000000aa", certificates, nil,
		20*time.Second, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Stop(context.Background()) })

	site := edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scopeID, TenantID: tenantID, SiteID: siteID, Revision: 1,
		Hosts:     edgesite.Hosts{Primary: host, Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: sitePort, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "127.0.0.1", Port: originPort, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 30000, TotalBudgetMS: 40000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
		Limits:   edgesite.Limits{MaxBodyBytes: 64 << 20},
	}
	cache := &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(tenantID, siteID), Domain: host, KeyByHost: true,
		Policy: edgeconfig.CachePolicyDocument{SchemaVersion: edgeconfig.CachePolicyDocumentSchemaV2, Revision: 1,
			Mode: edgeconfig.CacheOverride, DiskQuotaBytes: 64 << 20,
			Rules: []edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".svg"}, Action: edgeconfig.CacheRuleActionCache,
				TTLSeconds: 600, BrowserTTLSeconds: 600}},
			QueryMode: edgeconfig.CacheQueryPreserve, QueryNames: []string{}, VaryHeaders: []string{}}}
	cache.Generation, _ = edgesite.CacheGeneration(*cache)
	site.Cache, site.CacheStatusHeader = cache, true
	raw, err := edgesite.Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	if err := putSiteObject(objects, raw); err != nil {
		t.Fatal(err)
	}
	object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(context.Background(), dynroute.Input{Objects: []siteindex.Object{object},
		ScopeVersions: map[string]string{scopeID: "0d160000-0000-4000-8000-0000000000a1"}}); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(shared, "nginx.conf"))
	if err != nil || !strings.Contains(string(conf), "proxy_cache_path ") ||
		!strings.Contains(string(conf), "add_header X-CDN-Cache $cdnca_cache_status_header always;") {
		t.Fatalf("nginx.conf without the cache pool / X-CDN-Cache (%v)", err)
	}
	var statuses []string
	for _, path := range []string{"/favicon.svg", "/favicon.svg", "/no-store.svg", "/no-store.svg"} {
		request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", sitePort, path), nil)
		request.Host = host
		response, err := (&http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		statuses = append(statuses, fmt.Sprintf("%d %s %q reason=%q", response.StatusCode, response.Header.Get("X-CDN-Cache"),
			response.Header.Get("Cache-Control"), response.Header.Get("X-CDN-Cache-Reason")))
	}
	t.Logf("favicon.svg x2, no-store.svg x2: %v, favicon origin hits %d", statuses, originHits.Load())
	if !strings.HasPrefix(statuses[0], "200 MISS") || !strings.HasPrefix(statuses[1], "200 HIT") || originHits.Load() != 1 ||
		!strings.Contains(statuses[1], `"max-age=600"`) {
		t.Fatalf("favicon.svg answers %v, origin hits %d; want 200 MISS then 200 HIT (max-age=600), origin once",
			statuses[:2], originHits.Load())
	}
	for _, status := range statuses[2:] {
		if !strings.HasPrefix(status, "200 BYPASS") || !strings.Contains(status, `reason="origin_no_store"`) {
			t.Fatalf("no-store.svg answers %v, want BYPASS origin_no_store", statuses[2:])
		}
	}
}

func putSiteObject(store *objectstore.Store, raw []byte) error {
	return store.Put(edgesite.Digest(raw), raw)
}
