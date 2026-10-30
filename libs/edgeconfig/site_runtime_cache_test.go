package edgeconfig

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// siteRuntimeCacheV1Case is a production-shaped v1 site (as control-api
// compileCachePolicy builds it) and the same policy as its signed document.
type siteRuntimeCacheV1Case struct {
	name     string
	document CachePolicyDocument
	runtime  CachePolicy
}

func siteRuntimeCacheV1Cases() []siteRuntimeCacheV1Case {
	return []siteRuntimeCacheV1Case{
		{
			name:     "disabled",
			document: CachePolicyDocument{Mode: CacheDisabled, QueryMode: CacheQueryIgnore, Rules: []CacheRuleDocument{}},
			runtime:  CachePolicy{Mode: CacheDisabled},
		},
		{
			name: "follow origin",
			document: CachePolicyDocument{Revision: 3, Mode: CacheFollowOrigin, QueryMode: CacheQueryPreserve,
				DiskQuotaBytes: 64 << 20, Rules: []CacheRuleDocument{}},
			runtime: CachePolicy{Revision: 3, Mode: CacheFollowOrigin, ZoneSizeBytes: 1 << 20, MaxSizeBytes: 64 << 20,
				DefaultTTL: 60 * time.Second, QueryMode: CacheQueryPreserve},
		},
		{
			name: "override schema v1 status rule",
			document: CachePolicyDocument{Revision: 4, Mode: CacheOverride, QueryMode: CacheQueryPreserve, DiskQuotaBytes: 128 << 20,
				Rules: []CacheRuleDocument{{Order: 1, StatusCodes: []int{200, 404}, TTLSeconds: 300}}},
			runtime: CachePolicy{Revision: 4, Mode: CacheOverride, ZoneSizeBytes: 1 << 20, MaxSizeBytes: 128 << 20,
				DefaultTTL: 300 * time.Second, QueryMode: CacheQueryPreserve,
				StatusTTLs: []CacheStatusTTL{{Status: 200, TTL: 300 * time.Second}, {Status: 404, TTL: 300 * time.Second}},
				Rules:      []CacheRule{{Order: 1, StatusCodes: []int{200, 404}, TTL: 300 * time.Second}}},
		},
		{
			name: "schema v2 rules with query projection",
			document: CachePolicyDocument{SchemaVersion: CachePolicyDocumentSchemaV2, Revision: 5, Mode: CacheOverride,
				QueryMode: CacheQueryInclude, QueryNames: []string{"v"}, DiskQuotaBytes: 64 << 20,
				Rules: []CacheRuleDocument{
					{Order: 1, Extensions: []string{".css"}, StatusCodes: []int{200}, Action: CacheRuleActionCache, TTLSeconds: 60, BrowserTTLSeconds: 20},
					{Order: 2, PathPrefix: "/api/", Action: CacheRuleActionNoCache},
				}},
			runtime: CachePolicy{SchemaVersion: CachePolicyDocumentSchemaV2, Revision: 5, Mode: CacheOverride,
				ZoneSizeBytes: 1 << 20, MaxSizeBytes: 64 << 20, DefaultTTL: 60 * time.Second,
				QueryMode: CacheQueryInclude, QueryNames: []string{"v"},
				Rules: []CacheRule{
					{Order: 1, Extensions: []string{".css"}, StatusCodes: []int{200}, Action: CacheRuleActionCache, TTL: 60 * time.Second, BrowserTTL: 20 * time.Second},
					{Order: 2, PathPrefix: "/api/", Action: CacheRuleActionNoCache},
				}},
		},
	}
}

func siteRuntimeCacheV1Spec(policy CachePolicy) Spec {
	spec := productionCacheSpec()
	spec.StateRoot = "/var/lib/cdnca"
	spec.HealthPort = 18081
	spec.Sites[0].ListenPort = 8080
	spec.Sites[0].Range = true
	spec.Sites[0].Cache = policy
	return spec
}

func TestCachePolicyFromDocumentMatchesV1Publication(t *testing.T) {
	for _, item := range siteRuntimeCacheV1Cases() {
		t.Run(item.name, func(t *testing.T) {
			got, err := CachePolicyFromDocument(item.document)
			if err != nil {
				t.Fatal(err)
			}
			want, err := normalizeCache(item.runtime, true)
			if err != nil {
				t.Fatal(err)
			}
			if !equalCachePolicy(got, want) {
				t.Fatalf("derived policy differs from v1 publication:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// The v2 renderer's cache identity manifest binds to the node-compiled
// nginx.conf and names the site's stable namespace and cache generation
// (ge-cache A): not the config version, which changes on every publication.
func TestSiteCacheRendererManifestNamesStableIdentity(t *testing.T) {
	for _, item := range siteRuntimeCacheV1Cases() {
		t.Run(item.name, func(t *testing.T) {
			spec := siteRuntimeCacheV1Spec(item.runtime)
			site := spec.Sites[0]
			renderer, err := NewSiteCacheRenderer(spec.ConfigVersionID, "/var/lib/cdnca/shared", site.ID, 0,
				[]string{"alias.example.test", site.Domain}, true,
				SiteRuntimeCache{TenantID: spec.TenantID, Domain: site.Domain, Policy: item.document, SharedAcrossDomains: true})
			if err != nil {
				t.Fatal(err)
			}
			nginx := []byte(SiteRuntimeCacheHTTPMaps() + renderer.HTTPDefinitions(map[string]struct{}{}))
			listener := renderer.ManifestListener(SiteRuntimeCacheListener{Port: site.ListenPort}, spec.HealthPort)
			if !slices.Equal(listener.Domains, []string{site.Domain, "alias.example.test"}) {
				t.Fatalf("manifest served domains = %q", listener.Domains)
			}
			if listener.NamespaceID != CacheSiteNamespaceID(spec.TenantID, site.ID) ||
				listener.CacheGeneration != renderer.Generation() || !CacheGenerationPattern.MatchString(listener.CacheGeneration) ||
				listener.KeyPrefix != CacheKeyPrefix(spec.TenantID, site.ID, listener.CacheGeneration, site.Domain, site.ListenPort) {
				t.Fatalf("manifest identity = %+v", listener)
			}
			v2, err := SiteRuntimeCacheManifest(spec.ConfigVersionID, spec.ConfigRevision, spec.TenantID, nginx,
				[]CacheListenerPolicy{listener})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseSiteRuntimeCacheRelease(v2, nginx, CachePolicyKeyModule()); err != nil {
				t.Fatal(err)
			}
			if _, err := ParseSiteRuntimeCacheRelease(v2, append(nginx, ' '), CachePolicyKeyModule()); err == nil {
				t.Fatal("manifest accepted another nginx.conf")
			}
			if renderer.Enabled() {
				prefix := CachePrewarmPathPrefix(spec.TenantID, site.ID, spec.ConfigVersionID, site.Domain, site.ListenPort, ProtocolHTTP)
				if !strings.Contains(renderer.PrewarmLocations([]SiteRuntimeCacheListener{{Port: site.ListenPort}}, "", nil),
					"location ^~ "+prefix+" {") {
					t.Fatalf("prewarm location %s missing", prefix)
				}
			}
		})
	}
}

// proxyCacheKeys are the proxy_cache_key lines of a rendered fragment.
func proxyCacheKeys(fragment string) []string {
	var keys []string
	for _, line := range strings.Split(fragment, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "proxy_cache_key ") {
			keys = append(keys, strings.TrimSpace(line))
		}
	}
	return keys
}

// A simple policy's prewarm location must write the key its public location
// reads, per listener: the cache task prewarms each listener separately and
// a request on port 8080 reads the 8080 key.
func TestSiteCacheRendererSimplePrewarmKeyMatchesEveryPublicListener(t *testing.T) {
	spec := siteRuntimeCacheV1Spec(siteRuntimeCacheV1Cases()[1].runtime)
	site := spec.Sites[0]
	renderer, err := NewSiteCacheRenderer(spec.ConfigVersionID, "/var/lib/cdnca/shared", site.ID, 0,
		[]string{site.Domain}, false, SiteRuntimeCache{TenantID: spec.TenantID, Domain: site.Domain,
			Policy: siteRuntimeCacheV1Cases()[1].document})
	if err != nil || renderer.Advanced() {
		t.Fatalf("renderer = %v advanced=%v", err, renderer != nil && renderer.Advanced())
	}
	listeners := []SiteRuntimeCacheListener{{Port: 8080}, {Port: 8081}, {Port: 8443, TLS: true}}
	prewarm := renderer.PrewarmLocations(listeners, "", nil)
	for _, listener := range listeners {
		public := proxyCacheKeys(renderer.PublicDirectives(listener.Port))
		prefix := CachePrewarmPathPrefix(spec.TenantID, site.ID, spec.ConfigVersionID, site.Domain,
			listener.Port, listenerProtocol(listener))
		block, ok := nginxNamedBlock(prewarm, "    location ^~ "+prefix+" {")
		if !ok {
			t.Fatalf("port %d: prewarm location %s missing", listener.Port, prefix)
		}
		got := proxyCacheKeys(block)
		if len(public) != 1 || len(got) != 1 || got[0] != public[0] {
			t.Errorf("port %d: prewarm key %q, public key %q", listener.Port, got, public)
		}
	}
}

// cacheDirectivesOnly drops the Range lines, which v1 writes after the
// connection headers (the same directives, in a different position).
func cacheDirectivesOnly(fragment string) string {
	var kept []string
	for _, line := range strings.Split(fragment, "\n") {
		if !strings.Contains(line, "Range") && !strings.Contains(line, "proxy_force_ranges") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func TestSiteRuntimeCacheRejectsForeignDomainAndTenant(t *testing.T) {
	document := siteRuntimeCacheV1Cases()[1].document
	for _, cache := range []SiteRuntimeCache{
		{TenantID: "11111111-1111-4111-8111-111111111111", Domain: "other.example.test", Policy: document},
		{TenantID: "not-a-tenant", Domain: "cache.example.test", Policy: document},
		{TenantID: "11111111-1111-4111-8111-111111111111", Domain: "cache.example.test",
			Policy: CachePolicyDocument{Mode: CacheOverride, QueryMode: CacheQueryPreserve, Rules: []CacheRuleDocument{}}},
	} {
		if err := ValidateSiteRuntimeCache(cache, []string{"cache.example.test"}); err == nil {
			t.Fatalf("accepted %+v", cache)
		}
	}
}
