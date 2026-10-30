package edgeconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

// A site runtime v2 cache key names the request's own
// host (nginx $host: lower case, no port) unless the site shares one cache
// across its domains. The host is captured in the rewrite phase, before an
// origin signer replaces the Host header.
func siteRuntimeHostRenderer(t *testing.T, item siteRuntimeCacheV1Case, shared bool) (*SiteCacheRenderer, Site, Spec) {
	t.Helper()
	spec := siteRuntimeCacheV1Spec(item.runtime)
	site := spec.Sites[0]
	renderer, err := NewSiteCacheRenderer(spec.ConfigVersionID, "/var/lib/cdnca/shared", site.ID, 0,
		[]string{site.Domain, "alias.example.test"}, false,
		SiteRuntimeCache{TenantID: spec.TenantID, Domain: site.Domain, Policy: item.document, SharedAcrossDomains: shared})
	if err != nil {
		t.Fatal(err)
	}
	return renderer, site, spec
}

func TestSiteCacheRendererKeysByRequestHostByDefault(t *testing.T) {
	simple, advanced := siteRuntimeCacheV1Cases()[1], siteRuntimeCacheV1Cases()[3]
	renderer, site, spec := siteRuntimeHostRenderer(t, simple, false)
	generation := renderer.Generation()
	hostPrefix := CacheKeyVersion + "|" + spec.TenantID + "|" + site.ID + "|" + generation + "|$cdnca_cache_host|8080|"
	if got := renderer.ServerHeaders(); !strings.Contains(got, "    set $cdnca_cache_host $host;\n") {
		t.Fatalf("server headers do not capture the request host:\n%s", got)
	}
	public := proxyCacheKeys(renderer.PublicDirectives(8080))
	if len(public) != 1 || public[0] != `proxy_cache_key "`+hostPrefix+`$uri$is_args$args";` {
		t.Fatalf("public key = %q", public)
	}
	listener := SiteRuntimeCacheListener{Port: 8080}
	prewarm := renderer.PrewarmLocations([]SiteRuntimeCacheListener{listener}, "", nil)
	prefix := CachePrewarmPathPrefix(spec.TenantID, site.ID, spec.ConfigVersionID, site.Domain, 8080, ProtocolHTTP)
	block, ok := nginxNamedBlock(prewarm, "    location ^~ "+prefix+" {")
	if !ok || !strings.Contains(block, "      set $cdnca_cache_host $host;\n") ||
		strings.Index(block, "set $cdnca_cache_host") > strings.Index(block, "rewrite ") {
		t.Fatalf("prewarm location does not capture the host before its rewrite:\n%s", block)
	}
	if got := proxyCacheKeys(block); len(got) != 1 || got[0] != public[0] {
		t.Fatalf("prewarm key %q, public key %q", got, public)
	}
	entry := renderer.ManifestListener(listener, spec.HealthPort)
	if !entry.KeyByHost || entry.KeyPrefix != CacheKeyPrefix(spec.TenantID, site.ID, generation, site.Domain, 8080) {
		t.Fatalf("manifest listener = %+v", entry)
	}

	advancedRenderer, _, _ := siteRuntimeHostRenderer(t, advanced, false)
	lua := advancedRenderer.DispatchLua(8080, false)
	wantLua := `key_prefix = "` + CacheKeyVersion + "|" + spec.TenantID + "|" + site.ID + "|" + advancedRenderer.Generation() +
		`|" .. ngx.var.cdnca_cache_host .. "|8080|",`
	if !strings.Contains(lua, wantLua) {
		t.Fatalf("advanced dispatch key prefix:\n%s\nwant %s", lua, wantLua)
	}
	advancedPrewarm := advancedRenderer.PrewarmLocations([]SiteRuntimeCacheListener{listener}, "", nil)
	if block, ok := nginxNamedBlock(advancedPrewarm, "    location ^~ "+prefix+" {"); !ok ||
		!strings.Contains(block, "set $cdnca_cache_host $host;") || !strings.Contains(block, wantLua) {
		t.Fatalf("advanced prewarm location:\n%s", block)
	}
}

func TestSiteCacheRendererSharedAcrossDomainsKeysByPrimaryDomain(t *testing.T) {
	renderer, site, spec := siteRuntimeHostRenderer(t, siteRuntimeCacheV1Cases()[1], true)
	if strings.Contains(renderer.ServerHeaders(), "cdnca_cache_host") {
		t.Fatalf("shared cache captures the host: %s", renderer.ServerHeaders())
	}
	public := proxyCacheKeys(renderer.PublicDirectives(8080))
	want := `proxy_cache_key "` + CacheKeyPrefix(spec.TenantID, site.ID, renderer.Generation(), site.Domain, 8080) + `$uri$is_args$args";`
	if len(public) != 1 || public[0] != want {
		t.Fatalf("shared public key = %q, want %q", public, want)
	}
	if entry := renderer.ManifestListener(SiteRuntimeCacheListener{Port: 8080}, spec.HealthPort); entry.KeyByHost {
		t.Fatalf("shared manifest listener keys by host: %+v", entry)
	}
}

func TestSiteRuntimeCacheSharedAcrossDomainsRoundTrips(t *testing.T) {
	document := siteRuntimeCacheV1Cases()[1].document
	for _, shared := range []bool{false, true} {
		content, err := json.Marshal(SiteRuntimeCache{TenantID: "11111111-1111-4111-8111-111111111111",
			Domain: "cache.example.test", Policy: document, SharedAcrossDomains: shared})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(content), `"shared_across_domains":true`); got != shared {
			t.Fatalf("shared=%v encodes %s", shared, content)
		}
	}
}
