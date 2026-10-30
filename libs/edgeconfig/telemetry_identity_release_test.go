package edgeconfig

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// telemetryReleaseForTest is a site runtime release's identities for one
// cached site on ports listeners (18081...): the signed telemetry identity the
// control plane publishes and the cache identity the node compiles.
func telemetryReleaseForTest(t *testing.T, listeners int) (Bundle, error) {
	t.Helper()
	const tenant, site, version = "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333", "cfg-v1"
	manifest := TelemetryIdentityManifest{SchemaVersion: 1, ConfigVersionID: version, ConfigRevision: 7, TenantID: tenant,
		CapturePolicy: TelemetryCapturePolicyManifest{SchemaVersion: 1}, SourceCapabilities: TelemetrySourceCapabilities{SchemaVersion: 1}}
	var cacheListeners []CacheListenerPolicy
	for index := 0; index < listeners; index++ {
		port := uint16(18081 + index)
		access, security := TelemetryLogPaths("/var/lib/cdnca-edge", version, site, port)
		manifest.Sites = append(manifest.Sites, TelemetrySiteIdentity{SiteID: site, Domain: "www.example.test", ListenPort: port,
			NamespaceID: CacheSiteNamespaceID(tenant, site), AccessLogPath: access, SecurityLogPath: security})
		manifest.CapturePolicy.Sites = append(manifest.CapturePolicy.Sites, manifestCapturePolicy(site, "www.example.test", port,
			TelemetryCapturePolicy{SchemaVersion: 1, MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20}))
		renderer, err := NewSiteCacheRenderer(version, "/var/lib/cdnca-edge/shared", site, 0, []string{"www.example.test"}, false,
			SiteRuntimeCache{TenantID: tenant, Domain: "www.example.test", SharedAcrossDomains: true, Policy: CachePolicyDocument{
				Revision: 1, Mode: CacheFollowOrigin, QueryMode: CacheQueryPreserve, Rules: []CacheRuleDocument{},
				QueryNames: []string{}, VaryHeaders: []string{}, DiskQuotaBytes: 64 << 20}})
		if err != nil {
			t.Fatal(err)
		}
		cacheListeners = append(cacheListeners, renderer.ManifestListener(SiteRuntimeCacheListener{Port: port}, 18080))
	}
	identity, err := json.Marshal(manifest)
	if err != nil {
		return Bundle{}, err
	}
	cache, err := SiteRuntimeCacheManifest(version, 7, tenant, []byte("nginx"), cacheListeners)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Files: map[string][]byte{TelemetryIdentityManifestPath: append(identity, '\n'), CachePolicyManifestPath: cache}}, nil
}

func TestTelemetryCacheReleaseIdentityRejectsEveryMutableMismatch(t *testing.T) {
	bundle, err := telemetryReleaseForTest(t, 1)
	if err != nil {
		t.Fatal(err)
	}
	telemetry, err := ParseTelemetryIdentityManifest(bundle.Files[TelemetryIdentityManifestPath])
	if err != nil {
		t.Fatal(err)
	}
	cache, err := ParseCachePolicyManifest(bundle.Files[CachePolicyManifestPath])
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTelemetryCacheReleaseIdentity(telemetry, cache); err != nil {
		t.Fatalf("matching release identity error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*TelemetryIdentityManifest, *CachePolicyManifest)
	}{
		{name: "zero revision", mutate: func(value *TelemetryIdentityManifest, _ *CachePolicyManifest) { value.ConfigRevision = 0 }},
		{name: "revision", mutate: func(value *TelemetryIdentityManifest, _ *CachePolicyManifest) { value.ConfigRevision++ }},
		{name: "tenant", mutate: func(value *TelemetryIdentityManifest, _ *CachePolicyManifest) {
			value.TenantID = "44444444-4444-4444-8444-444444444444"
		}},
		{name: "version", mutate: func(value *TelemetryIdentityManifest, _ *CachePolicyManifest) { value.ConfigVersionID = "cfg-v2" }},
		{name: "site", mutate: func(value *TelemetryIdentityManifest, _ *CachePolicyManifest) {
			value.Sites[0].SiteID = "44444444-4444-4444-8444-444444444444"
		}},
		{name: "domain", mutate: func(value *TelemetryIdentityManifest, _ *CachePolicyManifest) {
			value.Sites[0].Domain = "other.example.test"
		}},
		{name: "listen port", mutate: func(value *TelemetryIdentityManifest, _ *CachePolicyManifest) { value.Sites[0].ListenPort++ }},
		{name: "namespace", mutate: func(value *TelemetryIdentityManifest, _ *CachePolicyManifest) {
			value.Sites[0].NamespaceID = strings.Repeat("0", 64)
		}},
		{name: "listener cardinality", mutate: func(_ *TelemetryIdentityManifest, value *CachePolicyManifest) { value.Listeners = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedTelemetry := telemetry
			changedTelemetry.Sites = append([]TelemetrySiteIdentity(nil), telemetry.Sites...)
			changedCache := cache
			changedCache.Listeners = append([]CacheListenerPolicy(nil), cache.Listeners...)
			test.mutate(&changedTelemetry, &changedCache)
			if err := ValidateTelemetryCacheReleaseIdentity(changedTelemetry, changedCache); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("ValidateTelemetryCacheReleaseIdentity() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestTelemetryAndCacheManifestsRejectForgedSiteDomainBindings(t *testing.T) {
	bundle, err := telemetryReleaseForTest(t, 2)
	if err != nil {
		t.Fatal(err)
	}
	telemetry, err := ParseTelemetryIdentityManifest(bundle.Files[TelemetryIdentityManifestPath])
	if err != nil {
		t.Fatal(err)
	}
	cache, err := ParseCachePolicyManifest(bundle.Files[CachePolicyManifestPath])
	if err != nil {
		t.Fatal(err)
	}

	forgedTelemetry := telemetry
	forgedTelemetry.Sites = append([]TelemetrySiteIdentity(nil), telemetry.Sites...)
	forgedTelemetry.CapturePolicy.Sites = append([]TelemetrySiteCapturePolicy(nil), telemetry.CapturePolicy.Sites...)
	forgedTelemetry.Sites[1].Domain = "other.example.test"
	forgedTelemetry.CapturePolicy.Sites[1].Domain = "other.example.test"
	content, err := json.Marshal(forgedTelemetry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTelemetryIdentityManifest(append(content, '\n')); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("forged telemetry site/domain binding error = %v, want ErrInvalidConfig", err)
	}

	forgedCache := cache
	forgedCache.Listeners = append([]CacheListenerPolicy(nil), cache.Listeners...)
	listener := &forgedCache.Listeners[1]
	listener.Domain = "other.example.test"
	listener.PrewarmPathPrefix = CachePrewarmPathPrefix(forgedCache.TenantID, listener.SiteID,
		forgedCache.ConfigVersionID, listener.Domain, listener.ListenPort, listener.Protocol)
	listener.KeyPrefix = CacheKeyPrefix(forgedCache.TenantID, listener.SiteID,
		forgedCache.ConfigVersionID, listener.Domain, listener.ListenPort)
	content, err = json.Marshal(forgedCache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCachePolicyManifest(append(content, '\n')); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("forged cache site/domain binding error = %v, want ErrInvalidConfig", err)
	}

	tests := []struct {
		name      string
		telemetry TelemetryIdentityManifest
		cache     CachePolicyManifest
	}{
		{name: "telemetry only", telemetry: forgedTelemetry, cache: cache},
		{name: "cache only", telemetry: telemetry, cache: forgedCache},
		{name: "matching forged manifests", telemetry: forgedTelemetry, cache: forgedCache},
	}
	duplicateTelemetry := telemetry
	duplicateTelemetry.Sites = []TelemetrySiteIdentity{telemetry.Sites[0], telemetry.Sites[0]}
	duplicateTelemetry.CapturePolicy.Sites = []TelemetrySiteCapturePolicy{
		telemetry.CapturePolicy.Sites[0], telemetry.CapturePolicy.Sites[0],
	}
	duplicateCache := cache
	duplicateCache.Listeners = []CacheListenerPolicy{cache.Listeners[0], cache.Listeners[0]}
	tests = append(tests, struct {
		name      string
		telemetry TelemetryIdentityManifest
		cache     CachePolicyManifest
	}{name: "matching duplicate tuples", telemetry: duplicateTelemetry, cache: duplicateCache})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateTelemetryCacheReleaseIdentity(test.telemetry, test.cache); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("ValidateTelemetryCacheReleaseIdentity() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}
