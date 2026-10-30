package edgepublish

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

const siteRuntimeCacheTestTenant = "018f47a2-5b9c-7d31-8a60-104c9c0b71aa"

func siteRuntimeCacheTestFact() siteFact {
	return siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "cache.example.test",
		domains: []string{"alias.example.test", "cache.example.test"}, httpPorts: []string{"80"}, balance: "round_robin",
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
}

func siteRuntimeCachePolicyFacts(siteID uuid.UUID) map[string]*cachePolicyFact {
	base := cachePolicyFact{
		siteID: siteID, revision: 4, edgeSourceRevision: 2, bindingMode: "override", definitionID: uuid.New(),
		definitionRevision: 1, definitionSourceSiteID: siteID, schemaVersion: cachePolicySchemaV1,
		queryMode: edgeconfig.CacheQueryPreserve, queryNames: nil, varyHeaders: nil, diskQuotaBytes: 64 << 20,
	}
	follow := base
	follow.mode = edgeconfig.CacheFollowOrigin
	override := base
	override.mode = edgeconfig.CacheOverride
	override.rules = []cachePolicyRuleFact{{order: 1, statusCodes: []int{200, 404}, ttlSeconds: 300}}
	rules := base
	rules.mode, rules.schemaVersion = edgeconfig.CacheOverride, cachePolicySchemaV2
	rules.queryMode, rules.queryNames = edgeconfig.CacheQueryInclude, []string{"v"}
	rules.rules = []cachePolicyRuleFact{
		{order: 1, extensions: []string{".css"}, action: edgeconfig.CacheRuleActionCache, ttlSeconds: 60, browserTTLSeconds: 20},
		{order: 2, pathPrefix: "/api/", action: edgeconfig.CacheRuleActionNoCache},
	}
	return map[string]*cachePolicyFact{"none": nil, "follow origin": &follow, "override status": &override, "rules": &rules}
}

func siteRuntimeCacheTestDocument(t *testing.T, fact siteFact, policy *cachePolicyFact) siteRuntimeV2Document {
	t.Helper()
	site, _, err := compileSiteRuntimeV2SiteFact(nil, nil, uuid.New(), fact, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", SourceRevision: 3,
		ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7102", Sites: []siteRuntimeV2Site{site},
		RequiredCapabilities: []siteRuntimeV2Capability{{"http1", 1}, {"ipv4", 1}, {"ipv6", 1}, {"site_runtime", edgeconfig.MinSiteRuntimeVersion}, {"websocket", 1}},
	}
	if err := bindSiteRuntimeV2Cache(&document, uuid.MustParse(siteRuntimeCacheTestTenant), []siteFact{fact},
		map[uuid.UUID]*cachePolicyFact{fact.id: policy}); err != nil {
		t.Fatal(err)
	}
	return document
}

// Every site carries its cache policy as a document the node derives its
// nginx cache policy from.
func TestSiteRuntimeV2CarriesTheSiteCachePolicy(t *testing.T) {
	fact := siteRuntimeCacheTestFact()
	for name, policy := range siteRuntimeCachePolicyFacts(fact.id) {
		t.Run(name, func(t *testing.T) {
			document := siteRuntimeCacheTestDocument(t, fact, policy)
			cache := document.Sites[0].Cache
			if cache == nil || cache.TenantID != siteRuntimeCacheTestTenant || cache.Domain != "cache.example.test" {
				t.Fatalf("site cache binding = %+v", cache)
			}
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
			if err != nil {
				t.Fatalf("cached document rejected: %v\n%s", err, raw)
			}
			version := uint32(0)
			for _, capability := range capabilities {
				if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
					version = capability.ApiVersion
				}
			}
			if version != edgeconfig.MinSiteRuntimeVersion {
				t.Fatalf("site_runtime = %d, want %d", version, edgeconfig.MinSiteRuntimeVersion)
			}
			// The node derives the cache policy from the document's.
			if _, err := edgeconfig.CachePolicyFromDocument(cache.Policy); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Cache rules combine with L2 forwarding, an HTTP policy and origin routes
// (the node renders per-target rule routes that restore the policy and follow
// fallback: siteruntimev2 writeCacheTargetRoutes).
func TestSiteRuntimeV2CacheRulesCombineWithL2HTTPPolicyAndOriginRoutes(t *testing.T) {
	fact := siteRuntimeCacheTestFact()
	rules := siteRuntimeCachePolicyFacts(fact.id)["rules"]
	document := siteRuntimeCacheTestDocument(t, fact, rules)
	enabled, directPool := true, "primary"
	document.Sites[0].L2.Enabled, document.Sites[0].L2.DirectFallbackPoolID = &enabled, &directPool
	l2 := document.Sites[0].OriginPools[0]
	nodeID := uuid.NewString()
	l2.ID, l2.Kind, l2.Position = "l2-topology", "l2", 0
	l2.Origins = []siteRuntimeV2Origin{{ID: uuid.NewString(), Tier: "l2", Scheme: "http", Host: "192.0.2.20", Port: 8443, Weight: 1, NodeID: &nodeID}}
	document.Sites[0].OriginPools[0].Position = 1
	document.Sites[0].OriginPools = append([]siteRuntimeV2OriginPool{l2}, document.Sites[0].OriginPools...)
	document.Sites[0].DefaultPoolID = l2.ID
	raw, _ := json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err != nil {
		t.Fatalf("cache rules with L2 refused: %v", err)
	}
	withPolicy := siteRuntimeCacheTestDocument(t, fact, rules)
	withPolicy.Sites[0].HTTPPolicy = &siteRuntimeV2HTTPPolicyBinding{PolicyID: uuid.NewString(), PolicyRevision: 1}
	if err := validateSiteRuntimeV2Cache(withPolicy.Sites[0], map[string]uint32{}); err != nil {
		t.Fatalf("cache rules with an HTTP policy refused: %v", err)
	}
}

func TestSiteRuntimeV2CacheRefusesOldNodesAndForeignDomains(t *testing.T) {
	fact := siteRuntimeCacheTestFact()
	// A declared v5 document cannot carry a cache; a v5 node is refused.
	plain := siteRuntimeCacheTestDocument(t, fact, nil)
	setSiteRuntimeV2CapabilityExact(plain.RequiredCapabilities, "site_runtime", 5)
	raw, _ := json.Marshal(plain)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cache under site_runtime v5 accepted: %v", err)
	}
	foreign := siteRuntimeCacheTestDocument(t, fact, nil)
	foreign.Sites[0].Cache.Domain = "other.example.test"
	raw, _ = json.Marshal(foreign)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cache on a foreign domain accepted: %v", err)
	}
}

func setSiteRuntimeV2CapabilityExact(values []siteRuntimeV2Capability, name string, version uint32) {
	for index := range values {
		if values[index].Name == name {
			values[index].APIVersion = version
		}
	}
}

// The site's 所有域名共用缓存 option reaches the v2 cache
// binding; off (the default) leaves the node keying by the request host.
func TestSiteRuntimeV2CacheCarriesSharedAcrossDomains(t *testing.T) {
	fact := siteRuntimeCacheTestFact()
	policy := siteRuntimeCachePolicyFacts(fact.id)["follow origin"]
	for _, shared := range []bool{false, true} {
		fact.cacheSharedAcrossDomains = shared
		document := siteRuntimeCacheTestDocument(t, fact, policy)
		if cache := document.Sites[0].Cache; cache == nil || cache.SharedAcrossDomains != shared {
			t.Fatalf("shared=%v: site cache binding = %+v", shared, cache)
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"shared_across_domains"`) != shared {
			t.Fatalf("shared=%v: document = %s", shared, raw)
		}
		if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err != nil {
			t.Fatalf("shared=%v: document rejected: %v", shared, err)
		}
	}
}
