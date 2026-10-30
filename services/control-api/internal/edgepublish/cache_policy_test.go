package edgepublish

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func TestDecodeCachePolicyRulesIsStrict(t *testing.T) {
	rules, err := decodeCachePolicyRules([]byte(`[{"order":1,"extensions":[".css"],"path_prefix":"/assets/","status_codes":[200],"ttl_seconds":30}]`), cachePolicySchemaV1)
	if err != nil || len(rules) != 1 || rules[0].order != 1 || rules[0].pathPrefix != "/assets/" || rules[0].ttlSeconds != 30 {
		t.Fatalf("decodeCachePolicyRules() = %+v, %v", rules, err)
	}
	for name, content := range map[string]string{
		"unknown field":  `[{"order":1,"ttl_seconds":30,"unexpected":true}]`,
		"V2 field in V1": `[{"order":1,"action":"cache","ttl_seconds":30,"browser_ttl_seconds":10}]`,
		"trailing value": `[] {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeCachePolicyRules([]byte(content), cachePolicySchemaV1); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("decodeCachePolicyRules() error = %v, want ErrInvalidInput", err)
			}
		})
	}
	v2, err := decodeCachePolicyRules([]byte(`[{"order":1,"extensions":[".css"],"path_prefix":"/assets/","status_codes":[200],"action":"cache","ttl_seconds":30,"browser_ttl_seconds":10},{"order":2,"path_prefix":"/assets/","action":"no_cache","ttl_seconds":0,"browser_ttl_seconds":0}]`), cachePolicySchemaV2)
	if err != nil || len(v2) != 2 || v2[0].action != edgeconfig.CacheRuleActionCache ||
		v2[0].browserTTLSeconds != 10 || v2[1].action != edgeconfig.CacheRuleActionNoCache {
		t.Fatalf("decodeCachePolicyRules(V2) = %+v, %v", v2, err)
	}
}

func TestCompileSiteFactCarriesAbsentBaselineAndOverrideCachePolicies(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	fact := siteFact{
		id: uuid.MustParse("11111111-1111-4111-8111-111111111111"), revision: 7,
		domain: "cache.example.test", balance: string(edgeconfig.BalanceRoundRobin), failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}},
	}

	snapshot, site, err := compileSiteFact(scopeID, fact, 80, nil, nil, nil)
	if err != nil || snapshot.Cache != nil || site.Cache.Mode != edgeconfig.CacheDisabled || site.Cache.Revision != 0 {
		t.Fatalf("absent policy snapshot=%+v site=%+v error=%v", snapshot.Cache, site.Cache, err)
	}

	follow := &cachePolicyFact{
		siteID: fact.id, revision: 3, edgeSourceRevision: 8, schemaVersion: cachePolicySchemaV1,
		bindingMode: "override", definitionID: fact.id, definitionRevision: 3, definitionSourceSiteID: fact.id,
		mode:      edgeconfig.CacheFollowOrigin,
		queryMode: edgeconfig.CacheQueryPreserve, diskQuotaBytes: 128 << 20,
	}
	snapshot, site, err = compileSiteFact(scopeID, fact, 80, follow, nil, nil)
	if err != nil || snapshot.Cache == nil || snapshot.Cache.Revision != 3 ||
		site.Cache.Mode != edgeconfig.CacheFollowOrigin || site.Cache.MaxSizeBytes != 128<<20 {
		t.Fatalf("follow-origin policy snapshot=%+v site=%+v error=%v", snapshot.Cache, site.Cache, err)
	}

	override := &cachePolicyFact{
		siteID: fact.id, revision: 4, edgeSourceRevision: 9, schemaVersion: cachePolicySchemaV2,
		bindingMode: "override", definitionID: fact.id, definitionRevision: 4, definitionSourceSiteID: fact.id,
		mode:      edgeconfig.CacheOverride,
		queryMode: edgeconfig.CacheQueryInclude, queryNames: []string{"lang", "version"},
		varyHeaders: []string{"accept-encoding"}, diskQuotaBytes: 256 << 20,
		rules: []cachePolicyRuleFact{{
			order: 1, extensions: []string{".css"}, pathPrefix: "/assets/",
			statusCodes: []int{200, 304}, action: edgeconfig.CacheRuleActionCache,
			ttlSeconds: 30, browserTTLSeconds: 10,
		}, {
			order: 2, pathPrefix: "/assets/", action: edgeconfig.CacheRuleActionNoCache,
		}},
	}
	snapshot, site, err = compileSiteFact(scopeID, fact, 81, override, nil, nil)
	if err != nil || snapshot.Cache == nil || snapshot.Cache.SchemaVersion != edgeconfig.CachePolicyDocumentSchemaV2 ||
		snapshot.Cache.Revision != 4 || len(snapshot.Cache.Rules) != 2 ||
		site.Cache.Mode != edgeconfig.CacheOverride || site.Cache.QueryMode != edgeconfig.CacheQueryInclude ||
		len(site.Cache.Rules) != 2 || site.Cache.Rules[0].Action != edgeconfig.CacheRuleActionCache ||
		site.Cache.Rules[0].TTL != 30*time.Second || site.Cache.Rules[0].BrowserTTL != 10*time.Second ||
		site.Cache.Rules[1].Action != edgeconfig.CacheRuleActionNoCache || site.Cache.Rules[1].TTL != 0 {
		t.Fatalf("override policy snapshot=%+v site=%+v error=%v", snapshot.Cache, site.Cache, err)
	}
}
