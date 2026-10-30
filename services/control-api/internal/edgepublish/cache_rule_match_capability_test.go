package edgepublish

import (
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// ge36: a cache policy with path_regex or content_types requires
// CACHE_RULE_MATCH (51/52 gated, no downgrade); origin follow redirect
// requires ORIGIN_FOLLOW_REDIRECT.
func TestCacheRuleMatchCapability(t *testing.T) {
	for name, capability := range map[string]agentv1.CapabilityName{
		edgeconfig.CacheRuleMatchCapability:       agentv1.CapabilityName_CAPABILITY_NAME_CACHE_RULE_MATCH,
		edgeconfig.OriginFollowRedirectCapability: agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_FOLLOW_REDIRECT,
	} {
		if got, ok := siteruntimecap.Name(name); !ok || got != capability {
			t.Errorf("%s maps to %v", name, got)
		}
		feature, gated := gatedFeature(&agentv1.Capability{Name: capability, ApiVersion: 1})
		if !gated || !strings.Contains(feature, agentv1.CapabilityName_name[int32(capability)][len("CAPABILITY_NAME_"):]) {
			t.Errorf("%s is not a gated feature: %q", name, feature)
		}
	}

	siteID := uuid.New()
	fact := func(rules ...cachePolicyRuleFact) *cachePolicyFact {
		return &cachePolicyFact{siteID: siteID, revision: 1, edgeSourceRevision: 1, bindingMode: "override",
			definitionID: uuid.New(), definitionRevision: 1, definitionSourceSiteID: siteID,
			schemaVersion: cachePolicySchemaV2, mode: edgeconfig.CacheOverride, queryMode: edgeconfig.CacheQueryPreserve,
			diskQuotaBytes: 64 << 20, rules: rules}
	}
	bind := func(policy *cachePolicyFact) siteRuntimeV2Document {
		document := siteRuntimeV2Document{RequiredCapabilities: []siteRuntimeV2Capability{{Name: "site_runtime", APIVersion: 9}},
			Sites: []siteRuntimeV2Site{{ID: siteID.String(), Domains: []string{"a.example.com"}}}}
		if err := bindSiteRuntimeV2Cache(&document, uuid.New(), []siteFact{{id: siteID, domain: "a.example.com"}},
			map[uuid.UUID]*cachePolicyFact{siteID: policy}); err != nil {
			t.Fatal(err)
		}
		return document
	}
	required := func(document siteRuntimeV2Document) uint32 {
		for _, capability := range document.RequiredCapabilities {
			if capability.Name == edgeconfig.CacheRuleMatchCapability {
				return capability.APIVersion
			}
		}
		return 0
	}
	plain := bind(fact(cachePolicyRuleFact{order: 1, extensions: []string{".css"}, action: edgeconfig.CacheRuleActionCache, ttlSeconds: 60}))
	if required(plain) != 0 {
		t.Fatalf("plain rules require %v", plain.RequiredCapabilities)
	}
	regex := bind(fact(cachePolicyRuleFact{order: 1, pathRegex: `^/v[0-9]+/`, action: edgeconfig.CacheRuleActionCache, ttlSeconds: 60}))
	if required(regex) != 1 || regex.Sites[0].Cache.Policy.Rules[0].PathRegex != `^/v[0-9]+/` {
		t.Fatalf("path_regex: %v %+v", regex.RequiredCapabilities, regex.Sites[0].Cache.Policy.Rules)
	}
	typed := bind(fact(cachePolicyRuleFact{order: 1, contentTypes: []string{"image/*"}, action: edgeconfig.CacheRuleActionCache, ttlSeconds: 60}))
	if required(typed) != 1 {
		t.Fatalf("content_types: %v", typed.RequiredCapabilities)
	}
	inferred := map[string]uint32{}
	if err := validateSiteRuntimeV2Cache(typed.Sites[0], inferred); err != nil || inferred[edgeconfig.CacheRuleMatchCapability] != 1 {
		t.Fatalf("validate inferred %v %v", inferred, err)
	}
	v1 := fact(cachePolicyRuleFact{order: 1, pathRegex: `^/a`, ttlSeconds: 60})
	v1.schemaVersion = cachePolicySchemaV1
	if document, _, err := compileCachePolicy(siteID, v1); err != nil || document.Rules[0].PathRegex != `^/a` {
		t.Fatalf("schema v1 rule with path_regex: %+v %v", document, err)
	}
}
