package edgepublish

import (
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// siteRuntimeV6APIVersion adds each site's cache policy (site.cache) to the
// site runtime document (the node renders it as the v1 release does) and a
// listener's managed WAF / JS challenge: one version, one gate.
const siteRuntimeV6APIVersion = edgeconfig.ListenerRuntimeSecuritySiteRuntimeVersion

// bindSiteRuntimeV2Cache gives every site its cache policy, compiled from the
// same facts and with the same rules as the v1 publication (compileCachePolicy):
// a site without a policy is disabled. The cache identity uses the tenant
// (tenants.id) and the site's primary domain, as v1 does; the node keys each
// object by the request host unless the site shares one cache across its
// domains (cacheSharedAcrossDomains).
func bindSiteRuntimeV2Cache(document *siteRuntimeV2Document, tenantID uuid.UUID, facts []siteFact,
	policies map[uuid.UUID]*cachePolicyFact) error {
	primary := make(map[string]string, len(facts))
	shared := make(map[string]bool, len(facts))
	for _, fact := range facts {
		primary[fact.id.String()] = fact.domain
		shared[fact.id.String()] = fact.cacheSharedAcrossDomains
	}
	for index := range document.Sites {
		site := &document.Sites[index]
		siteID, err := uuid.Parse(site.ID)
		if err != nil {
			return ErrInvalidInput
		}
		policy, _, err := compileCachePolicy(siteID, policies[siteID])
		if err != nil {
			return err
		}
		if policy == nil {
			policy = &edgeconfig.CachePolicyDocument{Mode: edgeconfig.CacheDisabled, QueryMode: edgeconfig.CacheQueryIgnore}
		}
		// The canonical document rejects explicit nulls: lists are always arrays.
		policy.Rules = nonNil(policy.Rules)
		policy.QueryNames = nonNil(policy.QueryNames)
		policy.VaryHeaders = nonNil(policy.VaryHeaders)
		domain := primary[site.ID]
		if !slices.Contains(site.Domains, domain) {
			domain = site.Domains[0]
		}
		site.Cache = &edgeconfig.SiteRuntimeCache{TenantID: tenantID.String(), Domain: domain, Policy: *policy,
			SharedAcrossDomains: shared[site.ID]}
		if version := cacheRuleMatchVersion(*policy); version != 0 {
			// path_regex / content_types (ge36), per-rule settings (v2): no
			// downgrade, a node without CACHE_RULE_MATCH at that version is
			// refused (validateFeatureCapabilityTargets)
			requireSiteRuntimeV2Capability(document, edgeconfig.CacheRuleMatchCapability, version)
		}
	}
	return nil
}

func nonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

// validateSiteRuntimeV2Cache checks a site's cache binding. Cache rules (and
// query/vary key projection) combine with an HTTP policy, L2 forwarding and
// origin routes: the node renders per-target rule routes that restore the
// policy and follow fallback (siteruntimev2 writeCacheTargetRoutes).
func validateSiteRuntimeV2Cache(site siteRuntimeV2Site, inferred map[string]uint32) error {
	if site.Cache == nil {
		return nil
	}
	if err := edgeconfig.ValidateSiteRuntimeCache(*site.Cache, site.Domains); err != nil {
		return ErrInvalidInput
	}
	if version := cacheRuleMatchVersion(site.Cache.Policy); version != 0 {
		inferred[edgeconfig.CacheRuleMatchCapability] = max(inferred[edgeconfig.CacheRuleMatchCapability], version)
	}
	return nil
}

// cacheRuleMatchVersion is the CACHE_RULE_MATCH version a policy needs (0:
// none): 2 with per-rule settings, 1 with path_regex or
// content_types only.
func cacheRuleMatchVersion(policy edgeconfig.CachePolicyDocument) uint32 {
	switch {
	case edgeconfig.CachePolicyUsesRuleExtras(policy):
		return edgeconfig.CacheRuleMatchExtrasAPIVersion
	case edgeconfig.CachePolicyUsesRuleMatch(policy):
		return 1
	}
	return 0
}
