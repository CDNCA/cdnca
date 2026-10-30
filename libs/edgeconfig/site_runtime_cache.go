package edgeconfig

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SiteRuntimeCache is a site's cache policy in the site runtime v2 document
// (site_runtime v6). Policy is the same document the v1 release signs
// (CachePolicyDocument); the node derives the runtime policy from it with
// CachePolicyFromDocument, exactly as the control plane's v1 publication does,
// and renders it with the v1 cache renderer. TenantID (tenants.id) and Domain
// (the site's primary domain) are the cache identity: namespace and prewarm
// path are computed from them as in v1. The cache key names the request's own
// host (nginx $host: lower case, without the port), so each name the site
// serves caches its own objects, unless SharedAcrossDomains keys every name by
// Domain (one cache for all of them, as v1).
type SiteRuntimeCache struct {
	TenantID            string              `json:"tenant_id"`
	Domain              string              `json:"domain"`
	Policy              CachePolicyDocument `json:"policy"`
	SharedAcrossDomains bool                `json:"shared_across_domains,omitempty"`
}

// Generation is the binding's cache generation (CacheGeneration).
func (cache SiteRuntimeCache) Generation() string {
	return CacheGeneration(cache.Domain, !cache.SharedAcrossDomains, cache.Policy)
}

// CachePolicyFromDocument derives the runtime cache policy from a signed
// document (control-api edgepublish compileCachePolicy): a key zone sized for
// the quota (CacheZoneBytesForQuota), the signed disk quota, a 60s default
// TTL, and for schema v1 rules the override default TTL (first rule) and the
// status-only rules as status TTLs. The result is normalized like a signed
// v1 site.
func CachePolicyFromDocument(document CachePolicyDocument) (CachePolicy, error) {
	if err := validateCachePolicyDocument(document); err != nil {
		return CachePolicy{}, err
	}
	policy := cachePolicyDocumentRuntime(document)
	if document.Mode != CacheDisabled {
		policy.ZoneSizeBytes = CacheZoneBytesForQuota(document.DiskQuotaBytes)
		policy.MaxSizeBytes = document.DiskQuotaBytes
		policy.DefaultTTL = 60 * time.Second
	}
	for index, rule := range policy.Rules {
		if document.SchemaVersion != 0 {
			continue
		}
		if index == 0 && document.Mode == CacheOverride {
			policy.DefaultTTL = rule.TTL
		}
		if len(rule.Extensions) == 0 && rule.PathPrefix == "" {
			for _, status := range rule.StatusCodes {
				policy.StatusTTLs = append(policy.StatusTTLs, CacheStatusTTL{Status: status, TTL: rule.TTL})
			}
		}
	}
	return normalizeCache(policy, true)
}

// ValidateSiteRuntimeCache checks a site runtime cache binding: a tenant
// identity, a primary domain the site serves, and a valid signed policy.
func ValidateSiteRuntimeCache(cache SiteRuntimeCache, domains []string) error {
	if !uuidPattern.MatchString(cache.TenantID) || !slices.Contains(domains, cache.Domain) {
		return ErrInvalidConfig
	}
	if domain, err := normalizeSiteDomainName(cache.Domain); err != nil || domain != cache.Domain {
		return ErrInvalidConfig
	}
	_, err := CachePolicyFromDocument(cache.Policy)
	return err
}

// SiteRuntimeCacheAdvanced reports whether the policy dispatches requests to
// per-rule named locations (rules, query or vary key projection).
func SiteRuntimeCacheAdvanced(document CachePolicyDocument) bool {
	return cachePolicyAdvanced(cachePolicyDocumentRuntime(document))
}

// SiteCacheRenderer renders one site runtime v2 site's cache with the v1
// renderer. SiteIndex is the site's index in the nginx.conf (unique across a
// composition); it names the site's rule maps and named cache locations.
type SiteCacheRenderer struct {
	tenantID        string
	generation      string
	zoneSize        int64
	maxSize         int64
	minFree         int64
	configVersionID string
	sharedRoot      string
	siteID          string
	siteIndex       int
	domain          string
	domains         []string
	rangeEnabled    bool
	keyByHost       bool
	policy          CachePolicy
	plan            cachePolicyPlan
}

// NewSiteCacheRenderer validates the binding and prepares its runtime policy.
func NewSiteCacheRenderer(configVersionID, sharedRoot, siteID string, siteIndex int, domains []string,
	rangeEnabled bool, cache SiteRuntimeCache) (*SiteCacheRenderer, error) {
	if !versionPattern.MatchString(configVersionID) || !uuidPattern.MatchString(siteID) || siteIndex < 0 ||
		!filepath.IsAbs(sharedRoot) || filepath.Clean(sharedRoot) != sharedRoot || strings.ContainsAny(sharedRoot, " \t\r\n;{}\"'$\\") {
		return nil, ErrInvalidConfig
	}
	if err := ValidateSiteRuntimeCache(cache, domains); err != nil {
		return nil, err
	}
	policy, err := CachePolicyFromDocument(cache.Policy)
	if err != nil {
		return nil, err
	}
	plan, err := buildCachePolicyPlan(policy)
	if err != nil {
		return nil, err
	}
	return &SiteCacheRenderer{
		tenantID: cache.TenantID, generation: cache.Generation(), zoneSize: policy.ZoneSizeBytes, maxSize: policy.MaxSizeBytes,
		configVersionID: configVersionID, sharedRoot: sharedRoot,
		siteID: siteID, siteIndex: siteIndex, domain: cache.Domain, domains: slices.Clone(domains), rangeEnabled: rangeEnabled,
		keyByHost: !cache.SharedAcrossDomains, policy: policy, plan: plan,
	}, nil
}

// hostCapture sets the captured request host in the rewrite phase of a block
// that caches by host: before access Lua (an origin signer) replaces Host.
func (renderer *SiteCacheRenderer) hostCapture(indent string) string {
	if !renderer.keyByHost {
		return ""
	}
	return indent + "set $" + CacheKeyHostVariable + " $host;\n"
}

// keyPrefixLua is the dispatch's key prefix: the fixed prefix, or for a
// host-keyed cache the same fields around the captured request host.
func (renderer *SiteCacheRenderer) keyPrefixLua(port uint16) string {
	if !renderer.keyByHost {
		return luaCacheString(CacheKeyPrefix(renderer.tenantID, renderer.siteID, renderer.generation, renderer.domain, port))
	}
	return luaCacheString(CacheKeyVersion+"|"+renderer.tenantID+"|"+renderer.siteID+"|"+renderer.generation+"|") +
		" .. ngx.var." + CacheKeyHostVariable + " .. " + luaCacheString("|"+strconv.Itoa(int(port))+"|")
}

func (renderer *SiteCacheRenderer) Enabled() bool  { return renderer.policy.Mode != CacheDisabled }
func (renderer *SiteCacheRenderer) Advanced() bool { return cachePolicyAdvanced(renderer.policy) }
func (renderer *SiteCacheRenderer) Domain() string { return renderer.domain }

// servedDomains is the manifest's Domains: the cache domain first, then the
// site's other names in order; nil when the site serves only that domain.
func (renderer *SiteCacheRenderer) servedDomains() []string {
	if len(renderer.domains) < 2 {
		return nil
	}
	result := []string{renderer.domain}
	for _, domain := range renderer.domains {
		if domain != renderer.domain {
			result = append(result, domain)
		}
	}
	return result
}

// PrewarmHost is the Host the site's prewarm locations send (CachePrewarmHost).
func (renderer *SiteCacheRenderer) PrewarmHost() string {
	if served := renderer.servedDomains(); served != nil {
		return CachePrewarmHost(served)
	}
	return CachePrewarmHost([]string{renderer.domain})
}
func (renderer *SiteCacheRenderer) TenantID() string {
	return renderer.tenantID
}

// NamespaceID is the site's stable cache namespace (shared/cache/<namespace>).
func (renderer *SiteCacheRenderer) NamespaceID() string {
	return CacheSiteNamespaceID(renderer.tenantID, renderer.siteID)
}

// Generation is the site's cache generation (the key's version field).
func (renderer *SiteCacheRenderer) Generation() string { return renderer.generation }

func (renderer *SiteCacheRenderer) spec() normalizedSpec {
	return normalizedSpec{ConfigVersionID: renderer.configVersionID, TenantID: renderer.tenantID}
}

// site is the v1 site this listener renders as; port is the public listen port.
func (renderer *SiteCacheRenderer) site(port uint16) Site {
	site := Site{ID: renderer.siteID, Domain: renderer.domain, ListenPort: port, Range: renderer.rangeEnabled, Cache: renderer.policy}
	if renderer.keyByHost {
		site.cacheKeyHost = "$" + CacheKeyHostVariable
	}
	return site
}

// SiteRuntimeCacheHTTPMaps are the http{} level maps of the v2 cache and the
// file serving directives of a caching node, written once per nginx.conf.
func SiteRuntimeCacheHTTPMaps() string {
	return SiteRuntimeCacheV2HTTPMaps() + cacheHTTPFileDirectives()
}

// HTTPDefinitions are the site's http{} level rule maps (schema v2 rules) and
// its cache zone. seen deduplicates zones across a nginx.conf.
func (renderer *SiteCacheRenderer) HTTPDefinitions(seen map[string]struct{}) string {
	var output strings.Builder
	if cachePolicyUsesV2Rules(renderer.policy) {
		spec := renderer.spec()
		spec.Sites = make([]Site, renderer.siteIndex+1)
		spec.Sites[renderer.siteIndex] = renderer.site(0)
		renderCachePolicyActionMaps(&output, spec)
	}
	if renderer.Enabled() {
		identity := renderer.NamespaceID()
		if _, exists := seen[identity]; !exists {
			seen[identity] = struct{}{}
			minFree := ""
			if renderer.minFree > 0 {
				minFree = " min_free=" + nginxCacheSize(renderer.minFree)
			}
			fmt.Fprintf(&output, "  proxy_cache_path %s/cache/%s levels=1:2 keys_zone=%s:%s max_size=%s%s inactive=%s use_temp_path=off;\n",
				renderer.sharedRoot, identity, renderer.zoneName(), nginxCacheSize(renderer.zoneSize),
				nginxCacheSize(renderer.maxSize), minFree, nginxCacheDuration(cacheInactiveV2(renderer.policy)))
		}
	}
	return output.String()
}

// ServerHeaders are the server{} level response headers v1 adds to every site
// and, for a host-keyed cache, the capture of the request host its keys name.
func (renderer *SiteCacheRenderer) ServerHeaders() string {
	return fmt.Sprintf("    add_header X-CDNCA-Config-Version %s always;\n", renderer.configVersionID) +
		cacheResponseHeaders("    ") + cacheVariableDefaults("    ") + renderer.hostCapture("    ")
}

func cacheResponseHeaders(indent string) string {
	return indent + "add_header X-CDN-Cache $cdnca_cache_header always;\n" +
		indent + "add_header X-CDN-Cache-Reason $cdnca_cache_reason_header always;\n"
}

// cacheVariableDefaults: every bypass input the http{} maps read has a
// value before any location runs (a rule route sets rule_matched, an advanced
// dispatch policy_bypass, the size filter size_bypass).
func cacheVariableDefaults(indent string) string {
	return indent + "set $cdnca_cache_rule_matched 0;\n" + indent + "set $cdnca_cache_policy_bypass 0;\n" +
		indent + "set $cdnca_cache_size_bypass 0;\n"
}

// HeaderFilterLua is the cache's header filter statement (object size
// bounds), empty without bounds. A location that already has a
// header_filter_by_lua_block (an HTTP policy) runs it in that block.
func (renderer *SiteCacheRenderer) HeaderFilterLua() string {
	if renderer.policy.Mode == CacheDisabled || renderer.policy.MinObjectBytes == 0 && renderer.policy.MaxObjectBytes == 0 {
		return ""
	}
	return cacheSizeFilterLua(renderer.policy)
}

// writeInternalHeaders strips the internal cache task headers toward the
// origin and from its response, as both v1 proxy bodies do.
func writeInternalHeaders(output *strings.Builder) {
	output.WriteString("      proxy_set_header X-CDNCA-Internal-Cache-Task \"\";\n")
	output.WriteString("      proxy_set_header X-CDNCA-Cache-Namespace \"\";\n")
	output.WriteString("      proxy_hide_header X-CDN-Cache;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Config-Version;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Internal-Cache-Task;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Cache-Namespace;\n")
}

func (renderer *SiteCacheRenderer) writeRange(output *strings.Builder) {
	if renderer.rangeEnabled {
		output.WriteString("      proxy_set_header Range $http_range;\n")
		output.WriteString("      proxy_set_header If-Range $http_if_range;\n")
		output.WriteString("      proxy_force_ranges on;\n")
	} else {
		output.WriteString("      proxy_set_header Range \"\";\n")
		output.WriteString("      proxy_set_header If-Range \"\";\n")
	}
}

// PublicDirectives are the cache directives of a proxying public location
// (v1 renderPublicProxyBody without a rule route): internal headers, the cache
// itself and Range forwarding. port is the listener's public port.
func (renderer *SiteCacheRenderer) PublicDirectives(port uint16) string {
	return renderer.publicDirectives(port, true)
}

// PublicDirectivesWithoutHeaderFilter is PublicDirectives for a location
// whose own header_filter_by_lua_block runs HeaderFilterLua.
func (renderer *SiteCacheRenderer) PublicDirectivesWithoutHeaderFilter(port uint16) string {
	return renderer.publicDirectives(port, false)
}

func (renderer *SiteCacheRenderer) publicDirectives(port uint16, headerFilter bool) string {
	var output strings.Builder
	writeInternalHeaders(&output)
	if renderer.Enabled() {
		renderer.v2Directives(&output, port, nil, false, headerFilter)
	} else {
		renderer.writeRange(&output)
	}
	return output.String()
}

// DispatchPrelude and DispatchLua route an advanced policy's request to its
// named rule location (v1 renderCachePolicyDispatch); the Lua runs in the
// location's access_by_lua_block after any firewall action.
func (renderer *SiteCacheRenderer) DispatchPrelude() string {
	return fmt.Sprintf("      # cdnca-cache-policy-plan %s\n      set $cdnca_cache_policy_key \"\";\n"+
		"      set $cdnca_cache_policy_bypass 1;\n      set $cdnca_cache_policy_routed 0;\n", renderer.plan.Digest)
}

func (renderer *SiteCacheRenderer) DispatchLua(port uint16, prewarm bool) string {
	return cachePolicyDispatchLuaExpression(renderer.keyPrefixLua(port), renderer.policy, renderer.plan, renderer.siteIndex, prewarm)
}

// NamedRoutes are an advanced policy's named locations: the bypass route and
// one per candidate rule set. proxy is the caller's proxy directives
// (upstream, Host, timeouts, retries, connection headers); prewarm selects the
// internal prewarm variant, which must be given proxy directives that do not
// forward client connection headers and send the site's Host.
func (renderer *SiteCacheRenderer) NamedRoutes(prewarm bool, proxy string) string {
	if !prewarm {
		return renderer.PublicTargetRoutes(0, proxy, "")
	}
	var output strings.Builder
	for index := -1; index < len(renderer.plan.Routes); index++ {
		fmt.Fprintf(&output, "    location %s {\n      internal;\n", cachePolicyRouteName(renderer.siteIndex, true, index+1))
		route := renderer.boundRoute(index)
		if route != nil {
			fmt.Fprintf(&output, "      # cdnca-cache-policy-candidates %s\n", route.Signature)
			// The request names a cache rule: its Cookie does not bypass.
			output.WriteString("      set $cdnca_cache_rule_matched 1;\n")
		}
		// A rule route's key is $cdnca_cache_policy_key, set by the
		// listener's dispatch, so one route set serves every port.
		renderer.writePrewarmBody(&output, proxy, 0, route, route == nil)
		output.WriteString("    }\n")
	}
	return output.String()
}

// boundRoute is the plan's rule route index (-1: the bypass route, nil).
func (renderer *SiteCacheRenderer) boundRoute(index int) *cachePolicyRoute {
	if index < 0 {
		return nil
	}
	bound := bindCachePolicyRouteVariables(renderer.plan.Routes[index], renderer.siteIndex, index)
	return &bound
}

// publicRouteName names public rule location routeIndex (0: the bypass route)
// of origin target target: target 0 is the site's default pool, target n the
// pool of the site's n-th origin route.
func (renderer *SiteCacheRenderer) publicRouteName(target, routeIndex int) string {
	name := cachePolicyRouteName(renderer.siteIndex, false, routeIndex)
	if target == 0 {
		return name
	}
	return fmt.Sprintf("%s_t%04d", name, target)
}

// DispatchLuaTo is DispatchLua for a public listener whose request goes to
// origin target target (PublicTargetRoutes).
func (renderer *SiteCacheRenderer) DispatchLuaTo(port uint16, target int) string {
	return cachePolicyDispatchLuaFor(renderer.keyPrefixLua(port),
		renderer.policy, renderer.plan, func(routeIndex int) string { return renderer.publicRouteName(target, routeIndex) })
}

// PublicTargetRoutes are the public named rule locations of origin target
// target. proxy is each location's directives toward the target's pool
// (upstream, Host, timeouts, retries, connection headers, error pages, any
// HTTP policy restore). fallback, when set, is the same toward the target's
// fallback pool (L2 direct fallback or an origin route's fallback): each rule
// location then hands 502/503/504 to its own fallback location, which caches
// under the same rule and key.
func (renderer *SiteCacheRenderer) PublicTargetRoutes(target int, proxy, fallback string) string {
	var output strings.Builder
	for index := -1; index < len(renderer.plan.Routes); index++ {
		name := renderer.publicRouteName(target, index+1)
		route := renderer.boundRoute(index)
		fmt.Fprintf(&output, "    location %s {\n      internal;\n", name)
		if route != nil {
			fmt.Fprintf(&output, "      # cdnca-cache-policy-candidates %s\n", route.Signature)
			// The request names a cache rule: its Cookie does not bypass.
			output.WriteString("      set $cdnca_cache_rule_matched 1;\n")
		}
		renderer.writePublicBody(&output, proxy, route, fallback != "")
		if fallback != "" {
			fmt.Fprintf(&output, "      proxy_intercept_errors on;\n      error_page 502 503 504 = %s_fallback;\n", name)
		}
		output.WriteString("    }\n")
		if fallback != "" {
			fmt.Fprintf(&output, "    location %s_fallback {\n      internal;\n", name)
			renderer.writePublicBody(&output, fallback, route, false)
			output.WriteString("    }\n")
		}
	}
	return output.String()
}

// writePublicBody writes a rule location's proxy and cache. keepGatewayErrors
// (a location that hands 502/503/504 to its fallback) stores no gateway error:
// nginx caches an upstream 502/504 that proxy_cache_valid covers (a rule's
// "any"), and the fallback, sharing the key, would serve it as a HIT. The
// first matching proxy_cache_valid wins, so this one precedes the rule's.
func (renderer *SiteCacheRenderer) writePublicBody(output *strings.Builder, proxy string, route *cachePolicyRoute,
	keepGatewayErrors bool) {
	output.WriteString(proxy)
	writeInternalHeaders(output)
	if keepGatewayErrors {
		output.WriteString("      proxy_cache_valid 502 503 504 0;\n")
	}
	if route != nil {
		// A proxy with an HTTP policy carries the location's one
		// header_filter_by_lua_block, which already runs HeaderFilterLua.
		renderer.v2Directives(output, 0, route, false, !strings.Contains(proxy, "header_filter_by_lua_block"))
	} else {
		renderer.writeRange(output)
	}
}

// writePrewarmBody renders a prewarm proxy body; port is the public listen
// port the simple cache key names.
func (renderer *SiteCacheRenderer) writePrewarmBody(output *strings.Builder, proxy string, port uint16, route *cachePolicyRoute, bypass bool) {
	fmt.Fprintf(output, "      add_header X-CDNCA-Config-Version %s always;\n", renderer.configVersionID)
	fmt.Fprintf(output, "      add_header X-CDNCA-Cache-Namespace %s always;\n", renderer.NamespaceID())
	output.WriteString(cacheResponseHeaders("      "))
	// proxy sends the Host: a second proxy_set_header Host would send two.
	output.WriteString(proxy)
	output.WriteString("      proxy_set_header X-Forwarded-For \"\";\n")
	writeInternalHeaders(output)
	output.WriteString("      proxy_set_header Upgrade \"\";\n")
	if !bypass {
		renderer.v2Directives(output, port, route, true, true)
		return
	}
	output.WriteString("      proxy_set_header Range \"\";\n")
	output.WriteString("      proxy_set_header If-Range \"\";\n")
}

// SiteRuntimeCacheListener is one public listener of a cached site.
type SiteRuntimeCacheListener struct {
	Port uint16
	TLS  bool
}

func listenerProtocol(listener SiteRuntimeCacheListener) Protocol {
	if listener.TLS {
		return ProtocolHTTPS
	}
	return ProtocolHTTP
}

// PrewarmLocations are the health server locations the cache task prewarms
// through (v1 renders them in the loopback health server): one per listener,
// and for an advanced policy the named prewarm routes once. proxy is the
// caller's proxy directives toward the default pool without client
// connection headers. access, when set, is the caller's access Lua for a
// listener's prewarm prefix (origin signing); it runs before an advanced
// policy's dispatch, whose ngx.exec keeps the request headers it sets.
// Empty when the cache is disabled.
func (renderer *SiteCacheRenderer) PrewarmLocations(listeners []SiteRuntimeCacheListener, proxy string,
	access func(prefix string) string) string {
	if !renderer.Enabled() {
		return ""
	}
	var output strings.Builder
	namespace := renderer.NamespaceID()
	for _, listener := range listeners {
		prefix := CachePrewarmPathPrefix(renderer.tenantID, renderer.siteID, renderer.configVersionID,
			renderer.domain, listener.Port, listenerProtocol(listener))
		fmt.Fprintf(&output, "    location ^~ %s {\n", prefix)
		output.WriteString("      if ($request_method != GET) { return 405; }\n")
		output.WriteString("      if ($http_x_cdnca_internal_cache_task != \"v2\") { return 404; }\n")
		fmt.Fprintf(&output, "      if ($http_x_cdnca_cache_namespace != \"%s\") { return 404; }\n", namespace)
		// The cache task sends the URL's own host: the key it writes is the
		// one that host's visitors read. Before rewrite...break, which ends
		// the rewrite phase.
		output.WriteString(renderer.hostCapture("      "))
		output.WriteString(cacheVariableDefaults("      "))
		fmt.Fprintf(&output, "      rewrite ^%s(.*)$ /$1 break;\n", regexp.QuoteMeta(prefix))
		accessLua := ""
		if access != nil {
			accessLua = access(prefix)
		}
		if renderer.Advanced() {
			output.WriteString(renderer.DispatchPrelude())
			output.WriteString("      access_by_lua_block {\n")
			output.WriteString(accessLua)
			output.WriteString(renderer.DispatchLua(listener.Port, true))
			output.WriteString("      }\n")
		} else {
			if accessLua != "" {
				output.WriteString("      access_by_lua_block {\n" + accessLua + "      }\n")
			}
			// The simple key names the public port: prewarm writes the key
			// this listener's public location reads.
			renderer.writePrewarmBody(&output, proxy, listener.Port, nil, false)
		}
		output.WriteString("    }\n")
	}
	if renderer.Advanced() {
		output.WriteString(renderer.NamedRoutes(true, proxy))
	}
	return output.String()
}

// ManifestListener is this listener's entry in the cache identity manifest.
func (renderer *SiteCacheRenderer) ManifestListener(listener SiteRuntimeCacheListener, prewarmPort uint16) CacheListenerPolicy {
	return CacheListenerPolicy{
		SiteID: renderer.siteID, Domain: renderer.domain, ListenPort: listener.Port, Protocol: listenerProtocol(listener),
		PrewarmPort: prewarmPort,
		PrewarmPathPrefix: CachePrewarmPathPrefix(renderer.tenantID, renderer.siteID, renderer.configVersionID,
			renderer.domain, listener.Port, listenerProtocol(listener)),
		NamespaceID:     renderer.NamespaceID(),
		KeyPrefix:       CacheKeyPrefix(renderer.tenantID, renderer.siteID, renderer.generation, renderer.domain, listener.Port),
		Policy:          cachePolicyDocument(renderer.policy),
		Domains:         renderer.servedDomains(),
		KeyByHost:       renderer.keyByHost,
		CacheGeneration: renderer.generation,
	}
}

// SiteRuntimeCacheManifest is the cache identity manifest (cache/policies-v2.json)
// of a node-compiled site runtime release; nginxSHA256 binds it to the
// release's nginx.conf as in v1.
func SiteRuntimeCacheManifest(configVersionID string, configRevision uint64, tenantID string, nginx []byte,
	listeners []CacheListenerPolicy) ([]byte, error) {
	sorted := slices.Clone(listeners)
	sort.Slice(sorted, func(left, right int) bool {
		if sorted[left].ListenPort != sorted[right].ListenPort {
			return sorted[left].ListenPort < sorted[right].ListenPort
		}
		return sorted[left].Domain < sorted[right].Domain
	})
	manifest := CachePolicyManifest{
		SchemaVersion: cachePolicySchema, ConfigVersionID: configVersionID, ConfigRevision: configRevision,
		TenantID: tenantID, NginxSHA256: digestHex(nginx), KeyModuleSHA256: CachePolicyKeyModuleSHA256, Listeners: sorted,
	}
	if err := normalizeCacheManifest(&manifest); err != nil {
		return nil, err
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

// ParseSiteRuntimeCacheRelease checks a node-compiled release's cache identity:
// a canonical manifest bound to the release's nginx.conf and key module.
func ParseSiteRuntimeCacheRelease(policyContent, nginxContent, keyModuleContent []byte) (CachePolicyManifest, error) {
	manifest, err := ParseCachePolicyManifest(policyContent)
	if err != nil || manifest.NginxSHA256 != digestHex(nginxContent) || digestHex(keyModuleContent) != CachePolicyKeyModuleSHA256 {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	return manifest, nil
}
