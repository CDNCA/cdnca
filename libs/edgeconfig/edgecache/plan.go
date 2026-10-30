package edgecache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// PlanSchema names the per-site plan the Lua module (dynroute/cdnca_cache.lua)
// executes; the node derives it from the site object, it is never published.
const PlanSchema = "cdnca.edge.cache-plan/v1"

// Bypass reasons (X-CDN-Cache-Reason, ge-cache H): the v7 names
// (edgeconfig SiteRuntimeCacheV2HTTPMaps) in v7's order of precedence, then
// the dynamic routing node's own (key, purge_state, disabled).
const (
	ReasonMethod        = "method"
	ReasonAuthorization = "authorization"
	ReasonCookie        = "cookie"
	ReasonUpgrade       = "upgrade"
	// ReasonNoCacheRule: no cache rule names the request, or the rules that
	// do cache no status (v7 $cdnca_cache_policy_bypass).
	ReasonNoCacheRule   = "no_cache_rule"
	ReasonSetCookie     = "set_cookie"
	ReasonOriginNoStore = "origin_no_store"
	ReasonObjectSize    = "object_size"
	// ReasonResponseRule: a site response rule replaced the response.
	ReasonResponseRule = "response_rule"
	// ReasonContentType: the rules left once the response's Content-Type
	// is known (content_types, ge36) cache nothing for it.
	ReasonContentType = "content_type"
	// ReasonNoCacheCondition: one of the deciding rule's 不缓存条件 matched:
	// not read from or stored in the cache.
	ReasonNoCacheCondition = "no_cache_condition"
	ReasonKey              = "key"
	ReasonPurgeState       = "purge_state"
	ReasonDisabled         = "disabled"
)

// Slice variants: nginx's slice size is configuration-time, so the skeleton
// renders one variant per size the console offers (SliceVariantSizes); a
// policy's slice_bytes (any 64 KiB multiple in 256 KiB..64 MiB) runs in the
// largest of them not above it (SliceVariantBytes). The size only decides
// how the origin is asked (one Range per slice); clients see the same bytes.
var sliceVariantSizes = []int64{256 << 10, 1 << 20, 4 << 20, 16 << 20, 64 << 20}

// SliceVariantSizes are the slice sizes the skeleton renders variants for.
func SliceVariantSizes() []int64 { return slices.Clone(sliceVariantSizes) }

// SliceVariantBytes is the slice size a policy's slice_bytes runs with
// (0: no slices).
func SliceVariantBytes(sliceBytes int64) int64 {
	var size int64
	for _, candidate := range sliceVariantSizes {
		if candidate <= sliceBytes {
			size = candidate
		}
	}
	return size
}

// StaleInactive: with stale_if_error an expired object stays on disk at
// least this long after its last read (v7 cacheStaleInactive).
const StaleInactive = 24 * time.Hour

// Plan is one site's cache plan.
type Plan struct {
	Schema string `json:"schema"`
	// KeyPrefix|Generation: edgesite.Cache (stable site identity and the
	// ge-cache generation); the purge generation (node state) follows them.
	KeyPrefix  string `json:"key_prefix"`
	Generation string `json:"generation"`
	Domain     string `json:"domain"`
	KeyByHost  bool   `json:"key_by_host"`
	Mode       string `json:"mode"` // override | follow_origin
	// QueryMode/QueryNames/VaryHeaders: the key projection (cachepolicy/key.lua).
	QueryMode   string   `json:"query_mode"`
	QueryNames  []string `json:"query_names"`
	VaryHeaders []string `json:"vary_headers"`
	// Projected: the key carries ?~q=<query digest>&~v=<vary digest> instead
	// of the raw query (v7 "advanced" policy without "legacy").
	Projected bool `json:"projected"`
	// Rules are the match conditions only; Routes maps the candidate
	// signature (the 1-based indexes of every matching rule, comma joined,
	// "" for a policy without rules) to the decision, exactly as v7's
	// cachePolicyPlan. A signature not in Routes is not cacheable (no_rule).
	Rules  []Match          `json:"rules"`
	Routes map[string]Route `json:"routes"`
	// Range forwarding of a bypassed request (site.range); every cache
	// variant answers Range from the cached object (v7 proxy_force_ranges).
	Range bool `json:"range"`
	// SliceBytes is the slice variant's size (SliceVariantBytes of
	// policy.slice_bytes; 0 = whole objects); 206 is cached like 200.
	SliceBytes int64 `json:"slice_bytes"`
	// StaleIfError/BackgroundUpdate pick the stale variant; MinObjectBytes/
	// MaxObjectBytes bound a stored object (0 = no bound; header filter).
	StaleIfError     bool  `json:"stale_if_error"`
	BackgroundUpdate bool  `json:"background_update"`
	MinObjectBytes   int64 `json:"min_object_bytes"`
	MaxObjectBytes   int64 `json:"max_object_bytes"`
	// QuotaBytes is the soft quota (policy.disk_quota_bytes): the agent's
	// per-site cleaner, not nginx, enforces it.
	QuotaBytes int64 `json:"quota_bytes"`
}

// Match is one rule's condition (cachepolicy/key.lua matching_candidates).
// PathRegex is matched on $uri (PCRE2, edgeconfig.ValidateCachePathRegex);
// ContentTypes on the response (header filter).
type Match struct {
	PathPrefix   string   `json:"path_prefix"`
	Extensions   []string `json:"extensions"`
	PathRegex    string   `json:"path_regex,omitempty"`
	ContentTypes []string `json:"content_types,omitempty"`
	// PathExact (单个路径): $uri must equal it.
	PathExact string `json:"path_exact,omitempty"`
}

// Route is the decision for one candidate set. Cache false: no status is
// cached (no_cache_rule: the response is still proxied, never stored). TTLs
// is the value of $cdnca_cache_ttls (TTLs.Value). Browser/BrowserAny: nginx
// expires per status (schema v2 rules; empty = no expires).
//
// With content_types rules (ge36) the signature is the request's; once the
// response's Content-Type is known its content_types rules that do not
// match are dropped and the remaining signature's route decides the TTLs
// (header filter). MayCache: some Content-Type leaves a route that caches
// (the request is looked up in the cache); equal to Cache without such rules.
//
// Per-rule settings (edgeconfig.CacheRuleExtras) come from
// the route's deciding rule, its first candidate: Variant is the named
// location of its cacheable requests (mode/force_cache, stale, slice size,
// ignore_vary), IgnoreQuery drops the query from the key, NoCache are its
// 不缓存条件 (a match bypasses the cache: no_cache_condition).
type Route struct {
	Cache       bool                               `json:"cache"`
	MayCache    bool                               `json:"may_cache"`
	TTLs        string                             `json:"ttls"`
	Browser     map[string]string                  `json:"browser,omitempty"`
	BrowserAny  string                             `json:"browser_any,omitempty"`
	Variant     string                             `json:"variant,omitempty"`
	IgnoreQuery bool                               `json:"ignore_query,omitempty"`
	NoCache     []edgeconfig.CacheNoCacheCondition `json:"no_cache,omitempty"`
}

// TTLs maps a status to seconds: Status entries win over Any; 0 = not cached.
type TTLs struct {
	Status map[int]int64
	Any    int64
}

// Value renders TTLs as $cdnca_cache_ttls, read through the skeleton's
// status map into patch 24's proxy_cache_valid: " 200=60 404=0 any=60 "
// (leading and trailing space so " <status>=" matches whole tokens).
func (ttls TTLs) Value() string {
	keys := make([]int, 0, len(ttls.Status))
	for status := range ttls.Status {
		keys = append(keys, status)
	}
	slices.Sort(keys)
	var output strings.Builder
	output.WriteByte(' ')
	for _, status := range keys {
		fmt.Fprintf(&output, "%d=%d ", status, ttls.Status[status])
	}
	fmt.Fprintf(&output, "any=%d ", ttls.Any)
	return output.String()
}

// Build derives a site's plan. nil cache or disabled mode = no plan.
func Build(site edgesite.Site) (*Plan, error) {
	cache := site.Cache
	if cache == nil || cache.Policy.Mode == edgeconfig.CacheDisabled {
		return nil, nil
	}
	policy, err := edgeconfig.CachePolicyFromDocument(cache.Policy)
	if err != nil {
		return nil, fmt.Errorf("%w: cache policy: %v", ErrInvalid, err)
	}
	if err := edgeconfig.ValidateCachePolicyExtensions(cache.Policy); err != nil {
		return nil, fmt.Errorf("%w: cache policy extensions", ErrInvalid)
	}
	plan := &Plan{
		Schema: PlanSchema, KeyPrefix: cache.KeyPrefix, Generation: cache.Generation, Domain: cache.Domain,
		KeyByHost: cache.KeyByHost, Mode: string(policy.Mode), QueryMode: string(policy.QueryMode),
		QueryNames: nonNil(policy.QueryNames), VaryHeaders: nonNil(policy.VaryHeaders),
		Projected: policy.QueryMode != edgeconfig.CacheQueryPreserve || len(policy.VaryHeaders) != 0,
		Rules:     []Match{}, Routes: map[string]Route{},
		Range: site.Range, QuotaBytes: cache.Policy.DiskQuotaBytes,
		SliceBytes:   SliceVariantBytes(policy.SliceBytes),
		StaleIfError: policy.StaleIfError, BackgroundUpdate: policy.BackgroundUpdate,
		MinObjectBytes: policy.MinObjectBytes, MaxObjectBytes: policy.MaxObjectBytes,
	}
	sliced := plan.SliceBytes > 0
	if len(policy.Rules) == 0 {
		plan.Routes[""] = Route{Cache: true, TTLs: sliceTTLs(simpleTTLs(policy), sliced).Value()}
		return plan, nil
	}
	for _, rule := range policy.Rules {
		plan.Rules = append(plan.Rules, Match{PathPrefix: rule.PathPrefix, Extensions: nonNil(rule.Extensions),
			PathRegex: rule.PathRegex, ContentTypes: rule.ContentTypes, PathExact: rule.PathExact})
	}
	signatures, err := candidateSets(policy.Rules)
	if err != nil {
		return nil, err
	}
	for signature, candidates := range signatures {
		route := decide(policy, candidates, plan.ruleSliceBytes(policy.Rules[candidates[0]]) > 0)
		plan.ruleSettings(&route, policy.Rules[candidates[0]])
		plan.Routes[signature] = route
	}
	for signature, candidates := range signatures {
		route := plan.Routes[signature]
		route.MayCache = route.Cache
		for _, effective := range contentTypeSubsets(policy.Rules, candidates) {
			route.MayCache = route.MayCache || plan.Routes[signatureOf(effective)].Cache
		}
		plan.Routes[signature] = route
	}
	return plan, nil
}

// sliceTTLs: with slices every object is a 206 slice, cached like 200 (v7
// v2Validity); "any" covers 206 already.
func sliceTTLs(ttls TTLs, sliced bool) TTLs {
	if value, ok := ttls.Status[200]; sliced && ok {
		if _, explicit := ttls.Status[206]; !explicit {
			ttls.Status[206] = value
		}
	}
	return ttls
}

// Variant is the named location of the plan's cacheable requests without a
// deciding rule's own settings:
// @cdnca_cache_<override|follow>[_stale|_stalebg][_nv][_s<KiB>] (VariantNames).
func (plan *Plan) Variant() string {
	return variantName(plan.Mode == string(edgeconfig.CacheOverride), staleOf(plan.StaleIfError, plan.BackgroundUpdate), false, plan.SliceBytes)
}

// ruleSliceBytes is the slice variant size of a rule's requests.
func (plan *Plan) ruleSliceBytes(rule edgeconfig.CacheRule) int64 {
	if rule.SliceBytes != nil {
		return SliceVariantBytes(*rule.SliceBytes)
	}
	return plan.SliceBytes
}

// ruleSettings fills a route's per-rule settings from its deciding rule; a
// rule without any keeps the plan's variant (Variant empty).
func (plan *Plan) ruleSettings(route *Route, rule edgeconfig.CacheRule) {
	route.IgnoreQuery = rule.IgnoreQuery
	route.NoCache = slices.Clone(rule.NoCache)
	if rule.SliceBytes == nil && rule.ForceCache == nil && !rule.IgnoreVary {
		return
	}
	override := plan.Mode == string(edgeconfig.CacheOverride)
	if rule.ForceCache != nil {
		override = *rule.ForceCache
	}
	route.Variant = variantName(override, staleOf(plan.StaleIfError, plan.BackgroundUpdate), rule.IgnoreVary, plan.ruleSliceBytes(rule))
}

// Inactive is how long the plan needs an unread object kept (pool inactive,
// ge-cache G): its longest TTL, with stale_if_error at least StaleInactive.
func (plan *Plan) Inactive() time.Duration {
	if plan.StaleIfError {
		return max(plan.MaxTTL(), StaleInactive)
	}
	return plan.MaxTTL()
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return slices.Clone(values)
}

// simpleTTLs: v7 renderCacheRuntime without a route (200/301/302 at the
// default TTL, v1 status rules override, other statuses not cached).
func simpleTTLs(policy edgeconfig.CachePolicy) TTLs {
	ttls := TTLs{Status: map[int]int64{}}
	for _, status := range []int{200, 301, 302} {
		ttls.Status[status] = seconds(policy.DefaultTTL)
	}
	for _, status := range policy.StatusTTLs {
		ttls.Status[status.Status] = seconds(status.TTL)
	}
	return ttls
}

func seconds(value time.Duration) int64 { return int64(value / time.Second) }

// maxRoutes bounds the route table (edgeconfig maxCachePolicyRoutes).
const maxRoutes, maxRouteKeys = 2048, 4096

func conditional(rule edgeconfig.CacheRule) bool {
	return rule.PathRegex != "" || len(rule.ContentTypes) != 0
}

// pathMatches: whether a rule names a request of path class class (a
// directory prefix or an exact path of some rule, "" = any other path).
// An exact class is that path itself; a prefix class every path under it.
func pathMatches(rule edgeconfig.CacheRule, class pathClass) bool {
	if rule.PathExact != "" {
		return class.exact && class.value == rule.PathExact
	}
	if rule.PathPrefix == "" {
		return true
	}
	return class.value != "" && strings.HasPrefix(class.value, rule.PathPrefix)
}

type pathClass struct {
	value string
	exact bool
}

func signatureOf(candidates []int) string {
	names := make([]string, len(candidates))
	for position, candidate := range candidates {
		names[position] = strconv.Itoa(candidate + 1)
	}
	return strings.Join(names, ",")
}

// subsets: candidates with every combination of the members keep() selects
// left out (the full set first), non-empty only.
func subsets(candidates []int, keep func(int) bool) [][]int {
	var optional []int
	for _, candidate := range candidates {
		if keep(candidate) {
			optional = append(optional, candidate)
		}
	}
	var result [][]int
	for mask := 0; mask < 1<<len(optional); mask++ {
		var set []int
		for _, candidate := range candidates {
			position := slices.Index(optional, candidate)
			if position < 0 || mask&(1<<position) == 0 {
				set = append(set, candidate)
			}
		}
		if len(set) != 0 {
			result = append(result, set)
		}
	}
	return result
}

// contentTypeSubsets are the signatures the header filter can leave of
// candidates (some of their content_types rules dropped; the set itself
// excluded). An empty result set is not cached (no route).
func contentTypeSubsets(rules []edgeconfig.CacheRule, candidates []int) [][]int {
	all := subsets(candidates, func(index int) bool { return len(rules[index].ContentTypes) != 0 })
	if len(all) > 0 && slices.Equal(all[0], candidates) {
		return all[1:]
	}
	return all
}

// candidateSets enumerates the candidate sets a request can produce, as v7
// buildCachePolicyPlan: every (path class, extension class) pair; a rule
// with a path_regex or content_types (at most
// edgeconfig.MaxCacheConditionalRules) may or may not be part of each.
func candidateSets(rules []edgeconfig.CacheRule) (map[string][]int, error) {
	paths, extensions := []pathClass{{}}, []string{""}
	seenPath, seenExtension := map[pathClass]bool{{}: true}, map[string]bool{"": true}
	for _, rule := range rules {
		class := pathClass{value: rule.PathPrefix}
		if rule.PathExact != "" {
			class = pathClass{value: rule.PathExact, exact: true}
		}
		if !seenPath[class] {
			seenPath[class] = true
			paths = append(paths, class)
		}
		for _, extension := range rule.Extensions {
			if !seenExtension[extension] {
				seenExtension[extension] = true
				extensions = append(extensions, extension)
			}
		}
	}
	if len(paths)*len(extensions) > maxRouteKeys {
		return nil, fmt.Errorf("%w: %d rule classes", ErrInvalid, len(paths)*len(extensions))
	}
	sets := map[string][]int{}
	for _, path := range paths {
		for _, extension := range extensions {
			var candidates []int
			for index, rule := range rules {
				extensionMatches := len(rule.Extensions) == 0 || extension != "" && slices.Contains(rule.Extensions, extension)
				if pathMatches(rule, path) && extensionMatches {
					candidates = append(candidates, index)
				}
			}
			for _, set := range subsets(candidates, func(index int) bool { return conditional(rules[index]) }) {
				sets[signatureOf(set)] = set
				if len(sets) > maxRoutes {
					return nil, fmt.Errorf("%w: more than %d routes", ErrInvalid, maxRoutes)
				}
			}
		}
	}
	if len(sets) > maxRoutes {
		return nil, fmt.Errorf("%w: %d routes", ErrInvalid, len(sets))
	}
	return sets, nil
}

// decide is v7's decision for a candidate set: per status the first
// candidate naming it (or naming no status) decides; "any" is the first
// candidate naming no status. Schema v1 rules always cache (cachePolicyRouteTTLs);
// schema v2 rules cache only with action cache (cachePolicyV2Route).
func decide(policy edgeconfig.CachePolicy, candidates []int, sliced bool) Route {
	v2 := policy.SchemaVersion == edgeconfig.CachePolicyDocumentSchemaV2
	pick := func(status int) (edgeconfig.CacheRule, bool) {
		for _, candidate := range candidates {
			rule := policy.Rules[candidate]
			if len(rule.StatusCodes) == 0 || status != 0 && slices.Contains(rule.StatusCodes, status) {
				return rule, true
			}
		}
		return edgeconfig.CacheRule{}, false
	}
	cacheable := func(rule edgeconfig.CacheRule, matched bool) bool {
		return matched && (!v2 || rule.Action == edgeconfig.CacheRuleActionCache)
	}
	ttls := TTLs{Status: map[int]int64{}}
	route := Route{}
	anyRule, hasAny := pick(0)
	if cacheable(anyRule, hasAny) {
		ttls.Any, route.Cache = seconds(anyRule.TTL), true
	}
	if v2 {
		route.BrowserAny, route.Browser = browserValue(anyRule, hasAny), map[string]string{}
	}
	var statuses []int
	for _, candidate := range candidates {
		for _, status := range policy.Rules[candidate].StatusCodes {
			if !slices.Contains(statuses, status) {
				statuses = append(statuses, status)
			}
		}
	}
	slices.Sort(statuses)
	for _, status := range statuses {
		rule, matched := pick(status)
		ttls.Status[status] = 0
		if cacheable(rule, matched) {
			ttls.Status[status], route.Cache = seconds(rule.TTL), true
		}
		if v2 {
			if browser := browserValue(rule, matched); browser != route.BrowserAny {
				route.Browser[strconv.Itoa(status)] = browser
			}
		}
	}
	if len(route.Browser) == 0 {
		route.Browser = nil
	}
	route.TTLs = sliceTTLs(ttls, sliced).Value()
	return route
}

func browserValue(rule edgeconfig.CacheRule, matched bool) string {
	if !matched || rule.Action != edgeconfig.CacheRuleActionCache {
		return "epoch"
	}
	if rule.BrowserTTL == 0 {
		return "off"
	}
	return strconv.FormatInt(seconds(rule.BrowserTTL), 10) + "s"
}

// MaxTTL is the longest cache time of the plan (pool inactive, ge-cache G).
func (plan *Plan) MaxTTL() time.Duration {
	var maximum int64
	for _, route := range plan.Routes {
		for _, field := range strings.Fields(route.TTLs) {
			_, value, _ := strings.Cut(field, "=")
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
				maximum = max(maximum, seconds)
			}
		}
	}
	return time.Duration(maximum) * time.Second
}

// Key is the cache key: <prefix>|<token>|<purge generation>|<host or domain>|<port>|<policy key>.
// generation is the site's purge generation (node state, decimal).
func Key(plan *Plan, generation uint64, host string, port int, policyKey string) string {
	name := plan.Domain
	if plan.KeyByHost {
		name = host
	}
	return plan.KeyPrefix + "|" + plan.Generation + "|" + strconv.FormatUint(generation, 10) + "|" + name + "|" +
		strconv.Itoa(port) + "|" + policyKey
}

// Digest is the plan's identity (the Lua caches compiled plans by it).
func (plan *Plan) Digest() string {
	raw, _ := json.Marshal(plan)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
