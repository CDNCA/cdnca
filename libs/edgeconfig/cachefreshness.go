package edgeconfig

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	CacheFreshnessSchemaVersion = "cdnca.edge.cache-freshness/v1"
	CacheFreshnessGuardPath     = "cachefreshness/guard.lua"
	CacheFreshnessGuardSHA256   = "c68cedb5df4ebcdd02984f7437af7a6bef4bf691f520042a00b8d1c9da498fb4"

	CacheFreshnessMaxPolicyBytes                   = 256 << 10
	CacheFreshnessMaxPolicyVersion                 = 1<<53 - 1
	CacheFreshnessMaxIdentifierBytes               = 128
	CacheFreshnessMaxHosts                         = 32
	CacheFreshnessMaxHostBytes                     = 253
	CacheFreshnessMaxCacheBytes              int64 = 1 << 40
	CacheFreshnessMaxCacheSeconds                  = 7 * 24 * 60 * 60
	CacheFreshnessMaxStaleSeconds                  = 60 * 60
	CacheFreshnessMinLockTimeoutMilliseconds       = 50
	CacheFreshnessMaxLockTimeoutMilliseconds       = 30_000
	CacheFreshnessMinLockAgeMilliseconds           = 100
	CacheFreshnessMaxLockAgeMilliseconds           = 60_000

	cacheFreshnessDefaultLockTimeoutMilliseconds = 5_000
	cacheFreshnessDefaultLockAgeMilliseconds     = 5_000
)

const (
	CacheFreshnessModeBaseline    CacheFreshnessMode = "baseline"
	CacheFreshnessModeEnhancement CacheFreshnessMode = "enhancement"
)

const (
	CacheFreshnessFailureUpdating      CacheFreshnessFailureClass = "updating"
	CacheFreshnessFailureError         CacheFreshnessFailureClass = "error"
	CacheFreshnessFailureTimeout       CacheFreshnessFailureClass = "timeout"
	CacheFreshnessFailureInvalidHeader CacheFreshnessFailureClass = "invalid_header"
	CacheFreshnessFailureHTTP500       CacheFreshnessFailureClass = "http_500"
	CacheFreshnessFailureHTTP502       CacheFreshnessFailureClass = "http_502"
	CacheFreshnessFailureHTTP503       CacheFreshnessFailureClass = "http_503"
	CacheFreshnessFailureHTTP504       CacheFreshnessFailureClass = "http_504"
)

var ErrInvalidCacheFreshnessPolicy = errors.New("invalid cache freshness policy")

type CacheFreshnessMode string

type CacheFreshnessFailureClass string

type CacheFreshnessPolicy struct {
	SchemaVersion        string                          `json:"schema_version"`
	PolicyVersion        uint64                          `json:"policy_version"`
	ConfigurationVersion uint64                          `json:"configuration_version"`
	TenantID             string                          `json:"tenant_id"`
	SiteID               string                          `json:"site_id"`
	Mode                 CacheFreshnessMode              `json:"mode"`
	ListenAddress        string                          `json:"listen_address"`
	ListenPort           uint16                          `json:"listen_port"`
	Hosts                []string                        `json:"hosts"`
	OriginHost           string                          `json:"origin_host"`
	OriginPort           uint16                          `json:"origin_port"`
	CacheMaxBytes        int64                           `json:"cache_max_bytes"`
	CacheInactiveSeconds uint32                          `json:"cache_inactive_seconds"`
	FreshSeconds         uint32                          `json:"fresh_seconds"`
	FollowOriginHeaders  bool                            `json:"follow_origin_headers,omitempty"`
	CacheableStatuses    []uint16                        `json:"cacheable_statuses"`
	Enhancement          CacheFreshnessEnhancementPolicy `json:"enhancement"`
}

type CacheFreshnessEnhancementPolicy struct {
	Enabled            bool                        `json:"enabled"`
	StaleWindowSeconds uint32                      `json:"stale_window_seconds,omitempty"`
	Expert             *CacheFreshnessExpertPolicy `json:"expert,omitempty"`
}

type CacheFreshnessExpertPolicy struct {
	LockTimeoutMilliseconds uint32                       `json:"lock_timeout_milliseconds,omitempty"`
	LockAgeMilliseconds     uint32                       `json:"lock_age_milliseconds,omitempty"`
	BackgroundUpdate        *bool                        `json:"background_update,omitempty"`
	Revalidation            *bool                        `json:"revalidation,omitempty"`
	FailureClasses          []CacheFreshnessFailureClass `json:"failure_classes,omitempty"`
}

//go:embed cachefreshness/guard.lua
var cacheFreshnessGuard []byte

func NormalizeCacheFreshnessPolicy(input CacheFreshnessPolicy) (CacheFreshnessPolicy, error) {
	if input.SchemaVersion != CacheFreshnessSchemaVersion {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("schema_version must be %q", CacheFreshnessSchemaVersion)
	}
	if input.PolicyVersion == 0 || input.PolicyVersion > CacheFreshnessMaxPolicyVersion {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("policy_version is out of range")
	}
	if input.ConfigurationVersion == 0 || input.ConfigurationVersion > CacheFreshnessMaxPolicyVersion {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("configuration_version is out of range")
	}
	if !validCacheFreshnessIdentifier(input.TenantID) || !validCacheFreshnessIdentifier(input.SiteID) {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("tenant_id and site_id are invalid")
	}
	if input.Mode != CacheFreshnessModeBaseline && input.Mode != CacheFreshnessModeEnhancement {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("mode is invalid")
	}
	if input.Mode == CacheFreshnessModeBaseline && input.Enhancement.Enabled {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("baseline mode cannot enable enhancement")
	}
	address, err := netip.ParseAddr(input.ListenAddress)
	if err != nil || address.Is4In6() || input.ListenPort == 0 {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("listen address or port is invalid")
	}
	origin, err := normalizeCacheFreshnessHost(input.OriginHost, true)
	if err != nil || input.OriginPort == 0 {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("origin host or port is invalid")
	}
	if len(input.Hosts) == 0 || len(input.Hosts) > CacheFreshnessMaxHosts {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("host count is invalid")
	}
	hosts := make([]string, 0, len(input.Hosts))
	seenHosts := make(map[string]struct{}, len(input.Hosts))
	for _, value := range input.Hosts {
		host, hostErr := normalizeCacheFreshnessHost(value, false)
		if hostErr != nil {
			return CacheFreshnessPolicy{}, invalidCacheFreshness("host %q is invalid", value)
		}
		if _, exists := seenHosts[host]; exists {
			return CacheFreshnessPolicy{}, invalidCacheFreshness("host %q is duplicated", host)
		}
		seenHosts[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	if input.CacheMaxBytes <= 0 || input.CacheMaxBytes > CacheFreshnessMaxCacheBytes ||
		input.CacheInactiveSeconds == 0 || input.CacheInactiveSeconds > CacheFreshnessMaxCacheSeconds ||
		input.FreshSeconds == 0 || input.FreshSeconds > CacheFreshnessMaxCacheSeconds ||
		len(input.CacheableStatuses) != 1 || input.CacheableStatuses[0] != 200 {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("cache bounds or statuses are invalid")
	}

	result := input
	result.ListenAddress = address.String()
	result.OriginHost = origin
	result.Hosts = hosts
	result.CacheableStatuses = []uint16{200}
	if !input.Enhancement.Enabled {
		result.Enhancement = CacheFreshnessEnhancementPolicy{Enabled: false}
		return result, nil
	}
	if input.Mode != CacheFreshnessModeEnhancement || input.Enhancement.StaleWindowSeconds == 0 ||
		input.Enhancement.StaleWindowSeconds > CacheFreshnessMaxStaleSeconds {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("enabled enhancement or stale window is invalid")
	}
	expert, err := normalizeCacheFreshnessExpert(input.Enhancement.Expert)
	if err != nil {
		return CacheFreshnessPolicy{}, err
	}
	result.Enhancement.Expert = &expert
	return result, nil
}

func CanonicalCacheFreshnessPolicy(input CacheFreshnessPolicy) ([]byte, error) {
	normalized, err := NormalizeCacheFreshnessPolicy(input)
	if err != nil {
		return nil, err
	}
	content, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical cache freshness policy: %w", err)
	}
	return append(content, '\n'), nil
}

func DecodeCacheFreshnessPolicy(content []byte) (CacheFreshnessPolicy, error) {
	if len(content) == 0 || len(content) > CacheFreshnessMaxPolicyBytes {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("policy size is invalid")
	}
	if err := RejectDuplicateJSONKeys(content); err != nil {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("policy JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var policy CacheFreshnessPolicy
	if err := decoder.Decode(&policy); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return CacheFreshnessPolicy{}, invalidCacheFreshness("policy JSON is invalid")
	}
	return NormalizeCacheFreshnessPolicy(policy)
}

func ValidateBundle(bundle Bundle) error {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return validateBundleWithBudget(bundle, &budget)
}

func validateBundleWithBudget(bundle Bundle, budget *cacheFreshnessLuaBudget) error {
	cacheFreshnessTrustTelemetryLuaBodies(bundle, budget)
	manifest, err := normalizeManifest(bundle.Manifest)
	if err != nil {
		return err
	}
	if bundle.ManifestSHA256 == "" || len(bundle.Files) == 0 {
		return fmt.Errorf("%w: bundle is incomplete", ErrInvalidBundle)
	}
	if err := validateBundleFiles(manifest, bundle.Files); err != nil {
		return err
	}
	if err := ValidateCCV2Bundle(bundle); err != nil {
		return err
	}
	if err := validateCacheFreshnessBundleWithBudget(bundle, budget); err != nil {
		return err
	}
	if err := validateCachePolicyBundleWithBudget(bundle, budget); err != nil {
		return err
	}
	return ValidateRangeCacheBundle(bundle)
}

func ValidateCacheFreshnessBundle(bundle Bundle) error {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return validateCacheFreshnessBundleWithBudget(bundle, &budget)
}

func validateCacheFreshnessBundleWithBudget(bundle Bundle, budget *cacheFreshnessLuaBudget) error {
	cacheFreshnessTrustTelemetryLuaBodies(bundle, budget)
	nginx := bundle.Files["nginx.conf"]
	policyCount := 0
	policies := make([]cacheFreshnessBundlePolicy, 0)
	for path, content := range bundle.Files {
		if !strings.HasPrefix(path, "cachefreshness/") || path == CacheFreshnessGuardPath {
			continue
		}
		siteIndex, validPath := cacheFreshnessSiteIndex(path)
		if !validPath {
			return fmt.Errorf("%w: unexpected cache freshness file %q", ErrInvalidBundle, path)
		}
		policy, decodeErr := DecodeCacheFreshnessPolicy(content)
		if decodeErr != nil {
			return fmt.Errorf("%w: invalid cache freshness policy", ErrInvalidBundle)
		}
		canonical, canonicalErr := CanonicalCacheFreshnessPolicy(policy)
		if canonicalErr != nil || !bytes.Equal(canonical, content) || !policy.Enhancement.Enabled {
			return fmt.Errorf("%w: cache freshness policy is not canonical and enabled", ErrInvalidBundle)
		}
		policyCount++
		policies = append(policies, cacheFreshnessBundlePolicy{siteIndex: siteIndex, policy: policy})
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].siteIndex < policies[j].siteIndex })
	if policyCount > 0 {
		manifest, manifestErr := ParseCachePolicyManifest(bundle.Files[CachePolicyManifestPath])
		if manifestErr != nil {
			return fmt.Errorf("%w: cache freshness policy binding is invalid", ErrInvalidBundle)
		}
		for _, bound := range policies {
			if !cacheFreshnessManifestIdentity(manifest, bound) {
				return fmt.Errorf("%w: cache freshness policy binding is invalid", ErrInvalidBundle)
			}
		}
	}
	if !budget.ensureSiteCapacity(policyCount) {
		return fmt.Errorf("%w: cache freshness Lua work is invalid", ErrInvalidBundle)
	}
	hasInit, hasInitWorker, runtimeHooks, validLua := structuredCacheFreshnessInitWithBudget(nginx, budget)
	hasRuntime := hasInit && hasInitWorker && runtimeHooks > 0
	guard, hasGuard := bundle.Files[CacheFreshnessGuardPath]
	_, hasCachePolicyManifest := bundle.Files[CachePolicyManifestPath]
	if validLua && hasCachePolicyManifest && !cacheFreshnessLuaIdentityWorkWithinBudget(nginx, budget) {
		validLua = false
	}
	if !validLua && (policyCount != 0 || hasGuard || hasCachePolicyManifest) {
		return fmt.Errorf("%w: cache freshness Lua work is invalid", ErrInvalidBundle)
	}
	if !hasInit && !hasInitWorker && runtimeHooks == 0 && policyCount == 0 && !hasGuard {
		return nil
	}
	if !hasRuntime || policyCount != runtimeHooks || !hasGuard ||
		cacheFreshnessGuardSHA256(guard) != CacheFreshnessGuardSHA256 ||
		!validateCacheFreshnessRequestHooks(nginx, policies, bundle.Files[CachePolicyManifestPath], budget) {
		return fmt.Errorf("%w: cache freshness runtime is incomplete", ErrInvalidBundle)
	}
	return nil
}

type cacheFreshnessBundlePolicy struct {
	siteIndex int
	policy    CacheFreshnessPolicy
}

func cacheFreshnessLuaIdentityWorkWithinBudget(nginx []byte, budget *cacheFreshnessLuaBudget) bool {
	document, ok := parseNginxDirectives(string(nginx))
	if !ok {
		return false
	}
	blockIDs := make([]int, 0, len(document.opaqueBodies))
	for blockID := range document.opaqueBodies {
		blockIDs = append(blockIDs, blockID)
	}
	sort.Ints(blockIDs)
	for _, blockID := range blockIDs {
		if _, valid := cacheFreshnessLuaIdentityAssignmentScanWithBudget(
			document.opaqueBodies[blockID], budget); !valid {
			return false
		}
	}
	return true
}

func validateCacheFreshnessRequestHooks(nginx []byte, policies []cacheFreshnessBundlePolicy,
	manifestContent []byte, budget *cacheFreshnessLuaBudget) bool {
	document, ok := parseNginxDirectives(string(nginx))
	if !ok || document.hasInclude {
		return false
	}
	httpBlocks := document.blockIDs(0, []string{"http"})
	if len(httpBlocks) != 1 {
		return false
	}
	manifest, manifestErr := ParseCachePolicyManifest(manifestContent)
	manifestValid := manifestErr == nil && manifest.NginxSHA256 == digestHex(nginx)
	for _, bound := range policies {
		policy := bound.policy
		if len(policy.Hosts) != 1 {
			return false
		}
		server, found := uniquePublicNginxServer(document, httpBlocks[0], policy.Hosts[0], policy.ListenPort)
		if !found {
			return false
		}
		matches := 0
		publicLocation, found := uniqueNginxBlock(document, server, []string{"location", "/"})
		if !found {
			return false
		}
		for _, hook := range document.blockNamed(publicLocation, "rewrite_by_lua_block") {
			if cacheFreshnessRequestBodyWithBudget(document.opaqueBodies[hook.blockID], policy, false, budget) &&
				cacheFreshnessIdentitySetWithBudget(document, server, publicLocation, policy, budget) {
				matches++
			}
		}
		routeName := cachePolicyRouteName(bound.siteIndex-1, false, 0)
		if location, found := uniqueNginxBlock(document, server, []string{"location", routeName}); found {
			for _, hook := range document.blockNamed(location, "access_by_lua_block") {
				allowedLuaBlocks, allowed := cacheFreshnessPolicyLuaBlocks(document, server, manifest, bound, policy, budget)
				if cacheFreshnessRequestBodyWithBudget(document.opaqueBodies[hook.blockID], policy, true, budget) && manifestValid &&
					cacheFreshnessManifestIdentity(manifest, bound) &&
					allowed && cacheFreshnessPolicyIdentitySetWithBudget(document, server, publicLocation, policy,
					allowedLuaBlocks, budget) {
					matches++
				}
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

func cacheFreshnessIdentitySet(document *nginxDocument, server, location int, policy CacheFreshnessPolicy) bool {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return cacheFreshnessIdentitySetWithBudget(document, server, location, policy, &budget)
}

func cacheFreshnessIdentitySetWithBudget(document *nginxDocument, server, location int,
	policy CacheFreshnessPolicy, budget *cacheFreshnessLuaBudget) bool {
	return cacheFreshnessIdentityWriters(document, server, location, policy, nil, budget)
}

func cacheFreshnessPolicyIdentitySet(document *nginxDocument, server, location int, policy CacheFreshnessPolicy,
	allowedLuaBlocks map[int]struct{}) bool {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return cacheFreshnessPolicyIdentitySetWithBudget(document, server, location, policy, allowedLuaBlocks, &budget)
}

func cacheFreshnessPolicyIdentitySetWithBudget(document *nginxDocument, server, location int,
	policy CacheFreshnessPolicy, allowedLuaBlocks map[int]struct{}, budget *cacheFreshnessLuaBudget) bool {
	return cacheFreshnessIdentityWriters(document, server, location, policy, allowedLuaBlocks, budget)
}

func cacheFreshnessIdentityWriters(document *nginxDocument, server, location int, policy CacheFreshnessPolicy,
	allowedLuaBlocks map[int]struct{}, budget *cacheFreshnessLuaBudget) bool {
	policyAware := allowedLuaBlocks != nil
	identity := cacheFreshnessIdentity(policy)
	if policyAware {
		identity = ""
	}
	want := []string{"set", "$cache_freshness_identity", identity}
	matches := 0
	blocks := []int{server}
	for len(blocks) > 0 {
		block := blocks[len(blocks)-1]
		blocks = blocks[:len(blocks)-1]
		for name, directives := range document.direct[block] {
			for _, directive := range directives {
				if len(directive.fields) < 2 || directive.fields[1] != "$cache_freshness_identity" {
					continue
				}
				if name != "set" || block != location || !equalNginxFields(directive.fields, want) {
					return false
				}
				matches++
			}
		}
		for name, directives := range document.blockNames[block] {
			for _, directive := range directives {
				if strings.HasPrefix(name, "set_by_lua") && len(directive.fields) >= 2 &&
					directive.fields[1] == "$cache_freshness_identity" {
					return false
				}
				body, opaque := document.opaqueBodies[directive.blockID]
				writes, valid := cacheFreshnessLuaIdentityAssignmentScanWithBudget(body, budget)
				if opaque && !valid {
					return false
				}
				if opaque && writes {
					if _, allowed := allowedLuaBlocks[directive.blockID]; !allowed {
						return false
					}
				}
				blocks = append(blocks, directive.blockID)
			}
		}
	}
	return matches == 1
}

func cacheFreshnessPolicyLuaBlocks(document *nginxDocument, server int, manifest CachePolicyManifest,
	bound cacheFreshnessBundlePolicy, policy CacheFreshnessPolicy,
	budget *cacheFreshnessLuaBudget) (map[int]struct{}, bool) {
	if bound.siteIndex < 1 || bound.siteIndex > len(manifest.Listeners) {
		return nil, false
	}
	plan, err := buildCachePolicyPlan(cachePolicyDocumentRuntime(manifest.Listeners[bound.siteIndex-1].Policy))
	if err != nil {
		return nil, false
	}
	allowed := make(map[int]struct{}, len(plan.Routes)+1)
	for routeIndex := 0; routeIndex <= len(plan.Routes); routeIndex++ {
		location, found := uniqueNginxBlock(document, server,
			[]string{"location", cachePolicyRouteName(bound.siteIndex-1, false, routeIndex)})
		if !found {
			return nil, false
		}
		hooks := document.blockNamed(location, "access_by_lua_block")
		if len(hooks) != 1 {
			return nil, false
		}
		body := document.opaqueBodies[hooks[0].blockID]
		var valid bool
		if routeIndex == 0 {
			valid = cacheFreshnessRequestBodyWithBudget(body, policy, true, budget)
		} else {
			valid = cacheFreshnessLuaBodyWithinBudget(body, budget) &&
				cacheFreshnessAliasRequestBody(body, policy)
		}
		if !valid {
			return nil, false
		}
		allowed[hooks[0].blockID] = struct{}{}
	}
	return allowed, true
}

func cacheFreshnessAliasRequestBody(body string, policy CacheFreshnessPolicy) bool {
	statement := cacheFreshnessRequestStatement(policy, true)
	statement = strings.Replace(statement, `require("cachefreshness.guard").access`,
		`cache_freshness_guard.access`, 1)
	lines := strings.Split(strings.TrimSpace(body), "\n")
	return len(lines) == 3 &&
		strings.TrimSpace(lines[0]) == "ngx.var.cache_freshness_identity = ngx.var.cdnca_cache_policy_key" &&
		strings.TrimSpace(lines[1]) == `local cache_freshness_guard = require("cachefreshness.guard")` &&
		strings.TrimSpace(lines[2]) == statement
}

func cacheFreshnessLuaIdentityAssignment(body string) bool {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return cacheFreshnessLuaIdentityAssignmentWithBudget(body, &budget)
}

func cacheFreshnessLuaIdentityAssignmentWithBudget(body string, budget *cacheFreshnessLuaBudget) bool {
	writes, valid := cacheFreshnessLuaIdentityAssignmentScanWithBudget(body, budget)
	return !valid || writes
}

var (
	challengeInitLoadPattern = regexp.MustCompile(
		`^local chunk_([0-9]{4}), load_error_([0-9]{4}) = loadfile\("/usr/local/share/cdnca/challenge/engine\.lua"\)$`)
	challengeInitPolicyPattern = regexp.MustCompile(
		`^module_([0-9]{4})\.init\(\{ policy_path = "/[A-Za-z0-9/._-]+/challenge/policies/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/versions/[0-9]{20}\.json", state_dict = "cdnca_challenge_state" \}\)$`)
)

// withoutCanonicalChallengeInit blanks every exact renderChallengeInit group
// (per-site loadfile of the node-installed challenge engine, init with its
// policy file, package.loaded registration under its own site module name).
// The identity scan treats loadfile and package.loaded writes as possible
// cache identity writers; this fixed template only loads the installed
// engine, which never touches cache_freshness variables. Anything else on
// those lines, or any partial or reindexed group, is left for the scan.
func withoutCanonicalChallengeInit(body string) string {
	if !strings.Contains(body, "/usr/local/share/cdnca/challenge/engine.lua") {
		return body
	}
	lines := strings.Split(body, "\n")
	for index := 0; index+6 <= len(lines); index++ {
		match := challengeInitLoadPattern.FindStringSubmatch(strings.TrimSpace(lines[index]))
		if match == nil || match[1] != match[2] {
			continue
		}
		number := match[1]
		policy := challengeInitPolicyPattern.FindStringSubmatch(strings.TrimSpace(lines[index+4]))
		if policy == nil || policy[1] != number ||
			strings.TrimSpace(lines[index+1]) != "if not chunk_"+number+" then error(load_error_"+number+") end" ||
			strings.TrimSpace(lines[index+2]) != "local module_"+number+" = chunk_"+number+"()" ||
			strings.TrimSpace(lines[index+3]) != `if type(module_`+number+`) ~= "table" or type(module_`+number+
				`.init) ~= "function" then error("invalid challenge module") end` ||
			strings.TrimSpace(lines[index+5]) != `package.loaded["cdnca_challenge_site_`+number+`"] = module_`+number {
			continue
		}
		for offset := 0; offset < 6; offset++ {
			lines[index+offset] = ""
		}
		index += 5
	}
	return strings.Join(lines, "\n")
}

// splitChallengeInitTail separates the canonical challenge init groups the
// renderer appends to the end of init_by_lua_block from the head that the
// other init contracts (CC v2 registry, cache freshness guard, URL auth)
// match exactly. ok is false when challenge init text is anything but such a
// trailing run of canonical groups.
func splitChallengeInitTail(body string) (head, tail string, ok bool) {
	stripped := withoutCanonicalChallengeInit(body)
	if stripped == body {
		return body, "", true
	}
	head = strings.TrimRight(stripped, " \t\r\n")
	if !strings.HasPrefix(body, head) || strings.TrimSpace(withoutCanonicalChallengeInit(body[len(head):])) != "" {
		return "", "", false
	}
	return head, body[len(head):], true
}

func cacheFreshnessLuaIdentityAssignmentScanWithBudget(body string,
	budget *cacheFreshnessLuaBudget) (bool, bool) {
	body = withoutCanonicalChallengeInit(body)
	tokens, ok := cacheFreshnessLuaTokens(body)
	if !ok {
		return false, false
	}
	if trusted, valid := cacheFreshnessTrustedLuaBodyWithinBudget(body, tokens, budget); trusted {
		return false, valid
	}
	if !cacheFreshnessLuaWithinBudgetWithBudget(tokens, budget) {
		return false, false
	}
	aliases := cacheFreshnessLuaVarAliases(tokens)
	if cacheFreshnessLuaDynamicExecution(tokens, aliases) {
		return true, true
	}
	for index, token := range tokens {
		if token.kind != cacheFreshnessLuaName &&
			!cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "(") {
			continue
		}
		if cacheFreshnessLuaOpaqueProtectedSource(tokens, index, aliases) {
			return true, true
		}
		if after, target := cacheFreshnessLuaIdentityTarget(tokens, index, aliases); target {
			next := cacheFreshnessLuaNext(tokens, after)
			previous := cacheFreshnessLuaPrevious(tokens, index-1)
			if cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, "=") ||
				!cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, "=") &&
					cacheFreshnessLuaAssignmentFollows(tokens, after) {
				return true, true
			}
		}
	}
	return false, true
}

func cacheFreshnessLuaIdentityReference(body string) bool {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return cacheFreshnessLuaIdentityReferenceWithBudget(body, &budget)
}

func cacheFreshnessLuaIdentityReferenceWithBudget(body string, budget *cacheFreshnessLuaBudget) bool {
	tokens, ok := cacheFreshnessLuaTokens(body)
	if !ok {
		return true
	}
	if trusted, valid := cacheFreshnessTrustedLuaBodyWithinBudget(body, tokens, budget); trusted {
		return !valid
	}
	if !cacheFreshnessLuaWithinBudgetWithBudget(tokens, budget) {
		return true
	}
	aliases := cacheFreshnessLuaVarAliases(tokens)
	if cacheFreshnessLuaDynamicExecution(tokens, aliases) {
		return true
	}
	for index := range tokens {
		if tokens[index].kind != cacheFreshnessLuaName &&
			!cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "(") {
			continue
		}
		if cacheFreshnessLuaOpaqueProtectedSource(tokens, index, aliases) {
			return true
		}
		if _, target := cacheFreshnessLuaIdentityTarget(tokens, index, aliases); target {
			return true
		}
	}
	return false
}

type cacheFreshnessLuaTokenKind uint8

const (
	cacheFreshnessLuaName cacheFreshnessLuaTokenKind = iota
	cacheFreshnessLuaString
	cacheFreshnessLuaSymbol
	cacheFreshnessLuaNewline
)

const (
	cacheFreshnessLuaMaxNesting = 32
	cacheFreshnessLuaMaxWork    = 131_072
	cacheFreshnessLuaSiteWork   = 32_768
)

type cacheFreshnessLuaToken struct {
	kind    cacheFreshnessLuaTokenKind
	value   string
	escaped bool
}

type cacheFreshnessLuaBudget struct {
	remaining         int
	siteCapacity      int
	trustedLinearBody map[string]struct{}
}

func (budget *cacheFreshnessLuaBudget) ensureSiteCapacity(siteCount int) bool {
	if budget == nil || siteCount < 0 || siteCount > 1000 {
		return false
	}
	accounted := max(budget.siteCapacity, 1)
	if siteCount > accounted {
		extra := (siteCount - accounted) * cacheFreshnessLuaSiteWork
		if extra < 0 || budget.remaining > int(^uint(0)>>1)-extra {
			return false
		}
		budget.remaining += extra
	}
	if siteCount > budget.siteCapacity {
		budget.siteCapacity = siteCount
	}
	return true
}

func cacheFreshnessTrustTelemetryLuaBodies(bundle Bundle, budget *cacheFreshnessLuaBudget) {
	if budget == nil || budget.trustedLinearBody != nil {
		return
	}
	manifest, err := ParseTelemetryIdentityManifest(bundle.Files[TelemetryIdentityManifestPath])
	if err != nil {
		return
	}
	trusted := make(map[string]struct{})
	for _, site := range manifest.CapturePolicy.Sites {
		if !site.Enabled {
			continue
		}
		policy := TelemetryCapturePolicy{
			SchemaVersion:              telemetryCaptureSchemaVersion,
			Enabled:                    true,
			RequestHeaderAllowlist:     append([]string(nil), site.RequestHeaderAllowlist...),
			ResponseHeaderAllowlist:    append([]string(nil), site.ResponseHeaderAllowlist...),
			RequestBodyFieldAllowlist:  append([]string(nil), site.RequestBodyFieldAllowlist...),
			ResponseBodyFieldAllowlist: append([]string(nil), site.ResponseBodyFieldAllowlist...),
			MaxValueBytes:              site.MaxValueBytes,
			MaxBodyBytes:               site.MaxBodyBytes,
			MaxEventBytes:              site.MaxEventBytes,
		}
		var rendered strings.Builder
		rendered.WriteString("http { server { location / {\n")
		renderTelemetryCapture(&rendered, policy)
		rendered.WriteString("} } }\n")
		document, ok := parseNginxDirectives(rendered.String())
		if !ok {
			return
		}
		for _, body := range document.opaqueBodies {
			trusted[body] = struct{}{}
		}
	}
	if len(trusted) != 0 {
		budget.trustedLinearBody = trusted
	}
}

func cacheFreshnessTrustedLuaBodyWithinBudget(body string, tokens []cacheFreshnessLuaToken,
	budget *cacheFreshnessLuaBudget) (bool, bool) {
	if budget == nil || budget.trustedLinearBody == nil {
		return false, false
	}
	if _, trusted := budget.trustedLinearBody[body]; !trusted {
		return false, false
	}
	if budget.remaining < 0 || len(tokens) > budget.remaining {
		return true, false
	}
	budget.remaining -= len(tokens)
	return true, true
}

func cacheFreshnessLuaTokens(body string) ([]cacheFreshnessLuaToken, bool) {
	tokens := make([]cacheFreshnessLuaToken, 0, 32)
	add := func(token cacheFreshnessLuaToken) bool {
		if len(tokens) >= maxNginxTokens {
			return false
		}
		tokens = append(tokens, token)
		return true
	}
	for index := 0; index < len(body); {
		switch body[index] {
		case ' ', '\t', '\f', '\v':
			index++
		case '\r', '\n':
			if body[index] == '\r' && index+1 < len(body) && body[index+1] == '\n' {
				index++
			}
			index++
			if !add(cacheFreshnessLuaToken{kind: cacheFreshnessLuaNewline}) {
				return nil, false
			}
		case '\'', '"':
			quote := body[index]
			index++
			value, next, escaped, valid := cacheFreshnessLuaQuotedString(body, index, quote)
			if !valid || !add(cacheFreshnessLuaToken{kind: cacheFreshnessLuaString,
				value: value, escaped: escaped}) {
				return nil, false
			}
			index = next
		case '-':
			if index+1 >= len(body) || body[index+1] != '-' {
				if !add(cacheFreshnessLuaToken{kind: cacheFreshnessLuaSymbol, value: "-"}) {
					return nil, false
				}
				index++
				continue
			}
			if closing, bodyStart, long := luaLongBracket(body, index+2); long {
				closingAt := strings.Index(body[bodyStart:], closing)
				if closingAt < 0 {
					return nil, false
				}
				comment := body[bodyStart : bodyStart+closingAt]
				index = bodyStart + closingAt + len(closing)
				if strings.ContainsAny(comment, "\r\n") &&
					!add(cacheFreshnessLuaToken{kind: cacheFreshnessLuaNewline}) {
					return nil, false
				}
				continue
			}
			index += 2
			for index < len(body) && body[index] != '\r' && body[index] != '\n' {
				index++
			}
		case '[':
			closing, bodyStart, long := luaLongBracket(body, index)
			if !long {
				if !add(cacheFreshnessLuaToken{kind: cacheFreshnessLuaSymbol, value: "["}) {
					return nil, false
				}
				index++
				continue
			}
			closingAt := strings.Index(body[bodyStart:], closing)
			if closingAt < 0 {
				return nil, false
			}
			value := body[bodyStart : bodyStart+closingAt]
			if strings.HasPrefix(value, "\r\n") {
				value = value[2:]
			} else if strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") {
				value = value[1:]
			}
			if !add(cacheFreshnessLuaToken{kind: cacheFreshnessLuaString, value: value}) {
				return nil, false
			}
			index = bodyStart + closingAt + len(closing)
		default:
			if cacheFreshnessLuaIdentifier(body[index]) && !(body[index] >= '0' && body[index] <= '9') {
				start := index
				for index < len(body) && cacheFreshnessLuaIdentifier(body[index]) {
					index++
				}
				if !add(cacheFreshnessLuaToken{kind: cacheFreshnessLuaName, value: body[start:index]}) {
					return nil, false
				}
				continue
			}
			value := body[index : index+1]
			if index+1 < len(body) {
				pair := body[index : index+2]
				switch pair {
				case "==", "~=", "<=", ">=", "::", "..", "//", "<<", ">>":
					value = pair
					index++
				}
			}
			if !add(cacheFreshnessLuaToken{kind: cacheFreshnessLuaSymbol, value: value}) {
				return nil, false
			}
			index++
		}
	}
	return tokens, true
}

func cacheFreshnessLuaWithinBudget(tokens []cacheFreshnessLuaToken) bool {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return cacheFreshnessLuaWithinBudgetWithBudget(tokens, &budget)
}

func cacheFreshnessLuaWithinBudgetWithBudget(tokens []cacheFreshnessLuaToken,
	budget *cacheFreshnessLuaBudget) bool {
	if budget == nil || budget.remaining < 0 || len(tokens) > budget.remaining {
		return false
	}
	work := len(tokens)
	statementStart, assignments, protected := 0, 0, 0
	parentheses, braces, brackets, blocks := 0, 0, 0, 0
	addWork := func(value int) bool {
		if value < 0 || work > budget.remaining-value {
			return false
		}
		work += value
		return true
	}
	finishStatement := func(end int) bool {
		span := end - statementStart
		multiplier := assignments*2 + protected
		if multiplier != 0 && (span > cacheFreshnessLuaMaxWork ||
			!addWork(span*multiplier)) {
			return false
		}
		statementStart, assignments, protected = end, 0, 0
		return true
	}
	for index, token := range tokens {
		if token.kind == cacheFreshnessLuaName {
			switch token.value {
			case "function", "if", "do", "repeat":
				blocks++
			case "end", "until":
				blocks--
			case "cache_freshness_identity":
				protected++
			}
		}
		if token.kind == cacheFreshnessLuaSymbol {
			switch token.value {
			case "(":
				parentheses++
			case ")":
				parentheses--
			case "{":
				braces++
			case "}":
				braces--
			case "[":
				brackets++
			case "]":
				brackets--
			case "=":
				assignments++
			}
		}
		nesting := parentheses + braces + brackets + blocks
		if parentheses < 0 || braces < 0 || brackets < 0 || blocks < 0 ||
			nesting > cacheFreshnessLuaMaxNesting || !addWork(nesting) {
			return false
		}
		boundary := token.kind == cacheFreshnessLuaNewline ||
			cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, ";")
		if boundary && nesting == 0 && !finishStatement(index+1) {
			return false
		}
	}
	if parentheses != 0 || braces != 0 || brackets != 0 || blocks != 0 ||
		!finishStatement(len(tokens)) {
		return false
	}
	budget.remaining -= work
	return true
}

func cacheFreshnessLuaQuotedString(body string, index int, quote byte) (string, int, bool, bool) {
	value := make([]byte, 0, len(body)-index)
	escaped := false
	for index < len(body) {
		current := body[index]
		if current == quote {
			return string(value), index + 1, escaped, true
		}
		if current == '\r' || current == '\n' {
			return "", index, escaped, false
		}
		if current != '\\' {
			value = append(value, current)
			index++
			continue
		}

		escaped = true
		index++
		if index >= len(body) {
			return "", index, escaped, false
		}
		current = body[index]
		switch current {
		case 'a':
			value = append(value, '\a')
			index++
		case 'b':
			value = append(value, '\b')
			index++
		case 'f':
			value = append(value, '\f')
			index++
		case 'n':
			value = append(value, '\n')
			index++
		case 'r':
			value = append(value, '\r')
			index++
		case 't':
			value = append(value, '\t')
			index++
		case 'v':
			value = append(value, '\v')
			index++
		case '\\', '\'', '"':
			value = append(value, current)
			index++
		case '\r', '\n':
			if current == '\r' && index+1 < len(body) && body[index+1] == '\n' {
				index++
			}
			value = append(value, '\n')
			index++
		case 'z':
			index++
			for index < len(body) && strings.ContainsRune(" \t\r\n\v\f", rune(body[index])) {
				index++
			}
		case 'x':
			if index+2 >= len(body) {
				return "", index, escaped, false
			}
			decoded, err := strconv.ParseUint(body[index+1:index+3], 16, 8)
			if err != nil {
				return "", index, escaped, false
			}
			value = append(value, byte(decoded))
			index += 3
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			start := index
			for index < len(body) && index-start < 3 && body[index] >= '0' && body[index] <= '9' {
				index++
			}
			decoded, err := strconv.ParseUint(body[start:index], 10, 8)
			if err != nil {
				return "", index, escaped, false
			}
			value = append(value, byte(decoded))
		default:
			return "", index, escaped, false
		}
	}
	return "", index, escaped, false
}

type cacheFreshnessLuaAliasKind uint8

const (
	cacheFreshnessLuaGlobalAlias cacheFreshnessLuaAliasKind = 1 << iota
	cacheFreshnessLuaRootAlias
	cacheFreshnessLuaVarAlias
	cacheFreshnessLuaDebugAlias
	cacheFreshnessLuaPackageAlias
	cacheFreshnessLuaLoadedAlias
	cacheFreshnessLuaRegistryAlias
	cacheFreshnessLuaOpaqueAlias
)

type cacheFreshnessLuaAliases struct {
	globals    map[string]struct{}
	roots      map[string]struct{}
	vars       map[string]struct{}
	debugs     map[string]struct{}
	packages   map[string]struct{}
	loaded     map[string]struct{}
	registries map[string]struct{}
	opaques    map[string]struct{}
	targets    map[int]struct{}
	exact      map[cacheFreshnessLuaSpan]struct{}
}

type cacheFreshnessLuaSpan struct {
	start int
	end   int
}

type cacheFreshnessLuaAssignmentName struct {
	name  string
	index int
}

type cacheFreshnessLuaAliasNode struct {
	name string
	kind cacheFreshnessLuaAliasKind
}

type cacheFreshnessLuaAliasSource struct {
	direct      cacheFreshnessLuaAliasKind
	dependency  string
	projections []cacheFreshnessLuaAliasProjection
}

type cacheFreshnessLuaAliasProjection struct {
	from cacheFreshnessLuaAliasKind
	to   cacheFreshnessLuaAliasKind
}

func cacheFreshnessLuaVarAliases(tokens []cacheFreshnessLuaToken) cacheFreshnessLuaAliases {
	aliases := cacheFreshnessLuaAliases{
		globals: make(map[string]struct{}), roots: make(map[string]struct{}), vars: make(map[string]struct{}),
		debugs: make(map[string]struct{}), packages: make(map[string]struct{}), loaded: make(map[string]struct{}),
		registries: make(map[string]struct{}), opaques: make(map[string]struct{}), targets: make(map[int]struct{}),
		exact: make(map[cacheFreshnessLuaSpan]struct{}),
	}
	edges := make(map[cacheFreshnessLuaAliasNode][]cacheFreshnessLuaAliasNode)
	queue := make([]cacheFreshnessLuaAliasNode, 0)
	add := func(node cacheFreshnessLuaAliasNode) {
		facts := aliases.globals
		switch node.kind {
		case cacheFreshnessLuaRootAlias:
			facts = aliases.roots
		case cacheFreshnessLuaVarAlias:
			facts = aliases.vars
		case cacheFreshnessLuaDebugAlias:
			facts = aliases.debugs
		case cacheFreshnessLuaPackageAlias:
			facts = aliases.packages
		case cacheFreshnessLuaLoadedAlias:
			facts = aliases.loaded
		case cacheFreshnessLuaRegistryAlias:
			facts = aliases.registries
		case cacheFreshnessLuaOpaqueAlias:
			facts = aliases.opaques
		}
		if _, exists := facts[node.name]; exists {
			return
		}
		facts[node.name] = struct{}{}
		queue = append(queue, node)
	}
	for equal, token := range tokens {
		if token.kind != cacheFreshnessLuaSymbol || token.value != "=" {
			continue
		}
		names := cacheFreshnessLuaAssignmentNames(tokens, equal)
		for _, name := range names {
			if name.index >= 0 {
				aliases.targets[name.index] = struct{}{}
			}
		}
		right := cacheFreshnessLuaNext(tokens, equal+1)
		for index, name := range names {
			end := cacheFreshnessLuaAliasValueEnd(tokens, right)
			after, source, matched := cacheFreshnessLuaAliasSourceExpression(tokens, right)
			exact := matched && after == end && name.name != ""
			if exact {
				aliases.exact[cacheFreshnessLuaSpan{start: right, end: end}] = struct{}{}
			}
			if exact && source.direct != 0 {
				for _, kind := range []cacheFreshnessLuaAliasKind{
					cacheFreshnessLuaGlobalAlias, cacheFreshnessLuaRootAlias,
					cacheFreshnessLuaVarAlias, cacheFreshnessLuaDebugAlias,
					cacheFreshnessLuaPackageAlias, cacheFreshnessLuaLoadedAlias,
					cacheFreshnessLuaRegistryAlias, cacheFreshnessLuaOpaqueAlias,
				} {
					if source.direct&kind != 0 {
						add(cacheFreshnessLuaAliasNode{name: name.name, kind: kind})
					}
				}
			} else if exact && len(source.projections) != 0 {
				for _, projection := range source.projections {
					from := cacheFreshnessLuaAliasNode{name: source.dependency, kind: projection.from}
					edges[from] = append(edges[from], cacheFreshnessLuaAliasNode{name: name.name, kind: projection.to})
				}
			} else if exact {
				for _, kind := range []cacheFreshnessLuaAliasKind{
					cacheFreshnessLuaGlobalAlias, cacheFreshnessLuaRootAlias,
					cacheFreshnessLuaVarAlias, cacheFreshnessLuaDebugAlias,
					cacheFreshnessLuaPackageAlias, cacheFreshnessLuaLoadedAlias,
					cacheFreshnessLuaRegistryAlias, cacheFreshnessLuaOpaqueAlias,
				} {
					from := cacheFreshnessLuaAliasNode{name: source.dependency, kind: kind}
					edges[from] = append(edges[from], cacheFreshnessLuaAliasNode{name: name.name, kind: kind})
				}
			}
			if index == len(names)-1 || !cacheFreshnessLuaTokenIs(tokens, end, cacheFreshnessLuaSymbol, ",") {
				break
			}
			right = cacheFreshnessLuaNext(tokens, end+1)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for _, dependent := range edges[node] {
			add(dependent)
		}
	}
	return aliases
}

func cacheFreshnessLuaDynamicExecution(tokens []cacheFreshnessLuaToken,
	aliases cacheFreshnessLuaAliases) bool {
	braces := 0
	for index, token := range tokens {
		if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "{") {
			braces++
		} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "}") {
			braces--
		}
		if _, _, matched, executable := cacheFreshnessLuaDynamicRoot(tokens, index, aliases, 0); matched && executable {
			return true
		}
		if token.kind != cacheFreshnessLuaName {
			continue
		}
		if cacheFreshnessLuaDynamicName(token.value) {
			previous := cacheFreshnessLuaPrevious(tokens, index-1)
			if cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, ".") ||
				cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, ":") {
				continue
			}
			if _, target := aliases.targets[index]; !target &&
				!cacheFreshnessLuaStaticTableField(tokens, index, braces) {
				return true
			}
		}
	}
	return false
}

type cacheFreshnessLuaDynamicRootKind uint8

const (
	cacheFreshnessLuaDynamicGlobal cacheFreshnessLuaDynamicRootKind = iota + 1
	cacheFreshnessLuaDynamicDebug
	cacheFreshnessLuaDynamicPackage
	cacheFreshnessLuaDynamicLoaded
	cacheFreshnessLuaDynamicRegistry
	cacheFreshnessLuaDynamicOpaque
)

func cacheFreshnessLuaDynamicRoot(tokens []cacheFreshnessLuaToken, index int,
	aliases cacheFreshnessLuaAliases, depth int) (int, cacheFreshnessLuaDynamicRootKind, bool, bool) {
	if depth > cacheFreshnessLuaMaxNesting {
		return index, 0, true, true
	}
	index = cacheFreshnessLuaNext(tokens, index)
	var root cacheFreshnessLuaDynamicRootKind
	if index < len(tokens) && tokens[index].kind == cacheFreshnessLuaName {
		name := tokens[index].value
		if name == "_G" {
			root = cacheFreshnessLuaDynamicGlobal
		} else if name == "debug" {
			root = cacheFreshnessLuaDynamicDebug
		} else if _, matched := aliases.globals[name]; matched {
			root = cacheFreshnessLuaDynamicGlobal
		} else if _, matched := aliases.debugs[name]; matched {
			root = cacheFreshnessLuaDynamicDebug
		} else if name == "package" {
			root = cacheFreshnessLuaDynamicPackage
		} else if _, matched := aliases.packages[name]; matched {
			root = cacheFreshnessLuaDynamicPackage
		} else if _, matched := aliases.loaded[name]; matched {
			root = cacheFreshnessLuaDynamicLoaded
		} else if _, matched := aliases.registries[name]; matched {
			root = cacheFreshnessLuaDynamicRegistry
		} else if _, matched := aliases.opaques[name]; matched {
			root = cacheFreshnessLuaDynamicOpaque
		} else {
			return index, 0, false, false
		}
		index++
	} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "(") {
		after, nestedRoot, matched, executable := cacheFreshnessLuaDynamicRoot(tokens, index+1, aliases, depth+1)
		if executable {
			return after, nestedRoot, true, true
		}
		after = cacheFreshnessLuaNext(tokens, after)
		if !matched || !cacheFreshnessLuaTokenIs(tokens, after, cacheFreshnessLuaSymbol, ")") {
			return after, 0, false, false
		}
		index = after + 1
		root = nestedRoot
	} else {
		return index, 0, false, false
	}
	for step := 0; step < cacheFreshnessLuaMaxNesting; step++ {
		next := cacheFreshnessLuaNext(tokens, index)
		if !cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, ".") &&
			!cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, "[") {
			if cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, "(") ||
				cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, "{") ||
				cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, ":") ||
				next < len(tokens) && tokens[next].kind == cacheFreshnessLuaString {
				return next, root, true, true
			}
			return index, root, true, false
		}
		if root == cacheFreshnessLuaDynamicOpaque {
			return next, root, true, true
		}
		after, value, known, valid := cacheFreshnessLuaPropertyValue(tokens, index)
		if !valid {
			return after, root, true, true
		}
		if !known {
			return after, root, true, true
		}
		switch root {
		case cacheFreshnessLuaDynamicGlobal:
			if cacheFreshnessLuaDynamicName(value) {
				return after, root, true, true
			}
			switch value {
			case "_G":
				root = cacheFreshnessLuaDynamicGlobal
			case "debug":
				root = cacheFreshnessLuaDynamicDebug
			case "package":
				root = cacheFreshnessLuaDynamicPackage
			case "ngx":
				return after, root, true, false
			default:
				root = cacheFreshnessLuaDynamicOpaque
			}
		case cacheFreshnessLuaDynamicDebug:
			if value == "getfenv" || value == "setfenv" || value == "getregistry" {
				return after, root, true, true
			}
			root = cacheFreshnessLuaDynamicOpaque
		case cacheFreshnessLuaDynamicPackage:
			if value == "loaded" {
				root = cacheFreshnessLuaDynamicLoaded
			} else {
				root = cacheFreshnessLuaDynamicOpaque
			}
		case cacheFreshnessLuaDynamicLoaded:
			switch value {
			case "_G":
				root = cacheFreshnessLuaDynamicGlobal
			case "debug":
				root = cacheFreshnessLuaDynamicDebug
			case "package":
				root = cacheFreshnessLuaDynamicPackage
			default:
				return after, root, true, true
			}
		case cacheFreshnessLuaDynamicRegistry:
			switch value {
			case "_G":
				root = cacheFreshnessLuaDynamicGlobal
			case "_LOADED":
				root = cacheFreshnessLuaDynamicLoaded
			default:
				return after, root, true, true
			}
		}
		index = after
	}
	return index, root, true, true
}

func cacheFreshnessLuaPropertyValue(tokens []cacheFreshnessLuaToken, index int) (int, string, bool, bool) {
	index = cacheFreshnessLuaNext(tokens, index)
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, ".") {
		field := cacheFreshnessLuaNext(tokens, index+1)
		if field >= len(tokens) || tokens[field].kind != cacheFreshnessLuaName {
			return field, "", false, false
		}
		return field + 1, tokens[field].value, true, true
	}
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "[") {
		return cacheFreshnessLuaBracketValue(tokens, index)
	}
	return index, "", false, false
}

func cacheFreshnessLuaStaticTableField(tokens []cacheFreshnessLuaToken, index, braceDepth int) bool {
	if braceDepth <= 0 {
		return false
	}
	if !cacheFreshnessLuaTokenIs(tokens, cacheFreshnessLuaNext(tokens, index+1),
		cacheFreshnessLuaSymbol, "=") {
		return false
	}
	previous := cacheFreshnessLuaPrevious(tokens, index-1)
	return cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, "{") ||
		cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, ",")
}

func cacheFreshnessLuaDynamicName(value string) bool {
	switch value {
	case "getfenv", "setfenv", "load", "loadstring", "loadfile", "dofile":
		return true
	default:
		return false
	}
}

func cacheFreshnessLuaOpaqueProtectedSource(tokens []cacheFreshnessLuaToken, index int,
	aliases cacheFreshnessLuaAliases) bool {
	start := cacheFreshnessLuaNext(tokens, index)
	if _, target := aliases.targets[start]; target {
		return false
	}
	after, source, matched := cacheFreshnessLuaAliasSourceExpression(tokens, start)
	if !matched || !cacheFreshnessLuaProtectedSource(source, aliases) {
		return false
	}
	previous := cacheFreshnessLuaPrevious(tokens, start-1)
	if cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, "(") {
		if !cacheFreshnessLuaCallParenthesis(tokens, previous) {
			return false
		}
		if cacheFreshnessLuaKnownUnrelatedVarProperty(tokens, previous, aliases) {
			return false
		}
	}
	_, exact := aliases.exact[cacheFreshnessLuaSpan{start: start, end: after}]
	return !exact
}

func cacheFreshnessLuaCallParenthesis(tokens []cacheFreshnessLuaToken, opening int) bool {
	previous := cacheFreshnessLuaPrevious(tokens, opening-1)
	if previous < 0 {
		return false
	}
	if tokens[previous].kind == cacheFreshnessLuaName {
		switch tokens[previous].value {
		case "and", "do", "else", "elseif", "for", "function", "if", "in", "local", "not", "or",
			"repeat", "return", "then", "until", "while":
			return false
		default:
			return true
		}
	}
	return cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, ")") ||
		cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, "]")
}

func cacheFreshnessLuaKnownUnrelatedVarProperty(tokens []cacheFreshnessLuaToken, index int,
	aliases cacheFreshnessLuaAliases) bool {
	after, matched := cacheFreshnessLuaVarExpression(tokens, index, aliases)
	if !matched {
		return false
	}
	after = cacheFreshnessLuaNext(tokens, after)
	if cacheFreshnessLuaTokenIs(tokens, after, cacheFreshnessLuaSymbol, ".") {
		field := cacheFreshnessLuaNext(tokens, after+1)
		return field < len(tokens) && tokens[field].kind == cacheFreshnessLuaName &&
			tokens[field].value != "cache_freshness_identity"
	}
	if !cacheFreshnessLuaTokenIs(tokens, after, cacheFreshnessLuaSymbol, "[") {
		return false
	}
	_, field, known, valid := cacheFreshnessLuaBracketValue(tokens, after)
	return valid && known && field != "cache_freshness_identity"
}

func cacheFreshnessLuaProtectedSource(source cacheFreshnessLuaAliasSource,
	aliases cacheFreshnessLuaAliases) bool {
	if source.direct != 0 {
		return true
	}
	if source.dependency == "" {
		return false
	}
	if len(source.projections) == 0 {
		return cacheFreshnessLuaAliasHasKind(aliases, source.dependency,
			cacheFreshnessLuaGlobalAlias|cacheFreshnessLuaRootAlias|cacheFreshnessLuaVarAlias|
				cacheFreshnessLuaDebugAlias|cacheFreshnessLuaPackageAlias|cacheFreshnessLuaLoadedAlias|
				cacheFreshnessLuaRegistryAlias|cacheFreshnessLuaOpaqueAlias)
	}
	for _, projection := range source.projections {
		if cacheFreshnessLuaAliasHasKind(aliases, source.dependency, projection.from) {
			return true
		}
	}
	return false
}

func cacheFreshnessLuaAliasHasKind(aliases cacheFreshnessLuaAliases, name string,
	kind cacheFreshnessLuaAliasKind) bool {
	if kind&cacheFreshnessLuaGlobalAlias != 0 {
		if _, found := aliases.globals[name]; found {
			return true
		}
	}
	if kind&cacheFreshnessLuaRootAlias != 0 {
		if _, found := aliases.roots[name]; found {
			return true
		}
	}
	if kind&cacheFreshnessLuaVarAlias != 0 {
		if _, found := aliases.vars[name]; found {
			return true
		}
	}
	if kind&cacheFreshnessLuaDebugAlias != 0 {
		if _, found := aliases.debugs[name]; found {
			return true
		}
	}
	if kind&cacheFreshnessLuaPackageAlias != 0 {
		if _, found := aliases.packages[name]; found {
			return true
		}
	}
	if kind&cacheFreshnessLuaLoadedAlias != 0 {
		if _, found := aliases.loaded[name]; found {
			return true
		}
	}
	if kind&cacheFreshnessLuaRegistryAlias != 0 {
		if _, found := aliases.registries[name]; found {
			return true
		}
	}
	if kind&cacheFreshnessLuaOpaqueAlias != 0 {
		if _, found := aliases.opaques[name]; found {
			return true
		}
	}
	return false
}

func cacheFreshnessLuaAliasValueEnd(tokens []cacheFreshnessLuaToken, index int) int {
	parentheses, braces, brackets, blocks := 0, 0, 0, 0
	for index < len(tokens) {
		token := tokens[index]
		if token.kind == cacheFreshnessLuaNewline && parentheses == 0 && braces == 0 && brackets == 0 && blocks == 0 {
			return index
		}
		if token.kind == cacheFreshnessLuaName {
			switch token.value {
			case "function", "if", "do", "repeat":
				blocks++
			case "end", "until":
				if blocks == 0 {
					return index
				}
				blocks--
			}
		}
		if token.kind == cacheFreshnessLuaSymbol {
			switch token.value {
			case "(":
				parentheses++
			case ")":
				if parentheses == 0 {
					return index
				}
				parentheses--
			case "{":
				braces++
			case "}":
				if braces == 0 {
					return index
				}
				braces--
			case "[":
				brackets++
			case "]":
				if brackets == 0 {
					return index
				}
				brackets--
			case ",", ";":
				if parentheses == 0 && braces == 0 && brackets == 0 && blocks == 0 {
					return index
				}
			}
		}
		index++
	}
	return index
}

func cacheFreshnessLuaAssignmentNames(tokens []cacheFreshnessLuaToken, equal int) []cacheFreshnessLuaAssignmentName {
	start := equal
	parentheses, braces, brackets := 0, 0, 0
	for start > 0 {
		previous := start - 1
		token := tokens[previous]
		if token.kind == cacheFreshnessLuaNewline && parentheses == 0 && braces == 0 && brackets == 0 {
			break
		}
		if token.kind == cacheFreshnessLuaSymbol {
			switch token.value {
			case ")":
				parentheses++
			case "(":
				if parentheses == 0 {
					return nil
				}
				parentheses--
			case "}":
				braces++
			case "{":
				if braces == 0 {
					return nil
				}
				braces--
			case "]":
				brackets++
			case "[":
				if brackets == 0 {
					return nil
				}
				brackets--
			case ";":
				if parentheses == 0 && braces == 0 && brackets == 0 {
					start = previous + 1
					goto split
				}
			}
		}
		start = previous
	}

split:
	names := make([]cacheFreshnessLuaAssignmentName, 0, 2)
	segment := start
	parentheses, braces, brackets = 0, 0, 0
	for index := start; index <= equal; index++ {
		boundary := index == equal
		if !boundary && tokens[index].kind == cacheFreshnessLuaSymbol {
			switch tokens[index].value {
			case "(":
				parentheses++
			case ")":
				parentheses--
			case "{":
				braces++
			case "}":
				braces--
			case "[":
				brackets++
			case "]":
				brackets--
			case ",":
				boundary = parentheses == 0 && braces == 0 && brackets == 0
			}
		}
		if !boundary {
			continue
		}
		name, nameIndex := cacheFreshnessLuaSimpleAssignmentName(tokens, segment, index)
		names = append(names, cacheFreshnessLuaAssignmentName{name: name, index: nameIndex})
		segment = index + 1
	}
	return names
}

func cacheFreshnessLuaSimpleAssignmentName(tokens []cacheFreshnessLuaToken, start, end int) (string, int) {
	start = cacheFreshnessLuaNext(tokens, start)
	for end > start && tokens[end-1].kind == cacheFreshnessLuaNewline {
		end--
	}
	if cacheFreshnessLuaTokenIs(tokens, start, cacheFreshnessLuaName, "local") {
		start = cacheFreshnessLuaNext(tokens, start+1)
	}
	if start+1 == end && tokens[start].kind == cacheFreshnessLuaName {
		return tokens[start].value, start
	}
	return "", -1
}

func cacheFreshnessLuaAliasSourceExpression(tokens []cacheFreshnessLuaToken, index int) (int,
	cacheFreshnessLuaAliasSource, bool) {
	index = cacheFreshnessLuaNext(tokens, index)
	var source cacheFreshnessLuaAliasSource
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "(") {
		after, nested, matched := cacheFreshnessLuaAliasSourceExpression(tokens, index+1)
		after = cacheFreshnessLuaNext(tokens, after)
		if !matched || !cacheFreshnessLuaTokenIs(tokens, after, cacheFreshnessLuaSymbol, ")") {
			return after, source, false
		}
		source = nested
		index = after + 1
	} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaName, "_G") {
		source.direct = cacheFreshnessLuaGlobalAlias
		index++
	} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaName, "ngx") {
		source.direct = cacheFreshnessLuaRootAlias
		index++
	} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaName, "debug") {
		source.direct = cacheFreshnessLuaDebugAlias
		index++
	} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaName, "package") {
		source.direct = cacheFreshnessLuaPackageAlias
		index++
	} else if index < len(tokens) && tokens[index].kind == cacheFreshnessLuaName {
		source.dependency = tokens[index].value
		index++
	} else {
		return index, source, false
	}
	for {
		next := cacheFreshnessLuaNext(tokens, index)
		if !cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, ".") &&
			!cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, "[") {
			return index, source, true
		}
		after, candidates, matched := cacheFreshnessLuaAliasProperty(tokens, index)
		if !matched {
			return after, cacheFreshnessLuaAliasSource{}, false
		}
		if source.direct != 0 {
			var projected cacheFreshnessLuaAliasKind
			for _, candidate := range candidates {
				if source.direct&candidate.from != 0 {
					projected |= candidate.to
				}
			}
			if projected == 0 {
				return after, cacheFreshnessLuaAliasSource{}, false
			}
			source.direct = projected
		} else if len(source.projections) == 0 {
			source.projections = candidates
		} else {
			projected := make([]cacheFreshnessLuaAliasProjection, 0, len(source.projections))
			for _, existing := range source.projections {
				for _, candidate := range candidates {
					if existing.to == candidate.from {
						projected = append(projected, cacheFreshnessLuaAliasProjection{
							from: existing.from, to: candidate.to,
						})
					}
				}
			}
			if len(projected) == 0 {
				return after, cacheFreshnessLuaAliasSource{}, false
			}
			source.projections = projected
		}
		index = after
	}
}

func cacheFreshnessLuaAliasProperty(tokens []cacheFreshnessLuaToken, index int) (int,
	[]cacheFreshnessLuaAliasProjection, bool) {
	index = cacheFreshnessLuaNext(tokens, index)
	value, known := "", true
	after := index
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, ".") {
		after = cacheFreshnessLuaNext(tokens, index+1)
		if after >= len(tokens) || tokens[after].kind != cacheFreshnessLuaName {
			return after, nil, false
		}
		value = tokens[after].value
		after++
	} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "[") {
		var valid bool
		after, value, known, valid = cacheFreshnessLuaBracketValue(tokens, index)
		if !valid {
			return after, nil, false
		}
	} else {
		return index, nil, false
	}
	projections := make([]cacheFreshnessLuaAliasProjection, 0, 4)
	if !known || value == "_G" {
		projections = append(projections, cacheFreshnessLuaAliasProjection{
			from: cacheFreshnessLuaGlobalAlias, to: cacheFreshnessLuaGlobalAlias,
		})
	}
	if !known || value == "debug" {
		projections = append(projections, cacheFreshnessLuaAliasProjection{
			from: cacheFreshnessLuaGlobalAlias, to: cacheFreshnessLuaDebugAlias,
		})
	}
	if !known || value == "ngx" {
		projections = append(projections, cacheFreshnessLuaAliasProjection{
			from: cacheFreshnessLuaGlobalAlias, to: cacheFreshnessLuaRootAlias,
		})
	}
	if !known || value == "var" {
		projections = append(projections, cacheFreshnessLuaAliasProjection{
			from: cacheFreshnessLuaRootAlias, to: cacheFreshnessLuaVarAlias,
		})
	}
	if !known || value == "package" {
		projections = append(projections,
			cacheFreshnessLuaAliasProjection{from: cacheFreshnessLuaGlobalAlias, to: cacheFreshnessLuaPackageAlias},
			cacheFreshnessLuaAliasProjection{from: cacheFreshnessLuaLoadedAlias, to: cacheFreshnessLuaPackageAlias})
	}
	if !known || value == "loaded" {
		projections = append(projections, cacheFreshnessLuaAliasProjection{
			from: cacheFreshnessLuaPackageAlias, to: cacheFreshnessLuaLoadedAlias,
		})
	}
	if !known || value == "_G" {
		projections = append(projections,
			cacheFreshnessLuaAliasProjection{from: cacheFreshnessLuaLoadedAlias, to: cacheFreshnessLuaGlobalAlias},
			cacheFreshnessLuaAliasProjection{from: cacheFreshnessLuaRegistryAlias, to: cacheFreshnessLuaGlobalAlias})
	}
	if !known || value == "debug" {
		projections = append(projections, cacheFreshnessLuaAliasProjection{
			from: cacheFreshnessLuaLoadedAlias, to: cacheFreshnessLuaDebugAlias,
		})
	}
	if !known || value == "_LOADED" {
		projections = append(projections, cacheFreshnessLuaAliasProjection{
			from: cacheFreshnessLuaRegistryAlias, to: cacheFreshnessLuaLoadedAlias,
		})
	}
	if !known || value == "getregistry" {
		projections = append(projections, cacheFreshnessLuaAliasProjection{
			from: cacheFreshnessLuaDebugAlias, to: cacheFreshnessLuaRegistryAlias,
		})
	}
	if known {
		if value != "_G" && value != "debug" && value != "ngx" && value != "package" &&
			!cacheFreshnessLuaDynamicName(value) {
			projections = append(projections, cacheFreshnessLuaAliasProjection{
				from: cacheFreshnessLuaGlobalAlias, to: cacheFreshnessLuaOpaqueAlias,
			})
		}
		if value != "getfenv" && value != "setfenv" && value != "getregistry" {
			projections = append(projections, cacheFreshnessLuaAliasProjection{
				from: cacheFreshnessLuaDebugAlias, to: cacheFreshnessLuaOpaqueAlias,
			})
		}
		if value != "loaded" {
			projections = append(projections, cacheFreshnessLuaAliasProjection{
				from: cacheFreshnessLuaPackageAlias, to: cacheFreshnessLuaOpaqueAlias,
			})
		}
	}
	return after, projections, len(projections) != 0
}

func cacheFreshnessLuaIdentityTarget(tokens []cacheFreshnessLuaToken, index int,
	aliases cacheFreshnessLuaAliases) (int, bool) {
	index, matched := cacheFreshnessLuaVarExpression(tokens, index, aliases)
	if !matched {
		return index, false
	}
	return cacheFreshnessLuaProperty(tokens, index, "cache_freshness_identity", true)
}

func cacheFreshnessLuaVarExpression(tokens []cacheFreshnessLuaToken, index int,
	aliases cacheFreshnessLuaAliases) (int, bool) {
	index = cacheFreshnessLuaNext(tokens, index)
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "(") {
		after, matched := cacheFreshnessLuaVarExpression(tokens, index+1, aliases)
		after = cacheFreshnessLuaNext(tokens, after)
		if matched && cacheFreshnessLuaTokenIs(tokens, after, cacheFreshnessLuaSymbol, ")") {
			return after + 1, true
		}
	}
	if index < len(tokens) && tokens[index].kind == cacheFreshnessLuaName {
		if _, matched := aliases.vars[tokens[index].value]; matched {
			return index + 1, true
		}
	}
	index, matched := cacheFreshnessLuaRootExpression(tokens, index, aliases.roots, aliases.globals)
	if !matched {
		return index, false
	}
	return cacheFreshnessLuaProperty(tokens, index, "var", true)
}

func cacheFreshnessLuaRootExpression(tokens []cacheFreshnessLuaToken, index int,
	aliases, globals map[string]struct{}) (int, bool) {
	index = cacheFreshnessLuaNext(tokens, index)
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaName, "ngx") {
		return index + 1, true
	}
	if index < len(tokens) && tokens[index].kind == cacheFreshnessLuaName {
		if _, matched := aliases[tokens[index].value]; matched {
			return index + 1, true
		}
		if _, matched := globals[tokens[index].value]; matched {
			return cacheFreshnessLuaProperty(tokens, index+1, "ngx", true)
		}
	}
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaName, "_G") {
		return cacheFreshnessLuaProperty(tokens, index+1, "ngx", true)
	}
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "(") {
		after, matched := cacheFreshnessLuaRootExpression(tokens, index+1, aliases, globals)
		after = cacheFreshnessLuaNext(tokens, after)
		if matched && cacheFreshnessLuaTokenIs(tokens, after, cacheFreshnessLuaSymbol, ")") {
			return after + 1, true
		}
	}
	return index, false
}

func cacheFreshnessLuaProperty(tokens []cacheFreshnessLuaToken, index int, value string,
	unknownMatches bool) (int, bool) {
	index = cacheFreshnessLuaNext(tokens, index)
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, ".") {
		index = cacheFreshnessLuaNext(tokens, index+1)
		if index >= len(tokens) || tokens[index].kind != cacheFreshnessLuaName {
			return index, false
		}
		return index + 1, tokens[index].value == value
	}
	if !cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "[") {
		return index, false
	}
	after, key, known, valid := cacheFreshnessLuaBracketValue(tokens, index)
	if !valid || !known {
		return after, unknownMatches
	}
	return after, key == value
}

func cacheFreshnessLuaBracketValue(tokens []cacheFreshnessLuaToken, index int) (int, string, bool, bool) {
	if !cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "[") {
		return index, "", false, false
	}
	after, value, known := cacheFreshnessLuaConstantString(tokens,
		cacheFreshnessLuaNext(tokens, index+1), 0)
	if !known {
		after = cacheFreshnessLuaBracketEnd(tokens, index+1)
	}
	after = cacheFreshnessLuaNext(tokens, after)
	if !cacheFreshnessLuaTokenIs(tokens, after, cacheFreshnessLuaSymbol, "]") {
		return after, "", false, false
	}
	return after + 1, value, known, true
}

func cacheFreshnessLuaConstantString(tokens []cacheFreshnessLuaToken, index, depth int) (int, string, bool) {
	if depth > 64 {
		return index, "", false
	}
	index = cacheFreshnessLuaNext(tokens, index)
	value := ""
	if index < len(tokens) && tokens[index].kind == cacheFreshnessLuaString {
		value = tokens[index].value
		index++
	} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "(") {
		var known bool
		index, value, known = cacheFreshnessLuaConstantString(tokens, index+1, depth+1)
		index = cacheFreshnessLuaNext(tokens, index)
		if !known || !cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, ")") {
			return index, "", false
		}
		index = cacheFreshnessLuaNext(tokens, index+1)
	} else {
		return index, "", false
	}
	index = cacheFreshnessLuaNext(tokens, index)
	for cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "..") {
		after, suffix, known := cacheFreshnessLuaConstantString(tokens, index+1, depth+1)
		if !known || len(value)+len(suffix) > 256 {
			return after, "", false
		}
		value += suffix
		index = cacheFreshnessLuaNext(tokens, after)
	}
	return index, value, true
}

func cacheFreshnessLuaBracketEnd(tokens []cacheFreshnessLuaToken, index int) int {
	depth := 0
	for index < len(tokens) {
		if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "[") {
			depth++
		} else if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "]") {
			if depth == 0 {
				return index
			}
			depth--
		}
		index++
	}
	return index
}

func cacheFreshnessLuaAssignmentFollows(tokens []cacheFreshnessLuaToken, index int) bool {
	index = cacheFreshnessLuaNext(tokens, index)
	if cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, "=") {
		return true
	}
	if !cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaSymbol, ",") {
		return false
	}
	parentheses, braces, brackets := 0, 0, 0
	previous := ","
	for index++; index < len(tokens); index++ {
		token := tokens[index]
		if token.kind == cacheFreshnessLuaNewline {
			next := cacheFreshnessLuaNext(tokens, index+1)
			if previous != "," && !cacheFreshnessLuaTokenIs(tokens, next, cacheFreshnessLuaSymbol, "=") {
				return false
			}
			continue
		}
		if token.kind == cacheFreshnessLuaSymbol {
			switch token.value {
			case "(":
				parentheses++
			case ")":
				parentheses--
			case "{":
				braces++
			case "}":
				braces--
			case "[":
				brackets++
			case "]":
				brackets--
			case "=":
				if parentheses == 0 && braces == 0 && brackets == 0 {
					return true
				}
			case ";":
				if parentheses == 0 && braces == 0 && brackets == 0 {
					return false
				}
			}
		}
		if parentheses < 0 || braces < 0 || brackets < 0 {
			return false
		}
		previous = token.value
	}
	return false
}

func cacheFreshnessLuaDirectAccessCount(body string) (int, bool) {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return cacheFreshnessLuaDirectAccessCountWithBudget(body, &budget)
}

func cacheFreshnessLuaDirectAccessCountWithBudget(body string,
	budget *cacheFreshnessLuaBudget) (int, bool) {
	tokens, ok := cacheFreshnessLuaTokens(body)
	if !ok {
		return 0, false
	}
	if trusted, valid := cacheFreshnessTrustedLuaBodyWithinBudget(body, tokens, budget); trusted {
		return 0, valid
	}
	if !cacheFreshnessLuaWithinBudgetWithBudget(tokens, budget) {
		return 0, false
	}
	count := 0
	for index := range tokens {
		if !cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaName, "require") {
			continue
		}
		if previous := cacheFreshnessLuaPrevious(tokens, index-1); previous >= 0 &&
			cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, ".") {
			continue
		}
		sequence := []struct {
			kind  cacheFreshnessLuaTokenKind
			value string
		}{
			{cacheFreshnessLuaSymbol, "("}, {cacheFreshnessLuaString, "cachefreshness.guard"},
			{cacheFreshnessLuaSymbol, ")"}, {cacheFreshnessLuaSymbol, "."},
			{cacheFreshnessLuaName, "access"}, {cacheFreshnessLuaSymbol, "("},
		}
		matched := true
		next := index + 1
		for _, want := range sequence {
			next = cacheFreshnessLuaNext(tokens, next)
			if !cacheFreshnessLuaTokenIs(tokens, next, want.kind, want.value) || tokens[next].escaped {
				matched = false
				break
			}
			next++
		}
		if matched {
			count++
		}
	}
	return count, true
}

func cacheFreshnessLuaTokenIs(tokens []cacheFreshnessLuaToken, index int, kind cacheFreshnessLuaTokenKind,
	value string) bool {
	return index >= 0 && index < len(tokens) && tokens[index].kind == kind && tokens[index].value == value
}

func cacheFreshnessLuaNext(tokens []cacheFreshnessLuaToken, index int) int {
	for index < len(tokens) && tokens[index].kind == cacheFreshnessLuaNewline {
		index++
	}
	return index
}

func cacheFreshnessLuaPrevious(tokens []cacheFreshnessLuaToken, index int) int {
	for index >= 0 && tokens[index].kind == cacheFreshnessLuaNewline {
		index--
	}
	return index
}

func cacheFreshnessLuaIdentifier(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}

func cacheFreshnessManifestIdentity(manifest CachePolicyManifest, bound cacheFreshnessBundlePolicy) bool {
	policy := bound.policy
	if bound.siteIndex < 1 || bound.siteIndex > len(manifest.Listeners) ||
		manifest.TenantID != policy.TenantID || manifest.ConfigRevision != policy.ConfigurationVersion {
		return false
	}
	listener := manifest.Listeners[bound.siteIndex-1]
	return listener.SiteID == policy.SiteID && listener.Domain == policy.Hosts[0] &&
		listener.ListenPort == policy.ListenPort
}

func cacheFreshnessRequestBody(body string, policy CacheFreshnessPolicy, policyAware bool) bool {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return cacheFreshnessRequestBodyWithBudget(body, policy, policyAware, &budget)
}

func cacheFreshnessRequestBodyWithBudget(body string, policy CacheFreshnessPolicy, policyAware bool,
	budget *cacheFreshnessLuaBudget) bool {
	statement := cacheFreshnessRequestStatement(policy, policyAware)
	body = strings.TrimSpace(body)
	if !cacheFreshnessLuaBodyWithinBudget(body, budget) {
		return false
	}
	if policyAware {
		lines := strings.Split(body, "\n")
		return len(lines) == 2 &&
			strings.TrimSpace(lines[0]) == "ngx.var.cache_freshness_identity = ngx.var.cdnca_cache_policy_key" &&
			strings.TrimSpace(lines[1]) == statement
	}
	if body == statement {
		return true
	}
	suffix, found := strings.CutPrefix(body, statement+"\n")
	return found && !cacheFreshnessLuaIdentityReferenceWithBudget(suffix, budget)
}

func cacheFreshnessLuaBodyWithinBudget(body string, budget *cacheFreshnessLuaBudget) bool {
	tokens, ok := cacheFreshnessLuaTokens(strings.TrimSpace(body))
	return ok && cacheFreshnessLuaWithinBudgetWithBudget(tokens, budget)
}

func cacheFreshnessRequestStatement(policy CacheFreshnessPolicy, policyAware bool) string {
	requestBypass := `ngx.var.cache_freshness_request_bypass == "1"`
	if policyAware {
		requestBypass += ` or ngx.var.cdnca_cache_policy_bypass == "1"`
	}
	followOriginHeaders := ""
	if policy.FollowOriginHeaders {
		followOriginHeaders = "follow_origin_headers = true, "
	}
	return fmt.Sprintf(`require("cachefreshness.guard").access({ identity = ngx.var.cache_freshness_identity, request_bypass = %s, %sfresh_seconds = %d, stale_seconds = %d, lock_seconds = %.3f, metadata_ttl_seconds = %d })`,
		requestBypass, followOriginHeaders, policy.FreshSeconds, policy.Enhancement.StaleWindowSeconds,
		float64(policy.Enhancement.Expert.LockAgeMilliseconds)/1000, policy.CacheInactiveSeconds+60)
}

func structuredCacheFreshnessInit(nginx []byte) (bool, bool, int) {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	hasInit, hasInitWorker, runtimeHooks, _ := structuredCacheFreshnessInitWithBudget(nginx, &budget)
	return hasInit, hasInitWorker, runtimeHooks
}

func structuredCacheFreshnessInitWithBudget(nginx []byte,
	budget *cacheFreshnessLuaBudget) (bool, bool, int, bool) {
	document, ok := parseNginxDirectives(string(nginx))
	if !ok {
		return false, false, 0, false
	}
	httpBlocks := document.blockIDs(0, []string{"http"})
	if len(httpBlocks) != 1 {
		return false, false, 0, false
	}
	httpBlock := httpBlocks[0]
	initBlocks := document.blockNamed(httpBlock, "init_by_lua_block")
	hasInit := false
	if len(initBlocks) == 1 {
		body, _, split := splitChallengeInitTail(strings.TrimSpace(document.opaqueBodies[initBlocks[0].blockID]))
		hasInit = split && body == `require("cachefreshness.guard")`
		if !hasInit && split && strings.HasSuffix(body, `; require("cachefreshness.guard")`) {
			_, err := DecodeCCV2RegistryFromNginx(nginx)
			hasInit = err == nil
		}
	}
	workerBlocks := document.blockNamed(httpBlock, "init_worker_by_lua_block")
	hasInitWorker := len(workerBlocks) == 1 &&
		strings.TrimSpace(document.opaqueBodies[workerBlocks[0].blockID]) == `require("cachefreshness.guard").init_worker()`
	runtimeHooks := 0
	blockIDs := make([]int, 0, len(document.opaqueBodies))
	for blockID := range document.opaqueBodies {
		blockIDs = append(blockIDs, blockID)
	}
	sort.Ints(blockIDs)
	for _, blockID := range blockIDs {
		count, valid := cacheFreshnessLuaDirectAccessCountWithBudget(document.opaqueBodies[blockID], budget)
		if !valid {
			return false, false, 0, false
		}
		runtimeHooks += count
	}
	return hasInit, hasInitWorker, runtimeHooks, true
}

func CacheFreshnessGuard() []byte {
	return append([]byte(nil), cacheFreshnessGuard...)
}

func normalizeCacheFreshnessExpert(input *CacheFreshnessExpertPolicy) (CacheFreshnessExpertPolicy, error) {
	background, revalidation := true, true
	result := CacheFreshnessExpertPolicy{
		LockTimeoutMilliseconds: cacheFreshnessDefaultLockTimeoutMilliseconds,
		LockAgeMilliseconds:     cacheFreshnessDefaultLockAgeMilliseconds,
		BackgroundUpdate:        &background,
		Revalidation:            &revalidation,
		FailureClasses:          []CacheFreshnessFailureClass{CacheFreshnessFailureUpdating},
	}
	if input != nil {
		if input.LockTimeoutMilliseconds != 0 {
			result.LockTimeoutMilliseconds = input.LockTimeoutMilliseconds
		}
		if input.LockAgeMilliseconds != 0 {
			result.LockAgeMilliseconds = input.LockAgeMilliseconds
		}
		if input.BackgroundUpdate != nil {
			value := *input.BackgroundUpdate
			result.BackgroundUpdate = &value
		}
		if input.Revalidation != nil {
			value := *input.Revalidation
			result.Revalidation = &value
		}
		if len(input.FailureClasses) > 0 {
			result.FailureClasses = append([]CacheFreshnessFailureClass(nil), input.FailureClasses...)
		}
	}
	if result.LockTimeoutMilliseconds < CacheFreshnessMinLockTimeoutMilliseconds ||
		result.LockTimeoutMilliseconds > CacheFreshnessMaxLockTimeoutMilliseconds ||
		result.LockAgeMilliseconds < CacheFreshnessMinLockAgeMilliseconds ||
		result.LockAgeMilliseconds > CacheFreshnessMaxLockAgeMilliseconds {
		return CacheFreshnessExpertPolicy{}, invalidCacheFreshness("lock bounds are invalid")
	}
	allowed := map[CacheFreshnessFailureClass]struct{}{
		CacheFreshnessFailureUpdating: {}, CacheFreshnessFailureError: {}, CacheFreshnessFailureTimeout: {},
		CacheFreshnessFailureInvalidHeader: {}, CacheFreshnessFailureHTTP500: {}, CacheFreshnessFailureHTTP502: {},
		CacheFreshnessFailureHTTP503: {}, CacheFreshnessFailureHTTP504: {},
	}
	seen := make(map[CacheFreshnessFailureClass]struct{}, len(result.FailureClasses))
	classes := make([]CacheFreshnessFailureClass, 0, len(result.FailureClasses))
	for _, class := range result.FailureClasses {
		if _, ok := allowed[class]; !ok {
			return CacheFreshnessExpertPolicy{}, invalidCacheFreshness("failure class is invalid")
		}
		if _, exists := seen[class]; exists {
			return CacheFreshnessExpertPolicy{}, invalidCacheFreshness("failure class is duplicated")
		}
		seen[class] = struct{}{}
		classes = append(classes, class)
	}
	if *result.BackgroundUpdate {
		if _, exists := seen[CacheFreshnessFailureUpdating]; !exists {
			classes = append(classes, CacheFreshnessFailureUpdating)
		}
	} else if _, exists := seen[CacheFreshnessFailureUpdating]; exists {
		return CacheFreshnessExpertPolicy{}, invalidCacheFreshness("updating requires background_update")
	}
	sort.Slice(classes, func(i, j int) bool {
		return cacheFreshnessFailureOrder(classes[i]) < cacheFreshnessFailureOrder(classes[j])
	})
	result.FailureClasses = classes
	return result, nil
}

func normalizeSiteCacheFreshness(site Site) (*CacheFreshnessPolicy, error) {
	if site.CacheFreshness == nil {
		return nil, nil
	}
	policy, err := NormalizeCacheFreshnessPolicy(*site.CacheFreshness)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	if !policy.Enhancement.Enabled {
		return nil, nil
	}
	if site.Cache.Mode == CacheDisabled || policy.ListenAddress != "0.0.0.0" || policy.ListenPort != site.ListenPort ||
		len(policy.Hosts) != 1 || policy.Hosts[0] != site.Domain || policy.CacheMaxBytes != site.Cache.MaxSizeBytes ||
		policy.CacheInactiveSeconds != uint32(cacheInactive(site.Cache).Seconds()) ||
		!siteHasCacheFreshnessOrigin(site, policy.OriginHost, policy.OriginPort) {
		return nil, ErrInvalidConfig
	}
	return &policy, nil
}

func siteHasCacheFreshnessOrigin(site Site, host string, port uint16) bool {
	for _, origin := range site.Origins {
		if origin.Host == host && origin.Port == port {
			return true
		}
	}
	return false
}

func validCacheFreshnessPolicyPath(path string) bool {
	_, ok := cacheFreshnessSiteIndex(path)
	return ok
}

func cacheFreshnessSiteIndex(path string) (int, bool) {
	if !strings.HasPrefix(path, "cachefreshness/site_") || !strings.HasSuffix(path, ".json") {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(path, "cachefreshness/site_"), ".json")
	if len(value) != 4 {
		return 0, false
	}
	index, err := strconv.ParseUint(value, 10, 16)
	return int(index), err == nil && index > 0
}

func cacheFreshnessGuardSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func cacheFreshnessFailureOrder(class CacheFreshnessFailureClass) int {
	order := map[CacheFreshnessFailureClass]int{
		CacheFreshnessFailureUpdating: 0, CacheFreshnessFailureError: 1, CacheFreshnessFailureTimeout: 2,
		CacheFreshnessFailureInvalidHeader: 3, CacheFreshnessFailureHTTP500: 4, CacheFreshnessFailureHTTP502: 5,
		CacheFreshnessFailureHTTP503: 6, CacheFreshnessFailureHTTP504: 7,
	}
	return order[class]
}

func normalizeCacheFreshnessHost(value string, allowIP bool) (string, error) {
	if len(value) == 0 || len(value) > CacheFreshnessMaxHostBytes || strings.ContainsAny(value, ":/\\%\x00\r\n\t ") {
		return "", errors.New("invalid host")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if !allowIP || address.Is4In6() {
			return "", errors.New("IP address is not allowed")
		}
		return address.String(), nil
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid host label")
		}
		for index := range label {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return "", errors.New("invalid host character")
		}
	}
	return value, nil
}

func validCacheFreshnessIdentifier(value string) bool {
	if len(value) == 0 || len(value) > CacheFreshnessMaxIdentifierBytes {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func invalidCacheFreshness(format string, values ...any) error {
	return errors.Join(ErrInvalidCacheFreshnessPolicy, fmt.Errorf(format, values...))
}

func cacheFreshnessLuaPackagePath() string {
	return filepath.ToSlash("$prefix/?.lua") + ";;"
}
