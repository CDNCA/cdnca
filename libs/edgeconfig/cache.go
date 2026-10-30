package edgeconfig

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	CachePolicyManifestPath    = "cache/policies-v2.json"
	CachePolicyKeyModulePath   = "cachepolicy/key.lua"
	CachePolicyKeyModuleSHA256 = "952fe0a12c54da2f75a33210bd588a227029aa49f7fa896b761c82b8a062f9c5"
	CacheKeyVersion            = "v2"
	cachePolicySchema          = "cdnca.edge.cache-policies/v2"
)

//go:embed cachepolicy/key.lua
var cachePolicyKeyModule []byte

type CacheQueryMode string

type CacheRuleAction string

const (
	maxCachePolicyRoutes    = 2048
	maxCachePolicyRouteKeys = 4096

	CacheQueryPreserve CacheQueryMode = "preserve"
	CacheQueryIgnore   CacheQueryMode = "ignore"
	CacheQueryInclude  CacheQueryMode = "include"
	CacheQueryExclude  CacheQueryMode = "exclude"

	CacheRuleActionCache   CacheRuleAction = "cache"
	CacheRuleActionNoCache CacheRuleAction = "no_cache"

	CachePolicyDocumentSchemaV2 = 2
)

type CacheRule struct {
	Order       int
	Extensions  []string
	PathPrefix  string
	StatusCodes []int
	Action      CacheRuleAction
	TTL         time.Duration
	BrowserTTL  time.Duration
	// PathRegex and ContentTypes (site runtime v2 only, ge36):
	// CacheRuleDocument.
	PathRegex    string
	ContentTypes []string
	// CacheRuleExtras (site runtime v2 only).
	CacheRuleExtras
}

type CachePolicyDocument struct {
	SchemaVersion  int                 `json:"schema_version,omitempty"`
	Revision       uint64              `json:"revision"`
	Mode           CacheMode           `json:"mode"`
	Rules          []CacheRuleDocument `json:"rules"`
	QueryMode      CacheQueryMode      `json:"query_mode"`
	QueryNames     []string            `json:"query_names"`
	VaryHeaders    []string            `json:"vary_headers"`
	DiskQuotaBytes int64               `json:"disk_quota_bytes"`
	// Site runtime v2 only (ge-cache). StaleIfError serves a cached object
	// past its TTL while the origin fails (error, timeout, 500/502/503/504)
	// for as long as it is still on disk (the zone's inactive time).
	// BackgroundUpdate serves the stale object while one request refreshes
	// it (stale-while-revalidate). Min/MaxObjectBytes: a response whose
	// Content-Length is outside the bounds is not stored (0 = no bound).
	// SliceBytes > 0 caches objects in slices of that size (nginx slice), so
	// a Range request reads and fills only the slices it covers.
	StaleIfError     bool  `json:"stale_if_error,omitempty"`
	BackgroundUpdate bool  `json:"background_update,omitempty"`
	MinObjectBytes   int64 `json:"min_object_bytes,omitempty"`
	MaxObjectBytes   int64 `json:"max_object_bytes,omitempty"`
	SliceBytes       int64 `json:"slice_bytes,omitempty"`
}

// Bounds of the site runtime v2 cache policy extensions.
const (
	CacheMinSliceBytes       int64 = 256 << 10
	CacheMaxSliceBytes       int64 = 64 << 20
	CacheMaxObjectBytesLimit int64 = 1 << 40
)

// cachePolicyExtended reports whether the document uses a site runtime v2
// only extension; a v1 signed release refuses those.
func cachePolicyExtended(policy CachePolicyDocument) bool {
	return policy.StaleIfError || policy.BackgroundUpdate || policy.MinObjectBytes != 0 ||
		policy.MaxObjectBytes != 0 || policy.SliceBytes != 0 || CachePolicyUsesRuleMatch(policy) ||
		CachePolicyUsesRuleExtras(policy)
}

// ValidateCachePolicyExtensions checks the site runtime v2 extensions of a
// policy document (control plane and node apply the same bounds).
func ValidateCachePolicyExtensions(policy CachePolicyDocument) error {
	if policy.Mode == CacheDisabled && cachePolicyExtended(policy) ||
		policy.BackgroundUpdate && !policy.StaleIfError ||
		policy.MinObjectBytes < 0 || policy.MaxObjectBytes < 0 || policy.MaxObjectBytes > CacheMaxObjectBytesLimit ||
		policy.MaxObjectBytes != 0 && policy.MinObjectBytes >= policy.MaxObjectBytes ||
		policy.MinObjectBytes > CacheMaxObjectBytesLimit ||
		policy.SliceBytes != 0 && (policy.SliceBytes < CacheMinSliceBytes || policy.SliceBytes > CacheMaxSliceBytes ||
			policy.SliceBytes%(64<<10) != 0) {
		return ErrInvalidConfig
	}
	return nil
}

type CacheRuleDocument struct {
	Order             int             `json:"order"`
	Extensions        []string        `json:"extensions,omitempty"`
	PathPrefix        string          `json:"path_prefix,omitempty"`
	StatusCodes       []int           `json:"status_codes,omitempty"`
	Action            CacheRuleAction `json:"action,omitempty"`
	TTLSeconds        int64           `json:"ttl_seconds"`
	BrowserTTLSeconds int64           `json:"browser_ttl_seconds,omitempty"`
	// PathRegex (ge36): the normalized request path ($uri) must
	// also match this regular expression (ValidateCachePathRegex: the subset
	// PCRE and RE2 read alike, bounded). ContentTypes: the rule applies only
	// to a response whose Content-Type (lower case, without parameters) is
	// one of these, or starts with one ending in "*"; decided when the
	// response header arrives (CacheContentTypeMatches). Both schema
	// versions; the first matching rule wins. Either needs the node
	// capability CACHE_RULE_MATCH.
	PathRegex    string   `json:"path_regex,omitempty"`
	ContentTypes []string `json:"content_types,omitempty"`
	// CacheRuleExtras: per-rule settings (cache_rule_extras.go).
	CacheRuleExtras
}

type cachePolicyTTLGroup struct {
	Statuses []int
	TTL      time.Duration
}

type cachePolicyRoute struct {
	Signature       string
	Candidates      []int
	TTLGroups       []cachePolicyTTLGroup
	WildcardTTL     time.Duration
	V2              bool
	NoCacheDefault  bool
	NoCacheStatuses []cachePolicyStatusValue
	BrowserDefault  string
	BrowserStatuses []cachePolicyStatusValue
	noCacheVariable string
	browserVariable string
}

type cachePolicyStatusValue struct {
	Status int
	Value  string
}

type cachePolicyPlan struct {
	Digest string
	Routes []cachePolicyRoute
}

type CacheListenerPolicy struct {
	SiteID            string              `json:"site_id"`
	Domain            string              `json:"domain"`
	ListenPort        uint16              `json:"listen_port"`
	URLAuthPolicyID   string              `json:"url_auth_policy_id,omitempty"`
	Protocol          Protocol            `json:"protocol"`
	PrewarmPort       uint16              `json:"prewarm_port"`
	PrewarmPathPrefix string              `json:"prewarm_path_prefix"`
	NamespaceID       string              `json:"namespace_id"`
	KeyPrefix         string              `json:"key_prefix"`
	Policy            CachePolicyDocument `json:"policy"`
	// Domains are every name the site serves (its server_name: Domain first,
	// then aliases and "*." wildcards) when that is more than Domain alone:
	// a cache task URL may name any host they cover. Site runtime v2 only.
	Domains []string `json:"domains,omitempty"`
	// KeyByHost: the cache key names the request's own host (nginx $host)
	// in KeyPrefix's domain field instead of Domain, so each host the site
	// serves has its own objects. Site runtime v2 only; every listener of a
	// site agrees.
	KeyByHost bool `json:"key_by_host,omitempty"`
	// CacheGeneration (site runtime v2): the namespace is the site's stable
	// CacheSiteNamespaceID and KeyPrefix names this generation where v1
	// names the config version. Every listener of a site agrees.
	CacheGeneration string `json:"cache_generation,omitempty"`
}

type CachePolicyManifest struct {
	SchemaVersion   string                `json:"schema_version"`
	ConfigVersionID string                `json:"config_version_id"`
	ConfigRevision  uint64                `json:"config_revision"`
	TenantID        string                `json:"tenant_id"`
	NginxSHA256     string                `json:"nginx_sha256"`
	KeyModuleSHA256 string                `json:"key_module_sha256"`
	Listeners       []CacheListenerPolicy `json:"listeners"`
}

var (
	cacheExtensionPattern = regexp.MustCompile(`^\.[a-z0-9][a-z0-9_+-]{0,15}$`)
	cacheQueryNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.~-]{0,127}$`)
	cacheHeaderPattern    = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$")
)

func CacheNamespaceID(tenantID, siteID, configVersionID string) string {
	value := CacheKeyVersion + "\x00" + tenantID + "\x00" + siteID + "\x00" + configVersionID
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// CacheSiteNamespaceID is a site runtime v2 site's cache namespace
// (shared/cache/<namespace>): fixed for the site's life, so a publication
// that changes nothing about caching keeps every cached object.
func CacheSiteNamespaceID(tenantID, siteID string) string {
	digest := sha256.Sum256([]byte("cdnca-edge-cache-namespace-v2\x00" + tenantID + "\x00" + siteID))
	return hex.EncodeToString(digest[:])
}

// CacheGenerationPattern is a cache generation: 16 lower hex digits.
var CacheGenerationPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// CacheGeneration is a site runtime v2 site's cache generation, the key
// field v1 fills with the config version: it changes only when something
// that decides which object a request reads changes: the cache domain, host
// keying, the policy's mode, rules, key projection (query, vary) and slice
// size. Revision, quota, stale, size bounds and background update keep it:
// they change how objects are stored or served, not which object a key
// names. "Purge everything" is a cache task (purge_site), not a new
// generation. A new
// generation is a new key space; the old objects age out of the zone
// (inactive, LRU under max_size).
func CacheGeneration(domain string, keyByHost bool, policy CachePolicyDocument) string {
	identity, err := json.Marshal(struct {
		Domain        string              `json:"domain"`
		KeyByHost     bool                `json:"key_by_host"`
		SchemaVersion int                 `json:"schema_version"`
		Mode          CacheMode           `json:"mode"`
		Rules         []CacheRuleDocument `json:"rules"`
		QueryMode     CacheQueryMode      `json:"query_mode"`
		QueryNames    []string            `json:"query_names"`
		VaryHeaders   []string            `json:"vary_headers"`
		SliceBytes    int64               `json:"slice_bytes"`
	}{domain, keyByHost, policy.SchemaVersion, policy.Mode, nonNilCacheRules(policy.Rules), policy.QueryMode,
		nonNilStrings(policy.QueryNames), nonNilStrings(policy.VaryHeaders), policy.SliceBytes})
	if err != nil {
		panic("cache generation identity could not be encoded")
	}
	digest := sha256.Sum256(append([]byte("cdnca-edge-cache-generation-v1\x00"), identity...))
	return hex.EncodeToString(digest[:8])
}

func nonNilCacheRules(values []CacheRuleDocument) []CacheRuleDocument {
	if values == nil {
		return []CacheRuleDocument{}
	}
	return values
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// CacheKeyHostVariable is the nginx variable a site runtime v2 server and
// prewarm location set to the request's $host in the rewrite phase, before an
// origin signer replaces the Host header; a host-keyed cache key names it in
// CacheKeyPrefix's domain field.
const CacheKeyHostVariable = "cdnca_cache_host"

func CacheKeyPrefix(tenantID, siteID, configVersionID, domain string, listenPort uint16) string {
	return CacheKeyVersion + "|" + tenantID + "|" + siteID + "|" + configVersionID + "|" +
		domain + "|" + strconv.Itoa(int(listenPort)) + "|"
}

func CachePrewarmPathPrefix(tenantID, siteID, configVersionID, domain string, listenPort uint16, protocol Protocol) string {
	value := CacheKeyVersion + "\x00prewarm\x00" + tenantID + "\x00" + siteID + "\x00" + configVersionID +
		"\x00" + domain + "\x00" + strconv.Itoa(int(listenPort)) + "\x00" + string(protocol)
	digest := sha256.Sum256([]byte(value))
	return "/.cdnca-internal/cache-task/v2/" + hex.EncodeToString(digest[:16]) + "/"
}

func CachePolicyKeyModule() []byte {
	if digestHex(cachePolicyKeyModule) != CachePolicyKeyModuleSHA256 {
		panic("embedded cache policy key module digest changed")
	}
	return bytes.Clone(cachePolicyKeyModule)
}

func ParseCachePolicyManifest(content []byte) (CachePolicyManifest, error) {
	if len(content) == 0 || len(content) > 1<<20 || RejectDuplicateJSONKeys(content) != nil {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest CachePolicyManifest
	if err := decoder.Decode(&manifest); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		normalizeCacheManifest(&manifest) != nil {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(content, append(canonical, '\n')) {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	return manifest, nil
}

func cachePolicyManifest(spec normalizedSpec, nginx []byte) []byte {
	listeners := make([]CacheListenerPolicy, len(spec.Sites))
	for index, site := range spec.Sites {
		listeners[index] = CacheListenerPolicy{
			SiteID: site.ID, Domain: site.Domain, ListenPort: site.ListenPort,
			Protocol: site.Protocol, PrewarmPort: spec.HealthPort,
			PrewarmPathPrefix: CachePrewarmPathPrefix(spec.TenantID, site.ID, spec.ConfigVersionID,
				site.Domain, site.ListenPort, site.Protocol),
			NamespaceID: CacheNamespaceID(spec.TenantID, site.ID, spec.ConfigVersionID),
			KeyPrefix:   CacheKeyPrefix(spec.TenantID, site.ID, spec.ConfigVersionID, site.Domain, site.ListenPort),
			Policy:      cachePolicyDocument(site.Cache),
		}
		if site.URLAuth != nil {
			listeners[index].URLAuthPolicyID = site.URLAuth.PolicyID
		}
	}
	manifest := CachePolicyManifest{
		SchemaVersion: cachePolicySchema, ConfigVersionID: spec.ConfigVersionID,
		ConfigRevision: spec.ConfigRevision, TenantID: spec.TenantID,
		NginxSHA256: digestHex(nginx), KeyModuleSHA256: CachePolicyKeyModuleSHA256, Listeners: listeners,
	}
	if normalizeCacheManifest(&manifest) != nil {
		panic("normalized cache policy manifest became invalid")
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		panic("normalized cache policy manifest could not be encoded")
	}
	return append(content, '\n')
}

func cachePolicyDocument(policy CachePolicy) CachePolicyDocument {
	rules := make([]CacheRuleDocument, len(policy.Rules))
	for index, rule := range policy.Rules {
		rules[index] = CacheRuleDocument{
			Order: rule.Order, Extensions: append([]string(nil), rule.Extensions...), PathPrefix: rule.PathPrefix,
			StatusCodes: append([]int(nil), rule.StatusCodes...), Action: rule.Action,
			TTLSeconds: int64(rule.TTL / time.Second), BrowserTTLSeconds: int64(rule.BrowserTTL / time.Second),
			PathRegex: rule.PathRegex, ContentTypes: append([]string(nil), rule.ContentTypes...),
			CacheRuleExtras: rule.CacheRuleExtras.Clone(),
		}
	}
	return CachePolicyDocument{
		SchemaVersion: policy.SchemaVersion, Revision: policy.Revision, Mode: policy.Mode, Rules: rules, QueryMode: policy.QueryMode,
		QueryNames: append([]string(nil), policy.QueryNames...), VaryHeaders: append([]string(nil), policy.VaryHeaders...),
		DiskQuotaBytes: policy.MaxSizeBytes,
		StaleIfError:   policy.StaleIfError, BackgroundUpdate: policy.BackgroundUpdate,
		MinObjectBytes: policy.MinObjectBytes, MaxObjectBytes: policy.MaxObjectBytes, SliceBytes: policy.SliceBytes,
	}
}

func normalizeCacheManifest(manifest *CachePolicyManifest) error {
	if manifest.SchemaVersion != cachePolicySchema || !versionPattern.MatchString(manifest.ConfigVersionID) ||
		manifest.ConfigRevision == 0 || !uuidPattern.MatchString(manifest.TenantID) || !validCacheDigest(manifest.NginxSHA256) ||
		manifest.KeyModuleSHA256 != CachePolicyKeyModuleSHA256 ||
		len(manifest.Listeners) == 0 || len(manifest.Listeners) > 1000 {
		return ErrInvalidConfig
	}
	publicPorts := make(map[uint16]struct{}, len(manifest.Listeners))
	for _, listener := range manifest.Listeners {
		publicPorts[listener.ListenPort] = struct{}{}
	}
	prewarmPort := manifest.Listeners[0].PrewarmPort
	siteDomains := make(map[string]string, len(manifest.Listeners))
	siteServedDomains := make(map[string]string, len(manifest.Listeners))
	siteKeyByHost := make(map[string]string, len(manifest.Listeners))
	siteGenerations := make(map[string]string, len(manifest.Listeners))
	for index := range manifest.Listeners {
		listener := &manifest.Listeners[index]
		domain, err := normalizeSiteDomainName(listener.Domain)
		if err != nil || domain != listener.Domain || !uuidPattern.MatchString(listener.SiteID) || listener.ListenPort == 0 ||
			(listener.URLAuthPolicyID != "" && !uuidPattern.MatchString(listener.URLAuthPolicyID)) ||
			(listener.Protocol != ProtocolHTTP && listener.Protocol != ProtocolHTTPS) || listener.PrewarmPort == 0 ||
			listener.PrewarmPort != prewarmPort || publicPort(publicPorts, listener.PrewarmPort) ||
			listener.PrewarmPathPrefix != CachePrewarmPathPrefix(manifest.TenantID, listener.SiteID,
				manifest.ConfigVersionID, listener.Domain, listener.ListenPort, listener.Protocol) ||
			listener.NamespaceID != listenerCacheNamespace(*manifest, *listener) ||
			listener.KeyPrefix != CacheKeyPrefix(manifest.TenantID, listener.SiteID, listenerCacheKeyVersion(*manifest, *listener),
				listener.Domain, listener.ListenPort) ||
			listener.CacheGeneration != "" && !CacheGenerationPattern.MatchString(listener.CacheGeneration) ||
			listener.CacheGeneration == "" && cachePolicyExtended(listener.Policy) ||
			validateCachePolicyDocument(listener.Policy) != nil {
			return ErrInvalidConfig
		}
		if !bindSiteDomain(siteDomains, listener.SiteID, listener.Domain) ||
			!bindSiteDomain(siteGenerations, listener.SiteID, listener.CacheGeneration) ||
			!validCacheListenerDomains(*listener) ||
			!bindSiteDomain(siteServedDomains, listener.SiteID, strings.Join(listener.Domains, " ")) ||
			!bindSiteDomain(siteKeyByHost, listener.SiteID, strconv.FormatBool(listener.KeyByHost)) {
			return ErrInvalidConfig
		}
		if index > 0 {
			previous := manifest.Listeners[index-1]
			if previous.ListenPort > listener.ListenPort || previous.ListenPort == listener.ListenPort && previous.Domain >= listener.Domain {
				return ErrInvalidConfig
			}
		}
	}
	return nil
}

// listenerCacheNamespace: v1 names the config version, site runtime v2 (a
// cache generation) the site's stable namespace.
func listenerCacheNamespace(manifest CachePolicyManifest, listener CacheListenerPolicy) string {
	if listener.CacheGeneration != "" {
		return CacheSiteNamespaceID(manifest.TenantID, listener.SiteID)
	}
	return CacheNamespaceID(manifest.TenantID, listener.SiteID, manifest.ConfigVersionID)
}

// listenerCacheKeyVersion is the key's version field: the config version in
// v1, the cache generation in site runtime v2.
func listenerCacheKeyVersion(manifest CachePolicyManifest, listener CacheListenerPolicy) string {
	if listener.CacheGeneration != "" {
		return listener.CacheGeneration
	}
	return manifest.ConfigVersionID
}

// validCacheListenerDomains: absent, or at least two canonical site names
// with the listener's Domain first and no duplicate (at most 100, as a site).
func validCacheListenerDomains(listener CacheListenerPolicy) bool {
	if listener.Domains == nil {
		return true
	}
	if len(listener.Domains) < 2 || len(listener.Domains) > 100 || listener.Domains[0] != listener.Domain {
		return false
	}
	seen := make(map[string]struct{}, len(listener.Domains))
	for _, domain := range listener.Domains {
		normalized, err := normalizeSiteDomainName(domain)
		if _, duplicate := seen[domain]; duplicate || err != nil || normalized != domain {
			return false
		}
		seen[domain] = struct{}{}
	}
	return true
}

// CachePrewarmHost is the Host a site's prewarm location sends its origin:
// the site's one concrete domain, else (aliases, a "*." wildcard) the cache
// task's request Host, which names the URL's own host.
func CachePrewarmHost(domains []string) string {
	if len(domains) == 1 && !strings.HasPrefix(domains[0], "*.") {
		return domains[0]
	}
	return "$host"
}

func publicPort(ports map[uint16]struct{}, port uint16) bool {
	_, present := ports[port]
	return present
}

func digestHex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func validCacheDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validateCachePolicyDocument(policy CachePolicyDocument) error {
	if policy.SchemaVersion != 0 && policy.SchemaVersion != CachePolicyDocumentSchemaV2 ||
		policy.Mode != CacheDisabled && policy.Mode != CacheFollowOrigin && policy.Mode != CacheOverride ||
		policy.QueryMode != CacheQueryPreserve && policy.QueryMode != CacheQueryIgnore &&
			policy.QueryMode != CacheQueryInclude && policy.QueryMode != CacheQueryExclude ||
		len(policy.Rules) > 100 || len(policy.QueryNames) > 64 || len(policy.VaryHeaders) > 16 {
		return ErrInvalidConfig
	}
	if policy.Revision == 0 {
		if policy.Mode != CacheDisabled || len(policy.Rules) != 0 || len(policy.QueryNames) != 0 ||
			len(policy.VaryHeaders) != 0 || policy.DiskQuotaBytes != 0 {
			return ErrInvalidConfig
		}
	} else if policy.Mode == CacheDisabled {
		if len(policy.Rules) != 0 || policy.DiskQuotaBytes != 0 {
			return ErrInvalidConfig
		}
	} else if policy.Mode == CacheFollowOrigin {
		if len(policy.Rules) != 0 || policy.DiskQuotaBytes < 64<<20 || policy.DiskQuotaBytes > 16<<40 {
			return ErrInvalidConfig
		}
	} else if policy.DiskQuotaBytes < 64<<20 || policy.DiskQuotaBytes > 16<<40 {
		return ErrInvalidConfig
	}
	if (policy.QueryMode == CacheQueryPreserve || policy.QueryMode == CacheQueryIgnore) != (len(policy.QueryNames) == 0) {
		return ErrInvalidConfig
	}
	for index, name := range policy.QueryNames {
		if !cacheQueryNamePattern.MatchString(name) || index > 0 && policy.QueryNames[index-1] >= name {
			return ErrInvalidConfig
		}
	}
	for index, name := range policy.VaryHeaders {
		if !cacheHeaderPattern.MatchString(name) || index > 0 && policy.VaryHeaders[index-1] >= name {
			return ErrInvalidConfig
		}
		switch name {
		case "authorization", "cookie", "proxy-authorization", "set-cookie":
			return ErrInvalidConfig
		}
	}
	if err := ValidateCachePolicyExtensions(policy); err != nil {
		return err
	}
	if cacheConditionalRules(policy.Rules) > MaxCacheConditionalRules {
		return ErrInvalidConfig
	}
	for index, rule := range policy.Rules {
		if policy.SchemaVersion == 0 && rule.Action != "" ||
			policy.SchemaVersion == CachePolicyDocumentSchemaV2 && rule.Action == "" {
			return ErrInvalidConfig
		}
		if rule.Order != index+1 || !validCacheRuleDurations(rule.Action,
			time.Duration(rule.TTLSeconds)*time.Second, time.Duration(rule.BrowserTTLSeconds)*time.Second, true) ||
			len(rule.Extensions) > 32 || len(rule.StatusCodes) > 32 ||
			rule.PathPrefix != "" && (!strings.HasPrefix(rule.PathPrefix, "/") || !strings.HasSuffix(rule.PathPrefix, "/")) {
			return ErrInvalidConfig
		}
		for valueIndex, extension := range rule.Extensions {
			if !cacheExtensionPattern.MatchString(extension) || valueIndex > 0 && rule.Extensions[valueIndex-1] >= extension {
				return ErrInvalidConfig
			}
		}
		if rule.PathRegex != "" && ValidateCachePathRegex(rule.PathRegex) != nil ||
			rule.ContentTypes != nil && validateCacheContentTypes(rule.ContentTypes) != nil ||
			ValidateCacheRuleExtras(rule.CacheRuleExtras, rule.PathPrefix, rule.Action) != nil ||
			rule.CacheRuleExtras.Used() && policy.SchemaVersion != CachePolicyDocumentSchemaV2 {
			return ErrInvalidConfig
		}
		for valueIndex, status := range rule.StatusCodes {
			if status < 100 || status > 599 || valueIndex > 0 && rule.StatusCodes[valueIndex-1] >= status {
				return ErrInvalidConfig
			}
		}
	}
	return nil
}

func normalizeCacheRules(rules []CacheRule, signedPolicy bool) ([]CacheRule, error) {
	if len(rules) > 100 {
		return nil, ErrInvalidConfig
	}
	result := make([]CacheRule, len(rules))
	for index, rule := range rules {
		if rule.Order != index+1 || !validCacheRuleDurations(rule.Action, rule.TTL, rule.BrowserTTL, signedPolicy) ||
			len(rule.Extensions) > 32 || len(rule.StatusCodes) > 32 ||
			rule.PathPrefix != "" && (!strings.HasPrefix(rule.PathPrefix, "/") || !strings.HasSuffix(rule.PathPrefix, "/")) {
			return nil, ErrInvalidConfig
		}
		rule.Extensions = append([]string(nil), rule.Extensions...)
		sort.Strings(rule.Extensions)
		for valueIndex, extension := range rule.Extensions {
			if !cacheExtensionPattern.MatchString(extension) || valueIndex > 0 && rule.Extensions[valueIndex-1] == extension {
				return nil, ErrInvalidConfig
			}
		}
		if rule.PathRegex != "" && ValidateCachePathRegex(rule.PathRegex) != nil ||
			rule.ContentTypes != nil && validateCacheContentTypes(rule.ContentTypes) != nil ||
			ValidateCacheRuleExtras(rule.CacheRuleExtras, rule.PathPrefix, rule.Action) != nil {
			return nil, ErrInvalidConfig
		}
		rule.ContentTypes = append([]string(nil), rule.ContentTypes...)
		rule.CacheRuleExtras = rule.CacheRuleExtras.Clone()
		rule.StatusCodes = append([]int(nil), rule.StatusCodes...)
		sort.Ints(rule.StatusCodes)
		for valueIndex, status := range rule.StatusCodes {
			if status < 100 || status > 599 || valueIndex > 0 && rule.StatusCodes[valueIndex-1] == status {
				return nil, ErrInvalidConfig
			}
		}
		result[index] = rule
	}
	return result, nil
}

func cachePolicyAdvanced(policy CachePolicy) bool {
	return policy.Mode != CacheDisabled &&
		(policy.QueryMode != CacheQueryPreserve || len(policy.VaryHeaders) != 0 || len(policy.Rules) != 0)
}

func cachePolicyDocumentRuntime(policy CachePolicyDocument) CachePolicy {
	rules := make([]CacheRule, len(policy.Rules))
	for index, rule := range policy.Rules {
		rules[index] = CacheRule{
			Order: rule.Order, Extensions: append([]string(nil), rule.Extensions...), PathPrefix: rule.PathPrefix,
			StatusCodes: append([]int(nil), rule.StatusCodes...), Action: rule.Action,
			TTL: time.Duration(rule.TTLSeconds) * time.Second, BrowserTTL: time.Duration(rule.BrowserTTLSeconds) * time.Second,
			PathRegex: rule.PathRegex, ContentTypes: append([]string(nil), rule.ContentTypes...),
			CacheRuleExtras: rule.CacheRuleExtras.Clone(),
		}
	}
	return CachePolicy{
		SchemaVersion: policy.SchemaVersion, Revision: policy.Revision, Mode: policy.Mode, Rules: rules, QueryMode: policy.QueryMode,
		QueryNames: append([]string(nil), policy.QueryNames...), VaryHeaders: append([]string(nil), policy.VaryHeaders...),
		StaleIfError: policy.StaleIfError, BackgroundUpdate: policy.BackgroundUpdate,
		MinObjectBytes: policy.MinObjectBytes, MaxObjectBytes: policy.MaxObjectBytes, SliceBytes: policy.SliceBytes,
	}
}

func hasAdvancedCachePolicy(sites []Site) bool {
	for _, site := range sites {
		if cachePolicyAdvanced(site.Cache) {
			return true
		}
	}
	return false
}

func buildCachePolicyPlan(policy CachePolicy) (cachePolicyPlan, error) {
	if policy.Mode == CacheDisabled {
		return cachePolicyPlan{}, nil
	}
	signatures := map[string][]int{}
	if len(policy.Rules) == 0 {
		signatures[""] = nil
	} else {
		pathClasses := []string{""}
		extensionClasses := []string{""}
		seenPaths := map[string]struct{}{"": {}}
		seenExtensions := map[string]struct{}{"": {}}
		for _, rule := range policy.Rules {
			if _, exists := seenPaths[rule.PathPrefix]; !exists {
				seenPaths[rule.PathPrefix] = struct{}{}
				pathClasses = append(pathClasses, rule.PathPrefix)
			}
			for _, extension := range rule.Extensions {
				if _, exists := seenExtensions[extension]; !exists {
					seenExtensions[extension] = struct{}{}
					extensionClasses = append(extensionClasses, extension)
				}
			}
		}
		sort.Strings(pathClasses[1:])
		sort.Strings(extensionClasses[1:])
		if len(pathClasses)*len(extensionClasses) > maxCachePolicyRouteKeys {
			return cachePolicyPlan{}, ErrInvalidConfig
		}
		for _, pathClass := range pathClasses {
			for _, extensionClass := range extensionClasses {
				candidates := make([]int, 0, len(policy.Rules))
				for index, rule := range policy.Rules {
					pathMatches := rule.PathPrefix == "" || pathClass != "" && strings.HasPrefix(pathClass, rule.PathPrefix)
					extensionMatches := len(rule.Extensions) == 0 || extensionClass != "" && stringSliceContains(rule.Extensions, extensionClass)
					if pathMatches && extensionMatches {
						candidates = append(candidates, index)
					}
				}
				if len(candidates) == 0 {
					continue
				}
				signature := cacheCandidateSignature(candidates)
				signatures[signature] = candidates
			}
		}
	}
	if len(signatures) == 0 || len(signatures) > maxCachePolicyRoutes {
		return cachePolicyPlan{}, ErrInvalidConfig
	}
	ordered := make([]string, 0, len(signatures))
	for signature := range signatures {
		ordered = append(ordered, signature)
	}
	sort.Strings(ordered)
	routes := make([]cachePolicyRoute, 0, len(ordered))
	for _, signature := range ordered {
		candidates := append([]int(nil), signatures[signature]...)
		groups, wildcard := cachePolicyRouteTTLs(policy, candidates)
		route := cachePolicyRoute{
			Signature: signature, Candidates: candidates, TTLGroups: groups, WildcardTTL: wildcard,
		}
		if cachePolicyUsesV2Rules(policy) {
			route = cachePolicyV2Route(policy, route)
		}
		routes = append(routes, route)
	}
	digestContent, err := json.Marshal(struct {
		Policy CachePolicyDocument `json:"policy"`
		Routes []string            `json:"routes"`
	}{Policy: cachePolicyDocument(policy), Routes: ordered})
	if err != nil {
		return cachePolicyPlan{}, ErrInvalidConfig
	}
	return cachePolicyPlan{Digest: digestHex(digestContent), Routes: routes}, nil
}

func stringSliceContains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func cacheCandidateSignature(candidates []int) string {
	values := make([]string, len(candidates))
	for index, candidate := range candidates {
		values[index] = strconv.Itoa(candidate + 1)
	}
	return strings.Join(values, ",")
}

func cachePolicyRouteTTLs(policy CachePolicy, candidates []int) ([]cachePolicyTTLGroup, time.Duration) {
	if len(policy.Rules) == 0 {
		return nil, 0
	}
	groups := make([]cachePolicyTTLGroup, 0, len(candidates))
	groupByTTL := make(map[time.Duration]int, len(candidates))
	seenStatuses := make(map[int]struct{})
	for _, candidate := range candidates {
		rule := policy.Rules[candidate]
		if len(rule.StatusCodes) == 0 {
			return groups, rule.TTL
		}
		for _, status := range rule.StatusCodes {
			if _, exists := seenStatuses[status]; exists {
				continue
			}
			seenStatuses[status] = struct{}{}
			group, exists := groupByTTL[rule.TTL]
			if !exists {
				group = len(groups)
				groupByTTL[rule.TTL] = group
				groups = append(groups, cachePolicyTTLGroup{TTL: rule.TTL})
			}
			groups[group].Statuses = append(groups[group].Statuses, status)
		}
	}
	return groups, 0
}

type cachePolicyDecision struct {
	cache      bool
	ttl        time.Duration
	browserTTL time.Duration
}

func cachePolicyUsesV2Rules(policy CachePolicy) bool {
	return policy.SchemaVersion == CachePolicyDocumentSchemaV2 && len(policy.Rules) != 0
}

func cachePolicyV2Route(policy CachePolicy, route cachePolicyRoute) cachePolicyRoute {
	route.V2 = true
	defaultDecision := cachePolicyDecision{}
	for _, candidate := range route.Candidates {
		rule := policy.Rules[candidate]
		if len(rule.StatusCodes) == 0 {
			defaultDecision = cachePolicyRuleDecision(rule)
			break
		}
	}
	route.NoCacheDefault = !defaultDecision.cache
	route.BrowserDefault = cachePolicyBrowserValue(defaultDecision)
	statuses := make([]int, 0)
	seen := make(map[int]struct{})
	for _, candidate := range route.Candidates {
		for _, status := range policy.Rules[candidate].StatusCodes {
			if _, exists := seen[status]; !exists {
				seen[status] = struct{}{}
				statuses = append(statuses, status)
			}
		}
	}
	sort.Ints(statuses)
	groups := make([]cachePolicyTTLGroup, 0)
	groupByTTL := make(map[time.Duration]int)
	for _, status := range statuses {
		decision := cachePolicyDecision{}
		for _, candidate := range route.Candidates {
			rule := policy.Rules[candidate]
			if len(rule.StatusCodes) == 0 || intSliceContains(rule.StatusCodes, status) {
				decision = cachePolicyRuleDecision(rule)
				break
			}
		}
		if decision.cache {
			group, exists := groupByTTL[decision.ttl]
			if !exists {
				group = len(groups)
				groupByTTL[decision.ttl] = group
				groups = append(groups, cachePolicyTTLGroup{TTL: decision.ttl})
			}
			groups[group].Statuses = append(groups[group].Statuses, status)
		}
		if !decision.cache != route.NoCacheDefault {
			value := "0"
			if !decision.cache {
				value = "1"
			}
			route.NoCacheStatuses = append(route.NoCacheStatuses, cachePolicyStatusValue{Status: status, Value: value})
		}
		browser := cachePolicyBrowserValue(decision)
		if browser != route.BrowserDefault {
			route.BrowserStatuses = append(route.BrowserStatuses, cachePolicyStatusValue{Status: status, Value: browser})
		}
	}
	route.TTLGroups = groups
	if defaultDecision.cache {
		route.WildcardTTL = defaultDecision.ttl
	} else {
		route.WildcardTTL = 0
	}
	return route
}

func cachePolicyRuleDecision(rule CacheRule) cachePolicyDecision {
	return cachePolicyDecision{
		cache: rule.Action == CacheRuleActionCache, ttl: rule.TTL, browserTTL: rule.BrowserTTL,
	}
}

func cachePolicyBrowserValue(decision cachePolicyDecision) string {
	if !decision.cache {
		return "epoch"
	}
	if decision.browserTTL == 0 {
		return "off"
	}
	return nginxCacheDuration(decision.browserTTL)
}

func intSliceContains(values []int, target int) bool {
	index := sort.SearchInts(values, target)
	return index < len(values) && values[index] == target
}

func validCacheRuleDurations(action CacheRuleAction, ttl, browserTTL time.Duration, signedPolicy bool) bool {
	switch action {
	case "":
		return browserTTL == 0 && validCacheTTL(ttl, signedPolicy)
	case CacheRuleActionCache:
		return validCacheTTL(ttl, signedPolicy) && browserTTL >= 0 && browserTTL <= ttl &&
			browserTTL%time.Second == 0
	case CacheRuleActionNoCache:
		return ttl == 0 && browserTTL == 0
	default:
		return false
	}
}

func validateCachePolicyBundle(bundle Bundle) error {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return validateCachePolicyBundleWithBudget(bundle, &budget)
}

func validateCachePolicyBundleWithBudget(bundle Bundle, budget *cacheFreshnessLuaBudget) error {
	_, present := bundle.Files[CachePolicyManifestPath]
	if !present {
		return nil
	}
	if _, modulePresent := bundle.Files[CachePolicyKeyModulePath]; !modulePresent {
		return fmt.Errorf("%w: cache policy key module is missing", ErrInvalidBundle)
	}
	if _, err := parseCachePolicyReleaseFilesWithBudget(bundle.Files, budget); err != nil {
		return fmt.Errorf("%w: invalid cache policy freshness binding", ErrInvalidBundle)
	}
	return nil
}

func cachePolicyFreshnessBindings(files map[string][]byte,
	manifest CachePolicyManifest) (map[int]cachePolicyFreshnessContract, error) {
	bindings := make(map[int]cachePolicyFreshnessContract)
	for index, listener := range manifest.Listeners {
		content, present := files[fmt.Sprintf("cachefreshness/site_%04d.json", index+1)]
		if !present {
			continue
		}
		policy, err := DecodeCacheFreshnessPolicy(content)
		if err != nil || policy.TenantID != manifest.TenantID || policy.SiteID != listener.SiteID ||
			policy.ConfigurationVersion != manifest.ConfigRevision || policy.ListenAddress != "0.0.0.0" ||
			policy.ListenPort != listener.ListenPort || len(policy.Hosts) != 1 || policy.Hosts[0] != listener.Domain ||
			policy.CacheMaxBytes != listener.Policy.DiskQuotaBytes || !policy.Enhancement.Enabled {
			return nil, ErrInvalidConfig
		}
		binding := cachePolicyFreshnessContract{
			initialized: true, enabled: true, authoritative: true,
			followOriginHeaders:  policy.FollowOriginHeaders,
			fresh:                strconv.FormatUint(uint64(policy.FreshSeconds), 10),
			stale:                strconv.FormatUint(uint64(policy.Enhancement.StaleWindowSeconds), 10),
			lockAge:              fmt.Sprintf("%.3f", float64(policy.Enhancement.Expert.LockAgeMilliseconds)/1000),
			lockTimeout:          fmt.Sprintf("%.3f", float64(policy.Enhancement.Expert.LockTimeoutMilliseconds)/1000),
			metadataTTL:          strconv.FormatUint(uint64(policy.CacheInactiveSeconds)+60, 10),
			cacheInactiveSeconds: policy.CacheInactiveSeconds,
			cacheKey:             []string{"proxy_cache_key", "$cache_freshness_generation|$cache_freshness_object_token|$cdnca_cache_policy_key"},
			cacheBypass:          []string{"proxy_cache_bypass", "$cache_freshness_request_bypass", "$cache_freshness_hard_bypass", "$cache_freshness_fail_closed"},
			noCache:              []string{"proxy_no_cache", "$cache_freshness_request_bypass", "$cache_freshness_response_bypass", "$cache_freshness_validator_bypass", "$cache_freshness_fail_closed"},
			nginxLockAge:         nginxCacheFreshnessDuration(policy.Enhancement.Expert.LockAgeMilliseconds),
			nginxLockTimeout:     nginxCacheFreshnessDuration(policy.Enhancement.Expert.LockTimeoutMilliseconds),
			backgroundUpdate:     []string{"proxy_cache_background_update", nginxBoolean(*policy.Enhancement.Expert.BackgroundUpdate)},
			revalidation:         []string{"proxy_cache_revalidate", nginxBoolean(*policy.Enhancement.Expert.Revalidation)},
		}
		if !cachePolicyAdvanced(cachePolicyDocumentRuntime(listener.Policy)) {
			binding.cacheKey = []string{"proxy_cache_key", "$cache_freshness_generation|$cache_freshness_object_token|" + cacheFreshnessIdentity(policy)}
		}
		if len(policy.Enhancement.Expert.FailureClasses) > 0 {
			binding.useStale = []string{"proxy_cache_use_stale"}
			for _, class := range policy.Enhancement.Expert.FailureClasses {
				binding.useStale = append(binding.useStale, string(class))
			}
		}
		bindings[index] = binding
	}
	return bindings, nil
}

func ParseCachePolicyRelease(policyContent, nginxContent []byte, keyModuleContent ...[]byte) (CachePolicyManifest, error) {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return parseCachePolicyReleaseWithBudget(policyContent, nginxContent, &budget, keyModuleContent...)
}

func parseCachePolicyReleaseWithBudget(policyContent, nginxContent []byte, budget *cacheFreshnessLuaBudget,
	keyModuleContent ...[]byte) (CachePolicyManifest, error) {
	manifest, err := ParseCachePolicyManifest(policyContent)
	module := cachePolicyKeyModule
	if len(keyModuleContent) == 1 {
		module = keyModuleContent[0]
	} else if len(keyModuleContent) != 0 {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	if err != nil || len(module) == 0 || len(module) > 256<<10 || digestHex(module) != manifest.KeyModuleSHA256 ||
		len(nginxContent) == 0 || len(nginxContent) > 8<<20 || digestHex(nginxContent) != manifest.NginxSHA256 ||
		validateCacheNginxContractWithBudget(manifest, string(nginxContent), budget) != nil {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	for _, listener := range manifest.Listeners {
		// A signed release keys every listener by its fixed KeyPrefix.
		if listener.KeyByHost {
			return CachePolicyManifest{}, ErrInvalidConfig
		}
	}
	return manifest, nil
}

// ParseCachePolicyReleaseFiles binds the executable Nginx cache contract to the
// canonical cache freshness policies carried by the same immutable release.
func ParseCachePolicyReleaseFiles(files map[string][]byte) (CachePolicyManifest, error) {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return parseCachePolicyReleaseFilesWithBudget(files, &budget)
}

func parseCachePolicyReleaseFilesWithBudget(files map[string][]byte,
	budget *cacheFreshnessLuaBudget) (CachePolicyManifest, error) {
	cacheFreshnessTrustTelemetryLuaBodies(Bundle{Files: files}, budget)
	module, present := files[CachePolicyKeyModulePath]
	if !present {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	manifest, err := parseCachePolicyReleaseWithBudget(files[CachePolicyManifestPath], files["nginx.conf"], budget, module)
	if err != nil {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	freshness, err := cachePolicyFreshnessBindings(files, manifest)
	guard, guardPresent := files[CacheFreshnessGuardPath]
	if err != nil || (len(freshness) > 0 && (!guardPresent || digestHex(guard) != CacheFreshnessGuardSHA256)) ||
		validateCacheNginxContractWithBudget(manifest, string(files["nginx.conf"]), budget, freshness) != nil {
		return CachePolicyManifest{}, ErrInvalidConfig
	}
	return manifest, nil
}

func validateCacheNginxContract(manifest CachePolicyManifest, nginx string,
	freshnessBindings ...map[int]cachePolicyFreshnessContract) error {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return validateCacheNginxContractWithBudget(manifest, nginx, &budget, freshnessBindings...)
}

func validateCacheNginxContractWithBudget(manifest CachePolicyManifest, nginx string,
	budget *cacheFreshnessLuaBudget, freshnessBindings ...map[int]cachePolicyFreshnessContract) error {
	if len(freshnessBindings) > 1 {
		return ErrInvalidConfig
	}
	document, ok := parseNginxDirectives(nginx)
	if !ok || document.hasInclude || hasUnexpectedCacheFreshnessIdentityWriteWithBudget(document, budget) {
		return ErrInvalidConfig
	}
	httpBlock, ok := uniqueUnquotedNginxBlock(document, 0, []string{"http"})
	if !ok {
		return ErrInvalidConfig
	}
	prewarmPort := manifest.Listeners[0].PrewarmPort
	loopbackServer, ok := uniqueNginxBlockWithDirectives(document, httpBlock, []string{"server"},
		[]string{"listen", fmt.Sprintf("127.0.0.1:%d", prewarmPort)},
		[]string{"listen", fmt.Sprintf("[::1]:%d", prewarmPort), "ipv6only=on"},
		[]string{"server_name", "_"})
	if !ok || hasPublicNginxListen(document, httpBlock, loopbackServer, prewarmPort) ||
		hasForbiddenInheritedProxyPassHeader(document, 0, httpBlock, loopbackServer) {
		return ErrInvalidConfig
	}
	healthLocation := 0
	healthLocations := document.blockIDs(loopbackServer, []string{"location", "=", "/healthz"})
	if len(healthLocations) > 1 {
		return ErrInvalidConfig
	}
	if len(healthLocations) == 1 {
		healthLocation = healthLocations[0]
		if document.childCounts[healthLocation] != 3 || !hasExactDirectNginxDirectives(document, healthLocation,
			[]string{"default_type", "text/plain"},
			[]string{"add_header", "X-CDNCA-Config-Version", manifest.ConfigVersionID, "always"},
			[]string{"return", "200", "ok:" + manifest.ConfigVersionID + "\n"}) {
			return ErrInvalidConfig
		}
	}
	cachePaths, cachePathsOK := indexNginxCachePaths(document, httpBlock)
	if !cachePathsOK {
		return ErrInvalidConfig
	}
	usedCacheZones := make(map[string]struct{}, len(cachePaths))
	internalLocations := make(map[string]int, len(manifest.Listeners))
	prewarmPolicyRoutes := make(map[string][]int, len(manifest.Listeners))
	policyPlans := make(map[string]cachePolicyPlan, len(manifest.Listeners))
	trustedLocations := make(map[int]struct{}, len(manifest.Listeners))
	trustedReturnBlocks := make(map[int]struct{}, len(manifest.Listeners)*3)
	for listenerIndex, listener := range manifest.Listeners {
		// The v1 renderer prewarms under the site domain only.
		if listener.Domains != nil {
			return ErrInvalidConfig
		}
		if listener.Policy.Mode == CacheDisabled {
			continue
		}
		path := listener.PrewarmPathPrefix
		internal, ok := uniqueUnquotedNginxBlock(document, loopbackServer, []string{"location", "^~", path})
		if !ok || document.locationCounts[path] != 1 {
			return ErrInvalidConfig
		}
		internalLocations[path] = internal
		trustedLocations[internal] = struct{}{}
		if runtimePolicy := cachePolicyDocumentRuntime(listener.Policy); cachePolicyAdvanced(runtimePolicy) {
			plan, err := buildCachePolicyPlan(runtimePolicy)
			if err != nil || !validateCachePolicyActionMaps(document, httpBlock, listenerIndex, plan) {
				return ErrInvalidConfig
			}
			policyPlans[path] = plan
			routes := make([]int, 0, len(plan.Routes)+1)
			for routeIndex := 0; routeIndex <= len(plan.Routes); routeIndex++ {
				route, ok := uniqueUnquotedNginxBlock(document, loopbackServer,
					[]string{"location", cachePolicyRouteName(listenerIndex, true, routeIndex)})
				if !ok {
					return ErrInvalidConfig
				}
				routes = append(routes, route)
				trustedLocations[route] = struct{}{}
			}
			prewarmPolicyRoutes[path] = routes
		}
		for _, guard := range []struct {
			block           []string
			returnDirective []string
		}{
			{block: []string{"if", "($request_method", "!=", "GET)"}, returnDirective: []string{"return", "405"}},
			{block: []string{"if", "($http_x_cdnca_internal_cache_task", "!=", "v2"}, returnDirective: []string{"return", "404"}},
			{block: []string{"if", "($http_x_cdnca_cache_namespace", "!=", listener.NamespaceID}, returnDirective: []string{"return", "404"}},
		} {
			guardBlock, ok := nginxGuardBlock(document, internal, guard.block, guard.returnDirective)
			if !ok {
				return ErrInvalidConfig
			}
			trustedReturnBlocks[guardBlock] = struct{}{}
		}
	}
	for listenerIndex, listener := range manifest.Listeners {
		if listener.URLAuthPolicyID != "" {
			required, bindingOK := rangeCacheURLAuthBindingRequired(document, httpBlock, RangeCacheDocument{
				TenantID: manifest.TenantID, SiteID: listener.SiteID,
				ListenPort: listener.ListenPort, URLAuthPolicyID: listener.URLAuthPolicyID,
			})
			if !bindingOK || !required {
				return ErrInvalidConfig
			}
		}
		listenOptions := ""
		if listener.Protocol == ProtocolHTTPS {
			listenOptions = " ssl"
		}
		ipv4Listen := []string{"listen", fmt.Sprintf("0.0.0.0:%d", listener.ListenPort)}
		ipv6Listen := []string{"listen", fmt.Sprintf("[::]:%d", listener.ListenPort)}
		if listenOptions != "" {
			ipv4Listen = append(ipv4Listen, strings.TrimSpace(listenOptions))
			ipv6Listen = append(ipv6Listen, strings.TrimSpace(listenOptions))
		}
		serverName := []string{"server_name", listener.Domain}
		publicServer, ok := uniquePublicNginxServer(document, httpBlock, listener.Domain, listener.ListenPort,
			ipv4Listen, ipv6Listen, serverName)
		if !ok {
			publicServer, ok = uniquePublicNginxServer(document, httpBlock, listener.Domain, listener.ListenPort,
				ipv4Listen, serverName)
		}
		if !ok || hasForbiddenInheritedProxyPassHeader(document, 0, httpBlock, publicServer) {
			return ErrInvalidConfig
		}
		publicLocation, ok := uniqueUnquotedNginxBlock(document, publicServer, []string{"location", "/"})
		if !ok {
			return ErrInvalidConfig
		}
		runtimePolicy := cachePolicyDocumentRuntime(listener.Policy)
		advanced := cachePolicyAdvanced(runtimePolicy)
		var publicPolicyRoutes []int
		if advanced {
			plan, exists := policyPlans[listener.PrewarmPathPrefix]
			if !exists {
				return ErrInvalidConfig
			}
			publicPolicyRoutes = make([]int, 0, len(plan.Routes)+1)
			for routeIndex := 0; routeIndex <= len(plan.Routes); routeIndex++ {
				route, routeOK := uniqueUnquotedNginxBlock(document, publicServer,
					[]string{"location", cachePolicyRouteName(listenerIndex, false, routeIndex)})
				if !routeOK {
					return ErrInvalidConfig
				}
				publicPolicyRoutes = append(publicPolicyRoutes, route)
			}
		}
		if hasUnexpectedPublicNginxLocation(document, publicServer, publicLocation, publicPolicyRoutes...) {
			return ErrInvalidConfig
		}
		if !advanced && (!hasReservedNginxHeaderContract(document, publicLocation) ||
			!hasUnquotedDirectNginxDirectives(document, publicLocation,
				[]string{"proxy_set_header", "X-CDNCA-Internal-Cache-Task", ""},
				[]string{"proxy_set_header", "X-CDNCA-Cache-Namespace", ""},
				[]string{"proxy_hide_header", "X-CDNCA-Internal-Cache-Task"},
				[]string{"proxy_hide_header", "X-CDNCA-Cache-Namespace"})) {
			return ErrInvalidConfig
		}
		if listener.Policy.Mode == CacheDisabled {
			if nginxProxyCacheEnabled(document, 0, httpBlock, publicServer, publicLocation) {
				return ErrInvalidConfig
			}
			continue
		}

		internal, ok := internalLocations[listener.PrewarmPathPrefix]
		expectedUpstream := fmt.Sprintf("http://site_%04d", listenerIndex+1)
		if advanced {
			prewarmRoutes := prewarmPolicyRoutes[listener.PrewarmPathPrefix]
			plan := policyPlans[listener.PrewarmPathPrefix]
			freshness := cachePolicyFreshnessContract{}
			if len(freshnessBindings) == 1 {
				freshness = cachePolicyFreshnessContract{initialized: true, authoritative: true}
				if binding, present := freshnessBindings[0][listenerIndex]; present {
					freshness = binding
				}
			}
			if !validateCachePolicyDispatcher(document, publicLocation, runtimePolicy, listener, plan,
				manifest.TenantID, listenerIndex, false) ||
				!validateCachePolicyDispatcher(document, internal, runtimePolicy, listener, plan,
					manifest.TenantID, listenerIndex, true) || len(prewarmRoutes) != len(plan.Routes)+1 ||
				!validateCachePolicyRouteSet(document, prewarmRoutes, listener, expectedUpstream, manifest.ConfigVersionID, plan, listenerIndex, true,
					httpBlock, loopbackServer, healthLocation, trustedLocations, trustedReturnBlocks, cachePaths,
					usedCacheZones, &freshness) ||
				!validateCachePolicyRouteSet(document, publicPolicyRoutes, listener, expectedUpstream, manifest.ConfigVersionID, plan, listenerIndex, false,
					httpBlock, publicServer, healthLocation, trustedLocations, trustedReturnBlocks, cachePaths,
					usedCacheZones, &freshness) {
				return ErrInvalidConfig
			}
			continue
		}
		expectedKey := listener.KeyPrefix + `$uri$is_args$args`
		preliminaryFreshnessKey := "$cache_freshness_generation|$cache_freshness_object_token|" +
			cacheFreshnessIdentity(CacheFreshnessPolicy{
				TenantID: manifest.TenantID, SiteID: listener.SiteID, ConfigurationVersion: manifest.ConfigRevision,
			})
		if len(freshnessBindings) == 1 {
			if binding, present := freshnessBindings[0][listenerIndex]; present {
				expectedKey = binding.cacheKey[1]
			}
		} else if hasUnquotedDirectNginxDirectives(document, internal, []string{"proxy_cache_key", preliminaryFreshnessKey}) &&
			hasUnquotedDirectNginxDirectives(document, publicLocation, []string{"proxy_cache_key", preliminaryFreshnessKey}) {
			expectedKey = preliminaryFreshnessKey
		}
		var cacheInactiveSeconds []uint32
		if len(freshnessBindings) == 1 {
			if binding, present := freshnessBindings[0][listenerIndex]; present && binding.authoritative && binding.enabled {
				cacheInactiveSeconds = []uint32{binding.cacheInactiveSeconds}
			}
		}
		if !ok ||
			!hasReservedNginxHeaderContract(document, internal) ||
			!hasTrustedCacheReceiptContract(document, httpBlock, loopbackServer, healthLocation, internal,
				trustedLocations, trustedReturnBlocks) ||
			!hasDirectNginxGuard(document, internal,
				[]string{"if", "($request_method", "!=", "GET)"}, []string{"return", "405"}) ||
			!hasDirectNginxGuard(document, internal,
				[]string{"if", "($http_x_cdnca_internal_cache_task", "!=", "v2"}, []string{"return", "404"}) ||
			!hasDirectNginxGuard(document, internal,
				[]string{"if", "($http_x_cdnca_cache_namespace", "!=", listener.NamespaceID},
				[]string{"return", "404"}) ||
			!hasUnquotedDirectNginxDirectives(document, internal,
				[]string{"rewrite", nginxUnquotedField("^" + regexp.QuoteMeta(listener.PrewarmPathPrefix) + "(.*)$"), "/$1", "break"},
				[]string{"add_header", "X-CDNCA-Config-Version", manifest.ConfigVersionID, "always"},
				[]string{"add_header", "X-CDNCA-Cache-Namespace", listener.NamespaceID, "always"},
				[]string{"proxy_set_header", "Host", CachePrewarmHost([]string{listener.Domain})},
				[]string{"proxy_set_header", "X-Forwarded-For", ""},
				[]string{"proxy_set_header", "X-CDNCA-Internal-Cache-Task", ""},
				[]string{"proxy_set_header", "X-CDNCA-Cache-Namespace", ""},
				[]string{"proxy_hide_header", "X-CDNCA-Internal-Cache-Task"},
				[]string{"proxy_hide_header", "X-CDNCA-Cache-Namespace"},
				[]string{"proxy_cache_key", expectedKey},
				[]string{"proxy_pass", expectedUpstream}) {
			return ErrInvalidConfig
		}
		if !hasExactDirectNginxDirectives(document, internal,
			[]string{"rewrite", nginxUnquotedField("^" + regexp.QuoteMeta(listener.PrewarmPathPrefix) + "(.*)$"), "/$1", "break"},
			[]string{"proxy_pass", expectedUpstream}) {
			return ErrInvalidConfig
		}
		zone, ok := nginxCacheZone(document, internal, listener.NamespaceID)
		if !ok || !nginxCachePathBindsZone(cachePaths[zone], listener.NamespaceID, zone, listener.Policy.DiskQuotaBytes, cacheInactiveSeconds...) ||
			!hasUnquotedDirectNginxDirectives(document, internal,
				[]string{"proxy_cache", zone},
				[]string{"proxy_cache_key", expectedKey}) {
			return ErrInvalidConfig
		}
		usedCacheZones[zone] = struct{}{}
		if !hasExactDirectNginxDirectives(document, publicLocation,
			[]string{"proxy_cache", zone}, []string{"proxy_cache_key", expectedKey}) {
			rangeZone, rangeOK := nginxRangeCacheContract(document, httpBlock, publicLocation, cachePaths, manifest, listener)
			if !rangeOK {
				return ErrInvalidConfig
			}
			usedCacheZones[rangeZone] = struct{}{}
		}
	}
	if len(cachePaths) != len(usedCacheZones) {
		return ErrInvalidConfig
	}
	for zone := range cachePaths {
		if _, used := usedCacheZones[zone]; !used {
			return ErrInvalidConfig
		}
	}
	return nil
}

func hasPublicNginxListen(document *nginxDocument, httpBlock, loopbackServer int, port uint16) bool {
	if !validNginxListenerPlacement(document, httpBlock) {
		return true
	}
	for _, serverDirective := range nginxListenerServers(document, httpBlock) {
		server := serverDirective.blockID
		for _, directive := range document.directNamed(server, "listen") {
			candidate, _ := nginxListenPort(directive)
			if server != loopbackServer && candidate == port {
				return true
			}
		}
	}
	return false
}

// nginxListenerServers returns the server blocks that may carry listen
// directives: those of the http block and, for L4 streams, of the single
// top-level stream block.
func nginxListenerServers(document *nginxDocument, httpBlock int) []nginxDirective {
	servers := document.blockNamed(httpBlock, "server")
	if streamBlock, ok := uniqueUnquotedNginxBlock(document, 0, []string{"stream"}); ok {
		servers = append(slices.Clip(servers), document.blockNamed(streamBlock, "server")...)
	}
	return servers
}

func validNginxListenerPlacement(document *nginxDocument, httpBlock int) bool {
	servers := make(map[int]struct{})
	for _, serverDirective := range nginxListenerServers(document, httpBlock) {
		if serverDirective.nameQuoted || !equalNginxFields(serverDirective.fields, []string{"server"}) {
			return false
		}
		server := serverDirective.blockID
		servers[server] = struct{}{}
		listeners := document.directNamed(server, "listen")
		if len(listeners) == 0 {
			return false
		}
		for _, directive := range listeners {
			if _, ok := nginxListenPort(directive); directive.nameQuoted || !ok {
				return false
			}
		}
	}
	for parent, directives := range document.direct {
		if len(directives["listen"]) == 0 {
			continue
		}
		if _, directServer := servers[parent]; !directServer {
			return false
		}
	}
	for _, directives := range document.blockNames {
		if len(directives["listen"]) != 0 {
			return false
		}
	}
	return true
}

func nginxCacheZone(document *nginxDocument, block int, namespace string) (string, bool) {
	prefix := "cdnca_cache_" + namespace[:32] + "_"
	zone := ""
	for _, directive := range document.directNamed(block, "proxy_cache") {
		if len(directive.fields) != 2 || !strings.HasPrefix(directive.fields[1], prefix) ||
			!strings.HasSuffix(directive.fields[1], "m") || directive.fields[1] == prefix+"m" {
			return "", false
		}
		for _, value := range strings.TrimSuffix(strings.TrimPrefix(directive.fields[1], prefix), "m") {
			if value < '0' || value > '9' {
				return "", false
			}
		}
		if zone != "" {
			return "", false
		}
		zone = directive.fields[1]
	}
	return zone, zone != ""
}

func validateCachePolicyDispatcher(document *nginxDocument, block int, policy CachePolicy,
	listener CacheListenerPolicy, plan cachePolicyPlan, tenantID string, listenerIndex int, prewarm bool) bool {
	luaBlocks := document.blockIDs(block, []string{"access_by_lua_block"})
	if len(luaBlocks) != 1 ||
		!hasUnquotedDirectNginxDirectives(document, block,
			[]string{"set", "$cdnca_cache_policy_key", ""},
			[]string{"set", "$cdnca_cache_policy_bypass", "1"},
			[]string{"set", "$cdnca_cache_policy_routed", "0"}) {
		return false
	}
	if policy.QueryMode != listener.Policy.QueryMode || len(plan.Routes) == 0 {
		return false
	}
	dispatchLua := cachePolicyDispatchLua(listener.KeyPrefix, policy, plan, listenerIndex, prewarm)
	urlAuthLua := ""
	if !prewarm && listener.URLAuthPolicyID != "" {
		urlAuthLua = urlAuthCachePolicyPrefixLua(tenantID, listener.SiteID, listener.ListenPort)
	}
	gotLua := strings.TrimSpace(document.opaqueBodies[luaBlocks[0]])
	// The public dispatcher may run this listener's own JS challenge first
	// (renderCachePolicyDispatch); it only returns early, never routes.
	if gotLua != strings.TrimSpace(urlAuthLua+dispatchLua) && (prewarm ||
		gotLua != strings.TrimSpace(urlAuthLua+challengeCachePolicyPrefixLua(tenantID, listener.SiteID, listenerIndex)+dispatchLua)) {
		return false
	}
	for routeIndex := 0; routeIndex <= len(plan.Routes); routeIndex++ {
		if cachePolicyRouteName(listenerIndex, prewarm, routeIndex) == "" {
			return false
		}
	}
	return true
}

type cachePolicyFreshnessContract struct {
	initialized          bool
	enabled              bool
	authoritative        bool
	followOriginHeaders  bool
	fresh                string
	stale                string
	lockAge              string
	lockTimeout          string
	metadataTTL          string
	cacheInactiveSeconds uint32
	cacheKey             []string
	cacheBypass          []string
	noCache              []string
	nginxLockAge         string
	nginxLockTimeout     string
	backgroundUpdate     []string
	revalidation         []string
	useStale             []string
}

var (
	cachePolicyFreshnessDirectAccessPattern = regexp.MustCompile(`^ngx\.var\.cache_freshness_identity = ngx\.var\.cdnca_cache_policy_key\s+require\("cachefreshness\.guard"\)\.access\(\{ identity = ngx\.var\.cache_freshness_identity, request_bypass = ngx\.var\.cache_freshness_request_bypass == "1" or ngx\.var\.cdnca_cache_policy_bypass == "1", (follow_origin_headers = true, )?fresh_seconds = ([1-9][0-9]*), stale_seconds = ([1-9][0-9]*), lock_seconds = ([0-9]+\.[0-9]{3}), metadata_ttl_seconds = ([1-9][0-9]*) \}\)$`)
	cachePolicyFreshnessAliasAccessPattern  = regexp.MustCompile(`^ngx\.var\.cache_freshness_identity = ngx\.var\.cdnca_cache_policy_key\s+local cache_freshness_guard = require\("cachefreshness\.guard"\)\s+cache_freshness_guard\.access\(\{ identity = ngx\.var\.cache_freshness_identity, request_bypass = ngx\.var\.cache_freshness_request_bypass == "1" or ngx\.var\.cdnca_cache_policy_bypass == "1", (follow_origin_headers = true, )?fresh_seconds = ([1-9][0-9]*), stale_seconds = ([1-9][0-9]*), lock_seconds = ([0-9]+\.[0-9]{3}), metadata_ttl_seconds = ([1-9][0-9]*) \}\)$`)
	cachePolicyFreshnessHeaderPattern       = regexp.MustCompile(`^require\("cachefreshness\.guard"\)\.header_filter\(\{ identity = ngx\.var\.cache_freshness_identity, response_bypass = ngx\.var\.cache_freshness_response_bypass == "1", validator_bypass = ngx\.var\.cache_freshness_validator_bypass == "1", vary_bypass = ngx\.var\.cache_freshness_enhancement_vary_bypass == "1", (follow_origin_headers = true, )?fresh_seconds = ([1-9][0-9]*), stale_seconds = ([1-9][0-9]*), lock_timeout_seconds = ([0-9]+\.[0-9]{3}), metadata_ttl_seconds = ([1-9][0-9]*) \}\)$`)
)

func hasUnexpectedCacheFreshnessIdentityWrite(document *nginxDocument) bool {
	budget := cacheFreshnessLuaBudget{remaining: cacheFreshnessLuaMaxWork}
	return hasUnexpectedCacheFreshnessIdentityWriteWithBudget(document, &budget)
}

func hasUnexpectedCacheFreshnessIdentityWriteWithBudget(document *nginxDocument,
	budget *cacheFreshnessLuaBudget) bool {
	blockIDs := make([]int, 0, len(document.opaqueBodies))
	for blockID := range document.opaqueBodies {
		blockIDs = append(blockIDs, blockID)
	}
	sort.Ints(blockIDs)
	for _, blockID := range blockIDs {
		rawBody := document.opaqueBodies[blockID]
		writes, valid := cacheFreshnessLuaIdentityAssignmentScanWithBudget(rawBody, budget)
		body := strings.TrimSpace(rawBody)
		if !valid || writes &&
			!cachePolicyFreshnessDirectAccessPattern.MatchString(body) &&
			!cachePolicyFreshnessAliasAccessPattern.MatchString(body) {
			return true
		}
	}
	for _, directives := range document.direct {
		for name, candidates := range directives {
			if !strings.HasPrefix(name, "set_by_lua") {
				continue
			}
			for _, directive := range candidates {
				if len(directive.fields) >= 2 && directive.fields[1] == "$cache_freshness_identity" {
					return true
				}
			}
		}
	}
	for _, directives := range document.blockNames {
		for name, candidates := range directives {
			if !strings.HasPrefix(name, "set_by_lua") {
				continue
			}
			for _, directive := range candidates {
				if len(directive.fields) >= 2 && directive.fields[1] == "$cache_freshness_identity" {
					return true
				}
			}
		}
	}
	return false
}

func validateCachePolicyFreshnessRoute(document *nginxDocument, block int, direct bool,
	contract *cachePolicyFreshnessContract) bool {
	access := document.blockIDs(block, []string{"access_by_lua_block"})
	header := document.blockIDs(block, []string{"header_filter_by_lua_block"})
	body := document.blockIDs(block, []string{"body_filter_by_lua_block"})
	logBlocks := document.blockIDs(block, []string{"log_by_lua_block"})
	if !contract.initialized && len(access)+len(header)+len(body)+len(logBlocks) == 0 {
		contract.initialized = true
		return true
	}
	if contract.initialized && !contract.enabled {
		return len(access)+len(header)+len(body)+len(logBlocks) == 0
	}
	if len(access) != 1 || len(header) != 1 || len(body) != 1 || len(logBlocks) != 1 {
		return false
	}
	pattern := cachePolicyFreshnessAliasAccessPattern
	if direct {
		pattern = cachePolicyFreshnessDirectAccessPattern
	}
	accessValues := pattern.FindStringSubmatch(strings.TrimSpace(document.opaqueBodies[access[0]]))
	headerValues := cachePolicyFreshnessHeaderPattern.FindStringSubmatch(strings.TrimSpace(document.opaqueBodies[header[0]]))
	if len(accessValues) != 6 || len(headerValues) != 6 || accessValues[1] != headerValues[1] ||
		accessValues[2] != headerValues[2] || accessValues[3] != headerValues[3] || accessValues[5] != headerValues[5] ||
		strings.TrimSpace(document.opaqueBodies[body[0]]) != `require("cachefreshness.guard").body_filter()` ||
		strings.TrimSpace(document.opaqueBodies[logBlocks[0]]) !=
			`require("cachefreshness.guard").log({ identity = ngx.var.cache_freshness_identity })` {
		return false
	}
	followOriginHeaders := accessValues[1] != ""
	if !contract.initialized {
		contract.initialized, contract.enabled = true, true
		contract.followOriginHeaders = followOriginHeaders
		contract.fresh, contract.stale = accessValues[2], accessValues[3]
		contract.lockAge, contract.lockTimeout = accessValues[4], headerValues[4]
		contract.metadataTTL = accessValues[5]
		return true
	}
	return contract.enabled && contract.followOriginHeaders == followOriginHeaders &&
		contract.fresh == accessValues[2] && contract.stale == accessValues[3] &&
		contract.lockAge == accessValues[4] && contract.lockTimeout == headerValues[4] &&
		contract.metadataTTL == accessValues[5]
}

func validateCachePolicyRouteSet(document *nginxDocument, blocks []int, listener CacheListenerPolicy,
	expectedUpstream, configVersionID string, plan cachePolicyPlan, listenerIndex int, prewarm bool, httpBlock, server, healthLocation int,
	trustedLocations, trustedReturnBlocks map[int]struct{}, cachePaths map[string][]nginxDirective,
	usedCacheZones map[string]struct{}, freshness *cachePolicyFreshnessContract) bool {
	if len(blocks) != len(plan.Routes)+1 {
		return false
	}
	for index, block := range blocks {
		if !hasUnquotedDirectNginxDirectives(document, block, []string{"internal"}) ||
			!hasReservedNginxHeaderContract(document, block) ||
			!hasUnquotedDirectNginxDirectives(document, block, []string{"proxy_pass", expectedUpstream}) ||
			!validateCachePolicyFreshnessRoute(document, block, !prewarm && index == 0, freshness) {
			return false
		}
		if prewarm {
			if !hasUnquotedDirectNginxDirectives(document, block,
				[]string{"add_header", "X-CDNCA-Config-Version", configVersionID, "always"},
				[]string{"add_header", "X-CDNCA-Cache-Namespace", listener.NamespaceID, "always"},
				[]string{"proxy_set_header", "Host", CachePrewarmHost([]string{listener.Domain})},
				[]string{"proxy_set_header", "X-Forwarded-For", ""}) ||
				!hasTrustedCacheReceiptContract(document, httpBlock, server, healthLocation, block,
					trustedLocations, trustedReturnBlocks) {
				return false
			}
		}
		if index == 0 {
			if len(document.directNamed(block, "proxy_cache")) != 0 ||
				len(document.directNamed(block, "proxy_cache_key")) != 0 ||
				len(document.directNamed(block, "proxy_cache_valid")) != 0 {
				return false
			}
			continue
		}
		route := bindCachePolicyRouteVariables(plan.Routes[index-1], listenerIndex, index-1)
		if route.V2 {
			noCache := []string{"proxy_no_cache", "$cdnca_cache_method_bypass", "$cdnca_cache_authorization_bypass",
				"$cdnca_cache_cookie_bypass", "$cdnca_cache_upgrade_bypass", "$cdnca_cache_range_bypass",
				"$cdnca_cache_response_cookie_bypass", "$cdnca_cache_response_control_bypass", route.noCacheVariable}
			if freshness.enabled {
				noCache = []string{"proxy_no_cache", "$cache_freshness_request_bypass", "$cache_freshness_response_bypass",
					"$cache_freshness_validator_bypass", "$cache_freshness_fail_closed", route.noCacheVariable}
			}
			if !hasUnquotedDirectNginxDirectives(document, block, noCache,
				[]string{"expires", route.browserVariable}) {
				return false
			}
		}
		zone, ok := nginxCacheZone(document, block, listener.NamespaceID)
		cacheKey := []string{"proxy_cache_key", "$cdnca_cache_policy_key"}
		if freshness.enabled {
			cacheKey = []string{"proxy_cache_key", "$cache_freshness_generation|$cache_freshness_object_token|$cdnca_cache_policy_key"}
			if freshness.authoritative {
				cacheKey = freshness.cacheKey
			}
		}
		var cacheInactiveSeconds []uint32
		if freshness != nil && freshness.authoritative && freshness.enabled {
			cacheInactiveSeconds = []uint32{freshness.cacheInactiveSeconds}
		}
		if !ok || !hasUnquotedDirectNginxDirectives(document, block, cacheKey) ||
			!nginxCachePathBindsZone(cachePaths[zone], listener.NamespaceID, zone, listener.Policy.DiskQuotaBytes, cacheInactiveSeconds...) ||
			!validateCachePolicyRouteTTLs(document, block, cachePolicyDocumentRuntime(listener.Policy), route) {
			return false
		}
		if freshness.authoritative && freshness.enabled && !validateAuthoritativeCacheFreshnessDirectives(document, block, *freshness, route) {
			return false
		}
		usedCacheZones[zone] = struct{}{}
	}
	return true
}

func validateAuthoritativeCacheFreshnessDirectives(document *nginxDocument, block int,
	contract cachePolicyFreshnessContract, route cachePolicyRoute) bool {
	noCache := append([]string(nil), contract.noCache...)
	if route.V2 {
		noCache = append(noCache, route.noCacheVariable)
	}
	expected := [][]string{
		contract.cacheKey,
		contract.cacheBypass,
		noCache,
		{"proxy_cache_lock", "on"},
		{"proxy_cache_lock_age", contract.nginxLockAge},
		{"proxy_cache_lock_timeout", contract.nginxLockTimeout},
		contract.backgroundUpdate,
		contract.revalidation,
	}
	if contract.useStale != nil {
		expected = append(expected, contract.useStale)
	}
	if !hasExactDirectNginxDirectives(document, block, expected...) {
		return false
	}
	return contract.useStale != nil || len(document.directNamed(block, "proxy_cache_use_stale")) == 0
}

func validateCachePolicyActionMaps(document *nginxDocument, httpBlock, listenerIndex int, plan cachePolicyPlan) bool {
	for routeIndex, route := range plan.Routes {
		if !route.V2 {
			continue
		}
		route = bindCachePolicyRouteVariables(route, listenerIndex, routeIndex)
		defaultNoCache := "0"
		if route.NoCacheDefault {
			defaultNoCache = "1"
		}
		noCache := [][]string{{"default", defaultNoCache}}
		for _, value := range route.NoCacheStatuses {
			noCache = append(noCache, []string{strconv.Itoa(value.Status), value.Value})
		}
		browser := [][]string{{"default", route.BrowserDefault}}
		for _, value := range route.BrowserStatuses {
			browser = append(browser, []string{strconv.Itoa(value.Status), value.Value})
		}
		if !hasExactNginxMap(document, httpBlock, []string{"map", "$status", route.noCacheVariable}, noCache...) ||
			!hasExactNginxMap(document, httpBlock, []string{"map", "$status", route.browserVariable}, browser...) {
			return false
		}
	}
	return true
}

func validateCachePolicyRouteTTLs(document *nginxDocument, block int, policy CachePolicy, route cachePolicyRoute) bool {
	if len(policy.Rules) == 0 {
		return len(document.directNamed(block, "proxy_cache_valid")) > 0
	}
	expected := make(map[string]int, len(route.TTLGroups)+1)
	for _, group := range route.TTLGroups {
		fields := []string{"proxy_cache_valid"}
		for _, status := range group.Statuses {
			fields = append(fields, strconv.Itoa(status))
		}
		fields = append(fields, nginxCacheDuration(group.TTL))
		expected[nginxFieldsKey(fields)]++
	}
	wildcard := "0s"
	if route.WildcardTTL != 0 {
		wildcard = nginxCacheDuration(route.WildcardTTL)
	}
	expected[nginxFieldsKey([]string{"proxy_cache_valid", "any", wildcard})]++
	actual := document.directNamed(block, "proxy_cache_valid")
	if len(actual) != len(expected) {
		return false
	}
	for _, directive := range actual {
		key := nginxFieldsKey(directive.fields)
		if expected[key] == 0 {
			return false
		}
		expected[key]--
	}
	return true
}

func uniqueNginxBlock(document *nginxDocument, parent int, fields []string) (int, bool) {
	blocks := document.blockIDs(parent, fields)
	return onlyNginxBlock(blocks)
}

func uniqueUnquotedNginxBlock(document *nginxDocument, parent int, fields []string) (int, bool) {
	if len(fields) == 0 {
		return 0, false
	}
	blocks := make([]int, 0, 1)
	for _, directive := range document.blockNamed(parent, fields[0]) {
		if !equalNginxFields(directive.fields, fields) {
			continue
		}
		if directive.nameQuoted {
			return 0, false
		}
		blocks = append(blocks, directive.blockID)
	}
	return onlyNginxBlock(blocks)
}

func uniqueNginxBlockWithDirectives(document *nginxDocument, parent int, fields []string,
	expected ...[]string) (int, bool) {
	block := 0
	if len(fields) == 0 {
		return 0, false
	}
	for _, directive := range document.blockNamed(parent, fields[0]) {
		if !equalNginxFields(directive.fields, fields) {
			continue
		}
		if directive.nameQuoted {
			return 0, false
		}
		candidate := directive.blockID
		if !hasExactDirectNginxDirectives(document, candidate, expected...) {
			continue
		}
		if block != 0 {
			return 0, false
		}
		block = candidate
	}
	return block, block != 0
}

func uniquePublicNginxServer(document *nginxDocument, httpBlock int, domain string, listenPort uint16,
	expected ...[]string) (int, bool) {
	if !validNginxListenerPlacement(document, httpBlock) {
		return 0, false
	}
	candidates := make([]int, 0, 1)
	for _, directive := range document.blockNamed(httpBlock, "server") {
		if !equalNginxFields(directive.fields, []string{"server"}) {
			continue
		}
		if directive.nameQuoted {
			return 0, false
		}
		server := directive.blockID
		if !nginxServerClaimsDomain(document, server, domain) || !nginxServerListensPort(document, server, listenPort) {
			continue
		}
		candidates = append(candidates, server)
	}
	server, ok := onlyNginxBlock(candidates)
	return server, ok && hasExactDirectNginxDirectives(document, server, expected...)
}

func onlyNginxBlock(blocks []int) (int, bool) {
	if len(blocks) != 1 {
		return 0, false
	}
	return blocks[0], true
}

func nginxServerClaimsDomain(document *nginxDocument, server int, domain string) bool {
	for _, directive := range document.directNamed(server, "server_name") {
		if directive.nameQuoted {
			continue
		}
		for _, candidate := range directive.fields[1:] {
			if strings.EqualFold(candidate, domain) {
				return true
			}
		}
	}
	return false
}

func nginxServerListensPort(document *nginxDocument, server int, port uint16) bool {
	for _, directive := range document.directNamed(server, "listen") {
		if directive.nameQuoted {
			continue
		}
		if candidate, ok := nginxListenPort(directive); ok && candidate == port {
			return true
		}
	}
	return false
}

func nginxListenPort(directive nginxDirective) (uint16, bool) {
	if len(directive.fields) < 2 || len(directive.fieldQuoted) != len(directive.fields) || directive.fieldQuoted[1] ||
		directive.multiline {
		return 0, false
	}
	address := directive.fields[1]
	portValue := address
	if strings.Contains(address, ":") {
		host, candidatePort, err := net.SplitHostPort(address)
		if err != nil {
			return 0, false
		}
		parsed, err := netip.ParseAddr(host)
		if err != nil || parsed.String() != host {
			return 0, false
		}
		if parsed.Is4() && address != host+":"+candidatePort ||
			parsed.Is6() && address != "["+host+"]:"+candidatePort {
			return 0, false
		}
		portValue = candidatePort
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	return uint16(port), err == nil && port != 0 && portValue == strconv.FormatUint(port, 10)
}

func hasUnexpectedPublicNginxLocation(document *nginxDocument, server, publicLocation int, allowedLocations ...int) bool {
	acme := []string{"location", "~", `^/\.well-known/acme-challenge/(?<cdnca_acme_token>[A-Za-z0-9_-]{22,256})$`}
	allowed := make(map[int]struct{}, len(allowedLocations)+1)
	allowed[publicLocation] = struct{}{}
	for _, location := range allowedLocations {
		allowed[location] = struct{}{}
	}
	for _, directive := range document.blockNamed(server, "location") {
		if _, ok := allowed[directive.blockID]; !ok && !equalNginxFields(directive.fields, acme) {
			return true
		}
	}
	blocks := append([]int(nil), allowedLocations...)
	blocks = append(blocks, publicLocation)
	for len(blocks) > 0 {
		block := blocks[len(blocks)-1]
		blocks = blocks[:len(blocks)-1]
		for name, directives := range document.blockNames[block] {
			if name == "location" {
				return true
			}
			for _, directive := range directives {
				blocks = append(blocks, directive.blockID)
			}
		}
	}
	return false
}

type nginxDirective struct {
	fields      []string
	fieldQuoted []bool
	parentBlock int
	blockID     int
	nameQuoted  bool
	multiline   bool
}

const (
	maxNginxDirectives         = 131_072
	maxNginxTokens             = 524_288
	maxNginxFieldsPerDirective = 64
	maxNginxTokenBytes         = 64 << 10
)

type nginxDocument struct {
	blocks         map[int]map[string][]int
	blockNames     map[int]map[string][]nginxDirective
	direct         map[int]map[string][]nginxDirective
	directExact    map[int]map[string]int
	childCounts    map[int]int
	locationCounts map[string]int
	directiveCount int
	hasInclude     bool
	opaqueBodies   map[int]string
}

// wafEngineGateInclude reports whether an include is one of the engine gate
// globs (IsWAFEngineInclude) in its context: load at main level, the others
// inside a block. Its files are written only by the agent after the engine
// extension verified (RenderWAFEngineGate), never taken from the bundle.
func wafEngineGateInclude(directive nginxDirective) bool {
	if len(directive.fields) != 2 || directive.blockID != 0 || len(directive.fieldQuoted) > 1 && directive.fieldQuoted[1] ||
		!IsWAFEngineInclude(directive.fields[1]) {
		return false
	}
	return strings.HasSuffix(directive.fields[1], "/load[.]conf") == (directive.parentBlock == 0)
}

func newNginxDocument() *nginxDocument {
	return &nginxDocument{
		blocks: make(map[int]map[string][]int), blockNames: make(map[int]map[string][]nginxDirective),
		direct:      make(map[int]map[string][]nginxDirective),
		directExact: make(map[int]map[string]int), childCounts: make(map[int]int),
		locationCounts: make(map[string]int), opaqueBodies: make(map[int]string),
	}
}

func (document *nginxDocument) add(directive nginxDirective) bool {
	if document.directiveCount >= maxNginxDirectives || len(directive.fields) == 0 {
		return false
	}
	document.directiveCount++
	if directive.fields[0] == "include" && !wafEngineGateInclude(directive) {
		document.hasInclude = true
	}
	document.childCounts[directive.parentBlock]++
	if directive.blockID != 0 {
		byFields := document.blocks[directive.parentBlock]
		if byFields == nil {
			byFields = make(map[string][]int)
			document.blocks[directive.parentBlock] = byFields
		}
		key := nginxFieldsKey(directive.fields)
		byFields[key] = append(byFields[key], directive.blockID)
		byName := document.blockNames[directive.parentBlock]
		if byName == nil {
			byName = make(map[string][]nginxDirective)
			document.blockNames[directive.parentBlock] = byName
		}
		byName[directive.fields[0]] = append(byName[directive.fields[0]], directive)
		if directive.fields[0] == "location" && len(directive.fields) >= 2 {
			path := directive.fields[len(directive.fields)-1]
			document.locationCounts[path]++
		}
		return true
	}
	byName := document.direct[directive.parentBlock]
	if byName == nil {
		byName = make(map[string][]nginxDirective)
		document.direct[directive.parentBlock] = byName
	}
	byName[directive.fields[0]] = append(byName[directive.fields[0]], directive)
	byFields := document.directExact[directive.parentBlock]
	if byFields == nil {
		byFields = make(map[string]int)
		document.directExact[directive.parentBlock] = byFields
	}
	byFields[nginxFieldsKey(directive.fields)]++
	return true
}

func (document *nginxDocument) blockIDs(parent int, fields []string) []int {
	return document.blocks[parent][nginxFieldsKey(fields)]
}

func (document *nginxDocument) directNamed(parent int, name string) []nginxDirective {
	return document.direct[parent][name]
}

func (document *nginxDocument) blockNamed(parent int, name string) []nginxDirective {
	return document.blockNames[parent][name]
}

func nginxFieldsKey(fields []string) string {
	var key strings.Builder
	for _, field := range fields {
		key.WriteString(strconv.Itoa(len(field)))
		key.WriteByte(':')
		key.WriteString(field)
	}
	return key.String()
}

func parseNginxDirectives(content string) (*nginxDocument, bool) {
	document := newNginxDocument()
	fields := make([]string, 0, 4)
	fieldQuoted := make([]bool, 0, 4)
	var token strings.Builder
	tokenCount := 0
	tokenStarted := false
	tokenQuoted := false
	firstFieldQuoted := false
	depth := 0
	blocks := []int{0}
	nextBlockID := 0
	var quote byte
	escaped := false
	quoteClosed := false
	variable := false
	comment := false
	multiline := false
	flushToken := func() bool {
		if tokenStarted {
			tokenCount++
			if tokenCount > maxNginxTokens || len(fields) >= maxNginxFieldsPerDirective {
				return false
			}
			fields = append(fields, token.String())
			fieldQuoted = append(fieldQuoted, tokenQuoted)
			token.Reset()
			tokenStarted = false
			tokenQuoted = false
		}
		return true
	}
	reset := func() {
		token.Reset()
		tokenStarted = false
		firstFieldQuoted = false
		variable = false
		multiline = false
		fields = fields[:0]
		fieldQuoted = fieldQuoted[:0]
	}
	emit := func(blockID int) bool {
		if len(fields) == 0 {
			return false
		}
		return document.add(nginxDirective{
			fields: append([]string(nil), fields...), fieldQuoted: append([]bool(nil), fieldQuoted...),
			parentBlock: blocks[len(blocks)-1], blockID: blockID,
			nameQuoted: firstFieldQuoted, multiline: multiline,
		})
	}
	openBlock := func(index int) (int, bool) {
		if !flushToken() {
			return index, false
		}
		nextBlockID++
		if !emit(nextBlockID) {
			return index, false
		}
		opaque := isOpaqueNginxBlock(fields)
		reset()
		if opaque {
			closing, ok := nginxOpaqueBlockEnd(content, index+1)
			if ok {
				document.opaqueBodies[nextBlockID] = content[index+1 : closing]
			}
			return closing, ok
		}
		blocks = append(blocks, nextBlockID)
		depth++
		return index, true
	}
	for index := 0; index < len(content); index++ {
		value := content[index]
		if comment {
			if value == '\n' {
				comment = false
				if tokenStarted || len(fields) != 0 {
					multiline = true
				}
			}
			continue
		}
		if quote != 0 {
			if escaped {
				if token.Len()+nginxEscapedSize(value) > maxNginxTokenBytes {
					return nil, false
				}
				appendNginxEscaped(&token, value)
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == quote {
				quote = 0
				quoteClosed = true
			} else {
				if token.Len() >= maxNginxTokenBytes {
					return nil, false
				}
				token.WriteByte(value)
			}
			continue
		}
		if escaped {
			if token.Len()+nginxEscapedSize(value) > maxNginxTokenBytes {
				return nil, false
			}
			appendNginxEscaped(&token, value)
			escaped = false
			continue
		}
		if quoteClosed {
			switch value {
			case '{':
				var ok bool
				index, ok = openBlock(index)
				if !ok {
					return nil, false
				}
				quoteClosed = false
				continue
			case ')':
				if !flushToken() {
					return nil, false
				}
				quoteClosed = false
				continue
			}
			quoteClosed = false
		}
		if value == '{' && variable {
			if token.Len() >= maxNginxTokenBytes {
				return nil, false
			}
			token.WriteByte(value)
			variable = false
			continue
		}
		if value != '$' {
			variable = false
		}
		switch value {
		case '#':
			if tokenStarted {
				if token.Len() >= maxNginxTokenBytes {
					return nil, false
				}
				token.WriteByte(value)
			} else {
				comment = true
			}
		case '\'', '"':
			tokenQuoted = true
			if !tokenStarted && len(fields) == 0 {
				firstFieldQuoted = true
			}
			tokenStarted = true
			quote = value
		case '\\':
			tokenStarted = true
			escaped = true
		case ' ', '\t', '\r', '\n':
			if (value == '\r' || value == '\n') && (tokenStarted || len(fields) != 0) {
				multiline = true
			}
			if !flushToken() {
				return nil, false
			}
		case '{':
			if tokenStarted {
				if token.Len() >= maxNginxTokenBytes {
					return nil, false
				}
				token.WriteByte(value)
				continue
			}
			var ok bool
			index, ok = openBlock(index)
			if !ok {
				return nil, false
			}
		case '}':
			if tokenStarted {
				if token.Len() >= maxNginxTokenBytes {
					return nil, false
				}
				token.WriteByte(value)
				continue
			}
			if len(fields) != 0 || len(blocks) == 1 {
				return nil, false
			}
			reset()
			depth--
			blocks = blocks[:len(blocks)-1]
			if depth < 0 {
				return nil, false
			}
		case ';':
			if !flushToken() {
				return nil, false
			}
			if len(fields) != 0 {
				if !emit(0) {
					return nil, false
				}
			}
			reset()
		default:
			if token.Len() >= maxNginxTokenBytes {
				return nil, false
			}
			tokenStarted = true
			token.WriteByte(value)
			if value == '$' {
				variable = true
			}
		}
	}
	return document, quote == 0 && !escaped && depth == 0 && len(blocks) == 1 && !tokenStarted && len(fields) == 0
}

func nginxEscapedSize(value byte) int {
	switch value {
	case '"', '\'', '\\', 't', 'r', 'n':
		return 1
	default:
		return 2
	}
}

func appendNginxEscaped(field *strings.Builder, value byte) {
	switch value {
	case '"', '\'', '\\':
		field.WriteByte(value)
	case 't':
		field.WriteByte('\t')
	case 'r':
		field.WriteByte('\r')
	case 'n':
		field.WriteByte('\n')
	default:
		field.WriteByte('\\')
		field.WriteByte(value)
	}
}

func nginxUnquotedField(value string) string {
	var field strings.Builder
	field.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+1 < len(value) {
			index++
			appendNginxEscaped(&field, value[index])
			continue
		}
		field.WriteByte(value[index])
	}
	return field.String()
}

func isOpaqueNginxBlock(fields []string) bool {
	return len(fields) != 0 && strings.HasSuffix(fields[0], "_by_lua_block")
}

func nginxOpaqueBlockEnd(content string, start int) (int, bool) {
	depth := 1
	var quote byte
	escaped := false
	lineComment := false
	for index := start; index < len(content); index++ {
		value := content[index]
		if lineComment {
			if value == '\n' {
				lineComment = false
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == quote {
				quote = 0
			}
			continue
		}
		if value == '-' && index+1 < len(content) && content[index+1] == '-' {
			if closing, bodyStart, ok := luaLongBracket(content, index+2); ok {
				closingAt := strings.Index(content[bodyStart:], closing)
				if closingAt < 0 {
					return 0, false
				}
				index = bodyStart + closingAt + len(closing) - 1
				continue
			}
			lineComment = true
			index++
			continue
		}
		if value == '[' {
			if closing, bodyStart, ok := luaLongBracket(content, index); ok {
				closingAt := strings.Index(content[bodyStart:], closing)
				if closingAt < 0 {
					return 0, false
				}
				index = bodyStart + closingAt + len(closing) - 1
				continue
			}
		}
		switch value {
		case '\'', '"':
			quote = value
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return index, true
			}
		}
	}
	return 0, false
}

func luaLongBracket(content string, start int) (string, int, bool) {
	if start >= len(content) || content[start] != '[' {
		return "", 0, false
	}
	index := start + 1
	for index < len(content) && content[index] == '=' {
		index++
	}
	if index >= len(content) || content[index] != '[' {
		return "", 0, false
	}
	equals := content[start+1 : index]
	return "]" + equals + "]", index + 1, true
}

func hasDirectNginxDirectives(document *nginxDocument, block int, expected ...[]string) bool {
	for _, want := range expected {
		if document.directExact[block][nginxFieldsKey(want)] != 1 {
			return false
		}
	}
	return true
}

func hasUnquotedDirectNginxDirectives(document *nginxDocument, block int, expected ...[]string) bool {
	for _, want := range expected {
		if len(want) == 0 {
			return false
		}
		count := 0
		for _, directive := range document.directNamed(block, want[0]) {
			if !directive.nameQuoted && equalNginxFields(directive.fields, want) {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}

func hasReservedNginxHeaderContract(document *nginxDocument, block int) bool {
	reserved := map[string]struct{}{
		"x-cdnca-internal-cache-task": {},
		"x-cdnca-cache-namespace":     {},
	}
	set, hidden := make(map[string]int), make(map[string]int)
	for name, directives := range document.direct[block] {
		if name != "proxy_set_header" && name != "proxy_hide_header" && name != "proxy_pass_header" {
			continue
		}
		for _, directive := range directives {
			if len(directive.fields) < 2 {
				continue
			}
			header := strings.ToLower(directive.fields[1])
			if _, ok := reserved[header]; !ok {
				continue
			}
			switch name {
			case "proxy_set_header":
				if len(directive.fields) != 3 || directive.fields[1] != canonicalReservedNginxHeader(header) ||
					directive.fields[2] != "" {
					return false
				}
				set[header]++
			case "proxy_hide_header":
				if len(directive.fields) != 2 || directive.fields[1] != canonicalReservedNginxHeader(header) {
					return false
				}
				hidden[header]++
			case "proxy_pass_header":
				return false
			}
		}
	}
	for header := range reserved {
		if set[header] != 1 || hidden[header] != 1 {
			return false
		}
	}
	return true
}

func canonicalReservedNginxHeader(header string) string {
	switch header {
	case "x-cdnca-internal-cache-task":
		return "X-CDNCA-Internal-Cache-Task"
	case "x-cdnca-cache-namespace":
		return "X-CDNCA-Cache-Namespace"
	default:
		return ""
	}
}

func hasForbiddenInheritedProxyPassHeader(document *nginxDocument, blocks ...int) bool {
	forbidden := map[string]struct{}{
		"x-cdn-cache":                 {},
		"x-cdnca-internal-cache-task": {},
		"x-cdnca-cache-namespace":     {},
	}
	for _, block := range blocks {
		for _, directive := range document.directNamed(block, "proxy_pass_header") {
			if len(directive.fields) < 2 {
				continue
			}
			if _, found := forbidden[strings.ToLower(directive.fields[1])]; found {
				return true
			}
		}
	}
	return false
}

func hasTrustedCacheReceiptContract(document *nginxDocument, httpBlock, server, healthLocation, location int,
	trustedLocations, trustedReturnBlocks map[int]struct{}) bool {
	if hasCacheReceiptAuthoringLua(document, httpBlock) {
		return false
	}
	for name, directives := range document.direct[httpBlock] {
		if !strings.HasPrefix(name, "more_") {
			continue
		}
		for _, directive := range directives {
			if nginxDirectiveTouchesCacheReceipt(directive) {
				return false
			}
		}
	}
	addSource := ""
	for _, directive := range document.directNamed(location, "add_header") {
		if len(directive.fields) < 2 || !strings.EqualFold(directive.fields[1], "X-CDN-Cache") {
			continue
		}
		if addSource != "" || len(directive.fields) != 4 || directive.fields[1] != "X-CDN-Cache" ||
			directive.fields[3] != "always" {
			return false
		}
		addSource = directive.fields[2]
	}
	hideCount := 0
	for _, directive := range document.directNamed(location, "proxy_hide_header") {
		if len(directive.fields) < 2 || !strings.EqualFold(directive.fields[1], "X-CDN-Cache") {
			continue
		}
		if len(directive.fields) != 2 || directive.fields[1] != "X-CDN-Cache" {
			return false
		}
		hideCount++
	}
	if hideCount != 1 {
		return false
	}
	for _, directive := range document.directNamed(location, "proxy_pass_header") {
		if len(directive.fields) >= 2 && strings.EqualFold(directive.fields[1], "X-CDN-Cache") {
			return false
		}
	}
	if addSource == "" || hasUntrustedCacheReceiptPath(document, server, healthLocation, addSource,
		trustedLocations, trustedReturnBlocks) {
		return false
	}
	switch addSource {
	case "$cdnca_cache_header":
		return hasExactNginxMap(document, httpBlock,
			[]string{"map", "$cdnca_cache_safe_bypass:$upstream_cache_status", "$cdnca_cache_header"},
			[]string{"default", "BYPASS"}, []string{"0:HIT", "HIT"}, []string{"0:STALE", "HIT"},
			[]string{"0:UPDATING", "HIT"}, []string{"0:REVALIDATED", "HIT"},
			[]string{"0:MISS", "MISS"}, []string{"0:EXPIRED", "MISS"})
	case "$cache_freshness_cache_header":
		return hasExactNginxMap(document, httpBlock,
			[]string{"map", "$cache_freshness_request_bypass:$cache_freshness_response_bypass:$cache_freshness_validator_bypass:$upstream_cache_status", "$cache_freshness_cache_header"},
			[]string{"default", "BYPASS"}, []string{"0:0:0:HIT", "HIT"}, []string{"0:0:0:STALE", "HIT"},
			[]string{"0:0:0:UPDATING", "HIT"}, []string{"0:0:0:REVALIDATED", "HIT"},
			[]string{"0:0:0:MISS", "MISS"}, []string{"0:0:0:EXPIRED", "MISS"})
	default:
		return false
	}
}

func isCacheReceiptVariable(source, variable string) bool {
	switch source {
	case "$cdnca_cache_header":
		return variable == "$cdnca_cache_header" || variable == "$cdnca_cache_safe_bypass"
	case "$cache_freshness_cache_header":
		return variable == "$cache_freshness_cache_header" ||
			variable == "$cache_freshness_request_bypass" ||
			variable == "$cache_freshness_response_bypass" ||
			variable == "$cache_freshness_validator_bypass"
	default:
		return false
	}
}

func hasUntrustedCacheReceiptPath(document *nginxDocument, server, healthLocation int, source string,
	trustedLocations, trustedReturnBlocks map[int]struct{}) bool {
	blocks := []int{server}
	for len(blocks) > 0 {
		block := blocks[len(blocks)-1]
		blocks = blocks[:len(blocks)-1]
		_, trustedLocation := trustedLocations[block]
		for name, directives := range document.direct[block] {
			if nginxCanAuthorResponseInLua(name) && !(trustedLocation && name == "access_by_lua_block") {
				return true
			}
			for _, directive := range directives {
				if name == "set" && len(directive.fields) >= 2 && isCacheReceiptVariable(source, directive.fields[1]) {
					return true
				}
				switch name {
				case "return":
					_, guardReturn := trustedReturnBlocks[block]
					if block != healthLocation && !guardReturn {
						return true
					}
				case "add_header", "proxy_hide_header", "proxy_pass_header":
					if !trustedLocation && len(directive.fields) >= 2 && strings.EqualFold(directive.fields[1], "X-CDN-Cache") {
						return true
					}
				case "rewrite":
					if !trustedLocation {
						return true
					}
				case "proxy_pass":
					if !trustedLocation {
						return true
					}
				case "error_page":
					return true
				default:
					if strings.HasPrefix(name, "more_") && nginxDirectiveTouchesCacheReceipt(directive) {
						return true
					}
				}
			}
		}
		for name, directives := range document.blockNames[block] {
			if nginxCanAuthorResponseInLua(name) {
				trustedAccess := trustedLocation && name == "access_by_lua_block" && len(directives) == 1 &&
					trustedCacheReceiptAccess(document, directives[0])
				trustedFreshnessFilter := trustedLocation && len(directives) == 1 &&
					trustedCacheFreshnessReceiptFilter(document, name, directives[0], source)
				if !trustedAccess && !trustedFreshnessFilter {
					return true
				}
			}
			for _, directive := range directives {
				if name == "location" {
					_, trustedChild := trustedLocations[directive.blockID]
					if block != server || directive.blockID != healthLocation && !trustedChild {
						return true
					}
				}
				blocks = append(blocks, directive.blockID)
			}
		}
	}
	return false
}

func trustedCacheReceiptAccess(document *nginxDocument, directive nginxDirective) bool {
	body := strings.TrimSpace(document.opaqueBodies[directive.blockID])
	return cachePolicyFreshnessAliasAccessPattern.MatchString(body) ||
		strings.HasPrefix(body, `return require("cachepolicy.key").dispatch({`) && strings.HasSuffix(body, "\n        })")
}

var trustedCacheFreshnessHeaderFilter = regexp.MustCompile(`^require\("cachefreshness\.guard"\)\.header_filter\(\{ identity = ngx\.var\.cache_freshness_identity, response_bypass = ngx\.var\.cache_freshness_response_bypass == "1", validator_bypass = ngx\.var\.cache_freshness_validator_bypass == "1", vary_bypass = ngx\.var\.cache_freshness_enhancement_vary_bypass == "1", (follow_origin_headers = true, )?fresh_seconds = [1-9][0-9]*, stale_seconds = [1-9][0-9]*, lock_timeout_seconds = [0-9]+\.[0-9]{3}, metadata_ttl_seconds = [1-9][0-9]* \}\)$`)

func trustedCacheFreshnessReceiptFilter(document *nginxDocument, name string, directive nginxDirective, source string) bool {
	if source != "$cache_freshness_cache_header" {
		return false
	}
	body := strings.TrimSpace(document.opaqueBodies[directive.blockID])
	switch name {
	case "header_filter_by_lua_block":
		return trustedCacheFreshnessHeaderFilter.MatchString(body)
	case "body_filter_by_lua_block":
		return body == `require("cachefreshness.guard").body_filter()`
	case "log_by_lua_block":
		return body == `require("cachefreshness.guard").log({ identity = ngx.var.cache_freshness_identity })`
	default:
		return false
	}
}

func nginxDirectiveTouchesCacheReceipt(directive nginxDirective) bool {
	for _, field := range directive.fields[1:] {
		if strings.Contains(strings.ToLower(field), "x-cdn-cache") {
			return true
		}
	}
	return false
}

func hasCacheReceiptAuthoringLua(document *nginxDocument, blocks ...int) bool {
	for _, block := range blocks {
		for name := range document.direct[block] {
			if nginxCanAuthorResponseInLua(name) {
				return true
			}
		}
		for name := range document.blockNames[block] {
			if nginxCanAuthorResponseInLua(name) {
				return true
			}
		}
	}
	return false
}

func nginxCanAuthorResponseInLua(name string) bool {
	for _, prefix := range []string{
		"set_by_lua", "rewrite_by_lua", "access_by_lua", "content_by_lua",
		"header_filter_by_lua", "body_filter_by_lua",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func hasExactNginxMap(document *nginxDocument, parent int, fields []string, expected ...[]string) bool {
	block, ok := uniqueUnquotedNginxBlock(document, parent, fields)
	return ok && document.childCounts[block] == len(expected) && hasDirectNginxDirectives(document, block, expected...)
}

func hasExactDirectNginxDirectives(document *nginxDocument, block int, expected ...[]string) bool {
	if !hasUnquotedDirectNginxDirectives(document, block, expected...) {
		return false
	}
	wantNames := make(map[string]int)
	for _, fields := range expected {
		if len(fields) == 0 {
			return false
		}
		wantNames[fields[0]]++
	}
	seenNames := make(map[string]int)
	for name := range wantNames {
		for range document.directNamed(block, name) {
			seenNames[name]++
		}
	}
	for name, count := range wantNames {
		if seenNames[name] != count {
			return false
		}
	}
	return true
}

func hasDirectNginxGuard(document *nginxDocument, block int, header, action []string) bool {
	_, ok := nginxGuardBlock(document, block, header, action)
	return ok
}

func nginxGuardBlock(document *nginxDocument, block int, header, action []string) (int, bool) {
	guardBlock, ok := uniqueUnquotedNginxBlock(document, block, header)
	if !ok || document.childCounts[guardBlock] != 1 {
		return 0, false
	}
	return guardBlock, hasUnquotedDirectNginxDirectives(document, guardBlock, action)
}

func equalNginxFields(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func indexNginxCachePaths(document *nginxDocument, httpBlock int) (map[string][]nginxDirective, bool) {
	result := make(map[string][]nginxDirective)
	for _, directive := range document.directNamed(httpBlock, "proxy_cache_path") {
		if directive.nameQuoted || len(directive.fields) < 4 || !safeAbsolutePath(directive.fields[1]) {
			return nil, false
		}
		zoneAndSize := ""
		for _, field := range directive.fields[2:] {
			if strings.HasPrefix(field, "keys_zone=") {
				if zoneAndSize != "" {
					return nil, false
				}
				zoneAndSize = strings.TrimPrefix(field, "keys_zone=")
			}
		}
		separator := strings.LastIndexByte(zoneAndSize, ':')
		if separator <= 0 || separator == len(zoneAndSize)-1 {
			return nil, false
		}
		zone := zoneAndSize[:separator]
		if _, exists := result[zone]; exists {
			return nil, false
		}
		result[zone] = append(result[zone], directive)
	}
	return result, true
}

func nginxProxyCacheEnabled(document *nginxDocument, blocks ...int) bool {
	for index := len(blocks) - 1; index >= 0; index-- {
		directives := document.directNamed(blocks[index], "proxy_cache")
		if len(directives) == 0 {
			continue
		}
		return len(directives) != 1 || len(directives[0].fields) != 2 || directives[0].fields[1] != "off"
	}
	return false
}

func nginxCachePathBindsZone(directives []nginxDirective, namespace, zone string, diskQuotaBytes int64,
	expectedInactiveSeconds ...uint32) bool {
	if len(directives) != 1 || len(expectedInactiveSeconds) > 1 || diskQuotaBytes <= 0 || diskQuotaBytes%cacheSizeUnit != 0 {
		return false
	}
	if len(expectedInactiveSeconds) == 1 && expectedInactiveSeconds[0] == 0 {
		return false
	}
	prefix := "cdnca_cache_" + namespace[:32] + "_"
	zoneSize := strings.TrimPrefix(zone, prefix)
	zoneSizeValue, err := strconv.ParseUint(strings.TrimSuffix(zoneSize, "m"), 10, 64)
	if err != nil || zoneSizeValue == 0 || zoneSize != strconv.FormatUint(zoneSizeValue, 10)+"m" {
		return false
	}
	pathSuffix := "/shared/cache/" + namespace
	for _, directive := range directives {
		fields := directive.fields
		inactiveOK := false
		if len(fields) == 7 {
			inactiveOK = validNginxCacheInactive(fields[5])
			if len(expectedInactiveSeconds) == 1 {
				inactiveOK = fields[5] == "inactive="+strconv.FormatUint(uint64(expectedInactiveSeconds[0]), 10)+"s"
			}
		}
		if len(fields) != 7 ||
			fields[0] != "proxy_cache_path" || !strings.HasSuffix(fields[1], pathSuffix) ||
			!safeAbsolutePath(strings.TrimSuffix(fields[1], pathSuffix)) || fields[2] != "levels=1:2" ||
			fields[3] != "keys_zone="+zone+":"+zoneSize || fields[4] != "max_size="+nginxCacheSize(diskQuotaBytes) ||
			!inactiveOK || fields[6] != "use_temp_path=off" {
			continue
		}
		return true
	}
	return false
}

func nginxRangeCacheContract(document *nginxDocument, httpBlock, block int, cachePaths map[string][]nginxDirective,
	manifest CachePolicyManifest, listener CacheListenerPolicy) (string, bool) {
	if !hasExactNginxMap(document, httpBlock,
		[]string{"map", "$upstream_http_vary", "$range_cache_vary"},
		[]string{"default", "1"}, []string{"", "0"}) ||
		!hasExactNginxMap(document, httpBlock,
			[]string{"map", "$http_range", "$range_cache_effective_range"},
			[]string{"volatile"}, []string{"default", "$slice_range"}, []string{"~,", "$http_range"}) ||
		!hasExactDirectNginxDirectives(document, block,
			[]string{"max_ranges", strconv.Itoa(RangeCacheMaxRanges)},
			[]string{"proxy_no_cache", "$range_cache_method_bypass", "$cdnca_cache_authorization_bypass", "$cdnca_cache_cookie_bypass", "$cdnca_cache_upgrade_bypass"},
			[]string{"proxy_no_cache", "$range_cache_guard_no_store", "$range_cache_encoded", "$range_cache_unknown_length", "$range_cache_vary", "$cdnca_cache_response_cookie_bypass", "$cdnca_cache_response_control_bypass"}) {
		return "", false
	}
	rangeHeaders := 0
	for _, directive := range document.directNamed(block, "proxy_set_header") {
		if len(directive.fields) < 2 || !strings.EqualFold(directive.fields[1], "range") {
			continue
		}
		rangeHeaders++
		if directive.nameQuoted || !equalNginxFields(directive.fields,
			[]string{"proxy_set_header", "Range", "$range_cache_effective_range"}) {
			return "", false
		}
	}
	if rangeHeaders != 1 {
		return "", false
	}
	identity := RangeCacheIdentity(manifest.TenantID, listener.SiteID, listener.Domain, listener.ListenPort)
	zone := "range_cache_" + identity
	cacheKeyDirectives := document.directNamed(block, "proxy_cache_key")
	if len(cacheKeyDirectives) != 1 || len(cacheKeyDirectives[0].fields) != 2 ||
		!hasExactDirectNginxDirectives(document, block, []string{"proxy_cache", zone}, cacheKeyDirectives[0].fields) {
		return "", false
	}
	prefix := "v=" + manifest.ConfigVersionID + "|policy="
	suffix := "|tenant=" + manifest.TenantID + "|site=" + listener.SiteID +
		"|range=$range_cache_effective_range|scheme=$scheme|host=$host|port=$server_port|request=$request_uri"
	key := cacheKeyDirectives[0].fields[1]
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return "", false
	}
	policyVersion := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
	version, err := strconv.ParseUint(policyVersion, 10, 64)
	if err != nil || version == 0 || version > RangeCacheMaxPolicyVersion || policyVersion != strconv.FormatUint(version, 10) {
		return "", false
	}
	directives := cachePaths[zone]
	if len(directives) != 1 {
		return "", false
	}
	fields := directives[0].fields
	pathSuffix := "/shared/range/" + identity
	if len(fields) != 7 || fields[0] != "proxy_cache_path" || !strings.HasSuffix(fields[1], pathSuffix) ||
		!safeAbsolutePath(strings.TrimSuffix(fields[1], pathSuffix)) || fields[2] != "levels=1:2" ||
		fields[3] != "keys_zone="+zone+":1m" || !validNginxPositiveUnit(fields[4], "inactive=", "s") ||
		fields[6] != "use_temp_path=off" || !strings.HasPrefix(fields[5], "max_size=") {
		return "", false
	}
	maxSizeText := strings.TrimPrefix(fields[5], "max_size=")
	maxSize, err := strconv.ParseInt(maxSizeText, 10, 64)
	return zone, err == nil && maxSize > 0 && maxSize <= RangeCacheMaxCacheBytes && maxSizeText == strconv.FormatInt(maxSize, 10)
}

func validNginxCacheInactive(value string) bool {
	return validNginxPositiveUnit(value, "inactive=", "smhd")
}

func validNginxPositiveUnit(value, prefix, units string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	numberWithUnit := strings.TrimPrefix(value, prefix)
	if len(numberWithUnit) < 2 || !strings.ContainsRune(units, rune(numberWithUnit[len(numberWithUnit)-1])) {
		return false
	}
	numberValue := numberWithUnit[:len(numberWithUnit)-1]
	number, err := strconv.ParseUint(numberValue, 10, 64)
	return err == nil && number > 0 && numberValue == strconv.FormatUint(number, 10)
}

func nginxNamedBlock(content, opening string) (string, bool) {
	if strings.Count(content, opening) != 1 {
		return "", false
	}
	return nginxBlockAt(content, strings.Index(content, opening))
}

func nginxBlockAt(content string, start int) (string, bool) {
	if start < 0 {
		return "", false
	}
	brace := strings.IndexByte(content[start:], '{')
	if brace < 0 {
		return "", false
	}
	brace += start
	depth := 0
	inSingle, inDouble, escaped, comment := false, false, false, false
	for index := brace; index < len(content); index++ {
		value := content[index]
		if comment {
			if value == '\n' {
				comment = false
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if (inSingle || inDouble) && value == '\\' {
			escaped = true
			continue
		}
		if !inSingle && !inDouble && value == '#' {
			comment = true
			continue
		}
		if !inDouble && value == '\'' {
			inSingle = !inSingle
			continue
		}
		if !inSingle && value == '"' {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}
		switch value {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[start : index+1], true
			}
			if depth < 0 {
				return "", false
			}
		}
	}
	return "", false
}
