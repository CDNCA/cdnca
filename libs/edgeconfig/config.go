package edgeconfig

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type BalanceMethod string
type Protocol string
type StreamProtocol string
type ACLAction string
type WAFAction string
type WAFControl string
type WAFPathKind string
type WAFHeaderKind string
type SecurityKind string
type CacheMode string

const (
	BalanceIPHash     BalanceMethod = "ip_hash"
	BalanceRoundRobin BalanceMethod = "round_robin"
	BalanceURLHash    BalanceMethod = "url_hash"
	BalanceLeastConn  BalanceMethod = "least_conn"
	BalanceRandom     BalanceMethod = "random"
)

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
)

const (
	StreamProtocolTCP StreamProtocol = "tcp"
	StreamProtocolUDP StreamProtocol = "udp"
)

const (
	ACLAllow ACLAction = "allow"
	ACLDeny  ACLAction = "deny"
)

const (
	WAFAllow WAFAction = "allow"
	WAFBlock WAFAction = "block"
	WAFDeny  WAFAction = WAFBlock
	WAFLog   WAFAction = "log"
)

const (
	WAFContinue WAFControl = "continue"
	WAFStop     WAFControl = "stop"
)

const (
	WAFPathExact     WAFPathKind = "exact"
	WAFPathPrefix    WAFPathKind = "prefix"
	WAFPathRawPrefix WAFPathKind = "raw_prefix"
)

const (
	WAFHeaderExists WAFHeaderKind = "exists"
	WAFHeaderExact  WAFHeaderKind = "exact"
)

const (
	SecurityACL SecurityKind = "acl"
	SecurityWAF SecurityKind = "waf"

	MaxSecurityRulesPerSite = 128
)

const (
	CacheDisabled     CacheMode = "disabled"
	CacheFollowOrigin CacheMode = "follow_origin"
	CacheOverride     CacheMode = "override"
)

const (
	cacheSizeUnit         int64 = 1 << 20
	minCacheZoneSize            = cacheSizeUnit
	maxCacheZoneSize            = 256 << 20
	legacyMaxCacheSize    int64 = 1 << 40
	signedMaxCacheSize    int64 = 16 << 40
	maxAggregateZoneSize  int64 = 1 << 30
	maxAggregateCacheSize int64 = 16 << 40
	maxCacheStatusTTLs          = 32
)

var (
	ErrInvalidConfig = errors.New("invalid site configuration")
	hostLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	streamIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	versionPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	methodPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,15}$`)
)

type Spec struct {
	ConfigVersionID string
	ConfigRevision  uint64
	// TenantID is the tenant (tenants.id) for telemetry and cache identity.
	TenantID string
	// TenantScopeID is the configuration scope (access_scopes.id) CC v2
	// policies are compiled for. Empty means TenantID, for callers whose
	// tenant and scope share one ID.
	TenantScopeID  string
	InstallationID string
	StateRoot      string
	HealthPort     uint16
	AllowEmpty     bool
	// SharedL4Ports lets v2 streams share ports with websites and with each
	// other under FindPortConflicts; agents need tcp/udp API v4 to serve such
	// a bundle. Unset, every v2 socket is exclusive as before.
	SharedL4Ports bool
	Nginx         *NginxSettings
	Sites         []Site
	L4StreamsV2   []L4StreamRuntimeV2
	CRSRules      *CRSRuleText
	// CRSProfiles are the CRS profile packs (rulepack.CRSProfileOf) the
	// sites' managed WAF may select (Site.ManagedWAF.Profile, by digest).
	CRSProfiles []CRSProfile
	// CRSApps are the application exclusion packs (rulepack.CRSAppOf) the
	// sites' managed WAF selects.
	CRSApps []CRSApp
}

type NginxSettings struct {
	WorkerProcesses       int
	WorkerRlimitNoFile    int
	WorkerShutdownTimeout time.Duration
	WorkerConnections     int
	ResolverAddresses     []string
	ResolverTimeout       time.Duration
	GzipLevel             int
	GzipMinimumBytes      int64
	GzipVary              bool
	// GzipDisabled turns gzip off node-wide; GzipTypes are the MIME types
	// compressed besides text/html (系统设置 > 网站默认 > 其它 > Gzip).
	// Sites override both (edgeconfig.SiteCompression).
	GzipDisabled        bool
	GzipTypes           []string
	ProxyBuffering      bool
	ProxyCacheMethods   []string
	ProxyCacheMaxBytes  int64
	ProxyCacheZoneBytes int64
	// ProxyCacheMinFreeBytes keeps this much of the cache file system free
	// (nginx min_free; site runtime v2): below it the cache manager evicts.
	ProxyCacheMinFreeBytes int64
	ProxyMaxTempFileBytes  int64
	ProxyConnectTimeout    time.Duration
	ProxySendTimeout       time.Duration
	ProxyReadTimeout       time.Duration
	StreamProxyTimeout     time.Duration
	ServerHeader           string
	ClientMaxBodyBytes     int64
	DefaultMIMEType        string
	KeepaliveRequests      int
	KeepaliveTimeout       time.Duration
	LogNotFound            bool
	ServerNamesHashMaxSize int
	ServerTokens           bool
	// The rest render only when set (a document from before these
	// fields existed leaves them zero and keeps the earlier behavior):
	// GzipHTTPVersion "1.0"/"1.1"; ProxyHTTPVersion "" = 1.1;
	// ProxyNextUpstream nil = error timeout http_502 http_503 http_504;
	// LargeClientHeaderBuffers count/size and ServerNamesHashBucketSize 0 =
	// nginx's default; ProxyRequestBufferingDisabled renders
	// proxy_request_buffering off; ServerAddrOutgoing binds every origin
	// connection to the address the client reached (入口 IP 回源).
	GzipHTTPVersion               string
	ProxyRequestBufferingDisabled bool
	ProxyHTTPVersion              string
	ProxyNextUpstream             []string
	LargeClientHeaderBufferCount  int
	LargeClientHeaderBufferBytes  int64
	ServerNamesHashBucketSize     int
	ServerAddrOutgoing            bool
	// ClientBodyBufferBytes renders client_body_buffer_size (0 = nginx's).
	ClientBodyBufferBytes int64
}

// nginxDefaultMIMEPattern is the control plane's default_type rule
// (systemconfig mimeTypePattern): an RFC 7230 token type/subtype.
var nginxDefaultMIMEPattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+/[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

// ProxyNextUpstreamConditions are the accepted ProxyNextUpstream values in
// canonical order ("off" only alone).
var ProxyNextUpstreamConditions = []string{"error", "timeout", "invalid_header", "http_500", "http_502", "http_503",
	"http_504", "http_403", "http_404", "http_429", "non_idempotent", "off"}

type ChallengeBinding struct {
	PolicyID      string
	PolicyVersion uint64
}

type Site struct {
	ID                    string
	PackageSubscriptionID string
	PackageConnections    *int64
	Domain                string
	Domains               []string
	ListenPort            uint16
	IPv6Enabled           *bool
	Protocol              Protocol
	TLS                   *TLSConfig
	HTTP2                 bool
	Origins               []Origin
	Balance               BalanceMethod
	FailoverTries         uint8
	ConnectTimeout        time.Duration
	ReadTimeout           time.Duration
	// OriginKeepaliveIdleTimeout overrides origin connection reuse: nil keeps
	// the node nginx default (1.29.7+: 32 idle connections, 60s), 0 is off.
	OriginKeepaliveIdleTimeout *time.Duration
	WebSocket                  bool
	Range                      bool
	ACL                        ACLPolicy
	WAF                        WAFPolicy
	SecurityPolicies           []SecurityPolicy
	ManagedWAF                 *ManagedWAF
	Cache                      CachePolicy
	CacheFreshness             *CacheFreshnessPolicy
	RangeCache                 *RangeCachePolicy
	TelemetryCapture           TelemetryCapturePolicy
	CCV2                       *CCV2SiteBinding
	URLAuth                    *URLAuthBinding
	Challenge                  *ChallengeBinding
	// cacheKeyHost replaces Domain in the simple cache key (site runtime v2
	// host-keyed caches: "$cdnca_cache_host"); empty keys by Domain.
	cacheKeyHost string
}

// cacheKeyDomain is the domain field of the site's simple cache key.
func (site Site) cacheKeyDomain() string {
	if site.cacheKeyHost != "" {
		return site.cacheKeyHost
	}
	return site.Domain
}

type URLAuthBinding struct {
	PolicyID string
}

type TLSConfig struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Protocols      []string
}

type ACLPolicy struct {
	Rules         []ACLRule
	DefaultAction ACLAction
}

type ACLRule struct {
	Action ACLAction
	CIDR   string
}

type WAFPolicy struct {
	DefaultAction WAFAction `json:"default_action,omitempty"`
	Rules         []WAFRule `json:"rules"`
}

type SecurityPolicy struct {
	Kind            SecurityKind `json:"kind"`
	PolicyID        string       `json:"policy_id"`
	PolicyVersion   int64        `json:"policy_version"`
	BindingRevision int64        `json:"binding_revision"`
	RuntimeSHA256   string       `json:"runtime_sha256"`
	Enabled         bool         `json:"enabled"`
	DefaultAction   WAFAction    `json:"default_action"`
	Rules           []WAFRule    `json:"rules"`
	// Mode observe (WAF only): every decision is recorded as log, nothing is
	// blocked, challenged or banned. AutoBlock (WAF only): ban a client after
	// repeated block / challenge decisions. Both need WAF v2 (waf_action.go).
	Mode      WAFMode       `json:"mode,omitempty"`
	AutoBlock *WAFAutoBlock `json:"auto_block,omitempty"`
}

type WAFRule struct {
	RuleID    string     `json:"rule_id,omitempty"`
	Comment   string     `json:"comment,omitempty"`
	ExpiresAt string     `json:"expires_at,omitempty"`
	Match     WAFMatch   `json:"match"`
	Action    WAFAction  `json:"action"`
	Control   WAFControl `json:"flow"`
	// ActionConfig: the parameters of a challenge or ban rule (waf_action.go).
	ActionConfig *WAFActionConfig `json:"action_config,omitempty"`
}

type WAFMatch struct {
	Host       string          `json:"host,omitempty"`
	Port       uint16          `json:"port,omitempty"`
	Method     string          `json:"method,omitempty"`
	Path       *WAFPathMatch   `json:"path,omitempty"`
	Header     *WAFHeaderMatch `json:"header,omitempty"`
	SourceCIDR string          `json:"source_cidr,omitempty"`
	Inspect    []WAFInspect    `json:"inspect,omitempty"`
	// JA4 matches when the request's TLS client fingerprint ($cdnca_ja4)
	// equals one of the values (sorted, unique). Bound security policies
	// only; it needs CAPABILITY_NAME_JA4 on the node.
	JA4 []string `json:"ja4,omitempty"`
	// NotJA4 matches when the request has a TLS client fingerprint and it is
	// none of the values (sorted, unique). Never set with JA4.
	// Bound security policies only; it needs CAPABILITY_NAME_JA4 and
	// CAPABILITY_NAME_WAF_JA4_NEGATION on the node.
	NotJA4 []string `json:"not_ja4,omitempty"`
	// IPIntel conditions on the client address' carrier / IDC tags, ASN,
	// country, province or city (WAFIPIntel). Bound security policies only;
	// it needs CAPABILITY_NAME_IP_INTEL v2 on the node.
	IPIntel []WAFIPIntel `json:"ip_intel,omitempty"`
	// IPLists: the client address is (or, negated, is not) in a named IP
	// list (WAFIPList). Bound security policies only; it
	// needs CAPABILITY_NAME_WAF v4.
	IPLists []WAFIPList `json:"ip_lists,omitempty"`
}

type WAFPathMatch struct {
	Kind  WAFPathKind `json:"kind"`
	Value string      `json:"value"`
}

type WAFHeaderMatch struct {
	Name  string        `json:"name"`
	Kind  WAFHeaderKind `json:"kind"`
	Value string        `json:"value,omitempty"`
}

type CachePolicy struct {
	SchemaVersion        int
	Revision             uint64
	Mode                 CacheMode
	ZoneSizeBytes        int64
	MaxSizeBytes         int64
	DefaultTTL           time.Duration
	StatusTTLs           []CacheStatusTTL
	StaleOnUpstreamError bool
	Rules                []CacheRule
	QueryMode            CacheQueryMode
	QueryNames           []string
	VaryHeaders          []string
	// Site runtime v2 extensions (CachePolicyDocument): stale-if-error
	// window, background update, stored object size bounds, slice size.
	StaleIfError     bool
	BackgroundUpdate bool
	MinObjectBytes   int64
	MaxObjectBytes   int64
	SliceBytes       int64
}

type CacheStatusTTL struct {
	Status int
	TTL    time.Duration
}

type Origin struct {
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	Weight uint8  `json:"weight"`
}

type normalizedSpec struct {
	ConfigVersionID string
	ConfigRevision  uint64
	TenantID        string
	InstallationID  string
	StateRoot       string
	HealthPort      uint16
	Nginx           *NginxSettings
	Sites           []Site
	L4StreamsV2     []L4StreamRuntimeV2
	ManagedWAF      *managedWAFRelease
}

func normalize(spec Spec) (normalizedSpec, error) {
	if !versionPattern.MatchString(spec.ConfigVersionID) || spec.HealthPort == 0 ||
		(!spec.AllowEmpty && len(spec.Sites) == 0 && len(spec.L4StreamsV2) == 0) ||
		len(spec.Sites) > 1000 || len(spec.L4StreamsV2) > 1000 {
		return normalizedSpec{}, ErrInvalidConfig
	}
	if !safeAbsolutePath(spec.StateRoot) {
		return normalizedSpec{}, ErrInvalidConfig
	}
	nginx, err := normalizeNginxSettings(spec.Nginx)
	if err != nil {
		return normalizedSpec{}, err
	}
	if _, err := PackageConnectionZones(sitePackageConnections(spec.Sites)); err != nil {
		return normalizedSpec{}, err
	}
	sites := make([]Site, len(spec.Sites))
	copy(sites, spec.Sites)
	for index := range sites {
		if sites[index].PackageConnections != nil {
			value := *sites[index].PackageConnections
			sites[index].PackageConnections = &value
		}
	}
	telemetryEnabled := spec.TenantID != ""
	if telemetryEnabled && !uuidPattern.MatchString(spec.TenantID) ||
		spec.InstallationID != "" && !uuidPattern.MatchString(spec.InstallationID) ||
		spec.TenantScopeID != "" && !uuidPattern.MatchString(spec.TenantScopeID) {
		return normalizedSpec{}, ErrInvalidConfig
	}
	tenantScopeID := spec.TenantScopeID
	if tenantScopeID == "" {
		tenantScopeID = spec.TenantID
	}
	seen := make(map[string]struct{}, len(sites))
	seenSiteDomains := make(map[string]string, len(sites))
	seenSiteCaches := make(map[string]CachePolicy, len(sites))
	urlAuthPolicies := make(map[string]string, len(sites))
	urlAuthSites := make(map[string]string, len(sites))
	cacheBudgets := make(map[string]struct{}, len(sites))
	portProtocols := make(map[uint16]Protocol, len(sites))
	var aggregateCacheZoneSize int64
	var aggregateCacheSize int64
	var aggregateRangeCacheSize int64
	rangeCacheSites := 0
	for siteIndex := range sites {
		site := &sites[siteIndex]
		if telemetryEnabled != (site.ID != "") || site.ID != "" && !uuidPattern.MatchString(site.ID) {
			return normalizedSpec{}, ErrInvalidConfig
		}
		if site.PackageSubscriptionID != "" && !uuidPattern.MatchString(site.PackageSubscriptionID) {
			return normalizedSpec{}, ErrInvalidConfig
		}
		if site.ID != "" {
			if domain, exists := seenSiteDomains[site.ID]; exists && domain != site.Domain {
				return normalizedSpec{}, ErrInvalidConfig
			}
			seenSiteDomains[site.ID] = site.Domain
		}
		if site.Challenge != nil && (!uuidPattern.MatchString(spec.TenantID) ||
			!uuidPattern.MatchString(site.ID) || !uuidPattern.MatchString(site.Challenge.PolicyID) ||
			site.Challenge.PolicyVersion == 0 || site.Challenge.PolicyVersion > 1<<53-1) {
			return normalizedSpec{}, ErrInvalidConfig
		}
		domain, err := normalizeSiteDomainName(site.Domain)
		if err != nil || site.ListenPort == 0 || site.ListenPort == spec.HealthPort ||
			!validBalance(site.Balance) || !validTimeout(site.ConnectTimeout, 50*time.Millisecond, 30*time.Second) ||
			!validTimeout(site.ReadTimeout, 100*time.Millisecond, 5*time.Minute) || len(site.Origins) == 0 || len(site.Origins) > 64 ||
			site.OriginKeepaliveIdleTimeout != nil && *site.OriginKeepaliveIdleTimeout != 0 &&
				!validTimeout(*site.OriginKeepaliveIdleTimeout, time.Second, 5*time.Minute) ||
			site.FailoverTries == 0 || int(site.FailoverTries) > len(site.Origins) {
			return normalizedSpec{}, ErrInvalidConfig
		}
		site.Domain = domain
		site.Domains, err = normalizeSiteDomains(domain, site.Domains)
		if err != nil {
			return normalizedSpec{}, err
		}
		if err := validateProtocol(site); err != nil {
			return normalizedSpec{}, err
		}
		acl, err := normalizeACL(site.ACL)
		if err != nil {
			return normalizedSpec{}, err
		}
		site.ACL = acl
		waf, err := normalizeWAF(site.WAF)
		if err != nil {
			return normalizedSpec{}, err
		}
		site.WAF = waf
		securityPolicies, err := normalizeSecurityPolicies(site.SecurityPolicies)
		if err != nil {
			return normalizedSpec{}, err
		}
		site.SecurityPolicies = securityPolicies
		managedWAF, err := normalizeManagedWAF(site.ManagedWAF)
		if err != nil || managedWAF != nil && !uuidPattern.MatchString(site.ID) {
			return normalizedSpec{}, ErrInvalidConfig
		}
		site.ManagedWAF = managedWAF
		ccV2, err := normalizeCCV2SiteBinding(tenantScopeID, *site)
		if err != nil {
			return normalizedSpec{}, err
		}
		site.CCV2 = ccV2
		if site.URLAuth != nil {
			if !telemetryEnabled || site.ID == "" || !uuidPattern.MatchString(site.URLAuth.PolicyID) {
				return normalizedSpec{}, ErrInvalidConfig
			}
			if boundSite, exists := urlAuthPolicies[site.URLAuth.PolicyID]; exists && boundSite != site.ID {
				return normalizedSpec{}, ErrInvalidConfig
			}
			if boundPolicy, exists := urlAuthSites[site.ID]; exists && boundPolicy != site.URLAuth.PolicyID {
				return normalizedSpec{}, ErrInvalidConfig
			}
			urlAuthPolicies[site.URLAuth.PolicyID] = site.ID
			urlAuthSites[site.ID] = site.URLAuth.PolicyID
		}
		cache, err := normalizeCache(site.Cache, spec.ConfigRevision != 0)
		if err != nil {
			return normalizedSpec{}, err
		}
		site.Cache = cache
		if site.ID != "" {
			if previous, exists := seenSiteCaches[site.ID]; exists && !equalCachePolicy(previous, cache) {
				return normalizedSpec{}, ErrInvalidConfig
			}
			seenSiteCaches[site.ID] = cache
		}
		if cache.Mode != CacheDisabled {
			budgetKey := site.ID
			if budgetKey == "" {
				budgetKey = site.Domain + "\x00" + strconv.Itoa(int(site.ListenPort))
			}
			if _, exists := cacheBudgets[budgetKey]; !exists {
				if aggregateCacheZoneSize > maxAggregateZoneSize-cache.ZoneSizeBytes ||
					aggregateCacheSize > maxAggregateCacheSize-cache.MaxSizeBytes {
					return normalizedSpec{}, ErrInvalidConfig
				}
				aggregateCacheZoneSize += cache.ZoneSizeBytes
				aggregateCacheSize += cache.MaxSizeBytes
				cacheBudgets[budgetKey] = struct{}{}
			}
		}
		if site.RangeCache != nil {
			if !site.Range || !telemetryEnabled {
				return normalizedSpec{}, ErrInvalidConfig
			}
			policy, err := NormalizeRangeCachePolicy(*site.RangeCache)
			if err != nil {
				return normalizedSpec{}, err
			}
			if cachePolicyAdvanced(cache) {
				return normalizedSpec{}, ErrInvalidConfig
			}
			rangeCacheSites++
			if rangeCacheSites > RangeCacheMaxSites || aggregateRangeCacheSize > rangeCacheMaxAggregateBytes-policy.CacheMaxBytes {
				return normalizedSpec{}, ErrInvalidConfig
			}
			aggregateRangeCacheSize += policy.CacheMaxBytes
			site.RangeCache = &policy
		}
		if protocol, exists := portProtocols[site.ListenPort]; exists && protocol != site.Protocol {
			return normalizedSpec{}, ErrInvalidConfig
		}
		portProtocols[site.ListenPort] = site.Protocol
		for _, configuredDomain := range site.Domains {
			key := strconv.Itoa(int(site.ListenPort)) + "\x00" + configuredDomain
			if _, exists := seen[key]; exists {
				return normalizedSpec{}, ErrInvalidConfig
			}
			seen[key] = struct{}{}
		}
		origins := make([]Origin, len(site.Origins))
		copy(origins, site.Origins)
		originSeen := make(map[string]struct{}, len(origins))
		for originIndex := range origins {
			origin := &origins[originIndex]
			host, err := normalizeOriginHost(origin.Host)
			if err != nil || origin.Port == 0 || origin.Weight == 0 || origin.Weight > 100 {
				return normalizedSpec{}, ErrInvalidConfig
			}
			origin.Host = host
			originKey := originEndpoint(*origin)
			if _, exists := originSeen[originKey]; exists {
				return normalizedSpec{}, ErrInvalidConfig
			}
			originSeen[originKey] = struct{}{}
		}
		sort.Slice(origins, func(i, j int) bool {
			left, right := originEndpoint(origins[i]), originEndpoint(origins[j])
			if left != right {
				return left < right
			}
			return origins[i].Weight < origins[j].Weight
		})
		site.Origins = origins
		freshness, err := normalizeSiteCacheFreshness(*site)
		if err != nil {
			return normalizedSpec{}, err
		}
		site.CacheFreshness = freshness
		if site.RangeCache != nil && freshness != nil {
			return normalizedSpec{}, ErrInvalidConfig
		}
		capture, err := normalizeTelemetryCapturePolicy(site.TelemetryCapture)
		if err != nil || capture.Enabled && (!telemetryEnabled || freshness != nil) ||
			capture.Enabled && len(capture.ResponseBodyFieldAllowlist) > 0 && site.RangeCache != nil {
			return normalizedSpec{}, ErrInvalidConfig
		}
		site.TelemetryCapture = capture
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].ListenPort != sites[j].ListenPort {
			return sites[i].ListenPort < sites[j].ListenPort
		}
		return sites[i].Domain < sites[j].Domain
	})
	streamIDs := map[string]struct{}{}
	streamListeners := map[string]struct{}{}
	portProtocols[spec.HealthPort] = ProtocolHTTP
	occupiedPorts := portProtocols
	if spec.SharedL4Ports {
		occupiedPorts = map[uint16]Protocol{spec.HealthPort: ProtocolHTTP}
	}
	l4StreamsV2, err := normalizeL4StreamsV2(spec.TenantID, spec.L4StreamsV2, occupiedPorts, streamListeners, streamIDs, spec.SharedL4Ports)
	if err != nil {
		return normalizedSpec{}, err
	}
	if spec.SharedL4Ports {
		var claims []PortClaim
		for _, site := range sites {
			https := site.Protocol == ProtocolHTTPS
			names := append([]string{site.Domain}, site.Domains...)
			claims = append(claims, SiteListenerPortClaims("", site.ID+"\x00"+site.Domain, site.ListenPort, https, https, names)...)
		}
		for _, stream := range l4StreamsV2 {
			claims = append(claims, L4StreamPortClaims("", stream)...)
		}
		if len(FindPortConflicts(claims)) != 0 {
			return normalizedSpec{}, ErrInvalidConfig
		}
	}
	managedWAF, err := resolveManagedWAFRelease(sites, spec.CRSRules, spec.CRSProfiles, false, spec.CRSApps...)
	if err != nil {
		return normalizedSpec{}, err
	}
	if managedWAF != nil {
		if _, err := renderManagedWAFMain(managedWAF, spec.StateRoot); err != nil {
			return normalizedSpec{}, ErrInvalidConfig
		}
	}
	return normalizedSpec{
		ManagedWAF:      managedWAF,
		ConfigVersionID: spec.ConfigVersionID,
		ConfigRevision:  spec.ConfigRevision,
		TenantID:        spec.TenantID,
		InstallationID:  spec.InstallationID,
		StateRoot:       spec.StateRoot,
		HealthPort:      spec.HealthPort,
		Nginx:           nginx,
		Sites:           sites,
		L4StreamsV2:     l4StreamsV2,
	}, nil
}

func normalizeNginxSettings(input *NginxSettings) (*NginxSettings, error) {
	if input == nil {
		return nil, nil
	}
	value := *input
	value.ResolverAddresses = slices.Clone(input.ResolverAddresses)
	value.ProxyCacheMethods = slices.Clone(input.ProxyCacheMethods)
	value.ProxyNextUpstream = slices.Clone(input.ProxyNextUpstream)
	value.GzipTypes = slices.Clone(input.GzipTypes)
	if len(value.GzipTypes) > MaxSiteCompressionTypes*2 {
		return nil, ErrInvalidConfig
	}
	for index, mime := range value.GzipTypes {
		if len(mime) > 128 || !siteAccessMIMEPattern.MatchString(mime) || index > 0 && value.GzipTypes[index-1] >= mime {
			return nil, ErrInvalidConfig
		}
	}
	if len(value.GzipTypes) == 0 {
		value.GzipTypes = nil
	}
	if value.WorkerProcesses < 0 || value.WorkerProcesses > 256 ||
		value.WorkerRlimitNoFile < 1024 || value.WorkerRlimitNoFile > 1_048_576 ||
		value.WorkerShutdownTimeout < time.Second || value.WorkerShutdownTimeout > 5*time.Minute ||
		value.WorkerConnections < 128 || value.WorkerConnections > value.WorkerRlimitNoFile ||
		len(value.ResolverAddresses) < 1 || len(value.ResolverAddresses) > 4 ||
		value.ResolverTimeout < 100*time.Millisecond || value.ResolverTimeout > 30*time.Second ||
		value.GzipLevel < 1 || value.GzipLevel > 9 || value.GzipMinimumBytes < 0 || value.GzipMinimumBytes > 1<<30 ||
		value.ProxyCacheMaxBytes < 0 || value.ProxyCacheMaxBytes > 1<<50 ||
		value.ProxyCacheZoneBytes < 1<<20 || value.ProxyCacheZoneBytes > 1<<34 ||
		value.ProxyCacheMinFreeBytes < 0 || value.ProxyCacheMinFreeBytes > 1<<44 || value.ProxyCacheMinFreeBytes%(1<<20) != 0 ||
		value.ProxyMaxTempFileBytes < 0 || value.ProxyMaxTempFileBytes > 1<<40 ||
		value.ProxyConnectTimeout < 100*time.Millisecond || value.ProxyConnectTimeout > 75*time.Second ||
		value.ProxySendTimeout < 100*time.Millisecond || value.ProxySendTimeout > time.Hour ||
		value.ProxyReadTimeout < 100*time.Millisecond || value.ProxyReadTimeout > time.Hour ||
		value.StreamProxyTimeout < 100*time.Millisecond || value.StreamProxyTimeout > 24*time.Hour ||
		value.ClientMaxBodyBytes < 1024 || value.ClientMaxBodyBytes > 10<<30 ||
		value.KeepaliveRequests < 1 || value.KeepaliveRequests > 1_000_000 ||
		value.KeepaliveTimeout < 100*time.Millisecond || value.KeepaliveTimeout > time.Hour ||
		value.ServerNamesHashMaxSize < 512 || value.ServerNamesHashMaxSize > 65_536 ||
		value.ServerNamesHashMaxSize&(value.ServerNamesHashMaxSize-1) != 0 ||
		len(value.DefaultMIMEType) > 128 || !nginxDefaultMIMEPattern.MatchString(value.DefaultMIMEType) ||
		(value.ServerHeader != "" && (!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`).MatchString(value.ServerHeader) ||
			strings.IndexFunc(value.ServerHeader, unicode.IsControl) >= 0)) {
		return nil, ErrInvalidConfig
	}
	seenResolvers := make(map[string]struct{}, len(value.ResolverAddresses))
	for index, raw := range value.ResolverAddresses {
		address, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || address.Zone() != "" || raw != strings.TrimSpace(raw) {
			return nil, ErrInvalidConfig
		}
		canonical := address.Unmap().String()
		if _, exists := seenResolvers[canonical]; exists {
			return nil, ErrInvalidConfig
		}
		seenResolvers[canonical] = struct{}{}
		value.ResolverAddresses[index] = canonical
	}
	sort.Strings(value.ResolverAddresses)
	seenMethods := make(map[string]struct{}, len(value.ProxyCacheMethods))
	if len(value.ProxyCacheMethods) < 1 || len(value.ProxyCacheMethods) > 2 {
		return nil, ErrInvalidConfig
	}
	for _, method := range value.ProxyCacheMethods {
		if method != "GET" && method != "HEAD" {
			return nil, ErrInvalidConfig
		}
		if _, exists := seenMethods[method]; exists {
			return nil, ErrInvalidConfig
		}
		seenMethods[method] = struct{}{}
	}
	sort.Strings(value.ProxyCacheMethods)
	if value.GzipHTTPVersion != "" && value.GzipHTTPVersion != "1.0" && value.GzipHTTPVersion != "1.1" ||
		value.ProxyHTTPVersion != "" && value.ProxyHTTPVersion != "1.0" && value.ProxyHTTPVersion != "1.1" ||
		(value.LargeClientHeaderBufferCount == 0) != (value.LargeClientHeaderBufferBytes == 0) ||
		value.LargeClientHeaderBufferCount < 0 || value.LargeClientHeaderBufferCount > 32 ||
		value.LargeClientHeaderBufferBytes != 0 && (value.LargeClientHeaderBufferBytes < 1024 || value.LargeClientHeaderBufferBytes > 1<<20) ||
		value.ClientBodyBufferBytes < 0 || value.ClientBodyBufferBytes > 1<<30 ||
		value.ServerNamesHashBucketSize != 0 && (value.ServerNamesHashBucketSize < 32 || value.ServerNamesHashBucketSize > 1024 ||
			value.ServerNamesHashBucketSize&(value.ServerNamesHashBucketSize-1) != 0) {
		return nil, ErrInvalidConfig
	}
	if len(value.ProxyNextUpstream) == 0 {
		value.ProxyNextUpstream = nil
	} else {
		selected := make(map[string]bool, len(value.ProxyNextUpstream))
		for _, condition := range value.ProxyNextUpstream {
			if !slices.Contains(ProxyNextUpstreamConditions, condition) || selected[condition] {
				return nil, ErrInvalidConfig
			}
			selected[condition] = true
		}
		if selected["off"] && len(selected) != 1 {
			return nil, ErrInvalidConfig
		}
		value.ProxyNextUpstream = value.ProxyNextUpstream[:0:0]
		for _, condition := range ProxyNextUpstreamConditions {
			if selected[condition] {
				value.ProxyNextUpstream = append(value.ProxyNextUpstream, condition)
			}
		}
	}
	return &value, nil
}

// NginxProxyHTTPVersion is the proxy_http_version a location renders.
func NginxProxyHTTPVersion(value NginxSettings) string {
	if value.ProxyHTTPVersion == "" {
		return "1.1"
	}
	return value.ProxyHTTPVersion
}

// NginxProxyNextUpstream is the proxy_next_upstream conditions a location renders.
func NginxProxyNextUpstream(value NginxSettings) string {
	if len(value.ProxyNextUpstream) == 0 {
		return "error timeout http_502 http_503 http_504"
	}
	return strings.Join(value.ProxyNextUpstream, " ")
}

func hasURLAuth(sites []Site) bool {
	for _, site := range sites {
		if site.URLAuth != nil {
			return true
		}
	}
	return false
}

func renderURLAuthInit(output *strings.Builder, spec normalizedSpec) {
	output.WriteString("    require(\"url_auth\").init({\n")
	output.WriteString("      state_dict = \"cdnca_url_auth_state\",\n")
	output.WriteString("      bindings = {\n")
	for _, site := range spec.Sites {
		if site.URLAuth == nil {
			continue
		}
		fmt.Fprintf(output, "        { tenant_id = %q, site_id = %q, listen_port = %d, policy_path = %q },\n",
			spec.TenantID, site.ID, site.ListenPort,
			filepath.Join(spec.StateRoot, "urlauth", "policies", site.URLAuth.PolicyID, "current.json"))
	}
	output.WriteString("      },\n")
	output.WriteString("    })\n")
}

func hasChallenge(sites []Site) bool {
	for _, site := range sites {
		if site.Challenge != nil {
			return true
		}
	}
	return false
}

func challengeModuleName(siteIndex int) string {
	return fmt.Sprintf("cdnca_challenge_site_%04d", siteIndex+1)
}

func renderChallengeInit(output *strings.Builder, spec normalizedSpec, indent string) {
	for siteIndex, site := range spec.Sites {
		if site.Challenge == nil {
			continue
		}
		path := filepath.Join(spec.StateRoot, "challenge", "policies", site.Challenge.PolicyID, "versions",
			fmt.Sprintf("%020d.json", site.Challenge.PolicyVersion))
		moduleIndex := siteIndex + 1
		fmt.Fprintf(output, "%slocal chunk_%04d, load_error_%04d = loadfile(\"/usr/local/share/cdnca/challenge/engine.lua\")\n",
			indent, moduleIndex, moduleIndex)
		fmt.Fprintf(output, "%sif not chunk_%04d then error(load_error_%04d) end\n", indent, moduleIndex, moduleIndex)
		fmt.Fprintf(output, "%slocal module_%04d = chunk_%04d()\n", indent, moduleIndex, moduleIndex)
		fmt.Fprintf(output, "%sif type(module_%04d) ~= \"table\" or type(module_%04d.init) ~= \"function\" then error(\"invalid challenge module\") end\n",
			indent, moduleIndex, moduleIndex)
		fmt.Fprintf(output, "%smodule_%04d.init({ policy_path = %q, state_dict = \"cdnca_challenge_state\" })\n",
			indent, moduleIndex, path)
		fmt.Fprintf(output, "%spackage.loaded[%q] = module_%04d\n", indent, challengeModuleName(siteIndex), moduleIndex)
	}
}

func renderGlobalNginxSettings(output *strings.Builder, value NginxSettings) {
	resolvers := make([]string, len(value.ResolverAddresses))
	for index, raw := range value.ResolverAddresses {
		address, _ := netip.ParseAddr(raw)
		if address.Is6() {
			resolvers[index] = "[" + raw + "]"
		} else {
			resolvers[index] = raw
		}
	}
	fmt.Fprintf(output, "  resolver %s;\n", strings.Join(resolvers, " "))
	fmt.Fprintf(output, "  resolver_timeout %s;\n", nginxReadableDuration(value.ResolverTimeout))
	output.WriteString("  gzip " + nginxBoolean(!value.GzipDisabled) + ";\n")
	if types := gzipTypesWithoutHTML(value.GzipTypes); len(types) != 0 {
		fmt.Fprintf(output, "  gzip_types %s;\n", strings.Join(types, " "))
	}
	fmt.Fprintf(output, "  gzip_comp_level %d;\n", value.GzipLevel)
	fmt.Fprintf(output, "  gzip_min_length %d;\n", value.GzipMinimumBytes)
	fmt.Fprintf(output, "  gzip_vary %s;\n", nginxBoolean(value.GzipVary))
	fmt.Fprintf(output, "  proxy_buffering %s;\n", nginxBoolean(value.ProxyBuffering))
	fmt.Fprintf(output, "  proxy_cache_methods %s;\n", strings.Join(value.ProxyCacheMethods, " "))
	fmt.Fprintf(output, "  proxy_max_temp_file_size %d;\n", value.ProxyMaxTempFileBytes)
	fmt.Fprintf(output, "  proxy_connect_timeout %s;\n", nginxReadableDuration(value.ProxyConnectTimeout))
	fmt.Fprintf(output, "  proxy_send_timeout %s;\n", nginxReadableDuration(value.ProxySendTimeout))
	fmt.Fprintf(output, "  proxy_read_timeout %s;\n", nginxReadableDuration(value.ProxyReadTimeout))
	fmt.Fprintf(output, "  server_tokens %s;\n", nginxBoolean(value.ServerTokens))
	fmt.Fprintf(output, "  client_max_body_size %d;\n", value.ClientMaxBodyBytes)
	// quoted: the token characters include ' (never " or \\)
	fmt.Fprintf(output, "  default_type \"%s\";\n", value.DefaultMIMEType)
	fmt.Fprintf(output, "  keepalive_requests %d;\n", value.KeepaliveRequests)
	fmt.Fprintf(output, "  keepalive_timeout %s;\n", nginxReadableDuration(value.KeepaliveTimeout))
	fmt.Fprintf(output, "  log_not_found %s;\n", nginxBoolean(value.LogNotFound))
	fmt.Fprintf(output, "  server_names_hash_max_size %d;\n", value.ServerNamesHashMaxSize)
	if value.ServerNamesHashBucketSize != 0 {
		fmt.Fprintf(output, "  server_names_hash_bucket_size %d;\n", value.ServerNamesHashBucketSize)
	}
	if value.GzipHTTPVersion != "" {
		fmt.Fprintf(output, "  gzip_http_version %s;\n", value.GzipHTTPVersion)
	}
	if value.ProxyRequestBufferingDisabled {
		output.WriteString("  proxy_request_buffering off;\n")
	}
	if value.ClientBodyBufferBytes != 0 {
		fmt.Fprintf(output, "  client_body_buffer_size %d;\n", value.ClientBodyBufferBytes)
	}
	if value.LargeClientHeaderBufferCount != 0 {
		fmt.Fprintf(output, "  large_client_header_buffers %d %d;\n", value.LargeClientHeaderBufferCount,
			value.LargeClientHeaderBufferBytes)
	}
	if value.ServerHeader == "" {
		output.WriteString("  more_clear_headers Server;\n")
	} else {
		fmt.Fprintf(output, "  more_set_headers %q;\n", "Server: "+value.ServerHeader)
	}
}

func siteIPv6Enabled(site Site) bool {
	return site.IPv6Enabled == nil || *site.IPv6Enabled
}

func renderCachePolicyNamedRoutes(output *strings.Builder, spec normalizedSpec, site Site, siteIndex int,
	prewarm bool, plan cachePolicyPlan) {
	fmt.Fprintf(output, "    location %s {\n      internal;\n", cachePolicyRouteName(siteIndex, prewarm, 0))
	renderCachePolicyFreshnessAccess(output, site, !prewarm)
	if prewarm {
		renderPrewarmProxyBody(output, spec, site, siteIndex, nil, true)
	} else {
		renderPublicProxyBody(output, spec, site, siteIndex, nil, true)
	}
	output.WriteString("    }\n")
	for index, route := range plan.Routes {
		route = bindCachePolicyRouteVariables(route, siteIndex, index)
		fmt.Fprintf(output, "    location %s {\n      internal;\n", cachePolicyRouteName(siteIndex, prewarm, index+1))
		fmt.Fprintf(output, "      # cdnca-cache-policy-candidates %s\n", route.Signature)
		renderCachePolicyFreshnessAccess(output, site, false)
		if prewarm {
			renderPrewarmProxyBody(output, spec, site, siteIndex, &route, false)
		} else {
			renderPublicProxyBody(output, spec, site, siteIndex, &route, false)
		}
		output.WriteString("    }\n")
	}
}

func renderCachePolicyFreshnessAccess(output *strings.Builder, site Site, canonical bool) {
	if !cacheFreshnessEnabled(site) {
		return
	}
	output.WriteString("      access_by_lua_block {\n")
	output.WriteString("        ngx.var.cache_freshness_identity = ngx.var.cdnca_cache_policy_key\n")
	if !canonical {
		output.WriteString("        local cache_freshness_guard = require(\"cachefreshness.guard\")\n")
	}
	renderCacheFreshnessAccess(output, *site.CacheFreshness, true, canonical)
	output.WriteString("      }\n")
}

func renderPrewarmProxyBody(output *strings.Builder, spec normalizedSpec, site Site, siteIndex int,
	route *cachePolicyRoute, bypass bool) {
	namespace := CacheNamespaceID(spec.TenantID, site.ID, spec.ConfigVersionID)
	fmt.Fprintf(output, "      add_header X-CDNCA-Config-Version %s always;\n", spec.ConfigVersionID)
	fmt.Fprintf(output, "      add_header X-CDNCA-Cache-Namespace %s always;\n", namespace)
	if cacheFreshnessEnabled(site) {
		output.WriteString("      add_header X-CDN-Cache $cache_freshness_cache_header always;\n")
		identity := cacheFreshnessIdentity(*site.CacheFreshness)
		if cachePolicyAdvanced(site.Cache) {
			identity = ""
		}
		renderCacheFreshnessVariables(output, *site.CacheFreshness, identity)
		if cachePolicyAdvanced(site.Cache) {
			renderCacheFreshnessFilters(output, *site.CacheFreshness)
		}
	} else {
		output.WriteString("      add_header X-CDN-Cache $cdnca_cache_header always;\n")
	}
	fmt.Fprintf(output, "      proxy_pass http://site_%04d;\n", siteIndex+1)
	output.WriteString("      proxy_http_version 1.1;\n")
	fmt.Fprintf(output, "      proxy_set_header Host %s;\n", CachePrewarmHost([]string{site.Domain}))
	output.WriteString("      proxy_set_header X-Forwarded-For \"\";\n")
	output.WriteString("      proxy_set_header X-CDNCA-Internal-Cache-Task \"\";\n")
	output.WriteString("      proxy_set_header X-CDNCA-Cache-Namespace \"\";\n")
	output.WriteString("      proxy_hide_header X-CDN-Cache;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Config-Version;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Internal-Cache-Task;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Cache-Namespace;\n")
	fmt.Fprintf(output, "      proxy_connect_timeout %s;\n", nginxDuration(site.ConnectTimeout))
	fmt.Fprintf(output, "      proxy_send_timeout %s;\n", nginxDuration(site.ReadTimeout))
	fmt.Fprintf(output, "      proxy_read_timeout %s;\n", nginxDuration(site.ReadTimeout))
	if !bypass {
		if route == nil {
			renderCache(output, spec, site)
		} else {
			renderCachePolicyRoute(output, spec, site, *route)
		}
	}
	output.WriteString("      proxy_set_header Upgrade \"\";\n")
	output.WriteString("      proxy_set_header Connection \"\";\n")
	output.WriteString("      proxy_set_header Range \"\";\n")
	output.WriteString("      proxy_set_header If-Range \"\";\n")
}

func renderPublicProxyBody(output *strings.Builder, spec normalizedSpec, site Site, siteIndex int,
	route *cachePolicyRoute, bypass bool) {
	advanced := cachePolicyAdvanced(site.Cache)
	if !advanced && (site.URLAuth != nil || site.Challenge != nil) {
		if site.RangeCache == nil && (site.URLAuth == nil || site.Challenge == nil) {
			if site.Challenge != nil {
				fmt.Fprintf(output, "      access_by_lua_block { return require(%q).access({ tenant_id = ", challengeModuleName(siteIndex))
				fmt.Fprintf(output, "%q, site_id = %q }) }\n", spec.TenantID, site.ID)
			} else {
				output.WriteString("      access_by_lua_block { return require(\"url_auth\").access({ tenant_id = ")
				fmt.Fprintf(output, "%q, site_id = %q, listen_port = %d }) }\n", spec.TenantID, site.ID, site.ListenPort)
			}
		} else {
			output.WriteString("      access_by_lua_block {\n")
			if site.URLAuth != nil {
				renderURLAuthAccess(output, spec, site)
			}
			if site.Challenge != nil {
				renderChallengeAccess(output, spec, site, siteIndex)
			}
			if site.RangeCache != nil {
				fmt.Fprintf(output, "        require(\"range.guard\").access({ max_range_bytes = %d, max_if_range_bytes = %d, max_ranges = %d, max_range_span_bytes = %d })\n",
					site.RangeCache.MaxRangeHeaderBytes, site.RangeCache.MaxIfRangeHeaderBytes,
					RangeCacheMaxRanges, RangeCacheMaxRangeSpanBytes)
			}
			output.WriteString("      }\n")
		}
	}
	if cacheFreshnessEnabled(site) && advanced {
		renderCacheFreshnessFilters(output, *site.CacheFreshness)
	} else if cacheFreshnessEnabled(site) {
		renderCacheFreshnessVariables(output, *site.CacheFreshness, cacheFreshnessIdentity(*site.CacheFreshness))
		renderWAFAndCacheFreshness(output, siteIndex, site.ID, site.WAF, site.SecurityPolicies, headerOverflowBlocks(site), *site.CacheFreshness, site.ID != "")
	} else if !advanced {
		renderWAF(output, siteIndex, site.ID, site.WAF, site.SecurityPolicies, headerOverflowBlocks(site), site.ID != "")
	}
	if site.TelemetryCapture.Enabled {
		renderTelemetryCapture(output, site.TelemetryCapture)
	}
	for _, rule := range site.ACL.Rules {
		fmt.Fprintf(output, "      %s %s;\n", rule.Action, rule.CIDR)
	}
	fmt.Fprintf(output, "      %s all;\n", site.ACL.DefaultAction)
	fmt.Fprintf(output, "      proxy_pass http://site_%04d;\n", siteIndex+1)
	output.WriteString("      proxy_http_version 1.1;\n")
	output.WriteString("      proxy_set_header Host $host;\n")
	output.WriteString("      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	output.WriteString("      proxy_set_header X-CDNCA-Internal-Cache-Task \"\";\n")
	output.WriteString("      proxy_set_header X-CDNCA-Cache-Namespace \"\";\n")
	output.WriteString("      proxy_hide_header X-CDN-Cache;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Config-Version;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Internal-Cache-Task;\n")
	output.WriteString("      proxy_hide_header X-CDNCA-Cache-Namespace;\n")
	fmt.Fprintf(output, "      proxy_connect_timeout %s;\n", nginxDuration(site.ConnectTimeout))
	fmt.Fprintf(output, "      proxy_send_timeout %s;\n", nginxDuration(site.ReadTimeout))
	fmt.Fprintf(output, "      proxy_read_timeout %s;\n", nginxDuration(site.ReadTimeout))
	if !bypass {
		if route != nil {
			renderCachePolicyRoute(output, spec, site, *route)
		} else if site.RangeCache != nil {
			renderRangeCache(output, spec, site)
		} else {
			renderCache(output, spec, site)
		}
	}
	if site.FailoverTries == 1 {
		output.WriteString("      proxy_next_upstream off;\n")
	} else {
		output.WriteString("      proxy_next_upstream error timeout http_502 http_503 http_504;\n")
		fmt.Fprintf(output, "      proxy_next_upstream_tries %d;\n", site.FailoverTries)
	}
	if site.WebSocket {
		// Buffering stays on: nginx caches only buffered responses, and it
		// tunnels an upgraded (101) connection unbuffered on its own.
		output.WriteString("      proxy_set_header Upgrade $http_upgrade;\n")
		if siteReusesOriginConnections(site) {
			output.WriteString("      proxy_set_header Connection $cdnca_connection_upgrade_keepalive;\n")
		} else {
			output.WriteString("      proxy_set_header Connection $cdnca_connection_upgrade;\n")
		}
	} else {
		output.WriteString("      proxy_set_header Upgrade \"\";\n")
		output.WriteString("      proxy_set_header Connection \"\";\n")
	}
	if site.RangeCache != nil {
		return
	}
	if site.Range {
		output.WriteString("      proxy_set_header Range $http_range;\n")
		output.WriteString("      proxy_set_header If-Range $http_if_range;\n")
		output.WriteString("      proxy_force_ranges on;\n")
	} else {
		output.WriteString("      proxy_set_header Range \"\";\n")
		output.WriteString("      proxy_set_header If-Range \"\";\n")
	}
}

func renderCacheMaps(output *strings.Builder) {
	output.WriteString("  map $request_method $cdnca_cache_method_bypass { default 1; GET 0; HEAD 0; }\n")
	output.WriteString("  map $http_authorization $cdnca_cache_authorization_bypass { default 1; '' 0; }\n")
	output.WriteString("  map $http_cookie $cdnca_cache_cookie_bypass { default 1; '' 0; }\n")
	output.WriteString("  map $http_upgrade $cdnca_cache_upgrade_bypass { default 1; '' 0; }\n")
	output.WriteString("  map $http_range $cdnca_cache_range_bypass { default 1; '' 0; }\n")
	output.WriteString("  map $upstream_http_set_cookie $cdnca_cache_response_cookie_bypass { default 1; '' 0; }\n")
	output.WriteString("  map $upstream_http_cache_control $cdnca_cache_response_control_bypass { default 0; ~*(^|[,[:space:]])(private|no-store|no-cache)([=,[:space:]]|$) 1; }\n")
	output.WriteString("  map \"$cdnca_cache_method_bypass:$cdnca_cache_authorization_bypass:$cdnca_cache_cookie_bypass:$cdnca_cache_upgrade_bypass:$cdnca_cache_range_bypass:$cdnca_cache_response_cookie_bypass:$cdnca_cache_response_control_bypass\" $cdnca_cache_safe_bypass { default 1; \"0:0:0:0:0:0:0\" 0; }\n")
	output.WriteString("  map \"$cdnca_cache_safe_bypass:$upstream_cache_status\" $cdnca_cache_header { default BYPASS; \"0:HIT\" HIT; \"0:STALE\" HIT; \"0:UPDATING\" HIT; \"0:REVALIDATED\" HIT; \"0:MISS\" MISS; \"0:EXPIRED\" MISS; }\n")
}

func renderCachePolicyActionMaps(output *strings.Builder, spec normalizedSpec) {
	for siteIndex, site := range spec.Sites {
		if !cachePolicyUsesV2Rules(site.Cache) {
			continue
		}
		plan, err := buildCachePolicyPlan(site.Cache)
		if err != nil {
			panic("normalized V2 cache policy plan became invalid")
		}
		for routeIndex, route := range plan.Routes {
			route = bindCachePolicyRouteVariables(route, siteIndex, routeIndex)
			defaultNoCache := "0"
			if route.NoCacheDefault {
				defaultNoCache = "1"
			}
			fmt.Fprintf(output, "  map $status %s { default %s;", route.noCacheVariable, defaultNoCache)
			for _, value := range route.NoCacheStatuses {
				fmt.Fprintf(output, " %d %s;", value.Status, value.Value)
			}
			output.WriteString(" }\n")
			fmt.Fprintf(output, "  map $status %s { default %s;", route.browserVariable, route.BrowserDefault)
			for _, value := range route.BrowserStatuses {
				fmt.Fprintf(output, " %d %s;", value.Status, value.Value)
			}
			output.WriteString(" }\n")
		}
	}
}

func bindCachePolicyRouteVariables(route cachePolicyRoute, siteIndex, routeIndex int) cachePolicyRoute {
	if route.V2 {
		route.noCacheVariable = fmt.Sprintf("$cdnca_cache_policy_no_cache_%04d_%04d", siteIndex+1, routeIndex+1)
		route.browserVariable = fmt.Sprintf("$cdnca_cache_policy_browser_ttl_%04d_%04d", siteIndex+1, routeIndex+1)
	}
	return route
}

func renderRangeCacheMaps(output *strings.Builder) {
	output.WriteString("  map $request_method $range_cache_method_bypass { default 1; GET 0; HEAD 0; }\n")
	output.WriteString("  map $upstream_http_content_encoding $range_cache_encoded { default 1; '' 0; identity 0; }\n")
	output.WriteString("  map $upstream_http_content_length $range_cache_unknown_length { default 0; '' 1; }\n")
	output.WriteString("  map $upstream_http_vary $range_cache_vary { default 1; '' 0; }\n")
	output.WriteString("  map $http_range $range_cache_effective_range { volatile; default $slice_range; ~, $http_range; }\n")
	output.WriteString("  map $upstream_cache_status $range_cache_header { default BYPASS; HIT HIT; STALE HIT; UPDATING HIT; REVALIDATED HIT; MISS MISS; EXPIRED MISS; }\n")
}

func renderCacheFreshnessMaps(output *strings.Builder) {
	for _, item := range []struct{ source, name string }{
		{"$http_if_range", "if_range"}, {"$http_if_match", "if_match"},
		{"$http_if_none_match", "if_none_match"}, {"$http_if_modified_since", "if_modified_since"},
		{"$http_if_unmodified_since", "if_unmodified_since"},
	} {
		fmt.Fprintf(output, "  map %s $cache_freshness_%s_bypass { default 1; '' 0; }\n", item.source, item.name)
	}
	output.WriteString("  map $http_cache_control $cache_freshness_request_cc_bypass { default 0; ~*(^|,)\\s*(private|no-store|no-cache)(\\s*(=|,|$)) 1; }\n")
	output.WriteString("  map $http_pragma $cache_freshness_pragma_bypass { default 0; ~*no-cache 1; }\n")
	output.WriteString("  map \"$cdnca_cache_method_bypass:$cdnca_cache_authorization_bypass:$cdnca_cache_cookie_bypass:$cdnca_cache_upgrade_bypass:$cdnca_cache_range_bypass:$cache_freshness_if_range_bypass:$cache_freshness_if_match_bypass:$cache_freshness_if_none_match_bypass:$cache_freshness_if_modified_since_bypass:$cache_freshness_if_unmodified_since_bypass:$cache_freshness_request_cc_bypass:$cache_freshness_pragma_bypass\" $cache_freshness_request_bypass { default 1; \"0:0:0:0:0:0:0:0:0:0:0:0\" 0; }\n")
	output.WriteString("  map $upstream_http_vary $cache_freshness_enhancement_vary_bypass { default 1; '' 0; }\n")
	output.WriteString("  map $status $cache_freshness_status_bypass { default 1; 200 0; }\n")
	output.WriteString("  map \"$upstream_http_etag|$upstream_http_last_modified|$upstream_http_content_length|$upstream_http_date\" $cache_freshness_validator_bypass { default 0; \"|||\" 1; }\n")
	output.WriteString("  map \"$cdnca_cache_response_cookie_bypass:$cdnca_cache_response_control_bypass:$cache_freshness_enhancement_vary_bypass:$cache_freshness_status_bypass\" $cache_freshness_response_bypass { default 1; \"0:0:0:0\" 0; }\n")
	output.WriteString("  map \"$cache_freshness_request_bypass:$cache_freshness_response_bypass:$cache_freshness_validator_bypass:$upstream_cache_status\" $cache_freshness_cache_header { default BYPASS; \"0:0:0:HIT\" HIT; \"0:0:0:STALE\" HIT; \"0:0:0:UPDATING\" HIT; \"0:0:0:REVALIDATED\" HIT; \"0:0:0:MISS\" MISS; \"0:0:0:EXPIRED\" MISS; }\n")
	output.WriteString("  map $upstream_cache_status $cache_freshness_cache_reason { default origin_error; '' cache_request_bypass; HIT cache_fresh_hit; MISS cache_miss; BYPASS cache_request_bypass; EXPIRED cache_miss; STALE stale_served_revalidate; UPDATING stale_served_revalidate; REVALIDATED cache_fresh_hit; }\n")
	output.WriteString("  map $cache_freshness_cache_reason $cache_freshness_cache_state { default expired; cache_fresh_hit fresh; coalesced_follower fresh; stale_served_revalidate stale; }\n")
}

func renderCachePolicyDispatch(output *strings.Builder, spec normalizedSpec, site Site, siteIndex int,
	prewarm bool, plan cachePolicyPlan) {
	fmt.Fprintf(output, "      # cdnca-cache-policy-plan %s\n", plan.Digest)
	output.WriteString("      set $cdnca_cache_policy_key \"\";\n")
	output.WriteString("      set $cdnca_cache_policy_bypass 1;\n")
	output.WriteString("      set $cdnca_cache_policy_routed 0;\n")
	output.WriteString("      access_by_lua_block {\n")
	if !prewarm && site.URLAuth != nil {
		output.WriteString(urlAuthCachePolicyPrefixLua(spec.TenantID, site.ID, site.ListenPort))
	}
	if !prewarm && site.Challenge != nil {
		output.WriteString(challengeCachePolicyPrefixLua(spec.TenantID, site.ID, siteIndex))
	}
	output.WriteString(cachePolicyDispatchLua(CacheKeyPrefix(
		spec.TenantID, site.ID, spec.ConfigVersionID, site.Domain, site.ListenPort), site.Cache, plan, siteIndex, prewarm))
	output.WriteString("      }\n")
}

func challengeCachePolicyPrefixLua(tenantID, siteID string, siteIndex int) string {
	var output strings.Builder
	fmt.Fprintf(&output, "        local cdnca_challenge_result = require(%q).access({ tenant_id = ", challengeModuleName(siteIndex))
	fmt.Fprintf(&output, "%q, site_id = %q })\n", tenantID, siteID)
	output.WriteString("        if cdnca_challenge_result ~= nil then\n")
	output.WriteString("          return cdnca_challenge_result\n")
	output.WriteString("        end\n")
	return output.String()
}

func urlAuthCachePolicyPrefixLua(tenantID, siteID string, listenPort uint16) string {
	var output strings.Builder
	output.WriteString("        local cdnca_url_auth_result = require(\"url_auth\").access({ tenant_id = ")
	fmt.Fprintf(&output, "%q, site_id = %q, listen_port = %d })\n", tenantID, siteID, listenPort)
	output.WriteString("        if cdnca_url_auth_result ~= nil then\n")
	output.WriteString("          return cdnca_url_auth_result\n")
	output.WriteString("        end\n")
	return output.String()
}

func renderURLAuthAccess(output *strings.Builder, spec normalizedSpec, site Site) {
	output.WriteString("        local function cdnca_url_auth_access()\n")
	output.WriteString("          return require(\"url_auth\").access({ tenant_id = ")
	fmt.Fprintf(output, "%q, site_id = %q, listen_port = %d })\n", spec.TenantID, site.ID, site.ListenPort)
	output.WriteString("        end\n")
	output.WriteString("        cdnca_url_auth_access()\n")
}

func renderChallengeAccess(output *strings.Builder, spec normalizedSpec, site Site, siteIndex int) {
	output.WriteString(challengeCachePolicyPrefixLua(spec.TenantID, site.ID, siteIndex))
}

func cachePolicyDispatchLua(keyPrefix string, policy CachePolicy, plan cachePolicyPlan, siteIndex int, prewarm bool) string {
	return cachePolicyDispatchLuaExpression(luaCacheString(keyPrefix), policy, plan, siteIndex, prewarm)
}

// cachePolicyDispatchLuaExpression is cachePolicyDispatchLua with the key
// prefix given as a Lua expression (a host-keyed site runtime v2 cache reads
// the captured request host).
func cachePolicyDispatchLuaExpression(keyPrefix string, policy CachePolicy, plan cachePolicyPlan, siteIndex int, prewarm bool) string {
	return cachePolicyDispatchLuaFor(keyPrefix, policy, plan, func(routeIndex int) string {
		return cachePolicyRouteName(siteIndex, prewarm, routeIndex)
	})
}

// cachePolicyDispatchLuaFor is cachePolicyDispatchLuaExpression dispatching
// to the named locations name returns (route 0 is the bypass route).
func cachePolicyDispatchLuaFor(keyPrefix string, policy CachePolicy, plan cachePolicyPlan, name func(int) string) string {
	var output strings.Builder
	output.WriteString("        return require(\"cachepolicy.key\").dispatch({\n")
	fmt.Fprintf(&output, "          key_prefix = %s,\n", keyPrefix)
	fmt.Fprintf(&output, "          legacy = %s,\n", nginxBoolean(
		policy.QueryMode == CacheQueryPreserve && len(policy.VaryHeaders) == 0))
	fmt.Fprintf(&output, "          query_mode = %s,\n", luaCacheString(string(policy.QueryMode)))
	fmt.Fprintf(&output, "          query_names = %s,\n", luaCacheArray(policy.QueryNames))
	fmt.Fprintf(&output, "          vary_headers = %s,\n", luaCacheArray(policy.VaryHeaders))
	output.WriteString("          rules = {")
	for index, rule := range policy.Rules {
		if index != 0 {
			output.WriteString(", ")
		}
		fmt.Fprintf(&output, "{path_prefix = %s, extensions = %s}",
			luaCacheString(rule.PathPrefix), luaCacheArray(rule.Extensions))
	}
	output.WriteString("},\n          routes = {")
	for index, route := range plan.Routes {
		if index != 0 {
			output.WriteString(", ")
		}
		fmt.Fprintf(&output, "[%s] = %s", luaCacheString(route.Signature), luaCacheString(name(index+1)))
	}
	fmt.Fprintf(&output, "},\n          bypass = %s,\n", luaCacheString(name(0)))
	output.WriteString("        })\n")
	return output.String()
}

func cachePolicyRouteName(siteIndex int, prewarm bool, routeIndex int) string {
	kind := "public"
	if prewarm {
		kind = "prewarm"
	}
	if routeIndex == 0 {
		return fmt.Sprintf("@cdnca_cache_%s_%04d_bypass", kind, siteIndex+1)
	}
	return fmt.Sprintf("@cdnca_cache_%s_%04d_%04d", kind, siteIndex+1, routeIndex)
}

func luaCacheArray(values []string) string {
	var output strings.Builder
	output.WriteByte('{')
	for index, value := range values {
		if index != 0 {
			output.WriteString(", ")
		}
		output.WriteString(luaCacheString(value))
	}
	output.WriteByte('}')
	return output.String()
}

func luaCacheString(value string) string {
	var output strings.Builder
	output.WriteByte('"')
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 0x20 && character <= 0x7e && character != '"' && character != '\\' {
			output.WriteByte(character)
			continue
		}
		fmt.Fprintf(&output, "\\%03d", character)
	}
	output.WriteByte('"')
	return output.String()
}

func renderCache(output *strings.Builder, spec normalizedSpec, site Site) {
	renderCacheRuntime(output, spec, site, nil)
}

func renderCachePolicyRoute(output *strings.Builder, spec normalizedSpec, site Site, route cachePolicyRoute) {
	renderCacheRuntime(output, spec, site, &route)
}

func renderCacheRuntime(output *strings.Builder, spec normalizedSpec, site Site, route *cachePolicyRoute) {
	if site.Cache.Mode == CacheDisabled {
		return
	}
	fmt.Fprintf(output, "      proxy_cache %s;\n", cacheZoneName(spec, site))
	if cacheFreshnessEnabled(site) && route != nil {
		output.WriteString("      proxy_cache_key \"$cache_freshness_generation|$cache_freshness_object_token|$cdnca_cache_policy_key\";\n")
	} else if cacheFreshnessEnabled(site) {
		fmt.Fprintf(output, "      proxy_cache_key \"$cache_freshness_generation|$cache_freshness_object_token|%s\";\n", cacheFreshnessIdentity(*site.CacheFreshness))
	} else if route != nil {
		output.WriteString("      proxy_cache_key $cdnca_cache_policy_key;\n")
	} else if spec.TenantID != "" && site.ID != "" {
		fmt.Fprintf(output, "      proxy_cache_key %q;\n", CacheKeyPrefix(spec.TenantID, site.ID, spec.ConfigVersionID, site.cacheKeyDomain(), site.ListenPort)+"$uri$is_args$args")
	} else {
		fmt.Fprintf(output, "      proxy_cache_key \"%s|%d|$uri$is_args$args\";\n", site.Domain, site.ListenPort)
	}
	output.WriteString("      proxy_cache_methods GET HEAD;\n")
	if cacheFreshnessEnabled(site) {
		output.WriteString("      proxy_cache_convert_head on;\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Cache-Reason;\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Cache-State;\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Cache-Policy;\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Cache-Status;\n")
		output.WriteString("      proxy_cache_bypass $cache_freshness_request_bypass $cache_freshness_hard_bypass $cache_freshness_fail_closed;\n")
		output.WriteString("      proxy_no_cache $cache_freshness_request_bypass $cache_freshness_response_bypass $cache_freshness_validator_bypass $cache_freshness_fail_closed")
	} else {
		output.WriteString("      proxy_cache_bypass $cdnca_cache_method_bypass $cdnca_cache_authorization_bypass $cdnca_cache_cookie_bypass $cdnca_cache_upgrade_bypass $cdnca_cache_range_bypass;\n")
		output.WriteString("      proxy_no_cache $cdnca_cache_method_bypass $cdnca_cache_authorization_bypass $cdnca_cache_cookie_bypass $cdnca_cache_upgrade_bypass $cdnca_cache_range_bypass $cdnca_cache_response_cookie_bypass $cdnca_cache_response_control_bypass")
	}
	if route != nil && route.V2 {
		fmt.Fprintf(output, " %s", route.noCacheVariable)
	}
	output.WriteString(";\n")
	if route != nil && route.V2 {
		fmt.Fprintf(output, "      expires %s;\n", route.browserVariable)
	}
	if site.Cache.Mode == CacheOverride {
		output.WriteString("      proxy_ignore_headers X-Accel-Expires Expires Cache-Control;\n")
	}
	if cacheFreshnessEnabled(site) {
		expert := site.CacheFreshness.Enhancement.Expert
		output.WriteString("      proxy_cache_lock on;\n")
		fmt.Fprintf(output, "      proxy_cache_lock_timeout %s;\n", nginxCacheFreshnessDuration(expert.LockTimeoutMilliseconds))
		fmt.Fprintf(output, "      proxy_cache_lock_age %s;\n", nginxCacheFreshnessDuration(expert.LockAgeMilliseconds))
		fmt.Fprintf(output, "      proxy_cache_background_update %s;\n", nginxBoolean(*expert.BackgroundUpdate))
		fmt.Fprintf(output, "      proxy_cache_revalidate %s;\n", nginxBoolean(*expert.Revalidation))
		if len(expert.FailureClasses) > 0 {
			classes := make([]string, len(expert.FailureClasses))
			for index, class := range expert.FailureClasses {
				classes[index] = string(class)
			}
			fmt.Fprintf(output, "      proxy_cache_use_stale %s;\n", strings.Join(classes, " "))
		}
		if route == nil || len(site.Cache.Rules) == 0 {
			fmt.Fprintf(output, "      proxy_cache_valid 200 %ds;\n", site.CacheFreshness.FreshSeconds)
			return
		}
	}
	if route != nil && len(site.Cache.Rules) != 0 {
		for _, group := range route.TTLGroups {
			statuses := make([]string, len(group.Statuses))
			for index, status := range group.Statuses {
				statuses[index] = strconv.Itoa(status)
			}
			fmt.Fprintf(output, "      proxy_cache_valid %s %s;\n", strings.Join(statuses, " "), nginxCacheDuration(group.TTL))
		}
		if route.WildcardTTL != 0 {
			fmt.Fprintf(output, "      proxy_cache_valid any %s;\n", nginxCacheDuration(route.WildcardTTL))
		} else {
			output.WriteString("      proxy_cache_valid any 0s;\n")
		}
		return
	}
	defaultStatuses := []int{200, 301, 302}
	customStatuses := make(map[int]struct{}, len(site.Cache.StatusTTLs))
	for _, status := range site.Cache.StatusTTLs {
		customStatuses[status.Status] = struct{}{}
	}
	remaining := make([]string, 0, len(defaultStatuses))
	for _, status := range defaultStatuses {
		if _, exists := customStatuses[status]; !exists {
			remaining = append(remaining, strconv.Itoa(status))
		}
	}
	if len(remaining) > 0 {
		fmt.Fprintf(output, "      proxy_cache_valid %s %s;\n", strings.Join(remaining, " "), nginxCacheDuration(site.Cache.DefaultTTL))
	}
	for _, status := range site.Cache.StatusTTLs {
		fmt.Fprintf(output, "      proxy_cache_valid %d %s;\n", status.Status, nginxCacheDuration(status.TTL))
	}
	if site.Cache.StaleOnUpstreamError {
		output.WriteString("      proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504;\n")
	}
}

func renderRangeCache(output *strings.Builder, spec normalizedSpec, site Site) {
	policy := site.RangeCache
	identity := rangeCacheIdentity(spec, site)
	output.WriteString("      set $range_cache_guard_no_store 0;\n")
	if site.URLAuth == nil && site.Challenge == nil {
		output.WriteString("      access_by_lua_block { require(\"range.guard\").access({ max_range_bytes = ")
		fmt.Fprintf(output, "%d, max_if_range_bytes = %d, max_ranges = %d, max_range_span_bytes = %d }) }\n",
			policy.MaxRangeHeaderBytes, policy.MaxIfRangeHeaderBytes, RangeCacheMaxRanges, RangeCacheMaxRangeSpanBytes)
	}
	output.WriteString("      header_filter_by_lua_block { require(\"range.guard\").header_filter({ max_header_bytes = ")
	fmt.Fprintf(output, "%d }) }\n", policy.MaxResponseHeaderBytes)
	output.WriteString("      body_filter_by_lua_block { require(\"range.guard\").body_filter() }\n")
	fmt.Fprintf(output, "      max_ranges %d;\n", RangeCacheMaxRanges)
	fmt.Fprintf(output, "      slice %d;\n", policy.SliceBytes)
	fmt.Fprintf(output, "      proxy_buffer_size %d;\n      proxy_buffers 8 %d;\n", policy.MaxResponseHeaderBytes, policy.MaxResponseHeaderBytes)
	output.WriteString("      proxy_set_header Range $range_cache_effective_range;\n")
	output.WriteString("      proxy_set_header If-Range \"\";\n")
	output.WriteString("      proxy_set_header Accept-Encoding \"identity\";\n")
	fmt.Fprintf(output, "      proxy_cache range_cache_%s;\n", identity)
	fmt.Fprintf(output, "      proxy_cache_key \"v=%s|policy=%d|tenant=%s|site=%s|range=$range_cache_effective_range|scheme=$scheme|host=$host|port=$server_port|request=$request_uri\";\n",
		spec.ConfigVersionID, policy.PolicyVersion, spec.TenantID, site.ID)
	output.WriteString("      proxy_cache_methods GET HEAD;\n")
	output.WriteString("      proxy_cache_convert_head on;\n")
	output.WriteString("      proxy_cache_lock on;\n      proxy_cache_lock_timeout 5s;\n      proxy_cache_lock_age 5s;\n")
	output.WriteString("      proxy_cache_bypass $range_cache_method_bypass $cdnca_cache_authorization_bypass $cdnca_cache_cookie_bypass $cdnca_cache_upgrade_bypass;\n")
	output.WriteString("      proxy_no_cache $range_cache_method_bypass $cdnca_cache_authorization_bypass $cdnca_cache_cookie_bypass $cdnca_cache_upgrade_bypass;\n")
	output.WriteString("      proxy_no_cache $range_cache_guard_no_store $range_cache_encoded $range_cache_unknown_length $range_cache_vary $cdnca_cache_response_cookie_bypass $cdnca_cache_response_control_bypass;\n")
	if site.Cache.Mode == CacheOverride {
		output.WriteString("      proxy_ignore_headers X-Accel-Expires Expires Cache-Control;\n")
	}
	fmt.Fprintf(output, "      proxy_cache_valid 200 206 %ds;\n", policy.CacheValidSeconds)
	output.WriteString("      proxy_cache_valid any 0s;\n      proxy_cache_revalidate on;\n      proxy_force_ranges on;\n")
}

// headerOverflowNoMatchLua: more than 100 request headers are logged and the
// site's header conditions see no headers (no match) instead of a 403.
const headerOverflowNoMatchLua = "        if header_error == \"truncated\" then\n" +
	"          ngx.log(ngx.WARN, \"cdnca waf: more than 100 request headers, header conditions do not match\")\n" +
	"          raw_headers = {}\n        end\n"

// headerOverflowBlocks reports whether a request with more than 100 headers is
// rejected (403) by the site's header conditions; otherwise (the default) the
// overflow is logged and header conditions do not match. The choice follows
// the site's managed WAF inspection limit action (ManagedWAF).
func headerOverflowBlocks(site Site) bool {
	return site.ManagedWAF != nil && site.ManagedWAF.InspectionLimitAction == ManagedWAFInspectionBlock
}

func renderWAF(output *strings.Builder, siteIndex int, siteID string, policy WAFPolicy, security []SecurityPolicy, overflowBlocks, telemetry bool) {
	if len(policy.Rules) == 0 && len(security) == 0 && policy.DefaultAction != WAFBlock {
		return
	}
	renderWAFBlock(output, siteIndex, siteID, policy, security, nil, overflowBlocks, telemetry)
}

func renderWAFAndCacheFreshness(output *strings.Builder, siteIndex int, siteID string, policy WAFPolicy, security []SecurityPolicy, overflowBlocks bool, freshness CacheFreshnessPolicy, telemetry bool) {
	renderWAFBlock(output, siteIndex, siteID, policy, security, &freshness, overflowBlocks, telemetry)
	renderCacheFreshnessFilters(output, freshness)
}

func renderCacheFreshnessFilters(output *strings.Builder, freshness CacheFreshnessPolicy) {
	output.WriteString("      header_filter_by_lua_block { require(\"cachefreshness.guard\").header_filter({ identity = ngx.var.cache_freshness_identity, response_bypass = ngx.var.cache_freshness_response_bypass == \"1\", validator_bypass = ngx.var.cache_freshness_validator_bypass == \"1\", vary_bypass = ngx.var.cache_freshness_enhancement_vary_bypass == \"1\", ")
	if freshness.FollowOriginHeaders {
		output.WriteString("follow_origin_headers = true, ")
	}
	fmt.Fprintf(output, "fresh_seconds = %d, stale_seconds = %d, lock_timeout_seconds = %.3f, metadata_ttl_seconds = %d }) }\n",
		freshness.FreshSeconds, freshness.Enhancement.StaleWindowSeconds,
		float64(freshness.Enhancement.Expert.LockTimeoutMilliseconds)/1000, freshness.CacheInactiveSeconds+60)
	output.WriteString("      body_filter_by_lua_block { require(\"cachefreshness.guard\").body_filter() }\n")
	output.WriteString("      log_by_lua_block { require(\"cachefreshness.guard\").log({ identity = ngx.var.cache_freshness_identity }) }\n")
}

func renderCacheFreshnessAccess(output *strings.Builder, freshness CacheFreshnessPolicy, policyAware bool, direct ...bool) {
	requestBypass := `ngx.var.cache_freshness_request_bypass == "1"`
	if policyAware {
		requestBypass += ` or ngx.var.cdnca_cache_policy_bypass == "1"`
	}
	if len(direct) == 1 && !direct[0] {
		output.WriteString("        cache_freshness_guard.access({ identity = ngx.var.cache_freshness_identity, request_bypass = ")
	} else {
		output.WriteString("        require(\"cachefreshness.guard\").access({ identity = ngx.var.cache_freshness_identity, request_bypass = ")
	}
	output.WriteString(requestBypass)
	output.WriteString(", ")
	if freshness.FollowOriginHeaders {
		output.WriteString("follow_origin_headers = true, ")
	}
	output.WriteString("fresh_seconds = ")
	fmt.Fprintf(output, "%d, stale_seconds = %d, lock_seconds = %.3f, metadata_ttl_seconds = %d })\n",
		freshness.FreshSeconds, freshness.Enhancement.StaleWindowSeconds,
		float64(freshness.Enhancement.Expert.LockAgeMilliseconds)/1000, freshness.CacheInactiveSeconds+60)
}

func renderWAFBlock(output *strings.Builder, siteIndex int, siteID string, policy WAFPolicy, security []SecurityPolicy, freshness *CacheFreshnessPolicy, overflowBlocks, telemetry bool) {
	hasMethod, hasPath, hasHeader := false, false, false
	for _, rule := range policy.Rules {
		hasMethod = hasMethod || rule.Match.Method != ""
		hasPath = hasPath || rule.Match.Path != nil
		hasHeader = hasHeader || rule.Match.Header != nil
	}
	for _, bound := range security {
		for _, rule := range bound.Rules {
			hasMethod = hasMethod || rule.Match.Method != ""
			hasPath = hasPath || rule.Match.Path != nil
			hasHeader = hasHeader || rule.Match.Header != nil
		}
	}
	output.WriteString("      rewrite_by_lua_block {\n")
	if freshness != nil {
		renderCacheFreshnessAccess(output, *freshness, false)
	}
	if hasMethod {
		output.WriteString("        local method = ngx.req.get_method()\n")
	}
	if hasPath {
		output.WriteString("        local uri = ngx.var.uri\n")
	}
	if hasHeader {
		output.WriteString("        local raw_headers, header_error = ngx.req.get_headers(100, true)\n")
		if overflowBlocks {
			output.WriteString("        if header_error == \"truncated\" then\n          return ngx.exit(403)\n        end\n")
		} else {
			output.WriteString(headerOverflowNoMatchLua)
		}
		output.WriteString("        local cdnca_headers = {}\n        local cdnca_duplicate_headers = {}\n")
		output.WriteString("        for name, value in pairs(raw_headers) do\n")
		output.WriteString("          local normalized_name = string.lower(name)\n")
		output.WriteString("          if cdnca_headers[normalized_name] ~= nil or type(value) == \"table\" then\n")
		output.WriteString("            cdnca_duplicate_headers[normalized_name] = true\n")
		output.WriteString("          end\n          cdnca_headers[normalized_name] = value\n        end\n")
		output.WriteString("        local function cdnca_header_exists(name)\n")
		output.WriteString("          return cdnca_headers[name] ~= nil\n        end\n")
		output.WriteString("        local function cdnca_header_exact(name, expected)\n")
		output.WriteString("          local value = cdnca_headers[name]\n")
		output.WriteString("          return not cdnca_duplicate_headers[name] and type(value) == \"string\" and value == expected\n")
		output.WriteString("        end\n")
	}
	for policyIndex, bound := range security {
		fmt.Fprintf(output, "        -- cdnca-security kind=%s policy_id=%s policy_version=%d binding_revision=%d runtime_sha256=%s\n",
			bound.Kind, bound.PolicyID, bound.PolicyVersion, bound.BindingRevision, bound.RuntimeSHA256)
		variable := fmt.Sprintf("cdnca_security_action_%d", policyIndex+1)
		ruleVariable := fmt.Sprintf("cdnca_security_rule_%d", policyIndex+1)
		stoppedVariable := fmt.Sprintf("cdnca_security_stopped_%d", policyIndex+1)
		fmt.Fprintf(output, "        local %s = %q\n        local %s = %q\n        local %s = false\n",
			variable, bound.DefaultAction, ruleVariable, bound.PolicyID+":default", stoppedVariable)
		actionSpec := ""
		if SecurityPolicyUsesWAFActions(bound) {
			// WAF v2: bans and the challenge verification run before the
			// rules; the verdict is carried out by cdnca_waf.act.
			actionSpec = luaLongString(WAFActionSpecJSON(siteID, bound, telemetry))
			fmt.Fprintf(output, "        require(%q).gate(%s)\n", wafInspectLuaModule, actionSpec)
		}
		if bound.Enabled {
			for ruleIndex, rule := range bound.Rules {
				condition := renderBoundSecurityCondition(siteIndex, policyIndex, ruleIndex, rule)
				fmt.Fprintf(output, "        if not %s and %s then\n          %s = %q\n          %s = %q\n",
					stoppedVariable, condition, variable, rule.Action, ruleVariable, rule.RuleID)
				if rule.Control == WAFStop {
					fmt.Fprintf(output, "          %s = true\n", stoppedVariable)
				}
				output.WriteString("        end\n")
			}
		}
		if actionSpec != "" {
			fmt.Fprintf(output, "        if %s ~= %q then\n          require(%q).act(%s, %s, %s)\n        end\n",
				variable, WAFAllow, wafInspectLuaModule, actionSpec, variable, ruleVariable)
			continue
		}
		fmt.Fprintf(output, "        if %s == %q then\n", variable, WAFBlock)
		if telemetry {
			fmt.Fprintf(output, "          ngx.var.cdnca_security_emit = \"1\"\n          ngx.var.cdnca_security_type = %q\n          ngx.var.cdnca_security_action = \"block\"\n          ngx.var.cdnca_security_block_page = \"1\"\n          ngx.var.cdnca_security_severity = \"high\"\n          ngx.var.cdnca_security_rule_id = %s\n", bound.Kind, ruleVariable)
			fmt.Fprintf(output, "          %s\n", securityEvidenceLua(bound.PolicyID))
		}
		output.WriteString("          return ngx.exit(403)\n")
		fmt.Fprintf(output, "        elseif %s == %q then\n", variable, WAFLog)
		if telemetry {
			fmt.Fprintf(output, "          ngx.var.cdnca_security_emit = \"1\"\n          ngx.var.cdnca_security_type = %q\n          ngx.var.cdnca_security_action = \"log\"\n          ngx.var.cdnca_security_severity = \"info\"\n          ngx.var.cdnca_security_rule_id = %s\n", bound.Kind, ruleVariable)
			fmt.Fprintf(output, "          %s\n", securityEvidenceLua(bound.PolicyID))
		}
		output.WriteString("        end\n")
	}
	if policy.DefaultAction == WAFBlock {
		fmt.Fprintf(output, "        local cdnca_waf_action = %q\n        local cdnca_waf_stopped = false\n", policy.DefaultAction)
		if telemetry {
			output.WriteString("        local cdnca_waf_rule_id = \"edgeconfig-waf-default\"\n")
		}
	}
	for ruleIndex, rule := range policy.Rules {
		conditions := make([]string, 0, 6)
		if rule.Match.Host != "" {
			conditions = append(conditions, "ngx.var.host == "+strconv.Quote(rule.Match.Host))
		}
		if rule.Match.Port != 0 {
			conditions = append(conditions, "tonumber(ngx.var.server_port) == "+strconv.Itoa(int(rule.Match.Port)))
		}
		if rule.Match.Method != "" {
			conditions = append(conditions, "method == "+strconv.Quote(rule.Match.Method))
		}
		if rule.Match.Path != nil {
			value := strconv.Quote(rule.Match.Path.Value)
			switch rule.Match.Path.Kind {
			case WAFPathExact:
				conditions = append(conditions, "uri == "+value)
			case WAFPathRawPrefix:
				conditions = append(conditions, fmt.Sprintf("string.sub(uri, 1, %d) == %s", len(rule.Match.Path.Value), value))
			default:
				child := strconv.Quote(rule.Match.Path.Value + "/")
				conditions = append(conditions, fmt.Sprintf("(uri == %s or string.sub(uri, 1, %d) == %s)", value, len(rule.Match.Path.Value)+1, child))
			}
		}
		if rule.Match.Header != nil {
			name := strconv.Quote(rule.Match.Header.Name)
			if rule.Match.Header.Kind == WAFHeaderExists {
				conditions = append(conditions, "cdnca_header_exists("+name+")")
			} else {
				conditions = append(conditions, "cdnca_header_exact("+name+", "+strconv.Quote(rule.Match.Header.Value)+")")
			}
		}
		if rule.Match.SourceCIDR != "" {
			conditions = append(conditions, "ngx.var."+wafSourceVariable(siteIndex, ruleIndex)+" == \"1\"")
		}
		if policy.DefaultAction == WAFAllow {
			fmt.Fprintf(output, "        -- WAF rule %d\n        if %s then\n", ruleIndex+1, strings.Join(conditions, " and "))
			switch {
			case rule.Action == WAFAllow && rule.Control == WAFContinue:
				output.WriteString("          -- allow and continue\n")
			case rule.Action == WAFAllow:
				output.WriteString("          -- allow and stop\n          return\n")
			case rule.Action == WAFDeny:
				if telemetry {
					fmt.Fprintf(output, "          ngx.var.cdnca_security_emit = \"1\"\n          ngx.var.cdnca_security_type = \"waf\"\n          ngx.var.cdnca_security_action = \"block\"\n          ngx.var.cdnca_security_block_page = \"1\"\n          ngx.var.cdnca_security_severity = \"high\"\n          ngx.var.cdnca_security_rule_id = \"edgeconfig-waf-%04d\"\n", ruleIndex+1)
				}
				output.WriteString("          -- deny and stop\n          return ngx.exit(403)\n")
			}
			output.WriteString("        end\n")
			continue
		}
		fmt.Fprintf(output, "        -- WAF rule %d\n        if not cdnca_waf_stopped and %s then\n", ruleIndex+1, strings.Join(conditions, " and "))
		fmt.Fprintf(output, "          cdnca_waf_action = %q\n", rule.Action)
		if telemetry && rule.Action == WAFBlock {
			fmt.Fprintf(output, "          cdnca_waf_rule_id = \"edgeconfig-waf-%04d\"\n", ruleIndex+1)
		}
		if rule.Control == WAFStop {
			output.WriteString("          cdnca_waf_stopped = true\n")
		}
		output.WriteString("        end\n")
	}
	if policy.DefaultAction == WAFBlock {
		output.WriteString("        if cdnca_waf_action == \"block\" then\n")
		if telemetry {
			output.WriteString("          ngx.var.cdnca_security_emit = \"1\"\n          ngx.var.cdnca_security_type = \"waf\"\n          ngx.var.cdnca_security_action = \"block\"\n          ngx.var.cdnca_security_block_page = \"1\"\n          ngx.var.cdnca_security_severity = \"high\"\n          ngx.var.cdnca_security_rule_id = cdnca_waf_rule_id\n")
		}
		output.WriteString("          return ngx.exit(403)\n        end\n")
	}
	output.WriteString("      }\n")
}

// specRecordsSecurityEvidence: some telemetry site (one with an ID, as the
// renderer's telemetry flag) has bound policies, whose block / log decisions
// call cdnca_waf.evidence.
func specRecordsSecurityEvidence(sites []Site) bool {
	for _, site := range sites {
		if site.ID != "" && len(site.SecurityPolicies) != 0 {
			return true
		}
	}
	return false
}

// securityEvidenceLua records the attack evidence of a bound policy's block
// / log decision (cdnca_waf.evidence, ge-waf S4).
func securityEvidenceLua(policyID string) string {
	return "require(\"" + wafInspectLuaModule + "\").evidence(" + strconv.Quote(policyID) + ")"
}

func renderBoundSecurityCondition(siteIndex, policyIndex, ruleIndex int, rule WAFRule) string {
	conditions := make([]string, 0, 6)
	match := rule.Match
	if rule.ExpiresAt != "" {
		expiresAt, _ := time.Parse("2006-01-02T15:04:05Z", rule.ExpiresAt)
		conditions = append(conditions, "ngx.time() < "+strconv.FormatInt(expiresAt.Unix(), 10))
	}
	if match.Host != "" {
		conditions = append(conditions, "ngx.var.host == "+strconv.Quote(match.Host))
	}
	if match.Port != 0 {
		conditions = append(conditions, "tonumber(ngx.var.server_port) == "+strconv.Itoa(int(match.Port)))
	}
	if match.Method != "" {
		conditions = append(conditions, "method == "+strconv.Quote(match.Method))
	}
	if match.Path != nil {
		value := strconv.Quote(match.Path.Value)
		switch match.Path.Kind {
		case WAFPathExact:
			conditions = append(conditions, "uri == "+value)
		case WAFPathRawPrefix:
			conditions = append(conditions, fmt.Sprintf("string.sub(uri, 1, %d) == %s", len(match.Path.Value), value))
		default:
			child := strconv.Quote(match.Path.Value + "/")
			conditions = append(conditions, fmt.Sprintf("(uri == %s or string.sub(uri, 1, %d) == %s)", value, len(match.Path.Value)+1, child))
		}
	}
	if match.Header != nil {
		name := strconv.Quote(match.Header.Name)
		if match.Header.Kind == WAFHeaderExists {
			conditions = append(conditions, "cdnca_header_exists("+name+")")
		} else {
			conditions = append(conditions, "cdnca_header_exact("+name+", "+strconv.Quote(match.Header.Value)+")")
		}
	}
	if match.SourceCIDR != "" {
		conditions = append(conditions, "ngx.var."+securitySourceVariable(siteIndex, policyIndex, ruleIndex)+" == \"1\"")
	}
	if match.JA4 != nil {
		conditions = append(conditions, RenderWAFJA4Condition(match.JA4))
	}
	if match.NotJA4 != nil {
		conditions = append(conditions, RenderWAFNotJA4Condition(match.NotJA4))
	}
	for _, condition := range match.IPIntel {
		conditions = append(conditions, RenderWAFIPIntelCondition(condition))
	}
	for _, list := range match.IPLists {
		conditions = append(conditions, RenderWAFIPListCondition(list))
	}
	for _, inspect := range match.Inspect {
		conditions = append(conditions, RenderWAFInspectCondition(inspect))
	}
	return "(" + strings.Join(conditions, " and ") + ")"
}

func wafSourceVariable(siteIndex, ruleIndex int) string {
	return fmt.Sprintf("cdnca_waf_%04d_%04d_source", siteIndex+1, ruleIndex+1)
}

func securitySourceVariable(siteIndex, policyIndex, ruleIndex int) string {
	return fmt.Sprintf("cdnca_security_%04d_%02d_%04d_source", siteIndex+1, policyIndex+1, ruleIndex+1)
}

func validateProtocol(site *Site) error {
	switch site.Protocol {
	case ProtocolHTTP:
		if site.ListenPort == 443 || site.TLS != nil || site.HTTP2 {
			return ErrInvalidConfig
		}
	case ProtocolHTTPS:
		if site.TLS == nil || len(site.TLS.CertificatePEM) == 0 || len(site.TLS.PrivateKeyPEM) == 0 {
			return ErrInvalidConfig
		}
		canonicalProtocols := []string{"TLSv1.2", "TLSv1.3"}
		if site.TLS.Protocols == nil {
			site.TLS.Protocols = canonicalProtocols
		} else if !slices.Equal(site.TLS.Protocols, canonicalProtocols) {
			return ErrInvalidConfig
		}
		pair, err := tls.X509KeyPair(site.TLS.CertificatePEM, site.TLS.PrivateKeyPEM)
		if err != nil || len(pair.Certificate) == 0 {
			return ErrInvalidConfig
		}
		certificate, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return ErrInvalidConfig
		}
		for _, domain := range site.Domains {
			if strings.HasPrefix(domain, "*.") {
				covered := false
				for _, san := range certificate.DNSNames {
					normalized, normalizeErr := normalizeDNSName(san, true)
					if normalizeErr == nil && normalized == domain {
						covered = true
						break
					}
				}
				if !covered {
					return ErrInvalidConfig
				}
				continue
			}
			if certificate.VerifyHostname(domain) != nil {
				return ErrInvalidConfig
			}
		}
	default:
		return ErrInvalidConfig
	}
	return nil
}

func normalizeACL(policy ACLPolicy) (ACLPolicy, error) {
	if !validACLAction(policy.DefaultAction) || len(policy.Rules) > 256 {
		return ACLPolicy{}, ErrInvalidConfig
	}
	normalized := ACLPolicy{DefaultAction: policy.DefaultAction, Rules: make([]ACLRule, 0, len(policy.Rules))}
	prefixes := make([]netip.Prefix, 0, len(policy.Rules))
	for _, rule := range policy.Rules {
		if !validACLAction(rule.Action) {
			return ACLPolicy{}, ErrInvalidConfig
		}
		prefix, err := normalizeCIDR(rule.CIDR)
		if err != nil {
			return ACLPolicy{}, ErrInvalidConfig
		}
		for _, previous := range prefixes {
			if previous.Addr().BitLen() == prefix.Addr().BitLen() && previous.Bits() <= prefix.Bits() && previous.Contains(prefix.Addr()) {
				return ACLPolicy{}, ErrInvalidConfig
			}
		}
		prefixes = append(prefixes, prefix)
		normalized.Rules = append(normalized.Rules, ACLRule{Action: rule.Action, CIDR: prefix.String()})
	}
	return normalized, nil
}

func normalizeWAF(policy WAFPolicy) (WAFPolicy, error) {
	if policy.DefaultAction == "" {
		policy.DefaultAction = WAFAllow
	}
	if len(policy.Rules) > 128 || policy.DefaultAction != WAFAllow && policy.DefaultAction != WAFBlock {
		return WAFPolicy{}, ErrInvalidConfig
	}
	normalized := WAFPolicy{DefaultAction: policy.DefaultAction, Rules: make([]WAFRule, 0, len(policy.Rules))}
	for _, rule := range policy.Rules {
		if rule.Comment != "" || rule.ExpiresAt != "" {
			return WAFPolicy{}, ErrInvalidConfig
		}
		if (rule.Action != WAFAllow && rule.Action != WAFDeny) ||
			(rule.Control != WAFContinue && rule.Control != WAFStop) ||
			(rule.Action == WAFDeny && rule.Control != WAFStop) {
			return WAFPolicy{}, ErrInvalidConfig
		}
		match, err := normalizeWAFMatch(rule.Match)
		if err != nil {
			return WAFPolicy{}, err
		}
		if match.JA4 != nil || match.NotJA4 != nil || match.IPIntel != nil {
			// The legacy site WAF renderer has no JA4 / IP intelligence
			// condition; dropping it would widen the rule to every client.
			return WAFPolicy{}, ErrInvalidConfig
		}
		for _, previous := range normalized.Rules {
			if previous.Control == WAFStop && wafMatchCovers(previous.Match, match) {
				return WAFPolicy{}, ErrInvalidConfig
			}
		}
		normalized.Rules = append(normalized.Rules, WAFRule{Match: match, Action: rule.Action, Control: rule.Control})
	}
	return normalized, nil
}

func normalizeSecurityPolicies(policies []SecurityPolicy) ([]SecurityPolicy, error) {
	if len(policies) > 2 {
		return nil, ErrInvalidConfig
	}
	normalized := make([]SecurityPolicy, len(policies))
	seen := make(map[SecurityKind]struct{}, len(policies))
	totalRules := 0
	for index, policy := range policies {
		if (policy.Kind != SecurityACL && policy.Kind != SecurityWAF) || !uuidPattern.MatchString(policy.PolicyID) ||
			policy.PolicyVersion < 1 || policy.PolicyVersion > 1<<53-1 || policy.BindingRevision < 1 ||
			len(policy.RuntimeSHA256) != sha256.Size*2 || !validHex(policy.RuntimeSHA256) ||
			(policy.DefaultAction != WAFAllow && policy.DefaultAction != WAFBlock) {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[policy.Kind]; duplicate {
			return nil, ErrInvalidConfig
		}
		seen[policy.Kind] = struct{}{}
		totalRules += len(policy.Rules)
		if totalRules > MaxSecurityRulesPerSite {
			return nil, ErrInvalidConfig
		}
		rules := make([]WAFRule, len(policy.Rules))
		for ruleIndex, rule := range policy.Rules {
			normalizedRule, err := normalizeSecurityRule(rule)
			if err != nil {
				return nil, err
			}
			rules[ruleIndex] = normalizedRule
		}
		header, err := normalizeSecurityPolicyHeader(policy)
		if err != nil {
			return nil, err
		}
		normalized[index] = SecurityPolicy{
			Kind: policy.Kind, PolicyID: policy.PolicyID, PolicyVersion: policy.PolicyVersion,
			BindingRevision: policy.BindingRevision, RuntimeSHA256: strings.ToLower(policy.RuntimeSHA256),
			Enabled: policy.Enabled, DefaultAction: policy.DefaultAction, Rules: rules,
			Mode: header.Mode, AutoBlock: header.AutoBlock,
		}
	}
	sort.Slice(normalized, func(left, right int) bool { return normalized[left].Kind < normalized[right].Kind })
	return normalized, nil
}

// normalizeSecurityRule checks one bound security policy rule and returns its
// canonical form.
func normalizeSecurityRule(rule WAFRule) (WAFRule, error) {
	if !uuidPattern.MatchString(rule.RuleID) ||
		(rule.Action != WAFAllow && rule.Action != WAFBlock && rule.Action != WAFLog &&
			rule.Action != WAFChallenge && rule.Action != WAFBan) ||
		(rule.Control != WAFContinue && rule.Control != WAFStop) {
		return WAFRule{}, ErrInvalidConfig
	}
	actionConfig, err := normalizeWAFActionConfig(rule.Action, rule.ActionConfig)
	if err != nil {
		return WAFRule{}, err
	}
	match, err := normalizeWAFMatch(rule.Match)
	if err != nil {
		return WAFRule{}, err
	}
	if err := validateSecurityRuleMetadata(rule.Comment, rule.ExpiresAt, match.SourceCIDR); err != nil {
		return WAFRule{}, err
	}
	return WAFRule{
		RuleID: rule.RuleID, Comment: rule.Comment, ExpiresAt: rule.ExpiresAt,
		Match: match, Action: rule.Action, Control: rule.Control, ActionConfig: actionConfig,
	}, nil
}

// normalizeSecurityPolicyHeader checks a bound policy's mode and auto block:
// WAF policies only.
func normalizeSecurityPolicyHeader(policy SecurityPolicy) (SecurityPolicy, error) {
	if policy.Mode != WAFModeDefend && policy.Mode != WAFModeObserve {
		return SecurityPolicy{}, ErrInvalidConfig
	}
	autoBlock, err := normalizeWAFAutoBlock(policy.AutoBlock)
	if err != nil {
		return SecurityPolicy{}, err
	}
	if policy.Kind != SecurityWAF && (policy.Mode != WAFModeDefend || autoBlock != nil) {
		return SecurityPolicy{}, ErrInvalidConfig
	}
	return SecurityPolicy{Mode: policy.Mode, AutoBlock: autoBlock}, nil
}

func validateSecurityRuleMetadata(comment, expiresAt, sourceCIDR string) error {
	if comment == "" && expiresAt == "" {
		return nil
	}
	if sourceCIDR == "" {
		return ErrInvalidConfig
	}
	if comment != "" && (len(comment) > 256 || !utf8.ValidString(comment) ||
		strings.TrimSpace(comment) != comment || strings.IndexFunc(comment, unicode.IsControl) >= 0) {
		return ErrInvalidConfig
	}
	if expiresAt != "" {
		const layout = "2006-01-02T15:04:05Z"
		parsed, err := time.Parse(layout, expiresAt)
		if err != nil || parsed.Unix() < 0 || parsed.Format(layout) != expiresAt {
			return ErrInvalidConfig
		}
	}
	return nil
}

func normalizeCache(policy CachePolicy, signedPolicy bool) (CachePolicy, error) {
	if policy.Mode == "" {
		policy.Mode = CacheDisabled
	}
	if policy.QueryMode == "" {
		if policy.Mode == CacheDisabled {
			policy.QueryMode = CacheQueryIgnore
		} else {
			policy.QueryMode = CacheQueryPreserve
		}
	}
	queryNames := append([]string(nil), policy.QueryNames...)
	sort.Strings(queryNames)
	for index, name := range queryNames {
		if !cacheQueryNamePattern.MatchString(name) || index > 0 && queryNames[index-1] == name {
			return CachePolicy{}, ErrInvalidConfig
		}
	}
	if (policy.QueryMode == CacheQueryPreserve || policy.QueryMode == CacheQueryIgnore) != (len(queryNames) == 0) ||
		policy.QueryMode != CacheQueryPreserve && policy.QueryMode != CacheQueryIgnore &&
			policy.QueryMode != CacheQueryInclude && policy.QueryMode != CacheQueryExclude {
		return CachePolicy{}, ErrInvalidConfig
	}
	varyHeaders := append([]string(nil), policy.VaryHeaders...)
	for index := range varyHeaders {
		varyHeaders[index] = strings.ToLower(varyHeaders[index])
	}
	sort.Strings(varyHeaders)
	for index, name := range varyHeaders {
		if !cacheHeaderPattern.MatchString(name) || index > 0 && varyHeaders[index-1] == name {
			return CachePolicy{}, ErrInvalidConfig
		}
		switch name {
		case "authorization", "cookie", "proxy-authorization", "set-cookie":
			return CachePolicy{}, ErrInvalidConfig
		}
	}
	rules, err := normalizeCacheRules(policy.Rules, signedPolicy)
	if err != nil {
		return CachePolicy{}, err
	}
	if policy.SchemaVersion != 0 && policy.SchemaVersion != CachePolicyDocumentSchemaV2 {
		return CachePolicy{}, ErrInvalidConfig
	}
	for _, rule := range rules {
		if policy.SchemaVersion == 0 && rule.Action != "" ||
			policy.SchemaVersion == CachePolicyDocumentSchemaV2 && rule.Action == "" {
			return CachePolicy{}, ErrInvalidConfig
		}
	}
	if policy.Mode == CacheDisabled {
		if policy.ZoneSizeBytes != 0 || policy.MaxSizeBytes != 0 || policy.DefaultTTL != 0 ||
			len(policy.StatusTTLs) != 0 || policy.StaleOnUpstreamError || len(rules) != 0 ||
			policy.StaleIfError || policy.BackgroundUpdate || policy.MinObjectBytes != 0 ||
			policy.MaxObjectBytes != 0 || policy.SliceBytes != 0 {
			return CachePolicy{}, ErrInvalidConfig
		}
		return CachePolicy{
			SchemaVersion: policy.SchemaVersion, Revision: policy.Revision, Mode: CacheDisabled, QueryMode: policy.QueryMode,
			QueryNames: queryNames, VaryHeaders: varyHeaders,
		}, nil
	}
	maximumSize := legacyMaxCacheSize
	if signedPolicy {
		maximumSize = signedMaxCacheSize
	}
	if (policy.Mode != CacheFollowOrigin && policy.Mode != CacheOverride) ||
		policy.ZoneSizeBytes < minCacheZoneSize || policy.ZoneSizeBytes > maxCacheZoneSize || policy.ZoneSizeBytes%cacheSizeUnit != 0 ||
		policy.MaxSizeBytes < cacheSizeUnit || policy.MaxSizeBytes > maximumSize || policy.MaxSizeBytes%cacheSizeUnit != 0 ||
		!validCacheTTL(policy.DefaultTTL, signedPolicy) || len(policy.StatusTTLs) > maxCacheStatusTTLs {
		return CachePolicy{}, ErrInvalidConfig
	}
	normalized := CachePolicy{
		SchemaVersion: policy.SchemaVersion, Revision: policy.Revision, Mode: policy.Mode,
		ZoneSizeBytes: policy.ZoneSizeBytes, MaxSizeBytes: policy.MaxSizeBytes,
		DefaultTTL: policy.DefaultTTL, StaleOnUpstreamError: policy.StaleOnUpstreamError,
		StatusTTLs: make([]CacheStatusTTL, len(policy.StatusTTLs)),
		Rules:      rules, QueryMode: policy.QueryMode, QueryNames: queryNames, VaryHeaders: varyHeaders,
		StaleIfError: policy.StaleIfError, BackgroundUpdate: policy.BackgroundUpdate,
		MinObjectBytes: policy.MinObjectBytes, MaxObjectBytes: policy.MaxObjectBytes, SliceBytes: policy.SliceBytes,
	}
	if ValidateCachePolicyExtensions(cachePolicyDocument(normalized)) != nil {
		return CachePolicy{}, ErrInvalidConfig
	}
	copy(normalized.StatusTTLs, policy.StatusTTLs)
	seen := make(map[int]struct{}, len(normalized.StatusTTLs))
	for _, value := range normalized.StatusTTLs {
		if value.Status < 200 || value.Status > 599 || !validCacheTTL(value.TTL, signedPolicy) {
			return CachePolicy{}, ErrInvalidConfig
		}
		if _, exists := seen[value.Status]; exists {
			return CachePolicy{}, ErrInvalidConfig
		}
		seen[value.Status] = struct{}{}
	}
	sort.Slice(normalized.StatusTTLs, func(i, j int) bool {
		return normalized.StatusTTLs[i].Status < normalized.StatusTTLs[j].Status
	})
	if cachePolicyAdvanced(normalized) {
		if _, err := buildCachePolicyPlan(normalized); err != nil {
			return CachePolicy{}, err
		}
	}
	return normalized, nil
}

func normalizeWAFMatch(match WAFMatch) (WAFMatch, error) {
	normalized := WAFMatch{}
	if match.Host != "" {
		host, err := normalizeDNSName(match.Host, true)
		if err != nil {
			return WAFMatch{}, err
		}
		normalized.Host = host
	}
	normalized.Port = match.Port
	if match.Method != "" {
		if strings.TrimSpace(match.Method) != match.Method {
			return WAFMatch{}, ErrInvalidConfig
		}
		normalized.Method = strings.ToUpper(match.Method)
		if !methodPattern.MatchString(normalized.Method) {
			return WAFMatch{}, ErrInvalidConfig
		}
	}
	if match.Path != nil {
		if !validWAFPath(*match.Path) {
			return WAFMatch{}, ErrInvalidConfig
		}
		normalized.Path = &WAFPathMatch{Kind: match.Path.Kind, Value: match.Path.Value}
	}
	if match.Header != nil {
		header, err := normalizeWAFHeader(*match.Header)
		if err != nil {
			return WAFMatch{}, err
		}
		normalized.Header = &header
	}
	if match.SourceCIDR != "" {
		prefix, err := normalizeCIDR(match.SourceCIDR)
		if err != nil {
			return WAFMatch{}, err
		}
		normalized.SourceCIDR = prefix.String()
	}
	inspect, err := normalizeWAFInspect(match.Inspect)
	if err != nil {
		return WAFMatch{}, err
	}
	normalized.Inspect = inspect
	normalized.JA4, err = normalizeWAFJA4(match.JA4)
	if err != nil {
		return WAFMatch{}, err
	}
	normalized.NotJA4, err = normalizeWAFJA4(match.NotJA4)
	if err != nil || normalized.JA4 != nil && normalized.NotJA4 != nil {
		return WAFMatch{}, ErrInvalidConfig
	}
	normalized.IPIntel, err = normalizeWAFIPIntel(match.IPIntel)
	if err != nil {
		return WAFMatch{}, err
	}
	normalized.IPLists, err = normalizeWAFIPLists(match.IPLists)
	if err != nil {
		return WAFMatch{}, err
	}
	if normalized.Host == "" && normalized.Port == 0 && normalized.Method == "" && normalized.Path == nil && normalized.Header == nil && normalized.SourceCIDR == "" && normalized.Inspect == nil && normalized.JA4 == nil && normalized.NotJA4 == nil && normalized.IPIntel == nil && normalized.IPLists == nil {
		return WAFMatch{}, ErrInvalidConfig
	}
	return normalized, nil
}

func validWAFPath(path WAFPathMatch) bool {
	if path.Kind != WAFPathExact && path.Kind != WAFPathPrefix && path.Kind != WAFPathRawPrefix {
		return false
	}
	value := path.Value
	if len(value) == 0 || len(value) > 512 || value[0] != '/' || !ascii(value) ||
		strings.ContainsAny(value, "?#%\\") || strings.Contains(value, "//") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return path.Kind == WAFPathExact || (value != "/" && !strings.HasSuffix(value, "/"))
}

func validHex(value string) bool {
	for index := range value {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') && (character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func normalizeWAFHeader(header WAFHeaderMatch) (WAFHeaderMatch, error) {
	if len(header.Name) == 0 || len(header.Name) > 64 || strings.TrimSpace(header.Name) != header.Name ||
		header.Name[0] == '-' || header.Name[len(header.Name)-1] == '-' {
		return WAFHeaderMatch{}, ErrInvalidConfig
	}
	for index := 0; index < len(header.Name); index++ {
		character := header.Name[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' {
			return WAFHeaderMatch{}, ErrInvalidConfig
		}
	}
	header.Name = strings.ToLower(header.Name)
	switch header.Kind {
	case WAFHeaderExists:
		if header.Value != "" {
			return WAFHeaderMatch{}, ErrInvalidConfig
		}
	case WAFHeaderExact:
		if len(header.Value) == 0 || len(header.Value) > 256 || strings.TrimSpace(header.Value) != header.Value || !ascii(header.Value) {
			return WAFHeaderMatch{}, ErrInvalidConfig
		}
		for index := 0; index < len(header.Value); index++ {
			if header.Value[index] < 0x20 || header.Value[index] > 0x7e {
				return WAFHeaderMatch{}, ErrInvalidConfig
			}
		}
	default:
		return WAFHeaderMatch{}, ErrInvalidConfig
	}
	return header, nil
}

func wafMatchCovers(previous, current WAFMatch) bool {
	if len(previous.Inspect) != 0 {
		return false
	}
	if previous.Method != "" && (current.Method == "" || previous.Method != current.Method) {
		return false
	}
	if !wafPathCovers(previous.Path, current.Path) || !wafHeaderCovers(previous.Header, current.Header) {
		return false
	}
	if previous.SourceCIDR == "" {
		return true
	}
	if current.SourceCIDR == "" {
		return false
	}
	previousPrefix := netip.MustParsePrefix(previous.SourceCIDR)
	currentPrefix := netip.MustParsePrefix(current.SourceCIDR)
	return previousPrefix.Addr().BitLen() == currentPrefix.Addr().BitLen() && previousPrefix.Bits() <= currentPrefix.Bits() &&
		previousPrefix.Contains(currentPrefix.Addr())
}

func wafPathCovers(previous, current *WAFPathMatch) bool {
	if previous == nil {
		return true
	}
	if current == nil {
		return false
	}
	switch previous.Kind {
	case WAFPathExact:
		return current.Kind == WAFPathExact && previous.Value == current.Value
	case WAFPathRawPrefix:
		return strings.HasPrefix(current.Value, previous.Value)
	case WAFPathPrefix:
		if current.Kind == WAFPathRawPrefix {
			return strings.HasPrefix(current.Value, previous.Value+"/")
		}
		return current.Value == previous.Value || strings.HasPrefix(current.Value, previous.Value+"/")
	default:
		return false
	}
}

func wafHeaderCovers(previous, current *WAFHeaderMatch) bool {
	if previous == nil {
		return true
	}
	if current == nil || previous.Name != current.Name {
		return false
	}
	return previous.Kind == WAFHeaderExists ||
		(previous.Kind == WAFHeaderExact && current.Kind == WAFHeaderExact && previous.Value == current.Value)
}

func normalizeCIDR(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || prefix.Addr().Is4In6() || prefix.Bits() == 0 && prefix != prefix.Masked() {
		return netip.Prefix{}, ErrInvalidConfig
	}
	prefix = prefix.Masked()
	if prefix.Addr().IsMulticast() {
		return netip.Prefix{}, ErrInvalidConfig
	}
	return prefix, nil
}

func validACLAction(value ACLAction) bool {
	return value == ACLAllow || value == ACLDeny
}

func safeAbsolutePath(value string) bool {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" || len(value) > 1024 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("/._-", character) {
			return false
		}
	}
	return true
}

func normalizeSiteDomains(primary string, values []string) ([]string, error) {
	if len(values) == 0 {
		values = []string{primary}
	}
	if len(values) > 100 {
		return nil, ErrInvalidConfig
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	primaryFound := false
	for _, value := range values {
		domain, err := normalizeSiteDomainName(value)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		primaryFound = primaryFound || domain == primary
		if _, duplicate := seen[domain]; duplicate {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	if !primaryFound || len(result) == 0 {
		return nil, ErrInvalidConfig
	}
	sort.Strings(result)
	return result, nil
}

// normalizeSiteDomainName normalizes a domain a site serves: an exact host
// name or a leading wildcard ("*.x.example", nginx server_name and map
// hostnames semantics), whose base needs at least two labels. A site's
// primary domain may be a wildcard; every registry keyed on the site's
// domain (CC v2, telemetry identity, cache identity) keys it on this form.
// Values matched against a request's host (CC/WAF host conditions, JS
// challenge rule hosts) stay exact names (normalizeDNSName).
func normalizeSiteDomainName(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	base, wildcard := strings.CutPrefix(value, "*.")
	domain, err := normalizeDNSName(base, true)
	if err != nil || wildcard && len(value) > 253 {
		return "", ErrInvalidConfig
	}
	if wildcard {
		domain = "*." + domain
	}
	return domain, nil
}

func normalizeDNSName(value string, requireDot bool) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || len(value) > 253 || !ascii(value) || strings.Contains(value, "..") {
		return "", ErrInvalidConfig
	}
	labels := strings.Split(value, ".")
	if requireDot && len(labels) < 2 {
		return "", ErrInvalidConfig
	}
	for _, label := range labels {
		if !hostLabelPattern.MatchString(label) {
			return "", ErrInvalidConfig
		}
	}
	return value, nil
}

func normalizeOriginHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || !ascii(value) || strings.ContainsAny(value, "[]/\\\r\n\t ") {
		return "", ErrInvalidConfig
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return "", ErrInvalidConfig
		}
		return address.String(), nil
	}
	return normalizeDNSName(value, false)
}

func originEndpoint(origin Origin) string {
	host := origin.Host
	if address, err := netip.ParseAddr(host); err == nil && address.Is6() {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(origin.Port))
}

// originKeepaliveConnections is how many idle origin connections each worker
// keeps per site upstream when keepalive is on.
const originKeepaliveConnections = 32

func sitesKeepOriginConnections(sites []Site) bool {
	for _, site := range sites {
		if siteReusesOriginConnections(site) {
			return true
		}
	}
	return false
}

func siteReusesOriginConnections(site Site) bool {
	return site.OriginKeepaliveIdleTimeout != nil && *site.OriginKeepaliveIdleTimeout != 0
}

func validBalance(value BalanceMethod) bool {
	switch value {
	case BalanceIPHash, BalanceRoundRobin, BalanceURLHash, BalanceLeastConn, BalanceRandom:
		return true
	default:
		return false
	}
}

func validStreamProtocol(value StreamProtocol) bool {
	return value == StreamProtocolTCP || value == StreamProtocolUDP
}

func validTimeout(value, minimum, maximum time.Duration) bool {
	return value >= minimum && value <= maximum && value%time.Millisecond == 0
}

func validCacheTTL(value time.Duration, signedPolicy bool) bool {
	maximum := 7 * 24 * time.Hour
	if signedPolicy {
		maximum = 365 * 24 * time.Hour
	}
	return value >= time.Second && value <= maximum && value%time.Second == 0
}

func equalCachePolicy(left, right CachePolicy) bool {
	if left.SchemaVersion != right.SchemaVersion || left.Revision != right.Revision || left.Mode != right.Mode || left.ZoneSizeBytes != right.ZoneSizeBytes ||
		left.MaxSizeBytes != right.MaxSizeBytes || left.DefaultTTL != right.DefaultTTL ||
		left.StaleOnUpstreamError != right.StaleOnUpstreamError || left.QueryMode != right.QueryMode ||
		!slices.Equal(left.QueryNames, right.QueryNames) || !slices.Equal(left.VaryHeaders, right.VaryHeaders) ||
		!slices.Equal(left.StatusTTLs, right.StatusTTLs) || len(left.Rules) != len(right.Rules) ||
		left.StaleIfError != right.StaleIfError || left.BackgroundUpdate != right.BackgroundUpdate ||
		left.MinObjectBytes != right.MinObjectBytes || left.MaxObjectBytes != right.MaxObjectBytes ||
		left.SliceBytes != right.SliceBytes {
		return false
	}
	for index := range left.Rules {
		leftRule, rightRule := left.Rules[index], right.Rules[index]
		if leftRule.Order != rightRule.Order || leftRule.PathPrefix != rightRule.PathPrefix || leftRule.Action != rightRule.Action ||
			leftRule.TTL != rightRule.TTL || leftRule.BrowserTTL != rightRule.BrowserTTL ||
			!slices.Equal(leftRule.Extensions, rightRule.Extensions) || !slices.Equal(leftRule.StatusCodes, rightRule.StatusCodes) {
			return false
		}
	}
	return true
}

func maximumCacheTTL(policy CachePolicy) time.Duration {
	maximum := policy.DefaultTTL
	for _, value := range policy.StatusTTLs {
		if value.TTL > maximum {
			maximum = value.TTL
		}
	}
	return maximum
}

func cacheInactive(policy CachePolicy) time.Duration {
	maximum := maximumCacheTTL(policy)
	if maximum < time.Hour {
		return time.Hour
	}
	return maximum
}

func cacheIdentity(spec normalizedSpec, site Site) string {
	if spec.TenantID != "" && site.ID != "" {
		return CacheNamespaceID(spec.TenantID, site.ID, spec.ConfigVersionID)
	}
	digest := sha256.Sum256([]byte(site.Domain + "\x00" + strconv.Itoa(int(site.ListenPort))))
	return hex.EncodeToString(digest[:16])
}

func cacheZoneName(spec normalizedSpec, site Site) string {
	identity := cacheIdentity(spec, site)
	if len(identity) > 32 {
		identity = identity[:32]
	}
	return "cdnca_cache_" + identity + "_" + strconv.FormatInt(site.Cache.ZoneSizeBytes/cacheSizeUnit, 10) + "m"
}

func hasCacheFreshness(sites []Site) bool {
	for _, site := range sites {
		if cacheFreshnessEnabled(site) {
			return true
		}
	}
	return false
}

func cacheFreshnessEnabled(site Site) bool {
	return site.CacheFreshness != nil && site.CacheFreshness.Enhancement.Enabled
}

func renderCacheFreshnessVariables(output *strings.Builder, policy CacheFreshnessPolicy, identity string) {
	fmt.Fprintf(output, "      set $cache_freshness_policy_version %d;\n", policy.PolicyVersion)
	output.WriteString("      set $cache_freshness_method GET;\n")
	output.WriteString("      if ($request_method !~ ^(GET|HEAD)$) { set $cache_freshness_method BYPASS; }\n")
	fmt.Fprintf(output, "      set $cache_freshness_identity %q;\n", identity)
	output.WriteString("      set $cache_freshness_hard_bypass 0;\n")
	output.WriteString("      set $cache_freshness_generation \"\";\n")
	output.WriteString("      set $cache_freshness_object_token \"\";\n")
	output.WriteString("      set $cache_freshness_fail_closed 0;\n")
}

func cacheFreshnessIdentity(policy CacheFreshnessPolicy) string {
	return fmt.Sprintf("v=1|tenant=%s|site=%s|config=%d|scheme=$scheme|host=$host|port=$server_port|method=$cache_freshness_method|request=$request_uri",
		policy.TenantID, policy.SiteID, policy.ConfigurationVersion)
}

func nginxCacheFreshnessDuration(milliseconds uint32) string {
	if milliseconds%1000 == 0 {
		return strconv.FormatUint(uint64(milliseconds/1000), 10) + "s"
	}
	return strconv.FormatUint(uint64(milliseconds), 10) + "ms"
}

func nginxBoolean(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func nginxCacheSize(value int64) string {
	return strconv.FormatInt(value/cacheSizeUnit, 10) + "m"
}

func nginxCacheDuration(value time.Duration) string {
	return strconv.FormatInt(int64(value/time.Second), 10) + "s"
}

func nginxDuration(value time.Duration) string {
	return strconv.FormatInt(value.Milliseconds(), 10) + "ms"
}

func nginxReadableDuration(value time.Duration) string {
	if value%time.Second == 0 {
		return strconv.FormatInt(int64(value/time.Second), 10) + "s"
	}
	return nginxDuration(value)
}

func ascii(value string) bool {
	for _, character := range value {
		if character > 127 {
			return false
		}
	}
	return true
}
