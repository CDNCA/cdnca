// Package edgesite is the semantic site object cdnca.edge.site/v2 (ADR 0009
// dynamic routing): one object per website that a node executes as data, at
// request time, on shared servers. It carries no nginx text; everything a
// request needs is either a field or a content-addressed reference
// (Ref.SHA256) into the same node object store as the site object itself.
//
// Encoding and addressing are those of site objects v1 (siteobject.Encode,
// siteobject.Digest): encoding/json of the structs below in field order,
// compact, no HTML escaping, no trailing newline; addressed by the SHA-256 of
// that plaintext. Decode accepts only that exact encoding and rejects unknown
// fields, so one site has one byte representation and one digest.
//
// The format is specified in docs/edge/site-object-v2.md; this package and
// its tests are normative where the two disagree.
package edgesite

import (
	"encoding/json"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

const (
	// Schema names the format; FormatVersion is its number. A change that an
	// older node would misread gets a new schema (v3), never a reused name.
	Schema        = "cdnca.edge.site/v2"
	FormatVersion = 2
	// MediaType is the object kind in the node object store and in a fetch
	// response (the store itself is keyed by digest only).
	MediaType = "application/vnd.cdnca.edge-site+json;version=2"

	// MaxObjectBytes bounds one site object's plaintext. Heavy content (CC
	// policies, HTTP policy, firewall actions, error page assets) is
	// referenced, not embedded, so a site stays well below it; the largest
	// embedded part is the rule plan.
	MaxObjectBytes = 2 << 20
	// MaxReferencedBytes bounds one referenced object (CC policy, HTTP policy
	// entry): the object store limit of site objects v1.
	MaxReferencedBytes = siteobject.MaxObjectBytes

	MaxNames        = 100 // primary + aliases (v2 document bound)
	MaxListeners    = 32
	MaxPools        = 64
	MaxEndpoints    = 32
	MaxRoutes       = 256
	MaxRouteCIDRs   = 64
	MaxRouteRegions = 32
	MaxRulePolicies = 2 // one ACL, one WAF
	MaxPlanRules    = 4096
	MaxCCBindings   = MaxListeners
	// MaxErrorPages: every (category, status) a site can carry (origin_response
	// and edge_route 400-599, edge_connect 502-504), so a range rule fits.
	MaxErrorPages    = 200 + 200 + 3
	MaxOriginAuth    = 8
	MaxSafeInteger   = int64(1<<53 - 1)
	MaxBodyBytes     = int64(10 << 30) // edgeconfig system client_max_body_size bound
	MaxConnections   = int64(65535)
	MaxBandwidthBPS  = int64(1_000_000_000_000_000)
	MaxRetryAttempts = 8
	// MaxSubscriptionCount bounds the market supply limits (Connections).
	MaxSubscriptionCount = int64(1_000_000_000)
)

// Site is one website. Field order is the encoding order.
type Site struct {
	Schema               string `json:"schema"`
	ConfigurationScopeID string `json:"configuration_scope_id"`
	TenantID             string `json:"tenant_id"`
	SiteID               string `json:"site_id"`
	Revision             int64  `json:"revision"`

	Hosts      Hosts       `json:"hosts"`
	Listeners  []Listener  `json:"listeners"`
	ForceHTTPS *ForceHTTPS `json:"force_https,omitempty"`
	HSTS       *HSTS       `json:"hsts,omitempty"`
	// TrafficLimit is set while the site is over its own traffic cap: the
	// node answers every request (ACME HTTP-01 excepted) with the notice
	// page and status 509.
	TrafficLimit *TrafficLimit `json:"traffic_limit,omitempty"`
	// PackageExpired (errpage-3, ERROR_PAGE_SLOTS): the site's package
	// ended; the node answers every request (ACME HTTP-01 excepted) with the
	// package_expired slot page and never reaches the origin.
	PackageExpired bool `json:"package_expired,omitempty"`
	WebSocket      bool `json:"websocket"`
	// WebSocketOrigins: an upgrade whose Origin is not listed gets 403 (a
	// request without Origin passes); empty: any Origin. Sorted, unique.
	WebSocketOrigins []string `json:"websocket_origins,omitempty"`
	Range            bool     `json:"range"`
	// CacheStatusHeader (响应头显示缓存状态): the
	// node answers X-CDN-Cache (and X-CDN-Cache-Reason) with the request's
	// cache status (HIT, MISS, ...). The control plane publishes it off while
	// the site is at attack escalation level B or above. Off: neither header,
	// except on the agent's own prewarm; an origin's own headers of those
	// names are removed either way (cdnca_cache sets $cdnca_cache_show).
	CacheStatusHeader bool `json:"cache_status_header,omitempty"`

	Origin   Origin      `json:"origin"`
	Cache    *Cache      `json:"cache,omitempty"`
	Security Security    `json:"security"`
	HTTP     *Ref        `json:"http_policy,omitempty"`
	Errors   []ErrorPage `json:"error_pages"`
	// ErrorVariants (errpage-ovr, ERROR_PAGE_SLOTS v1): the platform's
	// region / node overrides of the edge_connect pages (slots http_502 /
	// http_504), see ErrorPageVariant. Omitted when none.
	ErrorVariants []ErrorPageVariant `json:"error_page_variants,omitempty"`
	Limits        Limits             `json:"limits"`
	Telemetry     *Telemetry         `json:"telemetry,omitempty"`
	// Access is the site's request handling: host
	// redirects, HSTS, compression, per-client limits, basic auth and the
	// maintenance page, as the v2 document carries them.
	Access *edgeconfig.SiteAccess `json:"access,omitempty"`
	// Schedule302 is the site's HTTP 302 scheduling (sched302 v1; the
	// signing key and candidates come from the node's scheduling table).
	Schedule302 *sched302.Site `json:"schedule302,omitempty"`
	// Default (默认站点, SITE_EDGE_OPTIONS): a request on one of the site's
	// ports whose Host no site serves (or a TLS handshake without SNI or
	// with an unknown one) is served by this site. At most one site per
	// node (the control plane keeps one in the installation).
	Default bool `json:"default,omitempty"`
}

// Hosts: Primary is the site's identity name (cache identity, telemetry
// domain, the name rules were compiled against); Aliases are its other names,
// sorted. A name is a lower-case FQDN or a leading wildcard "*.<fqdn>" that
// matches exactly one more leftmost label chain (not the bare <fqdn>).
type Hosts struct {
	Primary string   `json:"primary"`
	Aliases []string `json:"aliases"`
}

// Listener is a public port the site is served on. A port is one shared
// server per (port, tls) on the node: every site on a port must agree on TLS
// (PortProfiles). HTTP2 is per site: the port's server has http2 on when any
// site does, and the client hello turns it off for a site without it
// (native patch 27, SITE_TLS_OPTIONS; cdnca_tls.lua). HTTP3 advertises h3
// (Alt-Svc) for this site; it needs TLS with TLSv1.3.
type Listener struct {
	Port          int    `json:"port"`
	AddressFamily string `json:"address_family"`
	TLS           *TLS   `json:"tls,omitempty"`
	HTTP2         bool   `json:"http2"`
	HTTP3         bool   `json:"http3"`
}

const (
	FamilyIPv4      = "ipv4"
	FamilyIPv6      = "ipv6"
	FamilyDualStack = "dual_stack"
)

// TLS: the certificate is a certificate version (the node fetches its key
// pair as a secret object); Protocols is the site's allowed set, an
// ascending contiguous range of TLSv1..TLSv1.3 applied in the client hello
// (edgeconfig.ValidateSiteTLSProtocols). CipherPreset is
// modern/compatible/legacy/custom ("" modern; TLSv1/1.1 need legacy);
// CipherSuites is the custom preset's ordered whitelisted TLS 1.2 list
// (edgeconfig.ValidateTLSCipherSuites, SITE_TLS_CUSTOM_CIPHERS). OCSPStapling
// staples the issuer's OCSP response (ngx.ocsp on the dynamic path).
// ClientAuth optional/required verifies client certificates against
// ClientCA (kind client_ca, content in the object store; ngx.ssl
// verify_client on the dynamic path) and hands the result to the origin.
type TLS struct {
	CertificateVersionID string   `json:"certificate_version_id"`
	Protocols            []string `json:"protocols"`
	CipherPreset         string   `json:"cipher_preset,omitempty"`
	CipherSuites         []string `json:"cipher_suites,omitempty"`
	OCSPStapling         bool     `json:"ocsp_stapling,omitempty"`
	ClientAuth           string   `json:"client_auth,omitempty"`
	ClientCA             *Ref     `json:"client_ca,omitempty"`
	// PreferServerCiphers: absent follows the preset (modern off,
	// compatible/legacy on); written only when it differs
	// (SITE_TLS_OPTIONS).
	PreferServerCiphers *bool `json:"prefer_server_ciphers,omitempty"`
}

// ForceHTTPS redirects plain requests to RedirectPort (one of the site's TLS
// ports), except /.well-known/acme-challenge/.
type ForceHTTPS struct {
	RedirectPort int `json:"redirect_port"`
	// Status is the redirect status (absent: 301); ExcludeHosts are site
	// names left on plain HTTP.
	Status       int      `json:"status,omitempty"`
	ExcludeHosts []string `json:"exclude_hosts,omitempty"`
}

// TrafficLimit: Period is the reached cap (daily, monthly, total);
// NoticeHTML the page ("" the node's default page).
type TrafficLimit struct {
	Period     string `json:"period"`
	NoticeHTML string `json:"notice_html,omitempty"`
}

// Origin is how a request reaches the site's origin: pools of endpoints,
// conditional routes that pick a pool, the L2 tier, origin authentication.
type Origin struct {
	DefaultPoolID         string       `json:"default_pool_id"`
	DefaultFallbackPoolID string       `json:"default_fallback_pool_id,omitempty"`
	Pools                 []Pool       `json:"pools"`
	Routes                []Route      `json:"routes"`
	L2                    *L2          `json:"l2,omitempty"`
	IngressSource         bool         `json:"ingress_source"`
	Auth                  []OriginAuth `json:"auth"`
	// TrustedProxyCIDRs: a peer in one of these keeps its X-Forwarded-For
	// chain (extended with the peer) and X-Real-IP; any other peer's are
	// replaced with its address. Sorted, masked, never /0.
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs,omitempty"`
	// HTTPSPoolID: TLS listeners use this pool by default (follow protocol).
	HTTPSPoolID string `json:"https_pool_id,omitempty"`
	// FollowRedirect (ge36, ORIGIN_FOLLOW_REDIRECT): the node follows the
	// origin's redirects; nil = the origin's redirect goes to the visitor.
	FollowRedirect *FollowRedirect `json:"follow_redirect,omitempty"`
	// SearchEngine (搜索引擎回源, SITE_EDGE_OPTIONS): a request whose
	// User-Agent names a search engine crawler goes to this pool and is
	// never served from or stored in the cache.
	SearchEngine *SearchEngineOrigin `json:"search_engine,omitempty"`
	// ACMEPassthrough (源站申请证书, SITE_EDGE_OPTIONS): an ACME HTTP-01
	// request the node holds no token of its own for (/$host/$token) goes
	// to the origin instead of 404; a token the node holds always wins.
	ACMEPassthrough bool `json:"acme_passthrough,omitempty"`
	// Unbuffered (数据实时返回/发送, SITE_EDGE_OPTIONS): a request the cache
	// does not serve is proxied without response ("response") and/or
	// request body ("request") buffering. Sorted, unique.
	Unbuffered []string `json:"unbuffered,omitempty"`
}

// SearchEngineOrigin: requests of the crawlers whose User-Agent contains one
// of Tokens (lower case, case-insensitive match; empty: the node's built-in
// search engine list) go to the pool PoolID.
type SearchEngineOrigin struct {
	PoolID string   `json:"pool_id"`
	Tokens []string `json:"tokens,omitempty"`
}

// Unbuffered directions (Origin.Unbuffered).
const (
	UnbufferedResponse = "response"
	UnbufferedRequest  = "request"
)

// FollowRedirect: for a bodyless GET/HEAD (no Upgrade) the node follows a
// 301/302/303/307/308 whose Location it can resolve, up to MaxHops (1..5)
// redirects (at most 5: nginx allows 10 internal redirects per
// request and the node uses some), and serves the final response; the request keeps its method
// (a 303 too: only GET/HEAD are followed) and headers, the origin is
// chosen as for the original request. A Location naming a host other than
// the request's host, a site host or an endpoint of the pool is followed
// only with CrossOrigin (then to that host on the pool's endpoints with
// Host set to it, never to an arbitrary address). A redirect not followed
// (hops exhausted, another host, unparsable) is returned to the visitor
// with Cache-Control: no-store. A cached response is the final one, under
// the original request's key.
type FollowRedirect struct {
	MaxHops     int  `json:"max_hops"`
	CrossOrigin bool `json:"cross_origin,omitempty"`
}

// MaxFollowRedirectHops bounds FollowRedirect.MaxHops.
const MaxFollowRedirectHops = 5

// Pool: endpoints in selection order; Retry applies to requests sent to it.
// KeepaliveIdleTimeoutMS: nil keeps the node default, 0 disables reuse.
type Pool struct {
	ID                     string     `json:"id"`
	Kind                   string     `json:"kind"`
	Algorithm              string     `json:"algorithm"`
	Endpoints              []Endpoint `json:"endpoints"`
	Retry                  Retry      `json:"retry"`
	KeepaliveIdleTimeoutMS *int64     `json:"keepalive_idle_timeout_ms,omitempty"`
	// HashKey: algorithm "hash", consistent hash of this template (allowed
	// variables only, edgeconfig ge-origin list).
	HashKey string `json:"hash_key,omitempty"`
	// Sticky: algorithm "sticky", the visitor's token pins an endpoint.
	Sticky *Sticky `json:"sticky,omitempty"`
	// RequestHost is the origin Host header; nil = the visitor's host.
	RequestHost *RequestHost `json:"request_host,omitempty"`
	// FollowPort: endpoints are contacted on the listener's public port.
	FollowPort bool `json:"follow_port,omitempty"`
	// ActiveLevel is the lowest endpoint level the edge may use: the control
	// plane's origin probe moved the pool down, or manual failback holds it
	// there until the user switches back. 0 = start at the primaries.
	ActiveLevel int `json:"active_level,omitempty"`
}

// MaxLevel bounds Endpoint.Level and Pool.ActiveLevel.
const MaxLevel = 15

// Sticky: Source cookie|header|arg named Name carries the token
// (hex SHA-256("cdnca-sticky-v1\0" site "\0" pool "\0" endpoint)[:24]).
type Sticky struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

// RequestHost: Mode "origin" sends the chosen endpoint's host (with its
// port unless default or FollowPort); "visitor_port" the visitor's host with
// the listener's public port (访问域名+端口); "custom" sends Value.
type RequestHost struct {
	Mode  string `json:"mode"`
	Value string `json:"value,omitempty"`
}

const (
	RequestHostOrigin      = "origin"
	RequestHostVisitorPort = "visitor_port"
	RequestHostCustom      = "custom"
)

// Endpoint SNIMode values.
const (
	SNIOriginHost  = "origin_host"
	SNIVisitorHost = "visitor_host"
	SNICustom      = "custom"
)

const (
	PoolOrigin = "origin"
	PoolL2     = "l2"
)

// Endpoint. HTTPS endpoints name the trust anchor (a pool CA set digest,
// "sha256:<hex>", or "system") and the SNI by SNIMode (Pool.TLSName):
// custom sends SNI, origin_host the endpoint's Host, visitor_host the
// visitor's host (per request); absent SNIMode sends SNI when set, else the
// origin request Host without its port. The SNI, the anchor and the origin
// auth identity are part of the node's upstream keepalive key, so
// connections never cross SNI or trust. L2 endpoints name the L2 node and
// its mTLS identity.
type Endpoint struct {
	ID                 string `json:"id"`
	Scheme             string `json:"scheme"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Weight             int    `json:"weight"`
	SNI                string `json:"sni,omitempty"`
	SNIMode            string `json:"sni_mode,omitempty"`
	TrustAnchor        string `json:"trust_anchor,omitempty"`
	NodeID             string `json:"node_id,omitempty"`
	MTLSIdentitySHA256 string `json:"mtls_identity_sha256,omitempty"`
	TopologyRevision   int64  `json:"topology_revision,omitempty"`
	// Level orders the endpoints (0 primary, 1 backup 1, ... MaxLevel): the
	// edge uses a level only when every endpoint of the levels before it
	// (from Pool.ActiveLevel) is unusable; within a level the pool's
	// algorithm and weights apply. MaxConns bounds one worker's connections
	// to the endpoint (0 = unbounded).
	Level    int `json:"level,omitempty"`
	MaxConns int `json:"max_conns,omitempty"`
}

// Retry: only bodyless GET/HEAD requests whose response has not started are
// retried, on connect error/timeout, read timeout and 502/503/504 (fixed by
// the format, not carried).
type Retry struct {
	Methods          []string `json:"methods"`
	MaxAttempts      int      `json:"max_attempts"`
	ConnectTimeoutMS int      `json:"connect_timeout_ms"`
	ReadTimeoutMS    int      `json:"read_timeout_ms"`
	TotalBudgetMS    int      `json:"total_budget_ms"`
}

// Route picks PoolID when every present condition matches (path prefix,
// client CIDR, node region). Routes are in evaluation order (priority
// descending, then specificity); the first match wins.
type Route struct {
	ID          string   `json:"id"`
	Priority    int      `json:"priority"`
	PathPrefix  string   `json:"path_prefix,omitempty"`
	ClientCIDRs []string `json:"client_cidrs,omitempty"`
	NodeRegions []string `json:"node_regions,omitempty"`
	// Hosts: the request host is one of these (exact, or "*.x" for any
	// deeper subdomain of x). Sorted, unique.
	Hosts          []string `json:"hosts,omitempty"`
	PoolID         string   `json:"pool_id"`
	FallbackPoolID string   `json:"fallback_pool_id,omitempty"`
}

// L2: the default pool is an L2 pool; after failures the node goes direct to
// DirectFallbackPoolID. One half-open probe and one hop are fixed.
type L2 struct {
	DirectFallbackPoolID string `json:"direct_fallback_pool_id"`
	ProbeIntervalMS      int    `json:"probe_interval_ms"`
	FailureThreshold     int    `json:"failure_threshold"`
	RecoveryThreshold    int    `json:"recovery_threshold"`
	// CacheOnly (L2配置 模式=缓存, L2_ROUTING): only a request whose URL a
	// cache rule of the site caches goes to L2; any other goes straight to
	// DirectFallbackPoolID (只有设了缓存的 URL 走 L2).
	CacheOnly bool `json:"cache_only,omitempty"`
	// Conditions (L2条件, L2_ROUTING): a request matching a condition (every
	// rule, on one of NodeIDs when present) goes to that condition's L2
	// endpoints, the endpoints of every matching condition together; any
	// other request to the L2 endpoints no condition names (none: direct).
	// Sorted by ID; an endpoint is in at most one condition.
	Conditions []L2Condition `json:"conditions,omitempty"`
	// Passthrough (L2_ROUTING v2, automatic publication): the L1 reaches an
	// L2 endpoint on the protocol and port the visitor's request came in on
	// (HTTPS keeps the Host as SNI and verifies the L2 presents this site's
	// own listener certificate); the L2, serving the same site object, goes
	// to the origin by the site's origin settings. The endpoints' scheme and
	// port are nominal then.
	Passthrough bool `json:"passthrough,omitempty"`
}

// L2Condition: the node evaluates request rules; rules on the L1 node
// (country, ISP, province, city, ID) were evaluated by the control plane
// into NodeIDs (empty: every node). No rules and no nodes: every request.
type L2Condition struct {
	ID          string   `json:"id"`
	Rules       []L2Rule `json:"rules,omitempty"`
	NodeIDs     []string `json:"node_ids,omitempty"`
	EndpointIDs []string `json:"endpoint_ids"`
}

// L2Rule: Field host | request_uri | uri | protocol; Operator eq | neq |
// contains | not_contains | prefix | suffix | regex | not_regex. A regex is
// RE2 in printable ASCII (L2-REGEX-01, httppolicycontrol
// normalizeRegexPattern): the node's PCRE runs it with the same meaning.
type L2Rule struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// L2 condition bounds: rules per condition as the L2 condition write
// (nodescheduler), L1 nodes per condition, the rule value length.
const (
	MaxL2Rules          = 32
	MaxL2ConditionNodes = 10000 // the publication target bound
	MaxL2RuleValueBytes = 4096
)

// OriginAuth signs requests sent to PoolID (COS/OSS/S3). The credentials are
// a secret object, never in the site object: Secret references it by rule and
// credential revision (Ref.Kind "origin_auth_secret").
type OriginAuth struct {
	PoolID   string `json:"pool_id"`
	Endpoint string `json:"endpoint"`
	Secret   Ref    `json:"secret"`
}

// Cache. KeyPrefix and Generation are derived (CacheKeyPrefix,
// CacheGeneration) and checked by Validate: the node's cache key is
// <KeyPrefix>|<Generation>|<purge generation>|<host or Domain>|<port>|<policy key>.
// The generation is edgeconfig.CacheGeneration (ge-cache, the same definition
// the v7 site runtime keys by): it changes only when what decides which
// object a request reads changes (cache domain, host keying, the policy's
// mode, rules, query/vary projection, slice size); a revision, quota, stale,
// lock/revalidate or size bound change, an unrelated site edit or a new
// publication keeps every object. "Purge everything" is the node's purge
// generation (cachecontrol purge_site), not part of the site object.
// Policy is the signed cache policy document; DiskQuotaBytes in it is a soft
// quota on the node's shared zone pool.
type Cache struct {
	KeyPrefix  string                         `json:"key_prefix"`
	Generation string                         `json:"generation"`
	Domain     string                         `json:"domain"`
	KeyByHost  bool                           `json:"key_by_host"`
	Policy     edgeconfig.CachePolicyDocument `json:"policy"`
}

// Security is everything that may refuse or alter a request before it is
// proxied, in the node's fixed phase order: CC (server rewrite), managed WAF
// (ModSecurity phase 1/2), rule plan (rewrite), firewall action, JS
// challenge (access).
type Security struct {
	Rules          RulePlan    `json:"rules"`
	CC             []CCBinding `json:"cc"`
	ManagedWAF     *ManagedWAF `json:"managed_waf,omitempty"`
	Challenge      *Ref        `json:"challenge,omitempty"`
	FirewallAction *Ref        `json:"firewall_action,omitempty"`
	// Mounts are the site's published rule pack mounts (control plane
	// site_security_mounts, libs/rulepack Security), in execution order,
	// and ResolvedSHA256 the digest the node reproduces before it runs them
	// (ADR 0009 §8.4). The packs are node artifact set items in the object
	// store, not referenced objects; both fields are absent without mounts.
	Mounts         []RuleMount `json:"mounts,omitempty"`
	ResolvedSHA256 string      `json:"resolved_sha256,omitempty"`
}

// RuleMount is one mounted pack (rulepack.Mount, same JSON).
type RuleMount struct {
	Layer    string                     `json:"layer"`
	PackID   string                     `json:"pack_id"`
	Version  string                     `json:"version"`
	SHA256   string                     `json:"sha256"`
	Engine   string                     `json:"engine"`
	Priority int                        `json:"priority"`
	Params   map[string]json.RawMessage `json:"params"`
}

// MaxRuleMounts bounds a site's mounts.
const MaxRuleMounts = 32

// CCBinding applies one compiled CC policy (Policy, Ref.Kind "cc_policy",
// the canonical edgeconfig.CCV2Policy) to the listed ports. SourceSHA256 is
// the policy source the control plane compiled.
type CCBinding struct {
	Ports        []int  `json:"ports"`
	Policy       Ref    `json:"policy"`
	SourceSHA256 string `json:"source_sha256"`
}

// ManagedWAF is the site's OWASP CRS managed WAF. CRSProfile names the CRS
// profile pack (system/crs-<level>, by digest) the node loads node-wide;
// Exclusions are rule IDs of the profile's exports the site does not
// evaluate (applied per request through the ModSecurity transaction);
// AllowCIDRs are networks the engine skips. Profile holds the
// configuration-time limits a node can only apply as node-level tiers (it
// serves the request with the tier that is at least as strict as Profile).
type ManagedWAF struct {
	PolicyID      string                   `json:"policy_id"`
	PolicyVersion int64                    `json:"policy_version"`
	Profile       ManagedWAFProfile        `json:"profile"`
	CRSProfile    edgeconfig.CRSProfileRef `json:"crs_profile"`
	Exclusions    []int                    `json:"exclusions"`
	AllowCIDRs    []string                 `json:"allow_cidrs"`
	// Apps are the site's application exclusion packs (waf-apptype): part of
	// the site's tier on a dynamic routing node (edgeconfig.DynamicWAFTier).
	Apps []edgeconfig.CRSAppRef `json:"apps,omitempty"`
}

type ManagedWAFProfile struct {
	RequestBodyLimit        int    `json:"request_body_limit"`
	RequestBodyNoFilesLimit int    `json:"request_body_no_files_limit"`
	RequestBodyLimitAction  string `json:"request_body_limit_action"`
	ArgumentsLimit          int    `json:"arguments_limit"`
	JSONDepthLimit          int    `json:"json_depth_limit"`
	PCREMatchLimit          int    `json:"pcre_match_limit"`
	InspectionLimitAction   string `json:"inspection_limit_action"`
}

// Ref is a reference to another object. SHA256 is the referenced plaintext's
// digest (the object store key) when the content travels as an object; it is
// empty only for kinds whose content the node holds by identity (a JS
// challenge policy version, installed by the challenge secret rollout).
type Ref struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256,omitempty"`
}

// Ref kinds.
const (
	RefCCPolicy         = "cc_policy"
	RefHTTPPolicy       = "http_policy"
	RefFirewallAction   = "firewall_action"
	RefChallenge        = "challenge_policy"
	RefOriginAuthSecret = "origin_auth_secret"
	RefErrorPageAsset   = "error_page_asset"
	// RefClientCA is a site's client CA bundle (PEM); ID and revision are the
	// site's, the digest is edgeconfig.ClientCARefFor's.
	RefClientCA = "client_ca"
)

// ErrorPage replaces the response of Status in Category with Asset (the
// node clears every origin header, writes the asset's headers and exact
// length, and ends the body; see ADR 0009 PoC §4, dynamic routing D9,
// docs/edge/dynroute-filters.md). The list is the site's effective pages:
// its own and the global ones merged (ErrorPagesFor). A status that appears
// in the list under any category is intercepted in every category, as v7's
// error_page list is: a response of that status in a category without a page
// gets the built-in text page (v7 errorpage/handler.lua fallback).
// RuleID is the publishing rule's identifier (errorpagecontrol rule IDs are
// UUIDs, theme default pages "theme.<category>.<status>"). StyleHash is the
// CSP source of an HTML page's one theme <style> (ADR 0007 §7.2,
// errorpagestyle.SourceHash), "" otherwise.
type ErrorPage struct {
	Category  string `json:"category"`
	Status    int    `json:"status"`
	RuleID    string `json:"rule_id"`
	MIMEType  string `json:"mime_type"`
	StyleHash string `json:"style_hash,omitempty"`
	Asset     Ref    `json:"asset"`
}

// ErrorPageVariant is a node-selected replacement of one site error page
// (errpage-ovr): the platform's region / node override of a slot whose page
// is a site page (http_502 / http_504: edge_connect 502 / 504). Region /
// NodeID use the node page selector form (siteobject.NodePageV2: exactly
// one, lower-case); a node takes, per (category, status), the variant naming
// it, else the one naming its region, else the site's Errors page (or none).
// Only published where the site's page is the theme's (or absent): a site's
// own rule keeps winning.
type ErrorPageVariant struct {
	Category  string `json:"category"`
	Status    int    `json:"status"`
	Region    string `json:"region,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
	RuleID    string `json:"rule_id"`
	MIMEType  string `json:"mime_type"`
	StyleHash string `json:"style_hash,omitempty"`
	Asset     Ref    `json:"asset"`
}

// MaxErrorPageVariants bounds a site's variants (two statuses for up to
// 1024 overridden nodes / regions).
const MaxErrorPageVariants = 2048

// ErrorPageMIMETypes are the media types a page may have (errorpage, v7).
var ErrorPageMIMETypes = []string{"application/json", "text/html", "text/plain"}

// HSTS is the site's Strict-Transport-Security header, sent on its TLS
// listeners only (RFC 6797 §7.2: never over plain HTTP). MaxAgeSeconds 0
// tells browsers to forget the policy.
type HSTS struct {
	MaxAgeSeconds     int64 `json:"max_age_seconds"`
	IncludeSubdomains bool  `json:"include_subdomains"`
	Preload           bool  `json:"preload"`
}

// MaxHSTSMaxAge bounds max-age (two years, the preload list's own ceiling
// is one year minimum; values above two years are refused).
const MaxHSTSMaxAge = int64(2 * 365 * 24 * 3600)

// HSTSPreloadMinAge is the max-age the preload list requires.
const HSTSPreloadMinAge = int64(365 * 24 * 3600)

// Error page categories (edge-agent errorpage.Category).
const (
	ErrorOriginResponse = "origin_response"
	ErrorEdgeRoute      = "edge_route"
	ErrorEdgeConnect    = "edge_connect"
	// Node page categories: global only, never in a site object.
	CategoryNoHost      = "no_host"
	CategoryUnknownSite = "unknown_site"
)

// Limits. MaxBodyBytes is the site's own request body limit (its HTTP
// policy's upload limit); 0 means the platform system limit, which the node
// takes from its node-level system configuration so that a platform change
// does not rewrite every site object. Either way the node writes a positive
// value into the client_max_body_size variable (native patch 23: an empty or
// 0 variable is a 500, never "unlimited").
// Connections is the package subscription's budgets shared by all its sites
// on the node.
type Limits struct {
	MaxBodyBytes int64        `json:"max_body_bytes"`
	Connections  *Connections `json:"connections,omitempty"`
}

type Connections struct {
	SubscriptionID string `json:"subscription_id"`
	// Max is the concurrent request budget (并发请求数: requests in flight,
	// each HTTP/2 or HTTP/3 stream counts; -1 unlimited, 0 refuse with 503).
	Max int64 `json:"max"`
	// BandwidthBPS is the subscription's outbound bandwidth budget on the
	// node (bit/s), split between its responses in flight; 0: unlimited.
	BandwidthBPS int64 `json:"bandwidth_bps,omitempty"`
	// ADR 0012 §6.2 market supply limits, the node's share (0: unlimited;
	// SUBSCRIPTION_LIMITS v1): MaxConnections concurrent client TCP
	// connections (QUIC is not counted), NewPerSecond new TCP connections
	// per second, QPS requests per second (503 + Retry-After: 1); over the
	// first two a request on a new connection is answered 503 and the
	// connection closed. Stopped refuses every request with 503.
	MaxConnections int64 `json:"max_connections,omitempty"`
	NewPerSecond   int64 `json:"new_per_second,omitempty"`
	QPS            int64 `json:"qps,omitempty"`
	Stopped        bool  `json:"stopped,omitempty"`
}

// Telemetry is what the node's log phase records for the site besides the
// identity fields (tenant, site, primary name, port): the package
// subscription the usage is billed to (only an enabled, live subscription;
// Limits.Connections may still name a disabled one, so the two are not
// required to agree) and the request capture policy.
type Telemetry struct {
	PackageSubscriptionID string                      `json:"package_subscription_id,omitempty"`
	Capture               siteobject.TelemetryCapture `json:"capture"`
}
