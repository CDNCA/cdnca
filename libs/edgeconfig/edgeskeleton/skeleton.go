// Package edgeskeleton renders the node skeleton of dynamic routing (ADR 0009
// section 3.1, site_runtime 9): the whole nginx.conf main/events/http levels
// with one shared server per public port, one dynamic upstream, the cache
// zone pool and the shared dictionaries. It holds no site: sites are data the
// Lua entry module (edge/openresty/dynroute/cdnca_dynroute.lua) selects per
// request. The skeleton changes, and nginx reloads, only when its input
// changes: the cross-site port table, the system configuration, the cache
// pool or the index dictionary tier.
//
// The phase entry points and their contract are frozen in
// docs/edge/node-skeleton.md; this package and the Lua module must agree.
package edgeskeleton

import (
	"bytes"
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

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
)

var (
	regionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ErrInvalid wraps every input rejection.
var ErrInvalid = errors.New("invalid node skeleton input")

// SiteRuntimeVersion is the site runtime API version the skeleton serves.
const SiteRuntimeVersion = edgeconfig.DynamicRoutingSiteRuntimeVersion

// Names shared with the Lua modules and later tasks (D3+). The dictionaries,
// configure() calls, control socket and variable declarations are the D3
// contract (docs/edge/dynroute-contract.md §6).
const (
	// EntryModule is required by every phase hook (lua_package_path has
	// <LuaRoot>/?.lua, so "dynroute.<module>").
	EntryModule = "dynroute.cdnca_dynroute"
	// Upstream is the one dynamic upstream; balancer_by_lua picks the peer.
	Upstream = "cdnca_dynamic"
	// IndexDictionary maps md5("<port>\0<name>") (edgesite.IndexKey) to the
	// 32-byte digest of the current site object (contract §4.1).
	IndexDictionary = "cdnca_site_index"
	// StateDictionary: generation pointer, port tables, rebuild state,
	// worker heartbeats (contract §4.2); LockDictionary: resty.lock.
	StateDictionary = "cdnca_site_state"
	LockDictionary  = "cdnca_site_lock"
	// StateDictionaryBytes / LockDictionaryBytes are fixed.
	StateDictionaryBytes int64 = 8 << 20
	LockDictionaryBytes  int64 = 1 << 20
	// LimitsDictionary counts each package subscription's requests in
	// flight (D10, cdnca_limits): one small key per subscription on the node.
	LimitsDictionary = "cdnca_limits_conn"
	// BandwidthDictionary: responses in flight per subscription that share
	// its bandwidth budget (D10; edgeconfig.PackageBandwidthDict, as v7).
	BandwidthDictionary         = edgeconfig.PackageBandwidthDict
	LimitsDictionaryBytes int64 = 1 << 20
	// MarketLimitsDictionary holds the market supply limits per subscription
	// (ADR 0012 ML-07, cdnca_limits): TCP connections, the new connection
	// and QPS windows, requests in flight and the per minute statistics.
	MarketLimitsDictionary            = "cdnca_limits_market"
	MarketLimitsDictionaryBytes int64 = 16 << 20
	// SubscriptionMinutesLocation (control socket) hands out the finished
	// minutes' per subscription statistics (cdnca.edge.subscription-minute/v1).
	SubscriptionMinutesLocation = "/subscription-minutes"
	// ConnectionsLocation is the control socket path the agent reads the
	// sites' in-flight counts from (JSON {"<site_id>|<port>": n}, D13-b2).
	ConnectionsLocation = "/connections"
	// ControlSocket (under Paths.StateRoot) is the agent's control socket
	// (contract §5.4); site-objects, site-index and tls-pool are the
	// directories the agent writes for the workers (§5.1, §5.5,
	// docs/edge/dynroute-tls.md §5).
	ControlSocket    = "run/cdnca-site-admin.sock"
	ObjectDirectory  = "site-objects"
	IndexDirectory   = "site-index"
	TLSPoolDirectory = "tls-pool"
	// DefaultSystemMaxBody is nginx's client_max_body_size default (1m), the
	// node limit when no system configuration is published.
	DefaultSystemMaxBody int64 = 1 << 20
	// CacheZonePrefix names the pool zones cdnca_cache_<i>[_<hash8>] (Paths.CacheZoneSuffix).
	CacheZonePrefix = "cdnca_cache_"
	// MaxCacheZones bounds the pool.
	MaxCacheZones = 64
	// MaxPorts bounds the port table (a node serves a handful in practice).
	MaxPorts = 4096
)

// SiteVariables are the contract's $cdnca_site_* (§1), written once per
// request by cdnca_site.route(); $cdnca_site_max_body defaults to "1" (patch
// 23 refuses an empty or 0 value).
var SiteVariables = []string{
	"cdnca_site_id", "cdnca_site_revision", "cdnca_site_digest", "cdnca_site_tenant", "cdnca_site_scope",
	"cdnca_site_host", "cdnca_site_port", "cdnca_site_generation", "cdnca_site_max_body", "cdnca_site_state",
}

// Variables are the module variables ($cdnca_<module>_*, contract §1 item 4)
// the skeleton declares for later modules; each is written in server_rewrite
// (before location selection) to take effect.
var Variables = append([]string{
	"cdnca_origin_scheme", // http | https
	"cdnca_origin_host",   // Host header sent to the origin
	"cdnca_origin_sni",    // real origin SNI (proxy_ssl_name)
	"cdnca_origin_pool",   // pool of the attempt (D5a, logs and later phases)
	"cdnca_origin_trust",  // trust anchor of the attempt (cdnca_origintls.verify)
	// what the origin receives (D5a, ge-origin forwarding): client address
	// headers, Upgrade/Connection, all written per attempt ("" = not sent)
	"cdnca_origin_xff", "cdnca_origin_real_ip", "cdnca_origin_proto",
	"cdnca_origin_upgrade", "cdnca_origin_connection",
	// L2 loop guard (L2_ROUTING v2): "1" on an L2 hop, "" otherwise (a
	// visitor's own X-Cdnca-L2-Hop is replaced, never passed on)
	"cdnca_origin_l2_hop",
	// "1" for an L1's hop this L2 trusts (mark + node network peer):
	// set in server_rewrite, survives ngx.exec
	L2TrustedVariable,
	// origin redirect following (ge36): the host a cross-origin redirect
	// moved the request to, and the attempt a redirect answer came from
	// (settled on re-entry: error_page clears ngx.ctx)
	"cdnca_follow_host", "cdnca_origin_attempt",
	"cdnca_waf_txid",          // managed WAF transaction ID (ADR 0009 PoC section 5, D11)
	"cdnca_waf_engine",        // "1" in location / when the skeleton runs the managed WAF engine (D11)
	"cdnca_waf_pass",          // managed WAF: "tier" while the request's first pass runs in its tier location (D11)
	"cdnca_waf_repeat_site",   // managed WAF: the two-level site whose grey zone sources log counts (waf-gap6, survives ngx.exec)
	"cdnca_filters_routed",    // "1" once server rewrite is done: errors from here on get site pages (D9)
	"cdnca_limits_conn_key",   // the subscription a request is counted against (D10, survives ngx.exec)
	"cdnca_limits_rate_key",   // the subscription whose bandwidth a response shares (D10)
	"cdnca_limits_ip_key",     // the site + client address a request is counted against (site access limits)
	"cdnca_limits_rate_after", // the site's limit_rate_after bytes ("" = 0, site access limits)
	"cdnca_limits_sub_key",    // the market subscription a request is admitted against (ML-07, survives ngx.exec)
	"cdnca_limits_site_key",   // the site + public port a request is counted in flight for (D13-b2)
}, slices.Concat(edgecache.Variables, // dynamic routing cache (D8): cdnca_cache_zone, key, TTL table, ...
	SecurityVariables)...)

// SecurityVariables are the D7 security telemetry variables (cdnca_security,
// docs/edge/dynroute-security.md): what the CC engine and the rule plan
// record for the access and security logs.
var SecurityVariables = []string{
	"cdnca_security_emit", "cdnca_security_type", "cdnca_security_action",
	"cdnca_security_severity", "cdnca_security_rule_id", "cdnca_security_block_page",
}

// Security dictionaries (D7): CC v2 counters, bans and challenge state; JS
// challenge nonces and failures; firewall action load windows.
const (
	CCStateDictionary        = "cdnca_cc_state"
	ChallengeStateDictionary = "cdnca_challenge_state"
	FirewallActionDictionary = "cdnca_firewall_action" // the engine's own name (v7 shared)
	// WAFStateDictionary: WAF v2 bans, auto block counters, challenge nonces
	// and the pass secret (cdnca_waf.lua, ge-waf), keyed by site scope.
	WAFStateDictionary       = edgeconfig.WAFStateDictionary
	CCStateDictionaryBytes   = 64 << 20
	ChallengeDictionaryBytes = 16 << 20
	FirewallDictionaryBytes  = 16 << 20
	WAFStateDictionaryBytes  = 32 << 20
	ChallengeDirectory       = "challenge"
)

// Input is everything the skeleton depends on.
type Input struct {
	// Ports is the cross-site port table (edgesite.PortProfiles of every site
	// the node composes); order does not matter.
	Ports []edgesite.PortProfile
	// IndexKeys is how many index entries the node holds (sum of
	// len(site.IndexEntries())); it selects the index dictionary tier.
	IndexKeys int
	// System is the platform system configuration; nil = built-in defaults.
	System *edgeconfig.SiteRuntimeSystem
	Node   Node
	Cache  CachePool
	Paths  Paths
	// Telemetry renders the node-level access/security logs (dynamic
	// routing D12, docs/edge/dynroute-telemetry.md): the http{} formats,
	// every server's access_log directives and the variables the log phase
	// writes. Off: no request is logged (access_log off).
	Telemetry bool
	// HealthPort (0 = none) is the agent's loopback health server: /healthz
	// and the CC v2 endpoints it polls (auto switch status, the kernel ban
	// queue of ge-ddos), as v7's health server serves them.
	HealthPort int
	// Challenges are the delivered JS challenge policy versions the master
	// preloads (their keys are root-only, as in v7): a new version changes
	// the skeleton, so it reloads. Sorted by (ID, revision), unique.
	Challenges []edgesite.Ref
	// ManagedWAF is the node's OWASP CRS engine (D11); nil renders none.
	ManagedWAF *ManagedWAF
	// UnknownSite is the node's domain mismatch page (the global unknown_site
	// error page); nil answers 421 with the node's built-in
	// default page (cdnca_filters.default_page).
	UnknownSite *NodePage
	// NoHost is the node's page for a request without a Host (the global
	// no_host error page, status 400, D13-b2); nil answers as an unknown
	// Host (UnknownSite or 421).
	NoHost *NodePage
	// SlotPages are the node's error page slot pages (errpage-3,
	// ERROR_PAGE_SLOTS: blacklist, http_403, traffic_exceeded,
	// package_expired, node_ip_access, connection_limit; the http_502 /
	// http_504 overrides are site page variants, errpage-ovr), by category; the agent already picked this node's
	// page of each (node, region, global). nil / empty: none.
	SlotPages map[string]*NodePage
	// Schedule302 renders HTTP 302 scheduling: the landing
	// location on every plain shared server (node level, before site
	// selection), realip from the loopback landing hop and the size
	// dictionary. Off: no landing and cdnca_sched302 is never called.
	Schedule302 bool
	// AutoDefense renders the auto defense dictionaries (fixed sizes,
	// ADR 0010 §10.4) and the gate location on the control socket
	// (AD-04, cdnca_autodefense). Off: the module is never loaded.
	AutoDefense bool
	// DispatchedPorts are the TCP ports the node's L4 runtime owns on IPv4
	// because an L4 forward shares them with websites (D13-c0): the port's
	// server listens on DispatchSocket(Paths.MuxRoot, port, tls) with PROXY
	// protocol instead of 0.0.0.0, the L4 dispatcher hands it the website
	// connections, and realip restores the client address. IPv6 and QUIC
	// stay direct (the L4 runtime binds TCP on IPv4).
	DispatchedPorts map[int]bool
	// ACMEOverlayRoot is the deployment root the agent's ACME HTTP-01
	// overlay serves tokens from (acmehttp01, edgeconfig.ACMEHTTP01OverlayRoot);
	// "" renders no ACME location. As in v7 every server answers
	// /.well-known/acme-challenge/<token> of a configured site's Host from the
	// overlay (no WAF, no origin); an unknown Host is still refused (421).
	ACMEOverlayRoot string
	// MarketProbe answers the node market probe path (204) and, with
	// MarketBenchmark (the node joins the market), the rate-limited benchmark
	// object, for an unknown or missing Host only (contract §1.1): a
	// configured site's Host gets the site's own response. Port 80 is served
	// for the probe even without a site there unless ProbePortTaken (an L4
	// forward owns it).
	MarketProbe     bool
	MarketBenchmark bool
	ProbePortTaken  bool
	// SiteGzip: a site sets its own compression (site.access.compression,
	// SiteGzipFromSites). gzip has no variable form, so every server turns
	// it on for any type and length and cdnca_dynroute's header_filter
	// leaves a response plain (drops Accept-Encoding) unless the site's
	// compression, or the system default for a site without one, takes it.
	SiteGzip bool
	// SiteBrotli: a site uses Brotli or a compression level of its own
	// (SiteCompression.NeedsEdgeBrotli, EDGE_BROTLI). Every server also turns
	// Brotli on for any type and length and takes both levels from
	// $cdnca_compress_* (native step 26); the same header_filter gate
	// leaves the request's Accept-Encoding at br, gzip or nothing.
	SiteBrotli bool
	// SiteWebP: a site converts JPEG/PNG to WebP (site.access.webp,
	// EDGE_WEBP): the conversion thread pool (main context), the variant
	// dictionary and cdnca_webp.
	SiteWebP bool
	// NodeNetworks are the platform's node addresses (system.ddos
	// node_networks, merged over the scopes; canonical prefixes): a request
	// marked as an L2 hop (X-Cdnca-L2-Hop) from one of them is an L1's and is
	// trusted (cdnca_dynroute). None: no hop is trusted.
	NodeNetworks []string
	// Maintenance stops serving (ADR 0014 LIC-BAN-05: the control installation
	// is banned or the node's service ticket expired): every site server keeps
	// its listeners and the site's own certificate handshake but answers every
	// request with the fixed 503 page; the probe server is not rendered. The
	// health and control servers stay, so the agent keeps working. nil = serve.
	Maintenance *Maintenance
}

// L2TrustedVariable is "1" for a request an L1 sent this node as its L2
// (X-Cdnca-L2-Hop from a node network): the L1 ran the site's
// security and counts; this node only serves it.
const L2TrustedVariable = "cdnca_l2_trusted"

// nodeNetworksConfigure is the configure option of Input.NodeNetworks.
func nodeNetworksConfigure(input Input) string {
	quoted := make([]string, 0, len(input.NodeNetworks))
	for _, network := range input.NodeNetworks {
		quoted = append(quoted, strconv.Quote(network))
	}
	return "      node_networks = { " + strings.Join(quoted, ", ") + " },\n"
}

// Maintenance is the stopped node's response.
type Maintenance struct {
	// RetryAfter is the Retry-After header value (an HTTP date); "" = none
	// (permanent).
	RetryAfter string
}

// MaintenancePage is the body of every response while stopped.
const MaintenancePage = "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>服务已暂停</title></head>" +
	"<body><h1>服务已暂停</h1><p>Service suspended.</p></body></html>\n"

// DispatchSocket is the internal socket of a dispatched port (the L4
// dispatcher connects to it): <muxRoot>/<port>-tls.sock or -plain.sock.
// cdnca_tls reads the public port back from the name.
func DispatchSocket(muxRoot string, port int, tls bool) string {
	mode := "plain"
	if tls {
		mode = "tls"
	}
	return filepath.Join(muxRoot, fmt.Sprintf("%d-%s.sock", port, mode))
}

// Auto defense (AD-04, edge/openresty/dynroute/cdnca_autodefense.lua): the
// gate the agent writes (sites, mitigations, platform allow list) and the
// per second counters (fixed length keys, 3 s TTL). Fixed sizes: a full
// dictionary evicts least recently used entries, it never grows.
const (
	AutoDefenseGateDictionary        = "cdnca_autodefense"
	AutoDefenseCountDictionary       = "cdnca_autodefense_count"
	AutoDefenseGateBytes       int64 = 64 << 20
	AutoDefenseCountBytes      int64 = 32 << 20
	// AutoDefenseLocation is the control socket path prefix the agent
	// POSTs the gate to (and GETs push statistics from).
	AutoDefenseLocation = "/autodefense/"
)

// NodePage is a node-level page a request no site serves gets: the status,
// the body file (read once in the master) and its media type.
type NodePage struct {
	Status    int
	MIMEType  string
	StyleHash string // CSP source of a theme page's <style>, or ""
	BodyFile  string // absolute path, worker readable
}

// UnknownSiteStatuses are the statuses a domain mismatch page may answer
// with (v7 errorpage CategoryUnknownSite).
var UnknownSiteStatuses = []int{403, 404, 410, 421}

func nodePageLua(page *NodePage) string {
	if page == nil {
		return "nil"
	}
	style := ""
	if page.StyleHash != "" {
		style = fmt.Sprintf(", style_hash = %q", page.StyleHash)
	}
	return fmt.Sprintf("{ status = %d, mime_type = %q, body_file = %q%s }", page.Status, page.MIMEType, page.BodyFile, style)
}

var slotPageNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// slotPagesLua renders SlotPages as a Lua table, names in order.
func slotPagesLua(pages map[string]*NodePage) string {
	if len(pages) == 0 {
		return "{}"
	}
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for index, name := range names {
		parts[index] = name + " = " + nodePageLua(pages[name])
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func validateNodePage(page *NodePage, statuses []int) error {
	if page == nil {
		return nil
	}
	if !slices.Contains(statuses, page.Status) || !slices.Contains(edgesite.ErrorPageMIMETypes, page.MIMEType) ||
		!filepath.IsAbs(page.BodyFile) || filepath.Clean(page.BodyFile) != page.BodyFile ||
		strings.ContainsAny(page.BodyFile, "\"\\$;{}\n\r\t ") ||
		page.StyleHash != "" && (page.MIMEType != "text/html" || !styleHashPattern.MatchString(page.StyleHash)) {
		return fmt.Errorf("%w: node page", ErrInvalid)
	}
	return nil
}

var styleHashPattern = regexp.MustCompile(`^sha256-[A-Za-z0-9+/]{43}=$`)

// ManagedWAF is the managed WAF part of the skeleton (task D11, ADR 0009
// PoC section 5, docs/edge/dynroute-managed-waf.md): the engine module, the
// node rule file at http level and one named location per tier. A request
// of a site with a managed WAF enters its tier location by ngx.exec from
// rewrite (cdnca_managed_waf.lua) after Lua wrote the site context into
// $cdnca_waf_txid; location / never runs ModSecurity, so sites without a
// managed WAF and node-level paths pay nothing. The files are the agent's
// (internal/dynwaf.Prepare); Tiers are every tier the node's sites use, so a
// site edit that keeps its tier changes nothing here and reloads nothing.
type ManagedWAF struct {
	ModulePath     string // ngx_http_modsecurity_module.so of the installed extension
	UnicodeMapPath string // libmodsecurity unicode.mapping of that extension
	RulesPath      string // node rule file (edgeconfig.RenderDynamicWAFRules)
	// Tiers: tier key (edgeconfig.DynamicWAFTier.Key) -> tier rule file
	// (edgeconfig.RenderDynamicWAFTier).
	Tiers map[string]string
	// CookieTiers: tier key -> the two-level tier's cookie variant rule file
	// (edgeconfig.RenderDynamicWAFTierCookies), location
	// @cdnca_waf_<key>_c; Lua enters it for a request with a cookie out of
	// the site's profile (cdnca_managed_waf adapt.shape).
	CookieTiers map[string]string
	// DetectProfiles: CRS profile pack digests whose sites get the detector
	// verdicts in their context (edgeconfig DynamicWAFRelease.TwoLevelProfiles).
	DetectProfiles []string
	// GreyProfiles: those whose grey zone challenges (grey_action challenge,
	// edgeconfig DynamicWAFRelease.GreyChallengeProfiles, ADR 0011 RI-03).
	GreyProfiles []string
	// Buckets: exclusion bucket location (edgeconfig.DynamicWAFBucketLocation)
	// -> its rule file (edgeconfig.RenderDynamicWAFBucket); SiteBuckets: the
	// sites with automatic exclusions in force -> their bucket location.
	// Every other site runs in its tier location.
	Buckets     map[string]string
	SiteBuckets map[string]string
	// CookieBuckets: exclusion bucket location -> its cookie variant rule
	// file (RenderDynamicWAFBucket over the tier's cookie variant), location
	// <bucket>_c; one per bucket of a tier in CookieTiers, so a site with
	// exclusions in force keeps the adaptive cookie reading.
	CookieBuckets map[string]string
}

// Adaptive managed WAF (ADR 0011 RI-03): the agent's per site waf_adapt
// (grey zone challenge switch, active automatic exclusions, typed
// parameters) in a fixed size dictionary, written through the control
// socket; the grey zone challenge location the node rules' 599 lands on.
// WAFGreyDictionary (waf-gap6) counts grey zone transactions per site x
// client address in fixed windows (cdnca_managed_waf repeat; LRU evicts,
// nothing queues).
const (
	WAFAdaptDictionary         = "cdnca_waf_adapt"
	WAFAdaptBytes        int64 = 16 << 20
	WAFGreyDictionary          = "cdnca_waf_grey"
	WAFGreyBytes         int64 = 8 << 20
	WAFAdaptLocation           = "/waf-adapt/"
	WAFChallengeLocation       = "@cdnca_waf_challenge"
	WAFBlockLocation           = "@cdnca_waf_block" // a tier location's ModSecurity 403 (error_page)
)

// Node is node-local origin settings (D5a cdnca_origin.configure): the
// node's region (conditional origin routes), the ingress source addresses
// (FX30 ingress-IP origin) and the resolvers for origin names (empty = the
// system configuration's resolvers, else /etc/resolv.conf).
type Node struct {
	Region string
	// ID: the node's id (lower-case UUID; "" = unknown), the L1 node an L2
	// condition's node_ids name (A19-b, cdnca_origin); cdnca_site also picks
	// a site's error page variants by it (errpage-ovr).
	ID                string
	IngressSourceIPv4 string
	IngressSourceIPv6 string
	Resolvers         []string
	// SystemCABundle verifies HTTPS origins with trust "system" (D5b;
	// "" = /etc/ssl/certs/ca-certificates.crt).
	SystemCABundle string
}

// OriginAuthDirectory (under the state root) holds the origin auth secret
// objects cdnca_originauth signs with (D5b; the agent writes them).
const OriginAuthDirectory = "origin-auth-secrets"

// BalancerKeepalive is the size of the worker's balancer connection pool
// (balancer_keepalive, shared by every site, pool, trust anchor and SNI key;
// v7 kept 32 per upstream).
const BalancerKeepalive = 256

// CachePool is the node's fixed set of cache zones (edgecache.PlanPool);
// sites pick one by variable. Zones = 0 renders no cache at all.
type CachePool = edgecache.Pool

// Paths are node-local absolute paths.
type Paths struct {
	SharedRoot string // pid, error log, temp and (by default) cache directories
	// CacheRoot holds the cache zone directories (the node's cache
	// directory, NODE_STORAGE); "" = SharedRoot/cache.
	CacheRoot string
	// LogRoot holds error.log and the node-level telemetry logs (the node's
	// log directory, NODE_STORAGE); "" = SharedRoot.
	LogRoot string
	LuaRoot string // contains dynroute/cdnca_dynroute.lua
	// StateRoot holds the agent-written run/, site-objects/, site-index/ and
	// tls-pool/ (worker readable, contract §5).
	StateRoot string
	// ObjectsRoot is where the workers read site objects
	// (<root>/sha256/<2>/<2>/<64>); "" = StateRoot/site-objects. A node
	// agent points it at its object store opened shared (F13: no copy).
	ObjectsRoot string
	// PlaceholderCertificate/Key satisfy nginx on TLS servers; the
	// certificate phase always replaces them (a client that sees this
	// certificate means the dynamic path failed open).
	PlaceholderCertificate string
	PlaceholderKey         string
	// OriginTrustPlaceholder satisfies proxy_ssl_verify; it must not hold
	// any tenant CA (origin trust is per pool, in proxy_ssl_verify_by_lua).
	OriginTrustPlaceholder string
	// RulePlanRoot holds the agent's compiled rule pack mount plans
	// (<resolved_sha256>.json, worker readable tmpfs); "" = no mounts.
	RulePlanRoot string
	// MuxRoot holds the internal sockets of DispatchedPorts; required
	// when any port is dispatched.
	MuxRoot string
}

// Cache is the cache zone root.
func (paths Paths) Cache() string {
	if paths.CacheRoot != "" {
		return paths.CacheRoot
	}
	return filepath.Join(paths.SharedRoot, "cache")
}

// CacheZoneSuffix is edgecache.ZoneSuffix of the cache root: "" under
// SharedRoot/cache (cdnca_cache_<i>), else _<hash8> so a moved cache
// directory reloads under new zone names.
func (paths Paths) CacheZoneSuffix() string {
	return edgecache.ZoneSuffix(paths.Cache(), filepath.Join(paths.SharedRoot, "cache"))
}

// Logs is the log root.
func (paths Paths) Logs() string {
	if paths.LogRoot != "" {
		return paths.LogRoot
	}
	return paths.SharedRoot
}

// Objects is the site object directory the workers read.
func (paths Paths) Objects() string {
	if paths.ObjectsRoot != "" {
		return paths.ObjectsRoot
	}
	return filepath.Join(paths.StateRoot, ObjectDirectory)
}

// IndexTier is one index dictionary size and the keys it holds with 25%
// headroom: each key is one 128-byte slab slot (16-byte key + 32-byte value,
// ADR 0009 PoC section 1).
type IndexTier struct {
	Bytes int64
	Keys  int
}

const indexSlotBytes = 128

// IndexTiers are the fixed tiers; changing tier resizes the zone, which nginx
// recreates empty on reload (the index is then rebuilt).
var IndexTiers = func() []IndexTier {
	var tiers []IndexTier
	for _, mib := range []int64{4, 16, 64, 160, 640} {
		bytes := mib << 20
		tiers = append(tiers, IndexTier{Bytes: bytes, Keys: int(bytes * 4 / 5 / indexSlotBytes)})
	}
	return tiers
}()

// SelectIndexTier is the smallest tier holding keys.
func SelectIndexTier(keys int) (IndexTier, error) {
	if keys < 0 {
		return IndexTier{}, fmt.Errorf("%w: negative index key count", ErrInvalid)
	}
	for _, tier := range IndexTiers {
		if keys <= tier.Keys {
			return tier, nil
		}
	}
	return IndexTier{}, fmt.Errorf("%w: %d index keys exceed the largest tier (%d)", ErrInvalid, keys, IndexTiers[len(IndexTiers)-1].Keys)
}

// FromSites builds the site-derived part of the input: the port table (with
// edgesite's cross-site checks) and the index key count.
func FromSites(sites []edgesite.Site) ([]edgesite.PortProfile, int, error) {
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return nil, 0, err
	}
	keys := 0
	for _, site := range sites {
		keys += len(site.IndexEntries())
	}
	return ports, keys, nil
}

// Render returns the node nginx.conf. The same input always gives the same
// bytes (ports are sorted, nothing depends on map order or time).
func Render(input Input) ([]byte, error) {
	ports, err := validate(input)
	if err != nil {
		return nil, err
	}
	tier, err := SelectIndexTier(input.IndexKeys)
	if err != nil {
		return nil, err
	}
	paths, cache := input.Paths, input.Cache
	var output bytes.Buffer
	output.WriteString("# generated by cdnca node skeleton (site_runtime 9); no site is compiled in\n")
	if waf := input.ManagedWAF; waf != nil {
		fmt.Fprintf(&output, "load_module %s;\n", quote(waf.ModulePath))
	}
	output.WriteString(edgeconfig.SiteRuntimeSystemMain(input.System))
	if input.SiteWebP {
		// cdnca_webp converts in ngx.run_worker_thread (never in the event loop)
		fmt.Fprintf(&output, "thread_pool %s threads=%d max_queue=%d;\n", WebPThreadPool, WebPThreads, WebPQueue)
	}
	fmt.Fprintf(&output, "error_log %s notice;\n", quote(filepath.Join(paths.Logs(), "error.log")))
	fmt.Fprintf(&output, "pid %s;\n", quote(filepath.Join(paths.SharedRoot, "nginx.pid")))
	output.WriteString(edgeconfig.SiteRuntimeSystemEvents(input.System))
	output.WriteString("http {\n  access_log off;\n")
	output.WriteString(edgeconfig.SiteRuntimeSystemHTTP(input.System))
	if input.Telemetry {
		output.WriteString(edgeconfig.RenderDynamicRoutingTelemetryHTTP())
	}
	for _, name := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		fmt.Fprintf(&output, "  %s_temp_path %s;\n", name, quote(filepath.Join(paths.SharedRoot, name+"-temp")))
	}
	// <lua>/dynroute/?.lua first: the dynroute modules require each other
	// by bare name (cdnca_site, cdnca_tls); <lua>/?.lua for "dynroute.x",
	// "httppolicy.engine", "firewallaction.engine"; <lua>/security/?.lua for
	// the security engines required by bare name (cc, cdnca_rule_interp,
	// cdnca_waf, cdnca_iplib).
	luaPath := filepath.Join(paths.LuaRoot, "dynroute", "?.lua") + ";" + filepath.Join(paths.LuaRoot, "?.lua") + ";" +
		filepath.Join(paths.LuaRoot, "security", "?.lua") + ";;"
	if input.Schedule302 {
		// cdnca_sched302 (HTTP 302 scheduling), required by bare name
		luaPath = filepath.Join(paths.LuaRoot, "sched302", "?.lua") + ";" + luaPath
	}
	fmt.Fprintf(&output, "  lua_package_path %s;\n", quote(luaPath))
	// The declaration locations never run; the first Lua read of a variable
	// must not warn (contract §6.2).
	output.WriteString("  uninitialized_variable_warn off;\n")
	// every module declares its variables (site, origin, cache, security):
	// more than nginx's default variables hash holds without a warning
	output.WriteString("  variables_hash_max_size 2048;\n  variables_hash_bucket_size 128;\n")
	// cache rule path_regex (ge36): a match needing more backtracking than
	// this fails (the rule does not match) instead of holding the worker
	fmt.Fprintf(&output, "  lua_regex_match_limit %d;\n", edgeconfig.CachePathRegexMatchLimit)
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", IndexDictionary, tier.Bytes>>20)
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", StateDictionary, StateDictionaryBytes>>20)
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", LockDictionary, LockDictionaryBytes>>20)
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", LimitsDictionary, LimitsDictionaryBytes>>20)
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", BandwidthDictionary, LimitsDictionaryBytes>>20)
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", MarketLimitsDictionary, MarketLimitsDictionaryBytes>>20)
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n  lua_shared_dict %s %dm;\n  lua_shared_dict %s %dm;\n",
		CCStateDictionary, CCStateDictionaryBytes>>20, ChallengeStateDictionary, ChallengeDictionaryBytes>>20,
		FirewallActionDictionary, FirewallDictionaryBytes>>20)
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", WAFStateDictionary, WAFStateDictionaryBytes>>20)
	output.WriteString(edgeconfig.SecurityBanHTTP)
	systemMaxBody := DefaultSystemMaxBody
	if input.System != nil {
		systemMaxBody = input.System.Nginx.ClientMaxBodyBytes
	}
	resolvers := input.Node.Resolvers
	if len(resolvers) == 0 && input.System != nil {
		resolvers = input.System.Nginx.ResolverAddresses
	}
	quoted := make([]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		quoted = append(quoted, strconv.Quote(resolver))
	}
	// Loaded in the master at start/reload. `nginx -t` never runs Lua (lua-nginx-module skips the VM
	// under ngx_test_config), so a broken module is found by the agent's init-only load
	// (agents/edge-agent/internal/nativeruntime/precheck.go), not by -t.
	fmt.Fprintf(&output, "  init_by_lua_block {\n    require(%q).configure({\n      objects_root = %q,\n      index_root = %q,\n"+
		"      tls_pool_root = %q,\n      system_max_body = %d,\n      node_region = %q,\n      node_id = %q,\n      ingress_source_ipv4 = %q,\n"+
		"      ingress_source_ipv6 = %q,\n      server_addr_outgoing = %t,\n      resolvers = { %s },\n      cache_zones = %d,\n"+
		"      challenge_root = %q,\n      challenge_lua = %q,\n      challenges = { %s },\n"+
		"      system_ca_file = %q,\n      origin_auth_root = %q,\n      unknown_site = %s,\n      no_host = %s,\n      slot_pages = %s,\n%s    })\n  }\n",
		EntryModule, paths.Objects(), filepath.Join(paths.StateRoot, IndexDirectory),
		filepath.Join(paths.StateRoot, TLSPoolDirectory), systemMaxBody, input.Node.Region, input.Node.ID, input.Node.IngressSourceIPv4,
		input.Node.IngressSourceIPv6, input.System != nil && input.System.Nginx.ServerAddrOutgoing, strings.Join(quoted, ", "), cache.Zones,
		filepath.Join(paths.StateRoot, ChallengeDirectory), filepath.Join(paths.LuaRoot, "challenge"), challengeList(input.Challenges),
		systemCABundle(input.Node), filepath.Join(paths.StateRoot, OriginAuthDirectory), nodePageLua(input.UnknownSite), nodePageLua(input.NoHost),
		slotPagesLua(input.SlotPages), cacheZoneSuffixConfigure(paths)+schedule302Configure(input)+rulePlanConfigure(paths)+managedWAFConfigure(input)+siteGzipConfigure(input)+siteBrotliConfigure(input)+securityAggregateConfigure(input)+nodeNetworksConfigure(input))
	fmt.Fprintf(&output, "  init_worker_by_lua_block { require(%q).init_worker() }\n", EntryModule)
	if waf := input.ManagedWAF; waf != nil {
		// The node rules are the parent of every tier location's rule set
		// (merged after the tier's own file); nothing at http level enables
		// the engine.
		fmt.Fprintf(&output, "  modsecurity_rules 'SecUnicodeMapFile %s 20127';\n  modsecurity_rules_file %s;\n",
			waf.UnicodeMapPath, quote(waf.RulesPath))
	}
	writeNodeLocationMap(&output, input)
	// limit_rate_after takes a size: an unset site value is 0
	output.WriteString("  map $cdnca_limits_rate_after $cdnca_limits_rate_after_bytes {\n    \"\" 0;\n    default $cdnca_limits_rate_after;\n  }\n")
	if input.MarketProbe && input.MarketBenchmark {
		output.WriteString(benchmarkZones)
	}
	if input.Schedule302 {
		fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", Schedule302SizesDictionary, Schedule302SizesDictionaryBytes>>20)
	}
	if input.ManagedWAF != nil {
		fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", WAFAdaptDictionary, WAFAdaptBytes>>20)
		fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", WAFGreyDictionary, WAFGreyBytes>>20)
	}
	if input.Telemetry {
		fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", SecurityAggregateDictionary, SecurityAggregateDictionaryBytes>>20)
	}
	if input.SiteWebP {
		fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", WebPDictionary, WebPDictionaryBytes>>20)
	}
	if input.AutoDefense {
		fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n  lua_shared_dict %s %dm;\n", AutoDefenseGateDictionary,
			AutoDefenseGateBytes>>20, AutoDefenseCountDictionary, AutoDefenseCountBytes>>20)
	}
	if cache.Zones > 0 {
		// D8: zone pool, purge generations, patch 24 TTL table, status maps
		output.WriteString(edgecache.HTTP(cache, paths.Cache(), paths.CacheZoneSuffix(), input.IndexKeys))
	}
	// nginx's own keepalive cache keys by sockaddr only and would hand a
	// connection verified for one pool's trust to another (PoC section 3):
	// off; reuse goes through balancer.enable_keepalive with a key that
	// carries the trust anchor (D5a: site, pool, trust anchor, SNI), from
	// the worker's balancer_keepalive pool.
	fmt.Fprintf(&output, "  upstream %s {\n    server 0.0.0.1;\n    balancer_by_lua_block { require(%q).balancer() }\n    keepalive 0;\n"+
		"    balancer_keepalive %d;\n  }\n", Upstream, EntryModule, BalancerKeepalive)
	for _, port := range ports {
		if input.Maintenance != nil {
			writeMaintenanceServer(&output, port, input)
			continue
		}
		writeServer(&output, port, input)
	}
	if input.Maintenance == nil && probeServer(input, ports) {
		writeProbeServer(&output, input)
	}
	if input.HealthPort != 0 {
		writeHealthServer(&output, input.HealthPort)
	}
	if input.Telemetry {
		writeSecurityFlushServer(&output, paths)
	}
	writeControlServer(&output, paths, input.Telemetry, input.Schedule302, input.AutoDefense, input.ManagedWAF != nil,
		input.MarketProbe && input.MarketBenchmark, input.SiteBrotli)
	output.WriteString("}\n")
	return output.Bytes(), nil
}

// NoHostLocation is the named location the nginx core's own 400 (a request
// refused while parsing: HTTP/1.1 without or with an empty Host) is sent to
// (B11; the no_host page or the built-in default page).
const NoHostLocation = "@cdnca_no_host"

// writeNoHost: error_page 400 to the no_host location, whose content is
// cdnca_site.no_host(). Only a request without a Host that never reached
// server rewrite gets the page there (the no_host page, else the node's
// built-in default page, so always rendered); any other 400
// (another malformed request, a site's ModSecurity or Lua) keeps nginx's own
// response. Server rewrite does not run in a named location; rewrite and
// access are switched off.
func writeNoHost(output *bytes.Buffer) {
	fmt.Fprintf(output, "    error_page 400 %s;\n    location %s {\n", NoHostLocation, NoHostLocation)
	output.WriteString("      rewrite_by_lua_block { return }\n      access_by_lua_block { return }\n")
	output.WriteString("      content_by_lua_block { return require(\"cdnca_site\").no_host() }\n    }\n")
}

func writeServer(output *bytes.Buffer, port edgesite.PortProfile, input Input) {
	output.WriteString("  server {\n")
	dispatched := input.DispatchedPorts[port.Port]
	ssl := ""
	if port.TLS {
		ssl = " ssl"
	}
	if dispatched {
		// IPv4 TCP comes from the L4 dispatcher (PROXY protocol)
		fmt.Fprintf(output, "    listen %s%s proxy_protocol default_server;\n",
			quote("unix:"+DispatchSocket(input.Paths.MuxRoot, port.Port, port.TLS)), ssl)
	}
	for _, address := range addresses(port) {
		listen := net(address, port.Port)
		if !dispatched || address != "0.0.0.0" {
			fmt.Fprintf(output, "    listen %s%s default_server;\n", listen, ssl)
		}
		if port.HTTP3 {
			// reuseport: the kernel (nginx's QUIC BPF helper) keeps a
			// connection's packets on one worker. Without it, with several
			// workers, 0.5% of new QUIC connections fail and ~10% just after
			// a reload (tests/dynroute-tls/run.sh ONLY=skeleton; v7 has no
			// reuseport). Known cost: each reload logs
			// "[emerg] close() socket <addr> failed (9: Bad file descriptor)"
			// once per worker and QUIC socket, with no effect on service.
			fmt.Fprintf(output, "    listen %s quic reuseport default_server;\n", listen)
		}
	}
	output.WriteString("    server_name _;\n")
	if port.TLS {
		// http2 on when any site of the port has it; the client hello turns
		// it off per connection for a site without it (native patch 27).
		fmt.Fprintf(output, "    http2 %s;\n", onOff(port.HTTP2))
		if port.HTTP3 {
			output.WriteString("    http3 on;\n")
		}
		// QUIC needs TLSv1.3 on the server; sites narrow in the client hello.
		output.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
		fmt.Fprintf(output, "    ssl_certificate %s;\n    ssl_certificate_key %s;\n",
			quote(input.Paths.PlaceholderCertificate), quote(input.Paths.PlaceholderKey))
		fmt.Fprintf(output, "    ssl_client_hello_by_lua_block { require(%q).client_hello() }\n", EntryModule)
		fmt.Fprintf(output, "    ssl_certificate_by_lua_block { require(%q).certificate() }\n", EntryModule)
	}
	for _, phase := range []string{"server_rewrite", "rewrite", "access", "header_filter", "body_filter", "log"} {
		fmt.Fprintf(output, "    %s_by_lua_block { require(%q).%s() }\n", phase, EntryModule, phase)
	}
	if input.Telemetry {
		// Paths were validated with the rest of the input.
		directives, _ := edgeconfig.RenderDynamicRoutingTelemetryServer(input.Paths.Logs())
		output.WriteString(directives)
	}
	output.WriteString("    client_max_body_size $cdnca_site_max_body;\n")
	// the site's limit_rate_after (cdnca_limits.client; $limit_rate is set there)
	output.WriteString("    limit_rate_after $cdnca_limits_rate_after_bytes;\n")
	if input.SiteGzip {
		output.WriteString(siteGzipServer)
	}
	if input.SiteBrotli {
		output.WriteString(siteBrotliServer)
	}
	if dispatched {
		// Only the L4 dispatcher reaches the internal socket; the PROXY
		// header carries the client address and the public port. The 302
		// landing's loopback realip cannot share the server (one
		// real_ip_header): a dispatched port has no landing.
		output.WriteString("    set_real_ip_from unix:;\n    real_ip_header proxy_protocol;\n")
	} else if input.Schedule302 && !port.TLS {
		output.WriteString(schedule302Landing(input))
	}
	proxy := proxyBody(input, "      ")
	var root strings.Builder
	if input.ManagedWAF != nil {
		// "the engine is here and the request is in location /": the only
		// place a request is handed to its tier location (set runs in the
		// rewrite phase before rewrite_by_lua, which ngx_lua postpones to
		// the end of the phase).
		root.WriteString("      set $cdnca_waf_engine 1;\n")
	}
	root.WriteString(proxy)
	if input.Cache.Zones > 0 {
		root.WriteString(edgecache.PublicLocation("      "))
	}
	writeNoHost(output)
	// a configured site's Host on a probe path is served as location /
	writeNodeLocations(output, input, port.TLS, root.String())
	output.WriteString("    location / {\n")
	output.WriteString(root.String())
	output.WriteString("    }\n")
	if waf := input.ManagedWAF; waf != nil {
		// The grey zone challenge (ADR 0011 PoC-3): the node rules deny with
		// 599, served here; the client sees the challenge page's own status.
		// The request's security ran in its tier location: the server's
		// rewrite and access handlers do not run again here (empty blocks
		// override them; $cdnca_waf_pass is still "tier").
		fmt.Fprintf(output, "    error_page %d = %s;\n    location %s {\n      rewrite_by_lua_block { }\n      access_by_lua_block { }\n"+
			"      content_by_lua_block { require(\"cdnca_managed_waf\").challenge() }\n    }\n",
			edgeconfig.DynamicWAFChallengeStatus, WAFChallengeLocation, WAFChallengeLocation)
		// A ModSecurity deny (403) gets the site's block page (retest N3):
		// marked as the node's own block response, the 403 nginx generates
		// here is replaced by cdnca_filters block_page (the site's edge_route
		// 403 page). The tier locations never intercept upstream errors
		// (proxy_intercept_errors stays off), so an origin's 403 is never
		// sent here.
		fmt.Fprintf(output, "    location %s {\n      rewrite_by_lua_block { }\n      access_by_lua_block { }\n"+
			"      content_by_lua_block { %s; return ngx.exit(403) }\n    }\n", WAFBlockLocation, edgeconfig.MarkBlockPageLua)
		// One location per tier, proxying as location / does; the tier's
		// rule file is merged before the http-level node rules. A cacheable
		// request moves on to a cache variant from here (its ModSecurity
		// transaction carries over: response phases and the audit log).
		// An exclusion bucket is a location the same way (its file
		// includes its tier's).
		locations := map[string]string{}
		for _, key := range sortedTierKeys(waf.Tiers) {
			locations[edgeconfig.DynamicWAFTierPrefix+key] = waf.Tiers[key]
			if path, ok := waf.CookieTiers[key]; ok {
				locations[edgeconfig.DynamicWAFTierPrefix+key+edgeconfig.DynamicWAFCookieSuffix] = path
			}
		}
		for name, path := range waf.Buckets {
			locations[name] = path
		}
		for name, path := range waf.CookieBuckets {
			locations[name+edgeconfig.DynamicWAFCookieSuffix] = path
		}
		for _, name := range sortedTierKeys(locations) {
			fmt.Fprintf(output, "    location %s {\n", name)
			fmt.Fprintf(output, "      modsecurity on;\n      modsecurity_rules_file %s;\n      modsecurity_transaction_id $%s;\n",
				quote(locations[name]), edgeconfig.DynamicWAFContextVariable)
			// a location's own error_page drops the server's (nginx does not
			// merge them): the grey zone 599 is repeated here
			fmt.Fprintf(output, "      error_page 403 = %s;\n      error_page %d = %s;\n", WAFBlockLocation,
				edgeconfig.DynamicWAFChallengeStatus, WAFChallengeLocation)
			output.WriteString(proxy)
			if input.Cache.Zones > 0 {
				output.WriteString(edgecache.PublicLocation("      "))
			}
			output.WriteString("    }\n")
		}
	}
	if input.Cache.Zones > 0 {
		// cacheable requests: the cache module ngx.exec's into a variant
		output.WriteString(edgecache.Variants("    ", proxy))
	}
	// origin redirect following (ge36): a following site's request the
	// cache does not serve
	output.WriteString(edgecache.FollowLocationBlock("    ", proxy, input.Cache.Zones > 0))
	// 数据实时返回/发送 (SITE_EDGE_OPTIONS): a request the cache does not
	// serve of a site that proxies it unbuffered (cdnca_origin.unbuffered_location)
	for _, location := range UnbufferedLocations {
		fmt.Fprintf(output, "    location %s {\n", location.Name)
		output.WriteString(root.String())
		if location.Response {
			output.WriteString("      proxy_buffering off;\n")
		}
		if location.Request {
			output.WriteString("      proxy_request_buffering off;\n")
		}
		output.WriteString("    }\n")
	}
	output.WriteString("  }\n")
}

// writeMaintenanceServer is a site port's server while the node is stopped:
// the same listeners (QUIC too) and TLS handshake through cdnca_tls, so a
// client gets the site's own certificate, then 503 for every request.
func writeMaintenanceServer(output *bytes.Buffer, port edgesite.PortProfile, input Input) {
	output.WriteString("  server {\n")
	ssl := ""
	if port.TLS {
		ssl = " ssl"
	}
	for _, address := range addresses(port) {
		listen := net(address, port.Port)
		fmt.Fprintf(output, "    listen %s%s default_server;\n", listen, ssl)
		if port.HTTP3 {
			fmt.Fprintf(output, "    listen %s quic reuseport default_server;\n", listen)
		}
	}
	output.WriteString("    server_name _;\n")
	if port.TLS {
		fmt.Fprintf(output, "    http2 %s;\n", onOff(port.HTTP2))
		if port.HTTP3 {
			output.WriteString("    http3 on;\n")
		}
		output.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
		fmt.Fprintf(output, "    ssl_certificate %s;\n    ssl_certificate_key %s;\n",
			quote(input.Paths.PlaceholderCertificate), quote(input.Paths.PlaceholderKey))
		fmt.Fprintf(output, "    ssl_client_hello_by_lua_block { require(%q).client_hello() }\n", EntryModule)
		fmt.Fprintf(output, "    ssl_certificate_by_lua_block { require(%q).certificate() }\n", EntryModule)
	}
	output.WriteString("    location / {\n      default_type \"text/html; charset=utf-8\";\n")
	if input.Maintenance.RetryAfter != "" {
		fmt.Fprintf(output, "      add_header Retry-After %s always;\n", quote(input.Maintenance.RetryAfter))
	}
	fmt.Fprintf(output, "      return 503 %s;\n    }\n  }\n", strconv.Quote(MaintenancePage))
}

func systemCABundle(node Node) string {
	if node.SystemCABundle != "" {
		return node.SystemCABundle
	}
	return "/etc/ssl/certs/ca-certificates.crt"
}

// ProxyHeaders are the request headers the origin receives, all written per
// attempt by cdnca_origin (an empty value sends no header): Host, the client
// address headers (X-Forwarded-For / X-Real-IP / X-Forwarded-Proto: the
// edge's peer, or a trusted proxy's kept chain; none for L2 hops and cache
// prewarm), Upgrade and Connection (WebSocket sites), and the L2 hop mark
// (L2_ROUTING v2: the L2 that receives it goes straight to the origin).
func ProxyHeaders(indent string) string {
	return indent + "proxy_set_header Host $cdnca_origin_host;\n" +
		indent + "proxy_set_header X-Forwarded-For $cdnca_origin_xff;\n" +
		indent + "proxy_set_header X-Real-IP $cdnca_origin_real_ip;\n" +
		indent + "proxy_set_header X-Forwarded-Proto $cdnca_origin_proto;\n" +
		indent + "proxy_set_header Upgrade $cdnca_origin_upgrade;\n" +
		indent + "proxy_set_header Connection $cdnca_origin_connection;\n" +
		indent + "proxy_set_header " + L2HopHeader + " $cdnca_origin_l2_hop;\n"
}

// L2HopHeader marks a request an L1 sends to an L2 (L2_ROUTING v2).
const L2HopHeader = "X-Cdnca-L2-Hop"

// proxyBody: the origin directives every proxying location shares.
func proxyBody(input Input, indent string) string {
	var output bytes.Buffer
	// proxy_http_version / proxy_next_upstream: the system configuration's
	// (系统设置 > Nginx > Http), 1.1 and the v7 conditions without one.
	var settings edgeconfig.NginxSettings
	if input.System != nil {
		settings = input.System.Nginx.Settings()
	}
	output.WriteString(indent + "proxy_http_version " + edgeconfig.NginxProxyHTTPVersion(settings) + ";\n")
	output.WriteString(ProxyHeaders(indent))
	// Retries are the balancer's (D5a: per pool tries and time budget, set
	// with set_more_tries/set_timeouts): nginx only says which outcomes may
	// go to the next attempt and puts no bound of its own.
	output.WriteString(indent + "proxy_next_upstream " + edgeconfig.NginxProxyNextUpstream(settings) + ";\n" +
		indent + "proxy_next_upstream_tries 0;\n" + indent + "proxy_next_upstream_timeout 0;\n")
	output.WriteString(indent + "proxy_ssl_server_name on;\n" + indent + "proxy_ssl_name $cdnca_origin_sni;\n" + indent + "proxy_ssl_verify on;\n")
	fmt.Fprintf(&output, "%sproxy_ssl_trusted_certificate %s;\n", indent, quote(input.Paths.OriginTrustPlaceholder))
	output.WriteString(indent + "lua_upstream_skip_openssl_default_verify on;\n")
	fmt.Fprintf(&output, "%sproxy_ssl_verify_by_lua_block { require(%q).proxy_ssl_verify() }\n", indent, EntryModule)
	fmt.Fprintf(&output, "%sproxy_pass $cdnca_origin_scheme://%s;\n", indent, Upstream)
	return output.String()
}

// Node-level paths an unknown Host may still reach on a shared server
// (contract §1.1): $cdnca_node_location is "1" for the 302 landing and
// "probe" for the market probe paths, which a configured site's Host takes
// back (their location proxies as location / does; cdnca_dynroute.probe
// serves them only for an unknown Host, and only then fills the benchmark's
// limit keys: limit_conn and limit_req skip an empty key).
const (
	// NodeLocationProbe is the map value of the market probe paths.
	NodeLocationProbe = "probe"
	// MarketProbePort is where the node market probes edges (plain HTTP).
	MarketProbePort = 80
)

// ProbeVariables are the benchmark's limit keys (empty: not counted).
var ProbeVariables = []string{"cdnca_probe_client", "cdnca_probe_all"}

// benchmarkZones rate-limit the benchmark object per client address and in
// total (v7 siteruntimev2 default server: a few probers, a few connections).
const benchmarkZones = "  limit_conn_zone $cdnca_probe_client zone=cdnca_market_benchmark_ip:1m;\n" +
	"  limit_conn_zone $cdnca_probe_all zone=cdnca_market_benchmark_all:64k;\n" +
	"  limit_req_zone $cdnca_probe_client zone=cdnca_market_benchmark_rate:1m rate=6r/m;\n"

const benchmarkLimits = "      limit_conn cdnca_market_benchmark_ip 8;\n      limit_conn cdnca_market_benchmark_all 32;\n" +
	"      limit_req zone=cdnca_market_benchmark_rate burst=40 nodelay;\n      limit_conn_status 429;\n      limit_req_status 429;\n"

// ACMEOriginLocation is where an ACME HTTP-01 request the node holds no
// token for goes (源站申请证书, cdnca_dynroute.acme_origin).
const ACMEOriginLocation = "@cdnca_acme_origin"

// UnbufferedLocations are the named locations of 数据实时返回 (response)
// and 数据实时发送 (request), cdnca_origin.unbuffered_location.
var UnbufferedLocations = []struct {
	Name              string
	Response, Request bool
}{
	{"@cdnca_unbuffered_response", true, false},
	{"@cdnca_unbuffered_request", false, true},
	{"@cdnca_unbuffered_both", true, true},
}

// writeNodeLocations: the ACME HTTP-01 overlay (v7 renderACMEHTTP01Location,
// without the site's WAF and origin selection: its own rewrite and access
// phases) and the market probe paths of a plain server.
func writeNodeLocations(output *bytes.Buffer, input Input, tls bool, rootBody string) {
	if input.ACMEOverlayRoot != "" {
		var acme strings.Builder
		acme.WriteString(edgeconfig.RenderACMEHTTP01Location(input.ACMEOverlayRoot))
		location := strings.Replace(acme.String(), "      default_type text/plain;\n",
			"      rewrite_by_lua_block { return }\n      access_by_lua_block { return }\n      default_type text/plain;\n", 1)
		// 源站申请证书 (SITE_EDGE_OPTIONS): a token the node does not hold
		// goes to the origin when the site passes ACME through, else 404;
		// one the node holds (our own issuance) is always answered here.
		location = strings.Replace(location, " =404;\n", " "+ACMEOriginLocation+";\n", 1)
		output.WriteString(location)
		fmt.Fprintf(output, "    location %s {\n      rewrite_by_lua_block { return }\n", ACMEOriginLocation)
		fmt.Fprintf(output, "      access_by_lua_block { return require(%q).acme_origin() }\n", EntryModule)
		output.WriteString("      add_header Cache-Control \"no-store\" always;\n")
		output.WriteString(rootBody)
		output.WriteString("    }\n")
	}
	if !input.MarketProbe || tls {
		return
	}
	paths := []string{marketprobe.Path}
	if input.MarketBenchmark {
		paths = append(paths, marketprobe.BenchmarkPath)
	}
	for _, path := range paths {
		fmt.Fprintf(output, "    location = %s {\n", path)
		if path == marketprobe.BenchmarkPath {
			output.WriteString(benchmarkLimits)
		}
		fmt.Fprintf(output, "      access_by_lua_block { return require(%q).probe() }\n", EntryModule)
		output.WriteString(rootBody)
		output.WriteString("    }\n")
	}
}

// probeServer: port 80 answers the probe without a site there, unless an L4
// forward owns it (v7 writeDefaultHTTPServers).
func probeServer(input Input, ports []edgesite.PortProfile) bool {
	if !input.MarketProbe || input.ProbePortTaken {
		return false
	}
	return !slices.ContainsFunc(ports, func(port edgesite.PortProfile) bool { return port.Port == MarketProbePort })
}

// writeProbeServer is port 80 without a site: no site selection, only the
// probe paths; everything else gets the unknown site answer.
func writeProbeServer(output *bytes.Buffer, input Input) {
	fmt.Fprintf(output, "  server {\n    listen 0.0.0.0:%d default_server;\n    server_name _;\n", MarketProbePort)
	writeNoHost(output)
	fmt.Fprintf(output, "    location = %s {\n      content_by_lua_block { return require(%q).probe() }\n    }\n", marketprobe.Path, EntryModule)
	if input.MarketBenchmark {
		fmt.Fprintf(output, "    location = %s {\n      set $cdnca_probe_client $binary_remote_addr;\n      set $cdnca_probe_all 1;\n%s", marketprobe.BenchmarkPath, benchmarkLimits)
		fmt.Fprintf(output, "      content_by_lua_block { return require(%q).probe() }\n    }\n", EntryModule)
	}
	output.WriteString("    location / {\n      content_by_lua_block { return require(\"cdnca_site\").reject_unknown() }\n    }\n  }\n")
}

func writeNodeLocationMap(output *bytes.Buffer, input Input) {
	schedule302 := input.Schedule302
	output.WriteString("  map $uri $cdnca_node_location {\n    default \"\";\n")
	if input.MarketProbe {
		fmt.Fprintf(output, "    %s %s;\n", marketprobe.Path, NodeLocationProbe)
		if input.MarketBenchmark {
			fmt.Fprintf(output, "    %s %s;\n", marketprobe.BenchmarkPath, NodeLocationProbe)
		}
	}

	if schedule302 {
		// the landing names its site in the path (the Host is a node's)
		fmt.Fprintf(output, "    ~^%s 1;\n", sched302.LandingPrefix)
	}
	output.WriteString("  }\n")
}

// writeControlServer: the agent's control socket (contract §5.4) and, in a
// location that never runs, the declaration of every variable (a
// server-level set would run in SERVER_REWRITE and overwrite what Lua wrote,
// PoC section 5; variables are http-wide, one declaration serves all).
func writeControlServer(output *bytes.Buffer, paths Paths, telemetry, schedule302, autoDefense, managedWAF, benchmark, brotli bool) {
	fmt.Fprintf(output, "  server {\n    listen %s;\n", quote("unix:"+filepath.Join(paths.StateRoot, ControlSocket)))
	output.WriteString("    client_max_body_size 4m;\n    client_body_buffer_size 4m;\n    access_log off;\n")
	output.WriteString("    location / { content_by_lua_block { require(\"cdnca_site_admin\").handle() } }\n")
	output.WriteString(edgecache.AdminLocation("    "))
	fmt.Fprintf(output, "    location = %s { content_by_lua_block { require(\"cdnca_limits\").admin() } }\n", SubscriptionMinutesLocation)
	fmt.Fprintf(output, "    location = %s { content_by_lua_block { require(\"cdnca_limits\").connections() } }\n", ConnectionsLocation)
	if autoDefense {
		fmt.Fprintf(output, "    location ^~ %s { content_by_lua_block { require(\"cdnca_autodefense\").admin() } }\n", AutoDefenseLocation)
	}
	if managedWAF {
		fmt.Fprintf(output, "    location ^~ %s { content_by_lua_block { require(\"cdnca_managed_waf\").admin() } }\n", WAFAdaptLocation)
	}
	output.WriteString("    location = /__cdnca_site_vars {\n      internal;\n")
	for _, name := range SiteVariables {
		value := ""
		if name == "cdnca_site_max_body" {
			value = "1"
		}
		fmt.Fprintf(output, "      set $%s %q;\n", name, value)
	}
	declared := map[string]bool{}
	for _, name := range SiteVariables {
		declared[name] = true
	}
	module := Variables
	if telemetry {
		module = append(append([]string(nil), Variables...), edgeconfig.DynamicRoutingTelemetryVariables...)
	}
	if schedule302 {
		module = append(append([]string(nil), module...), Schedule302Variables...)
	}
	if autoDefense {
		// the auto defense sample label (cdnca_autodefense INTEL_LABELS)
		// reads the deciding rule policy the rule plan writes (cdnca_security
		// enforce), with or without telemetry
		module = append(append([]string(nil), module...), "cdnca_security_policy_id")
	}
	if benchmark {
		module = append(append([]string(nil), module...), ProbeVariables...)
	}
	if brotli {
		module = append(append([]string(nil), module...), CompressVariables...)
	}
	for _, name := range module {
		if declared[name] {
			continue // one declaration per name (variables are http-wide)
		}
		declared[name] = true
		fmt.Fprintf(output, "      set $%s \"\";\n", name)
	}
	output.WriteString("    }\n  }\n")
}

func sortedTierKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func validPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\"\\$;{}\n\r\t ")
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

var bucketNumber = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})$`)

// tierKey is edgeconfig.DynamicWAFTier.Key's alphabet.
var tierKey = regexp.MustCompile(`^[0-9a-f]{16}_b[0-9]+_n[0-9]+_[rp]_a[0-9]+_j[0-9]+_p[0-9]+(?:_x[0-9a-f]{8}){0,16}$`)

func validate(input Input) ([]edgesite.PortProfile, error) {
	for _, path := range []string{input.Paths.SharedRoot, input.Paths.LuaRoot, input.Paths.StateRoot, input.Paths.PlaceholderCertificate,
		input.Paths.PlaceholderKey, input.Paths.OriginTrustPlaceholder, input.Paths.Objects(), input.Paths.Cache(), input.Paths.Logs()} {
		if !validPath(path) {
			return nil, fmt.Errorf("%w: path %q", ErrInvalid, path)
		}
	}
	if waf := input.ManagedWAF; waf != nil {
		if len(waf.Tiers) == 0 || len(waf.Tiers) > edgeconfig.DynamicWAFMaxTiers {
			return nil, fmt.Errorf("%w: %d managed WAF tiers", ErrInvalid, len(waf.Tiers))
		}
		for _, digest := range waf.DetectProfiles {
			if !sha256Hex.MatchString(digest) {
				return nil, fmt.Errorf("%w: managed WAF detector profile %q", ErrInvalid, digest)
			}
		}
		paths := []string{waf.ModulePath, waf.UnicodeMapPath, waf.RulesPath}
		for key, path := range waf.Tiers {
			if !tierKey.MatchString(key) {
				return nil, fmt.Errorf("%w: managed WAF tier %q", ErrInvalid, key)
			}
			paths = append(paths, path)
		}
		for key, path := range waf.CookieTiers {
			if _, ok := waf.Tiers[key]; !ok {
				return nil, fmt.Errorf("%w: managed WAF cookie variant of unknown tier %q", ErrInvalid, key)
			}
			paths = append(paths, path)
		}
		for name, path := range waf.Buckets {
			// <tier key>_x<n>: the last "_x" (a tier key with application
			// packs has "_x<8 hex>" parts of its own)
			trimmed := strings.TrimPrefix(name, edgeconfig.DynamicWAFTierPrefix)
			cut := strings.LastIndex(trimmed, "_x")
			key, number := "", ""
			if cut >= 0 {
				key, number = trimmed[:cut], trimmed[cut+2:]
			}
			if _, tier := waf.Tiers[key]; cut < 0 || !tier || !strings.HasPrefix(name, edgeconfig.DynamicWAFTierPrefix) ||
				!bucketNumber.MatchString(number) {
				return nil, fmt.Errorf("%w: managed WAF exclusion bucket %q", ErrInvalid, name)
			}
			paths = append(paths, path)
			// a bucket of a tier with a cookie variant has one too (Lua
			// enters <bucket>_c for every such tier's site)
			if _, variant := waf.CookieTiers[key]; variant != (waf.CookieBuckets[name] != "") {
				return nil, fmt.Errorf("%w: managed WAF exclusion bucket %q cookie variant", ErrInvalid, name)
			}
		}
		for name, path := range waf.CookieBuckets {
			if _, known := waf.Buckets[name]; !known {
				return nil, fmt.Errorf("%w: managed WAF cookie variant of unknown bucket %q", ErrInvalid, name)
			}
			paths = append(paths, path)
		}
		for site, name := range waf.SiteBuckets {
			if _, known := waf.Buckets[name]; !uuidPattern.MatchString(site) || !known {
				return nil, fmt.Errorf("%w: managed WAF site %q bucket %q", ErrInvalid, site, name)
			}
		}
		for _, path := range paths {
			if !validPath(path) || strings.Contains(path, "'") {
				return nil, fmt.Errorf("%w: managed WAF path %q", ErrInvalid, path)
			}
		}
	}
	if input.Telemetry {
		if _, err := edgeconfig.RenderDynamicRoutingTelemetryServer(input.Paths.Logs()); err != nil {
			return nil, fmt.Errorf("%w: telemetry log root %q", ErrInvalid, input.Paths.Logs())
		}
	}
	if bundle := input.Node.SystemCABundle; bundle != "" &&
		(!filepath.IsAbs(bundle) || filepath.Clean(bundle) != bundle || strings.ContainsAny(bundle, "\"\\$;{}\n\r\t ")) {
		return nil, fmt.Errorf("%w: system CA bundle %q", ErrInvalid, bundle)
	}
	// Node values go into Lua strings: a region is a lower-case token, the
	// addresses literal IPs (no zone).
	if err := validateNodePage(input.UnknownSite, UnknownSiteStatuses); err != nil {
		return nil, err
	}
	if err := validateNodePage(input.NoHost, []int{400}); err != nil {
		return nil, err
	}
	for name, page := range input.SlotPages {
		if !slotPageNamePattern.MatchString(name) || page == nil {
			return nil, fmt.Errorf("%w: slot page %q", ErrInvalid, name)
		}
		if err := validateNodePage(page, []int{page.Status}); err != nil || page.Status < 400 || page.Status > 599 {
			return nil, fmt.Errorf("%w: slot page %q", ErrInvalid, name)
		}
	}
	if input.Node.Region != "" && !regionPattern.MatchString(input.Node.Region) {
		return nil, fmt.Errorf("%w: node region %q", ErrInvalid, input.Node.Region)
	}
	if input.Node.ID != "" && !uuidPattern.MatchString(input.Node.ID) {
		return nil, fmt.Errorf("%w: node id %q", ErrInvalid, input.Node.ID)
	}
	for _, value := range []struct {
		address string
		ipv6    bool
	}{{input.Node.IngressSourceIPv4, false}, {input.Node.IngressSourceIPv6, true}} {
		if value.address == "" {
			continue
		}
		address, err := netip.ParseAddr(value.address)
		if err != nil || address.Zone() != "" || address.Is6() != value.ipv6 || address.Is4In6() || address.String() != value.address {
			return nil, fmt.Errorf("%w: ingress source %q", ErrInvalid, value.address)
		}
	}
	if len(input.Node.Resolvers) > 4 {
		return nil, fmt.Errorf("%w: %d resolvers", ErrInvalid, len(input.Node.Resolvers))
	}
	for _, resolver := range input.Node.Resolvers {
		if address, err := netip.ParseAddr(resolver); err != nil || address.Zone() != "" || address.String() != resolver {
			return nil, fmt.Errorf("%w: resolver %q", ErrInvalid, resolver)
		}
	}
	// sun_path is 108 bytes on Linux (104 on BSD): the socket must fit.
	if len(filepath.Join(input.Paths.StateRoot, ControlSocket)) > 100 || len(filepath.Join(input.Paths.StateRoot, SecurityFlushSocket)) > 100 {
		return nil, fmt.Errorf("%w: control socket path under %q is too long", ErrInvalid, input.Paths.StateRoot)
	}
	if input.System != nil {
		if err := input.System.Validate(); err != nil {
			return nil, fmt.Errorf("%w: system configuration: %v", ErrInvalid, err)
		}
	}
	cache := input.Cache
	if cache.Zones < 0 || cache.Zones > MaxCacheZones {
		return nil, fmt.Errorf("%w: %d cache zones", ErrInvalid, cache.Zones)
	}
	if cache.Zones > 0 && (cache.Zones&(cache.Zones-1) != 0 || cache.KeysZoneBytes < 1<<20 || cache.KeysZoneBytes > 1<<34 || cache.KeysZoneBytes%(1<<20) != 0 ||
		cache.MaxBytes < 1<<20 || cache.MaxBytes > 1<<50 || cache.MaxBytes%(1<<20) != 0 ||
		cache.MinFreeBytes < 0 || cache.MinFreeBytes%(1<<20) != 0 ||
		cache.Inactive < time.Minute || cache.Inactive > 365*24*time.Hour || cache.Inactive%time.Second != 0) {
		return nil, fmt.Errorf("%w: cache pool %+v", ErrInvalid, cache)
	}
	if cache.Zones == 0 && cache != (CachePool{}) {
		return nil, fmt.Errorf("%w: cache pool settings without zones", ErrInvalid)
	}
	if input.HealthPort < 0 || input.HealthPort > 65535 {
		return nil, fmt.Errorf("%w: health port %d", ErrInvalid, input.HealthPort)
	}
	for index, ref := range input.Challenges {
		if !uuidPattern.MatchString(ref.ID) || ref.Revision < 1 || ref.Revision > 1<<53-1 ||
			index > 0 && (input.Challenges[index-1].ID > ref.ID ||
				input.Challenges[index-1].ID == ref.ID && input.Challenges[index-1].Revision >= ref.Revision) {
			return nil, fmt.Errorf("%w: challenge %q revision %d (sorted, unique)", ErrInvalid, ref.ID, ref.Revision)
		}
	}
	if input.ACMEOverlayRoot != "" && !validPath(input.ACMEOverlayRoot) {
		return nil, fmt.Errorf("%w: ACME overlay root %q", ErrInvalid, input.ACMEOverlayRoot)
	}
	if input.MarketBenchmark && !input.MarketProbe {
		return nil, fmt.Errorf("%w: market benchmark without the market probe", ErrInvalid)
	}
	for port, dispatched := range input.DispatchedPorts {
		if !dispatched {
			continue
		}
		if !validPath(input.Paths.MuxRoot) || len(DispatchSocket(input.Paths.MuxRoot, 65535, false)) > 107 {
			return nil, fmt.Errorf("%w: mux root %q", ErrInvalid, input.Paths.MuxRoot)
		}
		if !slices.ContainsFunc(input.Ports, func(profile edgesite.PortProfile) bool { return profile.Port == port && profile.IPv4 }) {
			return nil, fmt.Errorf("%w: dispatched port %d has no IPv4 site", ErrInvalid, port)
		}
	}
	if len(input.Ports) > MaxPorts {
		return nil, fmt.Errorf("%w: %d ports", ErrInvalid, len(input.Ports))
	}
	ports := slices.Clone(input.Ports)
	slices.SortFunc(ports, func(a, b edgesite.PortProfile) int { return a.Port - b.Port })
	for index, port := range ports {
		switch {
		case port.Port < 1 || port.Port > 65535:
			return nil, fmt.Errorf("%w: port %d", ErrInvalid, port.Port)
		case index > 0 && ports[index-1].Port == port.Port:
			return nil, fmt.Errorf("%w: port %d twice", ErrInvalid, port.Port)
		case !port.IPv4 && !port.IPv6:
			return nil, fmt.Errorf("%w: port %d has no address family", ErrInvalid, port.Port)
		case !port.TLS && (port.HTTP2 || port.HTTP3):
			return nil, fmt.Errorf("%w: port %d: HTTP/2 and HTTP/3 need TLS", ErrInvalid, port.Port)
		case port.SiteCount < 1:
			return nil, fmt.Errorf("%w: port %d serves no site", ErrInvalid, port.Port)
		}
	}
	return ports, nil
}

// writeHealthServer: the loopback health server (127.0.0.1 only).
func writeHealthServer(output *bytes.Buffer, port int) {
	fmt.Fprintf(output, "  server {\n    listen 127.0.0.1:%d;\n    access_log off;\n    location = /healthz { return 204; }\n", port)
	output.WriteString("    location = /healthz/cc-auto-switch {\n      default_type application/json;\n" +
		"      content_by_lua_block { ngx.print(require(\"cjson.safe\").encode(require(\"cc\").auto_switch_status())) }\n    }\n")
	output.WriteString("    location = /healthz/cc-kernel-bans {\n      default_type text/plain;\n" +
		"      content_by_lua_block { for _, line in ipairs(require(\"cc\").kernel_bans()) do ngx.say(line) end }\n    }\n")
	output.WriteString("    location = /healthz/cc-stats {\n      default_type text/plain;\n" +
		"      content_by_lua_block { for _, line in ipairs(require(\"cc\").stats()) do ngx.say(line) end }\n    }\n")
	// FX45: the firewall action escalation state of the sites the agent
	// posts (cdnca_security.firewall_action_status).
	output.WriteString("    location = /healthz/firewall-action {\n      client_max_body_size 4m;\n      client_body_buffer_size 4m;\n" +
		"      content_by_lua_block { require(\"cdnca_security\").firewall_action_status() }\n    }\n")
	// The ban list library's snapshot (POST) and the WAF
	// kernel ban queue (GET), cdnca_banlist.
	output.WriteString("    location = /healthz/security-bans {\n      client_max_body_size 4m;\n      client_body_buffer_size 4m;\n" +
		"      content_by_lua_block { require(\"" + edgeconfig.SecurityBanLuaModule + "\").handle() }\n    }\n  }\n")
}

// challengeList is the Lua list of preloaded challenge versions.
func challengeList(refs []edgesite.Ref) string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, fmt.Sprintf("{ id = %q, revision = %d }", ref.ID, ref.Revision))
	}
	return strings.Join(parts, ", ")
}

// ChallengesFromSites is the sorted, unique challenge versions the sites
// bind (the skeleton's Challenges).
func ChallengesFromSites(sites []edgesite.Site) []edgesite.Ref {
	seen := map[string]bool{}
	var refs []edgesite.Ref
	for _, site := range sites {
		ref := site.Security.Challenge
		if ref == nil {
			continue
		}
		key := ref.ID + "@" + strconv.FormatInt(ref.Revision, 10)
		if !seen[key] {
			seen[key] = true
			refs = append(refs, edgesite.Ref{Kind: edgesite.RefChallenge, ID: ref.ID, Revision: ref.Revision})
		}
	}
	slices.SortFunc(refs, func(a, b edgesite.Ref) int {
		if a.ID != b.ID {
			return strings.Compare(a.ID, b.ID)
		}
		return int(a.Revision - b.Revision)
	})
	return refs
}

func addresses(port edgesite.PortProfile) []string {
	var result []string
	if port.IPv4 {
		result = append(result, "0.0.0.0")
	}
	if port.IPv6 {
		result = append(result, "[::]")
	}
	return result
}

func net(address string, port int) string { return address + ":" + strconv.Itoa(port) }

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// quote: validated paths carry no quote, backslash or dollar.
func quote(value string) string { return `"` + value + `"` }

// HTTP 302 scheduling (edge/openresty/sched302).
const (
	Schedule302SizesDictionary      = "cdnca_sched302_sizes"
	Schedule302SizesDictionaryBytes = 16 << 20
)

// Schedule302Variables are the landing hop's variables (written by
// cdnca_sched302.land, read by the loopback proxy).
var Schedule302Variables = []string{
	"cdnca_sched302_host", "cdnca_sched302_uri", "cdnca_sched302_port", "cdnca_sched302_token", "cdnca_sched302_client",
}

// Schedule302TablePath is the node's scheduling table under the state root
// (the agent's deployment root holds schedule302/table.json).
func Schedule302TablePath(stateRoot string) string {
	return filepath.Join(stateRoot, sched302.TableDirectory, sched302.TableFile)
}

// schedule302Landing is a plain shared server's landing: ^~ wins over
// location /, so no site phase runs for the landing itself; the token is
// verified and the request goes over loopback to this port as the original
// request (Host, URI) carrying the token and the client address, which
// cdnca_dynroute restores (realip, loopback only) and cdnca_sched302.access
// verifies again (a scheduled request is never redirected again).
func schedule302Landing(input Input) string {
	var output strings.Builder
	output.WriteString("    set_real_ip_from 127.0.0.1;\n    set_real_ip_from ::1;\n    real_ip_header X-Cdnca-S302-Client;\n")
	fmt.Fprintf(&output, "    location ^~ %s {\n", sched302.LandingPrefix)
	fmt.Fprintf(&output, "      content_by_lua_block { return require(\"cdnca_sched302\").land({ table = %q }) }\n",
		Schedule302TablePath(input.Paths.StateRoot))
	output.WriteString("    }\n    location @cdnca_sched302_land {\n      proxy_http_version 1.1;\n" +
		"      proxy_set_header Host $cdnca_sched302_host;\n      proxy_set_header Connection \"\";\n" +
		"      proxy_set_header X-Cdnca-S302 $cdnca_sched302_token;\n      proxy_set_header X-Cdnca-S302-Client $cdnca_sched302_client;\n" +
		"      proxy_buffering off;\n      proxy_request_buffering off;\n      proxy_read_timeout 3600s;\n      proxy_send_timeout 3600s;\n" +
		"      proxy_pass http://127.0.0.1:$cdnca_sched302_port$cdnca_sched302_uri;\n    }\n")
	return output.String()
}

// managedWAFConfigure: the profile packs whose sites get detector verdicts.
func managedWAFConfigure(input Input) string {
	if input.ManagedWAF == nil {
		return ""
	}
	list := func(digests []string) string {
		quoted := make([]string, 0, len(digests))
		for _, digest := range digests {
			quoted = append(quoted, strconv.Quote(digest))
		}
		return strings.Join(quoted, ", ")
	}
	// site ID -> bucket location, one entry per site with exclusions in force
	buckets := make([]string, 0, len(input.ManagedWAF.SiteBuckets))
	for _, site := range sortedTierKeys(input.ManagedWAF.SiteBuckets) {
		buckets = append(buckets, fmt.Sprintf("[%q] = %q", site, input.ManagedWAF.SiteBuckets[site]))
	}
	configure := fmt.Sprintf("      managed_waf_detect = { %s },\n      managed_waf_grey = { %s },\n      managed_waf_buckets = { %s },\n",
		list(input.ManagedWAF.DetectProfiles), list(input.ManagedWAF.GreyProfiles), strings.Join(buckets, ", "))
	if len(input.ManagedWAF.CookieTiers) > 0 {
		// the two-level tiers' cookie variants are here (cdnca_managed_waf)
		configure += "      managed_waf_cookie = true,\n"
	}
	return configure
}

const (
	// SecurityFlushDirectory / SecurityFlushSocket (under Paths.StateRoot,
	// telemetry only): the flush server of the aggregated security lines
	// (sec-log-agg). nginx makes a unix listener 0666; the directory (agent
	// owned, group worker, 0710) is the access control: only workers reach it.
	SecurityFlushDirectory = "run/secagg"
	SecurityFlushSocket    = SecurityFlushDirectory + "/flush.sock"
	// SecurityAggregateDictionary counts CC challenge pages / 429s per
	// (minute, site, client IP, rule, action) until worker 0 writes them.
	SecurityAggregateDictionary            = "cdnca_security_agg"
	SecurityAggregateDictionaryBytes int64 = 8 << 20
)

// securityAggregateConfigure: the aggregated security lines' dictionary and
// flush socket (telemetry only).
func securityAggregateConfigure(input Input) string {
	if !input.Telemetry {
		return ""
	}
	return fmt.Sprintf("      security_aggregate = { dict = %q, socket = %q, max_line = %d },\n", SecurityAggregateDictionary,
		filepath.Join(input.Paths.StateRoot, SecurityFlushSocket), SecurityAggregateMaxLine)
}

// SecurityAggregateMaxLine bounds one aggregated line (the plain security
// line has no capture: far below the event spool's limit).
const SecurityAggregateMaxLine = 16384

// writeSecurityFlushServer: worker 0 posts every finished minute's
// aggregated line here; the server writes it to the node security log, the
// file the master opened (docs/edge/dynroute-telemetry.md).
func writeSecurityFlushServer(output *bytes.Buffer, paths Paths) {
	_, security := edgeconfig.DynamicRoutingTelemetryPaths(paths.Logs())
	fmt.Fprintf(output, "  server {\n    listen %s;\n", quote("unix:"+filepath.Join(paths.StateRoot, SecurityFlushSocket)))
	fmt.Fprintf(output, "    client_max_body_size %d;\n    client_body_buffer_size %d;\n    access_log off;\n",
		SecurityAggregateMaxLine, SecurityAggregateMaxLine)
	fmt.Fprintf(output, "    location = %s {\n      content_by_lua_block { require(\"cdnca_telemetry\").flush_handler() }\n", edgeconfig.DynamicRoutingSecurityFlushPath)
	fmt.Fprintf(output, "      access_log %s cdnca_security_capture_json if=$cdnca_security_flush;\n    }\n", quote(security))
	output.WriteString("    location / { return 404; }\n  }\n")
}

func rulePlanConfigure(paths Paths) string {
	if paths.RulePlanRoot == "" {
		return ""
	}
	return fmt.Sprintf("      rule_plan_root = %q,\n", paths.RulePlanRoot)
}

// cacheZoneSuffixConfigure passes a non-default cache root's zone suffix
// to the cache module (absent: the default names, unchanged renders).
func cacheZoneSuffixConfigure(paths Paths) string {
	if suffix := paths.CacheZoneSuffix(); suffix != "" {
		return fmt.Sprintf("      cache_zone_suffix = %q,\n", suffix)
	}
	return ""
}

func schedule302Configure(input Input) string {
	if !input.Schedule302 {
		return ""
	}
	return fmt.Sprintf("      schedule302_table = %q,\n", Schedule302TablePath(input.Paths.StateRoot))
}

// siteGzipServer is every server's gzip when sites set their own (Input.SiteGzip).
const siteGzipServer = "    gzip on;\n    gzip_types *;\n    gzip_min_length 0;\n    gzip_proxied any;\n    gzip_vary off;\n"

// siteBrotliServer is every server's Brotli and both compression levels
// when a site sets Brotli or a level (Input.SiteBrotli): native step 26
// evaluates an empty level as the http{} level (the system gzip level,
// Brotli 6).
const siteBrotliServer = "    brotli on;\n    brotli_types *;\n    brotli_min_length 0;\n" +
	"    gzip_comp_level $cdnca_compress_gzip_level;\n    brotli_comp_level $cdnca_compress_brotli_level;\n"

// siteBrotliConfigure tells the header_filter gate that Brotli is rendered.
func siteBrotliConfigure(input Input) string {
	if !input.SiteBrotli {
		return ""
	}
	return "      site_brotli = true,\n"
}

// WebP conversion (cdnca_webp): the worker thread pool and its queue, the
// variant dictionary shared by the node's workers (LRU: a full dictionary
// evicts the least recently used variant).
const (
	WebPThreadPool      = "cdnca_webp"
	WebPThreads         = 2
	WebPQueue           = 64
	WebPDictionary      = "cdnca_webp"
	WebPDictionaryBytes = 256 << 20
)

// CompressVariables are the per-site compression levels the header_filter
// gate writes ("" = the node default).
var CompressVariables = []string{"cdnca_compress_gzip_level", "cdnca_compress_brotli_level"}

// siteGzipConfigure is the system default the Lua gate applies to a site
// without its own compression (nginx's own default without a system
// configuration: off).
func siteGzipConfigure(input Input) string {
	if !input.SiteGzip {
		return ""
	}
	disabled, vary, minimum, types := true, false, int64(20), []string{}
	if system := input.System; system != nil {
		disabled, vary, minimum = system.Nginx.GzipDisabled, system.Nginx.GzipVary, system.Nginx.GzipMinimumBytes
		types = system.Nginx.GzipTypes
	}
	quoted := make([]string, 0, len(types))
	for _, value := range types {
		quoted = append(quoted, strconv.Quote(value))
	}
	return fmt.Sprintf("      site_gzip = { disabled = %t, vary = %t, min_length = %d, types = { %s } },\n",
		disabled, vary, minimum, strings.Join(quoted, ", "))
}

// SiteGzipFromSites: any site the node composes sets its own compression.
func SiteGzipFromSites(sites []edgesite.Site) bool {
	for _, site := range sites {
		if site.Access != nil && site.Access.Compression != nil {
			return true
		}
	}
	return false
}

// SiteBrotliFromSites: any site the node composes uses Brotli or a
// compression level of its own.
func SiteBrotliFromSites(sites []edgesite.Site) bool {
	for _, site := range sites {
		if site.Access != nil && site.Access.Compression.NeedsEdgeBrotli() {
			return true
		}
	}
	return false
}

// SiteWebPFromSites: any site the node composes converts images to WebP.
func SiteWebPFromSites(sites []edgesite.Site) bool {
	for _, site := range sites {
		if site.Access != nil && site.Access.WebP != nil {
			return true
		}
	}
	return false
}

// Schedule302FromSites: the skeleton renders HTTP 302 scheduling when any
// site the node composes has it (the landing is node level: any plain port
// may receive a request scheduled to this node).
func Schedule302FromSites(sites []edgesite.Site) bool {
	for _, site := range sites {
		if site.Schedule302 != nil {
			return true
		}
	}
	return false
}
