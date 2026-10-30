package siteconf

import (
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

// Site options a subscriber's site carries to the leaf (fix-mktsiteconf,
// 1.0.35 baseline): the leaf is a cdnca controller with the same site model,
// so each option maps onto its own site field and the leaf's site service
// applies its own validation. Absent / zero is the site default.

// Balance methods of a site's origin pool (site.validBalanceMethod).
var balanceMethods = []string{"round_robin", "ip_hash", "url_hash", "least_conn", "random", "hash", "sticky"}

const (
	maxOriginLevel    = 15
	maxOriginMaxConns = 100_000
	maxListValues     = 64
	maxTextValue      = 4096
	maxCAPEM          = 64 << 10
)

// ClientAuth is TLS client certificate verification (Mode optional or
// required, against the PEM CA bundle).
type ClientAuth struct {
	Mode  string `json:"mode"`
	CAPEM string `json:"ca_pem"`
}

type Sticky struct {
	Source string `json:"source"` // cookie, header, arg
	Name   string `json:"name"`
}

// FollowRedirect: the edge follows the origin's redirects (bodyless GET/HEAD).
type FollowRedirect struct {
	MaxHops     int  `json:"max_hops"`
	CrossOrigin bool `json:"cross_origin,omitempty"`
}

// Forwarding is how the edge talks to the origin, beyond scheme, balance and
// timeouts. Zero values are the site defaults (visitor Host, ports 80/443,
// system CA, buffering on, keepalive on with the default idle timeout,
// automatic failback, health check "/").
type Forwarding struct {
	RequestHost        string          `json:"request_host,omitempty"` // visitor, visitor_port, origin, custom
	RequestHostValue   string          `json:"request_host_value,omitempty"`
	HTTPPort           int             `json:"http_port,omitempty"`
	HTTPSPort          int             `json:"https_port,omitempty"`
	FollowPort         bool            `json:"follow_port,omitempty"`
	TLSSNI             string          `json:"tls_sni,omitempty"`
	TLSCAPEM           string          `json:"tls_ca_pem,omitempty"`
	HashKey            string          `json:"hash_key,omitempty"`
	Sticky             *Sticky         `json:"sticky,omitempty"`
	FollowRedirect     *FollowRedirect `json:"follow_redirect,omitempty"`
	TrustedProxyCIDRs  []string        `json:"trusted_proxy_cidrs,omitempty"`
	SearchEngineOrigin string          `json:"search_engine_origin,omitempty"`
	WebSocketOrigins   []string        `json:"websocket_origins,omitempty"`
	ResponseBuffering  *bool           `json:"response_buffering,omitempty"`
	RequestBuffering   *bool           `json:"request_buffering,omitempty"`
	ACMEPassthrough    bool            `json:"acme_passthrough,omitempty"`
	KeepaliveDisabled  bool            `json:"keepalive_disabled,omitempty"`
	KeepaliveIdleMS    int             `json:"keepalive_idle_timeout_ms,omitempty"`
	FailbackManual     bool            `json:"failback_manual,omitempty"`
	HealthCheckPath    string          `json:"health_check_path,omitempty"`
	// FailoverTries: origins tried per request (0 = 1).
	FailoverTries int `json:"failover_tries,omitempty"`
	// L2Off: straight to the origin (L2 配置 关闭); absent is the leaf line
	// group's L2. A custom L2 configuration is the subscriber's own nodes and
	// is not carried (site_l2_custom).
	L2Off bool `json:"l2_off,omitempty"`
}

// OriginRoutes is the site's conditional origin document: extra pools and
// the rules that send a request to one of them (path prefix, client CIDR,
// host, node geography). Pool "default" is conventionally the site's own
// origins.
type OriginRoutes struct {
	Pools                 []RoutePool `json:"pools"`
	DefaultPoolID         string      `json:"default_pool_id"`
	DefaultFallbackPoolID string      `json:"default_fallback_pool_id,omitempty"`
	Routes                []Route     `json:"routes"`
	Retry                 RouteRetry  `json:"retry"`
}

type RoutePool struct {
	ID            string          `json:"id"`
	BalanceMethod string          `json:"balance_method,omitempty"`
	Endpoints     []RouteEndpoint `json:"endpoints"`
}

type RouteEndpoint struct {
	ID     string `json:"id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Weight int    `json:"weight"`
}

type Route struct {
	ID          string   `json:"id"`
	Priority    int      `json:"priority"`
	PathPrefix  string   `json:"path_prefix,omitempty"`
	ClientCIDRs []string `json:"client_cidrs,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	// NodeGeos: the route applies on nodes whose region has one of these
	// standard geographies (the subscriber's node regions mapped by their
	// region catalog country/province codes; each side matches its own).
	NodeGeos       []NodeGeo `json:"node_geos,omitempty"`
	PoolID         string    `json:"pool_id"`
	FallbackPoolID string    `json:"fallback_pool_id,omitempty"`
}

// NodeGeo is a standard geography: Country ISO 3166-1 alpha-2 and, for CN
// only, Province a GB/T 2260 province-level code ("" = the whole country).
type NodeGeo struct {
	Country  string `json:"country"`
	Province string `json:"province,omitempty"`
}

var (
	geoCountryPattern  = regexp.MustCompile(`^[A-Z]{2}$`)
	geoProvincePattern = regexp.MustCompile(`^[1-8][0-9]0000$`)
)

const maxRouteGeos = 32

func canonicalGeos(values []NodeGeo) ([]NodeGeo, bool) {
	if len(values) > maxRouteGeos {
		return nil, false
	}
	out := slices.Clone(values)
	for _, g := range out {
		if !geoCountryPattern.MatchString(g.Country) ||
			g.Province != "" && (g.Country != "CN" || !geoProvincePattern.MatchString(g.Province)) {
			return nil, false
		}
	}
	compare := func(a, b NodeGeo) int {
		if c := strings.Compare(a.Country, b.Country); c != 0 {
			return c
		}
		return strings.Compare(a.Province, b.Province)
	}
	slices.SortFunc(out, compare)
	out = slices.Compact(out)
	if len(out) == 0 {
		return nil, true
	}
	return out, true
}

type RouteRetry struct {
	Methods          []string `json:"methods"`
	MaxAttempts      int      `json:"max_attempts"`
	ConnectTimeoutMS int      `json:"connect_timeout_ms"`
	ReadTimeoutMS    int      `json:"read_timeout_ms"`
	TotalBudgetMS    int      `json:"total_budget_ms"`
}

var routeTokenPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func validText(value string, maximum int) bool {
	return len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func canonicalCIDRs(values []string) ([]string, bool) {
	if len(values) > maxListValues {
		return nil, false
	}
	out := make([]string, len(values))
	for i, v := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(v))
		if err != nil {
			return nil, false
		}
		out[i] = prefix.Masked().String()
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

func canonicalStrings(values []string, lower bool) ([]string, bool) {
	if len(values) > maxListValues {
		return nil, false
	}
	out := make([]string, len(values))
	for i, v := range values {
		v = strings.TrimSpace(v)
		if lower {
			v = strings.ToLower(v)
		}
		if v == "" || !validText(v, 512) {
			return nil, false
		}
		out[i] = v
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

// normalizeSiteOptions checks the shape of the site options and writes them
// canonically; an all-default block becomes absent.
func (c *Config) normalizeSiteOptions() error {
	if !slices.Contains(balanceMethods, c.BalanceMethod) || c.HTTPSRedirectPort < 0 || c.HTTPSRedirectPort > 65535 {
		return ErrInvalid
	}
	for _, o := range c.Origins {
		if o.MaxConns < 0 || o.MaxConns > maxOriginMaxConns || o.Level < 0 || o.Level > maxOriginLevel {
			return ErrInvalid
		}
	}
	if c.ForceHTTPS && len(c.HTTPSPorts) == 0 || c.HTTPSRedirectPort != 0 && !slices.Contains(c.HTTPSPorts, c.HTTPSRedirectPort) ||
		!c.ForceHTTPS && c.HTTPSRedirectPort != 0 {
		return ErrInvalid
	}
	if a := c.ClientAuth; a != nil {
		if a.Mode != "optional" && a.Mode != "required" || strings.TrimSpace(a.CAPEM) == "" || len(a.CAPEM) > maxCAPEM ||
			len(c.HTTPSPorts) == 0 {
			return ErrInvalid
		}
	}
	if err := c.normalizeForwarding(); err != nil {
		return err
	}
	return c.normalizeOriginRoutes()
}

func (c *Config) normalizeForwarding() error {
	f := c.Forwarding
	if f == nil {
		return nil
	}
	if f.RequestHost == "visitor" {
		f.RequestHost = ""
	}
	if f.HTTPPort == 80 {
		f.HTTPPort = 0
	}
	if f.HTTPSPort == 443 {
		f.HTTPSPort = 0
	}
	if f.HealthCheckPath == "/" {
		f.HealthCheckPath = ""
	}
	if f.FailoverTries == 1 {
		f.FailoverTries = 0
	}
	if !slices.Contains([]string{"", "visitor_port", "origin", "custom"}, f.RequestHost) ||
		(f.RequestHost == "custom") != (f.RequestHostValue != "") || !validText(f.RequestHostValue, 260) ||
		f.HTTPPort != 0 && !validPort(f.HTTPPort) || f.HTTPSPort != 0 && !validPort(f.HTTPSPort) ||
		!validText(f.TLSSNI, 253) || len(f.TLSCAPEM) > maxCAPEM || !validText(f.HashKey, 256) ||
		!validText(f.SearchEngineOrigin, 260) || !validText(f.HealthCheckPath, 512) ||
		f.KeepaliveIdleMS < 0 || f.KeepaliveIdleMS > 300_000 || f.FailoverTries < 0 || f.FailoverTries > len(c.Origins) {
		return ErrInvalid
	}
	f.TLSSNI = strings.ToLower(strings.TrimSpace(f.TLSSNI))
	if s := f.Sticky; s != nil && (!slices.Contains([]string{"cookie", "header", "arg"}, s.Source) || s.Name == "" || !validText(s.Name, 64)) {
		return ErrInvalid
	}
	if (c.BalanceMethod == "sticky") != (f.Sticky != nil) || (c.BalanceMethod == "hash") != (f.HashKey != "") {
		return ErrInvalid
	}
	if r := f.FollowRedirect; r != nil && (r.MaxHops < 1 || r.MaxHops > 5) {
		return ErrInvalid
	}
	var ok bool
	if f.TrustedProxyCIDRs, ok = canonicalCIDRs(f.TrustedProxyCIDRs); !ok {
		return ErrInvalid
	}
	if f.WebSocketOrigins, ok = canonicalStrings(f.WebSocketOrigins, true); !ok || len(f.WebSocketOrigins) > 0 && !c.WebSocket {
		return ErrInvalid
	}
	if len(f.TrustedProxyCIDRs) == 0 {
		f.TrustedProxyCIDRs = nil
	}
	if len(f.WebSocketOrigins) == 0 {
		f.WebSocketOrigins = nil
	}
	if reflect.DeepEqual(*f, Forwarding{}) {
		c.Forwarding = nil
	}
	return nil
}

func (c *Config) normalizeOriginRoutes() error {
	r := c.OriginRoutes
	if r == nil {
		return nil
	}
	if len(r.Pools) < 1 || len(r.Pools) > 64 || len(r.Routes) > 256 || !routeTokenPattern.MatchString(r.DefaultPoolID) ||
		r.DefaultFallbackPoolID != "" && !routeTokenPattern.MatchString(r.DefaultFallbackPoolID) {
		return ErrInvalid
	}
	for i := range r.Pools {
		p := &r.Pools[i]
		if p.BalanceMethod == "" {
			p.BalanceMethod = "round_robin"
		}
		if !routeTokenPattern.MatchString(p.ID) || len(p.Endpoints) < 1 || len(p.Endpoints) > 32 ||
			!slices.Contains(balanceMethods, p.BalanceMethod) {
			return ErrInvalid
		}
		for j := range p.Endpoints {
			e := &p.Endpoints[j]
			e.Host = strings.ToLower(strings.TrimSpace(e.Host))
			if !routeTokenPattern.MatchString(e.ID) || e.Host == "" || len(e.Host) > 253 || !validPort(e.Port) ||
				e.Weight < 1 || e.Weight > 100 || strings.ContainsAny(e.Host, "/ @") {
				return ErrInvalid
			}
		}
		slices.SortFunc(p.Endpoints, func(a, b RouteEndpoint) int { return strings.Compare(a.ID, b.ID) })
	}
	slices.SortFunc(r.Pools, func(a, b RoutePool) int { return strings.Compare(a.ID, b.ID) })
	for i := range r.Routes {
		route := &r.Routes[i]
		var ok bool
		if route.ClientCIDRs, ok = canonicalCIDRs(route.ClientCIDRs); !ok {
			return ErrInvalid
		}
		if route.Hosts, ok = canonicalStrings(route.Hosts, true); !ok {
			return ErrInvalid
		}
		if route.NodeGeos, ok = canonicalGeos(route.NodeGeos); !ok {
			return ErrInvalid
		}
		if len(route.ClientCIDRs) == 0 {
			route.ClientCIDRs = nil
		}
		if len(route.Hosts) == 0 {
			route.Hosts = nil
		}
		if !routeTokenPattern.MatchString(route.ID) || route.Priority < -1000 || route.Priority > 1000 ||
			!validText(route.PathPrefix, 512) || !routeTokenPattern.MatchString(route.PoolID) ||
			route.FallbackPoolID != "" && !routeTokenPattern.MatchString(route.FallbackPoolID) {
			return ErrInvalid
		}
	}
	slices.SortStableFunc(r.Routes, func(a, b Route) int { return strings.Compare(a.ID, b.ID) })
	var ok bool
	if r.Retry.Methods, ok = canonicalStrings(r.Retry.Methods, false); !ok || r.Retry.MaxAttempts < 0 || r.Retry.MaxAttempts > 8 ||
		r.Retry.ConnectTimeoutMS < 0 || r.Retry.ReadTimeoutMS < 0 || r.Retry.TotalBudgetMS < 0 || r.Retry.TotalBudgetMS > 120_000 {
		return ErrInvalid
	}
	if r.Routes == nil {
		r.Routes = []Route{}
	}
	return nil
}
