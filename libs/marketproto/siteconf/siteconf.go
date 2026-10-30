// Package siteconf is the controller-neutral site configuration sent through
// the relay (docs/marketplace/03-supply-api.md §4). It never mirrors a
// controller's own tables: each leaf maps it onto its local site model and
// reports anything it cannot honour as a blocker instead of degrading.
package siteconf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

const SchemaV1 = "cdnca.market.site/v1"

// Relay operations carrying site configuration.
const (
	OpPrepare = "supply.prepare_site"
	OpCommit  = "supply.commit_site"
	OpAbort   = "supply.abort_site"
	OpDelete  = "supply.delete_site"
	OpStatus  = "supply.site_status"
	OpPurge   = "supply.purge_cache"
	OpReply   = "supply.reply"
)

const (
	maxDomains = 100
	maxOrigins = 32
	maxPorts   = 16
)

var ErrInvalid = errors.New("invalid site configuration")

type Origin struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Weight int    `json:"weight"`
	// Level 0 is the primary, 1+ backups (origin failover levels).
	Level int `json:"level,omitempty"`
	// MaxConns bounds the edge's connections to this origin (0 unlimited).
	MaxConns int `json:"max_conns,omitempty"`
}

// Config is one revision of a subscriber's site. Extension blocks that a leaf
// does not implement yet are carried verbatim and surface as blockers.
type Config struct {
	Schema           string   `json:"schema"`
	Domains          []string `json:"domains"`
	HTTPPorts        []int    `json:"http_ports"`
	HTTPSPorts       []int    `json:"https_ports"`
	Origins          []Origin `json:"origins"`
	OriginScheme     string   `json:"origin_scheme"` // http, https, follow
	BalanceMethod    string   `json:"balance_method"`
	ConnectTimeoutMS int      `json:"connect_timeout_ms"`
	ReadTimeoutMS    int      `json:"read_timeout_ms"`
	WebSocket        bool     `json:"websocket"`
	HTTP3            bool     `json:"http3"`
	Certificate      string   `json:"certificate"` // leaf_issued, none
	// ForceHTTPS redirects plain HTTP to HTTPSRedirectPort (0: the lowest
	// HTTPS port). Site options (site_options.go):
	ForceHTTPS        bool          `json:"force_https,omitempty"`
	HTTPSRedirectPort int           `json:"https_redirect_port,omitempty"`
	ClientAuth        *ClientAuth   `json:"client_auth,omitempty"`
	Forwarding        *Forwarding   `json:"forwarding,omitempty"`
	OriginRoutes      *OriginRoutes `json:"origin_routes,omitempty"`
	// Site settings (site_settings.go): the HTTPS profile, IPv6, all domains
	// sharing one cache, the cache status header off, and the site access
	// settings (siteaccess.Settings without basic auth) as an object.
	TLS                      *TLSOptions     `json:"tls,omitempty"`
	IPv6                     bool            `json:"ipv6,omitempty"`
	CacheSharedAcrossDomains bool            `json:"cache_shared_across_domains,omitempty"`
	CacheStatusHeaderOff     bool            `json:"cache_status_header_off,omitempty"`
	SiteAccess               json.RawMessage `json:"site_access,omitempty"`
	// WAF is the site's WAF policy (fix-mktsiteconf2 ②) in the cdnca 1.0.35
	// security policy model: default action, rules without IDs (the managed
	// OWASP CRS rule carries the effective profile pack and exclusions),
	// WAF settings and quick block. The leaf writes it as its own policy.
	WAF json.RawMessage `json:"waf,omitempty"`
	// CC is the site's whole CC policy (fix-mktsiteconf3) in the same model:
	// default action, rules without IDs (challenges, counting keys, leaky
	// bucket and every other algorithm) and the CC settings with every
	// system-mode value resolved to a custom one. The leaf writes it as its
	// own CC policy; it replaces rate_limit, and a config carrying both is
	// refused.
	CC json.RawMessage `json:"cc,omitempty"`
	// HTTPPolicy is the site's enabled HTTP policy (fix-mktsiteconf3): origin
	// request headers, upload limit, response headers, rewrites, redirects,
	// CORS and hotlink protection as the cdnca 1.0.35 policy config. The leaf
	// writes it as its site's HTTP policy; absent removes the leaf's.
	HTTPPolicy json.RawMessage `json:"http_policy,omitempty"`
	// OriginAuth is the site's published origin auth rules, credentials
	// sealed per leaf (origin_auth.go, fix-mktsiteconf5).
	OriginAuth *OriginAuth     `json:"origin_auth,omitempty"`
	Cache      json.RawMessage `json:"cache,omitempty"`
	Access     json.RawMessage `json:"access,omitempty"`
	RateLimit  json.RawMessage `json:"rate_limit,omitempty"`
	// AutoDefense is the site's automatic defence setting (ADR 0012 §19.2);
	// the leaf clamps it to grant AutoDefenseCaps (AutoDefense.Clamp).
	AutoDefense json.RawMessage `json:"auto_defense,omitempty"`
}

// Normalize canonicalises c in place so that equal intent gives equal digest.
func (c *Config) Normalize() error {
	if c.Schema != SchemaV1 || len(c.Domains) == 0 || len(c.Domains) > maxDomains ||
		len(c.Origins) == 0 || len(c.Origins) > maxOrigins ||
		len(c.HTTPPorts)+len(c.HTTPSPorts) == 0 || len(c.HTTPPorts) > maxPorts || len(c.HTTPSPorts) > maxPorts {
		return ErrInvalid
	}
	for i, d := range c.Domains {
		ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if err != nil || ascii == "" || strings.HasPrefix(ascii, "*.") && strings.Count(ascii, ".") < 2 {
			return ErrInvalid
		}
		c.Domains[i] = strings.ToLower(ascii)
	}
	slices.Sort(c.Domains)
	if len(slices.Compact(slices.Clone(c.Domains))) != len(c.Domains) {
		return ErrInvalid
	}
	for _, ports := range []*[]int{&c.HTTPPorts, &c.HTTPSPorts} {
		for _, p := range *ports {
			if p < 1 || p > 65535 {
				return ErrInvalid
			}
		}
		slices.Sort(*ports)
		*ports = slices.Compact(*ports)
	}
	for _, p := range c.HTTPPorts {
		if slices.Contains(c.HTTPSPorts, p) {
			return ErrInvalid
		}
	}
	for i := range c.Origins {
		o := &c.Origins[i]
		o.Host = strings.ToLower(strings.TrimSpace(o.Host))
		if o.Weight == 0 {
			o.Weight = 1
		}
		if o.Host == "" || len(o.Host) > 253 || o.Port < 1 || o.Port > 65535 || o.Weight < 1 || o.Weight > 100 ||
			strings.ContainsAny(o.Host, "/ @") {
			return ErrInvalid
		}
		if ip := net.ParseIP(o.Host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
			return ErrInvalid
		}
	}
	slices.SortFunc(c.Origins, func(a, b Origin) int {
		return strings.Compare(a.Host+":"+strconv.Itoa(a.Port), b.Host+":"+strconv.Itoa(b.Port))
	})
	if c.OriginScheme == "" {
		c.OriginScheme = "http"
	}
	if c.BalanceMethod == "" {
		c.BalanceMethod = "round_robin"
	}
	if c.Certificate == "" {
		c.Certificate = "leaf_issued"
	}
	if !slices.Contains([]string{"http", "https", "follow"}, c.OriginScheme) ||
		!slices.Contains([]string{"leaf_issued", "none"}, c.Certificate) ||
		c.ConnectTimeoutMS < 0 || c.ConnectTimeoutMS > 600_000 || c.ReadTimeoutMS < 0 || c.ReadTimeoutMS > 3_600_000 {
		return ErrInvalid
	}
	if len(c.HTTPSPorts) > 0 && c.Certificate == "none" {
		return ErrInvalid
	}
	if err := c.normalizeSiteOptions(); err != nil {
		return err
	}
	if err := c.normalizeSiteSettings(); err != nil {
		return err
	}
	if err := c.normalizeOriginAuth(); err != nil {
		return err
	}
	if err := c.normalizeCache(); err != nil {
		return err
	}
	if err := c.normalizeSecurity(); err != nil {
		return err
	}
	return c.normalizeAutoDefense()
}

// Digest identifies a normalized revision; Commit must quote Prepare's digest.
func (c Config) Digest() string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Blocker is a reason a leaf refuses a revision.
type Blocker struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// CheckAllocation reports what the grant does not allow (allocation and the
// domains limit; an unselected domains limit is unlimited). Leaves add their
// own blockers for features they do not implement.
func (c Config) CheckAllocation(a spec.Allocation, limits spec.LimitSet) []Blocker {
	var out []Blocker
	if domains, ok := limits.Cap(spec.MetricDomains); ok && int64(len(c.Domains)) > domains {
		out = append(out, Blocker{Code: "domain_limit", Detail: strconv.FormatInt(domains, 10)})
	}
	if int64(len(c.HTTPPorts)+len(c.HTTPSPorts)) > a.HTTPPorts {
		out = append(out, Blocker{Code: "port_limit", Detail: strconv.FormatInt(a.HTTPPorts, 10)})
	}
	if c.WebSocket && !a.WebSocket {
		out = append(out, Blocker{Code: "websocket_not_allowed"})
	}
	if c.HTTP3 && !a.HTTP3 {
		out = append(out, Blocker{Code: "http3_not_allowed"})
	}
	return out
}

// Messages. Every request names the subscriber's own site id and revision so
// replies and retries correlate without the leaf knowing subscriber tables.
// The leaf keeps no mapping table: its first successful Commit returns the
// local LeafSiteID, which the subscriber stores in its supply binding and
// quotes on every later request for that site.

type PrepareRequest struct {
	SiteID   uuid.UUID `json:"site_id"`
	Revision int64     `json:"revision"`
	Config   Config    `json:"config"`
}

// CommitRequest carries the config again, so leaves keep no staging state:
// the digest proves it is exactly what Prepare accepted.
type CommitRequest struct {
	SiteID     uuid.UUID  `json:"site_id"`
	LeafSiteID *uuid.UUID `json:"leaf_site_id,omitempty"`
	Revision   int64      `json:"revision"`
	Digest     string     `json:"digest"`
	Config     Config     `json:"config"`
}

type SiteRef struct {
	SiteID     uuid.UUID `json:"site_id"`
	LeafSiteID uuid.UUID `json:"leaf_site_id"`
	Revision   int64     `json:"revision,omitempty"`
}

type PurgeRequest struct {
	SiteID     uuid.UUID `json:"site_id"`
	LeafSiteID uuid.UUID `json:"leaf_site_id"`
	URLs       []string  `json:"urls,omitempty"`
	Dirs       []string  `json:"dirs,omitempty"`
}

type Reply struct {
	Operation  string          `json:"operation"`
	SiteID     uuid.UUID       `json:"site_id"`
	LeafSiteID *uuid.UUID      `json:"leaf_site_id,omitempty"`
	Revision   int64           `json:"revision,omitempty"`
	OK         bool            `json:"ok"`
	Error      string          `json:"error,omitempty"`
	Blockers   []Blocker       `json:"blockers,omitempty"`
	Digest     string          `json:"digest,omitempty"`
	Status     json.RawMessage `json:"status,omitempty"`
}
