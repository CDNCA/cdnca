// Package sched302 is the HTTP 302 scheduling contract ("DNS +
// 302 双调度") shared by control-api, agent-gateway, edge-agent and the node
// Lua (edge/openresty/sched302/cdnca_sched302.lua):
//
//   - Site: a site's schedule302 settings as site runtime v2 carries them
//     (sites[].schedule302); the node renders them into the site's access
//     phase.
//   - Table: the node's scheduling table (cdnca.edge.sched302-table/v1), the
//     candidate nodes of every schedule302 site with their health and load,
//     pushed without a release (ConnectResponse.sched302_table) and written to
//     <deployment_root>/schedule302/table.json.
//   - Token / Sign: the short-lived landing signature, and Select the
//     reference candidate choice the Lua must match (tests compare both).
package sched302

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	// APIVersion is the CAPABILITY_NAME_SCHED302 version.
	APIVersion = 1
	// TableSchema is the table body schema.
	TableSchema = "cdnca.edge.sched302-table/v1"
	// TableDirectory and TableFile are the table below the deployment root.
	TableDirectory = "schedule302"
	TableFile      = "table.json"
	// LandingPrefix is the landing path a scheduled request arrives on:
	// /_cdnca302/<expires>.<signature>/<host><request URI>.
	LandingPrefix = "/_cdnca302/"
	// SignatureDomain prefixes every signed message.
	SignatureDomain = "cdnca-s302/v1"
	// SignatureLength is the base64url characters kept of the HMAC-SHA256
	// (22 characters = 132 bits).
	SignatureLength = 22
	// KeyBytes is a site signing key.
	KeyBytes = 32

	MinSignatureTTLSeconds     = 10
	MaxSignatureTTLSeconds     = 3600
	DefaultSignatureTTLSeconds = 60
	MaxExtensions              = 64
	MaxPathPrefixes            = 32
	MaxPathPrefixBytes         = 256
	MaxMinSizeBytes            = int64(1 << 40)
	// MaxTableSites / MaxCandidates bound one table.
	MaxTableSites = 4096
	MaxCandidates = 256
	MaxHosts      = 100
	// MaxTableBytes bounds table_json; MaxCarrierBytes the protobuf carrier.
	MaxTableBytes   = 4 << 20
	MaxCarrierBytes = MaxTableBytes + 4<<10
	// OverloadedLoad: a candidate at or above this load (0..100) is skipped
	// while another candidate in its tier is below it.
	OverloadedLoad = 90
	// Hold is how long a node keeps using a table without a newer one
	// before it stops redirecting (the table may be stale).
	HoldSeconds = 120
)

// Targets: TargetAddress redirects to the candidate's endpoint address,
// TargetHostname to its node direct hostname (candidates without one are not
// eligible).
const (
	TargetAddress  = "address"
	TargetHostname = "hostname"
)

// JetStream names: agent-gateway owns the stream; control-api publishes the
// newest table per node (subject <prefix>.<node>).
const (
	CommandStream         = "CDNCA_SCHED302_TABLES"
	CommandSubjectPrefix  = "cdnca.agent.sched302.tables"
	GatewayConsumerPrefix = "sched302"
)

var ErrInvalid = errors.New("schedule302 contract value is invalid")

var (
	extensionPattern = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hostnamePattern  = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	countryPattern   = regexp.MustCompile(`^[A-Z]{2}$`)
)

// Site is sites[].schedule302 of a site runtime v2 document. Field order is
// the encoding order. A site without the field is never redirected.
type Site struct {
	// Target: TargetAddress or TargetHostname.
	Target string `json:"target"`
	// KeepPath keeps the request path (else "/"); KeepQuery the query.
	KeepPath  bool `json:"keep_path"`
	KeepQuery bool `json:"keep_query"`
	// SignatureTTLSeconds is how long a redirect stays valid.
	SignatureTTLSeconds int64 `json:"signature_ttl_seconds"`
	// HTTPSToHTTP also redirects HTTPS requests (to the candidate's plain
	// HTTP port: a node has no certificate for its address or direct
	// hostname, so landing is always plain HTTP); off, HTTPS requests are
	// served where they arrive.
	HTTPSToHTTP bool `json:"https_to_http"`
	// Filters: with any set, only matching requests are redirected (OR
	// within a list, AND between the lists and the size).
	Extensions   []string `json:"extensions"`
	PathPrefixes []string `json:"path_prefixes"`
	// MinSizeBytes > 0 redirects only URLs whose last response was at least
	// this large (the node learns sizes from responses it served).
	MinSizeBytes int64 `json:"min_size_bytes"`
}

// NormalizeSite canonicalizes a site's settings in place (lower-case
// extensions without dots, sorted and unique; sorted unique prefixes) and
// validates them.
func NormalizeSite(site *Site) error {
	if site == nil {
		return ErrInvalid
	}
	if site.Target != TargetAddress && site.Target != TargetHostname {
		return fmt.Errorf("%w: target", ErrInvalid)
	}
	if site.SignatureTTLSeconds < MinSignatureTTLSeconds || site.SignatureTTLSeconds > MaxSignatureTTLSeconds {
		return fmt.Errorf("%w: signature_ttl_seconds", ErrInvalid)
	}
	if site.MinSizeBytes < 0 || site.MinSizeBytes > MaxMinSizeBytes {
		return fmt.Errorf("%w: min_size_bytes", ErrInvalid)
	}
	extensions := make([]string, 0, len(site.Extensions))
	for _, value := range site.Extensions {
		value = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "."))
		if !extensionPattern.MatchString(value) {
			return fmt.Errorf("%w: extension %q", ErrInvalid, value)
		}
		extensions = append(extensions, value)
	}
	slices.Sort(extensions)
	site.Extensions = slices.Compact(extensions)
	if len(site.Extensions) > MaxExtensions {
		return fmt.Errorf("%w: extensions", ErrInvalid)
	}
	prefixes := make([]string, 0, len(site.PathPrefixes))
	for _, value := range site.PathPrefixes {
		value = strings.TrimSpace(value)
		if !validPathPrefix(value) {
			return fmt.Errorf("%w: path prefix %q", ErrInvalid, value)
		}
		prefixes = append(prefixes, value)
	}
	slices.Sort(prefixes)
	site.PathPrefixes = slices.Compact(prefixes)
	if len(site.PathPrefixes) > MaxPathPrefixes {
		return fmt.Errorf("%w: path_prefixes", ErrInvalid)
	}
	return nil
}

// ValidSite reports whether site is already canonical and valid.
func ValidSite(site Site) bool {
	normalized := site
	normalized.Extensions = slices.Clone(site.Extensions)
	normalized.PathPrefixes = slices.Clone(site.PathPrefixes)
	if NormalizeSite(&normalized) != nil || site.Extensions == nil || site.PathPrefixes == nil {
		return false
	}
	return slices.Equal(normalized.Extensions, site.Extensions) && slices.Equal(normalized.PathPrefixes, site.PathPrefixes)
}

func validPathPrefix(value string) bool {
	if len(value) < 1 || len(value) > MaxPathPrefixBytes || value[0] != '/' || strings.HasPrefix(value, LandingPrefix) {
		return false
	}
	for _, character := range []byte(value) {
		// Printable ASCII without space, quote, backslash or percent (a
		// prefix is matched against the raw URI byte for byte).
		if character <= 0x20 || character >= 0x7f || character == '"' || character == '\\' || character == '%' {
			return false
		}
	}
	return true
}

// Table is the node's scheduling table. Field order is the encoding order.
type Table struct {
	Schema   string `json:"schema"`
	NodeID   string `json:"node_id"`
	Revision uint64 `json:"revision"`
	// GeneratedAt is Unix seconds; the node stops redirecting HoldSeconds
	// after it (a stale table must not keep sending clients to a node that
	// went down since).
	GeneratedAt int64       `json:"generated_at"`
	Sites       []TableSite `json:"sites"`
}

// TableSite is one schedule302 site the node serves, by site_id.
type TableSite struct {
	SiteID string `json:"site_id"`
	// Hosts are the site's names (primary first, then the aliases sorted;
	// "*.x" leading wildcards): the landing path names the original host and
	// is only accepted for one of them.
	Hosts []string `json:"hosts"`
	// Key is the site signing key (base64url without padding, 32 bytes).
	Key        string      `json:"key"`
	Candidates []Candidate `json:"candidates"`
}

// Candidate is one node a request may be sent to.
type Candidate struct {
	NodeID string `json:"node_id"`
	// Host is the redirect host: the endpoint address or the node direct
	// hostname (Site.Target).
	Host string `json:"host"`
	// HTTPPort is the site's plain HTTP port (IPv4 or dual stack) on the
	// candidate; the landing node proxies to it over loopback.
	HTTPPort int `json:"http_port"`
	// Carrier: telecom, unicom, mobile, bgp or "" (unknown).
	Carrier string `json:"carrier"`
	// Country is ISO 3166-1 alpha-2 upper case or ""; Province a GB/T 2260
	// province code (xx0000) or 0.
	Country  string `json:"country"`
	Province uint32 `json:"province"`
	Weight   int    `json:"weight"`
	// Available: serving in the line group, not held, node online.
	Available bool `json:"available"`
	// Load is 0..100 (CPU of the last minutes; 0 unknown).
	Load int `json:"load"`
}

// Carriers a candidate may name.
var carriers = map[string]bool{"": true, "telecom": true, "unicom": true, "mobile": true, "bgp": true}

// Encode is the canonical table JSON (struct order, compact, no HTML
// escaping, no trailing newline).
func Encode(table Table) ([]byte, error) {
	if err := ValidateTable(table); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(table); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	if len(encoded) > MaxTableBytes {
		return nil, fmt.Errorf("%w: table is too large", ErrInvalid)
	}
	return encoded, nil
}

// Decode parses and validates canonical table JSON.
func Decode(encoded []byte) (Table, error) {
	if len(encoded) == 0 || len(encoded) > MaxTableBytes {
		return Table{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var table Table
	if err := decoder.Decode(&table); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Table{}, ErrInvalid
	}
	canonical, err := Encode(table)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Table{}, ErrInvalid
	}
	return table, nil
}

// ValidateTable checks a table: sites sorted by site_id and unique,
// candidates sorted by node_id and unique, every value in range.
func ValidateTable(table Table) error {
	if table.Schema != TableSchema || !uuidPattern.MatchString(table.NodeID) || table.Revision == 0 ||
		table.GeneratedAt <= 0 || table.Sites == nil || len(table.Sites) > MaxTableSites {
		return fmt.Errorf("%w: table header", ErrInvalid)
	}
	for index, site := range table.Sites {
		if !uuidPattern.MatchString(site.SiteID) || index > 0 && table.Sites[index-1].SiteID >= site.SiteID {
			return fmt.Errorf("%w: site order", ErrInvalid)
		}
		if len(site.Hosts) == 0 || len(site.Hosts) > MaxHosts {
			return fmt.Errorf("%w: site hosts", ErrInvalid)
		}
		for _, host := range site.Hosts {
			if !validSiteHost(host) {
				return fmt.Errorf("%w: site host", ErrInvalid)
			}
		}
		if key, err := base64.RawURLEncoding.DecodeString(site.Key); err != nil || len(key) != KeyBytes {
			return fmt.Errorf("%w: site key", ErrInvalid)
		}
		if site.Candidates == nil || len(site.Candidates) > MaxCandidates {
			return fmt.Errorf("%w: candidates", ErrInvalid)
		}
		for position, candidate := range site.Candidates {
			if !uuidPattern.MatchString(candidate.NodeID) ||
				position > 0 && site.Candidates[position-1].NodeID >= candidate.NodeID {
				return fmt.Errorf("%w: candidate order", ErrInvalid)
			}
			if !ValidHost(candidate.Host) || candidate.HTTPPort < 1 || candidate.HTTPPort > 65535 ||
				!carriers[candidate.Carrier] || candidate.Country != "" && !countryPattern.MatchString(candidate.Country) ||
				candidate.Province != 0 && (candidate.Province < 110000 || candidate.Province > 829999 || candidate.Province%10000 != 0) ||
				candidate.Weight < 1 || candidate.Weight > 100 || candidate.Load < 0 || candidate.Load > 100 {
				return fmt.Errorf("%w: candidate %s", ErrInvalid, candidate.NodeID)
			}
		}
	}
	return nil
}

// ValidHost: an IP literal without zone (IPv6 not bracketed) or a lower-case
// hostname.
func ValidHost(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !address.Is4In6()
	}
	return len(value) <= 253 && hostnamePattern.MatchString(value)
}

// validSiteHost: a lower-case hostname or "*." + hostname.
func validSiteHost(value string) bool {
	return ValidHostname(strings.TrimPrefix(value, "*."))
}

// MatchHost reports whether host (lower case, no port) is one of hosts:
// exact, or a leading wildcard covering exactly the leftmost labels
// ("*.a.com" matches "x.a.com" and "x.y.a.com", not "a.com"), as nginx
// server_name and dynamic routing select sites.
func MatchHost(hosts []string, host string) bool {
	for _, name := range hosts {
		if name == host || strings.HasPrefix(name, "*.") && strings.HasSuffix(host, name[1:]) && len(host) > len(name)-1 {
			return true
		}
	}
	return false
}

// ValidHostname reports whether value can be a node direct hostname.
func ValidHostname(value string) bool {
	_, err := netip.ParseAddr(value)
	return err != nil && len(value) <= 253 && hostnamePattern.MatchString(value)
}

// SigningMessage is what a landing token signs: the site, the original host
// and the redirected request URI (path and the query kept), and the expiry.
func SigningMessage(siteID, host, uri string, expires int64) string {
	return SignatureDomain + "\n" + siteID + "\n" + host + "\n" + uri + "\n" + strconv.FormatInt(expires, 10)
}

// Sign returns the landing signature.
func Sign(key []byte, siteID, host, uri string, expires int64) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(SigningMessage(siteID, host, uri, expires)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:SignatureLength]
}

// LandingPath is the redirect path: /_cdnca302/<expires>.<signature>/<host><uri>.
func LandingPath(key []byte, siteID, host, uri string, expires int64) string {
	return LandingPrefix + strconv.FormatInt(expires, 10) + "." + Sign(key, siteID, host, uri, expires) + "/" + host + uri
}

// Client is what the node knows of a request's client from the IP library.
type Client struct {
	Address  netip.Addr
	Carrier  string // telecom, unicom, mobile or ""
	Country  string
	Province uint32
}

// Select is the reference choice of a candidate for a client (the node Lua
// implements the same): among available candidates the first non-empty tier
// wins —
//
//  1. same carrier and province, 2. same carrier and country,
//  3. BGP / unknown carrier in the client's country, 4. same country,
//  5. any.
//
// Inside a tier, candidates below OverloadedLoad are preferred; among them
// the highest weighted rendezvous hash of (client address, node ID) wins, so
// one client keeps landing on one node (ranged downloads) while the load
// spreads by weight. ok is false when no candidate is available.
func Select(candidates []Candidate, client Client) (Candidate, bool) {
	tiers := []func(Candidate) bool{
		func(c Candidate) bool {
			return client.Carrier != "" && c.Carrier == client.Carrier && client.Province != 0 && c.Province == client.Province
		},
		func(c Candidate) bool {
			return client.Carrier != "" && c.Carrier == client.Carrier && client.Country != "" && c.Country == client.Country
		},
		func(c Candidate) bool {
			return (c.Carrier == "bgp" || c.Carrier == "") && client.Country != "" && c.Country == client.Country
		},
		func(c Candidate) bool { return client.Country != "" && c.Country == client.Country },
		func(Candidate) bool { return true },
	}
	for _, inTier := range tiers {
		var best Candidate
		var bestScore float64
		bestRelieved, found := false, false
		for _, candidate := range candidates {
			if !candidate.Available || !inTier(candidate) {
				continue
			}
			relieved := candidate.Load < OverloadedLoad
			score := RendezvousScore(client.Address, candidate.NodeID, candidate.Weight)
			if !found || relieved && !bestRelieved || relieved == bestRelieved && score > bestScore {
				best, bestScore, bestRelieved, found = candidate, score, relieved, true
			}
		}
		if found {
			return best, true
		}
	}
	return Candidate{}, false
}

// RendezvousScore is the weighted rendezvous score: weight / -ln(u), u in
// (0,1) from the first 6 bytes of SHA-256(client address bytes ‖ node ID).
// 48 bits are exact in a Lua double.
func RendezvousScore(client netip.Addr, nodeID string, weight int) float64 {
	digest := sha256.Sum256(append(client.AsSlice(), nodeID...))
	var raw [8]byte
	copy(raw[2:], digest[:6])
	value := binary.BigEndian.Uint64(raw[:])
	u := (float64(value) + 0.5) / float64(uint64(1)<<48)
	return float64(weight) / -math.Log(u)
}
