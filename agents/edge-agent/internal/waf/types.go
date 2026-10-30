package waf

import (
	"net/netip"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	SchemaVersionV1 = "cdnca.edge.waf/v1"
	SchemaVersionV2 = "cdnca.edge.waf/v2"
	SchemaVersion   = SchemaVersionV1

	MaxPolicyVersion     = 1<<53 - 1
	MaxPolicyBytes       = 1 << 20
	MaxRules             = 512
	MaxRuleIDBytes       = 128
	MaxCommentBytes      = 256
	MaxHostBytes         = 253
	MaxMethodBytes       = 32
	MaxPathBytes         = 1024
	MaxNameBytes         = 128
	MaxValueBytes        = 1024
	MaxUserAgentBytes    = 512
	MaxRequestFields     = 100
	MaxGeoRanges         = 4096
	MaxTrustedProxies    = 64
	MaxTrustedCrawlers   = 64
	MaxCrawlerNetworks   = 64
	MaxCrawlerUserAgents = 64
	MaxProxyHops         = 16
	BlockStatus          = 403
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	ActionLog   Action = "log"
)

type Flow string

const (
	FlowContinue Flow = "continue"
	FlowStop     Flow = "stop"
)

type MatchOperator string

const (
	OperatorExists MatchOperator = "exists"
	OperatorExact  MatchOperator = "exact"
)

type PathKind string

const (
	PathExact     PathKind = "exact"
	PathPrefix    PathKind = "prefix"
	PathRawPrefix PathKind = "raw_prefix"
)

type Policy struct {
	SchemaVersion    string              `json:"schema_version"`
	PolicyVersion    uint64              `json:"policy_version"`
	ClientSource     *ClientSourcePolicy `json:"client_source,omitempty"`
	TrustedCrawlers  []TrustedCrawler    `json:"trusted_crawlers,omitempty"`
	Geo              []GeoRange          `json:"geo,omitempty"`
	UnknownGeoAction GeoUnknownAction    `json:"unknown_geo_action,omitempty"`
	Rules            []Rule              `json:"rules"`
}

type ClientSourcePolicy struct {
	Header            string   `json:"header"`
	MaxHops           uint8    `json:"max_hops"`
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs"`
}

type TrustedCrawler struct {
	Networks          []string `json:"networks"`
	UserAgentPrefixes []string `json:"user_agent_prefixes"`
}

type GeoRange struct {
	CIDR    string `json:"cidr"`
	Country string `json:"country"`
}

type CountryOperator string

const (
	CountryIn    CountryOperator = "in"
	CountryNotIn CountryOperator = "not_in"
)

type GeoUnknownAction string

const (
	GeoUnknownAllow GeoUnknownAction = "allow"
	GeoUnknownBlock GeoUnknownAction = "block"
)

type CountryMatch struct {
	Operator CountryOperator `json:"operator"`
	Values   []string        `json:"values"`
}

type Rule struct {
	RuleID    string  `json:"rule_id"`
	Priority  uint32  `json:"priority"`
	Action    Action  `json:"action"`
	Flow      Flow    `json:"flow"`
	Comment   *string `json:"comment,omitempty"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	Match     Match   `json:"match"`
	// Inspect carries security-policy request-content clauses for the
	// rendered state machine only; the JSON file engine never sees them.
	Inspect []edgeconfig.WAFInspect `json:"-"`
	// JA4 is the rule's TLS fingerprint set ($cdnca_ja4), also rendered
	// state machine only.
	JA4 []string `json:"-"`
	// IPIntel are the rule's carrier / IDC / ASN / region conditions
	// (cdnca_iplib), also rendered state machine only.
	IPIntel []edgeconfig.WAFIPIntel `json:"-"`
}

type Match struct {
	Host       string          `json:"host,omitempty"`
	Port       uint16          `json:"port,omitempty"`
	Method     string          `json:"method,omitempty"`
	Path       *PathMatch      `json:"path,omitempty"`
	Query      *ValueMatch     `json:"query,omitempty"`
	Header     *ValueMatch     `json:"header,omitempty"`
	UserAgent  *UserAgentMatch `json:"user_agent,omitempty"`
	SourceCIDR string          `json:"source_cidr,omitempty"`
	Country    *CountryMatch   `json:"country,omitempty"`
}

type PathMatch struct {
	Kind  PathKind `json:"kind"`
	Value string   `json:"value"`
}

type ValueMatch struct {
	Name     string        `json:"name"`
	Operator MatchOperator `json:"operator"`
	Value    string        `json:"value,omitempty"`
}

type UserAgentMatch struct {
	Operator MatchOperator `json:"operator"`
	Value    string        `json:"value,omitempty"`
}

type CompiledPolicy struct {
	SchemaVersion    string                      `json:"schema_version"`
	PolicyVersion    uint64                      `json:"policy_version"`
	ClientSource     *CompiledClientSourcePolicy `json:"client_source,omitempty"`
	TrustedCrawlers  []CompiledTrustedCrawler    `json:"trusted_crawlers,omitempty"`
	Rules            []CompiledRule              `json:"rules"`
	Geo              []CompiledGeoRange          `json:"geo,omitempty"`
	UnknownGeoAction GeoUnknownAction            `json:"unknown_geo_action,omitempty"`
	valid            bool
}

type CompiledClientSourcePolicy struct {
	Header            string         `json:"header"`
	MaxHops           uint8          `json:"max_hops"`
	TrustedProxyCIDRs []CompiledCIDR `json:"trusted_proxy_cidrs"`
}

type CompiledTrustedCrawler struct {
	Networks          []CompiledCIDR `json:"networks"`
	UserAgentPrefixes []string       `json:"user_agent_prefixes"`
}

type CompiledGeoRange struct {
	CIDR    CompiledCIDR `json:"cidr"`
	Country string       `json:"country"`
}

type CompiledRule struct {
	RuleID        string        `json:"rule_id"`
	Priority      uint32        `json:"priority"`
	Action        Action        `json:"action"`
	Flow          Flow          `json:"flow"`
	Comment       string        `json:"comment,omitempty"`
	ExpiresAtUnix int64         `json:"expires_at_unix,omitempty"`
	Match         CompiledMatch `json:"match"`
}

type CompiledMatch struct {
	Host       string          `json:"host,omitempty"`
	Port       uint16          `json:"port,omitempty"`
	Method     string          `json:"method,omitempty"`
	Path       *PathMatch      `json:"path,omitempty"`
	Query      *ValueMatch     `json:"query,omitempty"`
	Header     *ValueMatch     `json:"header,omitempty"`
	UserAgent  *UserAgentMatch `json:"user_agent,omitempty"`
	SourceCIDR *CompiledCIDR   `json:"source_cidr,omitempty"`
	Country    *CountryMatch   `json:"country,omitempty"`
}

type CompiledCIDR struct {
	Family       uint8    `json:"family"`
	Network      []uint16 `json:"network"`
	PrefixLength uint8    `json:"prefix_length"`
}

type Request struct {
	Host       string
	Port       uint16
	Method     string
	Path       string
	Query      map[string][]string
	Header     map[string][]string
	SourceAddr netip.Addr
}

type Decision struct {
	Action  Action
	Reason  string
	RuleID  string
	Version uint64
	Events  []Event
}

type Event struct {
	Reason string
	RuleID string
}
