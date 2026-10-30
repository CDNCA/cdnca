package cc

import (
	"errors"
	"net/netip"
)

const (
	SchemaVersion = "cdnca.edge.cc/v1"

	MaxPolicyBytes     = 1 << 20
	MaxPolicyVersion   = 1<<53 - 1
	MaxRules           = 512
	MaxProxyCIDRs      = 64
	MaxAllowlistCIDRs  = 256
	MaxIdentifierBytes = 128
	MaxHostBytes       = 253
	MaxMethodBytes     = 32
	MaxPathBytes       = 1024
	MaxCIDRBytes       = 64
	MaxRequests        = 1_000_000
	MaxWindowSeconds   = 3600
	MaxRatePerSecond   = 100_000
	MaxBurst           = 1_000_000
	MaxBanSeconds      = 86_400
)

var ErrInvalidPolicy = errors.New("invalid CC policy")

type Algorithm string

const (
	AlgorithmFixedWindow Algorithm = "fixed_window"
	AlgorithmLeakyBucket Algorithm = "leaky_bucket"
)

type Dimension string

const (
	DimensionClientIP Dimension = "client_ip"
	DimensionPath     Dimension = "path"
	DimensionSite     Dimension = "site"
)

type ActionKind string

const (
	ActionLog          ActionKind = "log"
	ActionReject429    ActionKind = "reject_429"
	ActionTemporaryBan ActionKind = "temporary_ban"
)

type PathKind string

const (
	PathExact  PathKind = "exact"
	PathPrefix PathKind = "prefix"
)

type Policy struct {
	SchemaVersion  string   `json:"schema_version"`
	PolicyVersion  uint64   `json:"policy_version"`
	TrustedProxies []string `json:"trusted_proxies"`
	Allowlist      []string `json:"allowlist"`
	Rules          []Rule   `json:"rules"`
}

type Rule struct {
	RuleID    string    `json:"rule_id"`
	Priority  uint32    `json:"priority"`
	TenantID  string    `json:"tenant_id"`
	SiteID    string    `json:"site_id"`
	Match     Match     `json:"match"`
	Dimension Dimension `json:"dimension"`
	Limit     Limit     `json:"limit"`
	Action    Action    `json:"action"`
}

type Match struct {
	Host   string     `json:"host,omitempty"`
	Port   uint16     `json:"port,omitempty"`
	Method string     `json:"method,omitempty"`
	Path   *PathMatch `json:"path,omitempty"`
}

type PathMatch struct {
	Kind  PathKind `json:"kind"`
	Value string   `json:"value"`
}

type Limit struct {
	Algorithm     Algorithm `json:"algorithm"`
	Requests      uint32    `json:"requests,omitempty"`
	WindowSeconds uint32    `json:"window_seconds,omitempty"`
	RatePerSecond uint32    `json:"rate_per_second,omitempty"`
	Burst         uint32    `json:"burst,omitempty"`
}

type Action struct {
	Kind       ActionKind `json:"kind"`
	BanSeconds uint32     `json:"ban_seconds,omitempty"`
}

type CompiledPolicy struct {
	SchemaVersion  string         `json:"schema_version"`
	PolicyVersion  uint64         `json:"policy_version"`
	TrustedProxies []CompiledCIDR `json:"trusted_proxies"`
	Allowlist      []CompiledCIDR `json:"allowlist"`
	Rules          []Rule         `json:"rules"`
}

// Network uses uint16 so encoding/json emits a numeric array rather than base64.
type CompiledCIDR struct {
	Family       uint8    `json:"family"`
	Network      []uint16 `json:"network"`
	PrefixLength uint8    `json:"prefix_length"`
}

func (cidr CompiledCIDR) prefix() netip.Prefix {
	if cidr.Family == 4 {
		var value [4]byte
		for index := range value {
			value[index] = byte(cidr.Network[index])
		}
		return netip.PrefixFrom(netip.AddrFrom4(value), int(cidr.PrefixLength))
	}
	var value [16]byte
	for index := range value {
		value[index] = byte(cidr.Network[index])
	}
	return netip.PrefixFrom(netip.AddrFrom16(value), int(cidr.PrefixLength))
}
