package challenge

import (
	"errors"
	"net/netip"
)

const (
	SchemaVersion       = "cdnca.edge.challenge/v1"
	AlgorithmHMACSHA256 = "hmac-sha256"

	MaxPolicyBytes           = 1 << 20
	MaxPolicyVersion         = 1<<53 - 1
	MaxRules                 = 64
	MaxIdentifierBytes       = 128
	MaxHostBytes             = 253
	MaxCookieNameBytes       = 64
	MaxProxyCIDRs            = 64
	MaxBypassRoutes          = 32
	MaxBypassPathBytes       = 512
	MaxCIDRBytes             = 64
	MaxKeyIDBytes            = 64
	MaxKeyFilePathBytes      = 4096
	MinKeyBytes              = 32
	MaxKeyBytes              = 128
	MinDelaySeconds          = 5
	MaxDelaySeconds          = 10
	MinChallengeTTLSeconds   = 10
	MaxChallengeTTLSeconds   = 300
	MaxPassTTLSeconds        = 3600
	MaxClockSkewSeconds      = 30
	MaxFailureWindowSeconds  = 3600
	MaxFailuresPerWindow     = 20
	RequiredAttemptsPerNonce = 1
	MaxRequestTargetBytes    = 4096
	MaxForwardedForBytes     = 2048
	MaxForwardedForHops      = 32
)

var ErrInvalidPolicy = errors.New("invalid challenge policy")

type Mode string

const (
	ModeDelay    Mode = "delay"
	ModeClick    Mode = "click"
	ModeSlider   Mode = "slider"
	ModeCaptcha  Mode = "captcha"
	ModeExternal Mode = "external"
)

type BypassKind string

const (
	BypassExact  BypassKind = "exact"
	BypassPrefix BypassKind = "prefix"
)

type BypassRoute struct {
	Kind BypassKind `json:"kind"`
	Path string     `json:"path"`
}

type IPBinding string

const (
	IPBindingNone  IPBinding = "none"
	IPBindingExact IPBinding = "exact"
)

type Policy struct {
	SchemaVersion  string        `json:"schema_version"`
	PolicyVersion  uint64        `json:"policy_version"`
	Algorithm      string        `json:"algorithm"`
	CookieName     string        `json:"cookie_name"`
	TrustedProxies []string      `json:"trusted_proxies"`
	BypassRoutes   []BypassRoute `json:"bypass_routes"`
	CurrentKey     KeyRef        `json:"current_key"`
	PreviousKey    *KeyRef       `json:"previous_key,omitempty"`
	Rules          []Rule        `json:"rules"`
}

type KeyRef struct {
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
}

type Rule struct {
	RuleID               string                  `json:"rule_id"`
	Priority             uint32                  `json:"priority"`
	TenantID             string                  `json:"tenant_id"`
	SiteID               string                  `json:"site_id"`
	Host                 string                  `json:"host"`
	Mode                 Mode                    `json:"mode"`
	MinDelaySeconds      uint32                  `json:"min_delay_seconds"`
	ChallengeTTLSeconds  uint32                  `json:"challenge_ttl_seconds"`
	PassTTLSeconds       uint32                  `json:"pass_ttl_seconds"`
	ClockSkewSeconds     uint32                  `json:"clock_skew_seconds"`
	AttemptsPerNonce     uint32                  `json:"attempts_per_nonce"`
	FailureWindowSeconds uint32                  `json:"failure_window_seconds"`
	MaxFailuresPerWindow uint32                  `json:"max_failures_per_window"`
	IPBinding            IPBinding               `json:"ip_binding"`
	BindUserAgent        bool                    `json:"bind_user_agent"`
	ExternalProvider     *ExternalProviderConfig `json:"external_provider,omitempty"`
}

type ExternalProviderConfig struct {
	Provider ExternalProvider `json:"provider"`
	AppID    string           `json:"app_id"`
}

type CompiledPolicy struct {
	SchemaVersion  string         `json:"schema_version"`
	PolicyVersion  uint64         `json:"policy_version"`
	Algorithm      string         `json:"algorithm"`
	CookieName     string         `json:"cookie_name"`
	TrustedProxies []CompiledCIDR `json:"trusted_proxies"`
	BypassRoutes   []BypassRoute  `json:"bypass_routes"`
	CurrentKey     CompiledKey    `json:"current_key"`
	PreviousKey    *CompiledKey   `json:"previous_key,omitempty"`
	Rules          []Rule         `json:"rules"`
}

type CompiledKey struct {
	KeyID     string `json:"key_id"`
	KeyFile   string `json:"key_file"`
	KeySHA256 string `json:"key_sha256"`
}

// Network uses uint16 so JSON represents address bytes as numbers, not base64.
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
