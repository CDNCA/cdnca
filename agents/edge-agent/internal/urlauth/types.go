package urlauth

import (
	"errors"
	"net/netip"
)

const (
	SchemaVersion       = "cdnca.edge.urlauth/v1"
	AlgorithmHMACSHA256 = "hmac-sha256"

	MaxPolicyBytes       = 1 << 20
	MaxPolicyVersion     = 1<<53 - 1
	MaxIdentifierBytes   = 128
	MaxParameterBytes    = 64
	MaxExcludedParams    = 32
	MaxProxyCIDRs        = 64
	MaxCIDRBytes         = 64
	MaxKeyIDBytes        = 64
	MaxKeyFilePathBytes  = 4096
	MinKeyBytes          = 32
	MaxKeyBytes          = 128
	MaxClockSkewSeconds  = 300
	MaxValiditySeconds   = 86_400
	MaxSignatureUses     = 1_000_000
	MaxURIBytes          = 4096
	MaxPathBytes         = 2048
	MaxQueryBytes        = 2048
	MaxQueryParameters   = 64
	MaxQueryValueBytes   = 1024
	MaxForwardedForBytes = 2048
	MaxForwardedForHops  = 32
)

var ErrInvalidPolicy = errors.New("invalid URL auth policy")

type Policy struct {
	SchemaVersion           string   `json:"schema_version"`
	PolicyVersion           uint64   `json:"policy_version"`
	TenantID                string   `json:"tenant_id"`
	SiteID                  string   `json:"site_id"`
	Algorithm               string   `json:"algorithm"`
	SignatureParameter      string   `json:"signature_parameter"`
	ExpirationParameter     string   `json:"expiration_parameter"`
	KeyIDParameter          string   `json:"key_id_parameter"`
	BindClientIP            bool     `json:"bind_client_ip"`
	MaxClockSkewSeconds     uint32   `json:"max_clock_skew_seconds"`
	MaxValiditySeconds      uint32   `json:"max_validity_seconds"`
	MaxSignatureUses        uint32   `json:"max_signature_uses"`
	ExcludedQueryParameters []string `json:"excluded_query_parameters"`
	TrustedProxies          []string `json:"trusted_proxies"`
	CurrentKey              KeyRef   `json:"current_key"`
	PreviousKey             *KeyRef  `json:"previous_key,omitempty"`
}

type KeyRef struct {
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
}

type CompiledPolicy struct {
	SchemaVersion           string         `json:"schema_version"`
	PolicyVersion           uint64         `json:"policy_version"`
	TenantID                string         `json:"tenant_id"`
	SiteID                  string         `json:"site_id"`
	Algorithm               string         `json:"algorithm"`
	SignatureParameter      string         `json:"signature_parameter"`
	ExpirationParameter     string         `json:"expiration_parameter"`
	KeyIDParameter          string         `json:"key_id_parameter"`
	BindClientIP            bool           `json:"bind_client_ip"`
	MaxClockSkewSeconds     uint32         `json:"max_clock_skew_seconds"`
	MaxValiditySeconds      uint32         `json:"max_validity_seconds"`
	MaxSignatureUses        uint32         `json:"max_signature_uses"`
	ExcludedQueryParameters []string       `json:"excluded_query_parameters"`
	TrustedProxies          []CompiledCIDR `json:"trusted_proxies"`
	CurrentKey              CompiledKey    `json:"current_key"`
	PreviousKey             *CompiledKey   `json:"previous_key,omitempty"`
}

type CompiledKey struct {
	KeyID     string `json:"key_id"`
	KeyFile   string `json:"key_file"`
	KeySHA256 string `json:"key_sha256"`
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
