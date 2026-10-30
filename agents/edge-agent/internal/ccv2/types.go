package ccv2

import (
	"errors"
)

const (
	SourceSchemaVersion   = "cdnca.security-policy.runtime/v1"
	CompiledSchemaVersion = "cdnca.edge.cc/v2"
	RegistrySchemaVersion = "cdnca.edge.cc-registry/v1"
	MaxSourceBytes        = 1 << 20
	MaxRules              = 128
)

var ErrInvalidSource = errors.New("invalid CC v2 source")

type Binding struct {
	BindingID       string
	BindingRevision int64
	PublicationID   string
}

type sourcePolicy struct {
	SchemaVersion string            `json:"schema_version"`
	TenantScopeID string            `json:"tenant_scope_id"`
	SiteID        string            `json:"site_id"`
	PolicyID      string            `json:"policy_id"`
	PolicyVersion int64             `json:"policy_version"`
	Kind          string            `json:"kind"`
	Enabled       bool              `json:"enabled"`
	DefaultAction string            `json:"default_action"`
	Rules         []sourceRule      `json:"rules"`
	AutoSwitch    *sourceAutoSwitch `json:"auto_switch,omitempty"`
	// CC API v6 (securitypolicy.RuntimeSnapshot): trusted crawlers and the
	// pass cookie domain.
	TrustedCrawlers       []trustedCrawler `json:"trusted_crawlers,omitempty"`
	ChallengeCookieDomain string           `json:"challenge_cookie_domain,omitempty"`
}

// trustedCrawler mirrors securitypolicy.CCTrustedCrawler and
// edgeconfig.CCV2TrustedCrawler (the same JSON in source and compiled).
type trustedCrawler struct {
	Name            string   `json:"name"`
	UserAgentTokens []string `json:"user_agent_tokens"`
	Networks        []string `json:"networks,omitempty"`
	RDNSSuffixes    []string `json:"rdns_suffixes,omitempty"`
}

// sourceAutoSwitch mirrors securitypolicy.RuntimeAutoSwitch (CC API v5).
type sourceAutoSwitch struct {
	QPSTotal       int          `json:"qps_total"`
	QPS5xx         int          `json:"qps_5xx"`
	RecoverSeconds int          `json:"recover_seconds"`
	Rules          []sourceRule `json:"rules"`
}

type sourceRule struct {
	ID           string             `json:"id"`
	Priority     int                `json:"priority"`
	Enabled      bool               `json:"enabled"`
	Conditions   []sourceCondition  `json:"conditions"`
	Action       string             `json:"action"`
	Flow         string             `json:"flow"`
	ActionConfig sourceActionConfig `json:"action_config"`
	CountBy      []sourceCountKey   `json:"count_by,omitempty"`
	ActionTarget string             `json:"action_target,omitempty"`
}

// sourceCountKey mirrors securitypolicy.CountKey (CC API v4 counting keys).
type sourceCountKey struct {
	Key        string `json:"key"`
	IPv4Prefix int    `json:"ipv4_prefix,omitempty"`
	IPv6Prefix int    `json:"ipv6_prefix,omitempty"`
	Name       string `json:"name,omitempty"` // CC API v7 header / cookie / query
}

type sourceCondition struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Key      string   `json:"key,omitempty"`
	Values   []string `json:"values"`
}

type sourceActionConfig struct {
	RateLimit *sourceRateLimit `json:"rate_limit,omitempty"`
	Challenge *sourceChallenge `json:"challenge,omitempty"`
}

// sourceChallenge mirrors securitypolicy.ChallengeConfig field for field so
// the canonical re-encoding of the runtime snapshot stays byte-identical.
type sourceChallenge struct {
	Type                  string `json:"type"`
	FailureWindowSeconds  int    `json:"failure_window_seconds,omitempty"`
	MaxFailures           int    `json:"max_failures,omitempty"`
	PassSeconds           int    `json:"pass_seconds,omitempty"`
	BanSeconds            int    `json:"ban_seconds,omitempty"`
	LogOnly               bool   `json:"log_only,omitempty"`
	PowBits               int    `json:"pow_bits,omitempty"`
	DelaySeconds          int    `json:"delay_seconds,omitempty"`
	ChallengeSeconds      int    `json:"challenge_seconds,omitempty"`
	BindIPv4Prefix        int    `json:"bind_ipv4_prefix,omitempty"`
	BindIPv6Prefix        int    `json:"bind_ipv6_prefix,omitempty"`
	KeyRotateSeconds      int    `json:"key_rotate_seconds,omitempty"`
	TriggerWindowSeconds  int    `json:"trigger_window_seconds,omitempty"`
	TriggerMaxRequests    int    `json:"trigger_max_requests,omitempty"`
	PassWindowSeconds     int    `json:"pass_window_seconds,omitempty"`
	PassMaxRequests       int    `json:"pass_max_requests,omitempty"`
	PassMaxRequestsPerURI int    `json:"pass_max_requests_per_uri,omitempty"`
}

type sourceRateLimit struct {
	WindowSeconds  int    `json:"window_seconds,omitempty"`
	MaxRequests    int    `json:"max_requests,omitempty"`
	MaxPerURI      int    `json:"max_requests_per_uri,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"`
	RatePerSecond  int    `json:"rate_per_second,omitempty"`
	Burst          int    `json:"burst,omitempty"`
	ResponseAction string `json:"response_action,omitempty"`
	BanSeconds     int    `json:"ban_seconds,omitempty"`
	Adaptive       any    `json:"adaptive,omitempty"`
}

type compiledPolicy struct {
	SchemaVersion   string              `json:"schema_version"`
	TenantScopeID   string              `json:"tenant_scope_id"`
	SiteID          string              `json:"site_id"`
	PolicyID        string              `json:"policy_id"`
	PolicyVersion   int64               `json:"policy_version"`
	BindingID       string              `json:"binding_id"`
	BindingRevision int64               `json:"binding_revision"`
	PublicationID   string              `json:"publication_id"`
	Enabled         bool                `json:"enabled"`
	TrustedProxies  []string            `json:"trusted_proxies"`
	Allowlist       []string            `json:"allowlist"`
	Rules           []compiledRule      `json:"rules"`
	AutoSwitch      *compiledAutoSwitch `json:"auto_switch,omitempty"`
	// CC API v6.
	TrustedCrawlers       []trustedCrawler `json:"trusted_crawlers,omitempty"`
	ChallengeCookieDomain string           `json:"challenge_cookie_domain,omitempty"`
}

type compiledAutoSwitch struct {
	QPSTotal       uint32         `json:"qps_total"`
	QPS5xx         uint32         `json:"qps_5xx"`
	RecoverSeconds uint32         `json:"recover_seconds"`
	Rules          []compiledRule `json:"rules"`
}

type compiledRule struct {
	RuleID    string             `json:"rule_id"`
	Priority  int                `json:"priority"`
	Flow      string             `json:"flow"`
	Match     compiledMatch      `json:"match"`
	Dimension string             `json:"dimension"`
	CountBy   []compiledCountKey `json:"count_by,omitempty"`
	Limit     compiledLimit      `json:"limit"`
	Action    compiledAction     `json:"action"`
}

type compiledCountKey struct {
	Key        string `json:"key"`
	IPv4Prefix uint32 `json:"ipv4_prefix,omitempty"`
	IPv6Prefix uint32 `json:"ipv6_prefix,omitempty"`
	Name       string `json:"name,omitempty"`
}

type compiledMatch struct {
	Host               string             `json:"host,omitempty"`
	Port               uint16             `json:"port,omitempty"`
	Method             string             `json:"method,omitempty"`
	Path               *compiledPathMatch `json:"path,omitempty"`
	SourceCIDR         string             `json:"source_cidr,omitempty"`
	DistinctUserAgents uint32             `json:"distinct_user_agents,omitempty"`
	Status404Count     uint32             `json:"status_404_count,omitempty"`
	PathContains       []string           `json:"path_contains,omitempty"`
	// CC API v6: client IP lists and header matches (all entries hold).
	ClientIP []compiledIPMatch     `json:"client_ip,omitempty"`
	Headers  []compiledHeaderMatch `json:"headers,omitempty"`
	// CC API v7 (fix-ja4rule): $cdnca_ja4 is one of these (sorted, unique).
	JA4 []string `json:"ja4,omitempty"`
}

type compiledIPMatch struct {
	Negate bool     `json:"negate,omitempty"`
	CIDRs  []string `json:"cidrs"`
}

type compiledHeaderMatch struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Values []string `json:"values"`
}

type compiledPathMatch struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type compiledLimit struct {
	Algorithm     string `json:"algorithm"`
	Requests      uint32 `json:"requests,omitempty"`
	PerURI        uint32 `json:"requests_per_uri,omitempty"`
	WindowSeconds uint32 `json:"window_seconds,omitempty"`
	RatePerSecond uint32 `json:"rate_per_second,omitempty"`
	Burst         uint32 `json:"burst,omitempty"`
}

type compiledAction struct {
	Kind       string             `json:"kind"`
	BanSeconds uint32             `json:"ban_seconds,omitempty"`
	Challenge  *compiledChallenge `json:"challenge,omitempty"`
	Target     string             `json:"target,omitempty"`
}

type compiledChallenge struct {
	Mode                 string         `json:"mode"`
	DelaySeconds         uint32         `json:"delay_seconds,omitempty"`
	FailureWindowSeconds uint32         `json:"failure_window_seconds"`
	MaxFailures          uint32         `json:"max_failures"`
	PassSeconds          uint32         `json:"pass_seconds"`
	LogOnly              bool           `json:"log_only,omitempty"`
	PassLimit            *compiledLimit `json:"pass_limit,omitempty"`
	PowBits              uint32         `json:"pow_bits"`
	ChallengeSeconds     uint32         `json:"challenge_seconds"`
	BindIPv4Prefix       uint32         `json:"bind_ipv4_prefix"`
	BindIPv6Prefix       uint32         `json:"bind_ipv6_prefix"`
	KeyRotateSeconds     uint32         `json:"key_rotate_seconds"`
}
