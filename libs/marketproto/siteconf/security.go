package siteconf

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
)

// Access is the controller-neutral client access list of a site
// (Config.Access): rules apply in order, the first matching CIDR decides,
// otherwise Default does. Absent means the subscriber does not manage it.
type Access struct {
	Default string       `json:"default"` // allow, block
	Rules   []AccessRule `json:"rules"`
}

type AccessRule struct {
	CIDR   string `json:"cidr"`
	Action string `json:"action"` // allow, block
}

// RateLimit is the controller-neutral per-client request limit of a site
// (Config.RateLimit). Absent means the subscriber does not manage it.
type RateLimit struct {
	Rules []RateLimitRule `json:"rules"`
}

// RateLimitRule counts requests per client IP in a fixed window, optionally
// only under PathPrefix; over the limit the client gets 429, or is banned for
// BanSeconds when OnExceed is "ban".
type RateLimitRule struct {
	PathPrefix    string `json:"path_prefix,omitempty"`
	WindowSeconds int    `json:"window_seconds"`
	MaxRequests   int    `json:"max_requests"`
	OnExceed      string `json:"on_exceed,omitempty"` // reject (default), ban
	BanSeconds    int    `json:"ban_seconds,omitempty"`
}

const (
	maxAccessRules    = 100
	maxRateLimitRules = 32
)

func decodeStrict(raw json.RawMessage, into any) (bool, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil || decoder.More() {
		return false, ErrInvalid
	}
	return true, nil
}

// DecodeAccess returns the access block, or nil when the config carries none.
func (c Config) DecodeAccess() (*Access, error) {
	var access Access
	if present, err := decodeStrict(c.Access, &access); !present || err != nil {
		return nil, err
	}
	if (access.Default != "allow" && access.Default != "block") || len(access.Rules) == 0 ||
		len(access.Rules) > maxAccessRules {
		return nil, ErrInvalid
	}
	for i, rule := range access.Rules {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(rule.CIDR))
		if err != nil || (rule.Action != "allow" && rule.Action != "block") {
			return nil, ErrInvalid
		}
		access.Rules[i].CIDR = prefix.Masked().String()
	}
	return &access, nil
}

// DecodeRateLimit returns the rate limit block, or nil when the config carries none.
func (c Config) DecodeRateLimit() (*RateLimit, error) {
	var limit RateLimit
	if present, err := decodeStrict(c.RateLimit, &limit); !present || err != nil {
		return nil, err
	}
	if len(limit.Rules) == 0 || len(limit.Rules) > maxRateLimitRules {
		return nil, ErrInvalid
	}
	for i := range limit.Rules {
		rule := &limit.Rules[i]
		if rule.OnExceed == "" {
			rule.OnExceed = "reject"
		}
		if rule.WindowSeconds < 1 || rule.WindowSeconds > 3600 || rule.MaxRequests < 1 || rule.MaxRequests > 1_000_000 ||
			!slices.Contains([]string{"reject", "ban"}, rule.OnExceed) || len(rule.PathPrefix) > 512 ||
			(rule.PathPrefix != "" && !strings.HasPrefix(rule.PathPrefix, "/")) ||
			(rule.OnExceed == "ban") != (rule.BanSeconds > 0) || rule.BanSeconds < 0 || rule.BanSeconds > 86_400 {
			return nil, ErrInvalid
		}
	}
	return &limit, nil
}

// normalizeSecurity rewrites the access and rate limit blocks canonically.
func (c *Config) normalizeSecurity() error {
	access, err := c.DecodeAccess()
	if err != nil {
		return err
	}
	limit, err := c.DecodeRateLimit()
	if err != nil {
		return err
	}
	if limit != nil && len(c.CC) > 0 {
		return ErrInvalid // one CC policy per site: the cc block replaces rate_limit
	}
	c.Access, c.RateLimit = nil, nil
	if access != nil {
		if c.Access, err = json.Marshal(access); err != nil {
			return ErrInvalid
		}
	}
	if limit != nil {
		if c.RateLimit, err = json.Marshal(limit); err != nil {
			return ErrInvalid
		}
	}
	return nil
}
