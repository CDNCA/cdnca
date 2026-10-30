package securitypolicy

import (
	"slices"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// CC counting keys (CC API v4). A rule counts requests per value of one key
// or the combination of two:
//   - client_ip: the client address (the default, and the only key before v4);
//   - client_cidr: the client network, IPv4Prefix / IPv6Prefix bits;
//   - host: the request Host; uri: path with query; uri_path: path only;
//   - ja4: the TLS fingerprint ($cdnca_ja4). A request without one is not
//     counted by the rule (it would otherwise share one bucket with every
//     other request without a fingerprint).
const (
	CountKeyClientIP   = "client_ip"
	CountKeyClientCIDR = "client_cidr"
	CountKeyHost       = "host"
	CountKeyURI        = "uri"
	CountKeyURIPath    = "uri_path"
	CountKeyJA4        = "ja4"
	// CC API v7 (fix-ja4rule, CAPABILITY_NAME_CC_MATCH_KEYS): User-Agent,
	// Referer and one named header / cookie / query argument (CountKey.Name);
	// a request without the value is not counted.
	CountKeyUserAgent = "user_agent"
	CountKeyReferer   = "referer"
	CountKeyHeader    = "header"
	CountKeyCookie    = "cookie"
	CountKeyQuery     = "query"

	ActionTargetClientIP = "client_ip"
	ActionTargetCountKey = "count_key"

	MaxCountKeys           = 2
	DefaultCountIPv4Prefix = 24
	DefaultCountIPv6Prefix = 64
	countByCCAPIVersion    = 4
	matchKeysCCAPIVersion  = 7
	defaultCCAPIVersion    = 2
)

// countKeyOrder is the canonical order of count_by keys.
var countKeyOrder = []string{CountKeyClientIP, CountKeyClientCIDR, CountKeyHost, CountKeyURI, CountKeyURIPath, CountKeyJA4,
	CountKeyUserAgent, CountKeyReferer, CountKeyHeader, CountKeyCookie, CountKeyQuery}

type CountKey struct {
	Key        string `json:"key"`
	IPv4Prefix int    `json:"ipv4_prefix,omitempty"`
	IPv6Prefix int    `json:"ipv6_prefix,omitempty"`
	// Name: the header (stored lower case) / cookie / query argument of key
	// header / cookie / query; absent for the other keys.
	Name string `json:"name,omitempty"`
}

// matchKeysCountKey: a counting key of CC API v7.
func matchKeysCountKey(key string) bool {
	return key == CountKeyUserAgent || key == CountKeyReferer || key == CountKeyHeader || key == CountKeyCookie || key == CountKeyQuery
}

// normalizeCountBy validates a CC rule's count_by and action_target and puts
// them in canonical form: keys in countKeyOrder, client_cidr with explicit
// prefixes, the default [client_ip] and target client_ip stored as absent.
func normalizeCountBy(kind string, rule *Rule) error {
	rule.ActionTarget = strings.TrimSpace(rule.ActionTarget)
	if rule.CountBy == nil && rule.ActionTarget == "" {
		return nil
	}
	if kind != KindCC {
		if rule.CountBy != nil {
			return refuse("count_by", fielderr.Invalid)
		}
		return refuse("action_target", fielderr.Invalid)
	}
	if rule.CountBy != nil {
		if len(rule.CountBy) < 1 {
			return refuse("count_by", fielderr.Required)
		}
		if len(rule.CountBy) > MaxCountKeys {
			return refuse("count_by", fielderr.OutOfRange)
		}
		keys := make([]CountKey, len(rule.CountBy))
		seen := make(map[string]bool, len(keys))
		for index, value := range rule.CountBy {
			path := indexed("count_by", index)
			value.Key = strings.TrimSpace(value.Key)
			if !slices.Contains(countKeyOrder, value.Key) {
				return refuse(path+".key", fielderr.Invalid)
			}
			if seen[value.Key] {
				return refuse(path+".key", fielderr.Duplicate)
			}
			seen[value.Key] = true
			if value.Key == CountKeyClientCIDR {
				if value.IPv4Prefix == 0 {
					value.IPv4Prefix = DefaultCountIPv4Prefix
				}
				if value.IPv6Prefix == 0 {
					value.IPv6Prefix = DefaultCountIPv6Prefix
				}
				if err := outOfRange(bound{path + ".ipv4_prefix", within(value.IPv4Prefix, 8, 32)},
					bound{path + ".ipv6_prefix", within(value.IPv6Prefix, 32, 128)}); err != nil {
					return err
				}
			} else if value.IPv4Prefix != 0 {
				return refuse(path+".ipv4_prefix", fielderr.Invalid)
			} else if value.IPv6Prefix != 0 {
				return refuse(path+".ipv6_prefix", fielderr.Invalid)
			}
			value.Name = strings.TrimSpace(value.Name)
			switch value.Key {
			case CountKeyHeader:
				value.Name = strings.ToLower(value.Name)
				if !headerNamePattern.MatchString(value.Name) || len(value.Name) > 64 {
					return refuse(path+".name", fielderr.InvalidFormat)
				}
			case CountKeyCookie, CountKeyQuery:
				if !wafNameKeyPattern.MatchString(value.Name) {
					return refuse(path+".name", fielderr.InvalidFormat)
				}
			default:
				if value.Name != "" {
					return refuse(path+".name", fielderr.Invalid)
				}
			}
			keys[index] = value
		}
		// One key subsumes the other: counting by both is counting by the finer.
		if seen[CountKeyClientIP] && seen[CountKeyClientCIDR] || seen[CountKeyURI] && seen[CountKeyURIPath] {
			return refuse("count_by", fielderr.Duplicate)
		}
		slices.SortFunc(keys, func(left, right CountKey) int {
			return slices.Index(countKeyOrder, left.Key) - slices.Index(countKeyOrder, right.Key)
		})
		rule.CountBy = keys
		if len(keys) == 1 && keys[0].Key == CountKeyClientIP {
			rule.CountBy = nil
		}
	}
	if rule.ActionTarget == ActionTargetClientIP {
		rule.ActionTarget = ""
	}
	if rule.ActionTarget != "" && rule.ActionTarget != ActionTargetCountKey {
		return refuse("action_target", fielderr.Invalid)
	}
	if rule.CountBy == nil {
		if rule.ActionTarget != "" {
			return refuse("action_target", fielderr.Invalid)
		}
		return nil
	}
	switch rule.Action {
	case ActionRateLimit:
		// Only a ban outlives the window; banning the whole bucket is the one
		// target a counted key changes.
		if rule.ActionTarget == ActionTargetCountKey && rule.ActionConfig.RateLimit.ResponseAction != "temporary_ban" {
			return refuse("action_target", fielderr.Invalid)
		}
	case ActionChallenge:
		// A challenge counts only through its trigger; one client passing it
		// must never let a whole network or fingerprint through.
		if rule.ActionTarget != "" {
			return refuse("action_target", fielderr.Invalid)
		}
		if rule.ActionConfig.Challenge.TriggerWindowSeconds == 0 {
			return refuse("action_config.challenge.trigger_window_seconds", fielderr.Required)
		}
	default:
		return refuse("count_by", fielderr.Invalid)
	}
	// distinct_user_agents / status_404_count count per client.
	for index, condition := range rule.Conditions {
		if isSEC11CountField(condition.Field) {
			return refuse(indexed("conditions", index)+".field", fielderr.Invalid)
		}
	}
	return nil
}

// ruleNeedsMatchKeys: a CC rule counting by a CC API v7 key or matching on JA4.
func ruleNeedsMatchKeys(rule Rule) bool {
	for _, key := range rule.CountBy {
		if matchKeysCountKey(key.Key) {
			return true
		}
	}
	for _, condition := range rule.Conditions {
		if condition.Field == "ja4" {
			return true
		}
	}
	return false
}

// RuleCountsByKey reports a rule with a non-default count_by.
func RuleCountsByKey(rule Rule) bool { return len(rule.CountBy) != 0 }

// PolicyCCAPIVersion is the CC API version a CC policy needs: 4 for counting
// keys, 3 for proof-of-work challenges, otherwise 2.
func PolicyCCAPIVersion(policy Policy) uint32 {
	if policy.Kind != KindCC {
		return 0
	}
	for _, rule := range policy.Rules {
		if rule.Enabled && ruleNeedsMatchKeys(rule) {
			return matchKeysCCAPIVersion
		}
	}
	for _, rule := range policy.Rules {
		if rule.Enabled && RuleCountsByKey(rule) {
			return countByCCAPIVersion
		}
	}
	if PolicyNeedsProofOfWork(policy) {
		return ccProofOfWorkAPIVersion
	}
	return defaultCCAPIVersion
}
