package securitypolicy

import (
	"errors"
	"strings"
	"testing"
)

func countByRule(countBy []CountKey) Rule {
	return Rule{Name: "count", Priority: 1, Enabled: true, Action: ActionRateLimit, Flow: FlowStop,
		Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
		ActionConfig: ActionConfig{RateLimit: &RateLimitConfig{Algorithm: "fixed_window", WindowSeconds: 10,
			MaxRequests: 30, ResponseAction: "temporary_ban", BanSeconds: 60}},
		CountBy: countBy}
}

func normalizeCCRule(rule Rule) (Rule, error) {
	fields := PolicyFields{Kind: KindCC, Name: "cc", Enabled: true, DefaultAction: ActionAllow, Rules: []Rule{rule}}
	err := normalizePublishableFields(&fields, true)
	if err != nil {
		return Rule{}, err
	}
	return fields.Rules[0], nil
}

// TestCountByNormalizesToCanonicalForm: count_by keys are stored in the
// fixed key order with explicit prefixes; the default [client_ip] is stored
// as absent so default rules keep their runtime snapshot bytes.
func TestCountByNormalizesToCanonicalForm(t *testing.T) {
	cases := map[string]struct {
		in   []CountKey
		want []CountKey
	}{
		"default client ip": {in: []CountKey{{Key: CountKeyClientIP}}, want: nil},
		"cidr defaults":     {in: []CountKey{{Key: CountKeyClientCIDR}}, want: []CountKey{{Key: CountKeyClientCIDR, IPv4Prefix: 24, IPv6Prefix: 64}}},
		"cidr explicit":     {in: []CountKey{{Key: CountKeyClientCIDR, IPv4Prefix: 16, IPv6Prefix: 48}}, want: []CountKey{{Key: CountKeyClientCIDR, IPv4Prefix: 16, IPv6Prefix: 48}}},
		"sorted pair":       {in: []CountKey{{Key: CountKeyURI}, {Key: CountKeyHost}}, want: []CountKey{{Key: CountKeyHost}, {Key: CountKeyURI}}},
		"ip and uri path":   {in: []CountKey{{Key: CountKeyURIPath}, {Key: CountKeyClientIP}}, want: []CountKey{{Key: CountKeyClientIP}, {Key: CountKeyURIPath}}},
		"ja4":               {in: []CountKey{{Key: CountKeyJA4}}, want: []CountKey{{Key: CountKeyJA4}}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			rule, err := normalizeCCRule(countByRule(test.in))
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if len(rule.CountBy) != len(test.want) {
				t.Fatalf("count_by = %#v, want %#v", rule.CountBy, test.want)
			}
			for index := range test.want {
				if rule.CountBy[index] != test.want[index] {
					t.Fatalf("count_by = %#v, want %#v", rule.CountBy, test.want)
				}
			}
		})
	}
}

func TestCountByRejectsInvalidCombinations(t *testing.T) {
	challenge := func(countBy []CountKey, trigger bool) Rule {
		rule := countByRule(countBy)
		rule.Action, rule.ActionConfig = ActionChallenge, ActionConfig{Challenge: &ChallengeConfig{Type: "js",
			FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 3600, BanSeconds: 600, PowBits: 16,
			ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}}
		if trigger {
			rule.ActionConfig.Challenge.TriggerWindowSeconds, rule.ActionConfig.Challenge.TriggerMaxRequests = 10, 30
		}
		return rule
	}
	cases := map[string]Rule{
		"three keys":        countByRule([]CountKey{{Key: CountKeyClientIP}, {Key: CountKeyHost}, {Key: CountKeyURI}}),
		"duplicate":         countByRule([]CountKey{{Key: CountKeyHost}, {Key: CountKeyHost}}),
		"ip with cidr":      countByRule([]CountKey{{Key: CountKeyClientIP}, {Key: CountKeyClientCIDR}}),
		"uri with uri path": countByRule([]CountKey{{Key: CountKeyURI}, {Key: CountKeyURIPath}}),
		"unknown key":       countByRule([]CountKey{{Key: "ja3"}}),
		"empty list":        countByRule([]CountKey{}),
		"ipv4 prefix low":   countByRule([]CountKey{{Key: CountKeyClientCIDR, IPv4Prefix: 7}}),
		"ipv4 prefix high":  countByRule([]CountKey{{Key: CountKeyClientCIDR, IPv4Prefix: 33}}),
		"ipv6 prefix low":   countByRule([]CountKey{{Key: CountKeyClientCIDR, IPv6Prefix: 31}}),
		"ipv6 prefix high":  countByRule([]CountKey{{Key: CountKeyClientCIDR, IPv6Prefix: 129}}),
		"prefix on host":    countByRule([]CountKey{{Key: CountKeyHost, IPv4Prefix: 24}}),
		"challenge always":  challenge([]CountKey{{Key: CountKeyHost}}, false),
		"challenge count key": func() Rule {
			rule := challenge([]CountKey{{Key: CountKeyHost}}, true)
			rule.ActionTarget = ActionTargetCountKey
			return rule
		}(),
		"target without count": func() Rule {
			rule := countByRule(nil)
			rule.ActionTarget = ActionTargetCountKey
			return rule
		}(),
		"target on reject": func() Rule {
			rule := countByRule([]CountKey{{Key: CountKeyJA4}})
			rule.ActionConfig.RateLimit.ResponseAction, rule.ActionConfig.RateLimit.BanSeconds = "reject_429", 0
			rule.ActionTarget = ActionTargetCountKey
			return rule
		}(),
		"unknown target": func() Rule {
			rule := countByRule([]CountKey{{Key: CountKeyJA4}})
			rule.ActionTarget = "site"
			return rule
		}(),
		"with distinct ua": func() Rule {
			rule := countByRule([]CountKey{{Key: CountKeyHost}})
			rule.Conditions = append(rule.Conditions, Condition{Field: "distinct_user_agents", Operator: "number_gte", Values: []string{"3"}})
			return rule
		}(),
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeCCRule(rule); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
	// count_by is a CC concept; WAF rules may not carry it.
	waf := PolicyFields{Kind: KindWAF, Name: "waf", Enabled: true, DefaultAction: ActionAllow, Rules: []Rule{{
		Name: "w", Priority: 1, Enabled: true, Action: ActionBlock, Flow: FlowStop,
		Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
		CountBy:    []CountKey{{Key: CountKeyHost}}}}}
	if err := normalizePublishableFields(&waf, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("WAF count_by error = %v", err)
	}
}

func TestCountByAcceptedTargetsAndChallengeTrigger(t *testing.T) {
	rule := countByRule([]CountKey{{Key: CountKeyJA4}})
	rule.ActionTarget = ActionTargetCountKey
	if normalized, err := normalizeCCRule(rule); err != nil || normalized.ActionTarget != ActionTargetCountKey {
		t.Fatalf("count_key ban: %v %#v", err, normalized)
	}
	rule.ActionTarget = ActionTargetClientIP
	if normalized, err := normalizeCCRule(rule); err != nil || normalized.ActionTarget != "" {
		t.Fatalf("explicit client_ip target should normalize to absent: %v %#v", err, normalized)
	}
	challenge := countByRule([]CountKey{{Key: CountKeyClientCIDR}, {Key: CountKeyURIPath}})
	challenge.Action, challenge.ActionConfig = ActionChallenge, ActionConfig{Challenge: &ChallengeConfig{Type: "js",
		FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 3600, BanSeconds: 600, PowBits: 16,
		ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400,
		TriggerWindowSeconds: 10, TriggerMaxRequests: 30}}
	if _, err := normalizeCCRule(challenge); err != nil {
		t.Fatalf("challenge triggered by count_by: %v", err)
	}
	leaky := countByRule([]CountKey{{Key: CountKeyHost}})
	leaky.ActionConfig.RateLimit = &RateLimitConfig{Algorithm: "leaky_bucket", RatePerSecond: 5, Burst: 10, ResponseAction: "reject_429"}
	if _, err := normalizeCCRule(leaky); err != nil {
		t.Fatalf("leaky bucket by host: %v", err)
	}
}

// TestCountByRuntimeSnapshotBytes: default rules keep their bytes; a
// count_by rule carries it right after action_config.
func TestCountByRuntimeSnapshotBytes(t *testing.T) {
	policy := runtimePolicy(KindCC)
	policy.Rules = []Rule{countByRule(nil)}
	policy.Rules[0].ID = runtimePolicy(KindCC).Rules[0].ID
	base, err := CompileRuntimeSnapshot(policy, runtimeSiteID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(base.CanonicalJSON), "count_by") || strings.Contains(string(base.CanonicalJSON), "action_target") {
		t.Fatalf("default rule gained fields: %s", base.CanonicalJSON)
	}
	policy.Rules[0].CountBy = []CountKey{{Key: CountKeyURI}, {Key: CountKeyClientCIDR, IPv4Prefix: 24}}
	policy.Rules[0].ActionTarget = ActionTargetCountKey
	compiled, err := CompileRuntimeSnapshot(policy, runtimeSiteID)
	if err != nil {
		t.Fatal(err)
	}
	want := `"action_config":{"rate_limit":{"window_seconds":10,"max_requests":30,"algorithm":"fixed_window","response_action":"temporary_ban","ban_seconds":60}},"count_by":[{"key":"client_cidr","ipv4_prefix":24,"ipv6_prefix":64},{"key":"uri"}],"action_target":"count_key"}`
	if !strings.Contains(string(compiled.CanonicalJSON), want) {
		t.Fatalf("runtime snapshot:\n%s\nwant suffix %s", compiled.CanonicalJSON, want)
	}
	if err := ValidateRuntimeSnapshot(compiled.Snapshot); err != nil {
		t.Fatalf("ValidateRuntimeSnapshot: %v", err)
	}
	if PolicyCCAPIVersion(policy) != 4 || PolicyCCAPIVersion(runtimePolicy(KindCC)) != 2 {
		t.Fatalf("PolicyCCAPIVersion = %d", PolicyCCAPIVersion(policy))
	}
}
