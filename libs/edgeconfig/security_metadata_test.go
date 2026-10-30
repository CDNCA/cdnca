package edgeconfig

import (
	"errors"
	"testing"
)

func TestBoundSecurityRejectsInvalidMetadata(t *testing.T) {
	valid := WAFRule{
		RuleID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", Match: WAFMatch{SourceCIDR: "192.0.2.0/24"},
		Action: WAFBlock, Control: WAFStop,
	}
	for name, mutate := range map[string]func(*WAFRule){
		"comment without CIDR": func(rule *WAFRule) { rule.Comment, rule.Match.SourceCIDR = "temporary", "" },
		"control comment":      func(rule *WAFRule) { rule.Comment = "bad\ncomment" },
		"offset expiry":        func(rule *WAFRule) { rule.ExpiresAt = "2030-01-02T03:04:05+00:00" },
		"pre epoch expiry":     func(rule *WAFRule) { rule.ExpiresAt = "1969-12-31T23:59:59Z" },
	} {
		t.Run(name, func(t *testing.T) {
			rule := valid
			mutate(&rule)
			_, err := normalizeSecurityPolicies([]SecurityPolicy{{
				Kind: SecurityACL, PolicyID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
				PolicyVersion: 1, BindingRevision: 1,
				RuntimeSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Enabled:       true, DefaultAction: WAFAllow, Rules: []WAFRule{rule},
			}})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
