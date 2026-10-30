package httppolicycontrol

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Header variables, allow_duplicate and rule conditions.
func TestNormalizeHeaderVariablesAndConditions(t *testing.T) {
	ok := validTestConfig()
	ok.RequestHeaders = []HeaderAction{
		{Kind: HeaderAdd, Name: "x-a", Values: []string{"$remote_addr $$ $host-x"}, AllowDuplicate: true},
		{Kind: HeaderSet, Name: "x-b", Values: []string{"$tls_fp"}},
	}
	ok.Rewrites = append(ok.Rewrites, RewriteRule{RuleID: "rewrite-mobile", Priority: 10, MatchKind: MatchExact,
		MatchPath: "/legacy", TargetPath: "/m", PreserveQuery: true, PreserveCookie: true,
		Conditions: []edgeconfig.RuleCondition{{Source: "user_agent", Pattern: "iPhone"}}})
	if _, err := normalizeConfig(ok); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"unknown variable":      func(c *Config) { c.RequestHeaders[1].Values = []string{"$nope"} },
		"name run":              func(c *Config) { c.RequestHeaders[1].Values = []string{"$hostx"} },
		"trailing dollar":       func(c *Config) { c.RequestHeaders[1].Values = []string{"a$"} },
		"duplicate on set":      func(c *Config) { c.RequestHeaders[1].AllowDuplicate = true },
		"condition bad source":  func(c *Config) { c.Rewrites[1].Conditions[0].Source = "body" },
		"condition bad pattern": func(c *Config) { c.Rewrites[1].Conditions[0].Pattern = "(a*)*" },
		"condition empty":       func(c *Config) { c.Rewrites[1].Conditions = []edgeconfig.RuleCondition{} },
		"overlap no conditions": func(c *Config) { c.Rewrites[1].Conditions = nil },
		"too many conditions": func(c *Config) {
			for range 8 {
				c.Rewrites[1].Conditions = append(c.Rewrites[1].Conditions, edgeconfig.RuleCondition{Source: "asn", Pattern: "^4134$"})
			}
		},
	} {
		candidate := ok
		candidate.RequestHeaders = append([]HeaderAction(nil), ok.RequestHeaders...)
		candidate.Rewrites = append([]RewriteRule(nil), ok.Rewrites...)
		candidate.Rewrites[1].Conditions = append([]edgeconfig.RuleCondition(nil), ok.Rewrites[1].Conditions...)
		mutate(&candidate)
		if _, err := normalizeConfig(candidate); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
