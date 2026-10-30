package marketsupply

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

func securityConfig(t *testing.T, access, limit string) siteconf.Config {
	t.Helper()
	c := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.cn"}, HTTPPorts: []int{80},
		Origins: []siteconf.Origin{{Host: "203.0.113.20", Port: 80}}}
	if access != "" {
		c.Access = json.RawMessage(access)
	}
	if limit != "" {
		c.RateLimit = json.RawMessage(limit)
	}
	if err := c.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return c
}

func TestAccessMapsOntoLocalACL(t *testing.T) {
	c := securityConfig(t, `{"default":"block","rules":[{"cidr":"198.51.100.0/24","action":"allow"},
		{"cidr":"2001:db8::/32","action":"allow"},{"cidr":"203.0.113.9/32","action":"block"}]}`, "")
	access, err := c.DecodeAccess()
	if err != nil {
		t.Fatal(err)
	}
	fields, unsupported, err := accessFields(access)
	if err != nil || unsupported != "" || fields.Kind != securitypolicy.KindACL || fields.DefaultAction != "block" ||
		len(fields.Rules) != 3 || fields.Rules[0].Conditions[0].Values[0] != "198.51.100.0/24" ||
		fields.Rules[2].Action != securitypolicy.ActionBlock || fields.Rules[2].Priority != 3 {
		t.Fatalf("fields %+v unsupported %q err %v", fields, unsupported, err)
	}
	if got := securityBlockers(c, false); len(got) != 1 || got[0] != (siteconf.Blocker{Code: "unsupported_access", Detail: activationPending}) {
		t.Fatalf("blockers %+v", got)
	}
}

func TestAccessThatLocalACLCannotOrderIsUnsupported(t *testing.T) {
	c := securityConfig(t, `{"default":"allow","rules":[{"cidr":"203.0.113.0/24","action":"block"},
		{"cidr":"203.0.113.7/32","action":"allow"}]}`, "")
	if got := securityBlockers(c, false); len(got) != 1 || got[0] != (siteconf.Blocker{Code: "unsupported_access", Detail: "allow_after_block"}) {
		t.Fatalf("blockers %+v", got)
	}
	// Overlapping terminal rules are refused by the local ACL rules themselves.
	overlap := securityConfig(t, `{"default":"allow","rules":[{"cidr":"203.0.113.0/24","action":"block"},
		{"cidr":"203.0.113.0/25","action":"block"}]}`, "")
	if got := securityBlockers(overlap, false); len(got) != 1 || got[0].Code != "access_invalid" {
		t.Fatalf("overlap blockers %+v", got)
	}
}

func TestRateLimitMapsOntoLocalCC(t *testing.T) {
	c := securityConfig(t, "", `{"rules":[{"window_seconds":60,"max_requests":600},
		{"path_prefix":"/login","window_seconds":10,"max_requests":5,"on_exceed":"ban","ban_seconds":600}]}`)
	limit, err := c.DecodeRateLimit()
	if err != nil {
		t.Fatal(err)
	}
	fields, err := rateLimitFields(limit)
	if err != nil || fields.Kind != securitypolicy.KindCC || len(fields.Rules) != 2 {
		t.Fatalf("fields %+v err %v", fields, err)
	}
	first, second := fields.Rules[0], fields.Rules[1]
	if first.Conditions[0].Values[0] != "/" || first.ActionConfig.RateLimit.ResponseAction != "reject_429" ||
		first.ActionConfig.RateLimit.MaxRequests != 600 || second.Conditions[0].Values[0] != "/login" ||
		second.ActionConfig.RateLimit.ResponseAction != "temporary_ban" || second.ActionConfig.RateLimit.BanSeconds != 600 {
		t.Fatalf("rules %+v %+v", first, second)
	}
	if got := securityBlockers(c, false); len(got) != 1 || got[0] != (siteconf.Blocker{Code: "unsupported_rate_limit", Detail: activationPending}) {
		t.Fatalf("blockers %+v", got)
	}
}

func TestNoSecurityBlocksMeansNoBlockers(t *testing.T) {
	if got := securityBlockers(securityConfig(t, "", ""), false); len(got) != 0 {
		t.Fatalf("blockers %+v", got)
	}
}

// A leaf that can activate security policies accepts well-formed blocks and
// still refuses ones it cannot express or that are invalid.
func TestWiredSecurityAcceptsMappableBlocks(t *testing.T) {
	both := securityConfig(t, `{"default":"block","rules":[{"cidr":"198.51.100.0/24","action":"allow"}]}`,
		`{"rules":[{"window_seconds":60,"max_requests":600}]}`)
	if got := securityBlockers(both, true); len(got) != 0 {
		t.Fatalf("wired blockers %+v", got)
	}
	shadowed := securityConfig(t, `{"default":"allow","rules":[{"cidr":"203.0.113.0/24","action":"block"},
		{"cidr":"203.0.113.7/32","action":"allow"}]}`, "")
	if got := securityBlockers(shadowed, true); len(got) != 1 || got[0].Detail != "allow_after_block" {
		t.Fatalf("wired shadowed blockers %+v", got)
	}
}
