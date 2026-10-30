package marketsupply

import (
	"fmt"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

// activationPending explains why a well-formed access or rate limit block is
// refused by a leaf whose security activation is not wired (WithSecurity).
const activationPending = "activation_pending"

// accessFields maps the neutral access list onto a local ACL policy. The
// local ACL evaluates every allow before any block, so a list that relies on
// a block rule shadowing a later allow cannot be honoured.
func accessFields(access *siteconf.Access) (securitypolicy.PolicyFields, string, error) {
	fields := securitypolicy.PolicyFields{Kind: securitypolicy.KindACL, Name: "market access", Enabled: true,
		DefaultAction: access.Default}
	blocked := false
	for i, rule := range access.Rules {
		if rule.Action == "allow" && blocked {
			return securitypolicy.PolicyFields{}, "allow_after_block", nil
		}
		blocked = blocked || rule.Action == "block"
		fields.Rules = append(fields.Rules, securitypolicy.Rule{
			Name: fmt.Sprintf("%s %s", rule.Action, rule.CIDR), Priority: i + 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{rule.CIDR}}},
			Action:     rule.Action, Flow: securitypolicy.FlowStop,
		})
	}
	policy := securitypolicy.Policy{Kind: fields.Kind, Name: fields.Name, Enabled: true,
		DefaultAction: fields.DefaultAction, Rules: fields.Rules}
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		return securitypolicy.PolicyFields{}, "", err
	}
	if err := securitypolicy.ValidateACLRules(fields.Rules); err != nil {
		return securitypolicy.PolicyFields{}, "", err
	}
	return fields, "", nil
}

// rateLimitFields maps the neutral limits onto a local CC policy: one
// fixed-window rule per limit, per client IP, under its path prefix.
func rateLimitFields(limit *siteconf.RateLimit) (securitypolicy.PolicyFields, error) {
	fields := securitypolicy.PolicyFields{Kind: securitypolicy.KindCC, Name: "market rate limit", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow}
	for i, rule := range limit.Rules {
		prefix := rule.PathPrefix
		if prefix == "" {
			prefix = "/"
		}
		config := &securitypolicy.RateLimitConfig{Algorithm: "fixed_window", WindowSeconds: rule.WindowSeconds,
			MaxRequests: rule.MaxRequests, ResponseAction: "reject_429"}
		if rule.OnExceed == "ban" {
			config.ResponseAction, config.BanSeconds = "temporary_ban", rule.BanSeconds
		}
		fields.Rules = append(fields.Rules, securitypolicy.Rule{
			Name: fmt.Sprintf("limit %d %s", i+1, prefix), Priority: i + 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{prefix}}},
			Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowContinue,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: config},
		})
	}
	policy := securitypolicy.Policy{Kind: fields.Kind, Name: fields.Name, Enabled: true,
		DefaultAction: fields.DefaultAction, Rules: fields.Rules}
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		return securitypolicy.PolicyFields{}, err
	}
	return fields, nil
}

// securityBlockers checks the access and rate limit blocks. A block that maps
// cleanly passes when the leaf can activate it (wired); otherwise it is
// refused with activation_pending, never silently dropped.
func securityBlockers(c siteconf.Config, wired bool) []siteconf.Blocker {
	var out []siteconf.Blocker
	if access, err := c.DecodeAccess(); err != nil {
		out = append(out, siteconf.Blocker{Code: "access_invalid"})
	} else if access != nil {
		if _, unsupported, err := accessFields(access); err != nil {
			out = append(out, siteconf.Blocker{Code: "access_invalid"})
		} else if unsupported != "" {
			out = append(out, siteconf.Blocker{Code: "unsupported_access", Detail: unsupported})
		} else if !wired {
			out = append(out, siteconf.Blocker{Code: "unsupported_access", Detail: activationPending})
		}
	}
	if limit, err := c.DecodeRateLimit(); err != nil {
		out = append(out, siteconf.Blocker{Code: "rate_limit_invalid"})
	} else if limit != nil {
		if _, err := rateLimitFields(limit); err != nil {
			out = append(out, siteconf.Blocker{Code: "rate_limit_invalid"})
		} else if !wired {
			out = append(out, siteconf.Blocker{Code: "unsupported_rate_limit", Detail: activationPending})
		}
	}
	return out
}
