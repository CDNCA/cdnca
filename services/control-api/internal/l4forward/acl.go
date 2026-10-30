package l4forward

import (
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// aclRuleNamespace derives the guard rule IDs of a stream's ACL, so the same
// ACL always publishes the same rules (stable intents, idempotent replays).
var aclRuleNamespace = uuid.MustParse("6d1c4f0e-3a51-4b8e-9d0c-5f1e2b7a4c90")

// aclGuardRules is the stream's 访问控制 IP rules as L4 guard rules
// (edgeconfig.L4GuardRuleV2, tcp/udp v10): each rule a client_ip condition
// with allow (no later rule is evaluated) or drop; ACL 默认拒绝 ends with a
// drop for every address. Allow rules only matter before a drop, so a default
// allow ACL publishes its deny rules and the allows in front of them.
//
// The stream's own guard rules follow the ACL's: an allowed client still
// meets them, a denied one never does. Consecutive rules of one action are
// merged into one CIDR list (fewer rules, same first-match result).
func aclGuardRules(streamID uuid.UUID, acl ACL) []GuardRule {
	type group struct {
		action string
		cidrs  []string
	}
	var groups []group
	for _, rule := range acl.Rules {
		action := edgeconfig.L4GuardActionAllow
		if rule.Action == ACLActionDeny {
			action = edgeconfig.L4GuardActionDrop
		}
		if len(groups) > 0 && groups[len(groups)-1].action == action &&
			len(groups[len(groups)-1].cidrs) < edgeconfig.L4GuardCIDRsPerRuleMax {
			groups[len(groups)-1].cidrs = append(groups[len(groups)-1].cidrs, rule.CIDR)
			continue
		}
		groups = append(groups, group{action: action, cidrs: []string{rule.CIDR}})
	}
	if acl.DefaultAction == ACLActionDeny {
		groups = append(groups, group{action: edgeconfig.L4GuardActionDrop, cidrs: []string{"0.0.0.0/0", "::/0"}})
	}
	// Trailing allows decide nothing (the stream's own rules come next in
	// both cases): only allows ahead of a drop are published.
	for len(groups) > 0 && groups[len(groups)-1].action == edgeconfig.L4GuardActionAllow {
		groups = groups[:len(groups)-1]
	}
	rules := make([]GuardRule, 0, len(groups))
	for index, value := range groups {
		id := uuid.NewSHA1(aclRuleNamespace, []byte(streamID.String()+"/"+strconv.Itoa(index)))
		rules = append(rules, GuardRule{ID: id.String(), Action: value.action,
			ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: value.cidrs}})
	}
	return rules
}

// runtimeGuardRulesWithACL is the published guard rule list: the ACL's
// first, then the stream's own; nil when both are empty.
func runtimeGuardRulesWithACL(item Forward) []GuardRule {
	rules := aclGuardRules(item.ID, item.ACL)
	rules = append(rules, item.GuardRules...)
	if len(rules) == 0 {
		return nil
	}
	// The canonical form the node checks (masked, sorted CIDRs); the ACL
	// was validated on write, so this only sorts.
	normalized, err := edgeconfig.NormalizeL4GuardRules(rules, item.TLSPassthrough)
	if err != nil {
		return rules
	}
	return normalized
}
