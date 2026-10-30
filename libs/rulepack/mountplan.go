package rulepack

import (
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// MountRulePlan compiles the WAF / ACL rules of a site's mounts (Verify or
// Resolve order) into the layered rule plan the node's interpreter runs
// after the site's own policies: one segment per mount, default allow (a
// pack only adds decisions), with its match index (AttachMatchIndex, ADR
// 0011 §6.5). A plan over the compiled cost budget fails with a
// *MatchBudgetError. Other engines' rules are skipped. digest names a
// mount's pack object (segment provenance).
func MountRulePlan(rules []NodeRule, digest func(packID string) string, overflowBlocks bool) (edgeconfig.RulePlan, error) {
	var segments []edgeconfig.RulePlanSegmentInput
	last := ""
	for _, rule := range rules {
		var kind edgeconfig.SecurityKind
		switch rule.Engine {
		case EngineWAFV2:
			kind = edgeconfig.SecurityWAF
		case EngineACL:
			kind = edgeconfig.SecurityACL
		default:
			continue
		}
		if rule.WAF == nil {
			return edgeconfig.RulePlan{}, fmt.Errorf("%w: pack %s rule %s", ErrInvalidPack, rule.PackID, rule.RuleID)
		}
		if mount := rule.PackID + "\x00" + rule.Version; mount != last {
			last = mount
			segments = append(segments, edgeconfig.RulePlanSegmentInput{Layer: edgeconfig.RulePlanLayer(rule.Layer),
				Policy: edgeconfig.SecurityPolicy{Kind: kind, PolicyID: NodeRuleID(rule.PackID, "@pack"),
					PolicyVersion: 1, BindingRevision: 1, RuntimeSHA256: digest(rule.PackID),
					Enabled: true, DefaultAction: edgeconfig.WAFAllow, Rules: []edgeconfig.WAFRule{}}})
		}
		segment := &segments[len(segments)-1]
		segment.Policy.Rules = append(segment.Policy.Rules, *rule.WAF)
	}
	plan, err := edgeconfig.CompileLayeredRulePlan(segments, overflowBlocks, true)
	if err != nil {
		return edgeconfig.RulePlan{}, fmt.Errorf("%w: rule plan: %v", ErrInvalidPack, err)
	}
	if err := AttachMatchIndex(&plan); err != nil {
		return edgeconfig.RulePlan{}, err
	}
	return plan, nil
}
