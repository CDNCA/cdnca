package securitypolicy

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
)

// maxCCAutoSwitchOverrides bounds the distinct override values (and so rule
// sets) one policy carries; nodes per value are bounded by the platform.
const (
	maxCCAutoSwitchOverrides     = 64
	maxCCAutoSwitchOverrideNodes = 10_000
)

// normalizeCCAutoSwitchOverrides validates a system switch's overrides and
// rule sets: overrides only in system mode, each naming distinct nodes
// (no node in two), a usable value or off, and a rule group that is the
// global one or has exactly one rule set (each rule set used).
func normalizeCCAutoSwitchOverrides(value *CCAutoSwitch, create bool) error {
	if len(value.Overrides) == 0 && len(value.RuleSets) == 0 {
		value.Overrides, value.RuleSets = nil, nil
		return nil
	}
	if value.Mode != CCSettingSystem || len(value.Overrides) == 0 || len(value.Overrides) > maxCCAutoSwitchOverrides ||
		len(value.RuleSets) > maxCCAutoSwitchOverrides {
		return ErrInvalidInput
	}
	global := ""
	if len(value.RuleGroups) == 1 {
		global = value.RuleGroups[0]
	}
	sets := make(map[string]int, len(value.RuleSets))
	for index := range value.RuleSets {
		set := &value.RuleSets[index]
		if set.Group == "" || len(set.Group) > 128 || set.Group == global || len(set.Rules) == 0 {
			return ErrInvalidInput
		}
		if _, duplicate := sets[set.Group]; duplicate {
			return ErrInvalidInput
		}
		sets[set.Group] = 0
		fields := PolicyFields{Kind: KindCC, Name: "auto-switch", Enabled: true, DefaultAction: ActionAllow, Rules: set.Rules}
		if err := normalizePublishableFields(&fields, create); err != nil {
			return err
		}
		set.Rules = fields.Rules
	}
	seen := map[uuid.UUID]struct{}{}
	for index := range value.Overrides {
		override := &value.Overrides[index]
		if len(override.Nodes) == 0 || len(override.Nodes) > maxCCAutoSwitchOverrideNodes {
			return ErrInvalidInput
		}
		slices.SortFunc(override.Nodes, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
		for _, node := range override.Nodes {
			if _, duplicate := seen[node]; duplicate || node == uuid.Nil {
				return ErrInvalidInput
			}
			seen[node] = struct{}{}
		}
		if override.RuleGroup == "" {
			if override.QPSTotal != 0 || override.QPS5xx != 0 || override.RecoverSeconds != 0 {
				return ErrInvalidInput
			}
			continue
		}
		if override.QPSTotal < 0 || override.QPSTotal > ccAutoSwitchMaxQPS || override.QPS5xx < 0 ||
			override.QPS5xx > ccAutoSwitchMaxQPS || override.QPSTotal == 0 && override.QPS5xx == 0 ||
			override.RecoverSeconds < ccAutoSwitchMinRecoverSeconds || override.RecoverSeconds > ccAutoSwitchMaxRecoverSeconds {
			return ErrInvalidInput
		}
		if override.RuleGroup == global && value.Active() {
			continue
		}
		if _, ok := sets[override.RuleGroup]; !ok {
			return ErrInvalidInput
		}
		sets[override.RuleGroup]++
	}
	for _, used := range sets {
		if used == 0 {
			return ErrInvalidInput
		}
	}
	slices.SortFunc(value.Overrides, func(left, right CCAutoSwitchOverride) int {
		return bytes.Compare(left.Nodes[0][:], right.Nodes[0][:])
	})
	slices.SortFunc(value.RuleSets, func(left, right CCAutoSwitchRuleSet) int {
		switch {
		case left.Group < right.Group:
			return -1
		case left.Group > right.Group:
			return 1
		}
		return 0
	})
	return nil
}

// ccAutoSwitchRuleSetRuleID derives the ID of a rule set's rule.
func ccAutoSwitchRuleSetRuleID(policyID uuid.UUID, group string, index int) uuid.UUID {
	return uuid.NewSHA1(policyID, []byte(fmt.Sprintf("cc-auto-switch-set:%s:%d", group, index)))
}

// resolveAutoSwitchOverrides fills value's overrides and rule sets from the
// platform nodes whose auto switch differs from global (value already holds
// the global resolution). An override whose rule group cannot be expanded
// is off on its nodes.
func resolveAutoSwitchOverrides(value *CCAutoSwitch, layers AutoSwitchLayers, catalog []rulecatalog.Item) {
	index := make(map[string]rulecatalog.Item, len(catalog))
	for _, item := range catalog {
		index[item.SystemKey] = item
	}
	global := ""
	if len(value.RuleGroups) == 1 {
		global = value.RuleGroups[0]
	}
	type key struct {
		qpsTotal, qps5xx, recover int
		group                     string
	}
	grouped := map[key][]uuid.UUID{}
	order := []key{}
	sets := map[string][]Rule{}
	for _, item := range NodeAutoSwitchOverrides(layers.Global, layers.Nodes) {
		entry := key{}
		if autoSwitchUsable(item.Value) {
			if group, found := catalogRuleGroupKey(catalog, item.Value.Rule); found {
				usable := group == global && value.Active()
				if !usable {
					if _, expanded := sets[group]; expanded {
						usable = true
					} else if rules, err := ExpandCCRuleGroup(index, group); err == nil && len(rules) > 0 {
						sets[group], usable = rules, true
					}
				}
				if usable {
					entry = key{qpsTotal: clampInt(item.Value.QPSTotal, 0, ccAutoSwitchMaxQPS),
						qps5xx: clampInt(item.Value.QPS5xx, 0, ccAutoSwitchMaxQPS), recover: recoverSeconds(item.Value), group: group}
				}
			}
		}
		if entry == (key{}) && !value.Active() {
			continue // off where global is off already
		}
		if entry.group == global && value.Active() && entry.qpsTotal == value.QPSTotal && entry.qps5xx == value.QPS5xx &&
			entry.recover == value.RecoverSeconds {
			continue // same as what global resolved to
		}
		if _, known := grouped[entry]; !known {
			order = append(order, entry)
		}
		grouped[entry] = append(grouped[entry], item.NodeID)
	}
	value.Overrides, value.RuleSets = nil, nil
	used := map[string]struct{}{}
	for _, entry := range order {
		value.Overrides = append(value.Overrides, CCAutoSwitchOverride{Nodes: grouped[entry], QPSTotal: entry.qpsTotal,
			QPS5xx: entry.qps5xx, RecoverSeconds: entry.recover, RuleGroup: entry.group})
		if entry.group != "" && (entry.group != global || !value.Active()) {
			used[entry.group] = struct{}{}
		}
	}
	for group := range used {
		value.RuleSets = append(value.RuleSets, CCAutoSwitchRuleSet{Group: group, Rules: sets[group]})
	}
	if len(value.Overrides) == 0 {
		value.Overrides, value.RuleSets = nil, nil
		return
	}
	slices.SortFunc(value.Overrides, func(left, right CCAutoSwitchOverride) int {
		return bytes.Compare(left.Nodes[0][:], right.Nodes[0][:])
	})
	slices.SortFunc(value.RuleSets, func(left, right CCAutoSwitchRuleSet) int {
		switch {
		case left.Group < right.Group:
			return -1
		case left.Group > right.Group:
			return 1
		}
		return 0
	})
}
