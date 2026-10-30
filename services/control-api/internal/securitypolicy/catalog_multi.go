package securitypolicy

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

// MaxCCRuleGroups is how many system CC rule groups one import may combine
// (v6.1.0 #16).
const MaxCCRuleGroups = 8

// CatalogDuplicate is a rule a later group contributed that an earlier chosen
// group already has (same conditions, counting keys, action and settings);
// it is dropped.
type CatalogDuplicate struct {
	GroupKey string `json:"group_key"`
	Rule     string `json:"rule"`
	SameAs   string `json:"same_as"`
}

// CatalogConflict is a rule with the same conditions and counting keys as one
// of an earlier group but another action or limit; both are kept and the
// earlier group's rule runs first.
type CatalogConflict struct {
	GroupKey string `json:"group_key"`
	Rule     string `json:"rule"`
	With     string `json:"with"`
}

// CCRuleGroupMerge is several system CC rule groups expanded in the chosen
// order: priority is group order × 1000 + position in the group (a dropped
// duplicate leaves its position unused).
type CCRuleGroupMerge struct {
	Rules      []Rule             `json:"rules"`
	Duplicates []CatalogDuplicate `json:"duplicates"`
	Conflicts  []CatalogConflict  `json:"conflicts"`
}

// ExpandCCRuleGroups expands 1..MaxCCRuleGroups distinct CC rule groups
// (ExpandCCRuleGroup) and merges them (mergeCCRuleGroups).
func ExpandCCRuleGroups(items map[string]rulecatalog.Item, keys []string) (CCRuleGroupMerge, error) {
	if len(keys) < 1 || len(keys) > MaxCCRuleGroups {
		return CCRuleGroupMerge{}, ErrInvalidInput
	}
	groups := make([][]Rule, len(keys))
	for index, key := range keys {
		if slices.Contains(keys[:index], key) {
			return CCRuleGroupMerge{}, fmt.Errorf("%w: %s chosen twice", ErrInvalidInput, key)
		}
		rules, err := ExpandCCRuleGroup(items, key)
		if err != nil {
			return CCRuleGroupMerge{}, err
		}
		groups[index] = rules
	}
	return mergeCCRuleGroups(keys, groups), nil
}

func mergeCCRuleGroups(keys []string, groups [][]Rule) CCRuleGroupMerge {
	result := CCRuleGroupMerge{Rules: []Rule{}, Duplicates: []CatalogDuplicate{}, Conflicts: []CatalogConflict{}}
	type origin struct{ group, rule string }
	full, match := map[string]origin{}, map[string]origin{}
	for groupIndex, rules := range groups {
		for position, rule := range rules {
			matchKey, _ := json.Marshal(struct {
				Conditions []Condition `json:"conditions"`
				CountBy    []CountKey  `json:"count_by"`
			}{rule.Conditions, rule.CountBy})
			fullKey, _ := json.Marshal(struct {
				Match        string       `json:"match"`
				Action       string       `json:"action"`
				Flow         string       `json:"flow"`
				ActionConfig ActionConfig `json:"action_config"`
				ActionTarget string       `json:"action_target"`
			}{string(matchKey), rule.Action, rule.Flow, rule.ActionConfig, rule.ActionTarget})
			if previous, seen := full[string(fullKey)]; seen {
				result.Duplicates = append(result.Duplicates, CatalogDuplicate{GroupKey: keys[groupIndex], Rule: rule.Name, SameAs: previous.group})
				continue
			}
			if previous, seen := match[string(matchKey)]; seen && previous.group != keys[groupIndex] {
				result.Conflicts = append(result.Conflicts, CatalogConflict{GroupKey: keys[groupIndex], Rule: rule.Name, With: previous.group})
			}
			full[string(fullKey)] = origin{keys[groupIndex], rule.Name}
			if _, seen := match[string(matchKey)]; !seen {
				match[string(matchKey)] = origin{keys[groupIndex], rule.Name}
			}
			rule.Priority = (groupIndex+1)*1000 + position + 1
			result.Rules = append(result.Rules, rule)
		}
	}
	return result
}
