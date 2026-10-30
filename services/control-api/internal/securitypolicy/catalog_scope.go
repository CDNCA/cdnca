package securitypolicy

import (
	"context"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
)

// ccProofOfWorkAPIVersion is the CC API version of verification pages (proof
// of work, page lifetime, bound and rotated pass; edgepublish.ccProofOfWorkAPIVersion).
const ccProofOfWorkAPIVersion uint32 = 3

// CatalogRuleSet is CatalogRules with, for CC, the rules several groups
// contributed twice or with another action.
type CatalogRuleSet struct {
	Rules []Rule `json:"rules"`
	// Duplicates / Conflicts (CC, several groups): rules dropped because an
	// earlier group has them, and same-match rules with another action.
	Duplicates []CatalogDuplicate `json:"duplicates,omitempty"`
	Conflicts  []CatalogConflict  `json:"conflicts,omitempty"`
	// Default (WAF, key SystemDefaultWAFKey): the system default WAF's master
	// switch and policy settings (auto block) that go with Rules.
	Default *DefaultWAFPolicy `json:"default,omitempty"`
}

// CatalogRulesForScope is CatalogRules for a policy of scopeID. A node of the
// scope that does not run verification pages (CC v3) gets the publication
// refused (edgepublish node_capability_unavailable), not a weaker challenge.
func (s *Service) CatalogRulesForScope(ctx context.Context, actor Actor, scopeID uuid.UUID, kind string, keys []string) (CatalogRuleSet, error) {
	if kind == KindWAF && len(keys) == 1 && keys[0] == SystemDefaultWAFKey {
		value, err := s.CatalogDefaultWAF(ctx)
		if err != nil {
			return CatalogRuleSet{}, err
		}
		return CatalogRuleSet{Rules: value.Rules, Default: &value}, nil
	}
	if kind != KindCC {
		rules, err := s.CatalogRules(ctx, kind, keys)
		return CatalogRuleSet{Rules: rules}, err
	}
	if actor.ScopeKind != "platform" && scopeID != actor.ScopeID {
		return CatalogRuleSet{}, ErrPermissionDenied
	}
	if len(keys) < 1 || len(keys) > MaxCCRuleGroups {
		return CatalogRuleSet{}, ErrInvalidInput
	}
	items, err := s.store.SystemCatalog(ctx)
	if err != nil {
		return CatalogRuleSet{}, err
	}
	index := make(map[string]rulecatalog.Item, len(items))
	for _, item := range items {
		index[item.SystemKey] = item
	}
	merged, err := ExpandCCRuleGroups(index, keys)
	if err != nil {
		return CatalogRuleSet{}, ErrInvalidInput
	}
	return CatalogRuleSet{Rules: merged.Rules, Duplicates: merged.Duplicates, Conflicts: merged.Conflicts}, nil
}

// PolicyNeedsProofOfWork reports whether a CC policy has an enabled challenge
// rule: every verification page needs CC v3 agents.
func PolicyNeedsProofOfWork(policy Policy) bool {
	if policy.Kind != KindCC {
		return false
	}
	for _, rule := range policy.Rules {
		if rule.Enabled && rule.Action == ActionChallenge && rule.ActionConfig.Challenge != nil {
			return true
		}
	}
	return false
}
