package rulepack

import (
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// WAF protection tiers: the CRS profile packs
// ordered from the narrowest to the widest judgement scope, each with its
// attack classes (rule sets), the scoring rules they evaluate and what it adds
// to the previous tier. Everything is counted from the CRS rule text (the
// manifest's paranoia-level tags), never written by hand.

// CRSTier is one profile pack as a protection tier.
type CRSTier struct {
	PackID string `json:"pack_id"`
	Name   string `json:"name"`
	// Order is the tier's position, narrowest first (0..).
	Order    int    `json:"order"`
	Action   string `json:"action"`
	Paranoia int    `json:"paranoia"`
	// Sets are the tier's attack classes in catalog order (Key = waf_set:<id>).
	Sets []CRSTierSet `json:"sets"`
	// Previous is the pack ID of the next narrower tier ("" for the first).
	Previous string `json:"previous"`
	// Added is what this tier adds to Previous: new classes, rules of higher
	// paranoia levels, or blocking where the previous tier only records.
	Added []CRSTierAddition `json:"added"`
}

// CRSTierSet is one attack class of a tier.
type CRSTierSet struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Paranoia int    `json:"paranoia"`
	// RulesByParanoia counts the class's scoring rules the tier evaluates per
	// paranoia level ("1".."4").
	RulesByParanoia map[string]int `json:"rules_by_paranoia"`
	// Rules are those rule IDs (sorted): excluding all of them turns the
	// class off for a policy or site.
	Rules []int `json:"rules"`
}

// CRSTierAddition is one item a tier adds. Kind "set": a class the previous
// tier lacks (Rules = its rules); "paranoia": higher-level rules of a class
// both have (FromParanoia exclusive .. ToParanoia inclusive; listed only when
// the class gains rules); "block": the
// previous tier records the same scope without blocking.
type CRSTierAddition struct {
	Kind         string `json:"kind"`
	Key          string `json:"key,omitempty"`
	Name         string `json:"name,omitempty"`
	FromParanoia int    `json:"from_paranoia,omitempty"`
	ToParanoia   int    `json:"to_paranoia,omitempty"`
	Rules        int    `json:"rules"`
}

// crsSetMembers is a set's scoring rules (Files prefixes + IncludeIDs -
// ExcludeIDs), the membership edgeconfig resolves.
func crsSetMembers(manifest *edgeconfig.CRSManifest, set edgeconfig.ManagedWAFSet) []edgeconfig.CRSRule {
	excluded := map[int]bool{}
	for _, id := range set.ExcludeIDs {
		excluded[id] = true
	}
	included := map[int]bool{}
	for _, id := range set.IncludeIDs {
		included[id] = true
	}
	members := []edgeconfig.CRSRule{}
	for _, rule := range manifest.Rules {
		member := included[rule.ID]
		for _, file := range set.Files {
			member = member || strings.HasPrefix(rule.File, file+"-")
		}
		if member && !excluded[rule.ID] {
			members = append(members, rule)
		}
	}
	return members
}

func crsTierSet(manifest *edgeconfig.CRSManifest, set edgeconfig.ManagedWAFSet) CRSTierSet {
	result := CRSTierSet{Key: set.Key, Name: set.Name, Paranoia: set.Paranoia, RulesByParanoia: map[string]int{}, Rules: []int{}}
	for _, rule := range crsSetMembers(manifest, set) {
		if rule.Paranoia <= set.Paranoia {
			result.RulesByParanoia[string(rune('0'+rule.Paranoia))]++
			result.Rules = append(result.Rules, rule.ID)
		}
	}
	sort.Ints(result.Rules)
	return result
}

// CRSTiers orders the profiles into tiers (fewer classes first, then lower
// paranoia, then record-only before blocking) and derives each tier's
// classes and additions from the manifest.
func CRSTiers(manifest *edgeconfig.CRSManifest, profiles []edgeconfig.CRSProfile, setOrder []string) []CRSTier {
	rank := map[string]int{}
	for index, key := range setOrder {
		rank[key] = index
	}
	tiers := make([]CRSTier, 0, len(profiles))
	for _, profile := range profiles {
		tier := CRSTier{PackID: profile.Ref.PackID, Name: profile.Name, Action: edgeconfig.ManagedWAFActionLog, Sets: []CRSTierSet{},
			Added: []CRSTierAddition{}}
		for _, set := range profile.Sets {
			tier.Sets = append(tier.Sets, crsTierSet(manifest, set))
			tier.Paranoia = max(tier.Paranoia, set.Paranoia)
			if set.Action == edgeconfig.ManagedWAFActionBlock {
				tier.Action = edgeconfig.ManagedWAFActionBlock
			}
		}
		sort.SliceStable(tier.Sets, func(i, j int) bool {
			left, okLeft := rank[tier.Sets[i].Key]
			right, okRight := rank[tier.Sets[j].Key]
			if okLeft != okRight {
				return okLeft
			}
			if left != right {
				return left < right
			}
			return tier.Sets[i].Key < tier.Sets[j].Key
		})
		tiers = append(tiers, tier)
	}
	sort.SliceStable(tiers, func(i, j int) bool {
		left, right := tiers[i], tiers[j]
		switch {
		case len(left.Sets) != len(right.Sets):
			return len(left.Sets) < len(right.Sets)
		case left.Paranoia != right.Paranoia:
			return left.Paranoia < right.Paranoia
		case left.Action != right.Action:
			return left.Action == edgeconfig.ManagedWAFActionLog
		}
		return left.PackID < right.PackID
	})
	for index := range tiers {
		tiers[index].Order = index
	}
	for index := 1; index < len(tiers); index++ {
		previous := map[string]CRSTierSet{}
		for _, set := range tiers[index-1].Sets {
			previous[set.Key] = set
		}
		tier := &tiers[index]
		tier.Previous = tiers[index-1].PackID
		if tiers[index-1].Action == edgeconfig.ManagedWAFActionLog && tier.Action == edgeconfig.ManagedWAFActionBlock {
			rules := 0
			for _, set := range tier.Sets {
				if _, both := previous[set.Key]; both {
					rules += len(previous[set.Key].Rules)
				}
			}
			tier.Added = append(tier.Added, CRSTierAddition{Kind: "block", Rules: rules})
		}
		for _, set := range tier.Sets {
			before, both := previous[set.Key]
			switch {
			case !both:
				tier.Added = append(tier.Added, CRSTierAddition{Kind: "set", Key: set.Key, Name: set.Name, Rules: len(set.Rules)})
			case set.Paranoia > before.Paranoia && len(set.Rules) > len(before.Rules):
				tier.Added = append(tier.Added, CRSTierAddition{Kind: "paranoia", Key: set.Key, Name: set.Name,
					FromParanoia: before.Paranoia, ToParanoia: set.Paranoia, Rules: len(set.Rules) - len(before.Rules)})
			}
		}
	}
	return tiers
}
