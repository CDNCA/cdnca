package rulepack

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Official intelligence packs (ADR 0011 §6.1, RI-13).
//
//   - system/crs-tuning (engine modsecurity): CRS target exclusions merged
//     from the rule intelligence, applied to the CRS profile packs only. One
//     pack rule is one entry: its ID is the entry number (1..999999, the c3
//     u= item), its body a CRSTuning {min_paranoia, rule, targets}. Every
//     entry is exported so a level can switch one off (ADR §6.4); a site's
//     mount exclusions are the entries it disables (u=). The node renders
//     the entries once into its node rules (edgeconfig.RenderDynamicWAFRules):
//     ctl:ruleRemoveTargetById with literal targets, never a wildcard.
//   - system/autodefense-intel, system/scanner-signatures (engine waf_v2):
//     only non-terminal rules (action log, flow continue): they mark a
//     request (the rule plan's log verdict, its segment policy ID is the
//     pack label IntelPackLabel) and never decide it (Q7: cross-tenant
//     intelligence only adds to a score).

const (
	CRSTuningPackID          = "system/crs-tuning"
	AutoDefenseIntelPackID   = "system/autodefense-intel"
	ScannerSignaturesPackID  = "system/scanner-signatures"
	maxCRSTuningEntries      = edgeconfig.DynamicWAFMaxTuningEntries
	maxCRSTuningEntryTargets = edgeconfig.DynamicWAFMaxTuningTargets
)

// IsCRSTuningPack reports whether a pack ID names the CRS tuning pack.
func IsCRSTuningPack(packID string) bool { return packID == CRSTuningPackID }

// IsIntelMarkPack reports whether a pack ID names an official pack whose
// rules only mark (score, never decide).
func IsIntelMarkPack(packID string) bool {
	return packID == AutoDefenseIntelPackID || packID == ScannerSignaturesPackID
}

// IntelPackLabel is the label the node's rule plan gives a request a mark
// pack's rule matched: the pack's segment policy ID (MountRulePlan), the
// value the interpreter reports with its log verdict.
func IntelPackLabel(packID string) string { return NodeRuleID(packID, "@pack") }

var errTuning = errors.New("crs tuning")

// validateTuningEntry checks one CRS tuning entry (the pack rule ID is the
// entry number).
func validateTuningEntry(id string, tuning *edgeconfig.CRSTuning) error {
	number, err := strconv.Atoi(id)
	if err != nil || strconv.Itoa(number) != id || number < 1 || number > 999999 {
		return fmt.Errorf("%w: entry id %q must be a number 1..999999 without leading zeros", errTuning, id)
	}
	if tuning == nil {
		return fmt.Errorf("%w: entry %s needs a tuning body", errTuning, id)
	}
	return edgeconfig.ValidateCRSTuning(*tuning)
}

// checkTuningPack checks the pack-level shape of system/crs-tuning (rules
// already normalized): system layer, no parameters besides exclusions,
// every entry exported, at most maxCRSTuningEntries entries.
func checkTuningPack(pack Pack) error {
	if pack.Layer != LayerSystem || pack.Engine != EngineModSecurity {
		return fmt.Errorf("%w: %s must be a system modsecurity pack", errTuning, pack.PackID)
	}
	if len(pack.ParamsSchema) != 0 {
		return fmt.Errorf("%w: %s takes no parameters", errTuning, pack.PackID)
	}
	if len(pack.Rules) > maxCRSTuningEntries {
		return fmt.Errorf("%w: %d entries (at most %d)", errTuning, len(pack.Rules), maxCRSTuningEntries)
	}
	ids := make([]string, 0, len(pack.Rules))
	for _, rule := range pack.Rules {
		ids = append(ids, rule.ID)
	}
	if !slices.Equal(sortUnique(ids), pack.Exports) {
		return fmt.Errorf("%w: every entry must be exported (and nothing else)", errTuning)
	}
	return nil
}

// checkIntelMarkRule: a mark pack rule only marks (log, continue).
func checkIntelMarkRule(rule Rule) error {
	if rule.WAF == nil || rule.WAF.Action != edgeconfig.WAFLog || rule.WAF.Control != edgeconfig.WAFContinue ||
		rule.WAF.ActionConfig != nil {
		return fmt.Errorf("rule %s: an intelligence pack rule only marks (action log, flow continue)", rule.ID)
	}
	return nil
}

// TuningOf is a site's CRS tuning from its mounts (Resolve allows at most
// one tuning pack): the entries of the pack (all of them, the node renders
// every entry) and the entries the site disables, as the c3 u= list.
// mounted is false without a tuning mount: the site then disables the whole
// pack (edgeconfig.DynamicWAFTuningAllOff). A sealed pack needs its rules
// (opened on the node, rulepack.Open); its manifest alone is refused.
func TuningOf(mounts []Mount, packs map[string]*CompiledPack) (entries []edgeconfig.CRSTuningEntry, disabled []int,
	mounted bool, err error) {
	for _, mount := range mounts {
		if !IsCRSTuningPack(mount.PackID) {
			continue
		}
		pack := packs[mount.SHA256]
		if pack == nil || pack.Pack.PackID != mount.PackID {
			return nil, nil, true, fmt.Errorf("%w: tuning pack %s is not readable here", ErrInvalidPack, mount.PackID)
		}
		entries, err = TuningEntries(pack)
		if err != nil {
			return nil, nil, true, err
		}
		params, err := parseParams(pack.Pack, mount.Params)
		if err != nil {
			return nil, nil, true, err
		}
		for _, id := range params.excluded {
			number, _ := strconv.Atoi(id)
			disabled = append(disabled, number)
		}
		slices.Sort(disabled)
		if len(disabled) > edgeconfig.DynamicWAFMaxTuningOff {
			return nil, nil, true, fmt.Errorf("%w: %d tuning entries disabled on one site (at most %d)", ErrInvalidPack,
				len(disabled), edgeconfig.DynamicWAFMaxTuningOff)
		}
		return entries, disabled, true, nil
	}
	return nil, nil, false, nil
}

// TuningEntries is the tuning pack's entries in entry number order (the
// node renders them; edgeconfig.RenderDynamicWAFRules).
func TuningEntries(pack *CompiledPack) ([]edgeconfig.CRSTuningEntry, error) {
	if pack == nil || !IsCRSTuningPack(pack.Pack.PackID) || len(pack.Pack.Rules) == 0 {
		return nil, fmt.Errorf("%w: not a readable CRS tuning pack (a sealed one must be opened)", ErrInvalidPack)
	}
	entries := make([]edgeconfig.CRSTuningEntry, 0, len(pack.Pack.Rules))
	for _, rule := range pack.Pack.Rules {
		number, _ := strconv.Atoi(rule.ID)
		entries = append(entries, edgeconfig.CRSTuningEntry{ID: number, CRSTuning: copyTuning(*rule.Tuning)})
	}
	slices.SortFunc(entries, func(a, b edgeconfig.CRSTuningEntry) int { return a.ID - b.ID })
	return entries, nil
}

func copyTuning(tuning edgeconfig.CRSTuning) edgeconfig.CRSTuning {
	out := tuning
	out.Targets = cloneSlice(tuning.Targets)
	return out
}

// checkTuningRules is the publisher's check of a tuning pack against the CRS
// rule text (CheckPublishable): every entry names a CRS scoring rule the
// text has, so the node never renders a ctl for a rule it does not load.
func checkTuningRules(pack Pack, crs *edgeconfig.CRSManifest) error {
	if crs == nil {
		return fmt.Errorf("%w: no CRS rule text to check the tuning entries", ErrInvalidPack)
	}
	known := make(map[int]bool, len(crs.Rules))
	for _, rule := range crs.Rules {
		known[rule.ID] = true
	}
	for _, rule := range pack.Rules {
		if !known[rule.Tuning.Rule] {
			return fmt.Errorf("%w: tuning entry %s names rule %d, not in CRS %s", ErrInvalidPack, rule.ID, rule.Tuning.Rule, crs.Version)
		}
	}
	return nil
}
