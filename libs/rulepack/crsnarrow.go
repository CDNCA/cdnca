package rulepack

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// modsecurity rule packs on a site (方案 A): the node runs CRS
// node-wide by profile tier (dynwaf), so a pack can only narrow the site's
// own CRS profile. Its rule sets must be sets of that profile with the same
// action and threshold and at most its paranoia, evaluating only rules the
// profile evaluates; every rule the profile evaluates and the pack does not
// (a set the pack leaves out included) becomes a site exclusion, applied per
// request like the site's own (ManagedWAF.Exclusions). Anything else is out
// of the profile and refused at publication; the shared CRS configuration is
// never changed for a pack.

// ConflictCRSOutOfProfile: a modsecurity pack selects CRS rules, settings or
// sets beyond the site's CRS profile (or the site runs no managed WAF).
const ConflictCRSOutOfProfile = "crs_out_of_profile"

// ErrOutOfProfile wraps every reason NarrowCRSProfile refuses a pack.
var ErrOutOfProfile = errors.New("modsecurity rule pack is outside the site's CRS profile")

// ModSecurityRules instantiates one modsecurity mount (its params applied:
// excluded IDs join each set's exclusions). A sealed pack has no readable
// rules here and cannot be checked against a profile: it is out of profile.
func ModSecurityRules(mount Mount, pack *CompiledPack) ([]NodeRule, error) {
	if pack == nil || mount.Engine != EngineModSecurity || pack.SHA256 != mount.SHA256 || pack.Pack.Engine != EngineModSecurity {
		return nil, fmt.Errorf("%w: mount %s does not match its pack", ErrInvalidPack, mount.PackID)
	}
	if pack.Sealed {
		return nil, fmt.Errorf("%w: sealed pack %s cannot be checked against the profile", ErrOutOfProfile, mount.PackID)
	}
	return program([]Mount{mount}, map[string]*CompiledPack{mount.SHA256: pack}, false)
}

// SiteCRSExclusions applies a site's modsecurity mount (Resolve allows at
// most one) to its managed WAF: ok is false without one (exclusions are then
// siteExclusions unchanged). profile is the site's CRS profile, nil when the
// site runs no managed WAF (a modsecurity mount is then out of profile).
func SiteCRSExclusions(mounts []Mount, packs map[string]*CompiledPack, manifest *edgeconfig.CRSManifest,
	profile *edgeconfig.CRSProfile, siteExclusions []int) (exclusions []int, ok bool, err error) {
	for _, mount := range mounts {
		if mount.Engine != EngineModSecurity || IsCRSTuningPack(mount.PackID) {
			continue // the tuning pack selects no CRS rule (TuningOf)
		}
		if ok {
			return nil, true, fmt.Errorf("%w: only one modsecurity pack can run on a site", ErrOutOfProfile)
		}
		ok = true
		if profile == nil {
			return nil, true, fmt.Errorf("%w: pack %s needs the site to run a managed WAF (CRS profile)", ErrOutOfProfile, mount.PackID)
		}
		pack := packs[mount.SHA256]
		if pack != nil && pack.Sealed {
			// The control plane only has the manifest: its crs_rule_ids or nothing.
			runs, listed, err := MountCRSRuns(mount, pack)
			if err != nil {
				return nil, true, err
			}
			if !listed {
				return nil, true, fmt.Errorf("%w: sealed pack %s lists no CRS rule IDs and cannot be checked against the profile",
					ErrOutOfProfile, mount.PackID)
			}
			if exclusions, err = NarrowCRSProfileByIDs(manifest, *profile, siteExclusions, mount.PackID, runs); err != nil {
				return nil, true, err
			}
			continue
		}
		rules, err := ModSecurityRules(mount, pack)
		if err != nil {
			return nil, true, err
		}
		if exclusions, err = NarrowCRSProfile(manifest, *profile, siteExclusions, rules); err != nil {
			return nil, true, err
		}
	}
	if !ok {
		return siteExclusions, false, nil
	}
	return exclusions, true, nil
}

// CheckCRSProfile refuses a resolution whose modsecurity mount is outside
// the site's CRS profile (SiteCRSExclusions): a crs_out_of_profile conflict
// naming the pack with its "disable" remedies, and no Security.
func CheckCRSProfile(resolution Resolution, requests []MountRequest, manifest *edgeconfig.CRSManifest,
	profile *edgeconfig.CRSProfile, siteExclusions []int) Resolution {
	if resolution.Security == nil {
		return resolution
	}
	packs := map[string]*CompiledPack{}
	for _, request := range requests {
		if request.Pack != nil {
			packs[request.Pack.SHA256] = request.Pack
		}
	}
	_, _, err := SiteCRSExclusions(resolution.Security.Mounts, packs, manifest, profile, siteExclusions)
	if err == nil {
		return resolution
	}
	var sides []MountRequest
	for _, request := range requests {
		if request.Pack != nil && request.Pack.Pack.Engine == EngineModSecurity && !IsCRSTuningPack(request.Pack.Pack.PackID) {
			sides = append(sides, request)
		}
	}
	resolution.Conflicts = append(resolution.Conflicts, conflictOf(ConflictCRSOutOfProfile, err.Error(), sides, ""))
	resolution.Security = nil
	return resolution
}

// NarrowCRSProfile returns the site's exclusions with a modsecurity pack's
// rules (ModSecurityRules) mounted on its CRS profile: siteExclusions plus
// every rule the profile evaluates that the pack does not, sorted and
// distinct. Each pack rule is one set, ID = the profile set key without
// "waf_set:".
func NarrowCRSProfile(manifest *edgeconfig.CRSManifest, profile edgeconfig.CRSProfile, siteExclusions []int,
	rules []NodeRule) ([]int, error) {
	if manifest == nil {
		return nil, fmt.Errorf("%w: no CRS rule text", ErrOutOfProfile)
	}
	sets := make(map[string]edgeconfig.ManagedWAFSet, len(profile.Sets))
	for _, set := range profile.Sets {
		sets[set.Key] = set
	}
	excluded := map[int]bool{}
	for _, id := range siteExclusions {
		excluded[id] = true
	}
	covered := map[string]bool{}
	for _, rule := range rules {
		if rule.CRS == nil {
			return nil, fmt.Errorf("%w: pack %s rule %s has no CRS set", ErrOutOfProfile, rule.PackID, rule.RuleID)
		}
		key := "waf_set:" + rule.RuleID
		set, ok := sets[key]
		switch {
		case !ok:
			return nil, fmt.Errorf("%w: profile %s has no rule set %s", ErrOutOfProfile, profile.Ref.PackID, key)
		case covered[key]:
			return nil, fmt.Errorf("%w: rule set %s is selected twice", ErrOutOfProfile, key)
		case rule.CRS.Action != set.Action || rule.CRS.Threshold != set.Threshold:
			return nil, fmt.Errorf("%w: rule set %s action/threshold %s/%d differ from the profile's %s/%d", ErrOutOfProfile,
				key, rule.CRS.Action, rule.CRS.Threshold, set.Action, set.Threshold)
		case rule.CRS.Paranoia > set.Paranoia:
			return nil, fmt.Errorf("%w: rule set %s paranoia %d is above the profile's %d", ErrOutOfProfile,
				key, rule.CRS.Paranoia, set.Paranoia)
		}
		covered[key] = true
		packSet := edgeconfig.ManagedWAFSet{Key: key, Paranoia: rule.CRS.Paranoia, Files: rule.CRS.Files,
			IncludeIDs: rule.CRS.IncludeIDs, ExcludeIDs: rule.CRS.ExcludeIDs}
		runs := map[int]bool{}
		for _, id := range crsTierSet(manifest, packSet).Rules {
			runs[id] = true
		}
		profileRules := crsTierSet(manifest, set).Rules
		for id := range runs {
			if _, found := slices.BinarySearch(profileRules, id); !found {
				return nil, fmt.Errorf("%w: rule %d of set %s is not evaluated by profile %s", ErrOutOfProfile,
					id, key, profile.Ref.PackID)
			}
		}
		for _, id := range profileRules {
			if !runs[id] {
				excluded[id] = true
			}
		}
	}
	for _, set := range profile.Sets {
		if !covered[set.Key] {
			for _, id := range crsTierSet(manifest, set).Rules {
				excluded[id] = true
			}
		}
	}
	return checkedExclusions(profile, excluded)
}

// Sealed modsecurity packs (the list is
// never the seller's): the control plane cannot read their rules, only the
// manifest's crs_rule_ids, which the license service computed from the
// plaintext when it sealed the copy (Seal) and signs by digest. Such a
// mount narrows the site's profile by those numbers alone: every rule the
// pack evaluates (the list minus the mount's excluded exports) must be a rule
// the profile evaluates, and every profile rule outside it becomes a site
// exclusion. The node, which opens the pack, checks the rules evaluate
// exactly the list (CheckCRSRuleIDs) before it applies the site.

// ErrCRSRuleIDsMismatch: an opened modsecurity pack's rules do not evaluate
// the CRS rule IDs its manifest lists.
var ErrCRSRuleIDsMismatch = errors.New("modsecurity rule pack rules do not match its listed CRS rule IDs")

// MountCRSRuns is the CRS rule IDs a modsecurity mount evaluates according
// to its sealed pack's crs_rule_ids (ok false without a list): the list minus
// the mount's exclusions parameter.
func MountCRSRuns(mount Mount, pack *CompiledPack) (runs []int, ok bool, err error) {
	if pack == nil || len(pack.CRSRuleIDs) == 0 {
		return nil, false, nil
	}
	var excluded []string
	if raw := mount.Params[ParamExclusions]; raw != nil {
		if err := json.Unmarshal(raw, &excluded); err != nil {
			return nil, true, fmt.Errorf("%w: exclusions", ErrInvalidPack)
		}
	}
	off := map[int]bool{}
	for _, id := range excluded {
		number, err := strconv.Atoi(id)
		if err != nil {
			return nil, true, fmt.Errorf("%w: exclusion %q", ErrInvalidPack, id)
		}
		off[number] = true
	}
	for _, id := range pack.CRSRuleIDs {
		if !off[id] {
			runs = append(runs, id)
		}
	}
	return runs, true, nil
}

// NarrowCRSProfileByIDs is NarrowCRSProfile for a pack known by the CRS rule
// IDs it evaluates (runs, sorted).
func NarrowCRSProfileByIDs(manifest *edgeconfig.CRSManifest, profile edgeconfig.CRSProfile, siteExclusions []int,
	packID string, runs []int) ([]int, error) {
	if manifest == nil {
		return nil, fmt.Errorf("%w: no CRS rule text", ErrOutOfProfile)
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("%w: pack %s evaluates no CRS rule", ErrOutOfProfile, packID)
	}
	evaluated := map[int]bool{}
	for _, set := range profile.Sets {
		for _, id := range crsTierSet(manifest, set).Rules {
			evaluated[id] = true
		}
	}
	running := map[int]bool{}
	for _, id := range runs {
		if !evaluated[id] {
			return nil, fmt.Errorf("%w: rule %d of pack %s is not evaluated by profile %s", ErrOutOfProfile,
				id, packID, profile.Ref.PackID)
		}
		running[id] = true
	}
	excluded := map[int]bool{}
	for _, id := range siteExclusions {
		excluded[id] = true
	}
	for id := range evaluated {
		if !running[id] {
			excluded[id] = true
		}
	}
	return checkedExclusions(profile, excluded)
}

// checkedExclusions sorts excluded and requires each to be an export of the
// profile, within MaxManagedWAFExclusions.
func checkedExclusions(profile edgeconfig.CRSProfile, excluded map[int]bool) ([]int, error) {
	result := make([]int, 0, len(excluded))
	for id := range excluded {
		if _, found := slices.BinarySearch(profile.Exports, id); !found {
			return nil, fmt.Errorf("%w: rule %d cannot be excluded from profile %s", ErrOutOfProfile, id, profile.Ref.PackID)
		}
		result = append(result, id)
	}
	sort.Ints(result)
	if len(result) > edgeconfig.MaxManagedWAFExclusions {
		return nil, fmt.Errorf("%w: %d exclusions exceed %d", ErrOutOfProfile, len(result), edgeconfig.MaxManagedWAFExclusions)
	}
	return result, nil
}

// CRSRuns is the CRS rule IDs a modsecurity pack's instantiated rules
// evaluate (sorted, distinct).
func CRSRuns(manifest *edgeconfig.CRSManifest, rules []NodeRule) []int {
	seen := map[int]bool{}
	for _, rule := range rules {
		if rule.CRS == nil {
			continue
		}
		set := edgeconfig.ManagedWAFSet{Paranoia: rule.CRS.Paranoia, Files: rule.CRS.Files,
			IncludeIDs: rule.CRS.IncludeIDs, ExcludeIDs: rule.CRS.ExcludeIDs}
		for _, id := range crsTierSet(manifest, set).Rules {
			seen[id] = true
		}
	}
	out := make([]int, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

// CheckCRSRuleIDs is the node's check of an opened sealed modsecurity
// mount: its instantiated rules (the mount's params applied) evaluate
// exactly MountCRSRuns. A sealed pack without the list is refused (no
// license service computed it); a plaintext pack has none and is not
// checked here (the node narrows the profile by its rules).
func CheckCRSRuleIDs(manifest *edgeconfig.CRSManifest, mount Mount, pack *CompiledPack, rules []NodeRule) error {
	declared, listed, err := MountCRSRuns(mount, pack)
	if err != nil {
		return err
	}
	if !listed {
		if pack != nil && pack.Sealed {
			return fmt.Errorf("%w: sealed pack %s carries no CRS rule ID list", ErrCRSRuleIDsMismatch, mount.PackID)
		}
		return nil
	}
	if manifest == nil {
		return fmt.Errorf("%w: no CRS rule text", ErrCRSRuleIDsMismatch)
	}
	actual := CRSRuns(manifest, rules)
	if !slices.Equal(actual, declared) {
		return fmt.Errorf("%w: pack %s lists %d rules, its rules evaluate %d (first difference %s)", ErrCRSRuleIDsMismatch,
			mount.PackID, len(declared), len(actual), firstDifference(declared, actual))
	}
	return nil
}

func firstDifference(left, right []int) string {
	for index := 0; index < len(left) || index < len(right); index++ {
		switch {
		case index >= len(left):
			return fmt.Sprintf("unlisted %d", right[index])
		case index >= len(right) || left[index] < right[index]:
			return fmt.Sprintf("listed %d not evaluated", left[index])
		case left[index] > right[index]:
			return fmt.Sprintf("unlisted %d", right[index])
		}
	}
	return "none"
}

// PackCRSRuleIDs is the CRS rule IDs a modsecurity pack's rule sets
// evaluate (the exclusions parameter not applied): what the sealer writes
// into the manifest.
func PackCRSRuleIDs(manifest *edgeconfig.CRSManifest, pack Pack) []int {
	rules := make([]NodeRule, 0, len(pack.Rules))
	for _, rule := range pack.Rules {
		rules = append(rules, NodeRule{CRS: rule.CRS})
	}
	return CRSRuns(manifest, rules)
}

// ComputeCRSRuleIDs is PackCRSRuleIDs as the publisher (license service when
// it seals, market review) computes it: a modsecurity pack with a CRS rule
// text, evaluating at least one and at most MaxCRSRuleIDs rules. Failing
// refuses the pack (ErrInvalidPack).
func ComputeCRSRuleIDs(manifest *edgeconfig.CRSManifest, pack Pack) ([]int, error) {
	if pack.Engine != EngineModSecurity {
		return nil, fmt.Errorf("%w: only modsecurity packs have CRS rule IDs", ErrInvalidPack)
	}
	if manifest == nil {
		return nil, fmt.Errorf("%w: no CRS rule text to compute the CRS rule IDs", ErrInvalidPack)
	}
	ids := PackCRSRuleIDs(manifest, pack)
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: pack %s evaluates no CRS rule", ErrInvalidPack, pack.PackID)
	}
	if err := validCRSRuleIDs(pack.Engine, ids); err != nil {
		return nil, fmt.Errorf("%w: CRS rule IDs: %v", ErrInvalidPack, err)
	}
	return ids, nil
}
