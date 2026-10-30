package rulepack

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

// CRS profile packs (PA-12, ADR 0007 §5.3): system/crs-<level> modsecurity
// packs. Each rule is one CRS rule set (its body a rulecatalog.WAFEngineSet:
// files, include/exclude IDs, action, paranoia, threshold) whose rule ID
// names the set key (waf_set:<rule id>); exports are the CRS scoring rule
// IDs a site may exclude. The node loads the pack's sets node-wide; a site
// only selects the profile and lists exclusions, which the request applies
// with ctl:ruleRemoveById (edgeconfig.ManagedWAF).

var crsProfilePackID = regexp.MustCompile(`^system/crs-[a-z0-9][a-z0-9-]{0,59}$`)

// IsCRSProfilePack reports whether a pack ID names a CRS profile pack.
// system/crs-tuning（RI-13 官方调优包）也落在 crs-* 命名里，但不是档位包。
func IsCRSProfilePack(packID string) bool {
	return crsProfilePackID.MatchString(packID) && !IsCRSTuningPack(packID)
}

// CRSProfileOf turns a compiled CRS profile pack into the profile the node
// compiler uses. It checks the pack's own shape (system layer, modsecurity
// engine, no parameters besides exclusions, set rules); whether its sets and
// exports match a CRS rule text is the compiler's check
// (edgeconfig.ResolveCRSProfile, Build, RenderListenerRuntimeSecurity).
func CRSProfileOf(compiled *CompiledPack) (edgeconfig.CRSProfile, error) {
	if compiled == nil {
		return edgeconfig.CRSProfile{}, fmt.Errorf("%w: no pack", ErrInvalidPack)
	}
	pack := compiled.Pack
	if pack.Layer != LayerSystem || pack.Engine != EngineModSecurity || !IsCRSProfilePack(pack.PackID) ||
		len(pack.ParamsSchema) != 0 || string(pack.Defaults[ParamExclusions]) != "[]" || len(pack.Defaults) != 1 {
		return edgeconfig.CRSProfile{}, fmt.Errorf("%w: %s is not a CRS profile pack", ErrInvalidPack, pack.PackID)
	}
	profile := edgeconfig.CRSProfile{
		Ref:  edgeconfig.CRSProfileRef{PackID: pack.PackID, Version: pack.Version, SHA256: compiled.SHA256},
		Name: pack.Name, Sets: make([]edgeconfig.ManagedWAFSet, 0, len(pack.Rules)),
		Exports: make([]int, 0, len(pack.Exports)),
	}
	for _, rule := range pack.Rules {
		crs := rule.CRS
		profile.Sets = append(profile.Sets, edgeconfig.ManagedWAFSet{Key: "waf_set:" + rule.ID, Name: rule.Name,
			Action: crs.Action, Paranoia: crs.Paranoia, Threshold: crs.Threshold, StrongParanoia: crs.StrongParanoia,
			WeakThreshold: crs.WeakThreshold, GreyAction: crs.GreyAction, Adaptive: crs.Adaptive,
			StrongRules: cloneSlice(crs.StrongRules), WeakWeights: weakWeights(crs.WeakWeights), Files: cloneSlice(crs.Files),
			IncludeIDs: cloneSlice(crs.IncludeIDs), ExcludeIDs: cloneSlice(crs.ExcludeIDs)})
	}
	for _, id := range pack.Exports {
		number, err := strconv.Atoi(id)
		if err != nil {
			return edgeconfig.CRSProfile{}, fmt.Errorf("%w: export %q", ErrInvalidPack, id)
		}
		profile.Exports = append(profile.Exports, number)
	}
	return profile, nil
}

// LoadCRSProfile is Load + CRSProfileOf: the stored or delivered bytes of a
// CRS profile pack, named by their digest.
func LoadCRSProfile(content []byte, wantSHA256 string) (*CompiledPack, edgeconfig.CRSProfile, error) {
	compiled, err := Load(content, wantSHA256)
	if err != nil {
		return nil, edgeconfig.CRSProfile{}, err
	}
	profile, err := CRSProfileOf(compiled)
	if err != nil {
		return nil, edgeconfig.CRSProfile{}, err
	}
	return compiled, profile, nil
}

// weakWeights is the node form of a set's learned weak weights (nil: none).
func weakWeights(weights []rulecatalog.WAFWeight) []edgeconfig.ManagedWAFWeight {
	if weights == nil {
		return nil
	}
	out := make([]edgeconfig.ManagedWAFWeight, len(weights))
	for index, weight := range weights {
		out[index] = edgeconfig.ManagedWAFWeight{Rule: weight.Rule, Weight: weight.Weight}
	}
	return out
}
