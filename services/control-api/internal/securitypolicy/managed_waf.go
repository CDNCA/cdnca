package securitypolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/jackc/pgx/v5"
)

// managedWAFValidationPolicyID only fills the identity fields edgeconfig
// requires; validation looks at the values, never at this ID.
const managedWAFValidationPolicyID = "00000000-0000-4000-8000-000000000000"

// DefaultCRSProfile is the profile a new managed WAF selects (CRS 标准 PL1).
const DefaultCRSProfile = "system/crs-pl1"

// CRSProfileArtifactPrefix is the catalog artifact ID prefix of CRS profile
// packs (crs_profile/crs-<level> carries system/crs-<level>).
const CRSProfileArtifactPrefix = "crs_profile/"

// CRSProfilePackArtifactID is the artifact ID of a CRS profile pack ID.
func CRSProfilePackArtifactID(packID string) string {
	return CRSProfileArtifactPrefix + strings.TrimPrefix(packID, "system/")
}

// ErrCRSProfileUnavailable: the selected CRS profile pack is not downloaded
// (or its catalog entry is no longer usable) on this control plane.
var ErrCRSProfileUnavailable = errors.New("CRS profile pack is not available")

// EdgeManagedWAF converts a policy's managed WAF (with a site's profile and
// exclusions already in place) into the node configuration. profile is the
// downloaded pack the release loads; allowCIDRs are networks the site's
// policies allow unconditionally (ModSecurity is off for them).
func EdgeManagedWAF(config ManagedWAFConfig, profile edgeconfig.CRSProfileRef, policyID string, policyVersion int64, allowCIDRs []string) edgeconfig.ManagedWAF {
	return edgeconfig.ManagedWAF{PolicyID: policyID, PolicyVersion: policyVersion,
		RequestBodyLimit: config.RequestBodyLimit, RequestBodyNoFilesLimit: config.RequestBodyNoFilesLimit,
		RequestBodyLimitAction: config.RequestBodyLimitAction, ArgumentsLimit: config.ArgumentsLimit,
		JSONDepthLimit: config.JSONDepthLimit, PCREMatchLimit: config.PCREMatchLimit, InspectionLimitAction: config.InspectionLimitAction,
		Profile: profile, Exclusions: append([]int(nil), config.Exclusions...), AllowCIDRs: append([]string(nil), allowCIDRs...)}
}

// EdgeCRSRuleText decodes the catalog's CRS rule text (waf_set:crs_rules)
// into the node compiler input (the CRS manifest is derived from it).
func EdgeCRSRuleText(bundle rulecatalog.WAFEngineBundle) (*edgeconfig.CRSRuleText, error) {
	files, err := rulecatalog.DecodeWAFEngineBundle(bundle)
	if err != nil {
		return nil, fmt.Errorf("%w: CRS rule text", ErrCatalogUnsupported)
	}
	return &edgeconfig.CRSRuleText{Version: bundle.Version, Files: files}, nil
}

// ValidateManagedWAF applies the node compiler's own checks (ranges, a CRS
// profile pack ID, exclusion syntax) at save time; whether the profile is
// downloaded and exports the exclusions is checked against the local packs
// (CRSProfiles.Check) when the policy or a site override is written.
func ValidateManagedWAF(config ManagedWAFConfig) error {
	if !rulepack.IsCRSProfilePack(config.Profile) {
		return ErrInvalidInput
	}
	probe := edgeconfig.CRSProfileRef{PackID: config.Profile, Version: "1.0.0", SHA256: strings.Repeat("0", 64)}
	normalized, err := edgeconfig.NormalizeManagedWAF(EdgeManagedWAF(config, probe, managedWAFValidationPolicyID, 1, nil))
	if err != nil || !slices.Equal(normalized.Exclusions, config.Exclusions) ||
		normalized.InspectionLimitAction != config.InspectionLimitAction && config.InspectionLimitAction != "" {
		return ErrInvalidInput
	}
	return nil
}

// CRSProfiles is the CRS profile packs this control plane downloaded and may
// use (artifactsync local artifacts crs_profile/crs-*, verified with
// rulepack.LoadCRSProfile), by pack ID.
type CRSProfiles map[string]CRSProfile

// CRSProfile is one usable downloaded CRS profile pack.
type CRSProfile struct {
	Profile     edgeconfig.CRSProfile
	Content     []byte
	Description string
	// Tier is the profile as a protection tier (attack classes, rule counts,
	// what it adds to the next narrower profile), counted from the synced CRS
	// rule text; nil while that text is not synced.
	Tier *rulepack.CRSTier
}

// Check reports whether config selects a downloaded profile and excludes
// only rules that profile exports.
func (profiles CRSProfiles) Check(config ManagedWAFConfig) error {
	profile, ok := profiles[config.Profile]
	if !ok {
		return ErrCRSProfileUnavailable
	}
	for _, id := range config.Exclusions {
		if _, found := slices.BinarySearch(profile.Profile.Exports, id); !found {
			return ErrInvalidInput
		}
	}
	return nil
}

// LoadCRSProfilesTx reads the usable downloaded CRS profile packs (active
// catalog entry, lease feature granted when the entry requires one: features
// nil grants only free packs). Bytes that do not verify are skipped: the
// download check already rejected them, so this only guards the store.
func LoadCRSProfilesTx(ctx context.Context, db pgx.Tx, features map[string]bool) (CRSProfiles, error) {
	rows, err := db.Query(ctx, `SELECT local.artifact_id,local.current_sha256,entry.requires_feature,object.content
		FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id AND entry.status='active'
		JOIN artifact_objects object ON object.sha256=local.current_sha256
		WHERE entry.kind='crs_profile' AND entry.media_type=$1 AND local.current_revision IS NOT NULL
		ORDER BY local.artifact_id`, artifactcatalog.MediaTypeCRSProfilePack)
	if err != nil {
		return nil, fmt.Errorf("read CRS profile packs: %w", err)
	}
	defer rows.Close()
	result := CRSProfiles{}
	for rows.Next() {
		var artifactID, digest, feature string
		var content []byte
		if err := rows.Scan(&artifactID, &digest, &feature, &content); err != nil {
			return nil, fmt.Errorf("scan CRS profile pack: %w", err)
		}
		if feature != "" && !features[feature] {
			continue
		}
		compiled, profile, err := rulepack.LoadCRSProfile(content, digest)
		if err != nil || CRSProfilePackArtifactID(profile.Ref.PackID) != artifactID {
			continue
		}
		result[profile.Ref.PackID] = CRSProfile{Profile: profile, Content: content, Description: compiled.Pack.Description}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, attachCRSTiers(ctx, db, result)
}

// CRSApps is the application exclusion packs this control plane downloaded
// (crs_profile/app-*, verified with rulepack.LoadCRSApp), by pack ID.
type CRSApps map[string]CRSApp

// CRSApp is one usable downloaded application exclusion pack.
type CRSApp struct {
	App         edgeconfig.CRSApp
	Content     []byte
	Description string
}

// CRSAppSummary is a selectable application type.
type CRSAppSummary struct {
	PackID      string `json:"pack_id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// Summaries lists the application types by pack ID.
func (apps CRSApps) Summaries() []CRSAppSummary {
	result := make([]CRSAppSummary, 0, len(apps))
	for _, app := range apps {
		result = append(result, CRSAppSummary{PackID: app.App.Ref.PackID, Key: app.App.Key, Name: app.App.Name,
			Version: app.App.Ref.Version, Description: app.Description})
	}
	slices.SortFunc(result, func(a, b CRSAppSummary) int { return strings.Compare(a.PackID, b.PackID) })
	return result
}

// Refs is the refs of packIDs (sorted); false when one is not downloaded.
func (apps CRSApps) Refs(packIDs []string) ([]edgeconfig.CRSAppRef, []edgeconfig.CRSApp, bool) {
	refs := make([]edgeconfig.CRSAppRef, 0, len(packIDs))
	selected := make([]edgeconfig.CRSApp, 0, len(packIDs))
	for _, packID := range packIDs {
		app, ok := apps[packID]
		if !ok {
			return nil, nil, false
		}
		refs = append(refs, app.App.Ref)
		selected = append(selected, app.App)
	}
	slices.SortFunc(refs, func(a, b edgeconfig.CRSAppRef) int { return strings.Compare(a.PackID, b.PackID) })
	return refs, selected, true
}

// LoadCRSAppsTx reads the usable downloaded application exclusion packs
// (free; active catalog entry). Bytes that do not verify are skipped.
func LoadCRSAppsTx(ctx context.Context, db pgx.Tx) (CRSApps, error) {
	rows, err := db.Query(ctx, `SELECT local.artifact_id,local.current_sha256,object.content
		FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id AND entry.status='active'
		JOIN artifact_objects object ON object.sha256=local.current_sha256
		WHERE entry.kind='crs_profile' AND entry.media_type=$1 AND entry.requires_feature='' AND
		  local.artifact_id LIKE 'crs_profile/app-%' AND local.current_revision IS NOT NULL
		ORDER BY local.artifact_id`, artifactcatalog.MediaTypeCRSProfilePack)
	if err != nil {
		return nil, fmt.Errorf("read application exclusion packs: %w", err)
	}
	defer rows.Close()
	result := CRSApps{}
	for rows.Next() {
		var artifactID, digest string
		var content []byte
		if err := rows.Scan(&artifactID, &digest, &content); err != nil {
			return nil, fmt.Errorf("scan application exclusion pack: %w", err)
		}
		compiled, app, err := rulepack.LoadCRSApp(content, digest)
		if err != nil || CRSProfilePackArtifactID(app.Ref.PackID) != artifactID {
			continue
		}
		result[app.Ref.PackID] = CRSApp{App: app, Content: content, Description: compiled.Pack.Description}
	}
	return result, rows.Err()
}

// attachCRSTiers derives the profiles' protection tiers from the synced CRS
// rule text (waf_set:crs_rules); without it the profiles carry no tier.
func attachCRSTiers(ctx context.Context, db pgx.Tx, profiles CRSProfiles) error {
	if len(profiles) == 0 {
		return nil
	}
	manifest, err := LoadCRSManifestTx(ctx, db)
	if err != nil || manifest == nil {
		return err
	}
	list := make([]edgeconfig.CRSProfile, 0, len(profiles))
	for _, profile := range profiles {
		list = append(list, profile.Profile)
	}
	for _, tier := range rulepack.CRSTiers(manifest, list, CRSSetOrder()) {
		profile := profiles[tier.PackID]
		profile.Tier = &tier
		profiles[tier.PackID] = profile
	}
	return nil
}

// LoadCRSManifestTx derives the manifest of the synced CRS rule text
// (waf_set:crs_rules); nil while that text is not synced or does not decode.
func LoadCRSManifestTx(ctx context.Context, db pgx.Tx) (*edgeconfig.CRSManifest, error) {
	var body []byte
	err := db.QueryRow(ctx, `SELECT body FROM security_system_rules WHERE system_key='waf_set:crs_rules' AND status='active'`).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read CRS rule text: %w", err)
	}
	var item rulecatalog.ItemBody
	if json.Unmarshal(body, &item) != nil || item.WAFRuleSet == nil || item.WAFRuleSet.Bundle == nil {
		return nil, nil
	}
	text, err := EdgeCRSRuleText(*item.WAFRuleSet.Bundle)
	if err != nil {
		return nil, nil
	}
	manifest, err := edgeconfig.DeriveCRSManifest(text)
	if err != nil {
		return nil, nil
	}
	return manifest, nil
}

// CRSSetOrder is the catalog order of the CRS rule sets (the order a tier
// lists its attack classes in).
func CRSSetOrder() []string {
	order := []string{}
	for _, item := range rulecatalog.CRSWAFSeed() {
		order = append(order, item.SystemKey)
	}
	return order
}

// ManagedWAFCatalog is the synced system rule catalog view the managed WAF
// needs: the engine-wide defaults and the CRS rule text (waf_set:crs_rules).
type ManagedWAFCatalog struct {
	Settings *rulecatalog.WAFEngineSettings
	Rules    *rulecatalog.WAFEngineBundle
}

// NewManagedWAFCatalog indexes catalog items (any kinds; non-WAF ignored).
func NewManagedWAFCatalog(items []rulecatalog.Item) ManagedWAFCatalog {
	catalog := ManagedWAFCatalog{}
	for _, item := range items {
		if item.Kind != rulecatalog.KindWAFRuleSet || item.Body.WAFRuleSet == nil {
			continue
		}
		switch body := item.Body.WAFRuleSet; {
		case body.Settings != nil && catalog.Settings == nil:
			settings := *body.Settings
			catalog.Settings = &settings
		case body.Bundle != nil && catalog.Rules == nil:
			bundle := *body.Bundle
			catalog.Rules = &bundle
		}
	}
	return catalog
}

// ManagedWAFDefaults is a managed WAF with the catalog's engine limits, the
// given profile and no exclusions (what the editor pre-fills).
func ManagedWAFDefaults(catalog ManagedWAFCatalog, profile string) (ManagedWAFConfig, error) {
	if catalog.Settings == nil {
		return ManagedWAFConfig{}, fmt.Errorf("%w: managed WAF catalog settings", ErrCatalogUnsupported)
	}
	config := ManagedWAFConfig{RequestBodyLimit: catalog.Settings.RequestBodyLimit,
		RequestBodyNoFilesLimit: catalog.Settings.RequestBodyNoFilesLimit,
		RequestBodyLimitAction:  catalog.Settings.RequestBodyLimitAction, ArgumentsLimit: catalog.Settings.ArgumentsLimit,
		JSONDepthLimit: catalog.Settings.JSONDepthLimit, PCREMatchLimit: catalog.Settings.PCREMatchLimit, Profile: profile}
	if err := ValidateManagedWAF(config); err != nil {
		return ManagedWAFConfig{}, err
	}
	return config, nil
}

// SystemCatalog loads the active synced system rule catalog items (the
// signed catalog control-api received from the license service).
func (s *Store) SystemCatalog(ctx context.Context) ([]rulecatalog.Item, error) {
	rows, err := s.pool.Query(ctx, `SELECT system_key,kind,legacy_id,name,description,sort,hidden,revision,body
		FROM security_system_rules WHERE status='active' ORDER BY system_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]rulecatalog.Item, 0)
	for rows.Next() {
		var item rulecatalog.Item
		var body []byte
		if err := rows.Scan(&item.SystemKey, &item.Kind, &item.LegacyID, &item.Name, &item.Description, &item.Sort,
			&item.Hidden, &item.Revision, &body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(body, &item.Body); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ManagedWAFCatalog loads the active synced WAF catalog items.
func (s *Store) ManagedWAFCatalog(ctx context.Context) (ManagedWAFCatalog, error) {
	items, err := s.SystemCatalog(ctx)
	if err != nil {
		return ManagedWAFCatalog{}, err
	}
	return NewManagedWAFCatalog(items), nil
}

// ManagedWAFRuleName names the managed_waf rule the editor inserts.
const ManagedWAFRuleName = "托管规则集 (OWASP CRS)"

// CatalogWAFRules builds the WAF policy rules of the given catalog waf_set
// keys, every value taken from the catalog. The two engines sit side by side
// and a policy may use either, both or neither:
//   - self-developed sets (signature rules + semantic detectors) expand to
//     ordinary policy rules (ExpandWAFRuleSets, catalog action);
//   - OWASP CRS sets (engine bodies) become one managed_waf rule running the
//     default CRS profile pack (ManagedWAFDefaults, DefaultCRSProfile): the
//     CRS sets, their paranoia and threshold are the profile's, a site picks
//     another profile or excludes rules (PA-12).
//
// A request is blocked when either engine blocks it; each engine records its
// own hits (WAF rule log / ModSecurity audit log tag cdnca/<set key>).
func CatalogWAFRules(items []rulecatalog.Item, keys []string) ([]Rule, error) {
	index := make(map[string]rulecatalog.Item, len(items))
	for _, item := range items {
		index[item.SystemKey] = item
	}
	selfDeveloped, crs := []string{}, []string{}
	seen := map[string]bool{}
	for _, key := range keys {
		item, ok := index[key]
		if seen[key] || !ok || item.Kind != rulecatalog.KindWAFRuleSet || item.Body.WAFRuleSet == nil || item.Hidden {
			return nil, fmt.Errorf("%w: %s", ErrCatalogUnsupported, key)
		}
		seen[key] = true
		switch body := item.Body.WAFRuleSet; {
		case body.Engine != nil:
			crs = append(crs, key)
		case body.Rules != nil:
			selfDeveloped = append(selfDeveloped, key)
		default:
			return nil, fmt.Errorf("%w: %s", ErrCatalogUnsupported, key)
		}
	}
	rules, err := ExpandWAFRuleSets(index, selfDeveloped, "")
	if err != nil {
		return nil, err
	}
	if len(crs) > 0 {
		config, err := ManagedWAFDefaults(NewManagedWAFCatalog(items), DefaultCRSProfile)
		if err != nil {
			return nil, err
		}
		rules = append(rules, Rule{Name: ManagedWAFRuleName, Priority: len(rules) + 1, Enabled: true, Action: ActionManagedWAF,
			Flow: FlowContinue, Conditions: []Condition{}, ActionConfig: ActionConfig{ManagedWAF: &config}})
	}
	return rules, nil
}

// CatalogRules returns policy rules built from the synced system catalog,
// with every value taken from it, for the editor to insert and adjust:
//   - kind waf: CatalogWAFRules of the given waf_set keys (self-developed
//     and/or OWASP CRS sets);
//   - kind cc: 1..MaxCCRuleGroups cc_rule groups merged in the given order
//     (ExpandCCRuleGroups).
//
// Rule IDs are left empty (assigned when the policy is saved).
func (s *Service) CatalogRules(ctx context.Context, kind string, keys []string) ([]Rule, error) {
	items, err := s.store.SystemCatalog(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case kind == KindWAF && len(keys) > 0 && len(keys) <= 32:
		rules, err := CatalogWAFRules(items, keys)
		if err != nil {
			return nil, ErrInvalidInput
		}
		return rules, nil
	case kind == KindCC && len(keys) >= 1 && len(keys) <= MaxCCRuleGroups:
		index := make(map[string]rulecatalog.Item, len(items))
		for _, item := range items {
			index[item.SystemKey] = item
		}
		merged, err := ExpandCCRuleGroups(index, keys)
		if err != nil {
			return nil, ErrInvalidInput
		}
		return merged.Rules, nil
	}
	return nil, ErrInvalidInput
}

// resolveManagedRules checks a policy's managed WAF against the downloaded
// CRS profile packs before the policy is stored: the profile must be
// available and export every excluded rule.
func (s *Service) resolveManagedRules(ctx context.Context, fields *PolicyFields) error {
	for index := range fields.Rules {
		rule := &fields.Rules[index]
		if rule.Action != ActionManagedWAF {
			continue
		}
		profiles, err := s.store.CRSProfiles(ctx)
		if err != nil {
			return err
		}
		if err := profiles.Check(*rule.ActionConfig.ManagedWAF); err != nil {
			return ErrInvalidInput
		}
	}
	return nil
}

// CRSProfiles reads the usable downloaded free CRS profile packs.
func (s *Store) CRSProfiles(ctx context.Context) (CRSProfiles, error) {
	var profiles CRSProfiles
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		profiles, err = LoadCRSProfilesTx(ctx, tx, nil)
		return err
	})
	return profiles, err
}

// CRSProfileSummary is one selectable CRS profile pack (the editor's list).
type CRSProfileSummary struct {
	PackID      string `json:"pack_id"`
	Version     string `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Exports     []int  `json:"exports"`
	// Tier: attack classes and what this profile adds (nil without the CRS rule text).
	Tier *rulepack.CRSTier `json:"tier"`
}

// Summaries lists the profiles by pack ID.
func (profiles CRSProfiles) Summaries() []CRSProfileSummary {
	result := make([]CRSProfileSummary, 0, len(profiles))
	for packID, profile := range profiles {
		result = append(result, CRSProfileSummary{PackID: packID, Version: profile.Profile.Ref.Version, Name: profile.Profile.Name,
			Description: profile.Description, Exports: append([]int{}, profile.Profile.Exports...), Tier: profile.Tier})
	}
	slices.SortFunc(result, func(left, right CRSProfileSummary) int { return strings.Compare(left.PackID, right.PackID) })
	return result
}

// CRSProfiles lists the downloaded CRS profile packs a managed WAF may select
// (security_policies.read).
func (s *Service) CRSProfiles(ctx context.Context) ([]CRSProfileSummary, error) {
	profiles, err := s.store.CRSProfiles(ctx)
	if err != nil {
		return nil, err
	}
	return profiles.Summaries(), nil
}
