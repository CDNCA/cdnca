package securitypolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CRSOverride is one site's own OWASP CRS settings (PA-12, 站点“防护”页
// “CRS 档位”): the site's WAF rule library's managed WAF holds the defaults,
// and an item the site sets replaces the library's for this site only. Each
// item is nil (inherit) or the site's value: Profile a CRS profile pack ID
// (system/crs-<level>), Exclusions the scoring rule IDs (from that profile's
// exports) the site does not evaluate, replacing the library's list as a
// whole (an empty list excludes nothing).
type CRSOverride struct {
	Profile    *string `json:"profile"`
	Exclusions *[]int  `json:"exclusions"`
	// Apps are the site's application types (application exclusion pack
	// IDs system/app-<key>, sorted; waf-apptype). Site only: a WAF library
	// has none, so there is nothing to inherit and nil means none.
	Apps []string `json:"apps,omitempty"`
}

// Inherits reports whether the override sets nothing.
func (override CRSOverride) Inherits() bool {
	return override.Profile == nil && override.Exclusions == nil && len(override.Apps) == 0
}

// NormalizeCRSOverride validates the items the override sets (a profile pack
// ID; rule IDs in the CRS range, at most MaxManagedWAFExclusions) and sorts
// the exclusions.
func NormalizeCRSOverride(override *CRSOverride) error {
	if override.Profile != nil && !rulepack.IsCRSProfilePack(*override.Profile) {
		return ErrInvalidInput
	}
	apps := slices.Clone(override.Apps)
	slices.Sort(apps)
	if len(apps) > edgeconfig.MaxManagedWAFApps || len(slices.Compact(slices.Clone(apps))) != len(apps) {
		return ErrInvalidInput
	}
	for _, app := range apps {
		if !rulepack.IsCRSAppPack(app) {
			return ErrInvalidInput
		}
	}
	if len(apps) == 0 {
		apps = nil
	}
	override.Apps = apps
	if override.Exclusions == nil {
		return nil
	}
	ids := slices.Clone(*override.Exclusions)
	slices.Sort(ids)
	if len(ids) > edgeconfig.MaxManagedWAFExclusions || len(slices.Compact(slices.Clone(ids))) != len(ids) {
		return ErrInvalidInput
	}
	for _, id := range ids {
		if id < 900000 || id > 999999 {
			return ErrInvalidInput
		}
	}
	if ids == nil {
		ids = []int{}
	}
	override.Exclusions = &ids
	return nil
}

// EffectiveManagedWAF is what a site runs: the library's managed WAF with the
// override's items in place.
func EffectiveManagedWAF(library ManagedWAFConfig, override CRSOverride) ManagedWAFConfig {
	effective := library
	effective.Exclusions = slices.Clone(library.Exclusions)
	if override.Profile != nil {
		effective.Profile = *override.Profile
	}
	if override.Exclusions != nil {
		effective.Exclusions = slices.Clone(*override.Exclusions)
	}
	if len(effective.Exclusions) == 0 {
		effective.Exclusions = nil
	}
	return effective
}

// DecodeCRSOverride decodes a stored override (site_crs_overrides.override):
// known items only, valid, and setting at least one item (a site that
// inherits everything has no row).
func DecodeCRSOverride(raw []byte) (CRSOverride, error) {
	var override CRSOverride
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&override) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		NormalizeCRSOverride(&override) != nil || override.Inherits() {
		return CRSOverride{}, ErrInvalidInput
	}
	return override, nil
}

// PolicyManagedWAF is the enabled managed WAF rule of a WAF policy (nil:
// none, or the policy is off).
func PolicyManagedWAF(policy Policy) *ManagedWAFConfig {
	if policy.Kind != KindWAF || !policy.Enabled {
		return nil
	}
	for _, rule := range policy.Rules {
		if rule.Enabled && rule.Action == ActionManagedWAF && rule.ActionConfig.ManagedWAF != nil {
			config := *rule.ActionConfig.ManagedWAF
			return &config
		}
	}
	return nil
}

// SiteManagedWAFTx is the managed WAF a site runs once published: the latest
// version of its WAF rule library's managed WAF rule with the site's CRS
// override (site_crs_overrides) applied; nil when the library runs none
// (no binding, deleted or disabled policy, no managed WAF rule).
func SiteManagedWAFTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (*ManagedWAFConfig, error) {
	var document []byte
	err := tx.QueryRow(ctx, `SELECT latest.document
		FROM security_policy_site_bindings binding
		JOIN security_policies policy ON policy.id=binding.policy_id AND policy.scope_id=binding.tenant_scope_id
		  AND policy.deleted_at IS NULL
		JOIN security_policy_versions latest ON latest.policy_id=policy.id AND latest.revision=policy.revision
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND binding.policy_kind=$3`,
		scopeID, siteID, KindWAF).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read site WAF policy: %w", err)
	}
	var policy Policy
	if err := json.Unmarshal(document, &policy); err != nil || policy.ScopeID != scopeID || policy.Kind != KindWAF {
		return nil, errors.New("decode site WAF policy version")
	}
	managed := PolicyManagedWAF(policy)
	if managed == nil {
		return nil, nil
	}
	var raw []byte
	override := CRSOverride{}
	err = tx.QueryRow(ctx, `SELECT override FROM site_crs_overrides WHERE scope_id=$1 AND site_id=$2`, scopeID, siteID).Scan(&raw)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, fmt.Errorf("read site CRS override: %w", err)
	default:
		if override, err = DecodeCRSOverride(raw); err != nil {
			return nil, fmt.Errorf("decode site CRS override: %w", err)
		}
	}
	effective := EffectiveManagedWAF(*managed, override)
	return &effective, nil
}
