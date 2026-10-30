package edgepublish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// withholdMarketPluginMounts applies a market tenant's supply plugins (ADR
// 0012 §20, ML-25, U14) to the published mounts of its sites: a pack that
// needs a plugin the tenant's latest grant does not include is left out of
// the site object (the remaining mounts get their own resolved_sha256); the
// published mounts stay as they are, so the pack returns once a grant
// includes the plugin again (marketsupply.applyPlugins republishes). A scope
// without a market_supply_tenant_plugins row is not a market tenant and is
// not touched.
//
// A pack needs a plugin when its catalog entry requires a licence feature
// (official paid packs: pack.cc.advanced, pack.crs, pack.selfwaf, ...) or
// when it came from the plugin market ("rule_pack:<pack id>"). Free official
// packs and the tenant's own packs are base protection and always stay.
func withholdMarketPluginMounts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, facts map[string]siteObjectV2Facts) error {
	var plugins []string
	err := tx.QueryRow(ctx, `SELECT plugins FROM market_supply_tenant_plugins WHERE tenant_scope_id=$1`, scopeID).Scan(&plugins)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: load market tenant plugins", ErrPersistence)
	}
	needs := map[string]string{} // pack@version -> plugin it needs ("" = none)
	for _, value := range facts {
		if value.Mounts == nil {
			continue
		}
		for _, mount := range value.Mounts.Mounts {
			key := mount.PackID + "@" + mount.Version
			if _, done := needs[key]; done {
				continue
			}
			var source, feature string
			if err := tx.QueryRow(ctx, `SELECT artifact.source, COALESCE(entry.requires_feature, '')
				FROM rule_pack_artifacts artifact
				LEFT JOIN artifact_catalog_entries entry ON entry.artifact_id=$3
				WHERE artifact.pack_id=$1 AND artifact.version=$2`, mount.PackID, mount.Version,
				artifactcatalog.RulePackArtifactID(mount.PackID)).Scan(&source, &feature); err != nil {
				return fmt.Errorf("%w: rule pack %s plugin: %v", ErrPersistence, key, err)
			}
			switch {
			case source == "market":
				needs[key] = "rule_pack:" + mount.PackID
			case source == "catalog":
				needs[key] = feature
			default:
				needs[key] = ""
			}
		}
	}
	withheld := func(mount rulepack.Mount) bool {
		plugin := needs[mount.PackID+"@"+mount.Version]
		return plugin != "" && !slices.Contains(plugins, plugin)
	}
	for siteID, value := range facts {
		if value.Mounts == nil || len(value.Mounts.Mounts) == 0 {
			continue
		}
		security, err := toLibSecurity(*value.Mounts)
		if err != nil {
			return fmt.Errorf("%w: site %s rule pack mounts: %v", ErrInvalidInput, siteID, err)
		}
		if !slices.ContainsFunc(security.Mounts, withheld) {
			continue
		}
		packs, err := loadKeptMountPacks(ctx, tx, security.Mounts, withheld)
		if err != nil {
			return err
		}
		kept, _, err := rulepack.Withhold(security, packs, withheld)
		if err != nil {
			return fmt.Errorf("%w: site %s rule pack mounts without market plugins: %v", ErrInvalidInput, siteID, err)
		}
		raw, err := json.Marshal(kept)
		if err != nil {
			return err
		}
		var mounts siteRuleMounts
		if err := decodeStrictJSON(raw, &mounts); err != nil {
			return fmt.Errorf("%w: site %s rule pack mounts: %v", ErrInvalidInput, siteID, err)
		}
		if mounts.Mounts == nil {
			mounts.Mounts = []edgesite.RuleMount{}
		}
		value.Mounts = &mounts
		facts[siteID] = value
	}
	return nil
}

func toLibSecurity(mounts siteRuleMounts) (rulepack.Security, error) {
	raw, err := json.Marshal(mounts)
	if err != nil {
		return rulepack.Security{}, err
	}
	var security rulepack.Security
	return security, json.Unmarshal(raw, &security)
}

// loadKeptMountPacks compiles the stored artifacts of the mounts that stay.
func loadKeptMountPacks(ctx context.Context, tx pgx.Tx, mounts []rulepack.Mount,
	withheld func(rulepack.Mount) bool) (map[string]*rulepack.CompiledPack, error) {
	packs := map[string]*rulepack.CompiledPack{}
	for _, mount := range mounts {
		if withheld(mount) {
			continue
		}
		var content []byte
		if err := tx.QueryRow(ctx, `SELECT content FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2 AND sha256=$3`,
			mount.PackID, mount.Version, mount.SHA256).Scan(&content); err != nil || content == nil {
			return nil, fmt.Errorf("%w: read mounted rule pack %s@%s", ErrPersistence, mount.PackID, mount.Version)
		}
		load := rulepack.Load
		if rulepack.IsSealed(content) {
			load = rulepack.OpenManifest
		}
		compiled, err := load(content, mount.SHA256)
		if err != nil {
			return nil, fmt.Errorf("%w: stored rule pack %s: %v", ErrInvalidInput, mount.PackID, err)
		}
		packs[mount.SHA256] = compiled
	}
	return packs, nil
}
