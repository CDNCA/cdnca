package edgepublish

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/jackc/pgx/v5"
)

// A site's modsecurity rule pack narrows the site's
// own CRS profile: the rules the profile evaluates and the pack does not
// join the site object's managed_waf.exclusions, which the node applies per
// request (ManagedWAF.Exclusions). The node-wide CRS configuration is never
// changed for a pack. rulepackcontrol refuses an out-of-profile mount when
// it is published, and a site CRS profile change suspends the mounts it no
// longer covers (rulepackcontrol suspend.go), so they are not published; a
// published mount still outside the profile (another path changed it) is
// refused here.

// CRSOutOfProfileError refuses a publication whose site mounts a
// modsecurity rule pack outside the site's CRS profile (or runs no managed
// WAF). It unwraps to ErrUnsupportedSecurityPolicy.
type CRSOutOfProfileError struct {
	SiteID string
	PackID string
	Reason string
}

func (e *CRSOutOfProfileError) Error() string {
	return fmt.Sprintf("site %s mounts modsecurity rule pack %s outside its CRS profile (规则包超出网站 CRS 档位范围): %s",
		e.SiteID, e.PackID, e.Reason)
}

func (e *CRSOutOfProfileError) Unwrap() error { return ErrUnsupportedSecurityPolicy }

// siteModSecurityFacts are the inputs of a site's modsecurity mount: its
// instantiated rules, the CRS manifest and the downloaded profile packs (by
// digest).
type siteModSecurityFacts struct {
	PackID string
	Rules  []rulepack.NodeRule
	// Runs is set instead of Rules for a sealed pack listing crs_rule_ids:
	// the CRS rule IDs the mount evaluates (rulepack.MountCRSRuns).
	Runs     []int
	Manifest *edgeconfig.CRSManifest
	Profiles map[string]edgeconfig.CRSProfile
}

// loadSiteModSecurityFacts fills facts[site].ModSecurity for every site
// whose published mounts include a modsecurity pack. A pack the control
// plane cannot read (sealed, missing) is out of profile.
func loadSiteModSecurityFacts(ctx context.Context, tx pgx.Tx, facts map[string]siteObjectV2Facts) error {
	var manifest *edgeconfig.CRSManifest
	var profiles map[string]edgeconfig.CRSProfile
	for siteID, value := range facts {
		if value.Mounts == nil {
			continue
		}
		for _, mount := range value.Mounts.Mounts {
			if mount.Engine != string(rulepack.EngineModSecurity) {
				continue
			}
			if profiles == nil {
				var err error
				if manifest, err = securitypolicy.LoadCRSManifestTx(ctx, tx); err != nil {
					return fmt.Errorf("%w: %v", ErrPersistence, err)
				}
				downloaded, err := securitypolicy.LoadCRSProfilesTx(ctx, tx, nil)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrPersistence, err)
				}
				profiles = make(map[string]edgeconfig.CRSProfile, len(downloaded))
				for _, profile := range downloaded {
					profiles[profile.Profile.Ref.SHA256] = profile.Profile
				}
			}
			rules, runs, err := modSecurityMountRules(ctx, tx, mount)
			if err != nil {
				return err
			}
			value.ModSecurity = &siteModSecurityFacts{PackID: mount.PackID, Rules: rules, Runs: runs, Manifest: manifest,
				Profiles: profiles}
			facts[siteID] = value
		}
	}
	return nil
}

// modSecurityMountRules reads a modsecurity mount's pack: its instantiated
// rules, or for a sealed pack its listed CRS rule IDs (runs); neither when
// the pack is missing or sealed without a list (applySiteModSecurity
// refuses it).
func modSecurityMountRules(ctx context.Context, tx pgx.Tx, mount edgesite.RuleMount) ([]rulepack.NodeRule, []int, error) {
	var content []byte
	err := tx.QueryRow(ctx, `SELECT content FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2 AND sha256=$3`,
		mount.PackID, mount.Version, mount.SHA256).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && content == nil {
		return nil, nil, nil // ModSecurityRules refuses the missing pack
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read modsecurity rule pack", ErrPersistence)
	}
	load := rulepack.Load
	if rulepack.IsSealed(content) {
		load = rulepack.OpenManifest
	}
	pack, err := load(content, mount.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: stored rule pack %s: %v", ErrInvalidInput, mount.PackID, err)
	}
	libMount := rulepack.Mount{Layer: rulepack.Layer(mount.Layer), PackID: mount.PackID,
		Version: mount.Version, SHA256: mount.SHA256, Engine: rulepack.Engine(mount.Engine), Priority: mount.Priority,
		Params: rulepack.Params(mount.Params)}
	if pack.Sealed {
		runs, listed, err := rulepack.MountCRSRuns(libMount, pack)
		if err != nil || !listed {
			return nil, nil, nil
		}
		return nil, runs, nil
	}
	rules, err := rulepack.ModSecurityRules(libMount, pack)
	if err != nil {
		return nil, nil, nil
	}
	return rules, nil, nil
}

// applySiteModSecurity narrows the site's managed WAF with its modsecurity
// mount (nil facts: none).
func applySiteModSecurity(site *edgesite.Site, facts *siteModSecurityFacts) error {
	if facts == nil {
		return nil
	}
	refuse := func(reason string) error {
		return &CRSOutOfProfileError{SiteID: site.SiteID, PackID: facts.PackID, Reason: reason}
	}
	waf := site.Security.ManagedWAF
	if waf == nil {
		return refuse("the site runs no managed WAF (CRS profile)")
	}
	if facts.Rules == nil && facts.Runs == nil {
		return refuse("the pack's rules are not readable by the control plane (sealed without crs_rule_ids, or not downloaded)")
	}
	profile, ok := facts.Profiles[waf.CRSProfile.SHA256]
	if !ok || profile.Ref != waf.CRSProfile {
		return refuse("the site's CRS profile pack is not downloaded")
	}
	var exclusions []int
	var err error
	if facts.Runs != nil {
		exclusions, err = rulepack.NarrowCRSProfileByIDs(facts.Manifest, profile, waf.Exclusions, facts.PackID, facts.Runs)
	} else {
		exclusions, err = rulepack.NarrowCRSProfile(facts.Manifest, profile, waf.Exclusions, facts.Rules)
	}
	if err != nil {
		return refuse(err.Error())
	}
	waf.Exclusions = exclusions
	return nil
}
