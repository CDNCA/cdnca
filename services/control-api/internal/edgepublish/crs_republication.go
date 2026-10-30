package edgepublish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CRS rule text republication. A release embeds the
// OWASP CRS rule text of the synced system rule catalog (waf_set:crs_rules)
// when it is built (loadSiteRuntimeV2CRSFiles); the rule
// set selectors of a managed WAF are fixed when its policy is saved. So a
// catalog delivery reaches the nodes only through a new release, and only
// the scopes whose published release loads a file whose text changed need
// one.

// CRSRuleCatalogKey is the system rule carrying the CRS rule text.
const CRSRuleCatalogKey = "waf_set:crs_rules"

// ChangedCRSRuleFiles returns the CRS rule text files whose content differs
// between the previous and the next active catalog body of
// waf_set:crs_rules (nil body: absent). A next body that is absent or does
// not decode changes nothing a release could take (it could not be built);
// a previous one that is absent or does not decode makes every next file
// changed.
func ChangedCRSRuleFiles(previous, next []byte) []string {
	nextFiles, ok := crsRuleFileDigests(next)
	if !ok {
		return nil
	}
	previousFiles, ok := crsRuleFileDigests(previous)
	var changed []string
	for name, digest := range nextFiles {
		if !ok || previousFiles[name] != digest {
			changed = append(changed, name)
		}
	}
	for name := range previousFiles {
		if _, kept := nextFiles[name]; !kept {
			changed = append(changed, name)
		}
	}
	slices.Sort(changed)
	return changed
}

func crsRuleFileDigests(body []byte) (map[string]string, bool) {
	if len(body) == 0 {
		return nil, false
	}
	var item rulecatalog.ItemBody
	if err := json.Unmarshal(body, &item); err != nil || item.WAFRuleSet == nil || item.WAFRuleSet.Bundle == nil ||
		len(item.WAFRuleSet.Bundle.Files) == 0 {
		return nil, false
	}
	digests := make(map[string]string, len(item.WAFRuleSet.Bundle.Files))
	for _, file := range item.WAFRuleSet.Bundle.Files {
		digests[file.Name] = file.SHA256
	}
	return digests, true
}

// CRSRuleCatalogScopesTx lists the tenant scopes whose latest publication
// loads one of the changed CRS rule files, in scope order. A release whose
// file set cannot be read back (selectors this build no longer resolves) is
// counted as affected.
func CRSRuleCatalogScopesTx(ctx context.Context, tx pgx.Tx, changed []string) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	if len(changed) == 0 {
		return nil, nil
	}
	// Coarse filter first: only releases that mention a managed WAF
	// (listener security) are decoded.
	rows, err := tx.Query(ctx, `WITH latest AS (
			SELECT DISTINCT ON (publication.configuration_scope_id)
			       publication.configuration_scope_id,publication.config_version_id
			FROM edge_config_publications publication
			JOIN access_scopes scope ON scope.id=publication.configuration_scope_id AND scope.kind='tenant'
			WHERE publication.contract_version=1
			ORDER BY publication.configuration_scope_id,publication.source_revision DESC)
		SELECT latest.configuration_scope_id,version.canonical_snapshot
		FROM latest JOIN config_versions version ON version.id=latest.config_version_id
		WHERE position(convert_to('"managed_waf"','UTF8') IN version.canonical_snapshot)>0
		ORDER BY latest.configuration_scope_id`)
	if err != nil {
		return nil, fmt.Errorf("%w: read CRS rule text publications", ErrPersistence)
	}
	type release struct {
		scopeID  uuid.UUID
		snapshot []byte
	}
	releases, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (release, error) {
		var item release
		return item, row.Scan(&item.scopeID, &item.snapshot)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: scan CRS rule text publications", ErrPersistence)
	}
	// The release's files are resolved against the next rule text (the
	// changed files are named by it) and the downloaded profile packs.
	crs, err := loadCRSInputs(ctx, tx)
	if err != nil && !errors.Is(err, ErrUnsupportedSecurityPolicy) {
		return nil, err
	}
	var text *edgeconfig.CRSRuleText
	var profiles securitypolicy.CRSProfiles
	if crs != nil {
		text, profiles = crs.RuleText, crs.Profiles
	}
	var scopes []uuid.UUID
	for _, item := range releases {
		names, known := publishedCRSRuleFiles(item.snapshot, text, profiles)
		if !known || slices.ContainsFunc(names, func(name string) bool { return slices.Contains(changed, name) }) {
			scopes = append(scopes, item.scopeID)
		}
	}
	return scopes, nil
}

// publishedCRSRuleFiles is the CRS rule text files a published release
// loads; known=false when that cannot be read back. The files follow from
// the CRS profile packs the release selects (PA-12): they are resolved from
// the downloaded packs (profiles, by digest) against the whole rule text
// (text); a release selecting a pack no longer downloaded is unknown.
func publishedCRSRuleFiles(snapshot []byte, text *edgeconfig.CRSRuleText, profiles securitypolicy.CRSProfiles) ([]string, bool) {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(snapshot, &document); err != nil || document.Schema != siteRuntimeV2Schema {
		return nil, false
	}
	sites, err := listenerSites(siteRuntimeSecurityListeners(document))
	if err != nil {
		return nil, false
	}
	byDigest := map[string]edgeconfig.CRSProfile{}
	for _, profile := range profiles {
		byDigest[profile.Profile.Ref.SHA256] = profile.Profile
	}
	var selected []edgeconfig.CRSProfile
	seen := map[string]bool{}
	for _, site := range sites {
		if site.ManagedWAF == nil || seen[site.ManagedWAF.Profile.SHA256] {
			continue
		}
		seen[site.ManagedWAF.Profile.SHA256] = true
		profile, ok := byDigest[site.ManagedWAF.Profile.SHA256]
		if !ok || text == nil {
			return nil, false
		}
		selected = append(selected, profile)
	}
	if len(selected) == 0 {
		return nil, true
	}
	files, err := edgeconfig.CRSReleaseFiles(sites, text, selected)
	if err != nil {
		return nil, false
	}
	prefix := edgeconfig.ListenerCRSReleasePath("")
	names := make([]string, 0, len(files))
	for path := range files {
		names = append(names, strings.TrimPrefix(path, prefix))
	}
	slices.Sort(names)
	return names, true
}

// listenerSites is the managed WAF of listeners as sites (one per site ID).
func listenerSites(listeners []edgeconfig.SecurityListener) ([]edgeconfig.Site, error) {
	var sites []edgeconfig.Site
	seen := map[string]bool{}
	for _, listener := range listeners {
		if listener.Security.ManagedWAF == nil || seen[listener.SiteID] {
			continue
		}
		seen[listener.SiteID] = true
		managed, err := edgeconfig.CanonicalListenerManagedWAF(*listener.Security.ManagedWAF)
		if err != nil {
			return nil, err
		}
		sites = append(sites, edgeconfig.Site{ID: listener.SiteID, ManagedWAF: managed})
	}
	return sites, nil
}

// CRSProfilePackScopesTx lists the tenant scopes whose latest publication
// selects a CRS profile pack by one of digests (the downloaded bytes of a
// pack changed: a new revision replaces them), in scope order.
func CRSProfilePackScopesTx(ctx context.Context, tx pgx.Tx, digests []string) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInvalidInput
	}
	if len(digests) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `WITH latest AS (
			SELECT DISTINCT ON (publication.configuration_scope_id)
			       publication.configuration_scope_id,publication.config_version_id
			FROM edge_config_publications publication
			JOIN access_scopes scope ON scope.id=publication.configuration_scope_id AND scope.kind='tenant'
			WHERE publication.contract_version=1
			ORDER BY publication.configuration_scope_id,publication.source_revision DESC)
		SELECT latest.configuration_scope_id
		FROM latest JOIN config_versions version ON version.id=latest.config_version_id
		WHERE EXISTS (SELECT 1 FROM unnest($1::text[]) digest
			WHERE position(convert_to(digest,'UTF8') IN version.canonical_snapshot)>0)
		ORDER BY latest.configuration_scope_id`, digests)
	if err != nil {
		return nil, fmt.Errorf("%w: read CRS profile pack publications", ErrPersistence)
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("%w: scan CRS profile pack publications", ErrPersistence)
	}
	return scopes, nil
}
