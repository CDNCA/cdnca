package rulepackcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// resolveSite computes the site's effective mounts from the current
// versions and every override that applies to it. Packs downloaded but not
// effectively enabled are not mounts (rulepack.MountRequests). The target
// engine versions are not gated here: node capability gating belongs to the
// publication of the site object (PA-01 receipts / g8c). A modsecurity
// mount must narrow the site's own CRS profile (crsProfileCheck).
//
// skip names suspended packs (suspend.go) left out of the resolution.
func resolveSite(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID, skip map[string]bool) (rulepack.Resolution, error) {
	subject, _, err := subjectFor(ctx, tx, actor, LevelInput{Level: rulepack.LevelSite, ObjectID: &siteID})
	if err != nil {
		return rulepack.Resolution{}, err
	}
	packs, err := loadPacks(ctx, tx, "")
	if err != nil {
		return rulepack.Resolution{}, err
	}
	overrides, err := loadOverrides(ctx, tx, subject, "")
	if err != nil {
		return rulepack.Resolution{}, err
	}
	requests := rulepack.MountRequests(rulepack.Effective(compiledPacks(packs), toLibOverrides(overrides), subject))
	if len(skip) != 0 {
		kept := requests[:0:0]
		for _, request := range requests {
			if request.Pack == nil || !skip[request.Pack.Pack.PackID] {
				kept = append(kept, request)
			}
		}
		requests = kept
	}
	resolution := rulepack.Resolve(requests, rulepack.Target{})
	return crsProfileCheck(ctx, tx, subject, requests, resolution)
}

// crsProfileCheck refuses a modsecurity mount outside the site's managed
// WAF profile (rulepack.CheckCRSProfile, 方案 A): the site's effective CRS
// profile and exclusions (as sitecrs shows them), the downloaded profile packs and the
// synced CRS rule text. Nothing is read without a modsecurity mount.
func crsProfileCheck(ctx context.Context, tx pgx.Tx, subject rulepack.Subject, requests []rulepack.MountRequest,
	resolution rulepack.Resolution) (rulepack.Resolution, error) {
	if resolution.Security == nil || !slices.ContainsFunc(resolution.Security.Mounts,
		func(mount rulepack.Mount) bool { return mount.Engine == rulepack.EngineModSecurity }) {
		return resolution, nil
	}
	scopeID, siteID := uuid.MustParse(subject.TenantScopeID), uuid.MustParse(subject.SiteID)
	effective, err := securitypolicy.SiteManagedWAFTx(ctx, tx, scopeID, siteID)
	if err != nil {
		return rulepack.Resolution{}, err
	}
	var profile *edgeconfig.CRSProfile
	var exclusions []int
	if effective != nil {
		profiles, err := securitypolicy.LoadCRSProfilesTx(ctx, tx, nil)
		if err != nil {
			return rulepack.Resolution{}, err
		}
		if selected, ok := profiles[effective.Profile]; ok {
			profile, exclusions = &selected.Profile, effective.Exclusions
		}
	}
	manifest, err := securitypolicy.LoadCRSManifestTx(ctx, tx)
	if err != nil {
		return rulepack.Resolution{}, err
	}
	return rulepack.CheckCRSProfile(resolution, requests, manifest, profile, exclusions), nil
}

// Site returns the published mounts of a site and its live resolution
// (final order, conflicts, warnings): the page shows both, and up_to_date
// says whether publishing would change anything.
func (s *Service) Site(ctx context.Context, actor Actor, siteID uuid.UUID) (SiteMounts, error) {
	var result SiteMounts
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		resolution, suspended, err := resolveWithSuspensions(ctx, tx, actor, siteID)
		if err != nil {
			return err
		}
		published, err := loadPublished(ctx, tx, siteID)
		if err != nil {
			return err
		}
		result = SiteMounts{SiteID: siteID, Published: published, Resolution: resolution, Suspended: suspended}
		return nil
	})
	if err != nil {
		return SiteMounts{}, err
	}
	switch {
	case result.Resolution.Security == nil:
		result.UpToDate = false
	case result.Published == nil:
		result.UpToDate = len(result.Resolution.Security.Mounts) == 0
	default:
		result.UpToDate = result.Published.Security.ResolvedSHA256 == result.Resolution.Security.ResolvedSHA256
	}
	return result, nil
}

// PublishSite writes the site's resolved security.mounts. It is refused with
// a *ConflictError (both sides, the levels they are enabled at and the
// "disable at level" remedies) while the effective mounts conflict. An
// unchanged resolution keeps the revision.
func (s *Service) PublishSite(ctx context.Context, actor Actor, siteID uuid.UUID) (SiteMounts, error) {
	record := auditRecord{scopeID: actor.ScopeID, resourceType: "site", resourceID: siteID.String(),
		payload: map[string]any{"site_id": siteID.String()}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return s.publishSite(ctx, tx, actor, siteID, &record) })
	if err != nil {
		return SiteMounts{}, s.auditDenied(ctx, actor, AuditSitePublish, record, err)
	}
	return s.Site(ctx, actor, siteID)
}

// resolveWithSuspensions resolves the site's mounts; when the resolution is
// refused only because suspended packs are still outside the site's CRS
// profile, it resolves without them (they stay suspended and are returned).
// A suspended pack the profile covers again (another version, say) is part
// of the first resolution and its suspension ends with the publication.
func resolveWithSuspensions(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID) (rulepack.Resolution,
	[]Suspension, error) {
	resolution, err := resolveSite(ctx, tx, actor, siteID, nil)
	if err != nil || resolution.Security != nil {
		return resolution, []Suspension{}, err
	}
	suspensions, err := SiteSuspensionsTx(ctx, tx, siteID)
	if err != nil || len(suspensions) == 0 {
		return resolution, []Suspension{}, err
	}
	skip := map[string]bool{}
	for _, item := range suspensions {
		skip[item.PackID] = true
	}
	for _, conflict := range resolution.Conflicts {
		if conflict.Code != rulepack.ConflictCRSOutOfProfile {
			return resolution, []Suspension{}, nil
		}
		for _, side := range conflict.Sides {
			if !skip[side.PackID] {
				return resolution, []Suspension{}, nil
			}
		}
	}
	without, err := resolveSite(ctx, tx, actor, siteID, skip)
	if err != nil || without.Security == nil {
		return resolution, []Suspension{}, err
	}
	return without, suspensions, nil
}

// publishSite is PublishSite inside tx (record collects the audit event).
func (s *Service) publishSite(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID, record *auditRecord) error {
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM sites WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, siteID).
		Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	resolution, suspended, err := resolveWithSuspensions(ctx, tx, actor, siteID)
	if err != nil {
		return err
	}
	// resolveSite checked the actor may see the site: from here on the
	// event goes to the site's tenant stream.
	if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1`, siteID).Scan(&record.scopeID); err != nil {
		return err
	}
	published, err := loadPublished(ctx, tx, siteID)
	if err != nil {
		return err
	}
	before := map[string]any{"revision": 0, "resolved_sha256": nil, "mounts": []string{}}
	if published != nil {
		before = map[string]any{"revision": published.Revision, "resolved_sha256": published.Security.ResolvedSHA256,
			"mounts": mountNames(published.Security.Mounts)}
	}
	record.payload["published"] = before
	if resolution.Security == nil {
		record.payload["conflicts"] = conflictSummary(resolution.Conflicts)
		return &ConflictError{Resolution: resolution}
	}
	// Suspensions still in force stay; the others are replaced by this publication.
	kept := make([]string, 0, len(suspended))
	for _, item := range suspended {
		kept = append(kept, item.PackID)
	}
	command, err := tx.Exec(ctx, `DELETE FROM rule_pack_mount_suspensions WHERE site_id=$1 AND NOT (pack_id = ANY($2))`,
		siteID, kept)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 0 {
		record.payload["suspensions_cleared"] = command.RowsAffected()
	}
	if len(kept) != 0 {
		record.payload["suspended"] = kept
	}
	if published != nil && published.Security.ResolvedSHA256 == resolution.Security.ResolvedSHA256 {
		// Nothing to publish: the revision stays; the request is still recorded.
		record.payload["unchanged"] = true
		return s.appendAudit(ctx, tx, actor, AuditSitePublish, *record, nil)
	}
	document, err := json.Marshal(resolution.Security)
	if err != nil {
		return err
	}
	now := s.now()
	var publishedBy *uuid.UUID
	if !actor.system {
		publishedBy = &actor.UserID
	}
	if _, err := tx.Exec(ctx, `INSERT INTO site_security_mounts(site_id,revision,security,resolved_sha256,
		published_by_user_id,published_at) VALUES($1,1,$2,$3,$4,$5)
		ON CONFLICT (site_id) DO UPDATE SET revision=site_security_mounts.revision+1, security=EXCLUDED.security,
		resolved_sha256=EXCLUDED.resolved_sha256, published_by_user_id=EXCLUDED.published_by_user_id,
		published_at=EXCLUDED.published_at`, siteID, document, resolution.Security.ResolvedSHA256,
		publishedBy, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM rule_pack_site_mount_artifacts WHERE site_id=$1`, siteID); err != nil {
		return err
	}
	for _, mount := range resolution.Security.Mounts {
		if _, err := tx.Exec(ctx, `INSERT INTO rule_pack_site_mount_artifacts(site_id,pack_id,version) VALUES($1,$2,$3)`,
			siteID, mount.PackID, mount.Version); err != nil {
			return err
		}
	}
	// The mounts are part of the site object (edgepublish reads them at
	// publication): a new revision is a new edge source revision, or the
	// scope could not be republished for it.
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, record.scopeID); err != nil {
		return fmt.Errorf("advance rule pack mounts edge source revision: %w", err)
	}
	revision := int64(1)
	if published != nil {
		revision = published.Revision + 1
	}
	record.changes = map[string]any{
		"revision":        change(before["revision"], revision),
		"resolved_sha256": change(before["resolved_sha256"], resolution.Security.ResolvedSHA256),
		"mounts":          change(before["mounts"], mountNames(resolution.Security.Mounts)),
	}
	return s.appendAudit(ctx, tx, actor, AuditSitePublish, *record, nil)
}

func loadPublished(ctx context.Context, q querier, siteID uuid.UUID) (*PublishedMounts, error) {
	var published PublishedMounts
	var document []byte
	err := q.QueryRow(ctx, `SELECT revision, security, published_at, published_by_user_id FROM site_security_mounts
		WHERE site_id=$1`, siteID).Scan(&published.Revision, &document, &published.PublishedAt, &published.PublishedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(document, &published.Security); err != nil {
		return nil, err
	}
	return &published, nil
}

// mountNames is the audit form of mounts: <pack>@<version>, in order.
func mountNames(mounts []rulepack.Mount) []string {
	out := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		out = append(out, mount.PackID+"@"+mount.Version)
	}
	return out
}

// conflictSummary is the audit form of a refused publication: per conflict
// its code and the two sides.
func conflictSummary(conflicts []rulepack.Conflict) []map[string]any {
	out := make([]map[string]any, 0, len(conflicts))
	for _, conflict := range conflicts {
		sides := make([]string, 0, len(conflict.Sides))
		for _, side := range conflict.Sides {
			name := side.PackID + "@" + side.Version
			if side.RuleID != "" {
				name += "#" + side.RuleID
			}
			sides = append(sides, name)
		}
		out = append(out, map[string]any{"code": conflict.Code, "sides": sides})
	}
	return out
}
