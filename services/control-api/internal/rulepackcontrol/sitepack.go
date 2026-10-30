package rulepackcontrol

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SitePackResult is what AddSitePack did.
type SitePackResult struct {
	PackID  string
	Version string
	Mounts  SiteMounts
}

// AddSitePack keeps compiled (a user-layer pack of the site's tenant) as a
// new version, enables it at the site level and publishes the site's
// mounts, all in tx: the three-layer resolution and conflict check of the
// rule pack page apply unchanged (a *ConflictError rolls everything back).
// Used by smart auto defense's "固化为我的规则" (ADR 0010 Q4, AD-10).
// The caller has checked the actor may manage the site; audit events
// (version create, override put, site publish) are written as usual.
func (s *Service) AddSitePack(ctx context.Context, tx pgx.Tx, actor Actor, siteID uuid.UUID, compiled *rulepack.CompiledPack,
	audit map[string]any) (SitePackResult, error) {
	pack := compiled.Pack
	owner, ok := rulepack.UserPackScope(pack.PackID)
	if !ok || pack.Layer != rulepack.LayerUser || IsSubscriptionPack(pack.PackID) {
		return SitePackResult{}, fmt.Errorf("%w: not a tenant user pack", ErrInvalidInput)
	}
	var scope uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, siteID).
		Scan(&scope); errors.Is(err, pgx.ErrNoRows) {
		return SitePackResult{}, ErrNotFound
	} else if err != nil {
		return SitePackResult{}, err
	}
	if scope.String() != owner || !mayManagePack(actor, string(pack.Layer), &scope) {
		return SitePackResult{}, ErrPermissionDenied
	}
	if _, err := AddVersion(ctx, tx, s.now(), NewVersion{Compiled: compiled, Source: "tenant", CreatedBy: actor.UserID,
		Actor: &actor, Audit: audit}); err != nil {
		return SitePackResult{}, err
	}
	// A pack this flow created is updated by this flow only: its newest
	// version is current (update_policy stays manual for the page).
	if _, err := tx.Exec(ctx, `UPDATE rule_packs SET current_version=$2, updated_by_user_id=$3, updated_at=$4 WHERE pack_id=$1`,
		pack.PackID, pack.Version, actor.UserID, s.now()); err != nil {
		return SitePackResult{}, err
	}
	override := auditRecord{scopeID: scope, resourceType: "rule_pack", resourceID: overrideResourceID(OverrideInput{
		Level: rulepack.LevelSite, LevelObjectID: &siteID, PackID: pack.PackID}), payload: map[string]any{
		"level": rulepack.LevelSite, "level_object_id": siteID.String(), "pack_id": pack.PackID, "version": pack.Version}}
	var existing uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM rule_pack_enablements WHERE level='site' AND level_object_id=$1 AND pack_id=$2
		AND rule_id IS NULL FOR UPDATE`, siteID, pack.PackID).Scan(&existing)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if _, err := tx.Exec(ctx, `INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,allow_lower,
			priority,params,updated_by_user_id,updated_at) VALUES($1,'site',$2,$3,NULL,'enabled',false,NULL,NULL,$4,$5)`,
			uuid.New(), siteID, pack.PackID, actor.UserID, s.now()); err != nil {
			return SitePackResult{}, err
		}
		override.changes = map[string]any{"state": change(rulepack.StateInherit, rulepack.StateEnabled)}
		override.payload["row_existed"] = false
	case err != nil:
		return SitePackResult{}, err
	default:
		if _, err := tx.Exec(ctx, `UPDATE rule_pack_enablements SET state='enabled', updated_by_user_id=$2, updated_at=$3 WHERE id=$1`,
			existing, actor.UserID, s.now()); err != nil {
			return SitePackResult{}, err
		}
		override.payload["row_existed"] = true
	}
	if err := s.appendAudit(ctx, tx, actor, AuditOverridePut, override, nil); err != nil {
		return SitePackResult{}, err
	}
	record := auditRecord{scopeID: scope, resourceType: "site", resourceID: siteID.String(),
		payload: map[string]any{"site_id": siteID.String()}}
	if err := s.publishSite(ctx, tx, actor, siteID, &record); err != nil {
		return SitePackResult{}, err
	}
	resolution, err := resolveSite(ctx, tx, actor, siteID, nil)
	if err != nil {
		return SitePackResult{}, err
	}
	published, err := loadPublished(ctx, tx, siteID)
	if err != nil {
		return SitePackResult{}, err
	}
	return SitePackResult{PackID: pack.PackID, Version: pack.Version, Mounts: SiteMounts{SiteID: siteID, Published: published,
		Resolution: resolution, UpToDate: true}}, nil
}
