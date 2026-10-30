package rulepackcontrol

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Default-on official packs (migration 454; every
// official free pack since migration 544): a site's
// mounts are otherwise computed only when its owner publishes them
// (PublishSite), so a pack enabled at platform level would reach no site
// that never published. RecomputeDefaultOnMountsTx publishes, as the control
// plane, the mounts of sites whose resolution changed; the caller then
// republishes the returned scopes through the system republication channel
// (edgeautopublish, trigger rule_catalog), FromRevision marking the source
// revision advances as the system's own.
//
// A site whose resolution conflicts keeps its published mounts (its owner
// sees the conflict on the rule pack page); a suspended mount stays
// suspended (resolveWithSuspensions).

// DefaultOnScope is one scope whose sites' mounts the recompute changed.
// FromRevision is its source revision before (0: never published).
type DefaultOnScope struct {
	ScopeID      uuid.UUID
	FromRevision int64
}

// defaultOnPacksSQL selects the default-on packs in force: system packs the
// platform level enables (the control plane's own row, or the
// administrator's).
const defaultOnPacksSQL = `SELECT enabled.pack_id FROM rule_pack_enablements enabled
	JOIN rule_packs pack ON pack.pack_id=enabled.pack_id AND pack.layer='system'
	WHERE enabled.level='platform' AND enabled.rule_id IS NULL AND enabled.state='enabled'`

// DefaultOnSitesTx lists the live tenant sites to recompute: all of them
// when all is set (a default-on pack arrived or changed version), else
// those without published mounts (sites created since) that did not switch
// every default-on pack off at tenant or site level (they would resolve to
// nothing again on every run).
func DefaultOnSitesTx(ctx context.Context, tx pgx.Tx, all bool) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT site.id FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		WHERE site.deleted_at IS NULL AND ($1 OR NOT EXISTS (SELECT 1 FROM site_security_mounts mount WHERE mount.site_id=site.id)
		  AND EXISTS (SELECT 1 FROM (`+defaultOnPacksSQL+`) pack WHERE NOT EXISTS (
		    SELECT 1 FROM rule_pack_enablements off WHERE off.rule_id IS NULL AND off.state='disabled'
		    AND off.pack_id=pack.pack_id AND (off.level='tenant' AND off.level_object_id=site.scope_id OR
		      off.level='site' AND off.level_object_id=site.id))))
		ORDER BY site.scope_id, site.id`, all)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// DefaultOnPackEnabledTx reports whether a system pack is enabled at
// platform level (the only level the recompute follows: a tenant or site
// that switched it off resolves without it anyway).
func DefaultOnPackEnabledTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (`+defaultOnPacksSQL+`)`).Scan(&enabled)
	return enabled, err
}

// RecomputeDefaultOnMountsTx publishes the current resolution of each site
// (sites in scope order; system actor: no user, audit rule.pack.site.publish
// with reason default_on_pack) and returns the scopes whose mounts changed.
func (s *Service) RecomputeDefaultOnMountsTx(ctx context.Context, tx pgx.Tx, siteIDs []uuid.UUID, requestID string) ([]DefaultOnScope, error) {
	actor := Actor{system: true, ScopeKind: "platform", RequestID: requestID}
	var changed []DefaultOnScope
	locked := map[uuid.UUID]int64{}
	for _, siteID := range siteIDs {
		var scopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1 AND deleted_at IS NULL`, siteID).
			Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
			continue
		} else if err != nil {
			return nil, err
		}
		from, ok := locked[scopeID]
		if !ok {
			// Publication lock order: the scope's configuration row first.
			err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
				scopeID).Scan(&from)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			locked[scopeID] = from
		}
		// Only a resolution that differs from what the site published is
		// written: every write advances the scope's source revision, and an
		// advance nobody republishes would block later system republications.
		before, err := loadPublished(ctx, tx, siteID)
		if err != nil {
			return nil, err
		}
		resolution, _, err := resolveWithSuspensions(ctx, tx, actor, siteID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		switch {
		case resolution.Security == nil: // conflict: the owner resolves it
			continue
		case before == nil && len(resolution.Security.Mounts) == 0:
			continue
		case before != nil && before.Security.ResolvedSHA256 == resolution.Security.ResolvedSHA256:
			continue
		}
		record := auditRecord{resourceType: "site", resourceID: siteID.String(),
			payload: map[string]any{"site_id": siteID.String(), "reason": "default_on_pack"}}
		if err := s.publishSite(ctx, tx, actor, siteID, &record); err != nil {
			return nil, err
		}
		if len(changed) == 0 || changed[len(changed)-1].ScopeID != scopeID {
			changed = append(changed, DefaultOnScope{ScopeID: scopeID, FromRevision: from})
		}
	}
	return changed, nil
}
