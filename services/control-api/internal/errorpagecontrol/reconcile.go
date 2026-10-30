package errorpagecontrol

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const abandonedInitiationAge = time.Hour

type reconcileCursor struct {
	UpdatedAt time.Time
	ID        uuid.UUID
}

func (s *Service) ReconcileAssets(ctx context.Context, limit int) (int, error) {
	if limit == 0 {
		limit = defaultReconcilePageSize
	}
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidInput
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	if s.reconcileCeiling.ID == uuid.Nil {
		ceiling, err := s.reconcileUpperBound(ctx)
		if err != nil {
			return 0, err
		}
		s.reconcileCeiling = ceiling
		if ceiling.ID == uuid.Nil {
			return 0, nil
		}
	}
	assets, err := s.listReconcileAssets(ctx, limit, s.reconcileCursor, s.reconcileCeiling)
	if err != nil {
		return 0, err
	}
	if len(assets) == 0 {
		s.reconcileCursor = reconcileCursor{}
		s.reconcileCeiling = reconcileCursor{}
		ceiling, err := s.reconcileUpperBound(ctx)
		if err != nil {
			return 0, err
		}
		s.reconcileCeiling = ceiling
		if ceiling.ID == uuid.Nil {
			return 0, nil
		}
		assets, err = s.listReconcileAssets(ctx, limit, s.reconcileCursor, s.reconcileCeiling)
		if err != nil {
			return 0, err
		}
	}
	if len(assets) > 0 {
		last := assets[len(assets)-1]
		s.reconcileCursor = reconcileCursor{UpdatedAt: last.UpdatedAt, ID: last.ID}
	}
	completed := 0
	var firstErr error
	for _, asset := range assets {
		if err := ctx.Err(); err != nil {
			return completed, err
		}
		changed, err := s.reconcileAsset(ctx, asset)
		if err != nil {
			if ctx.Err() != nil {
				return completed, ctx.Err()
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if changed {
			completed++
		}
	}
	return completed, firstErr
}

func (s *Service) reconcileUpperBound(ctx context.Context) (reconcileCursor, error) {
	var ceiling reconcileCursor
	err := s.pool.QueryRow(ctx, `SELECT updated_at,id FROM error_page_assets
		WHERE status IN ('initiated','finalizing','rejected','delete_pending')
		  AND NOT (status='rejected' AND object_state='absent')
		ORDER BY updated_at DESC,id DESC LIMIT 1`).Scan(&ceiling.UpdatedAt, &ceiling.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return reconcileCursor{}, nil
	}
	if err != nil {
		return reconcileCursor{}, fmt.Errorf("read error page reconciliation upper bound: %w", err)
	}
	return ceiling, nil
}

func (s *Service) listReconcileAssets(
	ctx context.Context,
	limit int,
	cursor reconcileCursor,
	ceiling reconcileCursor,
) ([]Asset, error) {
	query := `SELECT ` + assetColumns + ` FROM error_page_assets
		WHERE status IN ('initiated','finalizing','rejected','delete_pending')
		  AND NOT (status='rejected' AND object_state='absent')
		  AND (updated_at,id) <= ($2,$3)`
	args := []any{limit, ceiling.UpdatedAt, ceiling.ID}
	if cursor.ID != uuid.Nil && !cursor.UpdatedAt.IsZero() {
		query += ` AND (updated_at,id) > ($4,$5)`
		args = append(args, cursor.UpdatedAt, cursor.ID)
	}
	query += ` ORDER BY updated_at,id LIMIT $1`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list error page reconciliation work: %w", err)
	}
	defer rows.Close()
	assets := make([]Asset, 0, limit)
	for rows.Next() {
		asset, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return assets, nil
}

func (s *Service) reconcileAsset(ctx context.Context, asset Asset) (bool, error) {
	switch asset.Status {
	case StatusInitiated:
		info, err := s.content.Stat(ctx, assetObjectRef(asset, asset.stagingObjectKey))
		if err == nil {
			if validateObjectInfo(asset, info) != nil {
				if err := deleteObject(ctx, s.content, assetObjectRef(asset, asset.stagingObjectKey)); err != nil {
					return false, wrapUnavailable("clean invalid staged error page object", err)
				}
				return s.reconcileTransition(ctx, asset, StatusOrphaned, "absent", "failure", "staging_metadata_mismatch")
			}
			if _, _, err := s.readStagedAsset(ctx, asset); err != nil {
				return false, err
			}
			return s.reconcileTransition(ctx, asset, StatusStaged, "staging", "success", "staging_recovered")
		}
		if !errors.Is(err, ErrObjectNotFound) {
			return false, wrapUnavailable("stat initiated error page object", err)
		}
		if storeTime(s.now()).Sub(asset.UpdatedAt) < abandonedInitiationAge {
			return false, nil
		}
		return s.reconcileTransition(ctx, asset, StatusOrphaned, "absent", "success", "abandoned_initiation")
	case StatusFinalizing:
		_, staged, err := s.readStagedAsset(ctx, asset)
		if err != nil {
			if factErr := s.recordReconcileFailure(ctx, asset, "staging_integrity_failed"); factErr != nil {
				return false, wrapUnavailable("record staging integrity failure", factErr)
			}
			return false, err
		}
		if err := s.verifyPassedScanToken(ctx, asset, staged.ImmutableToken); err != nil {
			if factErr := s.recordReconcileFailure(ctx, asset, "scan_token_mismatch"); factErr != nil {
				return false, wrapUnavailable("record scan token mismatch", factErr)
			}
			return false, err
		}
		final, err := s.content.Finalize(ctx, assetObjectRef(asset, asset.stagingObjectKey),
			assetObjectRef(asset, asset.storageObjectKey), staged)
		if err != nil {
			if factErr := s.recordReconcileFailure(ctx, asset, "conditional_finalize_failed"); factErr != nil {
				return false, wrapUnavailable("record conditional finalize failure", factErr)
			}
			if errors.Is(err, ErrConflict) || errors.Is(err, ErrObjectNotFound) {
				return false, ErrConflict
			}
			return false, wrapUnavailable("recover error page finalize", err)
		}
		if err := s.verifyFinalObject(ctx, asset, staged, final); err != nil {
			if factErr := s.recordReconcileFailure(ctx, asset, "final_integrity_failed"); factErr != nil {
				return false, wrapUnavailable("record final integrity failure", factErr)
			}
			return false, err
		}
		return s.reconcileTransition(ctx, asset, StatusReady, "final", "success", "finalize_recovered")
	case StatusRejected:
		if asset.objectState == "absent" {
			return false, nil
		}
		if err := deleteObject(ctx, s.content, assetObjectRef(asset, asset.stagingObjectKey)); err != nil {
			return false, wrapUnavailable("clean rejected error page object", err)
		}
		return s.reconcileTransition(ctx, asset, StatusRejected, "absent", "success", "rejected_staging_removed")
	case StatusDeletePending:
		if err := deleteObject(ctx, s.content, assetObjectRef(asset, asset.stagingObjectKey)); err != nil {
			return false, wrapUnavailable("clean staged error page object", err)
		}
		if err := deleteObject(ctx, s.content, assetObjectRef(asset, asset.storageObjectKey)); err != nil {
			return false, wrapUnavailable("clean final error page object", err)
		}
		return s.reconcileTransition(ctx, asset, StatusDeleted, "absent", "success", "delete_completed")
	default:
		return false, nil
	}
}

func (s *Service) verifyPassedScanToken(ctx context.Context, asset Asset, immutableToken string) error {
	var tokenDigest string
	err := s.pool.QueryRow(ctx, `SELECT payload->>'immutability_token_sha256'
		FROM audit_events WHERE scope_id=$1 AND action='error_page.asset.scan'
		  AND resource_type='error_page_asset' AND resource_id=$2 AND result='success'
		ORDER BY stream_position DESC LIMIT 1`, asset.ScopeID, asset.ID.String()).Scan(&tokenDigest)
	if errors.Is(err, pgx.ErrNoRows) || tokenDigest != digestBytes([]byte(immutableToken)) {
		return ErrConflict
	}
	return err
}

func (s *Service) recordReconcileFailure(ctx context.Context, asset Asset, reason string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := loadAsset(ctx, tx, asset.ID, true)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Revision != asset.Revision || current.Status != asset.Status {
			return nil
		}
		var recorded bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM audit_events
			WHERE scope_id=$1 AND action='error_page.asset.reconcile'
			  AND resource_type='error_page_asset' AND resource_id=$2 AND result='failure'
			  AND payload->>'reason'=$3 AND payload->>'asset_revision'=$4
		)`, asset.ScopeID, asset.ID.String(), reason, strconv.FormatInt(asset.Revision, 10)).Scan(&recorded); err != nil {
			return err
		}
		if recorded {
			return nil
		}
		requestID := "reconcile-" + uuid.NewString()
		metadata := WriteMetadata{RequestID: requestID, TraceID: requestID}
		return s.appendAudit(ctx, tx, nil, asset.ScopeID, "error_page.asset.reconcile",
			"error_page_asset", asset.ID.String(), metadata, "failure", map[string]any{
				"from_status": asset.Status, "to_status": asset.Status, "reason": reason,
				"asset_revision": asset.Revision,
			})
	})
}

func (s *Service) reconcileTransition(
	ctx context.Context,
	expected Asset,
	status, objectState, result, reason string,
) (bool, error) {
	changed := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := loadAsset(ctx, tx, expected.ID, true)
		if err != nil {
			return err
		}
		if current.Revision != expected.Revision || current.Status != expected.Status {
			return nil
		}
		if status == StatusReady {
			if _, err := s.entitlementLimits(ctx, tx, EntitlementCheck{
				Operation: operationAssetReconcile, ScopeID: current.ScopeID, ResourceID: current.ID,
				PrincipalKind: entitlementPrincipalSystem, PrincipalID: errorPageReconcilerPrincipal,
				Expands: true,
			}); err != nil {
				return err
			}
		}
		now := storeTime(s.now())
		deletedAt := any(current.DeletedAt)
		scanStatus := current.ScanStatus
		if status == StatusOrphaned || status == StatusDeleted {
			deletedAt = now
		}
		command, err := tx.Exec(ctx, `UPDATE error_page_assets SET
			status=$2,scan_status=$3,object_state=$4,revision=revision+1,updated_at=$5,deleted_at=$6
			WHERE id=$1 AND revision=$7 AND status=$8`, current.ID, status, scanStatus, objectState,
			now, deletedAt, current.Revision, current.Status)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return nil
		}
		requestID := "reconcile-" + uuid.NewString()
		metadata := WriteMetadata{RequestID: requestID, TraceID: requestID}
		if err := s.appendAudit(ctx, tx, nil, current.ScopeID, "error_page.asset.reconcile",
			"error_page_asset", current.ID.String(), metadata, result, map[string]any{
				"from_status": current.Status, "to_status": status, "reason": reason,
			}); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("reconcile error page asset %s: %w", expected.ID, err)
	}
	return changed, nil
}

func deleteObject(ctx context.Context, store ContentStore, ref ObjectRef) error {
	err := store.Delete(ctx, ref)
	if errors.Is(err, ErrObjectNotFound) {
		return nil
	}
	return err
}
