package errorpagecontrol

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) InitiateAsset(ctx context.Context, actor Actor, request InitiateAssetRequest) (WriteResult[Asset], error) {
	if err := validateActor(actor); err != nil {
		return WriteResult[Asset]{}, err
	}
	if err := validateWriteMetadata(request.WriteMetadata); err != nil || request.Target.ScopeID == uuid.Nil && actor.ScopeKind == "platform" ||
		!ValidAssetName(request.Name) {
		return WriteResult[Asset]{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		Target AssetTarget `json:"target"`
		Name   string      `json:"name,omitempty"`
		MIME   string      `json:"mime"`
		Size   int64       `json:"size"`
		SHA256 string      `json:"sha256"`
	}{request.Target, request.Name, request.MIME, request.Size, request.SHA256})
	if err != nil {
		return WriteResult[Asset]{}, err
	}
	var result Asset
	var replayed bool
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeActor(ctx, tx, actor,
			authorizationTarget(actor, request.Target.ScopeID), permissionManage); err != nil {
			return err
		}
		target, err := resolveTargetScope(ctx, tx, actor, request.Target.ScopeID)
		if err != nil {
			return err
		}
		limits, err := s.checkEntitlement(ctx, tx, actor, EntitlementCheck{
			Operation: operationAssetInitiate, ScopeID: target.ID, RequestID: request.RequestID, Expands: true,
		})
		if err != nil {
			return err
		}
		stored, exists, err := s.claimWrite(ctx, tx, actor, target.ID, operationAssetInitiate, request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if exists {
			decoded, err := decodeReplay[Asset](stored)
			if err != nil {
				return err
			}
			result, replayed = decoded.Value, true
			return nil
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "error-page-assets:"+target.ID.String()); err != nil {
			return err
		}
		quota := limits.AssetQuota
		if err := validateAssetMetadata(request.MIME, request.Size, request.SHA256, quota.MaxAssetBytes); err != nil {
			return err
		}
		var count, total int64
		if err := tx.QueryRow(ctx, `
			SELECT count(*),COALESCE(sum(size_bytes),0)
			FROM error_page_assets
			WHERE scope_id=$1 AND status NOT IN ('rejected','deleted','orphaned')`, target.ID).
			Scan(&count, &total); err != nil {
			return err
		}
		if count+1 > quota.MaxAssets || total+request.Size > quota.MaxTotalBytes {
			return ErrQuotaExceeded
		}
		assetID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		stagingKey := "error-pages/staging/" + assetID.String()
		objectKey := "error-pages/objects/" + target.ID.String() + "/" + request.SHA256
		now := storeTime(s.now())
		_, err = tx.Exec(ctx, `
			INSERT INTO error_page_assets (
				id,scope_id,tenant_id,mime_type,size_bytes,sha256,staging_object_key,storage_object_key,
				status,scan_status,object_state,created_by_user_id,created_by_scope_id,
				created_request_id,created_trace_id,created_at,updated_at,name
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'initiated','pending','none',$9,$10,$11,$12,$13,$13,$14)`,
			assetID, target.ID, target.TenantID, request.MIME, request.Size, decodeSHA256(request.SHA256),
			stagingKey, objectKey, actor.UserID, actor.ScopeID, request.RequestID, request.TraceID, now, request.Name)
		if err != nil {
			if sqlState(err) == "23505" {
				return ErrConflict
			}
			return err
		}
		result, err = loadAsset(ctx, tx, assetID, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor, target.ID, operationAssetInitiate, "error_page_asset",
			assetID.String(), request.WriteMetadata, "success", map[string]any{
				"mime_type": request.MIME, "size_bytes": request.Size, "sha256": request.SHA256, "name": request.Name,
			}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationAssetInitiate, request.WriteMetadata, assetID, 201, result)
	})
	if err != nil {
		return WriteResult[Asset]{}, fmt.Errorf("initiate error page asset: %w", err)
	}
	return WriteResult[Asset]{Value: result, Replayed: replayed}, nil
}

func (s *Service) UploadAsset(ctx context.Context, actor Actor, request UploadAssetRequest) (WriteResult[Asset], error) {
	if err := validateActor(actor); err != nil {
		return WriteResult[Asset]{}, err
	}
	if request.AssetID == uuid.Nil || request.Body == nil || !validMIME(request.MIMEType) ||
		request.ContentLength < 1 || request.ContentLength > MaxEdgeResourceBytes ||
		validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[Asset]{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		AssetID       uuid.UUID `json:"asset_id"`
		MIMEType      string    `json:"mime_type"`
		ContentLength int64     `json:"content_length"`
	}{request.AssetID, request.MIMEType, request.ContentLength})
	asset, replay, err := s.claimAssetOperation(ctx, actor, request.AssetID, operationAssetUpload, request.WriteMetadata, digest)
	if err != nil {
		return WriteResult[Asset]{}, fmt.Errorf("claim error page upload: %w", err)
	}
	if replay != nil {
		return *replay, nil
	}
	if asset.Status != StatusInitiated && asset.Status != StatusStaged {
		return WriteResult[Asset]{}, ErrConflict
	}
	if request.MIMEType != asset.MIMEType || request.ContentLength != asset.SizeBytes {
		return WriteResult[Asset]{}, ErrInvalidInput
	}
	info, statErr := s.content.Stat(ctx, assetObjectRef(asset, asset.stagingObjectKey))
	if statErr == nil {
		if err := validateObjectInfo(asset, info); err != nil {
			return WriteResult[Asset]{}, ErrConflict
		}
		return s.finishUpload(ctx, actor, request, asset)
	}
	if !errors.Is(statErr, ErrObjectNotFound) {
		return WriteResult[Asset]{}, wrapUnavailable("stat staged error page object", statErr)
	}
	body, err := readBounded(request.Body, asset.SizeBytes)
	if err != nil || int64(len(body)) != asset.SizeBytes || digestBytes(body) != asset.SHA256 {
		return WriteResult[Asset]{}, ErrInvalidInput
	}
	if err := validateStaticBody(asset.MIMEType, body); err != nil {
		return WriteResult[Asset]{}, err
	}
	info, err = s.content.PutStaging(ctx, assetObjectRef(asset, asset.stagingObjectKey), body, asset.MIMEType)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return WriteResult[Asset]{}, ErrConflict
		}
		return WriteResult[Asset]{}, wrapUnavailable("stage error page object", err)
	}
	if err := validateObjectInfo(asset, info); err != nil {
		return WriteResult[Asset]{}, ErrConflict
	}
	return s.finishUpload(ctx, actor, request, asset)
}

func (s *Service) claimAssetOperation(
	ctx context.Context,
	actor Actor,
	assetID uuid.UUID,
	operation string,
	metadata WriteMetadata,
	digest [32]byte,
) (Asset, *WriteResult[Asset], error) {
	var asset Asset
	var replay *WriteResult[Asset]
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, found, err := assetScopeForAuthorization(ctx, tx, actor, assetID)
		if err != nil {
			return err
		}
		if err := s.authorizeActor(ctx, tx, actor, targetScopeID, permissionManage); err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		asset, err = loadAssetForActor(ctx, tx, actor, assetID, false)
		if err != nil {
			return err
		}
		if _, err := s.checkEntitlement(ctx, tx, actor, EntitlementCheck{
			Operation: operation, ScopeID: asset.ScopeID, ResourceID: asset.ID,
			RequestID: metadata.RequestID, Expands: true,
		}); err != nil {
			return err
		}
		stored, exists, err := s.claimWrite(ctx, tx, actor, asset.ScopeID, operation, metadata, digest)
		if err != nil {
			return err
		}
		if exists && stored.Completed {
			decoded, err := decodeReplay[Asset](stored)
			if err != nil {
				return err
			}
			replay = &decoded
		}
		return nil
	})
	return asset, replay, err
}

func (s *Service) finishUpload(ctx context.Context, actor Actor, request UploadAssetRequest, expected Asset) (WriteResult[Asset], error) {
	var result Asset
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeActor(ctx, tx, actor, expected.ScopeID, permissionManage); err != nil {
			return err
		}
		current, err := loadAssetForActor(ctx, tx, actor, request.AssetID, true)
		if err != nil {
			return err
		}
		if _, err := s.checkEntitlement(ctx, tx, actor, EntitlementCheck{
			Operation: operationAssetUpload, ScopeID: current.ScopeID, ResourceID: current.ID,
			RequestID: request.RequestID, Expands: true,
		}); err != nil {
			return err
		}
		stored, err := findWrite(ctx, tx, actor, operationAssetUpload,
			request.IdempotencyKey, request.RequestID)
		if err != nil {
			return err
		}
		if stored.Completed {
			decoded, err := decodeReplay[Asset](stored)
			if err != nil {
				return err
			}
			result, replayed = decoded.Value, true
			return nil
		}
		if current.SHA256 != expected.SHA256 || current.SizeBytes != expected.SizeBytes {
			return ErrConflict
		}
		if current.Status == StatusInitiated {
			now := storeTime(s.now())
			if _, err := tx.Exec(ctx, `UPDATE error_page_assets
				SET status='staged',object_state='staging',revision=revision+1,updated_at=$2
				WHERE id=$1 AND status='initiated'`, current.ID, now); err != nil {
				return err
			}
			current, err = loadAsset(ctx, tx, current.ID, false)
			if err != nil {
				return err
			}
			if err := s.appendAudit(ctx, tx, &actor, current.ScopeID, operationAssetUpload,
				"error_page_asset", current.ID.String(), request.WriteMetadata, "success",
				map[string]any{"revision": current.Revision, "sha256": current.SHA256}); err != nil {
				return err
			}
		} else if current.Status != StatusStaged {
			return ErrConflict
		}
		result = current
		return s.completeWrite(ctx, tx, actor, operationAssetUpload, request.WriteMetadata, current.ID, 200, current)
	})
	if err != nil {
		return WriteResult[Asset]{}, fmt.Errorf("complete error page upload: %w", err)
	}
	return WriteResult[Asset]{Value: result, Replayed: replayed}, nil
}

func (s *Service) FinalizeAsset(ctx context.Context, actor Actor, request FinalizeAssetRequest) (WriteResult[Asset], error) {
	if err := validateActor(actor); err != nil {
		return WriteResult[Asset]{}, err
	}
	if request.AssetID == uuid.Nil || validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[Asset]{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		AssetID uuid.UUID `json:"asset_id"`
	}{request.AssetID})
	asset, replay, err := s.claimAssetOperation(ctx, actor, request.AssetID, operationAssetFinalize, request.WriteMetadata, digest)
	if err != nil {
		return WriteResult[Asset]{}, fmt.Errorf("claim error page finalize: %w", err)
	}
	if replay != nil {
		return *replay, nil
	}
	if asset.Status == StatusRejected {
		return WriteResult[Asset]{}, ErrScanRejected
	}
	if asset.Status == StatusReady {
		_, staged, err := s.readStagedAsset(ctx, asset)
		if err != nil {
			return WriteResult[Asset]{}, err
		}
		final, err := s.content.Stat(ctx, assetObjectRef(asset, asset.storageObjectKey))
		if err != nil {
			return WriteResult[Asset]{}, wrapUnavailable("stat final error page object", err)
		}
		if err := s.verifyFinalObject(ctx, asset, staged, final); err != nil {
			return WriteResult[Asset]{}, err
		}
		return s.completeReadyFinalize(ctx, actor, request, staged.ImmutableToken)
	}
	var expectedStaged ObjectInfo
	if asset.Status == StatusStaged || asset.Status == StatusScanFailed {
		body, staged, err := s.readStagedAsset(ctx, asset)
		if err != nil {
			return WriteResult[Asset]{}, err
		}
		scanErr := s.scanner.Scan(ctx, ScanInput{
			AssetID: asset.ID, MIMEType: asset.MIMEType, Size: asset.SizeBytes,
			SHA256: asset.SHA256, ImmutableToken: staged.ImmutableToken, Body: bytes.NewReader(body),
		})
		result := "passed"
		code := ""
		nextStatus := StatusFinalizing
		if errors.Is(scanErr, ErrScanRejected) {
			result, code, nextStatus = "rejected", "malicious_content", StatusRejected
		} else if scanErr != nil {
			result, code, nextStatus = "error", "scanner_unavailable", StatusScanFailed
		}
		recordContext := ctx
		var cancel context.CancelFunc
		if ctx.Err() != nil {
			recordContext, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		if err := s.recordScan(recordContext, actor, request.WriteMetadata, asset.ID, result, code,
			nextStatus, staged.ImmutableToken); err != nil {
			return WriteResult[Asset]{}, err
		}
		if result == "rejected" {
			return WriteResult[Asset]{}, ErrScanRejected
		}
		if result == "error" {
			return WriteResult[Asset]{}, ErrUnavailable
		}
		expectedStaged = staged
		asset.Status = StatusFinalizing
	}
	if asset.Status != StatusFinalizing {
		return WriteResult[Asset]{}, ErrConflict
	}
	if expectedStaged.ImmutableToken == "" {
		_, expectedStaged, err = s.readStagedAsset(ctx, asset)
		if err != nil {
			return WriteResult[Asset]{}, err
		}
	}
	final, err := s.content.Finalize(ctx, assetObjectRef(asset, asset.stagingObjectKey),
		assetObjectRef(asset, asset.storageObjectKey), expectedStaged)
	if err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrObjectNotFound) {
			return WriteResult[Asset]{}, ErrConflict
		}
		return WriteResult[Asset]{}, wrapUnavailable("finalize error page object", err)
	}
	if err := s.verifyFinalObject(ctx, asset, expectedStaged, final); err != nil {
		return WriteResult[Asset]{}, err
	}
	return s.completeReadyFinalize(ctx, actor, request, expectedStaged.ImmutableToken)
}

func (s *Service) readStagedAsset(ctx context.Context, asset Asset) ([]byte, ObjectInfo, error) {
	info, err := s.content.Stat(ctx, assetObjectRef(asset, asset.stagingObjectKey))
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			return nil, ObjectInfo{}, ErrConflict
		}
		return nil, ObjectInfo{}, wrapUnavailable("stat staged error page object", err)
	}
	if err := validateObjectInfo(asset, info); err != nil {
		return nil, ObjectInfo{}, ErrConflict
	}
	reader, err := s.content.Open(ctx, assetObjectRef(asset, asset.stagingObjectKey), info.ImmutableToken)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			return nil, ObjectInfo{}, ErrConflict
		}
		return nil, ObjectInfo{}, wrapUnavailable("open staged error page object", err)
	}
	defer reader.Close()
	body, err := readBounded(reader, asset.SizeBytes)
	if err != nil || int64(len(body)) != asset.SizeBytes || digestBytes(body) != asset.SHA256 {
		return nil, ObjectInfo{}, ErrConflict
	}
	if err := validateStaticBody(asset.MIMEType, body); err != nil {
		return nil, ObjectInfo{}, err
	}
	return body, info, nil
}

func validateObjectInfo(asset Asset, info ObjectInfo) error {
	if info.Size != asset.SizeBytes || info.SHA256 != asset.SHA256 ||
		info.MIMEType != asset.MIMEType || !writeMetadataPattern.MatchString(info.ImmutableToken) {
		return ErrConflict
	}
	return nil
}

func (s *Service) verifyFinalObject(
	ctx context.Context,
	asset Asset,
	staged ObjectInfo,
	finalized ObjectInfo,
) error {
	if validateObjectInfo(asset, finalized) != nil || finalized.ImmutableToken != staged.ImmutableToken {
		return ErrConflict
	}
	stagedAfter, err := s.content.Stat(ctx, assetObjectRef(asset, asset.stagingObjectKey))
	if err != nil {
		return wrapUnavailable("stat preserved staged error page object", err)
	}
	if validateObjectInfo(asset, stagedAfter) != nil || stagedAfter.ImmutableToken != staged.ImmutableToken {
		return ErrConflict
	}
	final, err := s.content.Stat(ctx, assetObjectRef(asset, asset.storageObjectKey))
	if err != nil {
		return wrapUnavailable("stat final error page object", err)
	}
	if validateObjectInfo(asset, final) != nil || final.ImmutableToken != staged.ImmutableToken {
		return ErrConflict
	}
	reader, err := s.content.Open(ctx, assetObjectRef(asset, asset.storageObjectKey), staged.ImmutableToken)
	if err != nil {
		return wrapUnavailable("open final error page object", err)
	}
	defer reader.Close()
	body, err := readBounded(reader, asset.SizeBytes)
	if err != nil || int64(len(body)) != asset.SizeBytes || digestBytes(body) != asset.SHA256 {
		return ErrConflict
	}
	return validateStaticBody(asset.MIMEType, body)
}

func assetObjectRef(asset Asset, logicalKey string) ObjectRef {
	return ObjectRef{TenantID: asset.TenantID, ScopeID: asset.ScopeID, LogicalKey: logicalKey}
}

func (s *Service) recordScan(
	ctx context.Context,
	actor Actor,
	metadata WriteMetadata,
	assetID uuid.UUID,
	result, code, nextStatus string,
	immutableToken string,
) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, found, err := assetScopeForAuthorization(ctx, tx, actor, assetID)
		if err != nil {
			return err
		}
		if err := s.authorizeActor(ctx, tx, actor, targetScopeID, permissionManage); err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		asset, err := loadAssetForActor(ctx, tx, actor, assetID, true)
		if err != nil {
			return err
		}
		if _, err := s.checkEntitlement(ctx, tx, actor, EntitlementCheck{
			Operation: operationAssetFinalize, ScopeID: asset.ScopeID, ResourceID: asset.ID,
			RequestID: metadata.RequestID, Expands: true,
		}); err != nil {
			return err
		}
		if asset.Status != StatusStaged && asset.Status != StatusScanFailed {
			if asset.Status == StatusFinalizing && result == "passed" {
				return nil
			}
			return ErrConflict
		}
		var attempt int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(attempt),0)+1
			FROM error_page_asset_scan_facts WHERE asset_id=$1`, asset.ID).Scan(&attempt); err != nil {
			return err
		}
		factID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var errorCode any
		if code != "" {
			errorCode = code
		}
		now := storeTime(s.now())
		_, err = tx.Exec(ctx, `INSERT INTO error_page_asset_scan_facts (
			id,asset_id,attempt,scanner,result,content_size,content_sha256,error_code,request_id,trace_id,scanned_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, factID, asset.ID, attempt,
			s.scanner.Name(), result, asset.SizeBytes, decodeSHA256(asset.SHA256), errorCode,
			metadata.RequestID, metadata.TraceID, now)
		if err != nil {
			return err
		}
		scanStatus := result
		objectState := "staging"
		var deletedAt any
		if nextStatus == StatusRejected {
			objectState, deletedAt = "cleanup_pending", now
		}
		_, err = tx.Exec(ctx, `UPDATE error_page_assets SET
			status=$2,scan_status=$3,object_state=$4,revision=revision+1,updated_at=$5,deleted_at=$6
			WHERE id=$1`, asset.ID, nextStatus, scanStatus, objectState, now, deletedAt)
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, &actor, asset.ScopeID, "error_page.asset.scan",
			"error_page_asset", asset.ID.String(), metadata, mapScanResult(result), map[string]any{
				"scanner": s.scanner.Name(), "scan_result": result, "error_code": code, "attempt": attempt,
				"immutability_token_sha256": digestBytes([]byte(immutableToken)),
			})
	})
}

func (s *Service) completeReadyFinalize(
	ctx context.Context,
	actor Actor,
	request FinalizeAssetRequest,
	immutableToken string,
) (WriteResult[Asset], error) {
	var result Asset
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, found, err := assetScopeForAuthorization(ctx, tx, actor, request.AssetID)
		if err != nil {
			return err
		}
		if err := s.authorizeActor(ctx, tx, actor, targetScopeID, permissionManage); err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		asset, err := loadAssetForActor(ctx, tx, actor, request.AssetID, true)
		if err != nil {
			return err
		}
		if _, err := s.checkEntitlement(ctx, tx, actor, EntitlementCheck{
			Operation: operationAssetFinalize, ScopeID: asset.ScopeID, ResourceID: asset.ID,
			RequestID: request.RequestID, Expands: true,
		}); err != nil {
			return err
		}
		stored, err := findWrite(ctx, tx, actor, operationAssetFinalize,
			request.IdempotencyKey, request.RequestID)
		if err != nil {
			return err
		}
		if stored.Completed {
			decoded, err := decodeReplay[Asset](stored)
			if err != nil {
				return err
			}
			result, replayed = decoded.Value, true
			return nil
		}
		if asset.Status == StatusFinalizing {
			var tokenDigest string
			if err := tx.QueryRow(ctx, `SELECT payload->>'immutability_token_sha256'
				FROM audit_events WHERE scope_id=$1 AND action='error_page.asset.scan'
				  AND resource_type='error_page_asset' AND resource_id=$2 AND result='success'
				ORDER BY stream_position DESC LIMIT 1`, asset.ScopeID, asset.ID.String()).Scan(&tokenDigest); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrConflict
				}
				return err
			}
			if tokenDigest != digestBytes([]byte(immutableToken)) {
				return ErrConflict
			}
			now := storeTime(s.now())
			command, err := tx.Exec(ctx, `UPDATE error_page_assets SET
				status='ready',object_state='final',revision=revision+1,updated_at=$2
				WHERE id=$1 AND status='finalizing'`, asset.ID, now)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrConflict
			}
			asset, err = loadAsset(ctx, tx, asset.ID, false)
			if err != nil {
				return err
			}
			if err := s.appendAudit(ctx, tx, &actor, asset.ScopeID, operationAssetFinalize,
				"error_page_asset", asset.ID.String(), request.WriteMetadata, "success",
				map[string]any{"revision": asset.Revision, "sha256": asset.SHA256}); err != nil {
				return err
			}
		} else if asset.Status != StatusReady {
			return ErrConflict
		}
		result = asset
		return s.completeWrite(ctx, tx, actor, operationAssetFinalize, request.WriteMetadata, asset.ID, 200, asset)
	})
	if err != nil {
		return WriteResult[Asset]{}, fmt.Errorf("complete error page finalize: %w", err)
	}
	return WriteResult[Asset]{Value: result, Replayed: replayed}, nil
}

func (s *Service) DeleteAsset(ctx context.Context, actor Actor, request DeleteAssetRequest) (WriteResult[Asset], error) {
	if validateActor(actor) != nil || request.AssetID == uuid.Nil || request.ExpectedRevision < 1 ||
		validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[Asset]{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		AssetID  uuid.UUID `json:"asset_id"`
		Revision int64     `json:"expected_revision"`
	}{request.AssetID, request.ExpectedRevision})
	var result Asset
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, found, err := assetScopeForAuthorization(ctx, tx, actor, request.AssetID)
		if err != nil {
			return err
		}
		if err := s.authorizeActor(ctx, tx, actor, targetScopeID, permissionManage); err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		preflight, err := loadAssetForActor(ctx, tx, actor, request.AssetID, false)
		if err != nil {
			return err
		}
		stored, exists, err := s.claimWrite(ctx, tx, actor, preflight.ScopeID, operationAssetDelete, request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if exists {
			decoded, err := decodeReplay[Asset](stored)
			if err != nil {
				return err
			}
			result, replayed = decoded.Value, true
			return nil
		}
		if err := lockPublication(ctx, tx); err != nil {
			return err
		}
		asset, err := loadAssetForActor(ctx, tx, actor, request.AssetID, true)
		if err != nil {
			return err
		}
		if asset.ScopeID != preflight.ScopeID {
			return ErrConflict
		}
		if asset.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if asset.Status == StatusDeleted || asset.Status == StatusOrphaned || asset.Status == StatusRejected {
			return ErrNotFound
		}
		var referenced bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM error_page_rules identity
			JOIN LATERAL (
				SELECT revision.* FROM error_page_rule_revisions revision
				WHERE revision.rule_id=identity.id ORDER BY revision.revision DESC LIMIT 1
			) current ON true
			WHERE current.asset_id=$1 AND current.enabled AND NOT current.deleted
		)`, asset.ID).Scan(&referenced); err != nil {
			return err
		}
		if referenced {
			return ErrConflict
		}
		now := storeTime(s.now())
		_, err = tx.Exec(ctx, `UPDATE error_page_assets SET
			status='delete_pending',object_state='cleanup_pending',revision=revision+1,updated_at=$2,deleted_at=$2
			WHERE id=$1`, asset.ID, now)
		if err != nil {
			return err
		}
		result, err = loadAsset(ctx, tx, asset.ID, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor, asset.ScopeID, operationAssetDelete,
			"error_page_asset", asset.ID.String(), request.WriteMetadata, "success",
			map[string]any{"revision": result.Revision, "cleanup_state": "pending"}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationAssetDelete, request.WriteMetadata, asset.ID, 202, result)
	})
	if err != nil {
		return WriteResult[Asset]{}, fmt.Errorf("delete error page asset: %w", normalizeDatabaseError(err))
	}
	return WriteResult[Asset]{Value: result, Replayed: replayed}, nil
}

func (s *Service) GetAsset(ctx context.Context, actor Actor, id uuid.UUID) (Asset, error) {
	if validateActor(actor) != nil || id == uuid.Nil {
		return Asset{}, ErrInvalidInput
	}
	var result Asset
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, found, err := assetScopeForAuthorization(ctx, tx, actor, id)
		if err != nil {
			return err
		}
		if err := s.authorizeActor(ctx, tx, actor, targetScopeID, permissionRead); err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		result, err = loadAssetForActor(ctx, tx, actor, id, false)
		return err
	})
	if err != nil {
		return Asset{}, fmt.Errorf("get error page asset: %w", err)
	}
	return result, nil
}

// AssetContent is a ready asset with its body (the site's
// 错误页面 dialog edits a page's text). Only ready assets are read; the body
// is the stored object, integrity checked as a slot's.
type AssetContent struct {
	Asset   Asset  `json:"asset"`
	Content string `json:"content"`
}

// GetAssetContent reads a ready asset's body (error_pages.read).
func (s *Service) GetAssetContent(ctx context.Context, actor Actor, id uuid.UUID) (AssetContent, error) {
	asset, err := s.GetAsset(ctx, actor, id)
	if err != nil {
		return AssetContent{}, err
	}
	if asset.Status != StatusReady {
		return AssetContent{}, fmt.Errorf("get error page asset content: %w", ErrConflict)
	}
	body, err := s.readReadySlotContent(ctx, asset)
	if err != nil {
		return AssetContent{}, fmt.Errorf("get error page asset content: %w", err)
	}
	return AssetContent{Asset: asset, Content: string(body)}, nil
}

func (s *Service) ListAssets(ctx context.Context, actor Actor, request AssetPageRequest) (AssetPage, error) {
	if validateActor(actor) != nil || request.Limit < 1 || request.Limit > MaxPageSize ||
		(request.Status != "" && !validAssetStatus(request.Status)) {
		return AssetPage{}, ErrInvalidInput
	}
	var page AssetPage
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeActor(ctx, tx, actor,
			authorizationTarget(actor, request.TargetScopeID), permissionRead); err != nil {
			return err
		}
		targetScope := request.TargetScopeID
		if actor.ScopeKind == "tenant" {
			if targetScope != uuid.Nil && targetScope != actor.ScopeID {
				return ErrPermissionDenied
			}
			targetScope = actor.ScopeID
		}
		cursorEndpoint := "assets?status=" + request.Status
		cursor, err := decodePageCursor(request.Cursor, cursorEndpoint, actor, targetScope)
		if err != nil {
			return err
		}
		where := `WHERE ($1::uuid IS NULL OR scope_id=$1) AND ($2='' OR status=$2)`
		args := []any{nullableUUID(targetScope), request.Status}
		if cursor != nil {
			where += ` AND (created_at,id) < ($3,$4)`
			args = append(args, cursor.CreatedAt, cursor.ID)
		}
		args = append(args, request.Limit+1)
		rows, err := tx.Query(ctx, `SELECT `+assetColumns+` FROM error_page_assets `+where+
			` ORDER BY created_at DESC,id DESC LIMIT $`+fmt.Sprint(len(args)), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			asset, err := scanAsset(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, asset)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > request.Limit {
			last := page.Items[request.Limit-1]
			page.Items = page.Items[:request.Limit]
			page.NextCursor, err = encodePageCursor(cursorEndpoint, actor, targetScope, last.CreatedAt, last.ID)
			return err
		}
		return nil
	})
	if err != nil {
		return AssetPage{}, fmt.Errorf("list error page assets: %w", err)
	}
	if page.Items == nil {
		page.Items = []Asset{}
	}
	return page, nil
}

func assetScopeForAuthorization(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	assetID uuid.UUID,
) (uuid.UUID, bool, error) {
	query := `SELECT scope_id FROM error_page_assets WHERE id=$1`
	args := []any{assetID}
	if actor.ScopeKind == "tenant" {
		query += ` AND scope_id=$2`
		args = append(args, actor.ScopeID)
	}
	var scopeID uuid.UUID
	err := tx.QueryRow(ctx, query, args...).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return actor.ScopeID, false, nil
	}
	if err != nil || scopeID == uuid.Nil {
		return uuid.Nil, false, err
	}
	return scopeID, true, nil
}

func loadAssetForActor(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID, lock bool) (Asset, error) {
	query := `SELECT ` + assetColumns + ` FROM error_page_assets WHERE id=$1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += ` AND scope_id=$2`
		args = append(args, actor.ScopeID)
	}
	if lock {
		query += ` FOR UPDATE`
	}
	asset, err := scanAsset(tx.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	return asset, err
}

func loadAsset(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (Asset, error) {
	query := `SELECT ` + assetColumns + ` FROM error_page_assets WHERE id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	asset, err := scanAsset(tx.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	return asset, err
}

const assetColumns = `id,scope_id,tenant_id,mime_type,size_bytes,sha256,status,scan_status,revision,
	created_by_user_id,created_at,updated_at,deleted_at,staging_object_key,storage_object_key,object_state,name`

type rowScanner interface{ Scan(...any) error }

func scanAsset(row rowScanner) (Asset, error) {
	var asset Asset
	var digest []byte
	err := row.Scan(&asset.ID, &asset.ScopeID, &asset.TenantID, &asset.MIMEType, &asset.SizeBytes,
		&digest, &asset.Status, &asset.ScanStatus, &asset.Revision, &asset.CreatedBy, &asset.CreatedAt,
		&asset.UpdatedAt, &asset.DeletedAt, &asset.stagingObjectKey, &asset.storageObjectKey, &asset.objectState, &asset.Name)
	if err != nil {
		return Asset{}, err
	}
	if len(digest) != 32 {
		return Asset{}, ErrConflict
	}
	asset.SHA256 = hex.EncodeToString(digest)
	return asset, nil
}

func findWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key, requestID string,
) (storedWrite, error) {
	var result storedWrite
	var storedRequestID string
	var resourceID *uuid.UUID
	var status *int
	var completed *time.Time
	err := tx.QueryRow(ctx, `SELECT request_id,resource_id,response_status,response_body,completed_at
		FROM error_page_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
		actor.ScopeID, actor.UserID, operation, key).
		Scan(&storedRequestID, &resourceID, &status, &result.Response, &completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedWrite{}, ErrIdempotencyConflict
	}
	if err != nil {
		return storedWrite{}, err
	}
	if storedRequestID != requestID {
		return storedWrite{}, ErrIdempotencyConflict
	}
	if resourceID != nil {
		result.ResourceID = *resourceID
	}
	if status != nil {
		result.Status = *status
	}
	result.Completed = completed != nil
	return result, nil
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	if maximum < 1 || maximum > MaxEdgeResourceBytes {
		return nil, ErrInvalidInput
	}
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, ErrInvalidInput
	}
	return body, nil
}

func mapScanResult(result string) string {
	if result == "passed" {
		return "success"
	}
	return "failure"
}

func validAssetStatus(status string) bool {
	switch status {
	case StatusInitiated, StatusStaged, StatusScanFailed, StatusFinalizing, StatusReady,
		StatusRejected, StatusDeletePending, StatusDeleted, StatusOrphaned:
		return true
	default:
		return false
	}
}

func nullableUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}

func sqlState(err error) string {
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		return state.SQLState()
	}
	return ""
}
