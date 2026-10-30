package systemconfig

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type rowScanner interface {
	Scan(...any) error
}

type storedWrite struct {
	Response []byte
}

type streamState struct {
	Head   int64
	Active int64
}

func (s *Service) createDraft(
	ctx context.Context,
	actor Actor,
	request CreateDraftRequest,
	snapshot []byte,
	snapshotHash string,
	digest [32]byte,
) (Revision, error) {
	var result Revision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		now, err := s.currentTime()
		if err != nil {
			return err
		}
		write, replayed, err := s.claimWrite(ctx, tx, actor, operationCreateDraft, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			return decodeReplay(write, &result)
		}
		stream, err := lockStream(ctx, tx, actor.ScopeID, now)
		if err != nil {
			return err
		}
		if stream.Head != request.ExpectedHeadRevision || stream.Head >= maxRevision {
			return ErrRevisionConflict
		}
		revision := stream.Head + 1
		digestBytes, _ := hex.DecodeString(snapshotHash)
		_, err = tx.Exec(ctx, `INSERT INTO system_configuration_revisions (
			platform_scope_id,revision,status,canonical_schema,canonical_snapshot,snapshot_sha256,
			created_by_user_id,created_by_scope_id,created_at,state_changed_at
		) VALUES($1,$2,'draft',$3,$4,$5,$6,$1,$7,$7)`,
			actor.ScopeID, revision, canonicalSchema, snapshot, digestBytes, actor.UserID, now)
		if err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE system_configuration_streams
			SET head_revision=$2,updated_at=$3 WHERE platform_scope_id=$1 AND head_revision=$4`,
			actor.ScopeID, revision, now, request.ExpectedHeadRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result, err = loadRevision(ctx, tx, actor.ScopeID, revision)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, result, request.RequestID, operationCreateDraft, map[string]any{
			"expected_head_revision": request.ExpectedHeadRevision,
		}); err != nil {
			return err
		}
		result.Configuration = redactConfiguration(result.Configuration)
		return s.completeWrite(ctx, tx, actor, operationCreateDraft, request.IdempotencyKey, result, now)
	})
	if err != nil {
		return Revision{}, fmt.Errorf("create system configuration draft: %w", err)
	}
	return result, nil
}

func (s *Service) recordPreflight(
	ctx context.Context,
	actor Actor,
	request RecordPreflightRequest,
	passed bool,
	digest [32]byte,
) (Revision, error) {
	var result Revision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		now, err := s.currentTime()
		if err != nil {
			return err
		}
		expiresAt, err := checkedPreflightExpiry(now)
		if err != nil {
			return err
		}
		write, replayed, err := s.claimWrite(ctx, tx, actor, operationPreflight, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			return decodeReplay(write, &result)
		}
		current, err := lockRevision(ctx, tx, actor.ScopeID, request.Revision)
		if err != nil {
			return err
		}
		if current.Status != request.ExpectedStatus {
			return ErrRevisionConflict
		}
		if current.SnapshotSHA256 != request.SnapshotSHA256 {
			return ErrPreflightHash
		}
		var preflightSequence int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(preflight_sequence),0)
			FROM system_configuration_preflights WHERE platform_scope_id=$1 AND revision=$2`,
			actor.ScopeID, request.Revision).Scan(&preflightSequence); err != nil {
			return err
		}
		if preflightSequence >= maxRevision {
			return ErrRevisionConflict
		}
		preflightSequence++
		checks, err := json.Marshal(request.Checks)
		if err != nil {
			return ErrInvalidInput
		}
		hashBytes, _ := hex.DecodeString(request.SnapshotSHA256)
		_, err = tx.Exec(ctx, `INSERT INTO system_configuration_preflights (
			platform_scope_id,revision,preflight_sequence,snapshot_sha256,passed,checks,
			performed_by_user_id,performed_by_scope_id,performed_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$1,$8,$9)`, actor.ScopeID, request.Revision,
			preflightSequence, hashBytes, passed, checks, actor.UserID, now, expiresAt)
		if err != nil {
			return err
		}
		status := StatusRejected
		if passed {
			status = StatusValidated
		}
		if request.ExpectedStatus == StatusDraft {
			command, err := tx.Exec(ctx, `UPDATE system_configuration_revisions
				SET status=$3,state_changed_at=$4
				WHERE platform_scope_id=$1 AND revision=$2 AND status='draft'`,
				actor.ScopeID, request.Revision, status, now)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		}
		result, err = loadRevision(ctx, tx, actor.ScopeID, request.Revision)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, result, request.RequestID, operationPreflight, map[string]any{
			"passed": passed, "check_count": len(request.Checks),
			"preflight_sequence": preflightSequence, "expires_at": expiresAt,
		}); err != nil {
			return err
		}
		result.Configuration = redactConfiguration(result.Configuration)
		return s.completeWrite(ctx, tx, actor, operationPreflight, request.IdempotencyKey, result, now)
	})
	if err != nil {
		return Revision{}, fmt.Errorf("record system configuration preflight: %w", err)
	}
	return result, nil
}

func (s *Service) activate(ctx context.Context, actor Actor, request ActivateRequest, digest [32]byte) (Revision, error) {
	var result Revision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		now, err := s.currentTime()
		if err != nil {
			return err
		}
		write, replayed, err := s.claimWrite(ctx, tx, actor, operationActivate, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			return decodeReplay(write, &result)
		}
		stream, err := lockStream(ctx, tx, actor.ScopeID, now)
		if err != nil {
			return err
		}
		if stream.Active != request.ExpectedActiveRevision || request.Revision > stream.Head ||
			(stream.Active > 0 && request.Revision <= stream.Active) {
			return ErrRevisionConflict
		}
		current, err := lockRevision(ctx, tx, actor.ScopeID, request.Revision)
		if err != nil {
			return err
		}
		if current.Status != StatusValidated {
			return ErrInvalidTransition
		}
		if request.enforcePendingCategories {
			pending, err := pendingCategories(ctx, tx, actor.ScopeID, stream.Active, current.Configuration)
			if err != nil {
				return err
			}
			if !pendingCategoriesMatch(request.ExpectedPendingCategories, pending) {
				return ErrPendingCategoriesChanged
			}
		}
		var preflightHash []byte
		var passed bool
		var performedAt, expiresAt time.Time
		err = tx.QueryRow(ctx, `SELECT snapshot_sha256,passed,performed_at,expires_at
			FROM system_configuration_preflights
			WHERE platform_scope_id=$1 AND revision=$2
			ORDER BY preflight_sequence DESC LIMIT 1`, actor.ScopeID, request.Revision).
			Scan(&preflightHash, &passed, &performedAt, &expiresAt)
		if errors.Is(err, pgx.ErrNoRows) || !passed {
			return ErrPreflightRequired
		}
		if err != nil {
			return err
		}
		currentHash, _ := hex.DecodeString(current.SnapshotSHA256)
		if !bytes.Equal(preflightHash, currentHash) {
			return ErrPreflightHash
		}
		if now.Before(performedAt) {
			return ErrClockRollback
		}
		if !now.Before(expiresAt) {
			return ErrPreflightExpired
		}
		if s.publisher != nil {
			if _, err := s.publisher.PublishActivation(ctx, tx, ActivationPublicationRequest{
				Actor: actor, Revision: request.Revision, SnapshotSHA256: current.SnapshotSHA256,
				Configuration: current.Configuration, IdempotencyKey: request.IdempotencyKey,
				RequestID: request.RequestID, ActivatedAt: now,
			}); err != nil {
				slog.Error("system configuration activation publication failed",
					"scope_id", actor.ScopeID.String(), "revision", request.Revision,
					"request_id", request.RequestID, "error", err)
				return fmt.Errorf("%w: %v", ErrPublicationFailed, err)
			}
		}
		if stream.Active > 0 {
			command, err := tx.Exec(ctx, `UPDATE system_configuration_revisions
				SET status='superseded',state_changed_at=$3
				WHERE platform_scope_id=$1 AND revision=$2 AND status='active'`,
				actor.ScopeID, stream.Active, now)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		}
		command, err := tx.Exec(ctx, `UPDATE system_configuration_revisions
			SET status='active',state_changed_at=$3
			WHERE platform_scope_id=$1 AND revision=$2 AND status='validated'`,
			actor.ScopeID, request.Revision, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		command, err = tx.Exec(ctx, `UPDATE system_configuration_streams
			SET active_revision=$2,updated_at=$3
			WHERE platform_scope_id=$1 AND COALESCE(active_revision,0)=$4`,
			actor.ScopeID, request.Revision, now, request.ExpectedActiveRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result, err = loadRevision(ctx, tx, actor.ScopeID, request.Revision)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, result, request.RequestID, operationActivate, map[string]any{
			"previous_active_revision": request.ExpectedActiveRevision,
		}); err != nil {
			return err
		}
		result.Configuration = redactConfiguration(result.Configuration)
		return s.completeWrite(ctx, tx, actor, operationActivate, request.IdempotencyKey, result, now)
	})
	if err != nil {
		return Revision{}, fmt.Errorf("activate system configuration: %w", err)
	}
	return result, nil
}

func (s *Service) rollback(ctx context.Context, actor Actor, request RollbackRequest, digest [32]byte) (Revision, error) {
	var result Revision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		now, err := s.currentTime()
		if err != nil {
			return err
		}
		write, replayed, err := s.claimWrite(ctx, tx, actor, operationRollback, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			return decodeReplay(write, &result)
		}
		stream, err := lockStream(ctx, tx, actor.ScopeID, now)
		if err != nil {
			return err
		}
		if stream.Head != request.ExpectedHeadRevision || stream.Active != request.ExpectedActiveRevision ||
			stream.Head >= maxRevision {
			return ErrRevisionConflict
		}
		target, raw, hash, err := loadRevisionRaw(ctx, tx, actor.ScopeID, request.TargetRevision, false)
		if err != nil {
			return err
		}
		if target.Status != StatusActive && target.Status != StatusSuperseded {
			return ErrInvalidTransition
		}
		newRevision := stream.Head + 1
		_, err = tx.Exec(ctx, `INSERT INTO system_configuration_revisions (
			platform_scope_id,revision,status,canonical_schema,canonical_snapshot,snapshot_sha256,source_revision,
			created_by_user_id,created_by_scope_id,created_at,state_changed_at
		) VALUES($1,$2,'draft',$3,$4,$5,$6,$7,$1,$8,$8)`,
			actor.ScopeID, newRevision, canonicalSchema, raw, hash, request.TargetRevision, actor.UserID, now)
		if err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE system_configuration_streams
			SET head_revision=$2,updated_at=$3
			WHERE platform_scope_id=$1 AND head_revision=$4 AND active_revision=$5`,
			actor.ScopeID, newRevision, now, request.ExpectedHeadRevision, request.ExpectedActiveRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result, err = loadRevision(ctx, tx, actor.ScopeID, newRevision)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, result, request.RequestID, operationRollback, map[string]any{
			"source_revision":          request.TargetRevision,
			"expected_active_revision": request.ExpectedActiveRevision,
		}); err != nil {
			return err
		}
		result.Configuration = redactConfiguration(result.Configuration)
		return s.completeWrite(ctx, tx, actor, operationRollback, request.IdempotencyKey, result, now)
	})
	if err != nil {
		return Revision{}, fmt.Errorf("roll back system configuration: %w", err)
	}
	return result, nil
}

func (s *Service) getRevision(ctx context.Context, actor Actor, revision int64) (Revision, error) {
	var result Revision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		var err error
		result, err = loadRevision(ctx, tx, actor.ScopeID, revision)
		return err
	})
	if err != nil {
		return Revision{}, fmt.Errorf("get system configuration revision: %w", err)
	}
	result.Configuration = redactConfiguration(result.Configuration)
	return result, nil
}

func (s *Service) getActive(ctx context.Context, actor Actor) (Revision, error) {
	var result Revision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		var revision *int64
		if err := tx.QueryRow(ctx, `SELECT active_revision FROM system_configuration_streams
			WHERE platform_scope_id=$1`, actor.ScopeID).Scan(&revision); errors.Is(err, pgx.ErrNoRows) || revision == nil {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		var err error
		result, err = loadRevision(ctx, tx, actor.ScopeID, *revision)
		return err
	})
	if err != nil {
		return Revision{}, fmt.Errorf("get active system configuration: %w", err)
	}
	result.Configuration = redactConfiguration(result.Configuration)
	return result, nil
}

func authorizePlatformActor(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'system-configuration-authorization:' || $1::text || ':' || $2::text,0))`,
		actor.ScopeID, actor.UserID); err != nil {
		return err
	}
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes
		WHERE id=$1 FOR UPDATE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return err
	}
	if kind != "platform" || actor.ScopeKind != kind || tenantID != nil {
		return ErrPermissionDenied
	}
	var accountStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`,
		actor.UserID).Scan(&accountStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return err
	}
	var membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`, actor.ScopeID, actor.UserID).
		Scan(&membershipStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return err
	}
	if accountStatus != "active" || membershipStatus != "active" {
		return ErrPermissionDenied
	}
	var roleID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT assignment.role_id
		FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name=$3
		ORDER BY assignment.role_id
		LIMIT 1 FOR UPDATE OF assignment,role,grant_row`, actor.ScopeID, actor.UserID, permission).Scan(&roleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	return err
}

func lockStream(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, now time.Time) (streamState, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO system_configuration_streams (
		platform_scope_id,head_revision,created_at,updated_at
	) SELECT id,0,$2,$2 FROM access_scopes WHERE id=$1 AND kind='platform'
	ON CONFLICT(platform_scope_id) DO NOTHING`, scopeID, now); err != nil {
		return streamState{}, err
	}
	var state streamState
	var active *int64
	err := tx.QueryRow(ctx, `SELECT head_revision,active_revision FROM system_configuration_streams
		WHERE platform_scope_id=$1 FOR UPDATE`, scopeID).Scan(&state.Head, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return streamState{}, ErrPermissionDenied
	}
	if err != nil {
		return streamState{}, err
	}
	if active != nil {
		state.Active = *active
	}
	return state, nil
}

func lockRevision(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, revision int64) (Revision, error) {
	item, _, _, err := loadRevisionRaw(ctx, tx, scopeID, revision, true)
	return item, err
}

func loadRevision(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, revision int64) (Revision, error) {
	item, _, _, err := loadRevisionRaw(ctx, tx, scopeID, revision, false)
	return item, err
}

func loadRevisionRaw(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	revision int64,
	lock bool,
) (Revision, []byte, []byte, error) {
	query := `SELECT platform_scope_id,revision,status,canonical_schema,canonical_snapshot,snapshot_sha256,
		source_revision,created_by_user_id,created_at,state_changed_at
		FROM system_configuration_revisions WHERE platform_scope_id=$1 AND revision=$2`
	if lock {
		query += " FOR UPDATE"
	}
	var item Revision
	var schema string
	var snapshot, hash []byte
	err := tx.QueryRow(ctx, query, scopeID, revision).Scan(
		&item.ScopeID, &item.Revision, &item.Status, &schema, &snapshot, &hash,
		&item.SourceRevision, &item.CreatedBy, &item.CreatedAt, &item.StateChangedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Revision{}, nil, nil, ErrNotFound
	}
	if err != nil {
		return Revision{}, nil, nil, err
	}
	if schema != canonicalSchema || len(hash) != sha256Size {
		return Revision{}, nil, nil, ErrInvalidInput
	}
	item.SnapshotSHA256 = hex.EncodeToString(hash)
	item.Configuration, err = decodeCanonicalSnapshot(snapshot, item.SnapshotSHA256)
	if err != nil {
		return Revision{}, nil, nil, err
	}
	return item, snapshot, hash, nil
}

func (s *Service) claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key string,
	digest [32]byte,
	now time.Time,
) (storedWrite, bool, error) {
	if existing, found, err := findWrite(ctx, tx, actor.UserID, operation, key, digest); err != nil || found {
		return existing, found, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, false, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO system_configuration_write_requests (
		id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,created_at
		) VALUES($1,$2,$3,$3,$4,$5,$6,$7)
		ON CONFLICT(actor_user_id,operation,idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, operation, key, digest[:], now)
	if err != nil {
		return storedWrite{}, false, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, false, nil
	}
	existing, found, err := findWrite(ctx, tx, actor.UserID, operation, key, digest)
	if err != nil {
		return storedWrite{}, false, err
	}
	if !found {
		return storedWrite{}, false, ErrIdempotencyConflict
	}
	return existing, true, nil
}

func findWrite(
	ctx context.Context,
	tx pgx.Tx,
	actorID uuid.UUID,
	operation, key string,
	digest [32]byte,
) (storedWrite, bool, error) {
	var storedDigest, response []byte
	var completed *time.Time
	err := tx.QueryRow(ctx, `SELECT request_digest,response_body,completed_at
		FROM system_configuration_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actorID, operation, key).
		Scan(&storedDigest, &response, &completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedWrite{}, false, nil
	}
	if err != nil {
		return storedWrite{}, false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) || completed == nil || len(response) == 0 {
		return storedWrite{}, false, ErrIdempotencyConflict
	}
	return storedWrite{Response: response}, true, nil
}

func (s *Service) completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key string,
	result Revision,
	now time.Time,
) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE system_configuration_write_requests
		SET response_body=$4,completed_at=$5
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 AND completed_at IS NULL`,
		actor.UserID, operation, key, encoded, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func decodeReplay(write storedWrite, result *Revision) error {
	if err := json.Unmarshal(write.Response, result); err != nil {
		return err
	}
	result.Replayed = true
	return nil
}

func (s *Service) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	revision Revision,
	requestID, action string,
	extra map[string]any,
) error {
	payload := map[string]any{
		"revision": revision.Revision, "status": revision.Status,
		"snapshot_sha256": revision.SnapshotSHA256,
	}
	for key, value := range extra {
		payload[key] = value
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: revision.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "system_configuration_revision",
		ResourceID:   fmt.Sprintf("%s:%d", revision.ScopeID, revision.Revision),
		RequestID:    requestID, Result: "success", Payload: payload,
	})
}

const sha256Size = 32
