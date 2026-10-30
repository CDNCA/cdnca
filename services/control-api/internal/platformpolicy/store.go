package platformpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidStore     = errors.New("invalid platform policy store")
	ErrDeliveryConflict = errors.New("platform policy delivery conflict")
	ErrAckTransition    = errors.New("platform policy acknowledgement transition invalid")
	ErrNoPendingAck     = errors.New("no pending platform policy acknowledgement")
)

type SyncPosition struct {
	Cursor     *string
	ETag       *string
	ResolvedAt *time.Time
}

type StoredTarget struct {
	Signed  SignedPlatformPolicy
	Encoded []byte
}

type LocalState struct {
	GlobalHead         *ScopeHead
	InstallationHead   *ScopeHead
	GlobalActive       *StoredTarget
	InstallationActive *StoredTarget
	Position           SyncPosition
}

type PendingAck struct {
	EventID               uuid.UUID
	TargetRevisionID      string
	ScopeKind             string
	ScopeRevision         int64
	CanonicalPolicySHA256 string
	Status                string
	ErrorCode             *string
	ObservedAt            time.Time
	Attempts              int
}

type PostgresStore struct {
	pool           *pgxpool.Pool
	installationID uuid.UUID
}

func NewPostgresStore(pool *pgxpool.Pool, installationID uuid.UUID) (*PostgresStore, error) {
	if pool == nil || installationID == uuid.Nil {
		return nil, ErrInvalidStore
	}
	return &PostgresStore{pool: pool, installationID: installationID}, nil
}

func (store *PostgresStore) Load(ctx context.Context) (LocalState, error) {
	if store == nil || store.pool == nil {
		return LocalState{}, ErrInvalidStore
	}
	result := LocalState{}
	rows, err := store.pool.Query(ctx, `SELECT scope_kind,highwater_revision,head_target_revision_id,
		active_target_revision_id FROM platform_policy_scope_state
		WHERE scope_key IN ('global',$1) ORDER BY scope_kind`, scopeKey(ScopeInstallation, store.installationID))
	if err != nil {
		return LocalState{}, fmt.Errorf("load platform policy scope state: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, headID string
		var revision int64
		var activeID *string
		if err := rows.Scan(&kind, &revision, &headID, &activeID); err != nil {
			return LocalState{}, fmt.Errorf("scan platform policy scope state: %w", err)
		}
		head, err := loadHead(ctx, store.pool, headID, revision)
		if err != nil {
			return LocalState{}, err
		}
		var active *StoredTarget
		if activeID != nil {
			active, err = loadTarget(ctx, store.pool, *activeID)
			if err != nil {
				return LocalState{}, err
			}
		}
		if kind == ScopeGlobal {
			result.GlobalHead, result.GlobalActive = head, active
		} else {
			result.InstallationHead, result.InstallationActive = head, active
		}
	}
	if err := rows.Err(); err != nil {
		return LocalState{}, fmt.Errorf("iterate platform policy scope state: %w", err)
	}
	var cursor, etag *string
	var resolvedAt *time.Time
	err = store.pool.QueryRow(ctx, `SELECT cursor,etag,resolved_at FROM platform_policy_sync_state
		WHERE singleton=true`).Scan(&cursor, &etag, &resolvedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return LocalState{}, fmt.Errorf("load platform policy sync state: %w", err)
	}
	if err == nil {
		result.Position = SyncPosition{Cursor: cursor, ETag: etag, ResolvedAt: resolvedAt}
	}
	return result, nil
}

func (store *PostgresStore) PendingCandidates(ctx context.Context, now time.Time, limit int) ([]StoredTarget, error) {
	if store == nil || store.pool == nil || now.IsZero() || limit < 1 || limit > 256 {
		return nil, ErrInvalidStore
	}
	rows, err := store.pool.Query(ctx, `SELECT delivery.signed_target,delivery.signed_target_sha256
		FROM platform_policy_deliveries delivery
		WHERE delivery.valid_from <= $1
		AND (delivery.scope_kind='global' OR delivery.installation_id=$2)
		AND EXISTS (
			SELECT 1 FROM platform_policy_ack_events event
			WHERE event.target_revision_id=delivery.target_revision_id AND event.status='fetched'
		)
		AND NOT EXISTS (
			SELECT 1 FROM platform_policy_ack_events event
			WHERE event.target_revision_id=delivery.target_revision_id
			AND event.status IN ('validated','applied','rejected')
		)
		ORDER BY delivery.valid_from,delivery.fetched_at,delivery.target_revision_id
		LIMIT $3`, now.UTC(), store.installationID, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending platform policy candidates: %w", err)
	}
	defer rows.Close()
	result := make([]StoredTarget, 0, limit)
	for rows.Next() {
		var encoded, storedDigest []byte
		if err := rows.Scan(&encoded, &storedDigest); err != nil {
			return nil, fmt.Errorf("scan pending platform policy candidate: %w", err)
		}
		digest := sha256.Sum256(encoded)
		if !bytes.Equal(digest[:], storedDigest) {
			return nil, ErrDeliveryConflict
		}
		signed, err := Decode(encoded)
		if err != nil {
			return nil, err
		}
		result = append(result, StoredTarget{Signed: signed, Encoded: append([]byte(nil), encoded...)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending platform policy candidates: %w", err)
	}
	return result, nil
}

func (store *PostgresStore) RecordFetched(ctx context.Context, encoded []byte,
	signed SignedPlatformPolicy, observedAt time.Time) (bool, error) {
	if store == nil || store.pool == nil || observedAt.IsZero() || len(encoded) == 0 || len(encoded) > maxSignedPolicyBytes {
		return false, ErrInvalidStore
	}
	decoded, err := Decode(encoded)
	if err != nil || !equalSigned(decoded, signed) {
		return false, ErrInvalidEnvelope
	}
	canonicalPolicy, err := CanonicalPolicy(signed.Policy)
	if err != nil {
		return false, err
	}
	canonicalEnvelope, err := CanonicalEnvelope(signed.Envelope)
	if err != nil {
		return false, err
	}
	claimedDigest, _ := base64.RawURLEncoding.DecodeString(signed.Envelope.CanonicalPolicySHA256)
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	signedDigest := sha256.Sum256(encoded)
	targetID := uuid.MustParse(signed.Envelope.TargetRevisionID)
	installationID, err := optionalUUID(signed.Envelope.InstallationID)
	if err != nil {
		return false, err
	}
	var inserted bool
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx, `INSERT INTO platform_policy_deliveries(
			target_revision_id,scope_kind,installation_id,scope_revision,action,schema_version,key_id,
			canonical_policy_sha256,canonical_policy,canonical_envelope,signed_target,signed_target_sha256,
			signature,signed_at,valid_from,expires_at,control_protocol_min,control_protocol_max,supersedes,rollback_of,fetched_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
			ON CONFLICT(target_revision_id) DO NOTHING`,
			targetID, signed.Envelope.ScopeKind, installationID, signed.Envelope.ScopeRevision,
			signed.Envelope.Action, signed.Envelope.Schema, signed.Envelope.KeyID, claimedDigest,
			canonicalPolicy, canonicalEnvelope, encoded, signedDigest[:], signature,
			time.Unix(signed.Envelope.SignedAt, 0).UTC(),
			time.Unix(signed.Envelope.ValidFrom, 0).UTC(), time.Unix(signed.Envelope.ExpiresAt, 0).UTC(),
			signed.Envelope.ControlProtocolMin, signed.Envelope.ControlProtocolMax,
			optionalParsedUUID(signed.Envelope.Supersedes), optionalParsedUUID(signed.Envelope.RollbackOf), observedAt.UTC())
		if err != nil {
			var databaseError *pgconn.PgError
			if errors.As(err, &databaseError) && databaseError.Code == "23505" {
				return ErrDeliveryConflict
			}
			return err
		}
		inserted = command.RowsAffected() == 1
		if !inserted {
			var storedDigest []byte
			if err := tx.QueryRow(ctx, `SELECT signed_target_sha256 FROM platform_policy_deliveries
				WHERE target_revision_id=$1`, targetID).Scan(&storedDigest); err != nil {
				return err
			}
			if !bytes.Equal(storedDigest, signedDigest[:]) {
				return ErrDeliveryConflict
			}
			return nil
		}
		return appendAck(ctx, tx, store.installationID, targetID, AckFetched, nil, observedAt.UTC())
	})
	if err != nil {
		return false, fmt.Errorf("record fetched platform policy: %w", err)
	}
	return inserted, nil
}

func (store *PostgresStore) RecordRejected(ctx context.Context, targetRevisionID string,
	errorCode string, observedAt time.Time) error {
	if store == nil || !validUUID(targetRevisionID) || !codePattern.MatchString(errorCode) || observedAt.IsZero() {
		return ErrInvalidStore
	}
	targetID := uuid.MustParse(targetRevisionID)
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		return appendAck(ctx, tx, store.installationID, targetID, AckRejected, &errorCode, observedAt.UTC())
	})
}

func (store *PostgresStore) Apply(ctx context.Context, verified VerifiedPolicy, observedAt time.Time) error {
	if store == nil || store.pool == nil || observedAt.IsZero() || validateSignedShape(verified.Signed) != nil {
		return ErrInvalidStore
	}
	targetID := uuid.MustParse(verified.Signed.Envelope.TargetRevisionID)
	scope := verified.Signed.Envelope.ScopeKind
	scopeKeyValue := scopeKey(scope, store.installationID)
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		// Global and installation scopes share one effective pointer for this
		// installation, so their application transactions must be serialized.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(
			hashtext('cdnca.platform_policy.apply'),hashtext($1))`, store.installationID.String()); err != nil {
			return err
		}
		expiresAt, err := lockAndValidateDelivery(ctx, tx, store.installationID, targetID, verified)
		if err != nil {
			return err
		}
		previousEffective, err := effectiveTargetID(ctx, tx, store.installationID)
		if err != nil {
			return err
		}
		var currentRevision int64
		var currentHead string
		var lkgID, activeID *string
		err = tx.QueryRow(ctx, `SELECT highwater_revision,head_target_revision_id,
			lkg_target_revision_id,active_target_revision_id FROM platform_policy_scope_state
			WHERE scope_key=$1 FOR UPDATE`, scopeKeyValue).Scan(&currentRevision, &currentHead, &lkgID, &activeID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		stateExists := err == nil
		if stateExists && verified.Signed.Envelope.ScopeRevision == currentRevision && currentHead == targetID.String() {
			effective, err := effectiveTargetID(ctx, tx, store.installationID)
			if err != nil {
				return err
			}
			return materializeEffectiveCCSystemRules(ctx, tx, store.installationID, effective, observedAt.UTC())
		}
		var serverNow time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&serverNow); err != nil {
			return err
		}
		if !serverNow.Before(expiresAt) {
			return ErrExpired
		}
		if stateExists {
			if verified.Signed.Envelope.ScopeRevision <= currentRevision {
				return ErrRevisionOutOfOrder
			}
			if verified.Signed.Envelope.ScopeRevision == currentRevision+1 &&
				(verified.Signed.Envelope.Supersedes == nil || *verified.Signed.Envelope.Supersedes != currentHead) {
				return ErrSupersedesMismatch
			}
		}
		if verified.Signed.Envelope.RollbackOf != nil &&
			(!stateExists || *verified.Signed.Envelope.RollbackOf != currentHead) {
			return ErrSupersedesMismatch
		}
		if err := appendAck(ctx, tx, store.installationID, targetID, AckValidated, nil, observedAt.UTC()); err != nil {
			return err
		}
		newLKG, newActive := lkgID, (*string)(nil)
		if verified.Signed.Envelope.Action == ActionApply {
			value := targetID.String()
			newLKG, newActive = &value, &value
		}
		installationID := (*uuid.UUID)(nil)
		if scope == ScopeInstallation {
			value := store.installationID
			installationID = &value
		}
		_, err = tx.Exec(ctx, `INSERT INTO platform_policy_scope_state(
			scope_key,scope_kind,installation_id,highwater_revision,head_target_revision_id,
			lkg_target_revision_id,active_target_revision_id,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT(scope_key) DO UPDATE SET highwater_revision=EXCLUDED.highwater_revision,
			head_target_revision_id=EXCLUDED.head_target_revision_id,
			lkg_target_revision_id=EXCLUDED.lkg_target_revision_id,
			active_target_revision_id=EXCLUDED.active_target_revision_id,updated_at=EXCLUDED.updated_at`,
			scopeKeyValue, scope, installationID, verified.Signed.Envelope.ScopeRevision, targetID,
			optionalStringUUID(newLKG), optionalStringUUID(newActive), observedAt.UTC())
		if err != nil {
			return err
		}
		newEffective, err := effectiveTargetID(ctx, tx, store.installationID)
		if err != nil {
			return err
		}
		if err := materializeEffectiveCCSystemRules(ctx, tx, store.installationID, newEffective, observedAt.UTC()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO platform_policy_application_events(
			id,target_revision_id,previous_effective_target_id,effective_target_id,action,occurred_at)
			VALUES($1,$2,$3,$4,$5,$6)`, uuid.Must(uuid.NewV7()), targetID,
			optionalStringUUID(previousEffective), optionalStringUUID(newEffective),
			verified.Signed.Envelope.Action, observedAt.UTC())
		if err != nil {
			return err
		}
		if err := appendAck(ctx, tx, store.installationID, targetID, AckApplied, nil, observedAt.UTC()); err != nil {
			return err
		}
		rolledBackID := activeID
		if verified.Signed.Envelope.RollbackOf != nil {
			rolledBackID = verified.Signed.Envelope.RollbackOf
		}
		if (verified.Signed.Envelope.Action == ActionWithdraw || verified.Signed.Envelope.RollbackOf != nil) && rolledBackID != nil {
			oldID := uuid.MustParse(*rolledBackID)
			if oldID != targetID {
				if err := appendAck(ctx, tx, store.installationID, oldID, AckRolledBack, nil, observedAt.UTC()); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func lockAndValidateDelivery(ctx context.Context, tx pgx.Tx, installationID, targetID uuid.UUID,
	verified VerifiedPolicy) (time.Time, error) {
	var storedScope, storedAction, storedSchema, storedKeyID string
	var storedInstallationID, storedSupersedes, storedRollbackOf *uuid.UUID
	var storedRevision int64
	var storedPolicyDigest, storedPolicy, storedEnvelope, storedTarget, storedTargetDigest, storedSignature []byte
	var storedSignedAt, storedValidFrom, storedExpiresAt time.Time
	var storedProtocolMin, storedProtocolMax int
	err := tx.QueryRow(ctx, `SELECT scope_kind,installation_id,scope_revision,action,schema_version,key_id,
		canonical_policy_sha256,canonical_policy,canonical_envelope,signed_target,signed_target_sha256,
		signature,signed_at,valid_from,expires_at,control_protocol_min,control_protocol_max,supersedes,rollback_of
		FROM platform_policy_deliveries WHERE target_revision_id=$1 FOR UPDATE`, targetID).Scan(
		&storedScope, &storedInstallationID, &storedRevision, &storedAction, &storedSchema, &storedKeyID,
		&storedPolicyDigest, &storedPolicy, &storedEnvelope, &storedTarget, &storedTargetDigest,
		&storedSignature, &storedSignedAt, &storedValidFrom, &storedExpiresAt,
		&storedProtocolMin, &storedProtocolMax, &storedSupersedes, &storedRollbackOf,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrInvalidStore
	}
	if err != nil {
		return time.Time{}, err
	}

	signed := verified.Signed
	canonicalPolicy, policyErr := CanonicalPolicy(signed.Policy)
	canonicalEnvelope, envelopeErr := CanonicalEnvelope(signed.Envelope)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(signed.Signature)
	claimedDigest, digestErr := base64.RawURLEncoding.DecodeString(signed.Envelope.CanonicalPolicySHA256)
	targetDigest := sha256.Sum256(storedTarget)
	decoded, decodeErr := Decode(storedTarget)
	expectedInstallationID, installationErr := optionalUUID(signed.Envelope.InstallationID)
	expectedSupersedes, supersedesErr := optionalUUID(signed.Envelope.Supersedes)
	expectedRollbackOf, rollbackErr := optionalUUID(signed.Envelope.RollbackOf)
	computedPolicyDigest := sha256.Sum256(canonicalPolicy)
	if policyErr != nil || envelopeErr != nil || signatureErr != nil || digestErr != nil || decodeErr != nil ||
		installationErr != nil || supersedesErr != nil || rollbackErr != nil ||
		!equalSigned(decoded, signed) || !bytes.Equal(verified.CanonicalPolicy, canonicalPolicy) ||
		!bytes.Equal(verified.CanonicalEnvelope, canonicalEnvelope) || verified.Digest != computedPolicyDigest ||
		!bytes.Equal(verified.Signature, signature) || !bytes.Equal(storedTargetDigest, targetDigest[:]) ||
		!bytes.Equal(storedPolicyDigest, claimedDigest) || !bytes.Equal(storedPolicyDigest, computedPolicyDigest[:]) ||
		!bytes.Equal(storedPolicy, canonicalPolicy) || !bytes.Equal(storedEnvelope, canonicalEnvelope) ||
		!bytes.Equal(storedSignature, signature) || storedScope != signed.Envelope.ScopeKind ||
		storedRevision != signed.Envelope.ScopeRevision || storedAction != signed.Envelope.Action ||
		storedSchema != signed.Envelope.Schema || storedKeyID != signed.Envelope.KeyID ||
		!equalOptionalUUID(storedInstallationID, expectedInstallationID) ||
		!equalOptionalUUID(storedSupersedes, expectedSupersedes) ||
		!equalOptionalUUID(storedRollbackOf, expectedRollbackOf) ||
		!storedSignedAt.Equal(time.Unix(signed.Envelope.SignedAt, 0).UTC()) ||
		!storedValidFrom.Equal(time.Unix(signed.Envelope.ValidFrom, 0).UTC()) ||
		!storedExpiresAt.Equal(time.Unix(signed.Envelope.ExpiresAt, 0).UTC()) ||
		storedProtocolMin != signed.Envelope.ControlProtocolMin || storedProtocolMax != signed.Envelope.ControlProtocolMax ||
		(signed.Envelope.ScopeKind == ScopeInstallation &&
			(expectedInstallationID == nil || *expectedInstallationID != installationID)) {
		return time.Time{}, ErrDeliveryConflict
	}
	return storedExpiresAt, nil
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (store *PostgresStore) SavePosition(ctx context.Context, position SyncPosition, now time.Time) error {
	if store == nil || now.IsZero() || (position.Cursor != nil && len(*position.Cursor) > 512) ||
		(position.ETag != nil && len(*position.ETag) > 128) {
		return ErrInvalidStore
	}
	_, err := store.pool.Exec(ctx, `INSERT INTO platform_policy_sync_state(
		singleton,cursor,etag,resolved_at,updated_at) VALUES(true,$1,$2,$3,$4)
		ON CONFLICT(singleton) DO UPDATE SET cursor=EXCLUDED.cursor,etag=EXCLUDED.etag,
		resolved_at=EXCLUDED.resolved_at,updated_at=EXCLUDED.updated_at`,
		position.Cursor, position.ETag, position.ResolvedAt, now.UTC())
	if err != nil {
		return fmt.Errorf("save platform policy sync position: %w", err)
	}
	return nil
}

func (store *PostgresStore) PendingAcks(ctx context.Context, now time.Time, limit int) ([]PendingAck, error) {
	if store == nil || now.IsZero() || limit < 1 || limit > 256 {
		return nil, ErrInvalidStore
	}
	rows, err := store.pool.Query(ctx, `SELECT event.id,event.target_revision_id,delivery.scope_kind,
		delivery.scope_revision,delivery.canonical_policy_sha256,event.status,event.error_code,
		event.observed_at,outbox.attempts
		FROM platform_policy_ack_outbox outbox
		JOIN platform_policy_ack_events event ON event.id=outbox.ack_event_id
		JOIN platform_policy_deliveries delivery ON delivery.target_revision_id=event.target_revision_id
		WHERE outbox.delivered_at IS NULL AND outbox.next_attempt_at <= $1
		ORDER BY event.sequence LIMIT $2`, now.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("list pending platform policy acknowledgements: %w", err)
	}
	defer rows.Close()
	result := make([]PendingAck, 0, limit)
	for rows.Next() {
		var item PendingAck
		var digest []byte
		if err := rows.Scan(&item.EventID, &item.TargetRevisionID, &item.ScopeKind,
			&item.ScopeRevision, &digest, &item.Status, &item.ErrorCode, &item.ObservedAt, &item.Attempts); err != nil {
			return nil, fmt.Errorf("scan pending platform policy acknowledgement: %w", err)
		}
		item.CanonicalPolicySHA256 = base64.RawURLEncoding.EncodeToString(digest)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending platform policy acknowledgements: %w", err)
	}
	return result, nil
}

func (store *PostgresStore) CompleteAck(ctx context.Context, eventID uuid.UUID, now time.Time) error {
	if store == nil || eventID == uuid.Nil || now.IsZero() {
		return ErrInvalidStore
	}
	command, err := store.pool.Exec(ctx, `UPDATE platform_policy_ack_outbox
		SET delivered_at=$1,updated_at=$1,last_error_code=NULL WHERE ack_event_id=$2 AND delivered_at IS NULL`,
		now.UTC(), eventID)
	if err != nil {
		return fmt.Errorf("complete platform policy acknowledgement: %w", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNoPendingAck
	}
	return nil
}

func (store *PostgresStore) DeferAck(ctx context.Context, eventID uuid.UUID, errorCode string,
	nextAttempt, now time.Time) error {
	if store == nil || eventID == uuid.Nil || !codePattern.MatchString(errorCode) || now.IsZero() || nextAttempt.Before(now) {
		return ErrInvalidStore
	}
	command, err := store.pool.Exec(ctx, `UPDATE platform_policy_ack_outbox SET attempts=attempts+1,
		next_attempt_at=$1,last_error_code=$2,updated_at=$3 WHERE ack_event_id=$4 AND delivered_at IS NULL`,
		nextAttempt.UTC(), errorCode, now.UTC(), eventID)
	if err != nil {
		return fmt.Errorf("defer platform policy acknowledgement: %w", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNoPendingAck
	}
	return nil
}

func appendAck(ctx context.Context, tx pgx.Tx, installationID, targetID uuid.UUID,
	status string, errorCode *string, observedAt time.Time) error {
	if !validAck(status, errorCode) {
		return ErrAckTransition
	}
	var lockedID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT target_revision_id FROM platform_policy_deliveries
		WHERE target_revision_id=$1 FOR UPDATE`, targetID).Scan(&lockedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidStore
		}
		return err
	}
	rows, err := tx.Query(ctx, `SELECT status FROM platform_policy_ack_events
		WHERE target_revision_id=$1 ORDER BY sequence`, targetID)
	if err != nil {
		return err
	}
	var statuses []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			rows.Close()
			return err
		}
		statuses = append(statuses, value)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, existing := range statuses {
		if existing == status {
			return nil
		}
	}
	current := ""
	if len(statuses) > 0 {
		current = statuses[len(statuses)-1]
	}
	if !ackTransitionAllowed(current, status) {
		return ErrAckTransition
	}
	eventID := uuid.Must(uuid.NewV7())
	if _, err := tx.Exec(ctx, `INSERT INTO platform_policy_ack_events(
		id,target_revision_id,installation_id,status,error_code,observed_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$6)`, eventID, targetID, installationID, status, errorCode, observedAt.UTC()); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO platform_policy_ack_outbox(
		ack_event_id,next_attempt_at,updated_at) VALUES($1,$2,$2)`, eventID, observedAt.UTC())
	return err
}

func ackTransitionAllowed(current, next string) bool {
	switch current {
	case "":
		return next == AckFetched
	case AckFetched:
		return next == AckValidated || next == AckRejected
	case AckValidated:
		return next == AckApplied || next == AckRejected
	case AckApplied:
		return next == AckRolledBack
	default:
		return false
	}
}

func effectiveTargetID(ctx context.Context, tx pgx.Tx, installationID uuid.UUID) (*string, error) {
	var targetID *string
	err := tx.QueryRow(ctx, `SELECT active_target_revision_id FROM platform_policy_scope_state
		WHERE scope_key IN ($1,'global') AND active_target_revision_id IS NOT NULL
		ORDER BY CASE scope_kind WHEN 'installation' THEN 0 ELSE 1 END LIMIT 1`,
		scopeKey(ScopeInstallation, installationID)).Scan(&targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return targetID, err
}

func loadHead(ctx context.Context, queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, targetID string, revision int64) (*ScopeHead, error) {
	var digest, signature []byte
	if err := queryer.QueryRow(ctx, `SELECT canonical_policy_sha256,signature
		FROM platform_policy_deliveries WHERE target_revision_id=$1`, targetID).Scan(&digest, &signature); err != nil {
		return nil, fmt.Errorf("load platform policy head: %w", err)
	}
	return &ScopeHead{TargetRevisionID: targetID, ScopeRevision: revision,
		CanonicalPolicySHA256: base64.RawURLEncoding.EncodeToString(digest),
		Signature:             base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func loadTarget(ctx context.Context, queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, targetID string) (*StoredTarget, error) {
	var encoded, storedDigest []byte
	if err := queryer.QueryRow(ctx, `SELECT signed_target,signed_target_sha256
		FROM platform_policy_deliveries WHERE target_revision_id=$1`, targetID).Scan(&encoded, &storedDigest); err != nil {
		return nil, fmt.Errorf("load active platform policy: %w", err)
	}
	digest := sha256.Sum256(encoded)
	if !bytes.Equal(digest[:], storedDigest) {
		return nil, ErrDeliveryConflict
	}
	signed, err := Decode(encoded)
	if err != nil {
		return nil, err
	}
	return &StoredTarget{Signed: signed, Encoded: append([]byte(nil), encoded...)}, nil
}

func scopeKey(kind string, installationID uuid.UUID) string {
	if kind == ScopeGlobal {
		return ScopeGlobal
	}
	return ScopeInstallation + ":" + installationID.String()
}

func optionalUUID(value *string) (*uuid.UUID, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := uuid.Parse(*value)
	if err != nil || parsed == uuid.Nil || parsed.String() != *value {
		return nil, ErrInvalidEnvelope
	}
	return &parsed, nil
}

func optionalParsedUUID(value *string) *uuid.UUID {
	parsed, err := optionalUUID(value)
	if err != nil {
		return nil
	}
	return parsed
}

func optionalStringUUID(value *string) *uuid.UUID {
	if value == nil {
		return nil
	}
	parsed := uuid.MustParse(*value)
	return &parsed
}

func equalSigned(left, right SignedPlatformPolicy) bool {
	leftEncoded, leftErr := json.Marshal(left)
	rightEncoded, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftEncoded, rightEncoded)
}
