package nodecertlifecycle

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) RotateCAEpoch(ctx context.Context, actor Actor, request RotateCAEpochRequest) (CAEpoch, error) {
	request.KeyID = strings.TrimSpace(request.KeyID)
	if request.RequestID == uuid.Nil || request.ExpectedCurrentEpoch < 0 || !validKeyID(request.KeyID) ||
		!validTraceID(request.RequestTraceID) {
		return CAEpoch{}, ErrInvalidInput
	}
	certificate, certificateDigest, publicKeyDigest, err := validateCACertificate(request.CACertificatePEM)
	if err != nil {
		return CAEpoch{}, err
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	digest, err := digestJSON(struct {
		ExpectedCurrentEpoch int64    `json:"expected_current_epoch"`
		KeyID                string   `json:"key_id"`
		CertificateSHA256    [32]byte `json:"certificate_sha256"`
	}{request.ExpectedCurrentEpoch, request.KeyID, certificateDigest})
	if err != nil {
		return CAEpoch{}, ErrInvalidInput
	}
	var result CAEpoch
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeActor(ctx, tx, actor, uuid.Nil, true); err != nil {
			return err
		}
		installation, err := installationID(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM control_installation_entitlement WHERE singleton FOR UPDATE`); err != nil {
			return ErrPersistence
		}
		if existing, found, err := loadEpochByRequest(ctx, tx, request.RequestID, digest); err != nil {
			return err
		} else if found {
			result = existing
			result.Replayed = true
			return nil
		}
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return ErrCAEpochExpired
		}
		var highwater int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(epoch),0) FROM node_ca_key_epochs
			WHERE installation_id=$1`, installation).Scan(&highwater); err != nil {
			return ErrPersistence
		}
		if highwater != request.ExpectedCurrentEpoch {
			return ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE node_ca_key_epochs SET
			status='retired',retired_at=$2 WHERE installation_id=$1 AND status='active'`, installation, now); err != nil {
			return ErrPersistence
		}
		result = CAEpoch{
			ID: uuid.NewSHA1(request.RequestID, []byte("node-ca-key-epoch")), InstallationID: installation,
			Epoch: highwater + 1, KeyID: request.KeyID, Status: EpochActive,
			NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC(), CreatedAt: now,
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_ca_key_epochs(
			id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,
			not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$12,$13,$14)`,
			result.ID, installation, result.Epoch, result.KeyID, request.CACertificatePEM,
			certificateDigest[:], publicKeyDigest[:], result.NotBefore, result.NotAfter,
			request.RequestID, digest[:], actor.ScopeID, actor.UserID, now); err != nil {
			return err
		}
		return appendAudit(ctx, store.auditor, tx, actor.ScopeID, &actor.UserID,
			"node_certificate.ca_epoch.rotate", result.ID.String(), request.RequestTraceID, map[string]any{
				"installation_id": installation, "epoch": result.Epoch, "key_id": result.KeyID,
			})
	})
	if err != nil {
		return CAEpoch{}, wrap("rotate node CA key epoch", err)
	}
	return result, nil
}

func (store *Store) RevokeCAEpoch(ctx context.Context, actor Actor, request RevokeCAEpochRequest) error {
	request.Reason = strings.TrimSpace(request.Reason)
	if request.RequestID == uuid.Nil || request.EpochID == uuid.Nil || request.Reason == "" ||
		len(request.Reason) > 256 || !validTraceID(request.RequestTraceID) {
		return ErrInvalidInput
	}
	digest, err := digestJSON(struct {
		EpochID uuid.UUID `json:"epoch_id"`
		Reason  string    `json:"reason"`
	}{request.EpochID, request.Reason})
	if err != nil {
		return ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeActor(ctx, tx, actor, uuid.Nil, true); err != nil {
			return err
		}
		var storedDigest []byte
		err := tx.QueryRow(ctx, `SELECT request_digest FROM node_ca_key_epoch_revocations
			WHERE request_id=$1`, request.RequestID).Scan(&storedDigest)
		if err == nil {
			if !equalDigest(storedDigest, digest) {
				return ErrIdempotencyConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return ErrPersistence
		}
		var installation, status string
		if err := tx.QueryRow(ctx, `SELECT installation_id,status FROM node_ca_key_epochs
			WHERE id=$1 FOR UPDATE`, request.EpochID).Scan(&installation, &status); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return ErrPersistence
		}
		err = tx.QueryRow(ctx, `SELECT request_digest FROM node_ca_key_epoch_revocations
			WHERE request_id=$1`, request.RequestID).Scan(&storedDigest)
		if err == nil {
			if !equalDigest(storedDigest, digest) {
				return ErrIdempotencyConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return ErrPersistence
		}
		if status == EpochRevoked {
			return ErrCAEpochRevoked
		}
		if _, err := tx.Exec(ctx, `UPDATE node_ca_key_epochs SET status='revoked',revoked_at=$2,
			revocation_reason=$3 WHERE id=$1`, request.EpochID, now, request.Reason); err != nil {
			return ErrPersistence
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_ca_key_epoch_revocations(
			request_id,request_digest,ca_epoch_id,installation_id,reason,revoked_at,actor_scope_id,actor_user_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, request.RequestID, digest[:], request.EpochID,
			installation, request.Reason, now, actor.ScopeID, actor.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE node_identity_state state SET
			authorization_revision=authorization_revision+1,updated_at=GREATEST(updated_at,$2)
			FROM node_certificates certificate WHERE certificate.node_id=state.node_id
			AND certificate.ca_epoch_id=$1 AND certificate.rotation_status IN ('current','overlap')`,
			request.EpochID, now); err != nil {
			return ErrPersistence
		}
		return appendAudit(ctx, store.auditor, tx, actor.ScopeID, &actor.UserID,
			"node_certificate.ca_epoch.revoke", request.EpochID.String(), request.RequestTraceID,
			map[string]any{"installation_id": installation, "reason": request.Reason})
	})
	return wrap("revoke node CA key epoch", err)
}

func loadEpochByRequest(ctx context.Context, tx pgx.Tx, requestID uuid.UUID, digest [32]byte) (CAEpoch, bool, error) {
	var result CAEpoch
	var storedDigest []byte
	err := tx.QueryRow(ctx, `SELECT id,installation_id,epoch,key_id,status,not_before,not_after,created_at,request_digest
		FROM node_ca_key_epochs WHERE request_id=$1`, requestID).Scan(&result.ID, &result.InstallationID,
		&result.Epoch, &result.KeyID, &result.Status, &result.NotBefore, &result.NotAfter, &result.CreatedAt, &storedDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return CAEpoch{}, false, nil
	}
	if err != nil {
		return CAEpoch{}, false, ErrPersistence
	}
	if !equalDigest(storedDigest, digest) {
		return CAEpoch{}, false, ErrIdempotencyConflict
	}
	return result, true, nil
}

func validKeyID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:-", character)) {
			continue
		}
		return false
	}
	return true
}
