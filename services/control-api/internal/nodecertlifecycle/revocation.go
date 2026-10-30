package nodecertlifecycle

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) RevokeCertificate(ctx context.Context, actor Actor, request RevokeCertificateRequest) (Revocation, error) {
	request.Reason = strings.TrimSpace(request.Reason)
	if request.RequestID == uuid.Nil || request.NodeID == uuid.Nil || !validSerial(request.SerialNumber) ||
		!nonzeroDigest(request.LeafDERSHA256) || request.Reason == "" ||
		utf8.RuneCountInString(request.Reason) > 256 || !utf8.ValidString(request.Reason) ||
		strings.ContainsRune(request.Reason, '\x00') || !validTraceID(request.RequestTraceID) {
		return Revocation{}, ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	effectiveAt := request.EffectiveAt
	digestEffectiveAt := request.EffectiveAt
	if effectiveAt.IsZero() {
		effectiveAt = now
	} else {
		effectiveAt = effectiveAt.UTC().Truncate(time.Microsecond)
		digestEffectiveAt = effectiveAt
	}
	digest, err := digestJSON(struct {
		NodeID        uuid.UUID `json:"node_id"`
		SerialNumber  string    `json:"serial_number"`
		LeafDERSHA256 [32]byte  `json:"leaf_der_sha256"`
		Reason        string    `json:"reason"`
		EffectiveAt   time.Time `json:"effective_at"`
	}{request.NodeID, request.SerialNumber, request.LeafDERSHA256, request.Reason, digestEffectiveAt})
	if err != nil {
		return Revocation{}, ErrInvalidInput
	}

	var result Revocation
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		replayed, found, err := store.loadRevocationByRequest(ctx, tx, actor, request.RequestID, digest)
		if err != nil {
			return err
		}
		if found {
			result = replayed
			return nil
		}
		if effectiveAt.Before(now) || effectiveAt.Sub(now) > store.maxScheduledRevocation {
			return ErrInvalidInput
		}

		var certificateID uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM node_certificates
			WHERE node_id=$1 AND serial_number=$2 FOR UPDATE`, request.NodeID, request.SerialNumber).Scan(&certificateID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return ErrPersistence
		}
		if replayed, found, err := store.loadRevocationByRequest(ctx, tx, actor, request.RequestID, digest); err != nil {
			return err
		} else if found {
			result = replayed
			return nil
		}
		fact, err := loadCertificateFact(ctx, tx, request.NodeID, request.SerialNumber)
		if err != nil {
			return err
		}
		if fact.CertificateID != certificateID || fact.RotationStatus == RotationLegacyUnbound ||
			fact.OwnerScopeID == uuid.Nil || fact.InstallationID == "" || fact.CAEpochID == uuid.Nil ||
			fact.LeafDERSHA256 != request.LeafDERSHA256 {
			return ErrCertificateInvalid
		}
		if err := authorizeActor(ctx, tx, actor, fact.OwnerScopeID, false); err != nil {
			return err
		}
		installation, err := installationID(ctx, tx)
		if err != nil {
			return err
		}
		if installation != fact.InstallationID {
			return ErrCertificateInvalid
		}
		if fact.Status == "revoked" {
			return ErrCertificateRevoked
		}
		if fact.Status != "active" {
			return ErrCertificateInvalid
		}
		earliest, found, err := earliestRevocation(ctx, tx, fact.CertificateID)
		if err != nil {
			return err
		}
		if found && (earliest == nil || !now.Before(*earliest)) {
			return ErrCertificateRevoked
		}
		if found && !effectiveAt.Before(*earliest) {
			return ErrCertificateRevoked
		}

		revision, err := incrementAuthorizationRevision(ctx, tx, request.NodeID, now)
		if err != nil {
			return err
		}
		result = Revocation{
			RequestID: request.RequestID, CertificateID: fact.CertificateID, NodeID: request.NodeID,
			OwnerScopeID: fact.OwnerScopeID, InstallationID: fact.InstallationID,
			SerialNumber: request.SerialNumber, Reason: request.Reason, EffectiveAt: effectiveAt,
			RequestedAt: now, AuthorizationRevision: revision,
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_certificate_revocations(
			request_id,request_digest,certificate_id,node_id,reason,revoked_at,authorization_revision,
			owner_scope_id,installation_id,ca_epoch_id,leaf_der_sha256,effective_at,binding_status)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'bound')`, request.RequestID, digest[:],
			fact.CertificateID, request.NodeID, request.Reason, now, revision, fact.OwnerScopeID,
			fact.InstallationID, fact.CAEpochID, request.LeafDERSHA256[:], effectiveAt); err != nil {
			return err
		}
		if !effectiveAt.After(now) {
			command, err := tx.Exec(ctx, `UPDATE node_certificates SET status='revoked',revoked_at=$2,
				revocation_reason=$3 WHERE id=$1 AND status='active'`, fact.CertificateID, effectiveAt, request.Reason)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		}
		if !effectiveAt.After(now) {
			eventID := uuid.NewSHA1(request.RequestID, []byte("node-certificate-revocation-event"))
			if _, err := tx.Exec(ctx, `INSERT INTO node_certificate_events(
				id,node_id,certificate_id,event_type,reason,authorization_revision,occurred_at)
				VALUES($1,$2,$3,'revoked',$4,$5,$6)`, eventID, request.NodeID, fact.CertificateID,
				request.Reason, revision, now); err != nil {
				return err
			}
		}
		return appendAudit(ctx, store.auditor, tx, fact.OwnerScopeID, &actor.UserID,
			"node_certificate.lifecycle.revoke", fact.CertificateID.String(), request.RequestTraceID,
			map[string]any{"node_id": request.NodeID.String(), "serial_number": request.SerialNumber,
				"installation_id": fact.InstallationID, "ca_epoch_id": fact.CAEpochID.String(),
				"reason": request.Reason, "effective_at": effectiveAt})
	})
	if err != nil {
		return Revocation{}, wrap("revoke node certificate", err)
	}
	return result, nil
}

func (store *Store) loadRevocationByRequest(
	ctx context.Context, tx pgx.Tx, actor Actor, requestID uuid.UUID, digest [32]byte,
) (Revocation, bool, error) {
	var result Revocation
	var storedDigest []byte
	var bindingStatus string
	err := tx.QueryRow(ctx, `SELECT request_digest,binding_status FROM node_certificate_revocations
		WHERE request_id=$1`, requestID).Scan(&storedDigest, &bindingStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return Revocation{}, false, nil
	}
	if err != nil {
		return Revocation{}, false, ErrPersistence
	}
	if bindingStatus != "bound" || !equalDigest(storedDigest, digest) {
		return Revocation{}, false, ErrIdempotencyConflict
	}
	var revision int64
	err = tx.QueryRow(ctx, `SELECT revocation.request_id,revocation.certificate_id,revocation.node_id,
		revocation.owner_scope_id,revocation.installation_id,certificate.serial_number,
		revocation.reason,revocation.effective_at,revocation.revoked_at,
		revocation.authorization_revision
		FROM node_certificate_revocations revocation
		JOIN node_certificates certificate ON certificate.id=revocation.certificate_id
		WHERE revocation.request_id=$1 AND revocation.binding_status='bound'`, requestID).Scan(
		&result.RequestID, &result.CertificateID, &result.NodeID, &result.OwnerScopeID,
		&result.InstallationID, &result.SerialNumber, &result.Reason, &result.EffectiveAt,
		&result.RequestedAt, &revision)
	if err != nil || revision < 1 {
		return Revocation{}, false, ErrPersistence
	}
	result.AuthorizationRevision = uint64(revision)
	if err := authorizeActor(ctx, tx, actor, result.OwnerScopeID, false); err != nil {
		return Revocation{}, false, err
	}
	result.Replayed = true
	return result, true, nil
}
