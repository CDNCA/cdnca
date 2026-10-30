package nodecertlifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) AdoptCertificate(ctx context.Context, actor Actor, request AdoptCertificateRequest) (CertificateState, error) {
	if request.RequestID == uuid.Nil || request.NodeID == uuid.Nil || !validSerial(request.SerialNumber) ||
		!nonzeroDigest(request.LeafDERSHA256) || request.CAEpochID == uuid.Nil ||
		!validTraceID(request.RequestTraceID) {
		return CertificateState{}, ErrInvalidInput
	}
	digest, err := digestJSON(struct {
		NodeID        uuid.UUID `json:"node_id"`
		SerialNumber  string    `json:"serial_number"`
		LeafDERSHA256 [32]byte  `json:"leaf_der_sha256"`
		CAEpochID     uuid.UUID `json:"ca_epoch_id"`
	}{request.NodeID, request.SerialNumber, request.LeafDERSHA256, request.CAEpochID})
	if err != nil {
		return CertificateState{}, ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	var result CertificateState
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		fact, err := loadCertificateFact(ctx, tx, request.NodeID, request.SerialNumber)
		if err != nil {
			return err
		}
		if err := authorizeActor(ctx, tx, actor, fact.OwnerScopeID, false); err != nil {
			return err
		}
		if fact.lifecycleRequestID != nil {
			if *fact.lifecycleRequestID != request.RequestID || fact.lifecycleRequestDigest != digest {
				return ErrIdempotencyConflict
			}
			if fact.RotationStatus != RotationCurrent || fact.CAEpochID != request.CAEpochID ||
				fact.LeafDERSHA256 != request.LeafDERSHA256 {
				return ErrPersistence
			}
			result = fact.CertificateState
			result.Replayed = true
			return nil
		}
		installation, err := installationID(ctx, tx)
		if err != nil {
			return err
		}
		var caPEM []byte
		var caStatus string
		var caNotBefore, caNotAfter time.Time
		if err := tx.QueryRow(ctx, `SELECT ca_certificate_pem,status,not_before,not_after FROM node_ca_key_epochs
			WHERE id=$1 AND installation_id=$2`, request.CAEpochID, installation).Scan(
			&caPEM, &caStatus, &caNotBefore, &caNotAfter); errors.Is(err, pgx.ErrNoRows) {
			return ErrCAEpochConflict
		} else if err != nil {
			return ErrPersistence
		}
		if caStatus == EpochRevoked {
			return ErrCAEpochRevoked
		}
		if now.Before(caNotBefore) || !now.Before(caNotAfter) {
			return ErrCAEpochExpired
		}
		if fact.RotationStatus != RotationLegacyUnbound || fact.Status != "active" {
			return ErrRevisionConflict
		}
		if now.Before(fact.NotBefore) || !now.Before(fact.NotAfter) {
			return ErrCertificateExpired
		}
		if revoked, err := effectiveRevocation(ctx, tx, fact.CertificateID, now); err != nil {
			return err
		} else if revoked {
			return ErrCertificateRevoked
		}
		leaf, err := parseCertificatePEM(fact.leafPEM)
		if err != nil {
			return err
		}
		authority, err := parseCertificatePEM(caPEM)
		if err != nil || verifyLeaf(leaf, authority, request.NodeID, request.SerialNumber, request.LeafDERSHA256) != nil {
			return ErrCertificateInvalid
		}
		command, err := tx.Exec(ctx, `UPDATE node_certificates SET
			owner_scope_id=$2,installation_id=$3,ca_epoch_id=$4,leaf_der_sha256=$5,
			rotation_status='current',lifecycle_revision=1,lifecycle_request_id=$6,
			lifecycle_request_digest=$7,lifecycle_bound_at=$8
			WHERE id=$1 AND rotation_status='legacy_unbound'`, fact.CertificateID, fact.OwnerScopeID,
			installation, request.CAEpochID, request.LeafDERSHA256[:], request.RequestID, digest[:], now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			replayed, loadErr := loadCertificateFact(ctx, tx, request.NodeID, request.SerialNumber)
			if loadErr != nil {
				return ErrRevisionConflict
			}
			if replayed.lifecycleRequestID == nil || *replayed.lifecycleRequestID != request.RequestID ||
				replayed.lifecycleRequestDigest != digest {
				return ErrIdempotencyConflict
			}
			result = replayed.CertificateState
			result.Replayed = true
			return nil
		}
		if _, err := incrementAuthorizationRevision(ctx, tx, request.NodeID, now); err != nil {
			return err
		}
		if err := appendAudit(ctx, store.auditor, tx, fact.OwnerScopeID, &actor.UserID,
			"node_certificate.lifecycle.adopt", fact.CertificateID.String(), request.RequestTraceID,
			map[string]any{"node_id": request.NodeID.String(), "serial_number": request.SerialNumber,
				"installation_id": installation, "ca_epoch_id": request.CAEpochID.String()}); err != nil {
			return err
		}
		result = fact.CertificateState
		result.InstallationID = installation
		result.CAEpochID = request.CAEpochID
		result.LeafDERSHA256 = request.LeafDERSHA256
		result.RotationStatus = RotationCurrent
		result.Revision = 1
		return nil
	})
	if err != nil {
		return CertificateState{}, wrap("adopt node certificate lifecycle", err)
	}
	return result, nil
}
