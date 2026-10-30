package nodecertlifecycle

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) RecordGatewayMTLSProof(ctx context.Context, request RecordGatewayMTLSProofRequest) (RenewalProofFact, error) {
	if request.RenewalRequestID == uuid.Nil || request.NodeID == uuid.Nil ||
		!validSerial(request.CurrentSerialNumber) || !nonzeroDigest(request.CurrentLeafDERSHA256) ||
		request.TargetCAEpochID == uuid.Nil || !validGatewayMTLSPrincipal(request.Principal) ||
		!validTraceID(request.RequestTraceID) {
		return RenewalProofFact{}, ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	var result RenewalProofFact
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var currentCertificateID uuid.UUID
		var storedSerial, storedWorkload, storedInstance, status, popStatus, installation string
		var csrDigest, storedLeafDigest, messageDigest []byte
		var ownerScopeID, storedEpochID uuid.UUID
		var popRevision int64
		var expiresAt time.Time
		var popObservedAt *time.Time
		err := tx.QueryRow(ctx, `SELECT request.current_certificate_id,request.current_serial_number,
			request.csr_sha256,request.gateway_workload_identity,request.gateway_instance_id,
			request.status,request.expires_at,
			request.pop_status,request.pop_revision,request.owner_scope_id,
			COALESCE(request.installation_id,''),
			COALESCE(request.ca_epoch_id,'00000000-0000-0000-0000-000000000000'::uuid),
			request.current_leaf_der_sha256,request.pop_message_sha256,request.pop_observed_at
			FROM node_certificate_renewal_requests request
			WHERE request.request_id=$1 AND request.node_id=$2 FOR UPDATE`, request.RenewalRequestID,
			request.NodeID).Scan(&currentCertificateID, &storedSerial, &csrDigest, &storedWorkload, &storedInstance,
			&status, &expiresAt, &popStatus, &popRevision, &ownerScopeID, &installation,
			&storedEpochID, &storedLeafDigest, &messageDigest, &popObservedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil || len(csrDigest) != 32 {
			return ErrPersistence
		}
		if storedSerial != request.CurrentSerialNumber || storedWorkload != request.Principal.workloadIdentity ||
			storedInstance != request.Principal.instanceID {
			return ErrPermissionDenied
		}
		if popStatus != ProofLegacyUnbound {
			if len(storedLeafDigest) != 32 || len(messageDigest) != 32 || ownerScopeID == uuid.Nil ||
				installation == "" || storedEpochID == uuid.Nil || popObservedAt == nil || popRevision < 1 {
				return ErrPersistence
			}
			result = RenewalProofFact{
				RenewalRequestID: request.RenewalRequestID, NodeID: request.NodeID,
				OwnerScopeID: ownerScopeID, InstallationID: installation,
				CurrentSerialNumber: storedSerial, TargetCAEpochID: storedEpochID,
				Status: popStatus, Revision: popRevision, ObservedAt: *popObservedAt, Replayed: true,
			}
			copy(result.CSRSHA256[:], csrDigest)
			copy(result.CurrentLeafDERSHA256[:], storedLeafDigest)
			copy(result.MessageSHA256[:], messageDigest)
			if popStatus != ProofGatewayMTLS || result.CurrentLeafDERSHA256 != request.CurrentLeafDERSHA256 ||
				result.TargetCAEpochID != request.TargetCAEpochID {
				return ErrIdempotencyConflict
			}
			message, err := GatewayMTLSProofMessage(result, request.Principal)
			if err != nil {
				return ErrIdempotencyConflict
			}
			if sha256.Sum256(message) != result.MessageSHA256 {
				legacyMessage, legacyErr := legacyGatewayMTLSProofMessage(result, request.Principal)
				if legacyErr != nil || sha256.Sum256(legacyMessage) != result.MessageSHA256 {
					legacyInstanceMessage, legacyInstanceErr := legacyInstanceBoundGatewayMTLSProofMessage(result, request.Principal)
					if legacyInstanceErr != nil || sha256.Sum256(legacyInstanceMessage) != result.MessageSHA256 {
						return ErrIdempotencyConflict
					}
				}
			}
			return nil
		}
		if status == "expired" || !now.Before(expiresAt) {
			return ErrCertificateExpired
		}
		current, err := loadCertificateFact(ctx, tx, request.NodeID, request.CurrentSerialNumber)
		if err != nil {
			return err
		}
		if current.CertificateID != currentCertificateID || current.RotationStatus != RotationCurrent ||
			current.Status != "active" || current.LeafDERSHA256 != request.CurrentLeafDERSHA256 {
			return ErrCertificateInvalid
		}
		if now.Before(current.RenewalAt) {
			return ErrRenewalTooEarly
		}
		if now.Before(current.NotBefore) || !now.Before(current.NotAfter) {
			return ErrCertificateExpired
		}
		if revoked, err := effectiveRevocation(ctx, tx, current.CertificateID, now); err != nil {
			return err
		} else if revoked {
			return ErrCertificateRevoked
		}
		if current.InstallationID == "" || current.CAEpochID == uuid.Nil {
			return ErrCertificateInvalid
		}
		var targetStatus string
		var targetNotBefore, targetNotAfter time.Time
		if err := tx.QueryRow(ctx, `SELECT status,not_before,not_after FROM node_ca_key_epochs
			WHERE id=$1 AND installation_id=$2`, request.TargetCAEpochID, current.InstallationID).Scan(
			&targetStatus, &targetNotBefore, &targetNotAfter); errors.Is(err, pgx.ErrNoRows) {
			return ErrCAEpochConflict
		} else if err != nil {
			return ErrPersistence
		}
		if targetStatus != EpochActive {
			if targetStatus == EpochRevoked {
				return ErrCAEpochRevoked
			}
			return ErrCAEpochConflict
		}
		if now.Before(targetNotBefore) || !now.Before(targetNotAfter) {
			return ErrCAEpochExpired
		}
		result = RenewalProofFact{
			RenewalRequestID: request.RenewalRequestID, NodeID: request.NodeID,
			OwnerScopeID: current.OwnerScopeID, InstallationID: current.InstallationID,
			CurrentSerialNumber: current.SerialNumber, CurrentLeafDERSHA256: current.LeafDERSHA256,
			TargetCAEpochID: request.TargetCAEpochID, Status: ProofGatewayMTLS,
			Revision: 1, ObservedAt: now,
		}
		copy(result.CSRSHA256[:], csrDigest)
		message, err := GatewayMTLSProofMessage(result, request.Principal)
		if err != nil {
			return err
		}
		result.MessageSHA256 = sha256.Sum256(message)
		command, err := tx.Exec(ctx, `UPDATE node_certificate_renewal_requests SET
			owner_scope_id=$2,installation_id=$3,ca_epoch_id=$4,current_leaf_der_sha256=$5,
			pop_status='gateway_mtls_proven',pop_revision=1,pop_method='gateway_mtls',
			pop_message_sha256=$6,pop_observed_at=$7
			WHERE request_id=$1 AND pop_status='legacy_unbound'`, request.RenewalRequestID,
			result.OwnerScopeID, result.InstallationID, result.TargetCAEpochID,
			result.CurrentLeafDERSHA256[:], result.MessageSHA256[:], now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		return appendAudit(ctx, store.auditor, tx, result.OwnerScopeID, nil,
			"node_certificate.renewal.gateway_mtls_proof", request.RenewalRequestID.String(),
			request.RequestTraceID, map[string]any{
				"node_id": request.NodeID.String(), "serial_number": request.CurrentSerialNumber,
				"installation_id": result.InstallationID, "target_ca_epoch_id": request.TargetCAEpochID.String(),
				"gateway_instance_id": request.Principal.instanceID,
			})
	})
	if err != nil {
		return RenewalProofFact{}, wrap("record node certificate Gateway mTLS proof", err)
	}
	return result, nil
}

func (store *Store) BindIssuedRenewal(ctx context.Context, request BindIssuedRenewalRequest) (RotationResult, error) {
	if request.RenewalRequestID == uuid.Nil || request.NodeID == uuid.Nil ||
		!validSerial(request.NewSerialNumber) || !nonzeroDigest(request.NewLeafDERSHA256) ||
		!validTraceID(request.RequestTraceID) {
		return RotationResult{}, ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	var result RotationResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		proof, currentID, issuedID, requestDigest, err := loadRenewalProofForUpdate(ctx, tx, request.RenewalRequestID, request.NodeID)
		if err != nil {
			return err
		}
		if proof.Status == ProofLegacyUnbound {
			return ErrRenewalNotProven
		}
		if issuedID == nil {
			return ErrNotFound
		}
		if proof.RotationBoundAt != nil {
			if proof.NewSerialNumber() != request.NewSerialNumber {
				return ErrIdempotencyConflict
			}
			current, err := loadCertificateFact(ctx, tx, request.NodeID, request.NewSerialNumber)
			if err != nil {
				return err
			}
			if current.CertificateID != *issuedID || current.LeafDERSHA256 != request.NewLeafDERSHA256 {
				return ErrIdempotencyConflict
			}
			previous, err := loadCertificateFactByID(ctx, tx, currentID)
			if err != nil {
				return err
			}
			result = RotationResult{Proof: proof, CurrentCertificate: current.CertificateState,
				PreviousCertificate: previous.CertificateState, Replayed: true}
			if err := tx.QueryRow(ctx, `SELECT authorization_revision FROM node_identity_state WHERE node_id=$1`,
				request.NodeID).Scan(&result.AuthorizationRevision); err != nil {
				return ErrPersistence
			}
			return nil
		}
		var lockedCurrentID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM node_certificates WHERE id=$1 FOR UPDATE`, currentID).
			Scan(&lockedCurrentID); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil || lockedCurrentID != currentID {
			return ErrPersistence
		}
		current, err := loadCertificateFactByID(ctx, tx, currentID)
		if err != nil {
			return err
		}
		issued, err := loadCertificateFact(ctx, tx, request.NodeID, request.NewSerialNumber)
		if err != nil {
			return err
		}
		if issued.CertificateID != *issuedID || issued.issuanceKind != "renewal" ||
			issued.replacesID == nil || *issued.replacesID != current.CertificateID ||
			issued.renewalRequestID == nil || *issued.renewalRequestID != request.RenewalRequestID ||
			issued.csrHash != proof.CSRSHA256 || issued.Status != "active" ||
			issued.RotationStatus != RotationLegacyUnbound {
			return ErrCertificateInvalid
		}
		if current.RotationStatus != RotationCurrent || current.Status != "active" ||
			current.LeafDERSHA256 != proof.CurrentLeafDERSHA256 {
			return ErrCertificateInvalid
		}
		if revoked, err := effectiveRevocation(ctx, tx, current.CertificateID, now); err != nil {
			return err
		} else if revoked {
			return ErrCertificateRevoked
		}
		if now.Before(issued.NotBefore) || !now.Before(issued.NotAfter) {
			return ErrCertificateExpired
		}
		if issued.LeafDERSHA256 != [32]byte{} && issued.LeafDERSHA256 != request.NewLeafDERSHA256 {
			return ErrIdempotencyConflict
		}
		var caPEM []byte
		var caStatus string
		var caNotBefore, caNotAfter time.Time
		if err := tx.QueryRow(ctx, `SELECT ca_certificate_pem,status,not_before,not_after FROM node_ca_key_epochs
			WHERE id=$1 AND installation_id=$2`, proof.TargetCAEpochID, proof.InstallationID).Scan(
			&caPEM, &caStatus, &caNotBefore, &caNotAfter); errors.Is(err, pgx.ErrNoRows) {
			return ErrCAEpochConflict
		} else if err != nil {
			return ErrPersistence
		}
		if caStatus != EpochActive {
			if caStatus == EpochRevoked {
				return ErrCAEpochRevoked
			}
			return ErrCAEpochConflict
		}
		if now.Before(caNotBefore) || !now.Before(caNotAfter) {
			return ErrCAEpochExpired
		}
		leaf, err := parseCertificatePEM(issued.leafPEM)
		if err != nil {
			return err
		}
		authority, err := parseCertificatePEM(caPEM)
		if err != nil || verifyLeaf(leaf, authority, request.NodeID, request.NewSerialNumber, request.NewLeafDERSHA256) != nil {
			return ErrCertificateInvalid
		}
		var overlapID uuid.UUID
		var overlapUntil time.Time
		err = tx.QueryRow(ctx, `SELECT id,overlap_until FROM node_certificates
			WHERE node_id=$1 AND installation_id=$2 AND rotation_status='overlap' AND status='active'
			FOR UPDATE`, request.NodeID, proof.InstallationID).Scan(&overlapID, &overlapUntil)
		if err == nil {
			if now.Before(overlapUntil) {
				return ErrOverlapActive
			}
			if _, err := tx.Exec(ctx, `UPDATE node_certificates SET rotation_status='retired',
				lifecycle_revision=lifecycle_revision+1 WHERE id=$1`, overlapID); err != nil {
				return ErrPersistence
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return ErrPersistence
		}
		overlapUntil = now.Add(store.overlap)
		if current.NotAfter.Before(overlapUntil) {
			overlapUntil = current.NotAfter
		}
		if !overlapUntil.After(now) {
			return ErrCertificateExpired
		}
		currentUpdate, err := tx.Exec(ctx, `UPDATE node_certificates SET rotation_status='overlap',
			lifecycle_revision=lifecycle_revision+1,overlap_until=$2
			WHERE id=$1 AND status='active' AND rotation_status='current'`,
			current.CertificateID, overlapUntil)
		if err != nil {
			return err
		}
		if currentUpdate.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		issuedUpdate, err := tx.Exec(ctx, `UPDATE node_certificates SET
			owner_scope_id=$2,installation_id=$3,ca_epoch_id=$4,leaf_der_sha256=$5,
			rotation_status='current',lifecycle_revision=1,lifecycle_request_id=$6,
			lifecycle_request_digest=$7,lifecycle_bound_at=$8
			WHERE id=$1 AND rotation_status='legacy_unbound'`, issued.CertificateID, proof.OwnerScopeID,
			proof.InstallationID, proof.TargetCAEpochID, request.NewLeafDERSHA256[:],
			request.RenewalRequestID, requestDigest, now)
		if err != nil {
			return err
		}
		if issuedUpdate.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		command, err := tx.Exec(ctx, `UPDATE node_certificate_renewal_requests SET
			issued_leaf_der_sha256=$2,issued_ca_epoch_id=$3,rotation_bound_at=$4,
			overlap_until=$5,pop_revision=pop_revision+1
			WHERE request_id=$1 AND rotation_bound_at IS NULL`, request.RenewalRequestID,
			request.NewLeafDERSHA256[:], proof.TargetCAEpochID, now, overlapUntil)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		revision, err := incrementAuthorizationRevision(ctx, tx, request.NodeID, now)
		if err != nil {
			return err
		}
		if err := appendAudit(ctx, store.auditor, tx, proof.OwnerScopeID, nil,
			"node_certificate.renewal.bind", issued.CertificateID.String(), request.RequestTraceID,
			map[string]any{"node_id": request.NodeID.String(), "old_serial_number": current.SerialNumber,
				"new_serial_number": issued.SerialNumber, "overlap_until": overlapUntil,
				"ca_epoch_id": proof.TargetCAEpochID.String()}); err != nil {
			return err
		}
		proof.RotationBoundAt = &now
		proof.OverlapUntil = &overlapUntil
		proof.Revision++
		current.RotationStatus = RotationOverlap
		current.OverlapUntil = &overlapUntil
		current.Revision++
		issued.OwnerScopeID = proof.OwnerScopeID
		issued.InstallationID = proof.InstallationID
		issued.CAEpochID = proof.TargetCAEpochID
		issued.LeafDERSHA256 = request.NewLeafDERSHA256
		issued.RotationStatus = RotationCurrent
		issued.Revision = 1
		result = RotationResult{Proof: proof, CurrentCertificate: issued.CertificateState,
			PreviousCertificate: current.CertificateState, AuthorizationRevision: revision}
		return nil
	})
	if err != nil {
		return RotationResult{}, wrap("bind issued node certificate renewal", err)
	}
	return result, nil
}

func effectiveRevocation(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, certificateID uuid.UUID, now time.Time) (bool, error) {
	effectiveAt, found, err := earliestRevocation(ctx, query, certificateID)
	return found && (effectiveAt == nil || !now.Before(*effectiveAt)), err
}

func earliestRevocation(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, certificateID uuid.UUID) (*time.Time, bool, error) {
	var effectiveAt *time.Time
	err := query.QueryRow(ctx, `SELECT effective_at FROM node_certificate_revocations
		WHERE certificate_id=$1 ORDER BY effective_at ASC NULLS FIRST LIMIT 1`, certificateID).Scan(&effectiveAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, ErrPersistence
	}
	return effectiveAt, true, nil
}

func loadCertificateFactByID(ctx context.Context, tx pgx.Tx, certificateID uuid.UUID) (certificateFact, error) {
	var nodeID uuid.UUID
	var serial string
	if err := tx.QueryRow(ctx, `SELECT node_id,serial_number FROM node_certificates WHERE id=$1`,
		certificateID).Scan(&nodeID, &serial); errors.Is(err, pgx.ErrNoRows) {
		return certificateFact{}, ErrNotFound
	} else if err != nil {
		return certificateFact{}, ErrPersistence
	}
	return loadCertificateFact(ctx, tx, nodeID, serial)
}

func loadRenewalProofForUpdate(ctx context.Context, tx pgx.Tx, requestID, nodeID uuid.UUID) (
	RenewalProofFact, uuid.UUID, *uuid.UUID, []byte, error,
) {
	var result RenewalProofFact
	var currentID uuid.UUID
	var issuedID *uuid.UUID
	var requestDigest, csrDigest, leafDigest, messageDigest []byte
	var ownerScopeID *uuid.UUID
	var installation, popStatus string
	var epochID *uuid.UUID
	var popObservedAt, rotationBoundAt, overlapUntil *time.Time
	var popRevision int64
	var issuedSerial *string
	err := tx.QueryRow(ctx, `SELECT request.current_certificate_id,request.issued_certificate_id,
		request.request_digest,request.current_serial_number,request.csr_sha256,request.pop_status,
		request.pop_revision,request.owner_scope_id,COALESCE(request.installation_id,''),request.ca_epoch_id,
		request.current_leaf_der_sha256,request.pop_message_sha256,request.pop_observed_at,
		request.rotation_bound_at,request.overlap_until,issued.serial_number
		FROM node_certificate_renewal_requests request
		LEFT JOIN node_certificates issued ON issued.id=request.issued_certificate_id
		WHERE request.request_id=$1 AND request.node_id=$2 FOR UPDATE OF request`, requestID, nodeID).Scan(
		&currentID, &issuedID, &requestDigest, &result.CurrentSerialNumber, &csrDigest, &popStatus,
		&popRevision, &ownerScopeID, &installation, &epochID, &leafDigest, &messageDigest,
		&popObservedAt, &rotationBoundAt, &overlapUntil, &issuedSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		return RenewalProofFact{}, uuid.Nil, nil, nil, ErrNotFound
	}
	if err != nil || len(requestDigest) != 32 || len(csrDigest) != 32 {
		return RenewalProofFact{}, uuid.Nil, nil, nil, ErrPersistence
	}
	if popStatus != ProofLegacyUnbound && (ownerScopeID == nil || installation == "" || epochID == nil ||
		len(leafDigest) != 32 || len(messageDigest) != 32 || popObservedAt == nil) {
		return RenewalProofFact{}, uuid.Nil, nil, nil, ErrPersistence
	}
	result.RenewalRequestID, result.NodeID, result.Status, result.Revision = requestID, nodeID, popStatus, popRevision
	result.InstallationID, result.RotationBoundAt, result.OverlapUntil = installation, rotationBoundAt, overlapUntil
	if ownerScopeID != nil {
		result.OwnerScopeID = *ownerScopeID
	}
	if epochID != nil {
		result.TargetCAEpochID = *epochID
	}
	copy(result.CSRSHA256[:], csrDigest)
	copy(result.CurrentLeafDERSHA256[:], leafDigest)
	copy(result.MessageSHA256[:], messageDigest)
	if popObservedAt != nil {
		result.ObservedAt = *popObservedAt
	}
	if issuedSerial != nil {
		result.newSerialNumber = *issuedSerial
	}
	return result, currentID, issuedID, requestDigest, nil
}

func (fact RenewalProofFact) NewSerialNumber() string { return fact.newSerialNumber }
