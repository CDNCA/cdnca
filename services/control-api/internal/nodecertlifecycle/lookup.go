package nodecertlifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	denialLegacyUnbound      = "certificate_legacy_unbound"
	denialBindingInvalid     = "certificate_binding_invalid"
	denialCAEpochUnknown     = "ca_epoch_unknown"
	denialCAEpochRevoked     = "ca_epoch_revoked"
	denialCAEpochPending     = "ca_epoch_not_yet_valid"
	denialCAEpochExpired     = "ca_epoch_expired"
	denialCertificatePending = "certificate_not_yet_valid"
	denialCertificateExpired = "certificate_expired"
	denialCertificateRevoked = "certificate_revoked"
	denialCertificateRetired = "certificate_retired"
	denialOverlapExpired     = "certificate_overlap_expired"
	denialNodeInactive       = "node_inactive"
)

func (store *Store) LookupAuthorization(ctx context.Context, request LookupRequest) (AuthorizationSnapshot, error) {
	if request.NodeID == uuid.Nil || !validSerial(request.SerialNumber) || !nonzeroDigest(request.LeafDERSHA256) {
		return AuthorizationSnapshot{}, ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	snapshotExpiresAt := now.Add(store.snapshotTTL)

	var result AuthorizationSnapshot
	var revision int64
	var ownerScopeID, caEpochID *uuid.UUID
	var installation, caStatus string
	var caEpoch int64
	var caNotBefore, caNotAfter *time.Time
	var leafDigest []byte
	var scheduledRevocation *time.Time
	var revocationBinding string
	err := store.pool.QueryRow(ctx, `SELECT certificate.node_id,certificate.id,node.scope_id,
		certificate.owner_scope_id,COALESCE(certificate.installation_id,''),certificate.serial_number,
		certificate.leaf_der_sha256,certificate.ca_epoch_id,COALESCE(epoch.epoch,0),COALESCE(epoch.status,''),
		epoch.not_before,epoch.not_after,
		state.authorization_revision,node.admin_state,certificate.status,certificate.rotation_status,
		certificate.not_before,certificate.not_after,certificate.overlap_until,revocation.effective_at,
		COALESCE(revocation.binding_status,'')
		FROM node_certificates certificate
		JOIN nodes node ON node.id=certificate.node_id
		JOIN node_identity_state state ON state.node_id=node.id
		LEFT JOIN node_ca_key_epochs epoch ON epoch.id=certificate.ca_epoch_id
		LEFT JOIN LATERAL (
			SELECT CASE WHEN bool_or(item.binding_status='legacy_unbound')
				THEN 'legacy_unbound' ELSE 'bound' END AS binding_status,
				CASE WHEN bool_or(item.effective_at IS NULL) THEN NULL ELSE min(item.effective_at) END AS effective_at
			FROM node_certificate_revocations item
			WHERE item.certificate_id=certificate.id
			HAVING count(*) > 0
		) revocation ON true
		WHERE certificate.node_id=$1 AND certificate.serial_number=$2 AND certificate.leaf_der_sha256=$3`,
		request.NodeID, request.SerialNumber, request.LeafDERSHA256[:]).Scan(
		&result.NodeID, &result.CertificateID, &result.OwnerScopeID, &ownerScopeID, &installation,
		&result.SerialNumber, &leafDigest, &caEpochID, &caEpoch, &caStatus, &caNotBefore, &caNotAfter,
		&revision, &result.AdministrativeState, &result.CertificateStatus, &result.RotationStatus,
		&result.CertificateNotBefore, &result.CertificateNotAfter, &result.OverlapUntil, &scheduledRevocation,
		&revocationBinding)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthorizationSnapshot{}, ErrNotFound
	}
	if err != nil || revision < 1 || len(leafDigest) != 32 {
		return AuthorizationSnapshot{}, ErrPersistence
	}
	copy(result.LeafDERSHA256[:], leafDigest)
	result.AuthorizationRevision = uint64(revision)
	result.InstallationID = installation
	result.CAEpoch = caEpoch
	if caEpochID != nil {
		result.CAEpochID = *caEpochID
	}

	if result.CertificateNotAfter.Before(snapshotExpiresAt) {
		snapshotExpiresAt = result.CertificateNotAfter
	}
	if caNotAfter != nil && caNotAfter.Before(snapshotExpiresAt) {
		snapshotExpiresAt = *caNotAfter
	}
	if now.Before(result.CertificateNotBefore) && result.CertificateNotBefore.Before(snapshotExpiresAt) {
		snapshotExpiresAt = result.CertificateNotBefore
	}
	if result.OverlapUntil != nil && result.OverlapUntil.Before(snapshotExpiresAt) {
		snapshotExpiresAt = *result.OverlapUntil
	}
	if scheduledRevocation != nil && scheduledRevocation.Before(snapshotExpiresAt) {
		snapshotExpiresAt = *scheduledRevocation
	}
	result.SnapshotExpiresAt = snapshotExpiresAt

	currentInstallation, installErr := installationID(ctx, store.pool)
	if installErr != nil && !errors.Is(installErr, ErrInstallationMissing) {
		return AuthorizationSnapshot{}, installErr
	}
	switch {
	case result.RotationStatus == RotationLegacyUnbound:
		result.DenialReason = denialLegacyUnbound
	case ownerScopeID == nil || *ownerScopeID != result.OwnerScopeID || installation == "" ||
		caEpochID == nil || result.LeafDERSHA256 != request.LeafDERSHA256:
		result.DenialReason = denialBindingInvalid
	case installErr != nil || currentInstallation != installation:
		result.DenialReason = denialBindingInvalid
	case caStatus == "" || caEpoch < 1:
		result.DenialReason = denialCAEpochUnknown
	case caStatus == EpochRevoked:
		result.DenialReason = denialCAEpochRevoked
	case caNotBefore == nil || caNotAfter == nil:
		result.DenialReason = denialCAEpochUnknown
	case now.Before(*caNotBefore):
		result.DenialReason = denialCAEpochPending
	case !now.Before(*caNotAfter):
		result.DenialReason = denialCAEpochExpired
	case result.CertificateNotBefore.Before(*caNotBefore) || result.CertificateNotAfter.After(*caNotAfter):
		result.DenialReason = denialBindingInvalid
	case now.Before(result.CertificateNotBefore):
		result.DenialReason = denialCertificatePending
	case !now.Before(result.CertificateNotAfter):
		result.DenialReason = denialCertificateExpired
	case revocationBinding == RotationLegacyUnbound:
		result.DenialReason = denialCertificateRevoked
	case revocationBinding != "" && revocationBinding != "bound":
		result.DenialReason = denialBindingInvalid
	case result.CertificateStatus == "revoked" ||
		(scheduledRevocation != nil && !now.Before(*scheduledRevocation)):
		result.DenialReason = denialCertificateRevoked
	case result.CertificateStatus != "active":
		result.DenialReason = denialBindingInvalid
	case result.RotationStatus == RotationRetired:
		result.DenialReason = denialCertificateRetired
	case result.RotationStatus == RotationOverlap &&
		(result.OverlapUntil == nil || !now.Before(*result.OverlapUntil)):
		result.DenialReason = denialOverlapExpired
	case result.RotationStatus != RotationCurrent && result.RotationStatus != RotationOverlap:
		result.DenialReason = denialBindingInvalid
	case result.AdministrativeState != "active" && result.AdministrativeState != "draining":
		result.DenialReason = denialNodeInactive
	default:
		result.ConnectionAllowed = true
		result.DeploymentsAllowed = result.RotationStatus == RotationCurrent &&
			result.AdministrativeState == "active"
	}
	return result, nil
}
