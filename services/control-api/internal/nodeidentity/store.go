package nodeidentity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"time"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool, auditor: audit.New(pool)} }

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type authorizeStoreInput struct {
	normalizedAuthorize
	AuthorizationID uuid.UUID
	AuthorizedAt    time.Time
	ExpiresAt       time.Time
}

type enrollmentSigningClaim struct {
	AuthorizationID         uuid.UUID
	LifecycleRequestID      uuid.UUID
	NodeID                  uuid.UUID
	CSRDER                  []byte
	CSRHash                 [32]byte
	ArtifactKeyID           string
	GatewayWorkloadIdentity string
	GatewayInstanceID       string
	LeaseID                 uuid.UUID
	Existing                *Certificate
}

type renewalSigningClaim struct {
	RequestID            uuid.UUID
	NodeID               uuid.UUID
	CurrentCertificateID uuid.UUID
	CSRDER               []byte
	CSRHash              [32]byte
	LeaseID              uuid.UUID
	Existing             *Certificate
}

type persistedCertificate struct {
	Certificate
	CSRHash                   [32]byte
	PublicKeyHash             [32]byte
	URISAN                    string
	LeafHash                  [32]byte
	LeafDERHash               [32]byte
	IssuerCAHash              [32]byte
	EnrollmentAuthorizationID *uuid.UUID
	RenewalRequestID          *uuid.UUID
	ReplacesCertificateID     *uuid.UUID
}

func (s *Store) authorize(ctx context.Context, input authorizeStoreInput) (Authorization, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Authorization{}, ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if existing, digest, found, err := loadAuthorizationByRequest(ctx, tx, input.RequestID); err != nil {
		return Authorization{}, err
	} else if found {
		if subtle.ConstantTimeCompare(digest, input.RequestDigest[:]) != 1 {
			return Authorization{}, ErrIdempotencyConflict
		}
		existing.Replayed = true
		if err := tx.Commit(ctx); err != nil {
			return Authorization{}, ErrPersistence
		}
		return existing, nil
	}

	var tokenID, nodeID uuid.UUID
	var purpose, nodeState string
	var expiresAt time.Time
	var consumedAt *time.Time
	var consumeRequestID *string
	var consumeRequestDigest []byte
	err = tx.QueryRow(ctx, `
		SELECT token.id, token.node_id, token.purpose, token.expires_at, token.consumed_at,
		       token.consume_request_id,token.consume_request_digest,node.admin_state
		FROM node_enrollment_tokens token
		JOIN nodes node ON node.id=token.node_id
		WHERE token.token_hash=$1
		FOR UPDATE OF token, node`, input.TokenHash[:]).Scan(&tokenID, &nodeID, &purpose, &expiresAt,
		&consumedAt, &consumeRequestID, &consumeRequestDigest, &nodeState)
	if errors.Is(err, pgx.ErrNoRows) {
		return Authorization{}, ErrInvalidToken
	}
	if err != nil {
		return Authorization{}, ErrPersistence
	}
	if consumedAt != nil {
		if consumeRequestID != nil && *consumeRequestID == input.RequestID.String() &&
			subtle.ConstantTimeCompare(consumeRequestDigest, input.RequestDigest[:]) == 1 {
			existing, digest, found, err := loadAuthorizationByRequest(ctx, tx, input.RequestID)
			if err != nil {
				return Authorization{}, err
			}
			if !found || subtle.ConstantTimeCompare(digest, input.RequestDigest[:]) != 1 {
				return Authorization{}, ErrPersistence
			}
			existing.Replayed = true
			if err := tx.Commit(ctx); err != nil {
				return Authorization{}, ErrPersistence
			}
			return existing, nil
		}
		if consumeRequestID != nil && *consumeRequestID == input.RequestID.String() {
			return Authorization{}, ErrIdempotencyConflict
		}
		return Authorization{}, ErrTokenConsumed
	}
	if !input.AuthorizedAt.Before(expiresAt) {
		return Authorization{}, ErrTokenExpired
	}
	if nodeState == "disabled" || nodeState == "retired" {
		return Authorization{}, ErrEnrollmentDenied
	}

	var peerIP any
	if input.PeerIP != "" {
		peerIP = input.PeerIP
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO node_enrollment_authorizations
			(id, token_id, node_id, purpose, request_id, request_digest, authorized_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, input.AuthorizationID, tokenID, nodeID, purpose,
		input.RequestID.String(), input.RequestDigest[:], input.AuthorizedAt); err != nil {
		if uniqueViolation(err) {
			return Authorization{}, ErrIdempotencyConflict
		}
		return Authorization{}, ErrPersistence
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO node_identity_authorizations (
			id, token_id, node_id, purpose, request_id, request_digest, token_hash,
			csr_der, csr_sha256, machine_fingerprint_sha256,
			protocol_min_major, protocol_min_minor, protocol_max_major, protocol_max_minor,
			selected_protocol_major, selected_protocol_minor,
			capabilities_snapshot, capabilities_sha256, gateway_workload_identity,
			gateway_instance_id, peer_ip, artifact_key_id, artifact_public_key,
			status, authorized_at, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,'authorized',$24,$25)`,
		input.AuthorizationID, tokenID, nodeID, purpose, input.RequestID, input.RequestDigest[:], input.TokenHash[:],
		input.CSRDER, input.CSRHash[:], input.MachineFingerprint[:],
		input.Supported.Minimum.Major, input.Supported.Minimum.Minor, input.Supported.Maximum.Major, input.Supported.Maximum.Minor,
		input.Selected.Major, input.Selected.Minor, input.CapabilitiesSnapshot, input.CapabilitiesHash[:],
		input.GatewayWorkloadIdentity, input.GatewayInstanceID, peerIP, input.ArtifactKeyID,
		input.ArtifactPublicKey[:], input.AuthorizedAt, input.ExpiresAt); err != nil {
		if uniqueViolation(err) {
			return Authorization{}, ErrIdempotencyConflict
		}
		return Authorization{}, ErrPersistence
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO node_artifact_encryption_keys
			(id,node_id,authorization_id,public_key,public_key_sha256,status,created_at)
		VALUES ($1,$2,$3,$4,$5,'pending',$6)`, input.ArtifactKeyID, nodeID, input.AuthorizationID,
		input.ArtifactPublicKey[:], input.ArtifactPublicKeyHash[:], input.AuthorizedAt); err != nil {
		if uniqueViolation(err) {
			return Authorization{}, ErrIdempotencyConflict
		}
		return Authorization{}, ErrPersistence
	}
	result, err := tx.Exec(ctx, `
		UPDATE node_enrollment_tokens SET consumed_at=$2, consume_request_id=$3, consume_request_digest=$4
		WHERE id=$1 AND consumed_at IS NULL`, tokenID, input.AuthorizedAt, input.RequestID.String(), input.RequestDigest[:])
	if err != nil {
		return Authorization{}, ErrPersistence
	}
	if result.RowsAffected() != 1 {
		return Authorization{}, ErrTokenConsumed
	}
	if err := tx.Commit(ctx); err != nil {
		return Authorization{}, ErrPersistence
	}
	return Authorization{ID: input.AuthorizationID, NodeID: nodeID, CertificateSigningRequestSHA256: input.CSRHash,
		SelectedProtocolVersion: cloneProtocolVersion(input.Selected), ExpiresAt: input.ExpiresAt,
		ArtifactEncryptionKeyID: input.ArtifactKeyID}, nil
}

func loadAuthorizationByRequest(ctx context.Context, tx pgx.Tx, requestID uuid.UUID) (Authorization, []byte, bool, error) {
	var result Authorization
	var digest, csrHash []byte
	var major, minor int32
	err := tx.QueryRow(ctx, `
		SELECT id,node_id,request_digest,csr_sha256,selected_protocol_major,selected_protocol_minor,
		       expires_at,artifact_key_id
		FROM node_identity_authorizations WHERE request_id=$1`, requestID).Scan(&result.ID, &result.NodeID,
		&digest, &csrHash, &major, &minor, &result.ExpiresAt, &result.ArtifactEncryptionKeyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Authorization{}, nil, false, nil
	}
	if err != nil || len(csrHash) != 32 {
		return Authorization{}, nil, false, ErrPersistence
	}
	copy(result.CertificateSigningRequestSHA256[:], csrHash)
	result.SelectedProtocolVersion = &commonv1.ProtocolVersion{Major: uint32(major), Minor: uint32(minor)}
	return result, digest, true, nil
}

func (s *Store) preflightEnrollmentCompletion(ctx context.Context, authorizationID, requestID uuid.UUID, workload, instance string) (EnrollmentCompletion, bool, error) {
	var status, storedWorkload, storedInstance, artifactKeyID string
	var nodeID uuid.UUID
	var certificateID *uuid.UUID
	var hasCertificateFact bool
	err := s.pool.QueryRow(ctx, `
		SELECT auth.node_id,auth.status,auth.gateway_workload_identity,auth.gateway_instance_id,
		       auth.issued_certificate_id,auth.artifact_key_id,
		       EXISTS (
		           SELECT 1 FROM node_certificates certificate
		           WHERE certificate.id=auth.issued_certificate_id AND certificate.node_id=auth.node_id
		             AND certificate.enrollment_authorization_id=auth.id AND certificate.issuance_kind='initial'
		       )
		FROM node_identity_authorizations auth
		WHERE auth.id=$1`, authorizationID).Scan(&nodeID, &status, &storedWorkload, &storedInstance,
		&certificateID, &artifactKeyID, &hasCertificateFact)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollmentCompletion{}, false, ErrAuthorizationNotFound
	}
	if err != nil {
		return EnrollmentCompletion{}, false, ErrPersistence
	}
	if storedWorkload != workload || storedInstance != instance {
		return EnrollmentCompletion{}, false, ErrGatewayBinding
	}
	if status != "issued" {
		return EnrollmentCompletion{}, false, nil
	}
	if certificateID == nil || !hasCertificateFact {
		return EnrollmentCompletion{}, false, ErrPersistence
	}
	if err := requireArtifactKeyFact(ctx, s.pool, authorizationID, nodeID, artifactKeyID); err != nil {
		return EnrollmentCompletion{}, false, err
	}
	certificate, err := loadEnrollmentReplay(ctx, s.pool, authorizationID, requestID, nodeID, *certificateID,
		workload, instance)
	if err != nil {
		return EnrollmentCompletion{}, false, err
	}
	if certificate.NodeID != nodeID {
		return EnrollmentCompletion{}, false, ErrPersistence
	}
	return EnrollmentCompletion{Certificate: certificate, ArtifactEncryptionKeyID: artifactKeyID}, true, nil
}

func (s *Store) preflightRenewal(ctx context.Context, input normalizedRenew, now time.Time) (Certificate, bool, error) {
	var digest []byte
	var status, currentStatus, currentRotation string
	var nodeID uuid.UUID
	var certificateID *uuid.UUID
	var expiresAt, renewalAt, notAfter *time.Time
	var currentCertificateMatches, hasCertificateFact bool
	err := s.pool.QueryRow(ctx, `
		SELECT request.request_digest,request.status,request.node_id,request.issued_certificate_id,
		       request.expires_at,current_certificate.renewal_at,current_certificate.not_after,
		       COALESCE(current_certificate.status,''),COALESCE(current_certificate.rotation_status,''),
		       EXISTS (
		           SELECT 1 FROM node_certificates current_certificate
		           WHERE current_certificate.id=request.current_certificate_id
		             AND current_certificate.node_id=request.node_id AND current_certificate.node_id=$2
		             AND current_certificate.serial_number=request.current_serial_number
		             AND current_certificate.serial_number=$3 AND current_certificate.leaf_der_sha256=$4
		       ),
		       EXISTS (
		           SELECT 1 FROM node_certificates certificate
		           WHERE certificate.id=request.issued_certificate_id AND certificate.node_id=request.node_id
		             AND certificate.renewal_request_id=request.request_id AND certificate.issuance_kind='renewal'
		       )
		FROM node_certificate_renewal_requests request
		LEFT JOIN node_certificates current_certificate ON current_certificate.id=request.current_certificate_id
		WHERE request.request_id=$1`, input.RequestID,
		input.NodeID, input.CurrentSerial, input.CurrentCertificateSHA256[:]).Scan(
		&digest, &status, &nodeID, &certificateID, &expiresAt, &renewalAt, &notAfter,
		&currentStatus, &currentRotation, &currentCertificateMatches, &hasCertificateFact)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, false, nil
	}
	if err != nil {
		return Certificate{}, false, ErrPersistence
	}
	if !currentCertificateMatches {
		return Certificate{}, false, ErrCertificateNotFound
	}
	if !equalDigest(digest, input.RequestDigest[:]) {
		return Certificate{}, false, ErrIdempotencyConflict
	}
	if renewalAt == nil || notAfter == nil || expiresAt == nil || !renewalAt.Before(*notAfter) {
		return Certificate{}, false, ErrPersistence
	}
	switch status {
	case "expired":
		if currentStatus != "active" || currentRotation != "current" || !now.Before(*notAfter) {
			return Certificate{}, false, ErrCertificateNotFound
		}
		return Certificate{}, false, renewalRetryError(
			ErrAuthorizationExpired, RenewalReasonRequestExpired, *renewalAt, now,
		)
	case "issued":
		if certificateID == nil || !hasCertificateFact {
			return Certificate{}, false, ErrPersistence
		}
	case "pending", "signing":
		if currentStatus != "active" || currentRotation != "current" || !now.Before(*notAfter) {
			return Certificate{}, false, ErrCertificateNotFound
		}
		if !now.Before(*expiresAt) {
			return Certificate{}, false, renewalRetryError(
				ErrAuthorizationExpired, RenewalReasonRequestExpired, *renewalAt, now,
			)
		}
		if now.Before(*renewalAt) {
			return Certificate{}, false, renewalRetryError(
				ErrRenewalTooEarly, RenewalReasonTooEarly, *renewalAt, now,
			)
		}
		return Certificate{}, false, nil
	default:
		return Certificate{}, false, ErrPersistence
	}
	certificate, err := loadCertificateByID(ctx, s.pool, *certificateID)
	if err != nil {
		return Certificate{}, false, err
	}
	if certificate.NodeID != nodeID || nodeID != input.NodeID {
		return Certificate{}, false, ErrPersistence
	}
	return certificate, true, nil
}

func requireArtifactKeyFact(ctx context.Context, query rowQuerier, authorizationID, nodeID uuid.UUID, artifactKeyID string) error {
	var storedID string
	err := query.QueryRow(ctx, `
		SELECT id FROM node_artifact_encryption_keys
		WHERE id=$1 AND authorization_id=$2 AND node_id=$3`, artifactKeyID, authorizationID, nodeID).Scan(&storedID)
	if errors.Is(err, pgx.ErrNoRows) || storedID == "" {
		return ErrPersistence
	}
	if err != nil {
		return ErrPersistence
	}
	return nil
}

// hasLiveCertificateLifecycle reports whether the node still holds a usable
// certificate. A certificate whose validity window has closed is retained as an
// active lifecycle fact, but it no longer authorizes the node and must not block
// re-enrollment; without the expiry predicate a node that stays offline for one
// certificate TTL can never enroll again.
func hasLiveCertificateLifecycle(ctx context.Context, query rowQuerier, nodeID uuid.UUID, now time.Time) (bool, error) {
	var live bool
	err := query.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM node_certificates
		WHERE node_id=$1 AND status='active' AND rotation_status IN ('current','overlap')
		  AND not_after > $2
	)`, nodeID, now).Scan(&live)
	if err != nil {
		return false, ErrPersistence
	}
	return live, nil
}

func (s *Store) prepareEnrollmentSigning(ctx context.Context, authorizationID, requestID, leaseID uuid.UUID, workload, instance string, now, leaseExpires time.Time) (enrollmentSigningClaim, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return enrollmentSigningClaim{}, ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var claim enrollmentSigningClaim
	var status, storedWorkload, storedInstance, nodeState string
	var csrHash []byte
	var expiresAt time.Time
	var signingLeaseExpires *time.Time
	var certificateID *uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT auth.node_id,auth.csr_der,auth.csr_sha256,auth.artifact_key_id,auth.status,
		       auth.gateway_workload_identity,auth.gateway_instance_id,auth.expires_at,
		       auth.signing_lease_expires_at,auth.issued_certificate_id,node.admin_state
		FROM node_identity_authorizations auth JOIN nodes node ON node.id=auth.node_id
		WHERE auth.id=$1 FOR UPDATE OF auth,node`, authorizationID).Scan(&claim.NodeID, &claim.CSRDER, &csrHash,
		&claim.ArtifactKeyID, &status, &storedWorkload, &storedInstance, &expiresAt,
		&signingLeaseExpires, &certificateID, &nodeState)
	if errors.Is(err, pgx.ErrNoRows) {
		return enrollmentSigningClaim{}, ErrAuthorizationNotFound
	}
	if err != nil || len(csrHash) != 32 {
		return enrollmentSigningClaim{}, ErrPersistence
	}
	claim.AuthorizationID = authorizationID
	claim.LifecycleRequestID = requestID
	claim.GatewayWorkloadIdentity = workload
	claim.GatewayInstanceID = instance
	copy(claim.CSRHash[:], csrHash)
	if storedWorkload != workload || storedInstance != instance {
		return enrollmentSigningClaim{}, ErrGatewayBinding
	}
	if status == "issued" {
		if certificateID == nil {
			return enrollmentSigningClaim{}, ErrPersistence
		}
		certificate, err := loadEnrollmentReplay(ctx, tx, authorizationID, requestID, claim.NodeID,
			*certificateID, workload, instance)
		if err != nil {
			return enrollmentSigningClaim{}, err
		}
		if err := requireArtifactKeyFact(ctx, tx, authorizationID, claim.NodeID, claim.ArtifactKeyID); err != nil {
			return enrollmentSigningClaim{}, err
		}
		claim.Existing = &certificate
		if err := tx.Commit(ctx); err != nil {
			return enrollmentSigningClaim{}, ErrPersistence
		}
		return claim, nil
	}
	if status == "expired" {
		return enrollmentSigningClaim{}, ErrAuthorizationExpired
	}
	if !now.Before(expiresAt) {
		if _, err := tx.Exec(ctx, `UPDATE node_identity_authorizations SET status='expired', signing_lease_id=NULL, signing_lease_expires_at=NULL WHERE id=$1`, authorizationID); err != nil {
			return enrollmentSigningClaim{}, ErrPersistence
		}
		if _, err := tx.Exec(ctx, `
			UPDATE node_artifact_encryption_keys SET status='revoked',deactivated_at=$2,
			       deactivation_reason='enrollment authorization expired'
			WHERE authorization_id=$1 AND status='pending'`, authorizationID, now); err != nil {
			return enrollmentSigningClaim{}, ErrPersistence
		}
		if err := tx.Commit(ctx); err != nil {
			return enrollmentSigningClaim{}, ErrPersistence
		}
		return enrollmentSigningClaim{}, ErrAuthorizationExpired
	}
	if nodeState == "disabled" || nodeState == "retired" {
		return enrollmentSigningClaim{}, ErrNodeStateDenied
	}
	liveCertificate, err := hasLiveCertificateLifecycle(ctx, tx, claim.NodeID, now)
	if err != nil {
		return enrollmentSigningClaim{}, err
	}
	if liveCertificate {
		return enrollmentSigningClaim{}, ErrCertificateInvalid
	}
	if status == "signing" {
		if signingLeaseExpires != nil && now.Before(*signingLeaseExpires) {
			return enrollmentSigningClaim{}, ErrIssuanceInProgress
		}
		if _, err := tx.Exec(ctx, `UPDATE node_identity_authorizations SET status='authorized',signing_lease_id=NULL,signing_lease_expires_at=NULL WHERE id=$1`, authorizationID); err != nil {
			return enrollmentSigningClaim{}, ErrPersistence
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_identity_authorizations SET status='signing',signing_attempt=signing_attempt+1,
		       signing_lease_id=$2,signing_lease_expires_at=$3 WHERE id=$1`, authorizationID, leaseID, leaseExpires); err != nil {
		return enrollmentSigningClaim{}, ErrPersistence
	}
	claim.LeaseID = leaseID
	if err := tx.Commit(ctx); err != nil {
		return enrollmentSigningClaim{}, ErrPersistence
	}
	return claim, nil
}

func (s *Store) resetEnrollmentSigning(ctx context.Context, authorizationID, leaseID uuid.UUID, now time.Time) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE node_identity_authorizations
		SET status=CASE WHEN expires_at <= $3 THEN 'expired' ELSE 'authorized' END,
		    signing_lease_id=NULL,signing_lease_expires_at=NULL
		WHERE id=$1 AND status='signing' AND signing_lease_id=$2`, authorizationID, leaseID, now)
	if err != nil {
		return ErrPersistence
	}
	if result.RowsAffected() != 1 {
		return ErrIssuanceInProgress
	}
	return nil
}

func (s *Store) finalizeEnrollment(ctx context.Context, claim enrollmentSigningClaim, certificate persistedCertificate, now time.Time, eventID uuid.UUID) (Certificate, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var status, nodeState string
	var ownerScopeID uuid.UUID
	var currentLease *uuid.UUID
	var expiresAt time.Time
	var existingID *uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT auth.status,auth.signing_lease_id,auth.expires_at,auth.issued_certificate_id,
		       node.admin_state,node.scope_id
		FROM node_identity_authorizations auth JOIN nodes node ON node.id=auth.node_id
		WHERE auth.id=$1 AND auth.node_id=$2 FOR UPDATE OF auth,node`, claim.AuthorizationID, claim.NodeID).Scan(
		&status, &currentLease, &expiresAt, &existingID, &nodeState, &ownerScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrAuthorizationNotFound
	}
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	if status == "issued" && existingID != nil {
		result, err := loadEnrollmentReplay(ctx, tx, claim.AuthorizationID, claim.LifecycleRequestID,
			claim.NodeID, *existingID, claim.GatewayWorkloadIdentity, claim.GatewayInstanceID)
		if err != nil {
			return Certificate{}, err
		}
		if err := requireArtifactKeyFact(ctx, tx, claim.AuthorizationID, claim.NodeID, claim.ArtifactKeyID); err != nil {
			return Certificate{}, err
		}
		if tx.Commit(ctx) != nil {
			return Certificate{}, ErrPersistence
		}
		return result, nil
	}
	if status != "signing" || currentLease == nil || *currentLease != claim.LeaseID {
		return Certificate{}, ErrIssuanceInProgress
	}
	if !now.Before(expiresAt) {
		if _, err := tx.Exec(ctx, `
			UPDATE node_identity_authorizations SET status='expired',signing_lease_id=NULL,signing_lease_expires_at=NULL
			WHERE id=$1`, claim.AuthorizationID); err != nil {
			return Certificate{}, ErrPersistence
		}
		if _, err := tx.Exec(ctx, `
			UPDATE node_artifact_encryption_keys SET status='revoked',deactivated_at=$2,
			       deactivation_reason='enrollment authorization expired'
			WHERE authorization_id=$1 AND status='pending'`, claim.AuthorizationID, now); err != nil {
			return Certificate{}, ErrPersistence
		}
		if tx.Commit(ctx) != nil {
			return Certificate{}, ErrPersistence
		}
		return Certificate{}, ErrAuthorizationExpired
	}
	if nodeState == "disabled" || nodeState == "retired" {
		return Certificate{}, ErrNodeStateDenied
	}
	liveCertificate, err := hasLiveCertificateLifecycle(ctx, tx, claim.NodeID, now)
	if err != nil {
		return Certificate{}, err
	}
	if liveCertificate {
		return Certificate{}, ErrCertificateInvalid
	}
	var installationID string
	var caEpochID uuid.UUID
	var caCertificateHash []byte
	var caNotBefore, caNotAfter time.Time
	err = tx.QueryRow(ctx, `
		SELECT installation.installation_id,epoch.id,epoch.ca_certificate_sha256,
		       epoch.not_before,epoch.not_after
		FROM control_installation_entitlement installation
		JOIN node_ca_key_epochs epoch ON epoch.installation_id=installation.installation_id
		WHERE installation.singleton AND epoch.status='active'
		FOR UPDATE OF installation,epoch`).Scan(&installationID, &caEpochID, &caCertificateHash,
		&caNotBefore, &caNotAfter)
	if errors.Is(err, pgx.ErrNoRows) || installationID == "" || caEpochID == uuid.Nil || len(caCertificateHash) != 32 {
		return Certificate{}, ErrCertificateInvalid
	}
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	if subtle.ConstantTimeCompare(caCertificateHash, certificate.IssuerCAHash[:]) != 1 ||
		certificate.NotBefore.Before(caNotBefore) || certificate.NotAfter.After(caNotAfter) {
		return Certificate{}, ErrCertificateInvalid
	}
	lifecycleDigest, err := canonicalEnrollmentLifecycleDigest(claim.AuthorizationID, claim.NodeID,
		ownerScopeID, installationID, caEpochID, certificate.CSRHash, certificate.LeafDERHash,
		claim.GatewayWorkloadIdentity, claim.GatewayInstanceID)
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	// Expired certificates remain immutable facts, but must not occupy the
	// current/overlap uniqueness slots. Use the existing lifecycle transitions
	// inside the issuance transaction so any later failure restores them.
	retiredCertificates := []string{}
	for _, statement := range []string{
		`UPDATE node_certificates SET rotation_status='retired',lifecycle_revision=lifecycle_revision+1
		 WHERE node_id=$1 AND installation_id=$2 AND status='active' AND rotation_status='overlap' AND not_after<=$3 RETURNING id::text`,
		`UPDATE node_certificates SET rotation_status='overlap',lifecycle_revision=lifecycle_revision+1,overlap_until=not_after
		 WHERE node_id=$1 AND installation_id=$2 AND status='active' AND rotation_status='current' AND not_after<=$3 RETURNING id::text`,
		`UPDATE node_certificates SET rotation_status='retired',lifecycle_revision=lifecycle_revision+1
		 WHERE node_id=$1 AND installation_id=$2 AND status='active' AND rotation_status='overlap' AND not_after<=$3 RETURNING id::text`,
	} {
		rows, err := tx.Query(ctx, statement, claim.NodeID, installationID, now)
		if err != nil {
			return Certificate{}, ErrPersistence
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return Certificate{}, ErrPersistence
			}
			if !slices.Contains(retiredCertificates, id) {
				retiredCertificates = append(retiredCertificates, id)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return Certificate{}, ErrPersistence
		}
	}
	if err := insertEnrollmentCertificate(ctx, tx, certificate, ownerScopeID, installationID, caEpochID,
		claim.LifecycleRequestID, lifecycleDigest, now); err != nil {
		return Certificate{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_artifact_encryption_keys
		SET status='retired',deactivated_at=$2,deactivation_reason='replaced by enrollment key'
		WHERE node_id=$1 AND status='active'`, claim.NodeID, now); err != nil {
		return Certificate{}, ErrPersistence
	}
	result, err := tx.Exec(ctx, `
		UPDATE node_artifact_encryption_keys SET status='active',activated_at=$3
		WHERE id=$1 AND node_id=$2 AND status='pending'`, claim.ArtifactKeyID, claim.NodeID, now)
	if err != nil || result.RowsAffected() != 1 {
		return Certificate{}, ErrPersistence
	}
	// Console-reserved nodes activate on first enrollment. Self-registered
	// nodes stay pending ("待初始化") until an administrator initializes them,
	// so they receive no configuration and no DNS before that decision.
	if nodeState == "pending" && !node.IsSelfRegisteredNodeID(claim.NodeID) {
		if _, err := tx.Exec(ctx, `UPDATE nodes SET admin_state='active',revision=revision+1,updated_at=$2 WHERE id=$1`, claim.NodeID, now); err != nil {
			return Certificate{}, ErrPersistence
		}
	}
	var revision int64
	err = tx.QueryRow(ctx, `
		UPDATE node_identity_state SET active_artifact_key_id=$2,
		       authorization_revision=authorization_revision+1,updated_at=$3
		WHERE node_id=$1 RETURNING authorization_revision`, claim.NodeID, claim.ArtifactKeyID, now).Scan(&revision)
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_certificate_events
			(id,node_id,certificate_id,event_type,authorization_revision,occurred_at)
		VALUES ($1,$2,$3,'issued',$4,$5)`, eventID, claim.NodeID, certificate.ID, revision, now); err != nil {
		return Certificate{}, ErrPersistence
	}
	result, err = tx.Exec(ctx, `
		UPDATE node_identity_authorizations SET status='issued',signing_lease_id=NULL,
		       signing_lease_expires_at=NULL,issued_certificate_id=$3,completed_at=$4
		WHERE id=$1 AND status='signing' AND signing_lease_id=$2`, claim.AuthorizationID, claim.LeaseID, certificate.ID, now)
	if err != nil || result.RowsAffected() != 1 {
		return Certificate{}, ErrPersistence
	}
	payload := map[string]any{
		"node_id": claim.NodeID.String(), "authorization_id": claim.AuthorizationID.String(),
		"artifact_encryption_key_id": claim.ArtifactKeyID, "certificate_status": "active",
		"rotation_status": "current", "lifecycle_revision": 1,
		"authorization_revision": revision,
	}
	if len(retiredCertificates) > 0 {
		payload["retired_expired_certificate_ids"] = retiredCertificates
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: ownerScopeID, ActorUserID: nil,
		Action: "node_certificate.lifecycle.enroll", ResourceType: "node_certificate",
		ResourceID: certificate.ID.String(), RequestID: claim.LifecycleRequestID.String(), Result: "success",
		Payload: payload,
	}); err != nil {
		return Certificate{}, ErrPersistence
	}
	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, ErrPersistence
	}
	return cloneCertificate(certificate.Certificate), nil
}

// renewalAllowedForNodeState admits active and draining nodes, plus a
// self-registered node waiting in pending until an administrator initializes
// it: authorizationSnapshot already admits its session, and it must keep
// renewing its short-lived certificate instead of expiring after 24 hours.
func renewalAllowedForNodeState(nodeState string, nodeID uuid.UUID) bool {
	return nodeState == "active" || nodeState == "draining" ||
		nodeState == "pending" && node.IsSelfRegisteredNodeID(nodeID)
}

// newLeaseID is called only after every read-only gate (replay, renewal
// window, node state) has passed, so a refused renewal never consumes an ID.
func (s *Store) prepareRenewal(ctx context.Context, input normalizedRenew, newLeaseID func() (uuid.UUID, error), now, expiresAt, leaseExpires time.Time) (renewalSigningClaim, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return renewalSigningClaim{}, ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	claim := renewalSigningClaim{RequestID: input.RequestID, NodeID: input.NodeID, CSRDER: input.CSRDER, CSRHash: input.CSRHash}
	var digest, csrHash []byte
	var status, certificateStatus, rotationStatus string
	var signingExpires *time.Time
	var issuedID *uuid.UUID
	var certificateExpiry, renewalAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT request.request_digest,request.current_certificate_id,request.csr_der,request.csr_sha256,
		       request.status,request.signing_lease_expires_at,request.issued_certificate_id,request.expires_at,
		       cert.status,cert.rotation_status,cert.not_after,cert.renewal_at
		FROM node_certificate_renewal_requests request
		JOIN node_certificates cert ON cert.id=request.current_certificate_id
		WHERE request.request_id=$1 FOR UPDATE OF request,cert`, input.RequestID).Scan(
		&digest, &claim.CurrentCertificateID, &claim.CSRDER, &csrHash, &status, &signingExpires, &issuedID,
		&expiresAt, &certificateStatus, &rotationStatus, &certificateExpiry, &renewalAt)
	if err == nil {
		if !equalDigest(digest, input.RequestDigest[:]) {
			return renewalSigningClaim{}, ErrIdempotencyConflict
		}
		if len(csrHash) != 32 {
			return renewalSigningClaim{}, ErrPersistence
		}
		copy(claim.CSRHash[:], csrHash)
		if status == "issued" && issuedID != nil {
			certificate, err := loadCertificateByID(ctx, tx, *issuedID)
			if err != nil {
				return renewalSigningClaim{}, err
			}
			claim.Existing = &certificate
			if tx.Commit(ctx) != nil {
				return renewalSigningClaim{}, ErrPersistence
			}
			return claim, nil
		}
		if certificateStatus == "revoked" {
			return renewalSigningClaim{}, ErrCertificateRevoked
		}
		if certificateStatus != "active" || rotationStatus != "current" ||
			!now.Before(certificateExpiry) || !renewalAt.Before(certificateExpiry) {
			return renewalSigningClaim{}, ErrCertificateNotFound
		}
		if status == "expired" || !now.Before(expiresAt) {
			return renewalSigningClaim{}, renewalRetryError(
				ErrAuthorizationExpired, RenewalReasonRequestExpired, renewalAt, now,
			)
		}
		if now.Before(renewalAt) {
			return renewalSigningClaim{}, renewalRetryError(
				ErrRenewalTooEarly, RenewalReasonTooEarly, renewalAt, now,
			)
		}
		if status == "signing" && signingExpires != nil && now.Before(*signingExpires) {
			return renewalSigningClaim{}, ErrIssuanceInProgress
		}
		if status == "signing" {
			if _, err := tx.Exec(ctx, `UPDATE node_certificate_renewal_requests SET status='pending',signing_lease_id=NULL,signing_lease_expires_at=NULL WHERE request_id=$1`, input.RequestID); err != nil {
				return renewalSigningClaim{}, ErrPersistence
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return renewalSigningClaim{}, ErrPersistence
	} else {
		var nodeState string
		err = tx.QueryRow(ctx, `
			SELECT cert.id,cert.status,cert.rotation_status,cert.not_after,cert.renewal_at,node.admin_state
			FROM node_certificates cert JOIN nodes node ON node.id=cert.node_id
			WHERE cert.node_id=$1 AND cert.serial_number=$2 AND cert.leaf_der_sha256=$3
			FOR UPDATE OF cert,node`, input.NodeID, input.CurrentSerial, input.CurrentCertificateSHA256[:]).Scan(
			&claim.CurrentCertificateID, &certificateStatus, &rotationStatus, &certificateExpiry, &renewalAt, &nodeState)
		if errors.Is(err, pgx.ErrNoRows) {
			return renewalSigningClaim{}, ErrCertificateNotFound
		}
		if err != nil {
			return renewalSigningClaim{}, ErrPersistence
		}
		if certificateStatus == "revoked" {
			return renewalSigningClaim{}, ErrCertificateRevoked
		}
		if certificateStatus != "active" || rotationStatus != "current" ||
			!now.Before(certificateExpiry) || !renewalAt.Before(certificateExpiry) {
			return renewalSigningClaim{}, ErrCertificateNotFound
		}
		if !renewalAllowedForNodeState(nodeState, input.NodeID) {
			return renewalSigningClaim{}, ErrNodeStateDenied
		}
		if now.Before(renewalAt) {
			return renewalSigningClaim{}, renewalRetryError(
				ErrRenewalTooEarly, RenewalReasonTooEarly, renewalAt, now,
			)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE node_certificate_renewal_requests
			SET status='expired',signing_lease_id=NULL,signing_lease_expires_at=NULL
			WHERE current_certificate_id=$1 AND status IN ('pending','signing') AND expires_at<=$2`,
			claim.CurrentCertificateID, now); err != nil {
			return renewalSigningClaim{}, ErrPersistence
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO node_certificate_renewal_requests (
				request_id,request_digest,node_id,current_certificate_id,current_serial_number,
				csr_der,csr_sha256,gateway_workload_identity,gateway_instance_id,status,
				created_at,expires_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11)`, input.RequestID,
			input.RequestDigest[:], input.NodeID, claim.CurrentCertificateID, input.CurrentSerial,
			input.CSRDER, input.CSRHash[:], input.GatewayWorkloadIdentity, input.GatewayInstanceID, now, expiresAt)
		if err != nil {
			if uniqueViolation(err) {
				return renewalSigningClaim{}, ErrRenewalConflict
			}
			return renewalSigningClaim{}, ErrPersistence
		}
	}
	leaseID, err := newLeaseID()
	if err != nil || leaseID == uuid.Nil {
		return renewalSigningClaim{}, ErrPersistence
	}
	claim.LeaseID = leaseID
	result, err := tx.Exec(ctx, `
		UPDATE node_certificate_renewal_requests SET status='signing',signing_attempt=signing_attempt+1,
		       signing_lease_id=$2,signing_lease_expires_at=$3
		WHERE request_id=$1 AND status='pending' AND expires_at>$4`, input.RequestID, leaseID, leaseExpires, now)
	if err != nil {
		return renewalSigningClaim{}, ErrPersistence
	}
	if result.RowsAffected() != 1 {
		return renewalSigningClaim{}, renewalRetryError(
			ErrAuthorizationExpired, RenewalReasonRequestExpired, renewalAt, now,
		)
	}
	if err := tx.Commit(ctx); err != nil {
		return renewalSigningClaim{}, ErrPersistence
	}
	return claim, nil
}

func (s *Store) activeRenewalCAEpoch(
	ctx context.Context,
	issuerCAHash [sha256.Size]byte,
	certificateNotBefore, certificateNotAfter time.Time,
) (uuid.UUID, error) {
	var epochID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT epoch.id
		FROM control_installation_entitlement installation
		JOIN node_ca_key_epochs epoch ON epoch.installation_id=installation.installation_id
		WHERE installation.singleton AND epoch.status='active'
		  AND epoch.ca_certificate_sha256=$1
		  AND epoch.not_before<=$2 AND epoch.not_after>=$3`,
		issuerCAHash[:], certificateNotBefore, certificateNotAfter).Scan(&epochID)
	if errors.Is(err, pgx.ErrNoRows) || epochID == uuid.Nil {
		return uuid.Nil, ErrCertificateInvalid
	}
	if err != nil {
		return uuid.Nil, ErrPersistence
	}
	return epochID, nil
}

func (s *Store) resetRenewalSigning(ctx context.Context, requestID, leaseID uuid.UUID) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE node_certificate_renewal_requests SET status='pending',signing_lease_id=NULL,signing_lease_expires_at=NULL
		WHERE request_id=$1 AND status='signing' AND signing_lease_id=$2`, requestID, leaseID)
	if err != nil {
		return ErrPersistence
	}
	if result.RowsAffected() != 1 {
		return ErrIssuanceInProgress
	}
	return nil
}

func (s *Store) finalizeRenewal(ctx context.Context, claim renewalSigningClaim, certificate persistedCertificate, now time.Time, eventID uuid.UUID) (Certificate, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var status, nodeState string
	var lease *uuid.UUID
	var issuedID *uuid.UUID
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT request.status,request.signing_lease_id,request.issued_certificate_id,request.expires_at,node.admin_state
		FROM node_certificate_renewal_requests request JOIN nodes node ON node.id=request.node_id
		WHERE request.request_id=$1 AND request.node_id=$2 FOR UPDATE OF request,node`, claim.RequestID, claim.NodeID).Scan(
		&status, &lease, &issuedID, &expiresAt, &nodeState)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrCertificateNotFound
	}
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	if status == "issued" && issuedID != nil {
		result, err := loadCertificateByID(ctx, tx, *issuedID)
		if err != nil {
			return Certificate{}, err
		}
		if tx.Commit(ctx) != nil {
			return Certificate{}, ErrPersistence
		}
		return result, nil
	}
	if status != "signing" || lease == nil || *lease != claim.LeaseID {
		return Certificate{}, ErrIssuanceInProgress
	}
	if !now.Before(expiresAt) {
		if _, err := tx.Exec(ctx, `
			UPDATE node_certificate_renewal_requests SET status='expired',signing_lease_id=NULL,signing_lease_expires_at=NULL
			WHERE request_id=$1`, claim.RequestID); err != nil {
			return Certificate{}, ErrPersistence
		}
		if tx.Commit(ctx) != nil {
			return Certificate{}, ErrPersistence
		}
		return Certificate{}, ErrAuthorizationExpired
	}
	if !renewalAllowedForNodeState(nodeState, claim.NodeID) {
		return Certificate{}, ErrNodeStateDenied
	}
	if err := insertCertificate(ctx, tx, certificate, "renewal", now); err != nil {
		return Certificate{}, err
	}
	var revision int64
	if err := tx.QueryRow(ctx, `
		UPDATE node_identity_state SET authorization_revision=authorization_revision+1,updated_at=$2
		WHERE node_id=$1 RETURNING authorization_revision`, claim.NodeID, now).Scan(&revision); err != nil {
		return Certificate{}, ErrPersistence
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_certificate_events
			(id,node_id,certificate_id,event_type,related_certificate_id,authorization_revision,occurred_at)
		VALUES ($1,$2,$3,'renewed',$4,$5,$6)`, eventID, claim.NodeID, certificate.ID,
		claim.CurrentCertificateID, revision, now); err != nil {
		return Certificate{}, ErrPersistence
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_certificate_renewal_requests SET status='issued',signing_lease_id=NULL,
		       signing_lease_expires_at=NULL,issued_certificate_id=$3,completed_at=$4
		WHERE request_id=$1 AND signing_lease_id=$2`, claim.RequestID, claim.LeaseID, certificate.ID, now); err != nil {
		return Certificate{}, ErrPersistence
	}
	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, ErrPersistence
	}
	return cloneCertificate(certificate.Certificate), nil
}

func insertCertificate(ctx context.Context, tx pgx.Tx, certificate persistedCertificate, kind string, now time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO node_certificates (
			id,node_id,issuance_kind,enrollment_authorization_id,renewal_request_id,replaces_certificate_id,
			serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
			leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'active',$17)`,
		certificate.ID, certificate.NodeID, kind, certificate.EnrollmentAuthorizationID, certificate.RenewalRequestID,
		certificate.ReplacesCertificateID, certificate.SerialNumber, certificate.CSRHash[:], certificate.PublicKeyHash[:],
		certificate.URISAN, certificate.NotBefore, certificate.NotAfter, certificate.RenewalAt,
		certificate.LeafCertificatePEM, certificate.IssuingChainPEM, certificate.LeafHash[:], now)
	if err != nil {
		if uniqueViolation(err) {
			return ErrCertificateInvalid
		}
		return ErrPersistence
	}
	return nil
}

func insertEnrollmentCertificate(
	ctx context.Context,
	tx pgx.Tx,
	certificate persistedCertificate,
	ownerScopeID uuid.UUID,
	installationID string,
	caEpochID, lifecycleRequestID uuid.UUID,
	lifecycleRequestDigest [32]byte,
	now time.Time,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO node_certificates (
			id,node_id,issuance_kind,enrollment_authorization_id,renewal_request_id,replaces_certificate_id,
			serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
			leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at,
			owner_scope_id,installation_id,ca_epoch_id,leaf_der_sha256,rotation_status,lifecycle_revision,
			lifecycle_request_id,lifecycle_request_digest,lifecycle_bound_at
		) VALUES ($1,$2,'initial',$3,NULL,NULL,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'active',$14,
			$15,$16,$17,$18,'current',1,$19,$20,$21)`,
		certificate.ID, certificate.NodeID, certificate.EnrollmentAuthorizationID, certificate.SerialNumber,
		certificate.CSRHash[:], certificate.PublicKeyHash[:], certificate.URISAN, certificate.NotBefore,
		certificate.NotAfter, certificate.RenewalAt, certificate.LeafCertificatePEM, certificate.IssuingChainPEM,
		certificate.LeafHash[:], now, ownerScopeID, installationID, caEpochID, certificate.LeafDERHash[:],
		lifecycleRequestID, lifecycleRequestDigest[:], now)
	if err != nil {
		if uniqueViolation(err) {
			return ErrCertificateInvalid
		}
		return ErrPersistence
	}
	return nil
}

func loadEnrollmentReplay(
	ctx context.Context,
	query rowQuerier,
	authorizationID, lifecycleRequestID, nodeID, certificateID uuid.UUID,
	gatewayWorkloadIdentity, gatewayInstanceID string,
) (Certificate, error) {
	if certificate, historical, err := loadHistoricalEnrollmentReplay(ctx, query, authorizationID,
		lifecycleRequestID, nodeID, certificateID); err != nil {
		return Certificate{}, err
	} else if historical {
		return certificate, nil
	}
	var ownerScopeID, caEpochID uuid.UUID
	var installationID, rotationStatus, storedWorkload, storedInstance string
	var storedCSRHash, storedLeafDERHash, storedLifecycleDigest, storedCAHash []byte
	var storedLifecycleRequestID *uuid.UUID
	var lifecycleBoundAt *time.Time
	var lifecycleRevision, eventAuthorizationRevision, currentAuthorizationRevision int64
	err := query.QueryRow(ctx, `
		SELECT node.scope_id,certificate.installation_id,certificate.ca_epoch_id,
		       certificate.csr_sha256,certificate.leaf_der_sha256,certificate.rotation_status,
		       certificate.lifecycle_revision,certificate.lifecycle_request_id,
		       certificate.lifecycle_request_digest,certificate.lifecycle_bound_at,
		       epoch.ca_certificate_sha256,auth.gateway_workload_identity,
		       auth.gateway_instance_id,state.authorization_revision,
		       COALESCE((SELECT max(event.authorization_revision)
		                 FROM node_certificate_events event
		                 WHERE event.node_id=certificate.node_id
		                   AND event.certificate_id=certificate.id
		                   AND event.event_type='issued'),0)
		FROM node_certificates certificate
		JOIN nodes node ON node.id=certificate.node_id AND node.scope_id=certificate.owner_scope_id
		JOIN node_identity_authorizations auth
		  ON auth.id=certificate.enrollment_authorization_id
		 AND auth.node_id=certificate.node_id
		 AND auth.status='issued' AND auth.issued_certificate_id=certificate.id
		JOIN node_identity_state state ON state.node_id=certificate.node_id
		JOIN control_installation_entitlement installation
		  ON installation.singleton AND installation.installation_id=certificate.installation_id
		JOIN node_ca_key_epochs epoch
		  ON epoch.id=certificate.ca_epoch_id AND epoch.installation_id=certificate.installation_id
		WHERE certificate.id=$1 AND certificate.node_id=$2
		  AND certificate.enrollment_authorization_id=$3 AND certificate.issuance_kind='initial'`,
		certificateID, nodeID, authorizationID).Scan(&ownerScopeID, &installationID, &caEpochID,
		&storedCSRHash, &storedLeafDERHash, &rotationStatus, &lifecycleRevision,
		&storedLifecycleRequestID, &storedLifecycleDigest, &lifecycleBoundAt, &storedCAHash,
		&storedWorkload, &storedInstance, &currentAuthorizationRevision, &eventAuthorizationRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrPersistence
	}
	if err != nil || ownerScopeID == uuid.Nil || installationID == "" || caEpochID == uuid.Nil ||
		len(storedCSRHash) != 32 || len(storedLeafDERHash) != 32 || len(storedLifecycleDigest) != 32 ||
		len(storedCAHash) != 32 || storedLifecycleRequestID == nil || lifecycleBoundAt == nil ||
		rotationStatus == "legacy_unbound" || lifecycleRevision < 1 || eventAuthorizationRevision < 1 ||
		currentAuthorizationRevision < eventAuthorizationRevision {
		return Certificate{}, ErrPersistence
	}
	if storedWorkload != gatewayWorkloadIdentity || storedInstance != gatewayInstanceID {
		return Certificate{}, ErrGatewayBinding
	}
	if *storedLifecycleRequestID != lifecycleRequestID {
		return Certificate{}, ErrIdempotencyConflict
	}
	certificate, err := loadCertificateByID(ctx, query, certificateID)
	if err != nil {
		return Certificate{}, err
	}
	leaf, err := parseSinglePEMCertificate(certificate.LeafCertificatePEM)
	if err != nil || len(certificate.IssuingChainPEM) == 0 {
		return Certificate{}, ErrPersistence
	}
	issuer, err := parseSinglePEMCertificate(certificate.IssuingChainPEM[0])
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	leafDERHash := sha256.Sum256(leaf.Raw)
	issuerHash := sha256.Sum256(issuer.Raw)
	if subtle.ConstantTimeCompare(storedLeafDERHash, leafDERHash[:]) != 1 ||
		subtle.ConstantTimeCompare(storedCAHash, issuerHash[:]) != 1 {
		return Certificate{}, ErrPersistence
	}
	var csrHash [32]byte
	copy(csrHash[:], storedCSRHash)
	expectedDigest, err := canonicalEnrollmentLifecycleDigest(authorizationID, nodeID, ownerScopeID,
		installationID, caEpochID, csrHash, leafDERHash, gatewayWorkloadIdentity, gatewayInstanceID)
	if err != nil || subtle.ConstantTimeCompare(storedLifecycleDigest, expectedDigest[:]) != 1 {
		return Certificate{}, ErrPersistence
	}
	return certificate, nil
}

func loadHistoricalEnrollmentReplay(
	ctx context.Context,
	query rowQuerier,
	authorizationID, recoveryRequestID, nodeID, certificateID uuid.UUID,
) (Certificate, bool, error) {
	var authorizationRequestID uuid.UUID
	var ownerScopeID, caEpochID *uuid.UUID
	var installationID, rotationStatus string
	var csrHash, leafDERHash, lifecycleDigest []byte
	var workload, instance string
	err := query.QueryRow(ctx, `
		SELECT auth.request_id,certificate.rotation_status,certificate.owner_scope_id,
		       COALESCE(certificate.installation_id,''),certificate.ca_epoch_id,
		       certificate.csr_sha256,COALESCE(certificate.leaf_der_sha256,'\x'::bytea),
		       COALESCE(certificate.lifecycle_request_digest,'\x'::bytea),
		       auth.gateway_workload_identity,auth.gateway_instance_id
		FROM node_identity_authorizations auth
		JOIN node_certificates certificate
		  ON certificate.id=auth.issued_certificate_id
		 AND certificate.node_id=auth.node_id
		 AND certificate.enrollment_authorization_id=auth.id
		 AND certificate.issuance_kind='initial'
		WHERE auth.id=$1 AND auth.node_id=$2 AND auth.status='issued'
		  AND certificate.id=$3`, authorizationID, nodeID, certificateID).Scan(&authorizationRequestID,
		&rotationStatus, &ownerScopeID, &installationID, &caEpochID, &csrHash, &leafDERHash,
		&lifecycleDigest, &workload, &instance)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, false, ErrPersistence
	}
	if err != nil {
		return Certificate{}, false, ErrPersistence
	}
	historical := rotationStatus == "legacy_unbound"
	if !historical {
		if ownerScopeID == nil || caEpochID == nil || installationID == "" || len(csrHash) != 32 ||
			len(leafDERHash) != 32 || len(lifecycleDigest) != 32 {
			return Certificate{}, false, ErrPersistence
		}
		var storedCSRHash, storedLeafDERHash [32]byte
		copy(storedCSRHash[:], csrHash)
		copy(storedLeafDERHash[:], leafDERHash)
		expectedDigest, err := canonicalEnrollmentLifecycleDigest(authorizationID, nodeID, *ownerScopeID,
			installationID, *caEpochID, storedCSRHash, storedLeafDERHash, workload, instance)
		if err != nil {
			return Certificate{}, false, ErrPersistence
		}
		historical = subtle.ConstantTimeCompare(lifecycleDigest, expectedDigest[:]) != 1
	}
	if !historical {
		return Certificate{}, false, nil
	}
	if recoveryRequestID != authorizationRequestID {
		return Certificate{}, false, ErrIdempotencyConflict
	}
	certificate, err := loadCertificateByID(ctx, query, certificateID)
	if err != nil {
		return Certificate{}, false, err
	}
	return certificate, true, nil
}

func loadCertificateByID(ctx context.Context, query rowQuerier, id uuid.UUID) (Certificate, error) {
	var result Certificate
	err := query.QueryRow(ctx, `
		SELECT id,node_id,leaf_certificate_pem,issuing_chain_pem,serial_number,not_before,not_after,renewal_at
		FROM node_certificates WHERE id=$1`, id).Scan(&result.ID, &result.NodeID, &result.LeafCertificatePEM,
		&result.IssuingChainPEM, &result.SerialNumber, &result.NotBefore, &result.NotAfter, &result.RenewalAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrCertificateNotFound
	}
	if err != nil {
		return Certificate{}, ErrPersistence
	}
	return cloneCertificate(result), nil
}

func (s *Store) revoke(ctx context.Context, requestID, nodeID uuid.UUID, serial, reason string, digest [32]byte, now time.Time, eventID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var storedDigest []byte
	err = tx.QueryRow(ctx, `SELECT request_digest FROM node_certificate_revocations WHERE request_id=$1`, requestID).Scan(&storedDigest)
	if err == nil {
		if !equalDigest(storedDigest, digest[:]) {
			return ErrIdempotencyConflict
		}
		if tx.Commit(ctx) != nil {
			return ErrPersistence
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ErrPersistence
	}
	var certificateID uuid.UUID
	var status string
	err = tx.QueryRow(ctx, `
		SELECT id,status FROM node_certificates WHERE node_id=$1 AND serial_number=$2 FOR UPDATE`, nodeID, serial).Scan(&certificateID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCertificateNotFound
	}
	if err != nil {
		return ErrPersistence
	}
	if status == "revoked" {
		if err := tx.QueryRow(ctx, `
			SELECT request_digest FROM node_certificate_revocations WHERE request_id=$1`, requestID).Scan(&storedDigest); err == nil {
			if !equalDigest(storedDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			if tx.Commit(ctx) != nil {
				return ErrPersistence
			}
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return ErrPersistence
		}
		return ErrCertificateRevoked
	}
	var revision int64
	if err := tx.QueryRow(ctx, `
		UPDATE node_identity_state SET authorization_revision=authorization_revision+1,updated_at=$2
		WHERE node_id=$1 RETURNING authorization_revision`, nodeID, now).Scan(&revision); err != nil {
		return ErrPersistence
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_certificates SET status='revoked',revoked_at=$3,revocation_reason=$4
		WHERE id=$1 AND node_id=$2`, certificateID, nodeID, now, reason); err != nil {
		return ErrPersistence
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_certificate_revocations
			(request_id,request_digest,certificate_id,node_id,reason,revoked_at,authorization_revision)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, requestID, digest[:], certificateID, nodeID, reason, now, revision); err != nil {
		if uniqueViolation(err) {
			return ErrIdempotencyConflict
		}
		return ErrPersistence
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_certificate_events
			(id,node_id,certificate_id,event_type,reason,authorization_revision,occurred_at)
		VALUES ($1,$2,$3,'revoked',$4,$5,$6)`, eventID, nodeID, certificateID, reason, revision, now); err != nil {
		return ErrPersistence
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrPersistence
	}
	return nil
}

func (s *Store) authorizationSnapshot(ctx context.Context, request GetAuthorizationRequest, clock func() time.Time, snapshotTTL time.Duration) (AuthorizationSnapshot, error) {
	// The authenticated workload identity is the authorization boundary. The
	// instance ID is intentionally not pinned to the enrollment replica so a
	// healthy Gateway replica can take over an existing mTLS node session.
	options := pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
	if request.SessionFacts != nil {
		options = pgx.TxOptions{IsoLevel: pgx.ReadCommitted}
	}
	tx, err := s.pool.BeginTx(ctx, options)
	if err != nil {
		return AuthorizationSnapshot{}, ErrPersistence
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if request.SessionFacts != nil {
		if err := lockSessionAuthority(ctx, tx, request); err != nil {
			return AuthorizationSnapshot{}, err
		}
	}
	// In the writer path, validity is evaluated after acquiring authority locks.
	now := clock().UTC().Truncate(time.Microsecond)
	snapshotExpires := now.Add(snapshotTTL)

	var result AuthorizationSnapshot
	var revision int64
	var minMajor, minMinor, maxMajor, maxMinor int32
	var certificateStatus, rotationStatus, caStatus string
	var leafPEM, leafDERHash []byte
	var overlapUntil, revocationEffectiveAt *time.Time
	var nodeScopeID, configurationScopeID uuid.UUID
	var nodeScopeKind string
	var nodeTenantID, configurationTenantID, stateConfigurationScopeID *uuid.UUID
	var configurationScopeCount int64
	err = tx.QueryRow(ctx, `
		SELECT node.id,cert.installation_id,node.scope_id,scope.kind,
		       scope.tenant_id,config_state.configuration_scope_id,config_scope.tenant_id,config_state.scope_count,
		       state.authorization_revision,node.admin_state,cert.status,cert.not_after,
		       auth.protocol_min_major,auth.protocol_min_minor,auth.protocol_max_major,auth.protocol_max_minor,
		       state.active_artifact_key_id,cert.rotation_status,cert.overlap_until,
		       cert.leaf_certificate_pem,cert.leaf_der_sha256,epoch.status,
		       revocation.effective_at
		FROM nodes node
		JOIN access_scopes scope ON scope.id=node.scope_id
		JOIN node_identity_state state ON state.node_id=node.id
		LEFT JOIN LATERAL (
			SELECT CASE WHEN count(*)=1 THEN (array_agg(scoped.configuration_scope_id))[1] END AS configuration_scope_id,
			       count(*) AS scope_count
			FROM node_config_state scoped WHERE scoped.node_id=node.id
		) config_state ON true
		LEFT JOIN access_scopes config_scope ON config_scope.id=config_state.configuration_scope_id
		JOIN node_certificates cert ON cert.node_id=node.id AND cert.serial_number=$2
		 AND cert.leaf_der_sha256=$4
		 AND cert.owner_scope_id=node.scope_id AND cert.rotation_status IN ('current','overlap')
		JOIN control_installation_entitlement installation
		  ON installation.singleton AND installation.installation_id=cert.installation_id
		JOIN node_ca_key_epochs epoch
		  ON epoch.id=cert.ca_epoch_id AND epoch.installation_id=cert.installation_id
		LEFT JOIN LATERAL (
			SELECT min(fact.effective_at) AS effective_at
			FROM node_certificate_revocations fact
			WHERE fact.certificate_id=cert.id AND fact.node_id=cert.node_id
			  AND fact.binding_status='bound'
		) revocation ON true
		JOIN node_identity_authorizations auth ON auth.node_id=node.id AND auth.status='issued'
		WHERE node.id=$1 AND auth.gateway_workload_identity=$3
		ORDER BY auth.completed_at DESC LIMIT 1`, request.NodeID, request.CertificateSerialNumber,
		request.GatewayWorkloadIdentity, request.CertificateSHA256[:]).Scan(
		&result.NodeID, &result.InstallationID, &nodeScopeID, &nodeScopeKind,
		&nodeTenantID, &stateConfigurationScopeID, &configurationTenantID, &configurationScopeCount,
		&revision, &result.AdministrativeState, &certificateStatus,
		&result.CertificateExpirationTime, &minMajor, &minMinor, &maxMajor, &maxMinor,
		&result.ArtifactEncryptionKeyID, &rotationStatus, &overlapUntil, &leafPEM, &leafDERHash,
		&caStatus, &revocationEffectiveAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthorizationSnapshot{}, ErrCertificateNotFound
	}
	if err != nil {
		return AuthorizationSnapshot{}, fmt.Errorf("%w: read node authorization: %v", ErrPersistence, err)
	}
	if revision < 1 || result.InstallationID == "" || result.ArtifactEncryptionKeyID == "" ||
		nodeScopeID == uuid.Nil || nodeScopeKind == "" || len(leafDERHash) != 32 {
		return AuthorizationSnapshot{}, fmt.Errorf("%w: node authorization record is incomplete", ErrPersistence)
	}
	result.NodeScopeID = nodeScopeID
	configurationScopeID = nodeScopeID
	tenantID := nodeTenantID
	if stateConfigurationScopeID != nil {
		if *stateConfigurationScopeID == uuid.Nil ||
			(nodeScopeKind != "platform" && *stateConfigurationScopeID != nodeScopeID) ||
			(configurationTenantID == nil && nodeScopeKind == "tenant") {
			return AuthorizationSnapshot{}, fmt.Errorf("%w: node configuration scope %s does not match node scope %s",
				ErrPersistence, *stateConfigurationScopeID, nodeScopeID)
		}
		configurationScopeID = *stateConfigurationScopeID
		tenantID = configurationTenantID
	}
	if configurationScopeID == uuid.Nil {
		return AuthorizationSnapshot{}, ErrPersistence
	}
	// A node serving several scopes has no single tenant. It gets no top-level
	// tenant, so a legacy gateway session still fails closed, and the sites of
	// every scope, each bound to its own scope and tenant for scoped sessions.
	// Only platform nodes are shared (migration 291 and the claim path enforce
	// it too). A scope whose configuration cannot be attributed is left out
	// rather than taking the node and its other tenants offline.
	multiScope := configurationScopeCount > 1
	if multiScope && nodeScopeKind != "platform" {
		return AuthorizationSnapshot{}, fmt.Errorf("%w: %s node holds %d configuration scopes", ErrPersistence, nodeScopeKind, configurationScopeCount)
	}
	scopeTenants := map[uuid.UUID]*uuid.UUID{configurationScopeID: tenantID}
	if multiScope {
		tenantID = nil
		if scopeTenants, err = loadConfigurationScopeTenants(ctx, tx, request.NodeID, configurationScopeCount); err != nil {
			return AuthorizationSnapshot{}, err
		}
	}
	telemetrySites, excluded, err := loadTelemetrySiteScopes(ctx, tx, request.NodeID, scopeTenants, multiScope, now)
	if err != nil {
		return AuthorizationSnapshot{}, err
	}
	if len(excluded) != 0 {
		result.TelemetryExcludedScopes = excluded
		for scopeID, reason := range excluded {
			slog.WarnContext(ctx, "node authorization left a configuration scope's telemetry out",
				"node_id", request.NodeID, "configuration_scope_id", scopeID, "reason", reason)
		}
	}
	if tenantID != nil {
		result.TenantID = *tenantID
		result.TelemetrySites = telemetrySites
	} else if multiScope {
		result.TelemetrySites = telemetrySites
	} else if len(telemetrySites) != 0 {
		return AuthorizationSnapshot{}, fmt.Errorf("%w: telemetry sites without a tenant", ErrPersistence)
	}
	leaf, err := parseSinglePEMCertificate(leafPEM)
	if err != nil {
		return AuthorizationSnapshot{}, ErrPersistence
	}
	actualLeafDERHash := sha256.Sum256(leaf.Raw)
	if subtle.ConstantTimeCompare(leafDERHash, actualLeafDERHash[:]) != 1 {
		return AuthorizationSnapshot{}, ErrPersistence
	}
	result.AuthorizationRevision = uint64(revision)
	result.CertificateRevoked = certificateStatus == "revoked" ||
		(revocationEffectiveAt != nil && !now.Before(*revocationEffectiveAt))
	rotationAllowed := rotationStatus == "current" ||
		(rotationStatus == "overlap" && overlapUntil != nil && now.Before(*overlapUntil))
	result.ConnectionAllowed = !result.CertificateRevoked && caStatus != "revoked" && rotationAllowed &&
		now.Before(result.CertificateExpirationTime) &&
		// A self-registered node waits in pending until an administrator
		// initializes it; it keeps a session for heartbeat and certificate
		// renewal but DeploymentsAllowed below stays false.
		(result.AdministrativeState == "active" || result.AdministrativeState == "draining" ||
			result.AdministrativeState == "pending")
	result.DeploymentsAllowed = result.ConnectionAllowed && result.AdministrativeState == "active" &&
		rotationStatus == "current"
	result.AcceptedProtocolVersions = &commonv1.ProtocolVersionRange{
		Minimum: &commonv1.ProtocolVersion{Major: uint32(minMajor), Minor: uint32(minMinor)},
		Maximum: &commonv1.ProtocolVersion{Major: uint32(maxMajor), Minor: uint32(maxMinor)},
	}
	if result.CertificateExpirationTime.Before(snapshotExpires) {
		snapshotExpires = result.CertificateExpirationTime
	}
	if overlapUntil != nil && overlapUntil.Before(snapshotExpires) {
		snapshotExpires = *overlapUntil
	}
	if revocationEffectiveAt != nil && revocationEffectiveAt.Before(snapshotExpires) {
		snapshotExpires = *revocationEffectiveAt
	}
	result.SnapshotExpirationTime = snapshotExpires
	if request.SessionFacts != nil {
		result.SessionFactsSHA256, err = persistSessionCapabilities(ctx, tx, request, result, now)
		if err != nil {
			return AuthorizationSnapshot{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return AuthorizationSnapshot{}, ErrPersistence
	}
	return result, nil
}

// TelemetryScopeExclusions reports, for a node serving several scopes, the
// scopes its authorization snapshot leaves out of telemetry and why
// (TelemetryExclusion*). A node with one scope or none has no exclusions: it
// fails closed instead. It reads inside the caller's transaction.
func TelemetryScopeExclusions(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) (map[uuid.UUID]string, error) {
	var count int64
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT count(state.configuration_scope_id), bool_or(scope.kind='platform')
		FROM nodes node JOIN access_scopes scope ON scope.id=node.scope_id
		LEFT JOIN node_config_state state ON state.node_id=node.id
		WHERE node.id=$1 GROUP BY node.id`, nodeID).Scan(&count, &platform); err != nil {
		return nil, ErrPersistence
	}
	if count < 2 || !platform {
		return map[uuid.UUID]string{}, nil
	}
	scopeTenants, err := loadConfigurationScopeTenants(ctx, tx, nodeID, count)
	if err != nil {
		return nil, err
	}
	_, excluded, err := loadTelemetrySiteScopes(ctx, tx, nodeID, scopeTenants, true, now.UTC().Truncate(time.Microsecond))
	return excluded, err
}

// loadConfigurationScopeTenants returns the tenant of every scope a node holds
// a configuration state for; a platform scope has no tenant.
func loadConfigurationScopeTenants(
	ctx context.Context,
	tx pgx.Tx,
	nodeID uuid.UUID,
	expected int64,
) (map[uuid.UUID]*uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT state.configuration_scope_id,scope.tenant_id
		FROM node_config_state state
		JOIN access_scopes scope ON scope.id=state.configuration_scope_id
		WHERE state.node_id=$1`, nodeID)
	if err != nil {
		return nil, ErrPersistence
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*uuid.UUID)
	for rows.Next() {
		var scopeID uuid.UUID
		var tenantID *uuid.UUID
		if err := rows.Scan(&scopeID, &tenantID); err != nil || scopeID == uuid.Nil {
			return nil, ErrPersistence
		}
		result[scopeID] = tenantID
	}
	if rows.Err() != nil || int64(len(result)) != expected {
		return nil, ErrPersistence
	}
	return result, nil
}

// Reasons a node serving several scopes leaves one scope's telemetry out of
// its authorization snapshot. The node keeps its session and the other scopes.
const (
	TelemetryExclusionPlatformScope = "platform_scope"         // a platform scope has no tenant to attribute to
	TelemetryExclusionInvalidConfig = "invalid_config_version" // a config version of the scope cannot be read
	TelemetryExclusionSiteLimit     = "telemetry_site_limit"   // the scope does not fit the snapshot's site budget
)

// loadTelemetrySiteScopes returns the telemetry sites of the scopes in
// scopeTenants. With isolate (a node serving several scopes) a scope whose
// configuration cannot be attributed is left out and named in the returned
// exclusions, so one tenant cannot take the others' sessions down; a single
// scope still fails the whole snapshot closed.
func loadTelemetrySiteScopes(
	ctx context.Context,
	tx pgx.Tx,
	nodeID uuid.UUID,
	scopeTenants map[uuid.UUID]*uuid.UUID,
	isolate bool,
	now time.Time,
) ([]TelemetrySiteScope, map[uuid.UUID]string, error) {
	// A node serving several scopes holds a state per scope; every scope the
	// snapshot carries must be one of them when the node holds any.
	var stateScopes, claimedScopes int
	scopeIDs := make([]uuid.UUID, 0, len(scopeTenants))
	for scopeID := range scopeTenants {
		scopeIDs = append(scopeIDs, scopeID)
	}
	err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE configuration_scope_id=ANY($2::uuid[]))
		FROM node_config_state WHERE node_id=$1`, nodeID, scopeIDs).Scan(&stateScopes, &claimedScopes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: count node configuration scopes: %v", ErrPersistence, err)
	}
	if stateScopes != 0 && claimedScopes != len(scopeTenants) {
		return nil, nil, fmt.Errorf("%w: node holds %d configuration scopes, authorization carries %d of them",
			ErrPersistence, stateScopes, claimedScopes)
	}

	// Each scope reads at most MaxTelemetrySiteScopes+1 versions, so one
	// scope's history cannot crowd out another's.
	rows, err := tx.Query(ctx, `
		WITH candidate(config_version_id) AS (
			SELECT state.current_config_version_id
			FROM node_config_state state
			WHERE state.node_id=$1 AND state.current_config_version_id IS NOT NULL
			UNION
			SELECT deployment.config_version_id
			FROM node_deployments deployment
			JOIN deployment_status_events event
			  ON event.deployment_id=deployment.id AND event.attempt=deployment.attempt
			WHERE deployment.node_id=$1
			  AND event.occurred_at BETWEEN $2 AND $3
			  AND ((deployment.action='apply' AND deployment.state='healthy' AND event.state='healthy')
			    OR (deployment.action='rollback' AND deployment.state='reverted' AND event.state='reverted'))
			UNION
			SELECT reconciliation.observed_config_version_id
			FROM node_config_reconciliations reconciliation
			WHERE reconciliation.node_id=$1
			  AND reconciliation.reconciled_at BETWEEN $2 AND $3
			  AND reconciliation.observed_config_version_id IS NOT NULL
		), ranked AS (
			SELECT candidate.config_version_id,version.configuration_scope_id,version.status,
			       version.canonical_snapshot,version.canonical_snapshot_sha256,
			       row_number() OVER (PARTITION BY version.configuration_scope_id
			                          ORDER BY candidate.config_version_id) AS position
			FROM candidate
			LEFT JOIN config_versions version ON version.id=candidate.config_version_id
		)
		SELECT config_version_id,configuration_scope_id,status,canonical_snapshot,canonical_snapshot_sha256
		FROM ranked WHERE position<=$4
		ORDER BY config_version_id`, nodeID, now.Add(-90*24*time.Hour), now, MaxTelemetrySiteScopes+1)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read node telemetry config versions: %v", ErrPersistence, err)
	}
	defer rows.Close()

	type telemetryTuple struct {
		siteID, configVersionID uuid.UUID
	}
	excluded := make(map[uuid.UUID]string)
	exclude := func(scopeID uuid.UUID, reason string) error {
		if !isolate {
			return fmt.Errorf("%w: configuration scope %s cannot carry telemetry: %s", ErrPersistence, scopeID, reason)
		}
		if _, already := excluded[scopeID]; !already {
			excluded[scopeID] = reason
		}
		return nil
	}
	type telemetryCandidate struct {
		id               uuid.UUID
		scopeID          *uuid.UUID
		status           *string
		snapshot, digest []byte
	}
	var candidates []telemetryCandidate
	for rows.Next() {
		var candidate telemetryCandidate
		if err := rows.Scan(&candidate.id, &candidate.scopeID, &candidate.status, &candidate.snapshot, &candidate.digest); err != nil ||
			candidate.id == uuid.Nil || candidate.scopeID == nil {
			// A version the node reports but nobody published names no
			// scope to blame: the node's facts are inconsistent.
			return nil, nil, fmt.Errorf("%w: node telemetry config version %s is unpublished or unreadable (%v)",
				ErrPersistence, candidate.id, err)
		}
		// The node artifact set, its segments and other non site
		// publications share the deployment tables but name no site.
		if !telemetrySiteRuntimeCandidate(candidate.snapshot) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("%w: read node telemetry config versions: %v", ErrPersistence, err)
	}
	rows.Close()
	versionIDs := make([]uuid.UUID, len(candidates))
	for index, candidate := range candidates {
		versionIDs[index] = candidate.id
	}
	subscriptions, err := loadTelemetrySiteSubscriptions(ctx, tx, versionIDs)
	if err != nil {
		return nil, nil, err
	}
	perScope := make(map[uuid.UUID]map[telemetryTuple]TelemetrySiteScope)
	versions := make(map[uuid.UUID]int)
	for _, candidate := range candidates {
		candidateID, status, snapshot, storedDigest := candidate.id, candidate.status, candidate.snapshot, candidate.digest
		scopeID := *candidate.scopeID
		tenantID, carried := scopeTenants[scopeID]
		if !carried {
			// History of a scope that has since left the node: it is not
			// authorized for telemetry either way.
			if !isolate {
				return nil, nil, fmt.Errorf("%w: config version %s belongs to configuration scope %s the node does not carry",
					ErrPersistence, candidateID, scopeID)
			}
			continue
		}
		if _, out := excluded[scopeID]; out {
			continue
		}
		if tenantID == nil || *tenantID == uuid.Nil {
			if err := exclude(scopeID, TelemetryExclusionPlatformScope); err != nil {
				return nil, nil, err
			}
			continue
		}
		versions[scopeID]++
		if versions[scopeID] > MaxTelemetrySiteScopes {
			if err := exclude(scopeID, TelemetryExclusionSiteLimit); err != nil {
				return nil, nil, err
			}
			continue
		}
		if status == nil || (*status != "releasable" && *status != "superseded" && *status != "revoked") {
			if err := exclude(scopeID, TelemetryExclusionInvalidConfig); err != nil {
				return nil, nil, err
			}
			continue
		}
		sites, _, unverified, err := parseTelemetrySnapshot(snapshot, storedDigest, scopeID, *tenantID, candidateID, subscriptions[candidateID])
		if err != nil {
			slog.WarnContext(ctx, "node authorization cannot read a config version's telemetry sites",
				"node_id", nodeID, "configuration_scope_id", scopeID, "config_version_id", candidateID,
				"reason", telemetrySnapshotReason(err), "isolated", isolate)
			if !isolate {
				return nil, nil, err
			}
			_ = exclude(scopeID, TelemetryExclusionInvalidConfig)
			continue
		}
		if len(unverified) != 0 {
			// Published before migration 295: these sites keep their
			// telemetry, unattributed to a package, instead of failing.
			slog.WarnContext(ctx, "node authorization cannot verify the package subscription of v2 sites",
				"node_id", nodeID, "configuration_scope_id", scopeID, "config_version_id", candidateID,
				"sites", len(unverified))
		}
		if perScope[scopeID] == nil {
			perScope[scopeID] = make(map[telemetryTuple]TelemetrySiteScope)
		}
		for _, site := range sites {
			perScope[scopeID][telemetryTuple{site.SiteID, site.ConfigVersionID}] = site
		}
		if len(perScope[scopeID]) > MaxTelemetrySiteScopes {
			if err := exclude(scopeID, TelemetryExclusionSiteLimit); err != nil {
				return nil, nil, err
			}
		}
	}
	// Keep whole scopes, smallest first, while they fit the snapshot.
	kept := make([]uuid.UUID, 0, len(perScope))
	for scopeID := range perScope {
		if _, out := excluded[scopeID]; !out {
			kept = append(kept, scopeID)
		}
	}
	sort.Slice(kept, func(left, right int) bool {
		if len(perScope[kept[left]]) != len(perScope[kept[right]]) {
			return len(perScope[kept[left]]) < len(perScope[kept[right]])
		}
		return kept[left].String() < kept[right].String()
	})
	result := make([]TelemetrySiteScope, 0)
	for _, scopeID := range kept {
		if len(result)+len(perScope[scopeID]) > MaxTelemetrySiteScopes {
			if err := exclude(scopeID, TelemetryExclusionSiteLimit); err != nil {
				return nil, nil, err
			}
			continue
		}
		for _, site := range perScope[scopeID] {
			result = append(result, site)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		leftSite, rightSite := result[left].SiteID.String(), result[right].SiteID.String()
		if leftSite != rightSite {
			return leftSite < rightSite
		}
		return result[left].ConfigVersionID.String() < result[right].ConfigVersionID.String()
	})
	return result, excluded, nil
}

// loadTelemetrySiteSubscriptions returns, per config version, the package
// subscription the publication recorded for each site (the binding's
// TelemetrySiteScope.PackageSubscriptionID). Site runtime v2
// documents carry it only with a connection limit; publications since
// migration 295 record every site (config_version_telemetry_site_bindings,
// recorded), earlier ones only the package monitor bindings (114), which
// leave out sites published while recovering from a package status.
func loadTelemetrySiteSubscriptions(ctx context.Context, tx pgx.Tx, versionIDs []uuid.UUID) (map[uuid.UUID]telemetrySiteSubscriptions, error) {
	result := make(map[uuid.UUID]telemetrySiteSubscriptions)
	if len(versionIDs) == 0 {
		return result, nil
	}
	rows, err := tx.Query(ctx, `SELECT config_version_id,site_id,COALESCE(package_subscription_id,'00000000-0000-0000-0000-000000000000'),true
		FROM config_version_telemetry_site_bindings WHERE config_version_id=ANY($1::uuid[])
		UNION ALL
		SELECT monitor.config_version_id,monitor.site_id,monitor.subscription_id,false
		FROM package_monitor_site_subscription_bindings_114 monitor
		WHERE monitor.config_version_id=ANY($1::uuid[]) AND NOT EXISTS (
			SELECT 1 FROM config_version_telemetry_site_bindings recorded
			WHERE recorded.config_version_id=monitor.config_version_id)`, versionIDs)
	if err != nil {
		return nil, ErrPersistence
	}
	defer rows.Close()
	for rows.Next() {
		var versionID, siteID, subscriptionID uuid.UUID
		var recorded bool
		if err := rows.Scan(&versionID, &siteID, &subscriptionID, &recorded); err != nil {
			return nil, ErrPersistence
		}
		entry, exists := result[versionID]
		if !exists {
			entry = telemetrySiteSubscriptions{sites: make(map[uuid.UUID]uuid.UUID), recorded: recorded}
		}
		entry.sites[siteID] = subscriptionID
		result[versionID] = entry
	}
	if rows.Err() != nil {
		return nil, ErrPersistence
	}
	return result, nil
}

func parseTelemetryCanonicalSnapshot(
	raw, storedDigest []byte,
	configurationScopeID, tenantID, configVersionID uuid.UUID,
) ([]TelemetrySiteScope, error) {
	bindings, _, _, err := parseTelemetrySnapshot(raw, storedDigest, configurationScopeID, tenantID, configVersionID,
		telemetrySiteSubscriptions{})
	return bindings, err
}

// parseTelemetrySnapshot binds the sites of a published canonical snapshot of
// either schema the control plane publishes; both give the same bindings for
// the same sites. subscriptions are the package subscriptions the
// publication recorded per site, needed for v2 (see parseTelemetrySiteRuntimeV2,
// which also returns the v2 sites whose subscription it could not verify).
// An unknown schema is refused with its reason (TelemetrySnapshotError).
func parseTelemetrySnapshot(
	raw, storedDigest []byte,
	configurationScopeID, tenantID, configVersionID uuid.UUID,
	subscriptions telemetrySiteSubscriptions,
) ([]TelemetrySiteScope, []PublishedTelemetryListener, []uuid.UUID, error) {
	if len(raw) == 0 || len(storedDigest) != sha256.Size || configurationScopeID == uuid.Nil ||
		tenantID == uuid.Nil || configVersionID == uuid.Nil {
		return nil, nil, nil, ErrPersistence
	}
	digest := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
		return nil, nil, nil, telemetrySnapshotError(configVersionID, "canonical snapshot digest does not match")
	}
	schema, err := telemetrySnapshotSchema(raw)
	if err != nil {
		return nil, nil, nil, telemetrySnapshotError(configVersionID, "canonical snapshot does not decode")
	}
	switch schema {
	case telemetrySnapshotSchemaV2:
		return parseTelemetrySiteRuntimeV2(raw, configurationScopeID, tenantID, configVersionID, subscriptions)
	default:
		return nil, nil, nil, telemetrySnapshotError(configVersionID, fmt.Sprintf("unknown canonical snapshot schema %q", schema))
	}
}

func uniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}

func cloneProtocolVersion(value *commonv1.ProtocolVersion) *commonv1.ProtocolVersion {
	if value == nil {
		return nil
	}
	return &commonv1.ProtocolVersion{Major: value.Major, Minor: value.Minor}
}
