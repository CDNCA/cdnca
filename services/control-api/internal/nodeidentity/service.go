package nodeidentity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	certlifecycle "github.com/cdnca/cdnca/services/control-api/internal/nodecertlifecycle"
	"github.com/google/uuid"
)

const MaxTelemetrySiteScopes = 10_000

type Service struct {
	store          *Store
	signer         CertificateSigner
	config         Config
	recoveryAlerts RecoveryAlertEnqueuer
}

func DefaultConfig() Config {
	return withTestCertificateTTL(Config{
		AcceptedProtocols: &commonv1.ProtocolVersionRange{
			Minimum: &commonv1.ProtocolVersion{Major: 1, Minor: 0},
			Maximum: &commonv1.ProtocolVersion{Major: 1, Minor: 0},
		},
		AuthorizationTTL: 5 * time.Minute, RenewalRequestTTL: 10 * time.Minute,
		CertificateTTL: DefaultCertificateTTL, CertificateBackdate: time.Minute,
		RenewBefore: DefaultRenewBefore, SigningLeaseTTL: 30 * time.Second,
		SnapshotTTL: time.Minute, RecoveryWindow: DefaultRecoveryWindow, Clock: time.Now, NewID: uuid.NewV7,
	})
}

func NewService(store *Store, signer CertificateSigner, config Config) (*Service, error) {
	if store == nil || store.pool == nil || signer == nil || !validConfig(config) {
		return nil, ErrInvalidInput
	}
	config.AcceptedProtocols = cloneProtocolRange(config.AcceptedProtocols)
	return &Service{store: store, signer: signer, config: config}, nil
}

func (s *Service) Authorize(ctx context.Context, request AuthorizeRequest) (Authorization, error) {
	normalized, err := normalizeAuthorize(request, s.config.AcceptedProtocols)
	if err != nil {
		return Authorization{}, err
	}
	authorizationID, err := s.config.NewID()
	if err != nil || authorizationID == uuid.Nil {
		return Authorization{}, ErrPersistence
	}
	now := s.config.Clock().UTC().Truncate(time.Microsecond)
	return s.store.authorize(ctx, authorizeStoreInput{normalizedAuthorize: normalized,
		AuthorizationID: authorizationID, AuthorizedAt: now, ExpiresAt: now.Add(s.config.AuthorizationTTL)})
}

func (s *Service) Complete(ctx context.Context, request CompleteRequest) (EnrollmentCompletion, error) {
	requestID, err := canonicalRequestID(request.RequestID)
	if err != nil {
		return EnrollmentCompletion{}, err
	}
	if request.AuthorizationID == uuid.Nil || !validIdentity(request.GatewayWorkloadIdentity, 256) ||
		!validIdentity(request.GatewayInstanceID, 128) {
		return EnrollmentCompletion{}, ErrInvalidInput
	}
	if existing, found, err := s.store.preflightEnrollmentCompletion(ctx, request.AuthorizationID, requestID,
		request.GatewayWorkloadIdentity, request.GatewayInstanceID); err != nil {
		return EnrollmentCompletion{}, err
	} else if found {
		return existing, nil
	}
	leaseID, err := s.config.NewID()
	if err != nil || leaseID == uuid.Nil {
		return EnrollmentCompletion{}, ErrPersistence
	}
	now := s.config.Clock().UTC().Truncate(time.Second)
	claim, err := s.store.prepareEnrollmentSigning(ctx, request.AuthorizationID, requestID, leaseID,
		request.GatewayWorkloadIdentity, request.GatewayInstanceID, now, now.Add(s.config.SigningLeaseTTL))
	if err != nil {
		return EnrollmentCompletion{}, err
	}
	if claim.Existing != nil {
		return EnrollmentCompletion{Certificate: cloneCertificate(*claim.Existing),
			ArtifactEncryptionKeyID: claim.ArtifactKeyID}, nil
	}
	resetSigning := func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.store.resetEnrollmentSigning(cleanupCtx, claim.AuthorizationID, claim.LeaseID, s.config.Clock().UTC())
	}
	csr, _, csrHash, err := validateCSR(claim.CSRDER)
	if err != nil || csrHash != claim.CSRHash {
		resetSigning()
		return EnrollmentCompletion{}, ErrCertificateInvalid
	}
	result, err := s.sign(ctx, claim.NodeID, claim.CSRDER, "initial", now)
	if err != nil {
		resetSigning()
		return EnrollmentCompletion{}, err
	}
	persisted, err := s.prepareCertificate(result, csr, claim.NodeID, claim.CSRHash, now)
	if err != nil {
		resetSigning()
		return EnrollmentCompletion{}, err
	}
	certificateID, eventID, err := s.twoIDs()
	if err != nil {
		resetSigning()
		return EnrollmentCompletion{}, err
	}
	persisted.ID = certificateID
	persisted.Certificate.ID = certificateID
	persisted.EnrollmentAuthorizationID = &claim.AuthorizationID
	certificate, err := s.store.finalizeEnrollment(ctx, claim, persisted,
		s.config.Clock().UTC().Truncate(time.Microsecond), eventID)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.store.resetEnrollmentSigning(cleanupCtx, claim.AuthorizationID, claim.LeaseID, s.config.Clock().UTC())
		cancel()
		return EnrollmentCompletion{}, err
	}
	return EnrollmentCompletion{Certificate: certificate, ArtifactEncryptionKeyID: claim.ArtifactKeyID}, nil
}

func (s *Service) Renew(ctx context.Context, request RenewRequest) (Certificate, error) {
	normalized, err := normalizeRenew(request)
	if err != nil {
		return Certificate{}, err
	}
	now := s.config.Clock().UTC().Truncate(time.Second)
	if existing, found, err := s.store.preflightRenewal(ctx, normalized, now); err != nil {
		return Certificate{}, err
	} else if found {
		if err := s.completeRenewalLifecycle(ctx, normalized, existing); err != nil {
			return Certificate{}, err
		}
		return existing, nil
	}
	claim, err := s.store.prepareRenewal(ctx, normalized, s.config.NewID, now,
		now.Add(s.config.RenewalRequestTTL), now.Add(s.config.SigningLeaseTTL))
	if err != nil {
		return Certificate{}, err
	}
	if claim.Existing != nil {
		if err := s.completeRenewalLifecycle(ctx, normalized, *claim.Existing); err != nil {
			return Certificate{}, err
		}
		return cloneCertificate(*claim.Existing), nil
	}
	resetSigning := func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.store.resetRenewalSigning(cleanupCtx, claim.RequestID, claim.LeaseID)
	}
	csr, _, csrHash, err := validateCSR(claim.CSRDER)
	if err != nil || csrHash != claim.CSRHash {
		resetSigning()
		return Certificate{}, ErrCertificateInvalid
	}
	signed, err := s.sign(ctx, claim.NodeID, claim.CSRDER, "renewal", now)
	if err != nil {
		resetSigning()
		return Certificate{}, err
	}
	persisted, err := s.prepareCertificate(signed, csr, claim.NodeID, claim.CSRHash, now)
	if err != nil {
		resetSigning()
		return Certificate{}, err
	}
	if err := s.proveRenewalLifecycle(ctx, normalized, persisted.Certificate, persisted.IssuerCAHash); err != nil {
		resetSigning()
		return Certificate{}, err
	}
	certificateID, eventID, err := s.twoIDs()
	if err != nil {
		resetSigning()
		return Certificate{}, err
	}
	persisted.ID = certificateID
	persisted.Certificate.ID = certificateID
	persisted.RenewalRequestID = &claim.RequestID
	persisted.ReplacesCertificateID = &claim.CurrentCertificateID
	certificate, err := s.store.finalizeRenewal(ctx, claim, persisted,
		s.config.Clock().UTC().Truncate(time.Microsecond), eventID)
	if err != nil {
		resetSigning()
		return Certificate{}, err
	}
	if err := s.bindIssuedRenewal(ctx, normalized, certificate); err != nil {
		return Certificate{}, err
	}
	return certificate, nil
}

func (s *Service) completeRenewalLifecycle(ctx context.Context, normalized normalizedRenew, certificate Certificate) error {
	issuerHash, err := certificateIssuerHash(certificate)
	if err != nil {
		return err
	}
	if err := s.proveRenewalLifecycle(ctx, normalized, certificate, issuerHash); err != nil {
		return err
	}
	return s.bindIssuedRenewal(ctx, normalized, certificate)
}

func (s *Service) proveRenewalLifecycle(
	ctx context.Context,
	normalized normalizedRenew,
	certificate Certificate,
	issuerHash [sha256.Size]byte,
) error {
	epochID, err := s.store.activeRenewalCAEpoch(ctx, issuerHash, certificate.NotBefore, certificate.NotAfter)
	if err != nil {
		return err
	}
	principal, err := certlifecycle.NewGatewayMTLSPrincipal(normalized.GatewayWorkloadIdentity, normalized.GatewayInstanceID)
	if err != nil {
		return ErrGatewayBinding
	}
	lifecycle, err := certlifecycle.NewStore(s.store.pool, certlifecycle.Config{
		Clock: func() time.Time { return s.config.Clock() }, OverlapWindow: 10 * time.Minute,
		AuthorizationSnapshotTTL: s.config.SnapshotTTL, MaxScheduledRevocation: 7 * 24 * time.Hour,
	})
	if err != nil {
		return ErrPersistence
	}
	_, err = lifecycle.RecordGatewayMTLSProof(ctx, certlifecycle.RecordGatewayMTLSProofRequest{
		RenewalRequestID: normalized.RequestID, NodeID: normalized.NodeID,
		CurrentSerialNumber: normalized.CurrentSerial, CurrentLeafDERSHA256: normalized.CurrentCertificateSHA256,
		TargetCAEpochID: epochID, Principal: principal, RequestTraceID: normalized.RequestID.String(),
	})
	return mapRenewalLifecycleError(err)
}

func (s *Service) bindIssuedRenewal(ctx context.Context, normalized normalizedRenew, certificate Certificate) error {
	leaf, err := parseSinglePEMCertificate(certificate.LeafCertificatePEM)
	if err != nil {
		return ErrCertificateInvalid
	}
	lifecycle, err := certlifecycle.NewStore(s.store.pool, certlifecycle.Config{
		Clock: func() time.Time { return s.config.Clock() }, OverlapWindow: 10 * time.Minute,
		AuthorizationSnapshotTTL: s.config.SnapshotTTL, MaxScheduledRevocation: 7 * 24 * time.Hour,
	})
	if err != nil {
		return ErrPersistence
	}
	rotation, err := lifecycle.BindIssuedRenewal(ctx, certlifecycle.BindIssuedRenewalRequest{
		RenewalRequestID: normalized.RequestID, NodeID: normalized.NodeID,
		NewSerialNumber: certificate.SerialNumber, NewLeafDERSHA256: sha256.Sum256(leaf.Raw),
		RequestTraceID: normalized.RequestID.String(),
	})
	if err != nil {
		return mapRenewalLifecycleError(err)
	}
	if rotation.CurrentCertificate.CertificateID != certificate.ID ||
		rotation.CurrentCertificate.SerialNumber != certificate.SerialNumber ||
		rotation.CurrentCertificate.RotationStatus != certlifecycle.RotationCurrent ||
		rotation.PreviousCertificate.SerialNumber != normalized.CurrentSerial ||
		rotation.PreviousCertificate.RotationStatus != certlifecycle.RotationOverlap {
		return ErrPersistence
	}
	return nil
}

func certificateIssuerHash(certificate Certificate) ([sha256.Size]byte, error) {
	if len(certificate.IssuingChainPEM) == 0 {
		return [sha256.Size]byte{}, ErrCertificateInvalid
	}
	issuer, err := parseSinglePEMCertificate(certificate.IssuingChainPEM[0])
	if err != nil {
		return [sha256.Size]byte{}, ErrCertificateInvalid
	}
	return sha256.Sum256(issuer.Raw), nil
}

func mapRenewalLifecycleError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, certlifecycle.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, certlifecycle.ErrPermissionDenied):
		return ErrGatewayBinding
	case errors.Is(err, certlifecycle.ErrNotFound):
		return ErrCertificateNotFound
	case errors.Is(err, certlifecycle.ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	case errors.Is(err, certlifecycle.ErrRenewalTooEarly):
		return ErrRenewalTooEarly
	case errors.Is(err, certlifecycle.ErrCertificateRevoked):
		return ErrCertificateRevoked
	case errors.Is(err, certlifecycle.ErrOverlapActive):
		return ErrRenewalConflict
	case errors.Is(err, certlifecycle.ErrPersistence):
		return ErrPersistence
	default:
		return ErrCertificateInvalid
	}
}

func (s *Service) Revoke(ctx context.Context, request RevokeRequest) error {
	requestID, err := canonicalRequestID(request.RequestID)
	request.Reason = strings.TrimSpace(request.Reason)
	if err != nil || request.NodeID == uuid.Nil || !validSerial(request.SerialNumber) || request.Reason == "" ||
		!utf8.ValidString(request.Reason) || len(request.Reason) > 256 {
		return ErrInvalidInput
	}
	eventID, err := s.config.NewID()
	if err != nil || eventID == uuid.Nil {
		return ErrPersistence
	}
	return s.store.revoke(ctx, requestID, request.NodeID, request.SerialNumber, request.Reason,
		canonicalRevocationDigest(request.NodeID, request.SerialNumber, request.Reason),
		s.config.Clock().UTC().Truncate(time.Microsecond), eventID)
}

func (s *Service) GetAuthorization(ctx context.Context, request GetAuthorizationRequest) (AuthorizationSnapshot, error) {
	if request.NodeID == uuid.Nil || !validSerial(request.CertificateSerialNumber) ||
		!validIdentity(request.GatewayWorkloadIdentity, 256) || !validIdentity(request.GatewayInstanceID, 128) {
		return AuthorizationSnapshot{}, ErrInvalidInput
	}
	if request.SessionFacts != nil {
		facts, _, _, err := normalizeSessionFacts(request)
		if err != nil {
			return AuthorizationSnapshot{}, err
		}
		request.SessionFacts = facts
	}
	return s.store.authorizationSnapshot(ctx, request, s.config.Clock, s.config.SnapshotTTL)
}

func (s *Service) sign(ctx context.Context, nodeID uuid.UUID, csrDER []byte, kind string, now time.Time) (SignedCertificate, error) {
	notBefore := now.Add(-s.config.CertificateBackdate).Truncate(time.Second)
	notAfter := now.Add(s.config.CertificateTTL).Truncate(time.Second)
	result, err := s.signer.SignNodeCertificate(ctx, SignRequest{NodeID: nodeID,
		CertificateSigningRequestDER: append([]byte(nil), csrDER...), URISAN: NodeSPIFFEPrefix + nodeID.String(),
		NotBefore: notBefore, NotAfter: notAfter, IssuanceKind: kind})
	if err != nil {
		return SignedCertificate{}, ErrSigningFailed
	}
	return result, nil
}

func (s *Service) prepareCertificate(signed SignedCertificate, csr *x509.CertificateRequest, nodeID uuid.UUID, csrHash [32]byte, now time.Time) (persistedCertificate, error) {
	notBefore := now.Add(-s.config.CertificateBackdate).Truncate(time.Second)
	notAfter := now.Add(s.config.CertificateTTL).Truncate(time.Second)
	persisted, err := validateSignedCertificate(signed, csr, nodeID, notBefore, notAfter, s.config.RenewBefore)
	if err != nil {
		return persistedCertificate{}, err
	}
	persisted.CSRHash = csrHash
	return persisted, nil
}

func (s *Service) twoIDs() (uuid.UUID, uuid.UUID, error) {
	first, err := s.config.NewID()
	if err != nil || first == uuid.Nil {
		return uuid.Nil, uuid.Nil, ErrPersistence
	}
	second, err := s.config.NewID()
	if err != nil || second == uuid.Nil {
		return uuid.Nil, uuid.Nil, ErrPersistence
	}
	return first, second, nil
}

func canonicalRequestID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return uuid.Nil, ErrInvalidInput
	}
	return parsed, nil
}
