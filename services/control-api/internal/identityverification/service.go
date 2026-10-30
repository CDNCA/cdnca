package identityverification

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultReviewTTL       = 72 * time.Hour
	defaultRetentionPeriod = 6 * 365 * 24 * time.Hour
)

var (
	metadataPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	providerPattern          = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
	keyIDPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	objectPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/=@+\-]*$`)
	resolverNamePattern      = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
	resolverReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	reasonPattern            = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
)

type Service struct {
	pool            *pgxpool.Pool
	auditor         AuditAppender
	authorizer      TxAuthorizer
	now             Clock
	newID           IDGenerator
	reviewTTL       time.Duration
	retentionPeriod time.Duration
}

func NewService(pool *pgxpool.Pool) (*Service, error) {
	return NewServiceWithDependencies(pool, audit.New(pool), Config{})
}

func NewServiceWithDependencies(pool *pgxpool.Pool, auditor AuditAppender, config Config) (*Service, error) {
	return newService(pool, auditor, denyTxAuthorizer{}, config)
}

// NewTenantSessionService is retained only as a fail-closed compatibility constructor.
func NewTenantSessionService(
	pool *pgxpool.Pool,
	auditor AuditAppender,
	sessions *rbacmanager.Service,
	config Config,
) (*Service, error) {
	return nil, ErrInvalidService
}

// NewIAMService binds every write to iamlock.Authorizer inside its business transaction.
func NewIAMService(
	pool *pgxpool.Pool,
	auditor AuditAppender,
	sessions *iamlock.Authorizer,
	config Config,
) (*Service, error) {
	authorizer, err := newIAMSessionTxAuthorizer(sessions)
	if err != nil {
		return nil, err
	}
	return newService(pool, auditor, authorizer, config)
}

// newServiceWithTransactionAuthorizer is a package-local test seam.
func newServiceWithTransactionAuthorizer(
	pool *pgxpool.Pool,
	auditor AuditAppender,
	authorizer TxAuthorizer,
	config Config,
) (*Service, error) {
	return newService(pool, auditor, authorizer, config)
}

func newService(
	pool *pgxpool.Pool,
	auditor AuditAppender,
	authorizer TxAuthorizer,
	config Config,
) (*Service, error) {
	if pool == nil || auditor == nil || isNilTxAuthorizer(authorizer) {
		return nil, ErrInvalidService
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.NewID == nil {
		config.NewID = uuid.NewV7
	}
	if config.ReviewTTL == 0 {
		config.ReviewTTL = defaultReviewTTL
	}
	if config.RetentionPeriod == 0 {
		config.RetentionPeriod = defaultRetentionPeriod
	}
	if config.ReviewTTL <= 0 || config.RetentionPeriod <= 0 {
		return nil, ErrInvalidService
	}
	return &Service{pool: pool, auditor: auditor, authorizer: authorizer, now: config.Clock, newID: config.NewID,
		reviewTTL: config.ReviewTTL, retentionPeriod: config.RetentionPeriod}, nil
}

func (s *Service) CreateDraft(ctx context.Context, actor Actor, request CreateDraftRequest) (Case, error) {
	outcome, err := s.CreateDraftWithSettlement(ctx, actor, request)
	return outcome.Case, err
}

func (s *Service) CreateDraftWithSettlement(ctx context.Context, actor Actor, request CreateDraftRequest) (CreateDraftOutcome, error) {
	if !validActor(actor) {
		return CreateDraftOutcome{}, ErrInvalidInput
	}
	normalized, err := normalizeDraft(request)
	if err != nil {
		return CreateDraftOutcome{}, err
	}
	digest, err := requestDigest(normalized)
	if err != nil {
		return CreateDraftOutcome{}, err
	}
	return s.createDraft(ctx, actor, normalized, digest)
}

func (s *Service) Submit(ctx context.Context, actor Actor, request MutationRequest) (Case, error) {
	if !validActor(actor) || !validMutation(request) {
		return Case{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Case{}, err
	}
	return s.submit(ctx, actor, request, digest)
}

func (s *Service) StartReview(ctx context.Context, actor Actor, request MutationRequest) (Case, error) {
	if !validActor(actor) || !validMutation(request) {
		return Case{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Case{}, err
	}
	return s.startReview(ctx, actor, request, digest)
}

func (s *Service) Review(ctx context.Context, actor Actor, request ReviewRequest) (Case, error) {
	if !validActor(actor) || request.CaseID == uuid.Nil || request.ExpectedRevision < 1 ||
		(request.Decision != DecisionApprove && request.Decision != DecisionReject) ||
		!validReviewReason(request.Decision, request.ReasonCode) ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return Case{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Case{}, err
	}
	return s.review(ctx, actor, request, digest)
}

func (s *Service) Withdraw(ctx context.Context, actor Actor, request MutationRequest) (Case, error) {
	if !validActor(actor) || !validMutation(request) {
		return Case{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Case{}, err
	}
	return s.withdraw(ctx, actor, request, digest)
}

func (s *Service) Expire(ctx context.Context, actor Actor, request MutationRequest) (Case, error) {
	if !validActor(actor) || !validMutation(request) {
		return Case{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Case{}, err
	}
	return s.expire(ctx, actor, request, digest)
}

func (s *Service) Get(ctx context.Context, actor Actor, caseID uuid.UUID) (Case, error) {
	if !validActor(actor) || caseID == uuid.Nil {
		return Case{}, ErrInvalidInput
	}
	return s.get(ctx, actor, caseID)
}

func (s *Service) GetForReview(ctx context.Context, actor Actor, caseID uuid.UUID) (Case, error) {
	if !validActor(actor) || caseID == uuid.Nil {
		return Case{}, ErrInvalidInput
	}
	return s.getForReview(ctx, actor, caseID)
}

func validActor(actor Actor) bool {
	return actor.hasSessionBinding()
}

func validMutation(request MutationRequest) bool {
	return request.CaseID != uuid.Nil && request.ExpectedRevision > 0 &&
		validWriteMetadata(request.IdempotencyKey, request.RequestID)
}

func validWriteMetadata(key, requestID string) bool {
	return len(key) <= 128 && metadataPattern.MatchString(key) &&
		len(requestID) <= 128 && metadataPattern.MatchString(requestID)
}

func normalizeDraft(request CreateDraftRequest) (CreateDraftRequest, error) {
	request.OrganizationName = strings.TrimSpace(request.OrganizationName)
	if !validWriteMetadata(request.IdempotencyKey, request.RequestID) || len(request.SubjectFingerprint) != sha256.Size ||
		len(request.ResolverName) > 64 || !resolverNamePattern.MatchString(request.ResolverName) ||
		len(request.ResolverReference) > 256 || !resolverReferencePattern.MatchString(request.ResolverReference) ||
		request.EvidenceClaimDigest == ([32]byte{}) {
		return CreateDraftRequest{}, ErrInvalidInput
	}
	switch request.Kind {
	case KindPersonalInitial, KindPersonalReverification:
		if request.OrganizationName != "" || len(request.LegalPersonFingerprint) != 0 ||
			len(request.AgentFingerprint) != 0 || request.AgentRelationship != "" {
			return CreateDraftRequest{}, ErrInvalidInput
		}
	case KindEnterprise:
		if !utf8.ValidString(request.OrganizationName) || utf8.RuneCountInString(request.OrganizationName) < 2 ||
			utf8.RuneCountInString(request.OrganizationName) > 256 ||
			len(request.LegalPersonFingerprint) != sha256.Size || len(request.AgentFingerprint) != sha256.Size ||
			!validRelationship(request.AgentRelationship) ||
			(request.AgentRelationship == RelationshipLegalPerson &&
				!equalBytes(request.AgentFingerprint, request.LegalPersonFingerprint)) {
			return CreateDraftRequest{}, ErrInvalidInput
		}
	default:
		return CreateDraftRequest{}, ErrInvalidInput
	}
	if err := validateMaterials(request.Kind, request.AgentRelationship, request.Materials); err != nil {
		return CreateDraftRequest{}, err
	}
	request.SubjectFingerprint = append([]byte(nil), request.SubjectFingerprint...)
	request.LegalPersonFingerprint = append([]byte(nil), request.LegalPersonFingerprint...)
	request.AgentFingerprint = append([]byte(nil), request.AgentFingerprint...)
	request.Materials = cloneMaterials(request.Materials)
	return request, nil
}

func validateMaterials(kind, relationship string, materials []MaterialInput) error {
	if len(materials) < 2 || len(materials) > 16 {
		return ErrInvalidInput
	}
	found := make(map[string]bool, len(materials))
	for _, material := range materials {
		if !validMaterialKind(material.Kind) || found[material.Kind] && material.Kind != MaterialSupplementary ||
			len(material.EnvelopeProvider) > 64 || !providerPattern.MatchString(material.EnvelopeProvider) ||
			len(material.EnvelopeKeyID) > 256 || !keyIDPattern.MatchString(material.EnvelopeKeyID) ||
			len(material.EncryptedEnvelope) < 16 || len(material.EncryptedEnvelope) > 16384 ||
			len(material.ObjectReference) > 1024 || !objectPattern.MatchString(material.ObjectReference) ||
			len(material.ObjectSHA256) != sha256.Size || !validMIME(material.MIMEType) ||
			material.SizeBytes < 1 || material.SizeBytes > 20*1024*1024 {
			return ErrInvalidInput
		}
		found[material.Kind] = true
	}
	if kind != KindEnterprise {
		if !found[MaterialIdentityDocument] || !found[MaterialLivenessEvidence] {
			return ErrInvalidInput
		}
		return nil
	}
	if !found[MaterialBusinessLicense] || !found[MaterialLegalIdentity] || !found[MaterialAgentIdentity] ||
		(relationship != RelationshipLegalPerson && !found[MaterialAuthorization]) {
		return ErrInvalidInput
	}
	return nil
}

func validMaterialKind(value string) bool {
	switch value {
	case MaterialIdentityDocument, MaterialLivenessEvidence, MaterialBusinessLicense,
		MaterialLegalIdentity, MaterialAgentIdentity, MaterialAuthorization, MaterialSupplementary:
		return true
	default:
		return false
	}
}

func validRelationship(value string) bool {
	return value == RelationshipLegalPerson || value == RelationshipEmployee || value == RelationshipAuthorizedRepresentative
}

func validMIME(value string) bool {
	return value == "image/jpeg" || value == "image/png" || value == "application/pdf"
}

func validReviewReason(decision, reason string) bool {
	if decision == DecisionApprove {
		return reason == ReasonEvidenceVerified
	}
	switch reason {
	case ReasonIdentityMismatch, ReasonEvidenceIncomplete, ReasonEvidenceUnreadable,
		ReasonOrganizationMismatch, ReasonAuthorizationInvalid, ReasonSuspectedFraud:
		return true
	default:
		return false
	}
}

func cloneMaterials(input []MaterialInput) []MaterialInput {
	result := make([]MaterialInput, len(input))
	for index, material := range input {
		result[index] = material
		result[index].EncryptedEnvelope = append([]byte(nil), material.EncryptedEnvelope...)
		result[index].ObjectSHA256 = append([]byte(nil), material.ObjectSHA256...)
	}
	return result
}

func requestDigest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode identity verification request: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
