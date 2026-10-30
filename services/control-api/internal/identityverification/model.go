package identityverification

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput              = errors.New("invalid identity verification input")
	ErrInvalidService            = errors.New("invalid identity verification service")
	ErrPermissionDenied          = errors.New("identity verification permission denied")
	ErrNotFound                  = errors.New("identity verification case not found")
	ErrRevisionConflict          = errors.New("identity verification revision conflict")
	ErrInvalidTransition         = errors.New("invalid identity verification transition")
	ErrIdempotencyConflict       = errors.New("identity verification idempotency conflict")
	ErrActiveReview              = errors.New("identity verification review already active")
	ErrInitialApprovalRequired   = errors.New("approved initial identity required")
	ErrIdentityMismatch          = errors.New("identity fingerprint does not match approved identity")
	ErrAlreadyVerified           = errors.New("identity subject is already verified")
	ErrSelfReview                = errors.New("reviewer cannot review own identity verification")
	ErrReviewAssignment          = errors.New("identity verification reviewer is not assigned")
	ErrExpired                   = errors.New("identity verification case has expired")
	ErrNotExpired                = errors.New("identity verification case is not expired")
	ErrEvidenceSettlementPending = errors.New("identity verification evidence settlement is not settled")
	ErrSettlementClaimLost       = errors.New("identity verification evidence settlement claim lost")
	ErrCommitOutcomeUnknown      = errors.New("identity verification commit outcome is unknown")
	ErrUnavailable               = errors.New("identity verification unavailable")
)

const (
	KindPersonalInitial        = "personal_initial"
	KindPersonalReverification = "personal_reverification"
	KindEnterprise             = "enterprise"

	StatusDraft     = "draft"
	StatusSubmitted = "submitted"
	StatusReviewing = "reviewing"
	StatusApproved  = "approved"
	StatusRejected  = "rejected"
	StatusWithdrawn = "withdrawn"
	StatusExpired   = "expired"

	RelationshipLegalPerson              = "legal_person"
	RelationshipEmployee                 = "employee"
	RelationshipAuthorizedRepresentative = "authorized_representative"

	MaterialIdentityDocument = "identity_document"
	MaterialLivenessEvidence = "liveness_evidence"
	MaterialBusinessLicense  = "business_license"
	MaterialLegalIdentity    = "legal_person_identity"
	MaterialAgentIdentity    = "agent_identity"
	MaterialAuthorization    = "authorization_letter"
	MaterialSupplementary    = "supplementary"

	DecisionApprove = "approved"
	DecisionReject  = "rejected"

	ReasonEvidenceVerified     = "evidence_verified"
	ReasonIdentityMismatch     = "identity_mismatch"
	ReasonEvidenceIncomplete   = "evidence_incomplete"
	ReasonEvidenceUnreadable   = "evidence_unreadable"
	ReasonOrganizationMismatch = "organization_mismatch"
	ReasonAuthorizationInvalid = "authorization_invalid"
	ReasonSuspectedFraud       = "suspected_fraud"
)

const (
	CredentialKindSession = "session"

	operationCreateDraft = "identity_verification.create_draft"
	operationSubmit      = "identity_verification.submit"
	operationStartReview = "identity_verification.start_review"
	operationReview      = "identity_verification.review"
	operationWithdraw    = "identity_verification.withdraw"
	operationExpire      = "identity_verification.expire"

	permissionSelfManage        = "identity_verification.self.manage"
	permissionRead              = "identity_verification.read"
	permissionReview            = "identity_verification.review"
	permissionSettlementRequeue = "identity_verification.evidence_settlement.requeue"
)

type Clock func() time.Time
type IDGenerator func() (uuid.UUID, error)

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Actor struct {
	UserID     uuid.UUID
	ScopeID    uuid.UUID
	ScopeKind  string
	session    sessionReference
	rawSession string
	// reviewTargetScopeID is the tenant scope a platform administrator reviews
	// (平台管理员也能代审). Nil for tenant sessions.
	reviewTargetScopeID uuid.UUID
}

type sessionReference struct {
	userID    uuid.UUID
	scopeID   uuid.UUID
	sessionID uuid.UUID
	scopeKind string
}

func NewSessionActor(userID, scopeID uuid.UUID, scopeKind string, sessionID uuid.UUID,
	rawSession string,
) (Actor, error) {
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: scopeKind,
		session: sessionReference{userID: userID, scopeID: scopeID, sessionID: sessionID,
			scopeKind: scopeKind}, rawSession: rawSession}
	if !validActor(actor) {
		return Actor{}, ErrInvalidInput
	}
	return actor, nil
}

// NewPlatformReviewActor is a platform session acting as reviewer on one tenant
// scope. It is valid only for the reviewer operations (list/get/claim/decide);
// applicant operations still require a tenant session.
func NewPlatformReviewActor(userID, platformScopeID, sessionID uuid.UUID, rawSession string,
	tenantScopeID uuid.UUID,
) (Actor, error) {
	actor := Actor{UserID: userID, ScopeID: platformScopeID, ScopeKind: "platform",
		session: sessionReference{userID: userID, scopeID: platformScopeID, sessionID: sessionID,
			scopeKind: "platform"}, rawSession: rawSession, reviewTargetScopeID: tenantScopeID}
	if !validActor(actor) {
		return Actor{}, ErrInvalidInput
	}
	return actor, nil
}

// PlatformAdmin is a platform session listing every tenant's cases
// (fix-decide1027b item 3: the admin console's identity review entry). It
// only lists; reviewing one case still goes through NewPlatformReviewActor.
type PlatformAdmin struct {
	UserID     uuid.UUID
	ScopeID    uuid.UUID
	sessionID  uuid.UUID
	rawSession string
}

func NewPlatformAdmin(userID, platformScopeID, sessionID uuid.UUID, rawSession string) (PlatformAdmin, error) {
	admin := PlatformAdmin{UserID: userID, ScopeID: platformScopeID, sessionID: sessionID, rawSession: rawSession}
	if !admin.Valid() {
		return PlatformAdmin{}, ErrInvalidInput
	}
	return admin, nil
}

func (admin PlatformAdmin) Valid() bool {
	return admin.UserID != uuid.Nil && admin.ScopeID != uuid.Nil && admin.sessionID != uuid.Nil &&
		admin.rawSession != "" && len(admin.rawSession) <= 8192 && !strings.ContainsAny(admin.rawSession, " \t\r\n")
}

func (PlatformAdmin) String() string   { return "identityverification.PlatformAdmin{session:redacted}" }
func (PlatformAdmin) GoString() string { return "identityverification.PlatformAdmin{session:redacted}" }

func (PlatformAdmin) MarshalJSON() ([]byte, error) {
	return nil, errors.New("identity verification platform admin serialization forbidden")
}

func (actor Actor) SessionID() uuid.UUID { return actor.session.sessionID }
func (actor Actor) Valid() bool          { return validActor(actor) }

// TenantScopeID is the tenant scope the actor works on: the session scope for a
// tenant session, the review target for a platform administrator.
func (actor Actor) TenantScopeID() uuid.UUID {
	if actor.ScopeKind == "platform" {
		return actor.reviewTargetScopeID
	}
	return actor.ScopeID
}

// PlatformReviewer reports a platform session reviewing a tenant's cases.
func (actor Actor) PlatformReviewer() bool { return actor.ScopeKind == "platform" }

func (Actor) String() string   { return "identityverification.Actor{session:redacted}" }
func (Actor) GoString() string { return "identityverification.Actor{session:redacted}" }

func (Actor) MarshalJSON() ([]byte, error) {
	return nil, errors.New("identity verification actor serialization forbidden")
}

func (actor Actor) hasSessionBinding() bool {
	target := actor.ScopeKind == "tenant" && actor.reviewTargetScopeID == uuid.Nil ||
		actor.ScopeKind == "platform" && actor.reviewTargetScopeID != uuid.Nil &&
			actor.reviewTargetScopeID != actor.ScopeID
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && target &&
		actor.session.userID == actor.UserID && actor.session.scopeID == actor.ScopeID &&
		actor.session.scopeKind == actor.ScopeKind && actor.session.sessionID != uuid.Nil &&
		actor.rawSession != "" && len(actor.rawSession) <= 8192 &&
		!strings.ContainsAny(actor.rawSession, " \t\r\n")
}

// TxAuthorizer owns the IAM lock protocol for identity-verification writes.
type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, ...string) error
}

type MaterialInput struct {
	Kind              string
	EnvelopeProvider  string
	EnvelopeKeyID     string
	EncryptedEnvelope []byte
	ObjectReference   string
	ObjectSHA256      []byte
	MIMEType          string
	SizeBytes         int64
}

type Material struct {
	ID                       uuid.UUID `json:"id"`
	Kind                     string    `json:"kind"`
	EnvelopeProvider         string    `json:"envelope_provider"`
	EnvelopeKeyID            string    `json:"envelope_key_id"`
	EncryptedEnvelopePresent bool      `json:"encrypted_envelope_present"`
	EnvelopeSHA256Hint       string    `json:"envelope_sha256_hint"`
	ObjectReference          string    `json:"object_reference"`
	ObjectSHA256Hint         string    `json:"object_sha256_hint"`
	MIMEType                 string    `json:"mime_type"`
	SizeBytes                int64     `json:"size_bytes"`
	CreatedAt                time.Time `json:"created_at"`
}

type Retention struct {
	Eligible   bool      `json:"eligible"`
	EligibleAt time.Time `json:"eligible_at"`
	ReasonCode string    `json:"reason_code"`
}

type Case struct {
	ID                     uuid.UUID  `json:"id"`
	TenantScopeID          uuid.UUID  `json:"tenant_scope_id"`
	ApplicantUserID        uuid.UUID  `json:"applicant_user_id"`
	Kind                   string     `json:"kind"`
	Status                 string     `json:"status"`
	DecisionReasonCode     string     `json:"decision_reason_code,omitempty"`
	SubjectFingerprintHint string     `json:"subject_fingerprint_hint"`
	OrganizationName       string     `json:"organization_name,omitempty"`
	LegalFingerprintHint   string     `json:"legal_person_fingerprint_hint,omitempty"`
	AgentFingerprintHint   string     `json:"agent_fingerprint_hint,omitempty"`
	AgentRelationship      string     `json:"agent_relationship,omitempty"`
	ReviewerUserID         *uuid.UUID `json:"reviewer_user_id,omitempty"`
	Revision               int64      `json:"revision"`
	CreatedAt              time.Time  `json:"created_at"`
	StateChangedAt         time.Time  `json:"state_changed_at"`
	SubmittedAt            *time.Time `json:"submitted_at,omitempty"`
	ExpiresAt              *time.Time `json:"expires_at,omitempty"`
	TerminalAt             *time.Time `json:"terminal_at,omitempty"`
	Retention              Retention  `json:"retention"`
	Materials              []Material `json:"materials"`
	Replayed               bool       `json:"-"`
}

func validCaseDecisionReason(status, reason string) bool {
	switch status {
	case StatusApproved:
		return reason == ReasonEvidenceVerified
	case StatusRejected:
		switch reason {
		case ReasonIdentityMismatch, ReasonEvidenceIncomplete, ReasonEvidenceUnreadable,
			ReasonOrganizationMismatch, ReasonAuthorizationInvalid, ReasonSuspectedFraud:
			return true
		default:
			return false
		}
	default:
		return reason == ""
	}
}

type CreateDraftRequest struct {
	Kind                   string
	SubjectFingerprint     []byte
	OrganizationName       string
	LegalPersonFingerprint []byte
	AgentFingerprint       []byte
	AgentRelationship      string
	Materials              []MaterialInput
	ResolverName           string
	ResolverReference      string
	EvidenceClaimDigest    [32]byte
	IdempotencyKey         string
	RequestID              string
}

type CreateDraftOutcome struct {
	Case                Case
	TransactionStarted  bool
	AuthorizationPassed bool
	SettlementBound     bool
}

type EvidenceSettlement struct {
	ID            uuid.UUID
	TenantScopeID uuid.UUID
	CaseID        uuid.UUID
	State         string
	Revision      int64
	AttemptCount  int
	AvailableAt   time.Time
	UpdatedAt     time.Time
}

type RequeueSettlementRequest struct {
	SettlementID     uuid.UUID
	ExpectedRevision int64
	ReasonCode       string
	RequestID        string
}

type MutationRequest struct {
	CaseID           uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type ReviewRequest struct {
	CaseID           uuid.UUID
	ExpectedRevision int64
	Decision         string
	ReasonCode       string
	IdempotencyKey   string
	RequestID        string
}

type Config struct {
	Clock           Clock
	NewID           IDGenerator
	ReviewTTL       time.Duration
	RetentionPeriod time.Duration
}

var _ json.Marshaler = Actor{}
