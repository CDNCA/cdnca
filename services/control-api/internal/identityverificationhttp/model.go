package identityverificationhttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

var (
	ErrInvalidService                  = errors.New("invalid identity verification HTTP service")
	ErrInvalidRequest                  = errors.New("invalid identity verification HTTP request")
	ErrUnauthenticated                 = errors.New("identity verification authentication required")
	ErrPermissionDenied                = errors.New("identity verification HTTP permission denied")
	ErrNotFound                        = errors.New("identity verification HTTP resource not found")
	ErrStoreUnavailable                = errors.New("identity verification HTTP store unavailable")
	ErrInvalidStoreResponse            = errors.New("identity verification HTTP store returned invalid facts")
	ErrResponseTooLarge                = errors.New("identity verification HTTP response too large")
	ErrTrustedEvidenceResolverRequired = errors.New("trusted evidence resolver is required")
	ErrInvalidEvidence                 = errors.New("trusted identity evidence is invalid")
	ErrEvidenceReservationConflict     = errors.New("trusted evidence reservation conflicts with idempotency key")
	ErrEvidenceUnavailable             = errors.New("trusted identity evidence resolver unavailable")
)

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

func actorFromSession(session identity.AuthenticatedSession, rawSession string) (identityverification.Actor, bool) {
	actor, err := identityverification.NewSessionActor(session.Principal.UserID,
		session.Principal.ScopeID, session.Principal.ScopeKind, session.SessionID, rawSession)
	return actor, err == nil && validActor(actor)
}

type CoreService interface {
	AuthorizeCreateDraft(context.Context, identityverification.Actor) error
	CreateDraftWithSettlement(context.Context, identityverification.Actor, identityverification.CreateDraftRequest) (identityverification.CreateDraftOutcome, error)
	Submit(context.Context, identityverification.Actor, identityverification.MutationRequest) (identityverification.Case, error)
	StartReview(context.Context, identityverification.Actor, identityverification.MutationRequest) (identityverification.Case, error)
	Review(context.Context, identityverification.Actor, identityverification.ReviewRequest) (identityverification.Case, error)
	Withdraw(context.Context, identityverification.Actor, identityverification.MutationRequest) (identityverification.Case, error)
	Expire(context.Context, identityverification.Actor, identityverification.MutationRequest) (identityverification.Case, error)
	Get(context.Context, identityverification.Actor, uuid.UUID) (identityverification.Case, error)
	GetForReview(context.Context, identityverification.Actor, uuid.UUID) (identityverification.Case, error)
	CurrentStatus(context.Context, identityverification.Actor) (identityverification.SelfStatus, error)
}

// TrustedEvidenceResolver binds an opaque upload/KYC handle to one authenticated
// create request before exposing verified evidence to the core service.
type TrustedEvidenceResolver interface {
	Reserve(context.Context, identityverification.Actor, EvidenceReference, string, [32]byte) (EvidenceReservation, error)
	Abort(context.Context, string) error
	Quarantine(context.Context, string) error
}

type ReviewReadStore interface {
	ListCases(context.Context, identityverification.Actor, CasePageQuery) ([]CaseSummary, error)
	ListAdminCases(context.Context, identityverification.PlatformAdmin, CasePageQuery) ([]AdminCaseSummary, error)
}

type EvidenceReference struct {
	Kind  string
	Token string
}

type EvidenceReservation struct {
	ID                  string
	ResolverName        string
	ResolverReference   string
	EvidenceClaimDigest [32]byte
	Evidence            ResolvedEvidence
}

type ResolvedEvidence struct {
	Kind                   string
	SubjectFingerprint     []byte
	OrganizationName       string
	LegalPersonFingerprint []byte
	AgentFingerprint       []byte
	AgentRelationship      string
	Materials              []identityverification.MaterialInput
}

type CreateDraftInput struct {
	Kind          string
	EvidenceToken string
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
}

type MutationInput struct {
	CaseID           uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type DecisionInput struct {
	CaseID           uuid.UUID
	ExpectedRevision int64
	Decision         string
	ReasonCode       string
	WriteMetadata
}

type PageInput struct {
	Limit  int
	Cursor string
	Kind   string
	Status string
}

type CasePageQuery struct {
	Limit          int
	Kind           string
	Status         string
	AfterCreatedAt *time.Time
	AfterID        *uuid.UUID
}

type CaseSummary struct {
	ID              uuid.UUID  `json:"id"`
	ApplicantUserID uuid.UUID  `json:"applicant_user_id"`
	Kind            string     `json:"kind"`
	Status          string     `json:"status"`
	ReviewerUserID  *uuid.UUID `json:"reviewer_user_id,omitempty"`
	Revision        int64      `json:"revision"`
	CreatedAt       time.Time  `json:"created_at"`
	StateChangedAt  time.Time  `json:"state_changed_at"`
	SubmittedAt     *time.Time `json:"submitted_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

// AdminCaseSummary is one row of the platform administrator's cross-tenant
// list: the case summary plus whose tenant and applicant it is.
type AdminCaseSummary struct {
	CaseSummary
	TenantScopeID     uuid.UUID `json:"tenant_scope_id"`
	TenantName        string    `json:"tenant_name"`
	ApplicantUsername string    `json:"applicant_username"`
}

type AdminPageView struct {
	Items      []AdminCaseSummary `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type MaterialView struct {
	ID                       uuid.UUID `json:"id"`
	Kind                     string    `json:"kind"`
	EncryptedEnvelopePresent bool      `json:"encrypted_envelope_present"`
	MIMEType                 string    `json:"mime_type"`
	SizeBytes                int64     `json:"size_bytes"`
	CreatedAt                time.Time `json:"created_at"`
}

type RetentionView struct {
	Eligible   bool      `json:"eligible"`
	EligibleAt time.Time `json:"eligible_at"`
	ReasonCode string    `json:"reason_code"`
}

type CaseView struct {
	ID                 uuid.UUID      `json:"id"`
	ApplicantUserID    uuid.UUID      `json:"applicant_user_id"`
	Kind               string         `json:"kind"`
	Status             string         `json:"status"`
	DecisionReasonCode string         `json:"decision_reason_code,omitempty"`
	AgentRelationship  string         `json:"agent_relationship,omitempty"`
	ReviewerUserID     *uuid.UUID     `json:"reviewer_user_id,omitempty"`
	Revision           int64          `json:"revision"`
	CreatedAt          time.Time      `json:"created_at"`
	StateChangedAt     time.Time      `json:"state_changed_at"`
	SubmittedAt        *time.Time     `json:"submitted_at,omitempty"`
	ExpiresAt          *time.Time     `json:"expires_at,omitempty"`
	TerminalAt         *time.Time     `json:"terminal_at,omitempty"`
	Retention          RetentionView  `json:"retention"`
	Materials          []MaterialView `json:"materials"`
	Replayed           bool           `json:"replayed"`
}

// Self status values derived for the applicant's own profile badge.
const (
	SelfStatusUnverified = "unverified"
	SelfStatusPending    = "pending"
	SelfStatusVerified   = "verified"
	SelfStatusRejected   = "rejected"
)

// StatusView is the applicant's own verification standing. It deliberately
// omits fingerprints, document facts, materials and reviewer identity.
type StatusView struct {
	Status     string          `json:"status"`
	VerifiedAt *time.Time      `json:"verified_at,omitempty"`
	LatestCase *StatusCaseView `json:"latest_case,omitempty"`
}

type StatusCaseView struct {
	ID                 uuid.UUID  `json:"id"`
	Kind               string     `json:"kind"`
	Status             string     `json:"status"`
	DecisionReasonCode string     `json:"decision_reason_code,omitempty"`
	Revision           int64      `json:"revision"`
	CreatedAt          time.Time  `json:"created_at"`
	StateChangedAt     time.Time  `json:"state_changed_at"`
	SubmittedAt        *time.Time `json:"submitted_at,omitempty"`
}

type PageView struct {
	Items      []CaseSummary `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}
