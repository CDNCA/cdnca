package rbacmanager

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	CustomerControlIdentityDomain  = "customer_control"
	PlatformOperatorIdentityDomain = "platform_operator"
	ManagePermission               = "identity.roles.manage"
	StepUpMaxAge                   = 5 * time.Minute
)

var (
	ErrInvalidInput         = errors.New("invalid custom RBAC input")
	ErrInvalidStore         = errors.New("invalid custom RBAC store")
	ErrPermissionDenied     = errors.New("custom RBAC permission denied")
	ErrPermissionNotAllowed = errors.New("permission is not tenant delegable")
	ErrPermissionEscalation = errors.New("permission grant exceeds actor permissions")
	ErrSystemRoleImmutable  = errors.New("system role is immutable")
	ErrTenantBoundary       = errors.New("custom RBAC tenant boundary violation")
	ErrSelfAssignment       = errors.New("self role assignment is denied")
	ErrStepUpRequired       = errors.New("recent strong step-up is required")
	ErrNotFound             = errors.New("custom role not found")
	ErrRoleInactive         = errors.New("custom role is inactive")
	ErrGrantRevoked         = errors.New("custom role grant is revoked")
	ErrRevisionConflict     = errors.New("custom role revision conflict")
	ErrIdempotencyConflict  = errors.New("custom RBAC idempotency conflict")
	ErrNameConflict         = errors.New("custom role name conflict")
)

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

// StepUpVerifier adapts the customer control plane's MFA proof validation.
// Callers must not construct proofs from unverified request fields.
type StepUpVerifier interface {
	VerifyAndConsume(context.Context, pgx.Tx, StepUpProof, StepUpCheck) (StepUpEvidence, error)
}

type Actor struct {
	UserID         uuid.UUID
	ScopeID        uuid.UUID
	SessionID      uuid.UUID
	ScopeKind      string
	IdentityDomain string
}

// AuthenticatedSessionReference contains only server-authenticated session facts.
// Domain packages can pass it alongside their own transaction without widening identity.Principal.
type AuthenticatedSessionReference struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
}

type StepUpProof struct {
	Token string
}

type StepUpCheck struct {
	Actor            Actor
	TenantID         uuid.UUID
	Audience         string
	Action           string
	RoleID           uuid.UUID
	GrantID          uuid.UUID
	SubjectUserID    uuid.UUID
	ExpectedRevision int64
	Permissions      []string
	MutationDigest   []byte
	RequestID        string
	TraceID          string
}

type StepUpEvidence struct {
	ProofID    uuid.UUID
	Method     string
	VerifiedAt time.Time
}

type MutationContext struct {
	IdempotencyKey string
	RequestID      string
	TraceID        string
	StepUp         StepUpProof
}

type Role struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	TenantScopeID   uuid.UUID  `json:"tenant_scope_id"`
	Name            string     `json:"name"`
	CurrentRevision int64      `json:"current_revision"`
	Permissions     []string   `json:"permissions"`
	DeactivatedAt   *time.Time `json:"deactivated_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Replayed        bool       `json:"-"`
}

type Grant struct {
	ID              uuid.UUID `json:"id"`
	TenantID        uuid.UUID `json:"tenant_id"`
	TenantScopeID   uuid.UUID `json:"tenant_scope_id"`
	RoleID          uuid.UUID `json:"role_id"`
	RoleRevision    int64     `json:"role_revision"`
	SubjectUserID   uuid.UUID `json:"subject_user_id"`
	GrantedByUserID uuid.UUID `json:"granted_by_user_id"`
	GrantedAt       time.Time `json:"granted_at"`
	Replayed        bool      `json:"-"`
}

type Revocation struct {
	ID              uuid.UUID `json:"id"`
	GrantID         uuid.UUID `json:"grant_id"`
	RevokedByUserID uuid.UUID `json:"revoked_by_user_id"`
	RevokedAt       time.Time `json:"revoked_at"`
	Replayed        bool      `json:"-"`
}

type CreateRoleRequest struct {
	Name        string
	Permissions []string
	Mutation    MutationContext
}

type RenameRoleRequest struct {
	RoleID           uuid.UUID
	ExpectedRevision int64
	Name             string
	Mutation         MutationContext
}

type PublishRevisionRequest struct {
	RoleID           uuid.UUID
	ExpectedRevision int64
	Permissions      []string
	Mutation         MutationContext
}

type DeactivateRoleRequest struct {
	RoleID           uuid.UUID
	ExpectedRevision int64
	Mutation         MutationContext
}

type AssignRoleRequest struct {
	RoleID               uuid.UUID
	ExpectedRoleRevision int64
	SubjectUserID        uuid.UUID
	Mutation             MutationContext
}

type RevokeGrantRequest struct {
	GrantID  uuid.UUID
	Mutation MutationContext
}
