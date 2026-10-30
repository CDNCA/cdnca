package impersonation

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	ManagePermission = "identity.impersonation.manage"
	// ResellerPermission lets an active reseller's member switch to the
	// reseller's own customers (ADR 0018 RS-07, user decision 10-24 Q4,
	// migration 482).
	ResellerPermission = "reseller.customers.manage"
	// SwitchReason is recorded on every grant: the user list "switch" action is
	// the only entry point and takes no operator-typed reason or ticket.
	SwitchReason = "user_list_switch"

	SessionKindPrimary       = "primary"
	SessionKindImpersonation = "impersonation"

	CodeTTL    = 2 * time.Minute
	SessionTTL = 15 * time.Minute
)

var (
	ErrInvalidInput        = errors.New("invalid impersonation input")
	ErrInvalidStore        = errors.New("invalid impersonation store")
	ErrPermissionDenied    = errors.New("impersonation permission denied")
	ErrNested              = errors.New("nested impersonation is denied")
	ErrIdempotencyConflict = errors.New("impersonation idempotency conflict")
	ErrInvalidCode         = errors.New("invalid impersonation authorization code")
	ErrGrantExpired        = errors.New("impersonation grant expired")
	ErrGrantRevoked        = errors.New("impersonation grant revoked")
	ErrCodeReplay          = errors.New("impersonation authorization code replayed")
	ErrSessionExpired      = errors.New("impersonation session expired")
	ErrSessionRevoked      = errors.New("impersonation session revoked")
	ErrPrincipalChanged    = errors.New("impersonation principal changed")
	ErrSensitiveAction     = errors.New("sensitive action denied during impersonation")
)

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type RequestContext struct {
	RequestID string
	TraceID   string
}

// Actor is built from a verified customer-control session: a platform member
// or (RS-07) a reseller's tenant member. Platform license operators are a
// separate identity domain and must never be adapted to it.
type Actor struct {
	UserID               uuid.UUID
	ScopeID              uuid.UUID
	PrimaryAuthSessionID uuid.UUID
	ScopeKind            string
	SessionKind          string
	ImpersonationGrantID *uuid.UUID
}

type CreateRequest struct {
	TenantID       uuid.UUID
	TenantScopeID  uuid.UUID
	SubjectUserID  uuid.UUID
	IdempotencyKey string
	Context        RequestContext
}

type Grant struct {
	ID            uuid.UUID `json:"id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	ActorUserID   uuid.UUID `json:"actor_user_id"`
	ActorScopeID  uuid.UUID `json:"actor_scope_id"`
	SubjectUserID uuid.UUID `json:"subject_user_id"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type CreateResult struct {
	Grant             Grant  `json:"grant"`
	AuthorizationCode string `json:"authorization_code"`
	Replayed          bool   `json:"-"`
}

type ExchangeRequest struct {
	TenantID          uuid.UUID
	TenantScopeID     uuid.UUID
	AuthorizationCode string
	IdempotencyKey    string
	Context           RequestContext
}

type BannerClaims struct {
	GrantID            uuid.UUID `json:"grant_id"`
	ActorUserID        uuid.UUID `json:"actor_user_id"`
	ActorDisplayName   string    `json:"actor_display_name"`
	SubjectUserID      uuid.UUID `json:"subject_user_id"`
	SubjectDisplayName string    `json:"subject_display_name"`
	TenantID           uuid.UUID `json:"tenant_id"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type SubjectPrincipal struct {
	UserID      uuid.UUID `json:"user_id"`
	DisplayID   string    `json:"display_id"`
	ScopeID     uuid.UUID `json:"scope_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	ScopeKind   string    `json:"scope_kind"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
}

type Session struct {
	ID            uuid.UUID        `json:"id"`
	GrantID       uuid.UUID        `json:"grant_id"`
	ActorUserID   uuid.UUID        `json:"actor_user_id"`
	ActorScopeID  uuid.UUID        `json:"actor_scope_id"`
	SubjectUserID uuid.UUID        `json:"subject_user_id"`
	TenantID      uuid.UUID        `json:"tenant_id"`
	TenantScopeID uuid.UUID        `json:"tenant_scope_id"`
	CreatedAt     time.Time        `json:"created_at"`
	ExpiresAt     time.Time        `json:"expires_at"`
	Refreshable   bool             `json:"refreshable"`
	Banner        BannerClaims     `json:"banner"`
	Principal     SubjectPrincipal `json:"principal"`
	Replayed      bool             `json:"-"`
}

type UseRequest struct {
	Session Session
	Action  string
	Context RequestContext
}

type EffectiveIdentity struct {
	Session     Session
	Permissions []string
}

type RevokeRequest struct {
	GrantID        uuid.UUID
	TenantID       uuid.UUID
	TenantScopeID  uuid.UUID
	Reason         string
	IdempotencyKey string
	Context        RequestContext
}

type EndSessionRequest struct {
	Session Session
	Reason  string
	Context RequestContext
}

type Revocation struct {
	ID        uuid.UUID `json:"id"`
	GrantID   uuid.UUID `json:"grant_id"`
	RevokedBy uuid.UUID `json:"revoked_by"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
	Replayed  bool      `json:"-"`
}
