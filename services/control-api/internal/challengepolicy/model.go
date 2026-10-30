package challengepolicy

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	PermissionRead   = "challenge_policies.read"
	PermissionManage = "challenge_policies.manage"

	ModeDelay    = "delay"
	ModeClick    = "click"
	ModeSlider   = "slider"
	ModeCaptcha  = "captcha"
	ModeExternal = "external"

	ProviderTencent  = "tencent"
	ProviderGeetest4 = "geetest-v4"

	IPBindingNone  = "none"
	IPBindingExact = "exact"

	CredentialKindSession = "session"
	CredentialKindAPIKey  = "api_key"

	BypassExact  = "exact"
	BypassPrefix = "prefix"
)

var (
	ErrUnauthenticated        = errors.New("challenge policy authentication required")
	ErrInvalidInput           = errors.New("invalid challenge policy input")
	ErrValidation             = errors.New("challenge policy validation failed")
	ErrPermissionDenied       = errors.New("challenge policy permission denied")
	ErrNotFound               = errors.New("challenge policy not found")
	ErrConflict               = errors.New("challenge policy conflict")
	ErrSiteLocked             = errors.New("site is locked by a platform administrator")
	ErrRevisionConflict       = errors.New("challenge policy revision conflict")
	ErrIdempotencyConflict    = errors.New("challenge policy idempotency conflict")
	ErrEntitlementDenied      = errors.New("challenge policy entitlement denied")
	ErrEntitlementUnavailable = errors.New("challenge policy entitlement unavailable")
	ErrUnavailable            = errors.New("challenge policy storage unavailable")
	ErrInvalidCursorConfig    = errors.New("invalid challenge policy cursor configuration")
	ErrInvalidStoreConfig     = errors.New("invalid challenge policy store configuration")
)

type CredentialReference struct {
	Kind string
	ID   uuid.UUID
}

type Actor struct {
	UserID        uuid.UUID
	ScopeID       uuid.UUID
	ScopeKind     string
	Permissions   []string
	Credential    CredentialReference
	rawCredential string
	tenantID      *uuid.UUID
}

type BypassRoute struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type ExternalProviderReference struct {
	Provider     string `json:"provider"`
	AppReference string `json:"app_reference"`
}

type Config struct {
	Priority             int                        `json:"priority"`
	Mode                 string                     `json:"mode"`
	MinDelaySeconds      int                        `json:"min_delay_seconds"`
	ChallengeTTLSeconds  int                        `json:"challenge_ttl_seconds"`
	PassTTLSeconds       int                        `json:"pass_ttl_seconds"`
	ClockSkewSeconds     int                        `json:"clock_skew_seconds"`
	AttemptsPerNonce     int                        `json:"attempts_per_nonce"`
	FailureWindowSeconds int                        `json:"failure_window_seconds"`
	MaxFailuresPerWindow int                        `json:"max_failures_per_window"`
	IPBinding            string                     `json:"ip_binding"`
	BindUserAgent        bool                       `json:"bind_user_agent"`
	BypassRoutes         []BypassRoute              `json:"bypass_routes"`
	KeyReference         string                     `json:"key_reference"`
	ExternalProvider     *ExternalProviderReference `json:"external_provider"`
}

type Policy struct {
	ID                         uuid.UUID     `json:"id"`
	TenantScopeID              uuid.UUID     `json:"tenant_scope_id"`
	SiteID                     uuid.UUID     `json:"site_id"`
	Host                       string        `json:"host"`
	Priority                   int           `json:"priority"`
	Mode                       string        `json:"mode"`
	MinDelaySeconds            int           `json:"min_delay_seconds"`
	ChallengeTTLSeconds        int           `json:"challenge_ttl_seconds"`
	PassTTLSeconds             int           `json:"pass_ttl_seconds"`
	ClockSkewSeconds           int           `json:"clock_skew_seconds"`
	AttemptsPerNonce           int           `json:"attempts_per_nonce"`
	FailureWindowSeconds       int           `json:"failure_window_seconds"`
	MaxFailuresPerWindow       int           `json:"max_failures_per_window"`
	IPBinding                  string        `json:"ip_binding"`
	BindUserAgent              bool          `json:"bind_user_agent"`
	BypassRoutes               []BypassRoute `json:"bypass_routes"`
	KeyReferenceConfigured     bool          `json:"key_reference_configured"`
	ExternalProviderConfigured bool          `json:"external_provider_configured"`
	Enabled                    bool          `json:"enabled"`
	Deleted                    bool          `json:"deleted"`
	Revision                   int64         `json:"revision"`
	CreatedAt                  time.Time     `json:"created_at"`
	UpdatedAt                  time.Time     `json:"updated_at"`
}

type storedPolicy struct {
	Policy
	TenantID        uuid.UUID
	KeyReference    string
	External        *ExternalProviderReference
	CreatedByUserID uuid.UUID
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
	TraceID        string
}

type CreateRequest struct {
	TargetScopeID uuid.UUID
	SiteID        uuid.UUID
	Host          string
	Enabled       bool
	Config        Config
	WriteMetadata
}

type UpdateRequest struct {
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	Config           Config
	WriteMetadata
}

type StateRequest struct {
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	Enabled          bool
	WriteMetadata
}

type DeleteRequest struct {
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type ListFilter struct {
	TargetScopeID uuid.UUID
	Limit         int
	Cursor        string
	SiteID        uuid.UUID
	Host          string
	Enabled       *bool
}

type ListResult struct {
	Items      []Policy `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type WriteResult struct {
	Policy   Policy
	Replayed bool
}

type entitlementCheck struct {
	AuditScopeID uuid.UUID
	ActorUserID  uuid.UUID
	ResourceID   uuid.UUID
	RequestID    string
	Operation    string
}

type entitlementGate interface {
	Check(context.Context, pgx.Tx, entitlementCheck) error
}

// TxAuthorizer owns the IAM lock protocol and returns the locked target tenant.
// Implementations must recheck the server-authenticated credential, principal,
// membership, account, and permission facts in the caller-owned transaction.
type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) (uuid.UUID, error)
}
