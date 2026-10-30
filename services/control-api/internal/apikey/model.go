package apikey

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid API key input")
	ErrPermissionDenied    = errors.New("API key permission denied")
	ErrNotFound            = errors.New("API key not found")
	ErrRevisionConflict    = errors.New("API key revision conflict")
	ErrIdempotencyConflict = errors.New("API key idempotency conflict")
	ErrInvalidCredential   = errors.New("invalid API key credential")
	ErrInvalidTransition   = errors.New("invalid API key transition")
	ErrDisabled            = errors.New("API key service is disabled by platform policy")
	ErrUnavailable         = errors.New("API key service unavailable")
)

const (
	StatusPendingActivation = "pending_activation"
	StatusActive            = "active"
	StatusRevoked           = "revoked"
)

type Key struct {
	ID               uuid.UUID  `json:"id"`
	KeyID            string     `json:"key_id"`
	KeyPrefix        string     `json:"key_prefix"`
	ScopeID          uuid.UUID  `json:"scope_id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	UserID           uuid.UUID  `json:"user_id"`
	Name             string     `json:"name"`
	Scopes           []string   `json:"scopes"`
	IPAllowlist      []string   `json:"ip_allowlist"`
	Status           string     `json:"status"`
	PendingExpiresAt *time.Time `json:"pending_expires_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	ActivatedAt      *time.Time `json:"activated_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	Revision         int64      `json:"revision"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type IssuedKey struct {
	Key    Key    `json:"key"`
	Secret string `json:"secret"`
}

type APIKeyListInput struct {
	Limit  int
	Status string
	Name   string
	KeyID  string
	Cursor string
	// Offset pages by position (tp-b7b 页码分页); it cannot be combined with
	// Cursor and is capped at MaxListOffset.
	Offset int
}

// MaxListOffset bounds page-number access to one user's API keys.
const MaxListOffset = 10000

// APIKeyListPage freezes membership by CreatedAt at SnapshotAt. Later inserts
// stay out of the traversal; committed status updates and removals remain live.
type APIKeyListPage struct {
	Items      []Key     `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
	SnapshotAt time.Time `json:"snapshot_at"`
	// Total counts the filtered keys at SnapshotAt. It is only set on the
	// first page and on offset pages; cursor continuation pages leave it nil.
	Total *int `json:"total,omitempty"`
}

func (issued IssuedKey) String() string {
	return fmt.Sprintf("IssuedKey{KeyID:%s, Secret:[REDACTED]}", issued.Key.KeyID)
}

func (issued IssuedKey) GoString() string {
	return fmt.Sprintf("apikey.IssuedKey{Key:%#v, Secret:[REDACTED]}", issued.Key)
}

type CreateInput struct {
	Name           string
	Scopes         []string
	IPAllowlist    []string
	ExpiresAt      *time.Time
	IdempotencyKey string
	RequestID      string
}

type UpdateInput struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Name             string
	Scopes           []string
	IPAllowlist      []string
	ExpiresAt        *time.Time
	IdempotencyKey   string
	RequestID        string
}

type MutationInput struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IPAllowlist      []string
	IdempotencyKey   string
	RequestID        string
	// GrantAllScopes 只用于轮换（简单版"重置密钥"）：secret 轮换的同时把权限刷新为当前账号可授予的全部。
	GrantAllScopes bool
}

type AdminCreateInput struct {
	TargetScopeID  uuid.UUID
	TargetUserID   uuid.UUID
	Name           string
	Scopes         []string
	IPAllowlist    []string
	ExpiresAt      *time.Time
	PendingTTL     time.Duration
	IdempotencyKey string
	RequestID      string
}

type AdminRevokeInput struct {
	TargetScopeID    uuid.UUID
	TargetUserID     uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	IPAllowlist      []string
	IdempotencyKey   string
	RequestID        string
}
