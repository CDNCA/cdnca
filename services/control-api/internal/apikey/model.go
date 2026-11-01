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
	// ErrPluginInstallationUnavailable: the plugin installation to bind is not an enabled installation of this tenant.
	ErrPluginInstallationUnavailable = errors.New("API key plugin installation is not enabled in this tenant")
)

const (
	StatusPendingActivation = "pending_activation"
	StatusActive            = "active"
	StatusRevoked           = "revoked"
)

type Key struct {
	ID        uuid.UUID `json:"id"`
	KeyID     string    `json:"key_id"`
	KeyPrefix string    `json:"key_prefix"`
	ScopeID   uuid.UUID `json:"scope_id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	UserID    uuid.UUID `json:"user_id"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	// UnavailableScopes 只在列表/详情读取时按持有人实时权限计算：scopes 中已被收回、调用时不再生效的部分。不落库。
	UnavailableScopes []string   `json:"unavailable_scopes,omitempty"`
	IPAllowlist       []string   `json:"ip_allowlist"`
	Status            string     `json:"status"`
	PendingExpiresAt  *time.Time `json:"pending_expires_at,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	ActivatedAt       *time.Time `json:"activated_at,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	Revision          int64      `json:"revision"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	// Plugin* 非空表示这把密钥是某个插件安装的插件身份（迁移 604，ADR 0007 §3.2）：
	// 创建时绑定、不可改；安装停用/卸载后鉴权即拒绝。
	PluginInstallationAuthorizationID *uuid.UUID `json:"plugin_installation_authorization_id,omitempty"`
	PluginInstallationID              *uuid.UUID `json:"plugin_installation_id,omitempty"`
	PluginID                          *string    `json:"plugin_id,omitempty"`
}

// PluginBinding is the plugin installation an authenticated API key acts for.
type PluginBinding struct {
	AuthorizationID uuid.UUID
	InstallationID  uuid.UUID
	PluginID        string
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
	// PluginInstallationAuthorizationID 可选：把密钥绑定为本租户某个已启用插件安装的插件身份。
	PluginInstallationAuthorizationID *uuid.UUID
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
