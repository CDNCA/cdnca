package rbacmanagerhttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
)

var (
	ErrInvalidRequest       = errors.New("invalid custom RBAC HTTP request")
	ErrUnauthenticated      = errors.New("custom RBAC authentication required")
	ErrPermissionDenied     = errors.New("custom RBAC HTTP permission denied")
	ErrNotFound             = errors.New("custom RBAC HTTP resource not found")
	ErrStoreUnavailable     = errors.New("custom RBAC HTTP store unavailable")
	ErrInvalidStoreResponse = errors.New("custom RBAC HTTP store returned invalid facts")
	ErrResponseTooLarge     = errors.New("custom RBAC HTTP response too large")
	ErrStepUpUnavailable    = errors.New("custom RBAC step-up verifier is unavailable")
)

const ManagePermission = rbacmanager.ManagePermission

type AuthenticatedSession struct {
	UserID         uuid.UUID
	ScopeID        uuid.UUID
	SessionID      uuid.UUID
	ScopeKind      string
	IdentityDomain string
}

type AuthenticateFunc func(*http.Request) (AuthenticatedSession, error)

type Commands interface {
	CreateRole(context.Context, rbacmanager.Actor, rbacmanager.CreateRoleRequest) (rbacmanager.Role, error)
	RenameRole(context.Context, rbacmanager.Actor, rbacmanager.RenameRoleRequest) (rbacmanager.Role, error)
	PublishRevision(context.Context, rbacmanager.Actor, rbacmanager.PublishRevisionRequest) (rbacmanager.Role, error)
	DeactivateRole(context.Context, rbacmanager.Actor, rbacmanager.DeactivateRoleRequest) (rbacmanager.Role, error)
	AssignRole(context.Context, rbacmanager.Actor, rbacmanager.AssignRoleRequest) (rbacmanager.Grant, error)
	RevokeGrant(context.Context, rbacmanager.Actor, rbacmanager.RevokeGrantRequest) (rbacmanager.Revocation, error)
}

type ReadStore interface {
	ListRoles(context.Context, rbacmanager.Actor, RolePageQuery) (RolePageFacts, error)
	GetRole(context.Context, rbacmanager.Actor, uuid.UUID) (RoleView, error)
	PermissionCatalog(context.Context, rbacmanager.Actor) ([]PermissionView, error)
	ListGrants(context.Context, rbacmanager.Actor, GrantPageQuery) (GrantPageFacts, error)
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
	TraceID        string
	StepUpToken    string
}

type PageInput struct {
	Limit  int
	Cursor string
}

type RoleListInput struct {
	PageInput
	IncludeDeactivated bool
}

type GrantListInput struct {
	PageInput
	RoleID        *uuid.UUID
	SubjectUserID *uuid.UUID
	State         string
}

type RolePageQuery struct {
	Limit              int
	IncludeDeactivated bool
	SnapshotVersion    *int64
	AfterVersion       *int64
	AfterID            *uuid.UUID
}

type GrantPageQuery struct {
	Limit           int
	RoleID          *uuid.UUID
	SubjectUserID   *uuid.UUID
	State           string
	SnapshotVersion *int64
	AfterVersion    *int64
	AfterID         *uuid.UUID
}

type RolePageFacts struct {
	Items           []RoleView
	SnapshotVersion *int64
}

type GrantPageFacts struct {
	Items           []GrantView
	SnapshotVersion *int64
}

type RoleView struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	CurrentRevision int64      `json:"current_revision"`
	Permissions     []string   `json:"permissions"`
	DeactivatedAt   *time.Time `json:"deactivated_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Replayed        bool       `json:"replayed,omitempty"`
	StateVersion    int64      `json:"-"`
}

type PermissionView struct {
	Name           string `json:"name"`
	StepUpRequired bool   `json:"step_up_required"`
}

type GrantView struct {
	ID              uuid.UUID  `json:"id"`
	RoleID          uuid.UUID  `json:"role_id"`
	RoleRevision    int64      `json:"role_revision"`
	SubjectUserID   uuid.UUID  `json:"subject_user_id"`
	GrantedByUserID uuid.UUID  `json:"granted_by_user_id"`
	GrantedAt       time.Time  `json:"granted_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	Replayed        bool       `json:"replayed,omitempty"`
	StateVersion    int64      `json:"-"`
}

type RevocationView struct {
	ID              uuid.UUID `json:"id"`
	GrantID         uuid.UUID `json:"grant_id"`
	RevokedByUserID uuid.UUID `json:"revoked_by_user_id"`
	RevokedAt       time.Time `json:"revoked_at"`
	Replayed        bool      `json:"replayed,omitempty"`
}

type PageMeta struct {
	NextCursor string `json:"next_cursor,omitempty"`
}

type RolePageView struct {
	Data []RoleView `json:"data"`
	Page PageMeta   `json:"page"`
}

type GrantPageView struct {
	Data []GrantView `json:"data"`
	Page PageMeta    `json:"page"`
}
