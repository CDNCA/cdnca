package sitegroup

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	CredentialSession = "session"
	CredentialAPIKey  = "api_key"
)

var (
	ErrAuthenticationRequired = errors.New("site group authentication required")
	ErrPermissionDenied       = errors.New("site group permission denied")
	ErrInvalidInput           = errors.New("invalid site group request")
	ErrNotFound               = errors.New("site group not found")
	ErrNameConflict           = errors.New("site group name conflict")
	ErrRevisionConflict       = errors.New("site group revision conflict")
	ErrIdempotencyConflict    = errors.New("site group idempotency conflict")
	ErrInUse                  = errors.New("site group is in use")
	ErrInvalidReference       = errors.New("invalid site group reference")
	ErrResultUnknown          = errors.New("site group write result unknown")
	ErrUnavailable            = errors.New("site group service unavailable")
)

type Credential struct {
	Kind string
	Raw  string
}

type Actor struct {
	Credential Credential
}

type Group struct {
	ID        uuid.UUID  `json:"id"`
	ScopeID   uuid.UUID  `json:"scope_id"`
	Name      string     `json:"name"`
	Remark    string     `json:"remark"`
	DisplayID string     `json:"display_id,omitempty"`
	Revision  int64      `json:"revision"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
}

type CreateRequest struct {
	TargetScopeID uuid.UUID
	Name          string
	Remark        *string
	WriteMetadata
}

type RenameRequest struct {
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	Name             string
	Remark           *string
	WriteMetadata
}

type DeleteRequest struct {
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type ListRequest struct {
	TargetScopeID uuid.UUID
	Page          int
	Limit         int
}

type GroupList struct {
	Items []Group `json:"items"`
	Total int64   `json:"total"`
	Page  int     `json:"page"`
	Limit int     `json:"limit"`
}

type WriteResult struct {
	Group    Group           `json:"group"`
	Replayed bool            `json:"-"`
	Response json.RawMessage `json:"-"`
}

type GroupUser struct {
	ID        uuid.UUID `json:"id"`
	DisplayID string    `json:"display_id"`
	Username  string    `json:"username"`
}

type AdminGroup struct {
	Group
	User      *GroupUser `json:"user"`
	UserState string     `json:"user_state"`
}

type AdminGroupList struct {
	Items []AdminGroup `json:"items"`
	Total int64        `json:"total"`
	Page  int          `json:"page"`
	Limit int          `json:"limit"`
}
