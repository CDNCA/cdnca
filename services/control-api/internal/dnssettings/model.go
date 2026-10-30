package dnssettings

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid DNS settings request")
	ErrPermissionDenied    = errors.New("DNS settings permission denied")
	ErrNotFound            = errors.New("DNS settings resource not found")
	ErrRevisionConflict    = errors.New("DNS settings revision conflict")
	ErrIdempotencyConflict = errors.New("DNS settings idempotency conflict")
	ErrUnavailable         = errors.New("DNS settings service unavailable")
)

const (
	DefaultTTL = 600
	MinTTL     = 1
	MaxTTL     = 604800

	OperationRepair  = "repair"
	OperationCleanup = "cleanup"
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
	TenantID  uuid.UUID
}

func (actor Actor) valid() bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		actor.ScopeKind == "tenant" && actor.TenantID != uuid.Nil
}

func (actor Actor) validForRead() bool {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil {
		return false
	}
	return actor.valid() || (actor.ScopeKind == "platform" && actor.TenantID == uuid.Nil)
}

type Settings struct {
	ScopeID   uuid.UUID  `json:"scope_id"`
	TTL       int        `json:"ttl"`
	Revision  int64      `json:"version"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type UpdateRequest struct {
	TTL              int
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type OperationRequest struct {
	Kind           string
	IdempotencyKey string
	RequestID      string
	TraceID        string
}

type Operation struct {
	ID          uuid.UUID  `json:"id"`
	Kind        string     `json:"kind"`
	Subject     string     `json:"subject"`
	State       string     `json:"state"`
	Attempt     uint32     `json:"attempt"`
	MaxAttempts uint32     `json:"max_attempts"`
	Progress    Progress   `json:"progress"`
	LastError   string     `json:"last_error_code,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type Progress struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`
	Pending   int `json:"pending"`
}
