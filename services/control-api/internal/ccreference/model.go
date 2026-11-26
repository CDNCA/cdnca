package ccreference

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

type Kind string

const (
	KindMatcher Kind = "matcher"
	KindFilter  Kind = "filter"
)

var (
	ErrInvalidInput        = errors.New("invalid CC reference input")
	ErrPermissionDenied    = errors.New("CC reference permission denied")
	ErrNotFound            = errors.New("CC reference not found")
	ErrConflict            = errors.New("CC reference conflict")
	ErrRevisionConflict    = errors.New("CC reference revision conflict")
	ErrIdempotencyConflict = errors.New("CC reference idempotency conflict")
	ErrSystemRuleManaged   = errors.New("system CC reference is managed by the platform")
	// ErrInUse: a live CC policy's rules use the matcher / filter; it cannot
	// be deleted or disabled (InUseError names the policies).
	ErrInUse = errors.New("CC reference is used by a CC policy")
)

// InUseError names the CC policies (规则组) using a matcher / filter.
type InUseError struct {
	Policies []securitypolicy.CCReferenceUser
}

func (e *InUseError) Error() string { return ErrInUse.Error() }

func (e *InUseError) Unwrap() error { return ErrInUse }

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type OwnerReference struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
}

type MatcherFields struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Field       string   `json:"field"`
	Operator    string   `json:"operator"`
	Key         string   `json:"key,omitempty"`
	Values      []string `json:"values"`
}

type FilterFields struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Type        string          `json:"type"`
	Parameters  json.RawMessage `json:"parameters"`
}

type Item struct {
	ID            uuid.UUID       `json:"id"`
	ScopeID       uuid.UUID       `json:"scope_id"`
	Owner         *OwnerReference `json:"owner,omitempty"`
	Kind          Kind            `json:"kind"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Enabled       bool            `json:"enabled"`
	Revision      int64           `json:"version"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	SystemRule    bool            `json:"system_rule"`
	SystemRuleID  string          `json:"-"`
	SystemRuleKey string          `json:"-"`
	Sort          int             `json:"sort,omitempty"`
	PolicyID      uuid.UUID       `json:"policy_id,omitempty"`
	RuleID        uuid.UUID       `json:"rule_id,omitempty"`
	Field         string          `json:"field,omitempty"`
	Operator      string          `json:"operator,omitempty"`
	Key           string          `json:"key,omitempty"`
	Values        []string        `json:"values,omitempty"`
	Type          string          `json:"type,omitempty"`
	Parameters    json.RawMessage `json:"parameters,omitempty"`
}

type ListFilter struct {
	Page   int
	Limit  int
	Status string
	Name   string
	ID     uuid.UUID
	Owner  string
	Type   string
	// ScopeID (optional): only rows of this tenant scope (a CC policy
	// editor offers those of the policy's scope).
	ScopeID uuid.UUID
}

type ListResult struct {
	Items []Item `json:"items"`
	Total int64  `json:"total"`
	Page  int    `json:"page"`
	Limit int    `json:"limit"`
}

type CreateRequest struct {
	Kind           Kind
	TargetScopeID  uuid.UUID
	OwnerUserID    uuid.UUID
	Matcher        MatcherFields
	Filter         FilterFields
	IdempotencyKey string
	RequestID      string
}

type UpdateRequest struct {
	Kind             Kind
	ID               uuid.UUID
	ExpectedRevision int64
	Matcher          MatcherFields
	Filter           FilterFields
	IdempotencyKey   string
	RequestID        string
	SystemStateOnly  bool
}

type DeleteRequest struct {
	Kind             Kind
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type WriteResult struct {
	Item     Item
	Replayed bool
}

type DeleteResult struct {
	ID       uuid.UUID `json:"id"`
	Deleted  bool      `json:"deleted"`
	Revision int64     `json:"version"`
	Replayed bool      `json:"-"`
}
