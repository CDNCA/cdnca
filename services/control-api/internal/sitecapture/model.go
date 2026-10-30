package sitecapture

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	PermissionRead   = "site_capture.read"
	PermissionManage = "site_capture.manage"
	AuditActionSet   = "site.capture_policy.set"
)

var (
	ErrInvalidConfig    = errors.New("invalid site capture service configuration")
	ErrInvalidInput     = errors.New("invalid site capture policy")
	ErrUnauthenticated  = errors.New("site capture authentication required")
	ErrPermissionDenied = errors.New("site capture permission denied")
	ErrNotFound         = errors.New("site capture policy not found")
	// ErrUnconfigured: the site exists and is readable but has never saved a
	// policy. Callers show DefaultDocument and create with expected_revision 0.
	ErrUnconfigured        = errors.New("site capture policy unconfigured")
	ErrRevisionConflict    = errors.New("site capture policy revision conflict")
	ErrIdempotencyConflict = errors.New("site capture idempotency conflict")
	ErrUnavailable         = errors.New("site capture repository unavailable")
)

type Actor struct {
	UserID      uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string
	SessionID   uuid.UUID
	Permissions []string
}

type PolicyDocument struct {
	Enabled                    bool     `json:"enabled"`
	Methods                    []string `json:"methods"`
	URIPrefixes                []string `json:"uri_prefixes"`
	RequestHeaderAllowlist     []string `json:"request_header_allowlist"`
	ResponseHeaderAllowlist    []string `json:"response_header_allowlist"`
	RequestBodyFieldAllowlist  []string `json:"request_body_field_allowlist"`
	ResponseBodyFieldAllowlist []string `json:"response_body_field_allowlist"`
	MaxValueBytes              int      `json:"max_value_bytes"`
	MaxBodyBytes               int      `json:"max_body_bytes"`
	MaxEventBytes              int      `json:"max_event_bytes"`
}

type Policy struct {
	ScopeID        uuid.UUID      `json:"scope_id"`
	SiteID         uuid.UUID      `json:"site_id"`
	Revision       int64          `json:"revision"`
	Document       PolicyDocument `json:"document"`
	EvidenceDigest string         `json:"evidence_digest"`
	UpdatedAt      time.Time      `json:"updated_at"`
	UpdatedBy      uuid.UUID      `json:"updated_by"`
	RequestID      string         `json:"request_id"`
}

type UpdateRequest struct {
	ScopeID          uuid.UUID
	SiteID           uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	TraceID          string
	Document         PolicyDocument
}

type AuditFact struct {
	Action           string
	ActorUserID      uuid.UUID
	ScopeID          uuid.UUID
	SiteID           uuid.UUID
	ExpectedRevision int64
	RequestID        string
	TraceID          string
	DocumentSHA256   [32]byte
}

type WriteResult struct {
	Policy   Policy `json:"policy"`
	Replayed bool   `json:"replayed"`
}

// Store must persist the policy CAS, idempotency result, and audit fact in one transaction.
type Store interface {
	Get(context.Context, Actor, uuid.UUID, uuid.UUID) (Policy, error)
	CompareAndSwap(context.Context, Actor, UpdateRequest, [32]byte, AuditFact) (WriteResult, error)
}
