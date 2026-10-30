package securitybinding

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput          = errors.New("invalid security publication input")
	ErrPermissionDenied      = errors.New("security publication permission denied")
	ErrNotFound              = errors.New("security publication resource not found")
	ErrIdempotencyConflict   = errors.New("security publication idempotency conflict")
	ErrBindingConflict       = errors.New("security policy site binding conflict")
	ErrBindingRevision       = errors.New("security policy site binding revision conflict")
	ErrActiveVersionConflict = errors.New("security policy active version conflict")
	ErrPolicyVersionConflict = errors.New("security policy version is not monotonic")
	ErrTargetConflict        = errors.New("security publication node target conflict")
	ErrPlanExpired           = errors.New("security publication plan expired before claim")
	ErrSiteLocked            = errors.New("security publication site is locked")
	// ErrPolicyDeleted: a deleted library cannot be bound to a site again
	// (sec-rebind; detaching it is still allowed).
	ErrPolicyDeleted = errors.New("security policy is deleted")
)

type PublishRequest struct {
	TenantScopeID           uuid.UUID
	SiteID                  uuid.UUID
	PolicyID                uuid.UUID
	PolicyVersion           int64
	TargetNodeIDs           []uuid.UUID
	ExpectedBindingRevision int64
	ExpectedActiveVersion   int64
	RolloutID               uuid.UUID
	IdempotencyKey          string
	RequestID               string
	// Detach (sec-rebind, migration 470) withdraws the site's active library
	// of this kind: PolicyID/PolicyVersion are the binding's active ones, and
	// once promoted the site enforces no rule of the kind.
	Detach bool
}

type Publication struct {
	BundleID              uuid.UUID
	BindingID             uuid.UUID
	BindingRevision       int64
	TenantScopeID         uuid.UUID
	SiteID                uuid.UUID
	PolicyID              uuid.UUID
	PolicyKind            string
	PolicyVersion         int64
	ExpectedActiveVersion int64
	// ExpectedActivePolicyID is the library active when this publication
	// was claimed (nil when none was); PolicyID differs from it on a rebind.
	ExpectedActivePolicyID *uuid.UUID
	Detach                 bool
	RolloutID              uuid.UUID
	TargetNodeIDs          []uuid.UUID
	BundleJSON             []byte
	BundleSHA256           [32]byte
	CanonicalPayloadSHA256 [32]byte
	RuntimeSnapshotSHA256  [32]byte
	SigningKeyID           string
	IssuedAt               time.Time
	ExpiresAt              time.Time
	CreatedAt              time.Time
	Replayed               bool
}
