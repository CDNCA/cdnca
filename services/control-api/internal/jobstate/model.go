package jobstate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidRequest      = errors.New("invalid job request")
	ErrIdempotencyConflict = errors.New("job idempotency conflict")
	ErrInvalidTransition   = errors.New("invalid job state transition")
	ErrInvalidReport       = errors.New("invalid job result report")
	ErrReportConflict      = errors.New("job result report conflict")
	ErrRetriesExhausted    = errors.New("job retries exhausted")
	ErrNotFound            = errors.New("job not found")
	ErrClaimLost           = errors.New("job claim was lost")
)

type State string

const (
	StateQueued        State = "queued"
	StateRunning       State = "running"
	StateSucceeded     State = "succeeded"
	StatePartialFailed State = "partial_failed"
	StateFailed        State = "failed"
	StateCancelled     State = "cancelled"
)

func (state State) Terminal() bool {
	switch state {
	case StateSucceeded, StatePartialFailed, StateFailed, StateCancelled:
		return true
	default:
		return false
	}
}

func CanTransition(from, to State) bool {
	switch from {
	case StateQueued:
		return to == StateRunning || to == StateCancelled
	case StateRunning:
		return to == StateSucceeded || to == StatePartialFailed ||
			to == StateFailed || to == StateCancelled
	case StatePartialFailed, StateFailed:
		return to == StateQueued
	default:
		return false
	}
}

type ItemState string

const (
	ItemPending          ItemState = "pending"
	ItemSucceeded        ItemState = "succeeded"
	ItemFailed           ItemState = "failed"
	ItemCancelled        ItemState = "cancelled"
	CodeCancelled                  = "cancelled"
	CodeItemFailed                 = "item_failed"
	CodeAllItemsFailed             = "all_items_failed"
	CodeLeaseExpired               = "lease_expired"
	CodeRetriesExhausted           = "retries_exhausted"
)

type Request struct {
	IdempotencyKey string
	Payload        []byte
	ItemIDs        []string
	MaxRetries     uint32
}

type RequestDigest [sha256.Size]byte

func (digest RequestDigest) String() string {
	return hex.EncodeToString(digest[:])
}

type Report struct {
	ItemID   string
	State    ItemState
	Code     string
	Attempt  uint32
	Sequence uint64
}

type ItemResult struct {
	ItemID      string
	State       ItemState
	Code        string
	Attempt     uint32
	Sequence    uint64
	CompletedAt time.Time
}

type Progress struct {
	Total     int
	Completed int
	Succeeded int
	Failed    int
	Cancelled int
	Pending   int
}

type Snapshot struct {
	IdempotencyKey string
	Digest         RequestDigest
	State          State
	Attempt        uint32
	MaxRetries     uint32
	Progress       Progress
	Items          []ItemResult
	CreatedAt      time.Time
	StartedAt      time.Time
	UpdatedAt      time.Time
	CompletedAt    time.Time
}

type Clock func() time.Time

type CreateItem struct {
	ItemID string
	NodeID *uuid.UUID
}

type CreateInput struct {
	JobID          uuid.UUID
	TenantID       uuid.UUID
	Kind           string
	Subject        string
	IdempotencyKey string
	Payload        []byte
	Items          []CreateItem
	MaxAttempts    uint32
	RequestID      string
	TraceID        string
}

type StartInput struct {
	TenantID      uuid.UUID
	JobID         uuid.UUID
	Kind          string
	WorkerID      string
	LeaseDuration time.Duration
}

type CreateResult struct {
	Job      StoredJob
	Replayed bool
}

type StoredItem struct {
	ItemID      string
	NodeID      *uuid.UUID
	State       ItemState
	Attempt     uint32
	Sequence    uint64
	ErrorCode   string
	CompletedAt time.Time
}

type StoredJob struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	Kind              string
	Subject           string
	IdempotencyKey    string
	RequestDigest     RequestDigest
	RequestID         string
	TraceID           string
	State             State
	Attempt           uint32
	MaxAttempts       uint32
	CancelRequestedAt time.Time
	Progress          Progress
	LastErrorCode     string
	Items             []StoredItem
	CreatedAt         time.Time
	StartedAt         time.Time
	UpdatedAt         time.Time
	CompletedAt       time.Time
}

type ClaimInput struct {
	TenantID      uuid.UUID
	Kind          string
	WorkerID      string
	Limit         int
	LeaseDuration time.Duration
}

type Claim struct {
	Job            StoredJob
	LeaseID        uuid.UUID
	WorkerID       string
	LeaseExpiresAt time.Time
}

type HeartbeatInput struct {
	TenantID      uuid.UUID
	JobID         uuid.UUID
	WorkerID      string
	Attempt       uint32
	LeaseID       uuid.UUID
	LeaseDuration time.Duration
}

type ReportInput struct {
	TenantID uuid.UUID
	JobID    uuid.UUID
	WorkerID string
	LeaseID  uuid.UUID
	Report   Report
}

type ReportResult struct {
	Job     StoredJob
	Applied bool
}

type ReplayInput struct {
	TenantID       uuid.UUID
	JobID          uuid.UUID
	ActorScopeID   uuid.UUID
	ActorUserID    uuid.UUID
	IdempotencyKey string
	RequestDigest  []byte
	RequestID      string
}
