package dnsreconcile

import (
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

const (
	JobKind          = "dns_reconcile"
	JobItemID        = "reconcile"
	PermissionRead   = "dns.read"
	PermissionManage = "dns.manage"
)

var (
	ErrInvalidInput        = errors.New("invalid dns reconciliation input")
	ErrNotFound            = errors.New("dns reconciliation task not found")
	ErrIdempotencyConflict = errors.New("dns reconciliation idempotency conflict")
	ErrRevisionConflict    = errors.New("dns reconciliation revision conflict")
	ErrCommitNotReady      = errors.New("dns reconciliation is not ready to commit")
	ErrClaimLost           = errors.New("dns reconciliation claim lost")
	ErrOperationInFlight   = errors.New("dns reconciliation provider operation is in flight")
	ErrPermissionDenied    = errors.New("dns reconciliation permission denied")
	ErrEntitlementDenied   = errors.New("dns reconciliation entitlement denied")
	ErrUnavailable         = errors.New("dns reconciliation dependency unavailable")
)

type Action string

const (
	ActionDryRun Action = "dry_run"
	ActionApply  Action = "apply"
	ActionCommit Action = "commit"
	ActionCancel Action = "cancel"
)

type DryRunRequest struct {
	TenantID    uuid.UUID
	SiteID      uuid.UUID
	ActorUserID uuid.UUID
	RequestID   string
	Check       dnscheck.CheckRequest
}

type ApplyRequest struct {
	TenantID            uuid.UUID
	SiteID              uuid.UUID
	ActorUserID         uuid.UUID
	IdempotencyKey      string
	RequestID           string
	Traceparent         string
	ExpectedRevision    int64
	RequiredConsecutive int
	Check               dnscheck.CheckRequest
}

type CommitRequest struct {
	TenantID         uuid.UUID
	SiteID           uuid.UUID
	TaskID           uuid.UUID
	ActorUserID      uuid.UUID
	IdempotencyKey   string
	RequestID        string
	Traceparent      string
	ExpectedRevision int64
}

type CancelRequest struct {
	TenantID         uuid.UUID
	SiteID           uuid.UUID
	TaskID           uuid.UUID
	ActorUserID      uuid.UUID
	IdempotencyKey   string
	RequestID        string
	Traceparent      string
	ExpectedRevision int64
}

type ProviderReportRequest struct {
	TenantID         uuid.UUID
	SiteID           uuid.UUID
	TaskID           uuid.UUID
	WorkloadID       string
	JobAttempt       uint32
	LeaseID          uuid.UUID
	IdempotencyKey   string
	RequestID        string
	Traceparent      string
	ExpectedRevision int64
	Report           dnscheck.ProviderReport
}

type Task struct {
	ID                  uuid.UUID
	TenantID            uuid.UUID
	SiteID              uuid.UUID
	ActorUserID         uuid.UUID
	RequestID           string
	Revision            int64
	RequiredConsecutive int
	Job                 jobstate.StoredJob
	Prepared            dnscheck.PreparedReconcile
	Result              dnscheck.ReconcileResult
	CreatedAt           time.Time
	UpdatedAt           time.Time
	Replayed            bool
}

type ClaimRequest struct {
	TenantID      uuid.UUID
	WorkerID      string
	Limit         int
	LeaseDuration time.Duration
}

type ApplyLease struct {
	Task           Task
	WorkerID       string
	Attempt        uint32
	LeaseID        uuid.UUID
	LeaseExpiresAt time.Time
}

type CommitLease struct {
	Task           Task
	WorkerID       string
	Attempt        uint32
	LeaseID        uuid.UUID
	LeaseExpiresAt time.Time
	Command        CommitRequest
}

type ReportResult struct {
	Task     Task
	Accepted bool
}
