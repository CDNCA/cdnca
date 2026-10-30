package dnsreconcile

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/google/uuid"
)

type Store interface {
	Create(context.Context, ApplyRequest, dnscheck.PreparedReconcile) (Task, bool, error)
	Get(context.Context, uuid.UUID, uuid.UUID) (Task, error)
	Claim(context.Context, ClaimRequest) ([]ApplyLease, error)
	HeartbeatApply(context.Context, ApplyLease, time.Duration) (ApplyLease, error)
	CheckpointApply(context.Context, ApplyLease, dnscheck.ReconcileResult) (Task, error)
	FinishApply(context.Context, ApplyLease, dnscheck.ReconcileResult) (Task, error)
	AcquireCommit(context.Context, CommitRequest, string, time.Duration) (CommitLease, bool, error)
	HeartbeatCommit(context.Context, CommitLease, time.Duration) (CommitLease, error)
	CheckpointCommit(context.Context, CommitLease, dnscheck.ReconcileResult) (Task, error)
	Cancel(context.Context, CancelRequest) (Task, bool, error)
	RecordProviderReport(context.Context, ProviderReportRequest) (ReportResult, error)
}

type EntitlementGate interface {
	AuthorizeDNSReconcile(context.Context, EntitlementRequest) error
}

type EntitlementRequest struct {
	TenantID    uuid.UUID
	SiteID      uuid.UUID
	ActorUserID uuid.UUID
	RequestID   string
	Action      Action
}

type CheckerResolver interface {
	ResolveChecker(context.Context, uuid.UUID, uuid.UUID) (*dnscheck.Checker, error)
}

type PropagationEngine interface {
	Observe(context.Context, dnspropagation.Request) (dnspropagation.Result, error)
}

type PropagationRetryStore interface {
	Load(context.Context, dnspropagation.ProviderRetryKey) (dnspropagation.ProviderRetryStoreResult, bool, error)
	CompareAndSwap(context.Context, dnspropagation.ProviderRetryKey, uint64,
		dnspropagation.ProviderRetryState, time.Time) (dnspropagation.ProviderRetryStoreResult, error)
}

type PropagationContext struct {
	ScopeID    uuid.UUID
	ProviderID uuid.UUID
	ZoneID     uuid.UUID
	// Zone is the zone whose authoritative servers are asked: the CNAME
	// zone's hosted apex (dns_zones.provider_zone_apex), not its name (N14).
	Zone string
}

type PropagationContextResolver interface {
	ResolvePropagationContext(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (PropagationContext, error)
}

type ProviderResolver interface {
	ResolveProvider(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dnscheck.ProviderAdapter, error)
}
