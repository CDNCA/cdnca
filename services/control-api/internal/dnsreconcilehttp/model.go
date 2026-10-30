package dnsreconcilehttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	PermissionRead   = dnsreconcile.PermissionRead
	PermissionManage = dnsreconcile.PermissionManage

	defaultMaxRequestBytes int64 = 64 << 10
	defaultQueryTimeout          = 8 * time.Second
	defaultCommandTimeout        = 16 * time.Minute
)

var (
	ErrInvalidConfig           = errors.New("invalid DNS reconciliation HTTP configuration")
	ErrInvalidRequest          = errors.New("invalid DNS reconciliation HTTP request")
	ErrUnauthenticated         = errors.New("DNS reconciliation authentication required")
	ErrPermissionDenied        = errors.New("DNS reconciliation permission denied")
	ErrEntitlementDenied       = errors.New("DNS reconciliation entitlement denied")
	ErrWorkloadUnauthenticated = errors.New("DNS reconciliation workload authentication required")
	ErrUnavailable             = errors.New("DNS reconciliation HTTP dependency unavailable")
)

type Principal struct {
	SubjectID   uuid.UUID
	TenantID    uuid.UUID
	SessionID   uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string
	Permissions []string
}

func (principal Principal) valid() bool {
	return principal.SubjectID != uuid.Nil && principal.TenantID != uuid.Nil && principal.SessionID != uuid.Nil
}

type WorkloadPrincipal struct {
	WorkloadID string
	TenantID   uuid.UUID
	SiteID     uuid.UUID
}

func (principal WorkloadPrincipal) valid() bool {
	return principal.WorkloadID != "" && principal.TenantID != uuid.Nil && principal.SiteID != uuid.Nil
}

type AuthorizationRequest struct {
	Principal  Principal
	TenantID   uuid.UUID
	SiteID     uuid.UUID
	Permission string
}

type SessionAuthenticator interface {
	AuthenticateSession(context.Context, string) (Principal, error)
}

type IAMAuthorizer interface {
	Authorize(context.Context, AuthorizationRequest) error
}

type WorkloadAuthenticator interface {
	Authenticate(*http.Request) (WorkloadPrincipal, error)
}

type Domain interface {
	DryRun(context.Context, dnsreconcile.DryRunRequest) (dnscheck.ReconcileResult, error)
	Apply(context.Context, dnsreconcile.ApplyRequest) (dnsreconcile.Task, error)
	Get(context.Context, uuid.UUID, uuid.UUID) (dnsreconcile.Task, error)
	Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error)
	Cancel(context.Context, dnsreconcile.CancelRequest) (dnsreconcile.Task, error)
	RecordProviderReport(context.Context, dnsreconcile.ProviderReportRequest) (dnsreconcile.ReportResult, error)
}

type Dependencies struct {
	Sessions  SessionAuthenticator
	IAM       IAMAuthorizer
	Domain    Domain
	Workloads WorkloadAuthenticator
}

type Config struct {
	MaxRequestBytes int64
	QueryTimeout    time.Duration
	CommandTimeout  time.Duration
}

type ProductionDependencies struct {
	Pool             *pgxpool.Pool
	Jobs             *jobstate.Store
	CheckerResolver  dnsreconcile.CheckerResolver
	ProviderResolver dnsreconcile.ProviderResolver
	Entitlement      dnsreconcile.EntitlementGate
	Sessions         SessionAuthenticator
	IAM              IAMAuthorizer
	Workloads        WorkloadAuthenticator
}

type ProductionConfig struct {
	HTTP                 Config
	Runtime              dnsreconcile.RuntimeConfig
	DatabaseProbeTimeout time.Duration
}

type checkBody struct {
	Name                     string               `json:"name"`
	Expected                 []expectedRecordBody `json:"expected"`
	AuthoritativeNS          []string             `json:"authoritative_ns"`
	TTL                      uint32               `json:"ttl"`
	Line                     string               `json:"line"`
	Weight                   uint32               `json:"weight"`
	PropagationStartedAt     *time.Time           `json:"propagation_started_at,omitempty"`
	PropagationWindowSeconds int64                `json:"propagation_window_seconds"`
	Provider                 providerSnapshotBody `json:"provider"`
}

type expectedRecordBody struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

type providerSnapshotBody struct {
	ZoneID   string               `json:"zone_id"`
	Revision int64                `json:"revision"`
	Records  []providerRecordBody `json:"records"`
}

type providerRecordBody struct {
	RecordID string `json:"record_id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      uint32 `json:"ttl"`
	Line     string `json:"line"`
	Weight   uint32 `json:"weight"`
}

type providerReportBody struct {
	ClientRequestID   string                      `json:"client_request_id"`
	JobAttempt        uint32                      `json:"job_attempt"`
	LeaseID           uuid.UUID                   `json:"lease_id"`
	ProviderRequestID *string                     `json:"provider_request_id"`
	ProviderRecordID  *string                     `json:"provider_record_id"`
	ProviderRevision  *int64                      `json:"provider_revision"`
	Status            dnscheck.OperationStatus    `json:"status"`
	ErrorClass        dnscheck.ProviderErrorClass `json:"error_class"`
	ErrorCode         string                      `json:"error_code"`
	RetryAfterSeconds int64                       `json:"retry_after_seconds"`
	Sequence          uint64                      `json:"sequence"`
}

type emptyBody struct{}

type mutationMetadata struct {
	IdempotencyKey   string
	RequestID        string
	Traceparent      string
	ExpectedRevision int64
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}
