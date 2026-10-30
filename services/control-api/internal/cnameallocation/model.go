package cnameallocation

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	JobKind   = "cname_allocation"
	JobItemID = "allocate"
)

type Mode string

const (
	ModeSite    Mode = "site"
	ModePackage Mode = "package"
)

type State string

const (
	StatePending State = "pending"
	StateFailed  State = "failed"
	StateDone    State = "done"
)

var (
	ErrInvalidInput = errors.New("invalid CNAME allocation input")
	ErrNotFound     = errors.New("CNAME allocation authority not found")
	ErrConflict     = errors.New("CNAME allocation conflict")
	// ErrBlocked: the CNAME zone is covered by the platform domain blocklist.
	ErrBlocked     = errors.New("CNAME allocation domain is blocked")
	ErrUnavailable = errors.New("CNAME allocation unavailable")
	ErrClaimLost   = errors.New("CNAME allocation job claim lost")
	// ErrRetryable: the database aborted the transaction (deadlock 40P01,
	// serialization failure 40001, NOWAIT lock 55P03); running it again can
	// succeed, so the job is retried within seconds, not after its lease (N20).
	ErrRetryable = errors.New("CNAME allocation retryable database conflict")
	// errIntentSuperseded: a newer CNAME intent replaced the executing one.
	errIntentSuperseded = errors.New("CNAME intent superseded")
)

// Failure codes an intent records when allocation cannot start. The
// configuration codes are what DNS configuration changes recover from
// (RecoverableFailureCodes); allocation_rejected stays the fallback.
const (
	FailureDNSProviderNotConfigured = "dns_provider_not_configured"
	FailureCNAMEZoneNotConfigured   = "cname_zone_not_configured"
	// The CNAME domain's own DNS provider is disabled (fix-cnamerand: zones
	// may sit on any provider; the code keeps its historical name).
	FailureCNAMEZoneProviderDiffers = "cname_zone_provider_mismatch"
	FailurePackageInactive          = "package_subscription_inactive"
	FailureNodeGroupUnavailable     = "node_group_unavailable"
	FailureNoServingAddress         = "node_targets_unavailable"
	// A site without a package freezes its targets from the platform default
	// line group (migration 533) and allocates in the default CNAME zone.
	FailureNoDefaultLineGroup = "cname_no_default_line_group"
	FailureNoDefaultZone      = "cname_no_default_zone"

	// The platform DNS configuration exists but could not be copied into the
	// tenant scope (credentials unavailable, no active member, name clash).
	FailurePlatformDNSSyncFailed = "platform_dns_sync_failed"

	// The site is gone, or the intent's actor lost site/DNS permission (or,
	// for a platform actor, its session).
	FailureSiteAuthority      = "site_authority_unavailable"
	FailureAllocationRejected = "allocation_rejected"
	// The operator may not write the tenant's DNS: neither a tenant member
	// nor a platform administrator (fix-regen2).
	FailureDNSPermissionDenied = "dns_permission_denied"
	// Every generated label candidate (MaxLabelAttempts) is already claimed.
	FailureLabelExhausted = "cname_label_exhausted"
)

// allocationFailure is an ErrNotFound/ErrInvalidInput with the reason the
// allocation could not start; mapError keeps it intact.
type allocationFailure struct {
	code string
	base error
}

func (failure *allocationFailure) Error() string { return failure.base.Error() + ": " + failure.code }
func (failure *allocationFailure) Unwrap() error { return failure.base }

func failWith(code string, base error) error { return &allocationFailure{code: code, base: base} }

// failureCode returns the intent failure code of an Allocate error.
func failureCode(err error) string {
	var failure *allocationFailure
	switch {
	case errors.As(err, &failure):
		return failure.code
	case errors.Is(err, ErrBlocked):
		return "domain_blocked"
	case errors.Is(err, errIntentSuperseded):
		return "intent_superseded"
	}
	return FailureAllocationRejected
}

type Key struct {
	ID     string
	Secret []byte
}

type Keyring interface {
	Active(context.Context) (Key, error)
	Lookup(context.Context, string) (Key, error)
}

type AllocateRequest struct {
	platformIntentID uuid.UUID
	// intentJobID is the dns.cname.intent job being executed. The intent is
	// current while it is the site's cname_task_id; site edits that keep the
	// CNAME inputs do not supersede it (migration 405).
	intentJobID uuid.UUID
	// streamID: a stream's own allocation (migration 505), in the audit payload.
	streamID             uuid.UUID
	TargetScopeID        uuid.UUID
	SiteID               uuid.UUID
	ActorScopeID         uuid.UUID
	ActorUserID          uuid.UUID
	Mode                 Mode
	Domain               string
	Hostname             string
	IdempotencyKey       string
	RequestID            string
	TraceID              string
	ExpectedSiteRevision int64
	Regenerate           bool
}

type Allocation struct {
	ID                    uuid.UUID
	TenantID              uuid.UUID
	ScopeID               uuid.UUID
	SiteID                uuid.UUID
	OwnerID               uuid.UUID
	ProviderID            uuid.UUID
	ZoneID                uuid.UUID
	PackageSubscriptionID uuid.UUID
	JobID                 uuid.UUID
	Mode                  Mode
	State                 State
	Domain                string
	Hostname              string
	KeyID                 string
	FailureCode           string
	Revision              int64
	LKGRevision           int64
	SiteRevision          int64
	Replayed              bool
}

type ResultRequest struct {
	TargetScopeID    uuid.UUID
	SiteID           uuid.UUID
	AllocationID     uuid.UUID
	JobID            uuid.UUID
	ExpectedRevision int64
	WorkerID         string
	Attempt          uint32
	LeaseID          uuid.UUID
	Sequence         uint64
	FailureCode      string
}

type TargetValues struct {
	A    []string
	AAAA []string
	// CNAME, when set, replaces A/AAAA: the site is served by a node market
	// supply and its hostname points at the market's supply name.
	CNAME string `json:",omitempty"`
}

// empty reports whether there is nothing to publish.
func (values TargetValues) empty() bool {
	return values.CNAME == "" && len(values.A)+len(values.AAAA) == 0
}

type Target struct {
	TenantID, ScopeID, SiteID, AllocationID, JobID uuid.UUID
	PackageSubscriptionID, NodeGroupID             uuid.UUID
	NodeGroupRevision                              int64
	ProviderID, ZoneID                             uuid.UUID
	ZoneRevision                                   int64
	OwnerName                                      string
	ActorUserID                                    uuid.UUID
	RequestID                                      string
	Traceparent                                    string
	SiteRevision                                   int64
	AllocationRevision                             int64
	TTL                                            uint32
	Values                                         TargetValues
	Digest                                         string
	ChildTaskID                                    uuid.UUID
	ChildTaskRevision                              int64
	// Publish is the TTL / IP weight of 节点管理 > DNS配置 at load time.
	Publish PublishSettings
}

type ClaimStore interface {
	Claim(context.Context, jobstate.ClaimInput) ([]jobstate.Claim, error)
}

type TargetStore interface {
	LoadTarget(context.Context, jobstate.Claim) (Target, error)
	AttachChild(context.Context, jobstate.Claim, Target, dnsreconcile.Task) error
	Complete(context.Context, ResultRequest) (Allocation, error)
	Fail(context.Context, ResultRequest) (Allocation, error)
	// Yield gives the claim's lease back; the job is claimable again after delay.
	Yield(context.Context, jobstate.Claim, time.Duration) error
}

type ReconcileRuntime interface {
	Apply(context.Context, dnsreconcile.ApplyRequest) (dnsreconcile.Task, error)
	Get(context.Context, uuid.UUID, uuid.UUID) (dnsreconcile.Task, error)
	Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error)
}

type TenantSource interface {
	PendingTenants(context.Context, int) ([]uuid.UUID, error)
}

type IntentStore interface {
	PrepareIntent(context.Context, jobstate.Claim) error
}

type StreamIntentStore interface {
	PrepareStreamIntent(context.Context, jobstate.Claim) error
}

// PlatformDNS copies the platform DNS configuration into a tenant scope that
// has none yet (dnsacme.Service.EnsurePlatformTenantCopy).
type PlatformDNS interface {
	EnsurePlatformTenantCopy(context.Context, uuid.UUID) (bool, error)
}

type Store struct {
	pool        *pgxpool.Pool
	keyring     Keyring
	now         func() time.Time
	auditor     *audit.Log
	platformDNS PlatformDNS
	// pick draws the zone index for a CNAME without a domain (fix-cnamerand);
	// nil is math/rand/v2 IntN. Tests inject a fixed source.
	pick func(int) int
}
