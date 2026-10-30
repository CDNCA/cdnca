package cnameallocation

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type frozenStoreAPI113 interface {
	Allocate(context.Context, AllocateRequest) (Allocation, error)
	Complete(context.Context, ResultRequest) (Allocation, error)
	Fail(context.Context, ResultRequest) (Allocation, error)
	Get(context.Context, uuid.UUID, uuid.UUID) (Allocation, error)
}

var (
	_ frozenStoreAPI113                                                                = (*Store)(nil)
	_ func(Key, uuid.UUID, uuid.UUID, uuid.UUID, Mode, string, uint64) (string, error) = GenerateLabel
	_ func(*pgxpool.Pool, Keyring, func() time.Time) (*Store, error)                   = NewStore
)

func TestCNAMEAllocationPublicContract(t *testing.T) {
	if ModeSite != "site" || ModePackage != "package" {
		t.Fatalf("modes = (%q,%q), want site/package", ModeSite, ModePackage)
	}
	if StatePending != "pending" || StateFailed != "failed" || StateDone != "done" {
		t.Fatalf("states = (%q,%q,%q), want pending/failed/done", StatePending, StateFailed, StateDone)
	}
	if JobKind != "cname_allocation" || JobItemID != "allocate" {
		t.Fatalf("job identity = (%q,%q)", JobKind, JobItemID)
	}

	_ = AllocateRequest{
		TargetScopeID: uuid.Nil, SiteID: uuid.Nil, ActorScopeID: uuid.Nil, ActorUserID: uuid.Nil,
		Mode: ModeSite, Domain: "example.com", Hostname: "", IdempotencyKey: "allocate-1",
		RequestID: "request-1", TraceID: "trace-1", ExpectedSiteRevision: 1, Regenerate: true,
	}
	_ = Allocation{
		ID: uuid.Nil, TenantID: uuid.Nil, ScopeID: uuid.Nil, SiteID: uuid.Nil, OwnerID: uuid.Nil,
		ProviderID: uuid.Nil, ZoneID: uuid.Nil, PackageSubscriptionID: uuid.Nil, JobID: uuid.Nil,
		Mode: ModePackage, State: StatePending, Domain: "example.com", Hostname: "label.example.com",
		KeyID: "key-1", FailureCode: "", Revision: 1, LKGRevision: 0, SiteRevision: 1, Replayed: false,
	}
	_ = ResultRequest{
		TargetScopeID: uuid.Nil, SiteID: uuid.Nil, AllocationID: uuid.Nil, JobID: uuid.Nil,
		ExpectedRevision: 1, WorkerID: "worker-1", Attempt: 1, LeaseID: uuid.Nil,
		Sequence: 1, FailureCode: "provider_unavailable",
	}
	for name, err := range map[string]error{
		"invalid": ErrInvalidInput, "not found": ErrNotFound, "conflict": ErrConflict,
		"unavailable": ErrUnavailable, "claim lost": ErrClaimLost,
	} {
		if err == nil {
			t.Fatalf("%s error is nil", name)
		}
	}
}

func TestCNAMEAllocationStoreSQLContract(t *testing.T) {
	data, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	contracts := []struct {
		name     string
		required []string
	}{
		{name: "default zone authority", required: []string{"dns_zones", "is_default", "provider_id", "scope_id"}},
		{name: "explicit domain same provider", required: []string{"lower(name)", "lower($", "provider_id"}},
		{name: "site and package owner authority", required: []string{"sites", "owner_user_id", "package_subscription_id", "package_subscriptions", "package_monitor_subscription_owners", "package_orders", "fulfilled"}},
		{name: "explicit hostname share identity", required: []string{"cname_hostname_claims", "explicit_hostname", "tenant_scope_id", "provider_id", "domain", "mode", "owner_id"}},
		{name: "durable request and audit", required: []string{"cname_allocation_requests", "actor_scope_id", "actor_user_id", "idempotency_key", "request_digest", "request_id", "audit_event_id"}},
		{name: "durable job state", required: []string{"background_jobs", "background_job_items", "cname_allocation", "allocate", "job_id"}},
		{name: "CAS and replay", required: []string{"expected_revision", "current_revision", "binding_revision", "ErrConflict", "Replayed"}},
		{name: "failure preserves LKG", required: []string{"StateFailed", "failure_code", "lkg_revision", "lkg_allocation_id"}},
	}
	for _, contract := range contracts {
		t.Run(contract.name, func(t *testing.T) {
			for _, required := range contract.required {
				if !strings.Contains(source, required) {
					t.Errorf("store.go missing %q", required)
				}
			}
		})
	}
	for _, forbidden := range []string{
		"TargetScopeID: req.ActorScopeID",
		"OwnerID: req.TargetScopeID",
		"PackageSubscriptionID: req.SiteID",
		"UPDATE cname_hostname_claims",
		"DELETE FROM cname_hostname_claims",
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("store.go contains unsafe authority shortcut %q", forbidden)
		}
	}
}
