package dnsmaintenance

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

type maintenanceFixture struct {
	provider  *fakeProvider
	reconcile *fakeReconcile
	targets   *fakeTargets
	platform  *fakePlatform
	jobs      *fakeJobs
	worker    *Worker
	zoneID    uuid.UUID
}

func newMaintenanceFixture(t *testing.T, records ...dnsproviderremote.ZoneRecord) *maintenanceFixture {
	t.Helper()
	tenantID, scopeID, zoneID := uuid.New(), uuid.New(), uuid.New()
	provider := newFakeProvider(records...)
	fixture := &maintenanceFixture{provider: provider, zoneID: zoneID,
		reconcile: &fakeReconcile{provider: provider, tasks: map[uuid.UUID]dnsreconcile.Task{}},
		targets: &fakeTargets{tenantID: tenantID, scopeID: scopeID, targets: map[string]RepairTarget{},
			serving: map[string]cnameallocation.TargetValues{}, claimed: map[string]bool{}},
		platform: &fakePlatform{tenant: dnsacme.PlatformTenant{TenantID: tenantID, ScopeID: scopeID},
			zones: map[uuid.UUID]string{zoneID: "cdn.example.com"}},
		jobs: &fakeJobs{}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "test", PollInterval: time.Second, LeaseDuration: time.Minute,
		ItemTimeout: time.Second, TaskPoll: time.Millisecond}, fixture.jobs, fixture.targets, fixture.platform,
		provider, fixture.reconcile)
	if err != nil {
		t.Fatal(err)
	}
	fixture.worker = worker
	return fixture
}

func (fixture *maintenanceFixture) allocate(owner string, values cnameallocation.TargetValues) {
	fixture.targets.targets[owner] = RepairTarget{TenantID: fixture.targets.tenantID, ScopeID: fixture.targets.scopeID,
		SiteID: uuid.New(), ProviderID: dnsacme.PlatformProviderCopyID(fixture.targets.scopeID), ZoneID: fixture.zoneID,
		ZoneName: "cdn.example.com", ZoneRevision: 1, NodeGroupID: uuid.New(), NodeGroupRevision: 1, Owner: owner,
		ActorUserID: uuid.New(), RequestID: "req-1"}
	fixture.targets.serving[owner] = values
	fixture.targets.claimed[owner] = true
}

func (fixture *maintenanceFixture) run(t *testing.T, kind string, items ...string) []jobstate.Report {
	t.Helper()
	stored := make([]jobstate.StoredItem, len(items))
	for index, item := range items {
		stored[index] = jobstate.StoredItem{ItemID: item, State: jobstate.ItemPending}
	}
	fixture.jobs.claims = []jobstate.Claim{{Job: jobstate.StoredJob{ID: uuid.New(), TenantID: fixture.targets.tenantID,
		Kind: kind, Attempt: 1, RequestID: "req-op", Items: stored}, LeaseID: uuid.New(), WorkerID: "test"}}
	fixture.jobs.reports = nil
	if err := fixture.worker.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	return fixture.jobs.reports
}

func zoneRecord(id, name string, recordType dnscheck.RecordType, value string, ttl uint32) dnsproviderremote.ZoneRecord {
	return dnsproviderremote.ZoneRecord{ID: id, Name: name, Type: recordType, Value: value, TTL: ttl}
}

// 记录修复 replaces a stale record, adds the missing one, deletes an extra
// AAAA and rewrites every value with the configured TTL.
func TestRepairRewritesOwnerRecords(t *testing.T) {
	owner := "abc.cdn.example.com."
	fixture := newMaintenanceFixture(t,
		zoneRecord("stale", owner, dnscheck.RecordA, "198.51.100.9", 300),
		zoneRecord("extra", owner, dnscheck.RecordAAAA, "2001:db8::9", 300),
		zoneRecord("other", "keep.cdn.example.com.", dnscheck.RecordA, "198.51.100.1", 300))
	fixture.allocate(owner, cnameallocation.TargetValues{A: []string{"192.0.2.1", "192.0.2.2"}})
	item := RepairItem(owner, []string{"192.0.2.1", "192.0.2.2"}, nil)
	reports := fixture.run(t, RepairJobKind, item)
	if len(reports) != 1 || reports[0].State != jobstate.ItemSucceeded || reports[0].ItemID != item {
		t.Fatalf("reports = %+v", reports)
	}
	if got := fixture.provider.values(owner, dnscheck.RecordA); !slices.Equal(got, []string{"192.0.2.1/600", "192.0.2.2/600"}) {
		t.Fatalf("A records = %v", got)
	}
	if got := fixture.provider.values(owner, dnscheck.RecordAAAA); len(got) != 0 {
		t.Fatalf("AAAA records = %v", got)
	}
	if got := fixture.provider.values("keep.cdn.example.com.", dnscheck.RecordA); len(got) != 1 {
		t.Fatalf("other owner touched: %v", got)
	}
	if applied := fixture.reconcile.applied[0]; applied.ActorUserID == uuid.Nil || applied.Check.TTL != 600 ||
		!strings.HasPrefix(applied.IdempotencyKey, "dnsrepair-") {
		t.Fatalf("apply = %+v", applied)
	}
	if !strings.HasPrefix(item, "修复记录 abc.cdn.example.com A 192.0.2.1,192.0.2.2") {
		t.Fatalf("item = %q", item)
	}
}

func TestRepairReportsMissingEndpointsAndAllocations(t *testing.T) {
	fixture := newMaintenanceFixture(t)
	fixture.allocate("down.cdn.example.com.", cnameallocation.TargetValues{})
	reports := fixture.run(t, RepairJobKind, RepairItem("down.cdn.example.com.", nil, nil),
		RepairItem("gone.cdn.example.com.", []string{"192.0.2.1"}, nil), NothingToRepair)
	codes := []string{reports[0].Code, reports[1].Code, reports[2].Code}
	if !slices.Equal(codes, []string{CodeNoServingEndpoint, CodeAllocationMissing, ""}) || reports[2].State != jobstate.ItemSucceeded {
		t.Fatalf("reports = %+v", reports)
	}
}

// 清除CDN无关解析 lists only A/AAAA/CNAME (the lister never returns NS/MX/TXT),
// keeps the apex and allocated CNAME hostnames and deletes the rest.
func TestCleanupDeletesOnlyUnallocatedRecords(t *testing.T) {
	fixture := newMaintenanceFixture(t,
		zoneRecord("apex", "cdn.example.com.", dnscheck.RecordA, "198.51.100.1", 600),
		zoneRecord("ours", "abc.cdn.example.com.", dnscheck.RecordA, "192.0.2.1", 600),
		zoneRecord("foreign-a", "old.cdn.example.com.", dnscheck.RecordA, "198.51.100.7", 600),
		zoneRecord("foreign-cname", "www.cdn.example.com.", dnscheck.RecordCNAME, "elsewhere.example.net.", 600))
	fixture.allocate("abc.cdn.example.com.", cnameallocation.TargetValues{A: []string{"192.0.2.1"}})
	planner, err := NewPlanner(fixture.targets, fixture.platform, fixture.provider)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := planner.PlanCleanup(t.Context())
	if err != nil {
		t.Fatalf("PlanCleanup() error = %v", err)
	}
	if len(jobs) != 1 || len(jobs[0].Items) != 2 {
		t.Fatalf("cleanup jobs = %+v", jobs)
	}
	for _, item := range jobs[0].Items {
		if !strings.HasPrefix(item, "删除记录 old.cdn.example.com A 198.51.100.7 #") &&
			!strings.HasPrefix(item, "删除记录 www.cdn.example.com CNAME elsewhere.example.net #") {
			t.Fatalf("cleanup item = %q", item)
		}
	}
	// The www record becomes an allocated hostname before the job runs: kept.
	fixture.targets.claimed["www.cdn.example.com."] = true
	reports := fixture.run(t, CleanupJobKind, jobs[0].Items...)
	states := map[string]string{}
	for _, report := range reports {
		states[report.ItemID[:len("删除记录 xxx")]] = report.Code
	}
	if len(reports) != 2 || states["删除记录 old"] != "" || states["删除记录 www"] != CodeRecordChanged {
		t.Fatalf("reports = %+v", reports)
	}
	if !slices.Equal(fixture.provider.deletes, []string{"foreign-a"}) {
		t.Fatalf("deleted = %v", fixture.provider.deletes)
	}
	for _, id := range []string{"apex", "ours", "foreign-cname"} {
		if _, ok := fixture.provider.records[id]; !ok {
			t.Fatalf("record %s was deleted", id)
		}
	}
}

func TestCleanupItemRoundTrip(t *testing.T) {
	zoneID := uuid.New()
	record := CleanupRecord{ZoneID: zoneID, Name: "old.cdn.example.com.", Type: "A", Value: "198.51.100.7", RecordID: "rec-1"}
	parsed, ok := ParseCleanupItem(CleanupItem(record))
	if !ok || parsed.ZoneID != zoneID || parsed.Name != record.Name || parsed.Type != "A" || parsed.RecordID != "rec-1" {
		t.Fatalf("parsed = %+v %t", parsed, ok)
	}
	long := record
	long.Value = strings.Repeat("v", 400)
	item := CleanupItem(long)
	if parsed, ok := ParseCleanupItem(item); !ok || parsed.RecordID != "rec-1" || len([]rune(item)) > 256 {
		t.Fatalf("long item = %q (%t)", item, ok)
	}
	if owner, ok := RepairOwner(RepairItem("ABC.cdn.example.com.", []string{"192.0.2.1"}, nil)); !ok || owner != "abc.cdn.example.com" {
		t.Fatalf("owner = %q", owner)
	}
}

func TestPlanRepairListsOwnersOrNothing(t *testing.T) {
	fixture := newMaintenanceFixture(t)
	planner, _ := NewPlanner(fixture.targets, fixture.platform, fixture.provider)
	jobs, err := planner.PlanRepair(t.Context())
	if err != nil || len(jobs) != 1 || !slices.Equal(jobs[0].Items, []string{NothingToRepair}) {
		t.Fatalf("empty repair plan = %+v, %v", jobs, err)
	}
	fixture.allocate("b.cdn.example.com.", cnameallocation.TargetValues{A: []string{"192.0.2.2"}})
	fixture.allocate("a.cdn.example.com.", cnameallocation.TargetValues{AAAA: []string{"2001:db8::1"}})
	jobs, err = planner.PlanRepair(t.Context())
	if err != nil || len(jobs) != 1 || !slices.Equal(jobs[0].Items, []string{
		"修复记录 a.cdn.example.com AAAA 2001:db8::1", "修复记录 b.cdn.example.com A 192.0.2.2"}) {
		t.Fatalf("repair plan = %+v, %v", jobs, err)
	}
}

func TestProductionReconcileRemoteListsAndDeletes(t *testing.T) {
	if _, ok := dnsproviderremote.NewReconcileRemote().(Remote); !ok {
		t.Fatal("the production reconcile remote does not implement Remote")
	}
}

// 记录修复 rewrites the default line only: a per-line record the aggregated
// edge scheduler wrote on the owner (ADR 0008 §6.1) is kept.
func TestRepairKeepsOtherLineRecords(t *testing.T) {
	owner := "abc.cdn.example.com."
	overseas := zoneRecord("overseas", owner, dnscheck.RecordCNAME, "cf.example.net.", 60)
	overseas.Line = "境外"
	fixture := newMaintenanceFixture(t, zoneRecord("stale", owner, dnscheck.RecordA, "198.51.100.9", 300), overseas)
	fixture.allocate(owner, cnameallocation.TargetValues{A: []string{"192.0.2.1"}})
	reports := fixture.run(t, RepairJobKind, RepairItem(owner, []string{"192.0.2.1"}, nil))
	if len(reports) != 1 || reports[0].State != jobstate.ItemSucceeded {
		t.Fatalf("reports = %+v", reports)
	}
	for _, record := range fixture.reconcile.applied[0].Check.Provider.Records {
		if record.RecordID == "overseas" {
			t.Fatal("the overseas line record is in the default-line repair")
		}
	}
	if got := fixture.provider.values(owner, dnscheck.RecordCNAME); len(got) != 1 {
		t.Fatalf("overseas CNAME = %v", got)
	}
}
