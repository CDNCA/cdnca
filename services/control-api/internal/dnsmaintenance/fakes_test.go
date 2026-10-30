package dnsmaintenance

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeProvider is an in-memory DNS zone (the "假提供商").
type fakeProvider struct {
	records map[string]dnsproviderremote.ZoneRecord
	next    int
	deletes []string
}

func newFakeProvider(records ...dnsproviderremote.ZoneRecord) *fakeProvider {
	provider := &fakeProvider{records: map[string]dnsproviderremote.ZoneRecord{}}
	for _, record := range records {
		provider.records[record.ID] = record
	}
	return provider
}

func (provider *fakeProvider) ListZoneRecords(_ context.Context, _ dnsproviderremote.ProviderConfig, owner string) ([]dnsproviderremote.ZoneRecord, error) {
	result := make([]dnsproviderremote.ZoneRecord, 0)
	for _, record := range provider.records {
		if owner == "" || record.Name == owner {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (provider *fakeProvider) Mutate(_ context.Context, _ dnsproviderremote.ProviderConfig, operation dnscheck.ProviderOperation) (string, error) {
	switch operation.Action {
	case dnscheck.ProviderDelete:
		delete(provider.records, operation.RecordID)
		provider.deletes = append(provider.deletes, operation.RecordID)
		return operation.RecordID, nil
	case dnscheck.ProviderUpdate:
		record := provider.records[operation.RecordID]
		record.Value, record.TTL, record.Line, record.Weight = operation.Value, operation.TTL, operation.Line, operation.Weight
		provider.records[operation.RecordID] = record
		return operation.RecordID, nil
	default:
		provider.next++
		id := fmt.Sprintf("new-%d", provider.next)
		provider.records[id] = dnsproviderremote.ZoneRecord{ID: id, Name: operation.Name, Type: operation.Type,
			Value: operation.Value, TTL: operation.TTL, Line: operation.Line, Weight: operation.Weight}
		return id, nil
	}
}

func (provider *fakeProvider) values(owner string, recordType dnscheck.RecordType) []string {
	values := make([]string, 0)
	for _, record := range provider.records {
		if record.Name == owner && record.Type == recordType {
			values = append(values, fmt.Sprintf("%s/%d", record.Value, record.TTL))
		}
	}
	sort.Strings(values)
	return values
}

// fakeReconcile prepares the real dnscheck plan and applies it to the fake
// provider, then reports ready_to_commit / committed like the runtime.
type fakeReconcile struct {
	provider *fakeProvider
	tasks    map[uuid.UUID]dnsreconcile.Task
	applied  []dnsreconcile.ApplyRequest
}

func (reconcile *fakeReconcile) Apply(ctx context.Context, request dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	reconcile.applied = append(reconcile.applied, request)
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{IdempotencyKey: request.IdempotencyKey, Check: request.Check}, time.Now)
	if err != nil {
		return dnsreconcile.Task{}, dnsreconcile.ErrInvalidInput
	}
	for _, operation := range prepared.Result.Operations {
		if _, err := reconcile.provider.Mutate(ctx, dnsproviderremote.ProviderConfig{}, operation.Operation); err != nil {
			return dnsreconcile.Task{}, err
		}
	}
	task := dnsreconcile.Task{ID: uuid.New(), TenantID: request.TenantID, SiteID: request.SiteID, Revision: 1}
	task.Result.Status = dnscheck.TaskReadyToCommit
	task.Result.DeferredDeletes = prepared.Result.DeferredDeletes
	reconcile.tasks[task.ID] = task
	return task, nil
}

func (reconcile *fakeReconcile) Get(_ context.Context, _ uuid.UUID, id uuid.UUID) (dnsreconcile.Task, error) {
	return reconcile.tasks[id], nil
}

func (reconcile *fakeReconcile) Commit(_ context.Context, request dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	task := reconcile.tasks[request.TaskID]
	for _, deferred := range task.Result.DeferredDeletes { // deletes run at commit, like the runtime
		if _, err := reconcile.provider.Mutate(context.Background(), dnsproviderremote.ProviderConfig{}, deferred.Operation); err != nil {
			return dnsreconcile.Task{}, err
		}
	}
	task.Result.Status = dnscheck.TaskCommitted
	reconcile.tasks[task.ID] = task
	return task, nil
}

type fakeTargets struct {
	tenantID, scopeID uuid.UUID
	targets           map[string]RepairTarget
	serving           map[string]cnameallocation.TargetValues
	claimed           map[string]bool
}

func (targets *fakeTargets) PendingTenants(context.Context) ([]uuid.UUID, error) {
	return []uuid.UUID{targets.tenantID}, nil
}
func (targets *fakeTargets) TenantScope(context.Context, uuid.UUID) (uuid.UUID, error) {
	return targets.scopeID, nil
}
func (targets *fakeTargets) RepairTarget(_ context.Context, _, _ uuid.UUID, owner string) (RepairTarget, error) {
	target, ok := targets.targets[canonicalOwner(owner)]
	if !ok {
		return RepairTarget{}, pgx.ErrNoRows
	}
	return target, nil
}
func (targets *fakeTargets) RepairTargets(context.Context, uuid.UUID, uuid.UUID) ([]RepairTarget, error) {
	result := make([]RepairTarget, 0, len(targets.targets))
	for _, target := range targets.targets {
		result = append(result, target)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Owner < result[j].Owner })
	return result, nil
}
func (targets *fakeTargets) ServingValues(_ context.Context, target RepairTarget) (cnameallocation.TargetValues, error) {
	return targets.serving[target.Owner], nil
}
func (targets *fakeTargets) PublishSettings(context.Context, RepairTarget) (cnameallocation.PublishSettings, error) {
	return cnameallocation.PublishSettings{TTL: 600}, nil
}
func (targets *fakeTargets) ZoneApex(_ context.Context, target RepairTarget, _ string,
	_ map[string]string) (string, error) {
	return target.ZoneName, nil
}

func (targets *fakeTargets) ClaimedHostnames(context.Context, []uuid.UUID) (map[string]bool, error) {
	return targets.claimed, nil
}

type fakePlatform struct {
	tenant dnsacme.PlatformTenant
	zones  map[uuid.UUID]string
}

func (platform *fakePlatform) PlatformTenantCopies(context.Context) ([]dnsacme.PlatformTenant, error) {
	return []dnsacme.PlatformTenant{platform.tenant}, nil
}
func (platform *fakePlatform) PlatformCredentials(context.Context) (string, map[string]string, error) {
	return "dnspod_cn", map[string]string{"dp_id": "1", "dp_key": "k"}, nil
}
func (platform *fakePlatform) PlatformZoneNames(context.Context) (map[uuid.UUID]string, error) {
	return platform.zones, nil
}
func (platform *fakePlatform) PlatformZoneApex(_ context.Context, zoneID uuid.UUID, _ string,
	_ map[string]string) (string, error) {
	return platform.zones[zoneID], nil
}

type fakeJobs struct {
	claims  []jobstate.Claim
	reports []jobstate.Report
}

func (jobs *fakeJobs) Claim(_ context.Context, input jobstate.ClaimInput) ([]jobstate.Claim, error) {
	result := make([]jobstate.Claim, 0)
	remaining := jobs.claims[:0]
	for _, claim := range jobs.claims {
		if claim.Job.Kind == input.Kind {
			result = append(result, claim)
		} else {
			remaining = append(remaining, claim)
		}
	}
	jobs.claims = remaining
	return result, nil
}
func (jobs *fakeJobs) Heartbeat(context.Context, jobstate.HeartbeatInput) (time.Time, error) {
	return time.Now(), nil
}
func (jobs *fakeJobs) Report(_ context.Context, input jobstate.ReportInput) (jobstate.ReportResult, error) {
	jobs.reports = append(jobs.reports, input.Report)
	return jobstate.ReportResult{}, nil
}
