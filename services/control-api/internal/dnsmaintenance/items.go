package dnsmaintenance

import (
	"context"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

// repair recomputes the owner's records (site CNAME label -> line group ->
// serving endpoints), lists what the provider has and runs the change through
// the DNS reconcile Apply/Commit path: missing records are added, wrong ones
// updated and extra ones deleted. It returns "" or a failure code.
func (worker *Worker) repair(ctx context.Context, claim jobstate.Claim, scopeID uuid.UUID, item string) string {
	if item == NothingToRepair {
		return ""
	}
	owner, ok := RepairOwner(item)
	if !ok {
		return CodeAllocationMissing
	}
	target, err := worker.targets.RepairTarget(ctx, scopeID, dnsacme.PlatformProviderCopyID(scopeID), owner)
	if err != nil {
		return CodeAllocationMissing
	}
	values, err := worker.targets.ServingValues(ctx, target)
	if err != nil {
		return CodeReconcileFailed
	}
	if values.CNAME == "" && len(values.A)+len(values.AAAA) == 0 {
		return CodeNoServingEndpoint
	}
	settings, err := worker.targets.PublishSettings(ctx, target)
	if err != nil {
		return CodeReconcileFailed
	}
	providerType, credentials, err := worker.platform.PlatformCredentials(ctx)
	if err != nil {
		return CodeProviderUnavailable
	}
	defer clear(credentials)
	apex, err := worker.targets.ZoneApex(ctx, target, providerType, credentials)
	if err != nil {
		return CodeProviderUnavailable
	}
	config := dnsproviderremote.ProviderConfig{TenantID: target.TenantID, ScopeID: target.ScopeID, TenantScopeID: target.ScopeID,
		ProviderID: target.ProviderID, ProviderType: providerType, ZoneID: target.ZoneID, ZoneName: target.ZoneName,
		ProviderZoneName: apex, Credentials: credentials}
	existing, err := worker.remote.ListZoneRecords(ctx, config, target.Owner)
	if err != nil {
		return CodeProviderUnavailable
	}
	check := cnameallocation.PublishCheckRequest(target.TenantID, target.SiteID, target.ZoneID, target.ZoneRevision,
		target.Owner, values, settings)
	seen := map[string]bool{}
	for _, record := range existing {
		if seen[record.ID] { // record IDs are unique (Huawei multi-value sets list <set>/<value>)
			continue
		}
		// Other lines are the aggregated edge's per-line records (ADR 0008 §6.1).
		if !cnameallocation.SameLine(record.Line, check.Line) {
			continue
		}
		seen[record.ID] = true
		check.Provider.Records = append(check.Provider.Records, dnscheck.ProviderRecord{RecordID: record.ID, Name: record.Name,
			Type: record.Type, Value: record.Value, TTL: record.TTL, Line: record.Line, Weight: record.Weight})
	}
	key := digest("dns-repair", claim.Job.ID.String(), item, strconv.FormatUint(uint64(claim.Job.Attempt), 10))
	requestID := claim.Job.RequestID
	if requestID == "" {
		requestID = target.RequestID
	}
	traceparent := "00-" + key[:32] + "-" + key[32:48] + "-01"
	task, err := worker.reconcile.Apply(ctx, dnsreconcile.ApplyRequest{TenantID: target.TenantID, SiteID: target.SiteID,
		ActorUserID: target.ActorUserID, IdempotencyKey: "dnsrepair-" + key[:48], RequestID: requestID,
		Traceparent: traceparent, ExpectedRevision: target.ZoneRevision, RequiredConsecutive: 3, Check: check})
	if err != nil {
		return CodeReconcileFailed
	}
	deadline := time.Now().Add(worker.config.ItemTimeout)
	lastBeat := time.Now()
	committing := false
	for {
		switch task.Result.Status {
		case dnscheck.TaskCommitted:
			return ""
		case dnscheck.TaskFailed, dnscheck.TaskCommitFailed, dnscheck.TaskCancelled, dnscheck.TaskTimedOut:
			return CodeReconcileFailed
		case dnscheck.TaskReadyToCommit:
			if !committing {
				committing = true
				committed, err := worker.reconcile.Commit(ctx, dnsreconcile.CommitRequest{TenantID: target.TenantID,
					SiteID: target.SiteID, TaskID: task.ID, ActorUserID: target.ActorUserID,
					IdempotencyKey: "dnsrepair-commit-" + key[:40], RequestID: requestID, Traceparent: traceparent,
					ExpectedRevision: task.Revision})
				if err != nil {
					return CodeReconcileFailed
				}
				task = committed
				continue
			}
		}
		if time.Now().After(deadline) {
			return CodeReconcileTimeout
		}
		select {
		case <-ctx.Done():
			return CodeReconcileTimeout
		case <-time.After(worker.config.TaskPoll):
		}
		if time.Since(lastBeat) > worker.config.LeaseDuration/4 {
			if worker.heartbeat(ctx, claim) != nil {
				return CodeReconcileTimeout
			}
			lastBeat = time.Now()
		}
		if task, err = worker.reconcile.Get(ctx, target.TenantID, task.ID); err != nil {
			return CodeReconcileFailed
		}
	}
}

// cleanup deletes one record listed by 清除CDN无关解析 after checking again
// that it still exists unchanged and its owner is still no allocated CNAME.
func (worker *Worker) cleanup(ctx context.Context, claim jobstate.Claim, scopeID uuid.UUID, item string) string {
	if item == NothingToClean {
		return ""
	}
	record, ok := ParseCleanupItem(item)
	if !ok {
		return CodeRecordChanged
	}
	zones, err := worker.platform.PlatformZoneNames(ctx)
	if err != nil {
		return CodeProviderUnavailable
	}
	zoneName, ok := zones[record.ZoneID]
	if !ok {
		return CodeRecordChanged
	}
	tenants, err := worker.platform.PlatformTenantCopies(ctx)
	if err != nil {
		return CodeProviderUnavailable
	}
	copies := make([]uuid.UUID, len(tenants))
	for index, tenant := range tenants {
		copies[index] = dnsacme.PlatformZoneCopyID(tenant.ScopeID, record.ZoneID)
	}
	claimed, err := worker.targets.ClaimedHostnames(ctx, copies)
	if err != nil {
		return CodeProviderUnavailable
	}
	if claimed[record.Name] || record.Name == canonicalOwner(zoneName) {
		return CodeRecordChanged
	}
	providerType, credentials, err := worker.platform.PlatformCredentials(ctx)
	if err != nil {
		return CodeProviderUnavailable
	}
	defer clear(credentials)
	apex, err := worker.platform.PlatformZoneApex(ctx, record.ZoneID, providerType, credentials)
	if err != nil {
		return CodeProviderUnavailable
	}
	config := providerConfig(dnsacme.PlatformTenant{TenantID: claim.Job.TenantID, ScopeID: scopeID}, providerType,
		credentials, record.ZoneID, zoneName, apex)
	current, err := worker.remote.ListZoneRecords(ctx, config, record.Name)
	if err != nil {
		return CodeProviderUnavailable
	}
	for _, found := range current {
		if found.ID != record.RecordID {
			continue
		}
		if recordTypeName(found.Type) != record.Type {
			return CodeRecordChanged
		}
		if _, err := worker.remote.Mutate(ctx, config, dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete,
			RecordID: found.ID, Name: found.Name, Type: found.Type, Value: found.Value, TTL: found.TTL}); err != nil {
			return CodeDeleteFailed
		}
		return ""
	}
	return "" // already gone
}

func recordTypeName(recordType dnscheck.RecordType) string {
	switch recordType {
	case dnscheck.RecordA:
		return "A"
	case dnscheck.RecordAAAA:
		return "AAAA"
	case dnscheck.RecordCNAME:
		return "CNAME"
	default:
		return "OTHER"
	}
}
