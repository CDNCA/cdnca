package dnsmaintenance

import (
	"context"
	"errors"
	"sort"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

// Platform is the 节点管理 > DNS配置 source (dnsacme.Service).
type Platform interface {
	PlatformTenantCopies(context.Context) ([]dnsacme.PlatformTenant, error)
	PlatformCredentials(context.Context) (string, map[string]string, error)
	PlatformZoneNames(context.Context) (map[uuid.UUID]string, error)
	// PlatformZoneApex is the hosted domain of a platform CNAME domain,
	// looked up once for domains saved before migration 473.
	PlatformZoneApex(ctx context.Context, zoneID uuid.UUID, providerType string, credentials map[string]string) (string, error)
}

// Job is one background job to create: its tenant and result items. A
// cleanup job also carries the full record behind each item (by item text),
// stored with the job (migration 686).
type Job struct {
	TenantID uuid.UUID
	ScopeID  uuid.UUID
	Items    []string
	Records  map[string]CleanupRecord
}

// PlannerStore is the Store subset the planner uses (faked in tests).
type PlannerStore interface {
	RepairTargets(context.Context, uuid.UUID, uuid.UUID) ([]RepairTarget, error)
	ServingValues(context.Context, RepairTarget) (cnameallocation.TargetValues, error)
	ClaimedHostnames(context.Context, []uuid.UUID) (map[string]bool, error)
}

type Planner struct {
	store    PlannerStore
	platform Platform
	lister   dnsproviderremote.ZoneRecordLister
}

func NewPlanner(store PlannerStore, platform Platform, lister dnsproviderremote.ZoneRecordLister) (*Planner, error) {
	if store == nil || platform == nil || lister == nil {
		return nil, ErrInvalidInput
	}
	return &Planner{store: store, platform: platform, lister: lister}, nil
}

// PlanRepair returns one job per tenant scope with settled CNAME owners on
// the platform provider copy (one item per owner). Without any owner, the
// first tenant gets a single NothingToRepair item.
func (planner *Planner) PlanRepair(ctx context.Context) ([]Job, error) {
	tenants, err := planner.platform.PlatformTenantCopies(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		return nil, ErrNoTenant
	}
	jobs := make([]Job, 0, len(tenants))
	for _, tenant := range tenants {
		targets, err := planner.store.RepairTargets(ctx, tenant.ScopeID, dnsacme.PlatformProviderCopyID(tenant.ScopeID))
		if err != nil {
			return nil, err
		}
		items, seen := make([]string, 0, len(targets)), map[string]bool{}
		for _, target := range targets {
			values, err := planner.store.ServingValues(ctx, target)
			if err != nil {
				return nil, err
			}
			item := RepairItem(target.Owner, values.A, values.AAAA)
			if !seen[item] {
				seen[item] = true
				items = append(items, item)
			}
		}
		if len(items) > 0 {
			jobs = append(jobs, Job{TenantID: tenant.TenantID, ScopeID: tenant.ScopeID, Items: items})
		}
	}
	if len(jobs) == 0 {
		jobs = append(jobs, Job{TenantID: tenants[0].TenantID, ScopeID: tenants[0].ScopeID, Items: []string{NothingToRepair}})
	}
	return jobs, nil
}

// PlanCleanup lists every platform CNAME domain at the provider and returns
// one job (first tenant) with an item per A/AAAA/CNAME record that is not the
// zone apex and whose owner is no allocated CNAME hostname of any tenant.
// Records of other types (NS, SOA, MX, TXT, ...) are never listed.
func (planner *Planner) PlanCleanup(ctx context.Context) ([]Job, error) {
	tenants, err := planner.platform.PlatformTenantCopies(ctx)
	if err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		return nil, ErrNoTenant
	}
	host := tenants[0]
	providerType, credentials, err := planner.platform.PlatformCredentials(ctx)
	if errors.Is(err, dnsacme.ErrPlatformNotConfigured) {
		return nil, ErrNotConfigured
	}
	if err != nil {
		return nil, ErrProviderListed
	}
	defer clear(credentials)
	zones, err := planner.platform.PlatformZoneNames(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(zones))
	for id := range zones {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return zones[ids[i]] < zones[ids[j]] })
	items, planned := make([]string, 0), map[string]CleanupRecord{}
	for _, zoneID := range ids {
		claimed, err := planner.claimed(ctx, tenants, zoneID)
		if err != nil {
			return nil, err
		}
		apex, err := planner.platform.PlatformZoneApex(ctx, zoneID, providerType, credentials)
		if err != nil {
			return nil, ErrProviderListed
		}
		config := providerConfig(host, providerType, credentials, zoneID, zones[zoneID], apex)
		records, err := planner.lister.ListZoneRecords(ctx, config, "")
		if err != nil {
			return nil, ErrProviderListed
		}
		zoneOwner := canonicalOwner(zones[zoneID])
		for _, record := range records {
			if record.Name == zoneOwner || claimed[record.Name] {
				continue
			}
			full := CleanupRecord{ZoneID: zoneID, Name: canonicalOwner(record.Name),
				Type: recordTypeName(record.Type), Value: record.Value, RecordID: record.ID}
			item := CleanupItem(full)
			if _, seen := planned[item]; !seen {
				planned[item] = full
				items = append(items, item)
			}
		}
	}
	if len(items) == 0 {
		return []Job{{TenantID: host.TenantID, ScopeID: host.ScopeID, Items: []string{NothingToClean}}}, nil
	}
	return []Job{{TenantID: host.TenantID, ScopeID: host.ScopeID, Items: items, Records: planned}}, nil
}

func (planner *Planner) claimed(ctx context.Context, tenants []dnsacme.PlatformTenant, zoneID uuid.UUID) (map[string]bool, error) {
	copies := make([]uuid.UUID, len(tenants))
	for index, tenant := range tenants {
		copies[index] = dnsacme.PlatformZoneCopyID(tenant.ScopeID, zoneID)
	}
	return planner.store.ClaimedHostnames(ctx, copies)
}

func providerConfig(tenant dnsacme.PlatformTenant, providerType string, credentials map[string]string,
	zoneID uuid.UUID, zoneName, apex string) dnsproviderremote.ProviderConfig {
	scopeCopy := make(map[string]string, len(credentials))
	for key, value := range credentials {
		scopeCopy[key] = value
	}
	return dnsproviderremote.ProviderConfig{TenantID: tenant.TenantID, ScopeID: tenant.ScopeID, TenantScopeID: tenant.ScopeID,
		ProviderID: dnsacme.PlatformProviderCopyID(tenant.ScopeID), ProviderType: providerType,
		ZoneID: dnsacme.PlatformZoneCopyID(tenant.ScopeID, zoneID), ZoneName: zoneName, ProviderZoneName: apex,
		Credentials: scopeCopy}
}
