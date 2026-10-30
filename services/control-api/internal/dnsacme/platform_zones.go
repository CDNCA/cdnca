package dnsacme

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type rowsQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *Store) ListPlatformZones(ctx context.Context, query PlatformZoneQuery) (PlatformZonePage, error) {
	_, doc, err := loadPlatformDocument(ctx, s.pool, false)
	if err != nil {
		return PlatformZonePage{}, err
	}
	_, copies, err := platformCopyIDs(ctx, s.pool, doc.Zones)
	if err != nil {
		return PlatformZonePage{}, err
	}
	inUse, err := platformZonesInUse(ctx, s.pool, copies)
	if err != nil {
		return PlatformZonePage{}, err
	}
	matched := make([]PlatformZone, 0, len(doc.Zones))
	for _, zone := range doc.Zones {
		if query.Search != "" && !strings.Contains(zone.Name, query.Search) {
			continue
		}
		matched = append(matched, PlatformZone{ID: zone.ID, DisplayID: zone.DisplayID, Name: zone.Name, Remark: zone.Remark,
			InUse: inUse[zone.ID], RandomAllocation: zone.RandomAllocation, Revision: zone.Revision,
			CreatedAt: zone.CreatedAt, UpdatedAt: zone.UpdatedAt})
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].DisplayID < matched[j].DisplayID })
	page := PlatformZonePage{Items: []PlatformZone{}, Total: len(matched)}
	start := (query.Page - 1) * query.Limit
	if start < len(matched) {
		page.Items = matched[start:min(start+query.Limit, len(matched))]
	}
	return page, nil
}

func (s *Store) CreatePlatformZone(ctx context.Context, actor Actor, request PlatformZoneRequest, digest [32]byte) (PlatformZone, error) {
	var result PlatformZone
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replay, err := reserveWrite(ctx, tx, actor, actor.ScopeID, "dns.platform.zone.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		scopeID, doc, err := loadPlatformDocument(ctx, tx, true)
		if err != nil {
			return err
		}
		for _, zone := range doc.Zones {
			if zone.Name == request.Name {
				return ErrConflict
			}
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		doc.NextZoneID++
		zone := platformZoneV{ID: id, DisplayID: doc.NextZoneID, Name: request.Name, Remark: request.Remark,
			ProviderZoneApex: request.ProviderZoneApex, RandomAllocation: request.RandomAllocation != nil && *request.RandomAllocation,
			Revision: 1, CreatedAt: now, UpdatedAt: now}
		doc.Zones = append(doc.Zones, zone)
		if err := savePlatformDocument(ctx, tx, scopeID, doc); err != nil {
			return err
		}
		result = PlatformZone{ID: id, DisplayID: zone.DisplayID, Name: zone.Name, Remark: zone.Remark,
			RandomAllocation: zone.RandomAllocation, Revision: 1, CreatedAt: now, UpdatedAt: now}
		if err := s.appendAudit(ctx, tx, actor, actor.ScopeID, request.RequestID, "dns.platform.zone.create",
			"dns_platform_zone", id, map[string]any{"name": zone.Name, "remark": zone.Remark,
				"random_allocation": zone.RandomAllocation}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.platform.zone.create", request.IdempotencyKey, id, result)
	})
	return result, err
}

func (s *Store) UpdatePlatformZone(ctx context.Context, actor Actor, request PlatformZoneRequest, digest [32]byte) (PlatformZone, error) {
	var result PlatformZone
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replay, err := reserveWrite(ctx, tx, actor, actor.ScopeID, "dns.platform.zone.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		scopeID, doc, err := loadPlatformDocument(ctx, tx, true)
		if err != nil {
			return err
		}
		index := -1
		for position, zone := range doc.Zones {
			if zone.ID == request.ID {
				index = position
			} else if zone.Name == request.Name {
				return ErrConflict
			}
		}
		if index < 0 {
			return ErrNotFound
		}
		zone := doc.Zones[index]
		if zone.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		_, copies, err := platformCopyIDs(ctx, tx, []platformZoneV{zone})
		if err != nil {
			return err
		}
		inUse, err := platformZonesInUse(ctx, tx, copies)
		if err != nil {
			return err
		}
		// Allocated hostnames end in the domain name; a used domain keeps its name.
		if zone.Name != request.Name && inUse[zone.ID] {
			return ErrPlatformZoneInUse
		}
		if request.ProviderZoneApex != "" || zone.Name != request.Name {
			zone.ProviderZoneApex = request.ProviderZoneApex
		}
		zone.Name, zone.Remark, zone.Revision, zone.UpdatedAt = request.Name, request.Remark, zone.Revision+1, time.Now().UTC()
		// Changing the flag moves no allocated CNAME; only new ones draw.
		if request.RandomAllocation != nil {
			zone.RandomAllocation = *request.RandomAllocation
		}
		doc.Zones[index] = zone
		if err := savePlatformDocument(ctx, tx, scopeID, doc); err != nil {
			return err
		}
		result = PlatformZone{ID: zone.ID, DisplayID: zone.DisplayID, Name: zone.Name, Remark: zone.Remark,
			InUse: inUse[zone.ID], RandomAllocation: zone.RandomAllocation, Revision: zone.Revision,
			CreatedAt: zone.CreatedAt, UpdatedAt: zone.UpdatedAt}
		if err := s.appendAudit(ctx, tx, actor, actor.ScopeID, request.RequestID, "dns.platform.zone.update",
			"dns_platform_zone", zone.ID, map[string]any{"name": zone.Name, "remark": zone.Remark,
				"random_allocation": zone.RandomAllocation}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.platform.zone.update", request.IdempotencyKey, zone.ID, result)
	})
	return result, err
}

// DeletePlatformZone removes a CNAME domain and its tenant copies. A domain
// with allocated CNAME hostnames is refused (ErrPlatformZoneInUse). When the
// removed copy was a tenant's default allocation zone, the oldest remaining
// platform copy becomes the default.
func (s *Store) DeletePlatformZone(ctx context.Context, actor Actor, request PlatformZoneRequest, digest [32]byte) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replay, err := reserveWrite(ctx, tx, actor, actor.ScopeID, "dns.platform.zone.delete", request.IdempotencyKey, digest)
		if err != nil || replay != nil {
			return err
		}
		scopeID, doc, err := loadPlatformDocument(ctx, tx, true)
		if err != nil {
			return err
		}
		index := -1
		for position, zone := range doc.Zones {
			if zone.ID == request.ID {
				index = position
			}
		}
		if index < 0 {
			return ErrNotFound
		}
		zone := doc.Zones[index]
		if zone.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		providers, copies, err := platformCopyIDs(ctx, tx, []platformZoneV{zone})
		if err != nil {
			return err
		}
		inUse, err := platformZonesInUse(ctx, tx, copies)
		if err != nil {
			return err
		}
		if inUse[zone.ID] {
			return ErrPlatformZoneInUse
		}
		if len(providers) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM dns_zones WHERE id = ANY($1)`, copies[zone.ID]); err != nil {
				if isForeignKeyViolation(err) {
					return ErrPlatformZoneInUse
				}
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE dns_zones SET is_default=true
				WHERE id IN (SELECT DISTINCT ON (candidate.scope_id) candidate.id FROM dns_zones candidate
				  WHERE candidate.provider_id = ANY($1) AND NOT EXISTS (
				    SELECT 1 FROM dns_zones current WHERE current.scope_id=candidate.scope_id AND current.is_default)
				  ORDER BY candidate.scope_id, candidate.created_at, candidate.id)`, providers); err != nil {
				return err
			}
		}
		doc.Zones = append(doc.Zones[:index], doc.Zones[index+1:]...)
		if err := savePlatformDocument(ctx, tx, scopeID, doc); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, actor.ScopeID, request.RequestID, "dns.platform.zone.delete",
			"dns_platform_zone", zone.ID, map[string]any{"name": zone.Name}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.platform.zone.delete", request.IdempotencyKey, zone.ID,
			map[string]string{"id": zone.ID.String()})
	})
}
