package cnameallocation

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// defaultPublishTTL is the CNAME record TTL when the tenant scope has no
// 节点管理 > DNS配置 TTL (dns_legacy_settings) yet.
const defaultPublishTTL uint32 = 300

// PublishSettings are the record attributes 节点管理 > DNS配置 controls: the
// TTL and, with "开启IP权重" on a provider that writes weights (DNSPod), the
// line endpoint weight of every address.
type PublishSettings struct {
	TTL  uint32
	Line string
	// Weights are keyed by (carrier, address): one IP on several carrier
	// lines (migration 500) keeps the weight of each line.
	Weights map[WeightKey]uint32
}

// WeightKey is one line group endpoint's carrier and canonical address.
type WeightKey struct {
	Carrier, Address string
}

// DefaultLineWeight is the weight the default line writes for an address:
// the endpoint on the default carrier ("") if there is one, otherwise the
// endpoint with the smallest carrier, so the answer does not depend on
// row order.
func (settings PublishSettings) DefaultLineWeight(address string) (uint32, bool) {
	if weight, ok := settings.Weights[WeightKey{Address: address}]; ok {
		return weight, true
	}
	carrier, weight, found := "", uint32(0), false
	for key, value := range settings.Weights {
		if key.Address == address && (!found || key.Carrier < carrier) {
			carrier, weight, found = key.Carrier, value, true
		}
	}
	return weight, found
}

// PropagationWindow is how long resolvers may keep serving a replaced
// answer: two TTLs, at least five minutes.
func PropagationWindow(ttl uint32) time.Duration {
	window := 2 * time.Duration(ttl) * time.Second
	if window < 5*time.Minute {
		window = 5 * time.Minute
	}
	return window
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// LoadPublishSettings reads the TTL of the tenant scope and, for the platform
// provider copy with IP weights enabled, the endpoint weights of the line
// group revision.
func LoadPublishSettings(ctx context.Context, database rowQuerier, scopeID, zoneID, groupID uuid.UUID,
	groupRevision int64) (PublishSettings, error) {
	settings := PublishSettings{TTL: defaultPublishTTL}
	var ttl *int32
	var providerID uuid.UUID
	var providerType string
	var weightEnabled bool
	err := database.QueryRow(ctx, `SELECT
			(SELECT ttl FROM dns_legacy_settings WHERE scope_id=$1),
			zone.provider_id, provider.provider_type,
			COALESCE((SELECT (settings.settings #>> '{dns_config,ip_weight}')::boolean
			          FROM platform_system_other_settings settings
			          JOIN access_scopes platform ON platform.id=settings.platform_scope_id
			           AND platform.kind='platform' AND platform.tenant_id IS NULL), false)
		FROM dns_zones zone JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		WHERE zone.scope_id=$1 AND zone.id=$2`, scopeID, zoneID).Scan(&ttl, &providerID, &providerType, &weightEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return PublishSettings{}, mapError(err)
	}
	if ttl != nil && *ttl > 0 {
		settings.TTL = uint32(*ttl)
	}
	if !weightEnabled || providerType != "dnspod_cn" || providerID != dnsacme.PlatformProviderCopyID(scopeID) ||
		groupID == uuid.Nil || groupRevision < 1 {
		return settings, nil
	}
	queryer, ok := database.(interface {
		Query(context.Context, string, ...any) (pgx.Rows, error)
	})
	if !ok {
		return settings, nil
	}
	// The line group is the tenant's own or the platform's (sold packages).
	rows, err := queryer.Query(ctx, `SELECT carrier, host(address), weight FROM node_line_endpoints
		WHERE (tenant_scope_id=$1 OR tenant_scope_id=(SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL))
		  AND line_group_id=$2 AND config_revision=$3`, scopeID, groupID, groupRevision)
	if err != nil {
		return PublishSettings{}, mapError(err)
	}
	type endpointWeight struct {
		carrier, address string
		weight           int16
	}
	weights, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (endpointWeight, error) {
		var value endpointWeight
		return value, row.Scan(&value.carrier, &value.address, &value.weight)
	})
	if err != nil {
		return PublishSettings{}, mapError(err)
	}
	settings.Line, settings.Weights = "默认", make(map[WeightKey]uint32, len(weights))
	for _, endpoint := range weights {
		if endpoint.weight >= 1 && endpoint.weight <= 100 {
			settings.Weights[WeightKey{Carrier: endpoint.carrier, Address: endpoint.address}] = uint32(endpoint.weight)
		}
	}
	return settings, nil
}

// PublishCheckRequest builds the reconcile request of one CNAME owner. The
// propagation window covers at least twice the TTL (dnscheck requires a
// window no shorter than the TTL).
func PublishCheckRequest(tenantID, siteID, zoneID uuid.UUID, zoneRevision int64, owner string, values TargetValues,
	settings PublishSettings) dnscheck.CheckRequest {
	if settings.TTL == 0 {
		settings.TTL = defaultPublishTTL
	}
	expected := make([]dnscheck.ExpectedRecord, 0, 2)
	if values.CNAME != "" {
		// A CNAME owner carries no other record; weights apply to addresses only.
		expected = append(expected, dnscheck.ExpectedRecord{Type: dnscheck.RecordCNAME, Values: []string{values.CNAME}})
		values.A, values.AAAA = nil, nil
	}
	for _, family := range []struct {
		recordType dnscheck.RecordType
		values     []string
	}{{dnscheck.RecordA, values.A}, {dnscheck.RecordAAAA, values.AAAA}} {
		if len(family.values) == 0 {
			continue
		}
		record := dnscheck.ExpectedRecord{Type: family.recordType, Values: family.values}
		for _, value := range family.values {
			if weight, ok := settings.DefaultLineWeight(value); ok {
				if record.Weights == nil {
					record.Weights = map[string]uint32{}
				}
				record.Weights[value] = weight
			}
		}
		expected = append(expected, record)
	}
	window := PropagationWindow(settings.TTL)
	return dnscheck.CheckRequest{TenantID: tenantID, SiteID: siteID, Name: owner, Expected: expected,
		TTL: settings.TTL, Line: settings.Line, PropagationWindow: window,
		Provider: dnscheck.ProviderSnapshot{TenantID: tenantID, SiteID: siteID, ZoneID: zoneID, Revision: zoneRevision}}
}
