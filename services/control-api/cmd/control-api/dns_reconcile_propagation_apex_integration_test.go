//go:build integration

package main

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type recordingPropagationApexSource struct {
	apex  string
	calls int
}

func (source *recordingPropagationApexSource) PropagationZoneApex(_ context.Context, _, _, _ uuid.UUID) (string, error) {
	source.calls++
	return source.apex, nil
}

// N14: the propagation check of a CNAME subdomain zone (cdn.example.test)
// asks the authoritative servers of the hosted apex (example.test), read
// from dns_zones.provider_zone_apex; a zone saved before 473 (NULL apex)
// gets it from the apex source once, as the mutation path does.
func TestDNSReconcilePropagationContextUsesHostedApex(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	fixture := seedDNSRuntimeRecovery(t, pool, 1)
	storedZone, lazyZone := uuid.New(), uuid.New()
	for _, zone := range []struct {
		id   uuid.UUID
		name string
		apex any
	}{{storedZone, "cdn.example.test", "example.test"}, {lazyZone, "edge.example.test", nil}} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(id,scope_id,provider_id,name,status,
			created_by_user_id,updated_by_user_id,provider_zone_apex) VALUES($1,$2,$3,$4,'draft',$5,$5,$6)`,
			zone.id, fixture.scopeID, fixture.providerID, zone.name, fixture.userID, zone.apex); err != nil {
			t.Fatal(err)
		}
	}
	apex := &recordingPropagationApexSource{apex: "example.test"}
	resolver := &dnsReconcilePropagationContextResolver{pool: pool, apex: apex}

	stored, err := resolver.ResolvePropagationContext(t.Context(), fixture.tenantID, fixture.siteID, storedZone, fixture.userID)
	if err != nil || stored.Zone != "example.test" || stored.ZoneID != storedZone || apex.calls != 0 {
		t.Fatalf("stored apex context = (%+v, %v), apex lookups %d; want example.test without lookup", stored, err, apex.calls)
	}
	lazy, err := resolver.ResolvePropagationContext(t.Context(), fixture.tenantID, fixture.siteID, lazyZone, fixture.userID)
	if err != nil || lazy.Zone != "example.test" || apex.calls != 1 {
		t.Fatalf("lazy apex context = (%+v, %v), apex lookups %d; want example.test after one lookup", lazy, err, apex.calls)
	}
	// an apex that does not cover the zone is refused, not asked
	apex.apex = "other.test"
	if _, err := resolver.ResolvePropagationContext(t.Context(), fixture.tenantID, fixture.siteID, lazyZone, fixture.userID); err == nil {
		t.Fatal("non-covering apex accepted")
	}
	// the zone equal to its hosted domain keeps its own name
	same, err := resolver.ResolvePropagationContext(t.Context(), fixture.tenantID, fixture.siteID, fixture.zoneID, fixture.userID)
	if err != nil || same.Zone != "example.test" {
		t.Fatalf("apex zone context = (%+v, %v)", same, err)
	}
}
