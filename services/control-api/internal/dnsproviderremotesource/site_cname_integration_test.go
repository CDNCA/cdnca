//go:build integration

package dnsproviderremotesource

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

// n10-dnshosted: the tenant's only zone is the platform CNAME zone
// cdn.example.com whose account hosts example.com (provider_zone_apex). The
// site's own www.example.com is written in example.com with the relative
// name www, and only while its record points into cdn.example.com.
func TestSiteCNAMEWriterUsesProviderZoneApex(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "site-cname-apex")
	cipher := mustSourceCipher(t, "site-cname-apex-key", 61)
	providerID := insertSourceProvider(t, pool, tenant, "dnspod_cn", "verified", cipher, `{"dp_id":"1","dp_key":"secret-apex-key"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "cdn.example.com")
	if _, err := pool.Exec(t.Context(), `UPDATE dns_zones SET provider_zone_apex='example.com' WHERE id=$1`, zoneID); err != nil {
		t.Fatal(err)
	}
	siteID := insertSourceReconcileSite(t, pool, tenant, "www.example.com")
	zone := &memoryZone{records: []dnsproviderremote.ZoneRecord{
		{ID: "www", Name: "www.example.com.", Type: dnscheck.RecordCNAME, Value: "pkg.cdn.example.com.", TTL: 300, Line: "默认"},
		{ID: "api", Name: "api.example.com.", Type: dnscheck.RecordCNAME, Value: "origin.example.net.", TTL: 300, Line: "默认"},
	}}
	writer, err := NewSiteCNAMEWriter(New(pool, cipher), zone)
	if err != nil {
		t.Fatal(err)
	}
	change, err := writer.Point(t.Context(), siteID, "www.example.com", "s1.cdn.example.com")
	if err != nil || !change.Changed || change.Before != "pkg.cdn.example.com" || zone.config.ZoneID != zoneID ||
		zone.config.ZoneName != "example.com" || zone.config.ProviderZoneName != "example.com" || zone.key != "secret-apex-key" {
		t.Fatalf("Point = %+v %v; config %s/%s", change, err, zone.config.ZoneName, zone.config.ProviderZoneName)
	}
	if len(zone.writes) != 1 || zone.writes[0].Name != "www.example.com." || zone.writes[0].Value != "s1.cdn.example.com." {
		t.Fatalf("writes = %+v", zone.writes)
	}
	// Not pointing into the CNAME zone, or no record at all: not taken over.
	for _, domain := range []string{"api.example.com", "new.example.com"} {
		if _, err := writer.Point(t.Context(), siteID, domain, "s1.cdn.example.com"); CNAMEFailureCode(err) != CNAMECodeForeign {
			t.Fatalf("%s: %v", domain, err)
		}
	}
	// The hosted apex itself still has no managing zone.
	if _, err := writer.Point(t.Context(), siteID, "example.com", "s1.cdn.example.com"); CNAMEFailureCode(err) != CNAMECodeNotHosted {
		t.Fatalf("apex: %v", err)
	}
	if len(zone.writes) != 1 {
		t.Fatalf("unexpected writes %+v", zone.writes)
	}
}
