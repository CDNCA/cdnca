//go:build integration

package dnsproviderremotesource

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

// memoryZone is a provider holding records in memory.
type memoryZone struct {
	mu      sync.Mutex
	records []dnsproviderremote.ZoneRecord
	config  dnsproviderremote.ProviderConfig
	key     string // dp_key seen during the call (the map is cleared after it)
	writes  []dnscheck.ProviderOperation
	ignore  bool // accept writes without applying them
	next    int
}

func (zone *memoryZone) ListZoneRecords(_ context.Context, config dnsproviderremote.ProviderConfig,
	owner string) ([]dnsproviderremote.ZoneRecord, error) {
	zone.mu.Lock()
	defer zone.mu.Unlock()
	zone.config, zone.key = config, config.Credentials["dp_key"]
	var out []dnsproviderremote.ZoneRecord
	for _, record := range zone.records {
		if record.Name == owner {
			out = append(out, record)
		}
	}
	return out, nil
}

func (zone *memoryZone) Mutate(_ context.Context, _ dnsproviderremote.ProviderConfig, operation dnscheck.ProviderOperation) (string, error) {
	zone.mu.Lock()
	defer zone.mu.Unlock()
	zone.writes = append(zone.writes, operation)
	if zone.ignore {
		return "ignored", nil
	}
	switch operation.Action {
	case dnscheck.ProviderCreate:
		zone.next++
		zone.records = append(zone.records, dnsproviderremote.ZoneRecord{ID: "r" + strconv.Itoa(zone.next), Name: operation.Name,
			Type: operation.Type, Value: operation.Value, TTL: operation.TTL, Line: operation.Line})
	case dnscheck.ProviderUpdate, dnscheck.ProviderDelete:
		for index, record := range zone.records {
			if record.ID != operation.RecordID {
				continue
			}
			if operation.Action == dnscheck.ProviderDelete {
				zone.records = append(zone.records[:index], zone.records[index+1:]...)
			} else {
				zone.records[index].Value, zone.records[index].TTL = operation.Value, operation.TTL
			}
			break
		}
	}
	return "ok", nil
}

// TestLineRecordsPublishOneLine: the per-line writer decrypts the zone's
// credentials, writes only the asked line of the owner (the default line and
// other owners stay), confirms by reading back and refuses owners outside
// the zone or the default line before any provider call.
func TestLineRecordsPublishOneLine(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "line-records")
	cipher := mustSourceCipher(t, "line-records-key", 61)
	providerID := insertSourceProvider(t, pool, tenant, "dnspod_cn", "verified", cipher, `{"dp_id":"1","dp_key":"secret-line-key"}`)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "cdn.example.com")
	siteID := insertSourceReconcileSite(t, pool, tenant, "lines.example.com")
	const owner = "s1.cdn.example.com."
	zone := &memoryZone{records: []dnsproviderremote.ZoneRecord{
		{ID: "default", Name: owner, Type: dnscheck.RecordA, Value: "192.0.2.1", TTL: 300, Line: "默认"},
		{ID: "stale", Name: owner, Type: dnscheck.RecordA, Value: "192.0.2.9", TTL: 300, Line: "境外"},
		{ID: "other", Name: "s2.cdn.example.com.", Type: dnscheck.RecordCNAME, Value: "x.example.net.", TTL: 60, Line: "境外"},
	}}
	writer, err := NewLineRecords(New(pool, cipher), zone)
	if err != nil {
		t.Fatal(err)
	}
	publication := LinePublication{TenantID: tenant.tenantID, SiteID: siteID, ZoneID: zoneID, Owner: "s1.cdn.example.com",
		Line: dnsproviderremote.LineOverseas, CNAME: "cf.cdn.example.net", TTL: 300}
	if err := writer.Publish(t.Context(), publication); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if zone.config.ProviderType != "dnspod_cn" || zone.key != "secret-line-key" || zone.config.ZoneName != "cdn.example.com" {
		t.Fatalf("provider config = %s %s", zone.config.ProviderType, zone.config.ZoneName)
	}
	if len(zone.config.Credentials) != 0 {
		t.Fatal("credentials not cleared after the call")
	}
	byID := map[string]dnsproviderremote.ZoneRecord{}
	for _, record := range zone.records {
		byID[record.ID] = record
	}
	if _, kept := byID["default"]; !kept || byID["other"].Value != "x.example.net." {
		t.Fatalf("default line or another owner touched: %+v", zone.records)
	}
	if _, kept := byID["stale"]; kept || len(zone.records) != 3 {
		t.Fatalf("overseas line = %+v", zone.records)
	}
	writes := len(zone.writes)
	if err := writer.Publish(t.Context(), publication); err != nil || len(zone.writes) != writes {
		t.Fatalf("converged republish wrote %d (%v)", len(zone.writes)-writes, err)
	}
	// Follow the default line: the overseas record goes, nothing else.
	publication.CNAME = ""
	if err := writer.Publish(t.Context(), publication); err != nil || len(zone.records) != 2 {
		t.Fatalf("follow default: %+v %v", zone.records, err)
	}
	// A provider that drops the write is not confirmed.
	zone.ignore = true
	publication.CNAME = "cf.cdn.example.net"
	if err := writer.Publish(t.Context(), publication); !errors.Is(err, ErrLineUnconfirmed) {
		t.Fatalf("dropped write = %v, want ErrLineUnconfirmed", err)
	}
	zone.ignore, writes = false, len(zone.writes)
	for _, bad := range []LinePublication{
		{TenantID: tenant.tenantID, SiteID: siteID, ZoneID: zoneID, Owner: "s1.other.example", Line: "境外", CNAME: "a.example.net", TTL: 60},
		{TenantID: tenant.tenantID, SiteID: siteID, ZoneID: zoneID, Owner: owner, Line: "默认", CNAME: "a.example.net", TTL: 60},
		{TenantID: uuid.New(), SiteID: siteID, ZoneID: zoneID, Owner: owner, Line: "境外", CNAME: "a.example.net", TTL: 60},
	} {
		if err := writer.Publish(t.Context(), bad); err == nil || len(zone.writes) != writes {
			t.Fatalf("%+v accepted (%v)", bad, err)
		}
	}
}
