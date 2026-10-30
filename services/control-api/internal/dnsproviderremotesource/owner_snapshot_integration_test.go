//go:build integration

package dnsproviderremotesource

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

type recordingLister struct {
	config dnsproviderremote.ProviderConfig
	owner  string
}

func (lister *recordingLister) ListZoneRecords(_ context.Context, config dnsproviderremote.ProviderConfig,
	owner string) ([]dnsproviderremote.ZoneRecord, error) {
	lister.config, lister.owner = config, owner
	return []dnsproviderremote.ZoneRecord{{ID: "rec-1", Name: owner, Type: dnscheck.RecordA, Value: "192.0.2.1", TTL: 300}}, nil
}

// The CNAME publication snapshot lists the owner's records with the zone's
// decrypted provider credentials, bound to tenant, site and zone.
func TestOwnerSnapshotListsOwnerRecordsWithZoneCredentials(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "owner-snapshot")
	cipher := mustSourceCipher(t, "owner-snapshot-key", 51)
	providerID := insertSourceProvider(t, pool, tenant, "cloudflare", "verified", cipher, `{"api_token":"sensitive-snapshot-token"}`)
	// Production stores credentials in the provider-bound envelope.
	keyID, ciphertext, err := cipher.EncryptCredential(dnsacme.CredentialBinding{TenantID: tenant.tenantID,
		ScopeID: tenant.scopeID, ProviderID: providerID}, []byte(`{"api_token":"sensitive-snapshot-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	setSourceCredentials(t, pool, providerID, keyID, ciphertext)
	zoneID := insertSourceZone(t, pool, tenant, providerID, "example.test")
	siteID := insertSourceReconcileSite(t, pool, tenant, "snapshot.example.test")
	lister := &recordingLister{}
	snapshot, err2 := NewOwnerSnapshot(New(pool, cipher), lister)
	if err2 != nil {
		t.Fatal(err2)
	}
	records, err := snapshot.OwnerRecords(t.Context(), tenant.tenantID, siteID, zoneID, "edge.example.test")
	if err != nil || len(records) != 1 || records[0].RecordID != "rec-1" || records[0].Value != "192.0.2.1" {
		t.Fatalf("OwnerRecords() = (%+v, %v)", records, err)
	}
	if lister.owner != "edge.example.test." || lister.config.ProviderID != providerID || lister.config.ZoneName != "example.test" ||
		lister.config.ProviderType != "cloudflare" {
		t.Fatalf("lister call = %q %+v", lister.owner, lister.config)
	}
	// An owner outside the zone, or another tenant's zone, is refused before any provider call.
	lister.owner = ""
	if _, err := snapshot.OwnerRecords(t.Context(), tenant.tenantID, siteID, zoneID, "edge.other.test"); err == nil || lister.owner != "" {
		t.Fatalf("owner outside the zone = %v (lister called with %q)", err, lister.owner)
	}
	if _, err := snapshot.OwnerRecords(t.Context(), uuid.New(), siteID, zoneID, "edge.example.test"); err == nil || lister.owner != "" {
		t.Fatalf("foreign tenant = %v", err)
	}
}
