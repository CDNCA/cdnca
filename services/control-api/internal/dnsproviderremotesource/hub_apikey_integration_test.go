//go:build integration

package dnsproviderremotesource

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

// TestHubAPIKeyScopesAndLiveRBAC (plugapi-S1): a tenant API key acts with
// its scopes ∩ the owner's live RBAC. A dns.read key lists but cannot
// write; a dns.records.manage key writes records (audited actor_ref
// api_key:<id>); revoking the owner's grant disables the key at once;
// another tenant's account stays 404 for a key too.
func TestHubAPIKeyScopesAndLiveRBAC(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	cipher := mustSourceCipher(t, "hub-key-apikey", 61)
	tenantA, tenantB := seedSourceTenant(t, pool, "hubkey-a"), seedSourceTenant(t, pool, "hubkey-b")
	grantSourceTenantPermissions(t, pool, tenantA, "dns.read", "dns.records.manage")
	grantSourceTenantPermissions(t, pool, tenantB, "dns.read", "dns.manage")
	accountA := insertSourceProvider(t, pool, tenantA, "dnspod_cn", "verified", cipher, `{"dp_id":"1","dp_key":"key-a"}`)
	accountB := insertSourceProvider(t, pool, tenantB, "dnspod_cn", "verified", cipher, `{"dp_id":"2","dp_key":"key-b"}`)
	remote := &memoryHubRemote{
		domains: map[string][]string{"key-a": {"a.example.com"}, "key-b": {"b.example.com"}},
		records: map[string][]dnsproviderremote.ZoneRecord{
			"a.example.com": {{ID: "a-www", Name: "www.a.example.com.", Type: dnscheck.RecordA, Value: "192.0.2.1", TTL: 600, Line: "默认"}},
			"b.example.com": {{ID: "b-www", Name: "www.b.example.com.", Type: dnscheck.RecordA, Value: "198.51.100.1", TTL: 600, Line: "默认"}},
		},
	}
	clock := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	hub, err := NewHub(New(pool, cipher), remote, audit.New(pool), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.RefreshDomains(ctx, hubActor(tenantA), uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if _, err := hub.RefreshDomains(ctx, hubActor(tenantB), uuid.Nil); err != nil {
		t.Fatal(err)
	}
	keyActor := func(tenant sourceTenant, keyID uuid.UUID, scopes ...string) HubActor {
		actor := hubActor(tenant)
		actor.APIKeyID, actor.APIKeyScopes = keyID, scopes
		return actor
	}
	readKey, writeKey := uuid.New(), uuid.New()
	reader := keyActor(tenantA, readKey, "dns.read")
	writer := keyActor(tenantA, writeKey, "dns.read", "dns.records.manage")
	create := func(key string) HubMutation {
		return HubMutation{ProviderID: accountA, Apex: "a.example.com", Action: "create", IdempotencyKey: key,
			Record: HubRecordInput{Name: "edge", Type: "A", Value: "192.0.2.20", TTL: 600, Line: "默认"}}
	}

	page, err := hub.ListDomains(ctx, reader, HubDomainQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ProviderID != accountA {
		t.Fatalf("dns.read key lists = %+v, %v", page, err)
	}
	if _, err := hub.Mutate(ctx, reader, create("key-read-1")); !errors.Is(err, ErrHubPermission) {
		t.Fatalf("dns.read key writes: %v", err)
	}
	// Scopes never widen the owner: a key claiming dns.manage the owner lacks.
	if _, err := hub.Mutate(ctx, keyActor(tenantA, uuid.New(), "dns.manage"), create("key-wide-1")); !errors.Is(err, ErrHubPermission) {
		t.Fatalf("dns.manage key without the owner's grant writes: %v", err)
	}
	created, err := hub.Mutate(ctx, writer, create("key-write-1"))
	if err != nil || created.State != "applied" || created.Status != 201 {
		t.Fatalf("dns.records.manage key create = %+v, %v", created, err)
	}
	var actorRef string
	if err := pool.QueryRow(ctx, `SELECT actor_ref FROM audit_events WHERE scope_id=$1 AND action='dns.hub.record.create'
		ORDER BY stream_position DESC LIMIT 1`, tenantA.scopeID).Scan(&actorRef); err != nil || actorRef != "api_key:"+writeKey.String() {
		t.Fatalf("audit actor_ref = %q, %v", actorRef, err)
	}

	// Cross-tenant: B's account is not found for A's key.
	if _, err := hub.ListRecords(ctx, writer, accountB, "b.example.com", HubRecordQuery{}); !errors.Is(err, ErrHubNotFound) {
		t.Fatalf("A key reads B's records: %v", err)
	}
	writes := len(remote.writes)
	cross := create("key-cross-1")
	cross.ProviderID, cross.Apex = accountB, "b.example.com"
	if _, err := hub.Mutate(ctx, writer, cross); !errors.Is(err, ErrHubNotFound) {
		t.Fatalf("A key writes B's account: %v", err)
	}
	if len(remote.writes) != writes {
		t.Fatal("a cross-tenant key write reached the provider")
	}

	// The owner loses the role granting dns.records.manage: the same key
	// stops writing (and reading: the role held dns.read too).
	if _, err := pool.Exec(ctx, `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
		tenantA.scopeID, tenantA.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Mutate(ctx, writer, create("key-write-2")); !errors.Is(err, ErrHubPermission) {
		t.Fatalf("key after the owner's grant was revoked: %v", err)
	}
	if _, err := hub.ListDomains(ctx, reader, HubDomainQuery{}); !errors.Is(err, ErrHubPermission) {
		t.Fatalf("read key after the owner's grant was revoked: %v", err)
	}
}
