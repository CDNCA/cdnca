//go:build integration

package dnsproviderremotesource

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// memoryHubRemote is a provider account holding domains and records in
// memory, keyed by the account the call was made for.
type memoryHubRemote struct {
	mu      sync.Mutex
	domains map[string][]string // dp_key -> hosted domains
	records map[string][]dnsproviderremote.ZoneRecord
	writes  []dnscheck.ProviderOperation
	lists   int
	keys    []string // dp_key of each call
	next    int
	drop    bool // accept a write without applying it
}

func (remote *memoryHubRemote) HostedDomains(_ context.Context, _ string, credentials map[string]string) ([]string, error) {
	remote.mu.Lock()
	defer remote.mu.Unlock()
	remote.lists++
	remote.keys = append(remote.keys, credentials["dp_key"])
	return append([]string(nil), remote.domains[credentials["dp_key"]]...), nil
}

func (remote *memoryHubRemote) ListHubRecords(_ context.Context, config dnsproviderremote.ProviderConfig, owner string) ([]dnsproviderremote.ZoneRecord, int, error) {
	remote.mu.Lock()
	defer remote.mu.Unlock()
	remote.keys = append(remote.keys, config.Credentials["dp_key"])
	var out []dnsproviderremote.ZoneRecord
	for _, record := range remote.records[config.ZoneName] {
		if owner == "" || record.Name == owner {
			out = append(out, record)
		}
	}
	return out, 0, nil
}

func (remote *memoryHubRemote) Lookup(context.Context, dnsproviderremote.ProviderConfig, dnscheck.ProviderOperation) (dnsproviderremote.ReconcileLookup, error) {
	return dnsproviderremote.ReconcileLookup{}, errors.New("not used")
}

func (remote *memoryHubRemote) Mutate(_ context.Context, config dnsproviderremote.ProviderConfig, operation dnscheck.ProviderOperation) (string, error) {
	remote.mu.Lock()
	defer remote.mu.Unlock()
	remote.writes = append(remote.writes, operation)
	if remote.drop {
		return "dropped", nil
	}
	zone := remote.records[config.ZoneName]
	switch operation.Action {
	case dnscheck.ProviderCreate:
		remote.next++
		id := "new-" + strconv.Itoa(remote.next)
		remote.records[config.ZoneName] = append(zone, dnsproviderremote.ZoneRecord{ID: id, Name: operation.Name,
			Type: operation.Type, Value: operation.Value, TTL: operation.TTL, Line: operation.Line, Weight: operation.Weight})
		return id, nil
	default:
		for index, record := range zone {
			if record.ID != operation.RecordID {
				continue
			}
			if operation.Action == dnscheck.ProviderDelete {
				remote.records[config.ZoneName] = append(zone[:index], zone[index+1:]...)
			} else {
				zone[index].Value, zone[index].TTL, zone[index].Line = operation.Value, operation.TTL, operation.Line
			}
			return record.ID, nil
		}
		return "", &dnsproviderremote.Error{Code: dnsproviderremote.CodeRecordMismatch}
	}
}

func grantSourceTenantPermissions(t *testing.T, pool *pgxpool.Pool, tenant sourceTenant, permissions ...string) {
	t.Helper()
	roleID := uuid.New()
	// 042 guard_system_role_mutation 只许 custom RBAC facts 建自定义角色；system 角色同样经
	// custom_rbac_effective_permissions 的 role_permissions 分支生效（dns.read/manage 不在受限名单）。
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'hub test',true)`,
		roleID, tenant.scopeID, "hub-"+roleID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	for _, permission := range permissions {
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		tenant.scopeID, tenant.userID, roleID); err != nil {
		t.Fatal(err)
	}
}

func hubActor(tenant sourceTenant) HubActor {
	return HubActor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant", RequestID: "hub-" + uuid.NewString()[:8]}
}

// TestHubTenantIsolationAndRecordLifecycle covers ADR 0020 §6 必测 for the
// DNS hub: tenant A never sees, refreshes, reads or writes tenant B's
// accounts, domains or records (404), the platform copy is never listed,
// dns.read cannot write, refresh is throttled per account, a write needs the
// value the member saw, a platform-managed record needs confirm_managed,
// Idempotency-Key replays, and every change is audited.
func TestHubTenantIsolationAndRecordLifecycle(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	cipher := mustSourceCipher(t, "hub-key", 59)
	tenantA, tenantB := seedSourceTenant(t, pool, "hub-a"), seedSourceTenant(t, pool, "hub-b")
	grantSourceTenantPermissions(t, pool, tenantA, "dns.read", "dns.manage")
	grantSourceTenantPermissions(t, pool, tenantB, "dns.read", "dns.manage")
	accountA := insertSourceProvider(t, pool, tenantA, "dnspod_cn", "verified", cipher, `{"dp_id":"1","dp_key":"key-a"}`)
	accountB := insertSourceProvider(t, pool, tenantB, "dnspod_cn", "verified", cipher, `{"dp_id":"2","dp_key":"key-b"}`)
	// A platform copy in A's scope (managed_by='platform') must never show.
	platformCopy := insertSourceProvider(t, pool, tenantA, "dnspod_cn", "verified", cipher, `{"dp_id":"3","dp_key":"key-platform"}`)
	if _, err := pool.Exec(ctx, `UPDATE dns_providers SET managed_by='platform' WHERE id=$1`, platformCopy); err != nil {
		t.Fatal(err)
	}
	remote := &memoryHubRemote{
		domains: map[string][]string{"key-a": {"a.example.com"}, "key-b": {"b.example.com"}, "key-platform": {"platform.example.com"}},
		records: map[string][]dnsproviderremote.ZoneRecord{
			"a.example.com": {
				{ID: "a-www", Name: "www.a.example.com.", Type: dnscheck.RecordA, Value: "192.0.2.1", TTL: 600, Line: "默认"},
				{ID: "a-spf", Name: "a.example.com.", Type: dnscheck.RecordTXT, Value: "v=spf1 -all", TTL: 600, Line: "默认"},
				{ID: "a-cdn", Name: "cdn.a.example.com.", Type: dnscheck.RecordCNAME, Value: "s1.cname.example.net.", TTL: 600, Line: "默认"},
			},
			"b.example.com": {{ID: "b-www", Name: "www.b.example.com.", Type: dnscheck.RecordA, Value: "198.51.100.1", TTL: 600, Line: "默认"}},
		},
	}
	clock := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	hub, err := NewHub(New(pool, cipher), remote, audit.New(pool), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	actorA, actorB := hubActor(tenantA), hubActor(tenantB)

	// Refresh: own accounts only, platform copy never listed.
	results, err := hub.RefreshDomains(ctx, actorA, uuid.Nil)
	if err != nil || len(results) != 1 || results[0].ProviderID != accountA || results[0].State != "refreshed" || results[0].DomainCount != 1 {
		t.Fatalf("refresh A = %+v, %v", results, err)
	}
	for _, key := range remote.keys {
		if key != "key-a" {
			t.Fatalf("refresh used credential %q", key)
		}
	}
	if _, err := hub.RefreshDomains(ctx, actorB, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	// Throttled within a minute, without a provider call.
	lists := remote.lists
	results, err = hub.RefreshDomains(ctx, actorA, accountA)
	if err != nil || results[0].State != "throttled" || results[0].RetryAfterSeconds != 60 || remote.lists != lists {
		t.Fatalf("throttled refresh = %+v, %v (lists %d -> %d)", results, err, lists, remote.lists)
	}
	page, err := hub.ListDomains(ctx, actorA, HubDomainQuery{})
	if err != nil || len(page.Accounts) != 1 || page.Accounts[0].ProviderID != accountA ||
		len(page.Items) != 1 || page.Items[0].Apex != "a.example.com" {
		t.Fatalf("A domains = %+v, %v", page, err)
	}

	// Cross-tenant: every read and write of B's account by A is not found.
	if _, err := hub.ListDomains(ctx, actorA, HubDomainQuery{ProviderID: accountB}); !errors.Is(err, ErrHubNotFound) {
		t.Fatalf("A lists B's account: %v", err)
	}
	if _, err := hub.RefreshDomains(ctx, actorA, accountB); !errors.Is(err, ErrHubNotFound) {
		t.Fatalf("A refreshes B's account: %v", err)
	}
	if _, err := hub.RefreshDomains(ctx, actorA, platformCopy); !errors.Is(err, ErrHubNotFound) {
		t.Fatalf("A refreshes the platform copy: %v", err)
	}
	if _, err := hub.ListRecords(ctx, actorA, accountB, "b.example.com", HubRecordQuery{}); !errors.Is(err, ErrHubNotFound) {
		t.Fatalf("A reads B's records: %v", err)
	}
	// A's own account with B's domain is not in A's list either.
	if _, err := hub.ListRecords(ctx, actorA, accountA, "b.example.com", HubRecordQuery{}); !errors.Is(err, ErrHubNotFound) {
		t.Fatalf("A reads B's domain through its own account: %v", err)
	}
	writes := len(remote.writes)
	for _, mutation := range []HubMutation{
		{ProviderID: accountB, Apex: "b.example.com", Action: "create", IdempotencyKey: "x-1",
			Record: HubRecordInput{Name: "evil", Type: "A", Value: "192.0.2.66", TTL: 600}},
		{ProviderID: accountB, Apex: "b.example.com", Action: "delete", IdempotencyKey: "x-2", RecordRef: encodeHubRecordRef("b-www"),
			Expected: &HubRecordInput{Name: "www", Type: "A", Value: "198.51.100.1", TTL: 600}},
		{ProviderID: platformCopy, Apex: "platform.example.com", Action: "create", IdempotencyKey: "x-3",
			Record: HubRecordInput{Name: "evil", Type: "A", Value: "192.0.2.66", TTL: 600}},
	} {
		if _, err := hub.Mutate(ctx, actorA, mutation); !errors.Is(err, ErrHubNotFound) {
			t.Fatalf("A mutates %s: %v", mutation.Apex, err)
		}
	}
	if len(remote.writes) != writes {
		t.Fatal("a cross-tenant write reached the provider")
	}
	// A session of another kind, or a member without dns.manage, cannot write.
	if _, err := hub.ListDomains(ctx, HubActor{UserID: tenantA.userID, ScopeID: tenantA.scopeID, ScopeKind: "platform"}, HubDomainQuery{}); !errors.Is(err, ErrHubPermission) {
		t.Fatalf("platform-kind actor: %v", err)
	}
	reader := seedSourceTenant(t, pool, "hub-reader")
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, tenantA.scopeID, reader.userID); err != nil {
		t.Fatal(err)
	}
	readerInA := sourceTenant{tenantID: tenantA.tenantID, scopeID: tenantA.scopeID, userID: reader.userID}
	grantSourceTenantPermissions(t, pool, readerInA, "dns.read")
	if _, err := hub.ListRecords(ctx, hubActor(readerInA), accountA, "a.example.com", HubRecordQuery{}); err != nil {
		t.Fatalf("dns.read lists records: %v", err)
	}
	if _, err := hub.Mutate(ctx, hubActor(readerInA), HubMutation{ProviderID: accountA, Apex: "a.example.com", Action: "create",
		IdempotencyKey: "r-1", Record: HubRecordInput{Name: "r", Type: "A", Value: "192.0.2.5", TTL: 600}}); !errors.Is(err, ErrHubPermission) {
		t.Fatalf("dns.read writes: %v", err)
	}

	// Records: TXT included, platform-managed CNAME marked.
	siteID := insertSourceReconcileSite(t, pool, tenantA, "cdn.a.example.com")
	if _, err := pool.Exec(ctx, `UPDATE sites SET cname='s1.cname.example.net' WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO site_domain_facts(scope_id,site_id,site_revision,action,canonical_domain,
		actor_scope_id,actor_user_id,request_id,occurred_at) VALUES($1,$2,1,'activate','cdn.a.example.com',$1,$3,'hub-seed',now())`,
		tenantA.scopeID, siteID, tenantA.userID); err != nil {
		t.Fatal(err)
	}
	list, err := hub.ListRecords(ctx, actorA, accountA, "a.example.com", HubRecordQuery{})
	if err != nil || len(list.Items) != 3 {
		t.Fatalf("A records = %+v, %v", list, err)
	}
	byName := map[string]HubRecord{}
	for _, item := range list.Items {
		byName[item.Name+"/"+item.Type] = item
	}
	if byName["@/TXT"].Value != "v=spf1 -all" || byName["cdn/CNAME"].Managed == nil ||
		byName["cdn/CNAME"].Managed.SiteID != siteID.String() || byName["www/A"].Managed != nil {
		t.Fatalf("records = %+v", byName)
	}
	var cached *int
	if err := pool.QueryRow(ctx, `SELECT record_count FROM tenant_dns_domains WHERE scope_id=$1 AND apex='a.example.com'`,
		tenantA.scopeID).Scan(&cached); err != nil || cached == nil || *cached != 3 {
		t.Fatalf("record_count = %v, %v", cached, err)
	}

	// Create TXT, replay with the same key, reuse the key for another body.
	create := HubMutation{ProviderID: accountA, Apex: "a.example.com", Action: "create", IdempotencyKey: "create-1",
		Record: HubRecordInput{Name: "_verify", Type: "TXT", Value: "site-verification=abc 123", TTL: 600}}
	created, err := hub.Mutate(ctx, actorA, create)
	if err != nil || created.State != "applied" || created.Status != 201 || created.Record == nil || created.Record.Value != "site-verification=abc 123" {
		t.Fatalf("create = %+v, %v", created, err)
	}
	writes = len(remote.writes)
	replayed, err := hub.Mutate(ctx, actorA, create)
	if err != nil || replayed.OpID != created.OpID || len(remote.writes) != writes {
		t.Fatalf("replay = %+v, %v (writes %d)", replayed, err, len(remote.writes)-writes)
	}
	reused := create
	reused.Record.Value = "other"
	if _, err := hub.Mutate(ctx, actorA, reused); !errors.Is(err, ErrHubIdempotency) {
		t.Fatalf("reused key: %v", err)
	}

	// Update with a stale expected value is refused with the current record.
	stale := HubMutation{ProviderID: accountA, Apex: "a.example.com", Action: "update", IdempotencyKey: "update-1",
		RecordRef: byName["www/A"].RecordRef, Record: HubRecordInput{Name: "www", Type: "A", Value: "192.0.2.2", TTL: 600},
		Expected: &HubRecordInput{Name: "www", Type: "A", Value: "192.0.2.99", TTL: 600}}
	var changed *HubChangedError
	if _, err := hub.Mutate(ctx, actorA, stale); !errors.As(err, &changed) || changed.Current == nil || changed.Current.Value != "192.0.2.1" {
		t.Fatalf("stale update: %v", err)
	}
	stale.Expected.Value, stale.IdempotencyKey = "192.0.2.1", "update-2"
	updated, err := hub.Mutate(ctx, actorA, stale)
	if err != nil || updated.State != "applied" || updated.Record == nil || updated.Record.Value != "192.0.2.2" {
		t.Fatalf("update = %+v, %v", updated, err)
	}

	// Deleting the platform-managed CNAME needs confirm_managed.
	remove := HubMutation{ProviderID: accountA, Apex: "a.example.com", Action: "delete", IdempotencyKey: "delete-1",
		RecordRef: byName["cdn/CNAME"].RecordRef, Expected: &HubRecordInput{Name: "cdn", Type: "CNAME", Value: "s1.cname.example.net", TTL: 600}}
	var managed *HubManagedError
	if _, err := hub.Mutate(ctx, actorA, remove); !errors.As(err, &managed) || managed.Managed.Kind != "site_cname" {
		t.Fatalf("managed delete: %v", err)
	}
	remove.ConfirmManaged, remove.IdempotencyKey = true, "delete-2"
	if result, err := hub.Mutate(ctx, actorA, remove); err != nil || result.State != "applied" || result.Status != 200 {
		t.Fatalf("confirmed delete = %+v, %v", result, err)
	}

	// A provider that drops the write reads back as uncertain (202).
	remote.drop = true
	dropped, err := hub.Mutate(ctx, actorA, HubMutation{ProviderID: accountA, Apex: "a.example.com", Action: "create",
		IdempotencyKey: "create-dropped", Record: HubRecordInput{Name: "lost", Type: "A", Value: "192.0.2.7", TTL: 600}})
	if err != nil || dropped.State != "uncertain" || dropped.Status != 202 {
		t.Fatalf("dropped create = %+v, %v", dropped, err)
	}
	remote.drop = false

	// Operations and audit events stay in A's scope.
	var ops, otherOps int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE scope_id=$1), count(*) FILTER (WHERE scope_id<>$1)
		FROM tenant_dns_record_ops`, tenantA.scopeID).Scan(&ops, &otherOps); err != nil || ops != 4 || otherOps != 0 {
		t.Fatalf("ops = %d other = %d, %v", ops, otherOps, err)
	}
	rows, err := pool.Query(ctx, `SELECT action, result FROM audit_events WHERE scope_id=$1 AND action LIKE 'dns.hub.%' ORDER BY stream_position`,
		tenantA.scopeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action, result string
		if err := rows.Scan(&action, &result); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, action+":"+result)
	}
	want := []string{"dns.hub.domain.refresh:success", "dns.hub.record.create:success", "dns.hub.record.update:success",
		"dns.hub.record.delete:success", "dns.hub.record.create:success"}
	if len(actions) != len(want) {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
	for index := range want {
		if actions[index] != want[index] {
			t.Fatalf("audit actions = %v, want %v", actions, want)
		}
	}
	var leaked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action LIKE 'dns.hub.record.%'`,
		tenantB.scopeID).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("B audit hub record events = %d, %v", leaked, err)
	}
}
