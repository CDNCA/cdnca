//go:build integration

package site

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Migration 490: 网站列表 > 默认设置 and 建站「DNS API（自动添加记录）」.

func TestTenantSiteDefaultsIsolationIdempotencyAndCreate(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a, b := f.a.siteActor(), f.b.siteActor()

	create := func(actor Actor, name, value, key string) (SiteUserDefault, error) {
		return f.sites.CreateUserDefault(ctx, actor, SiteUserDefaultCreateRequest{
			Fields: SiteUserDefaultFields{SettingName: name, Value: value}, IdempotencyKey: key, RequestID: key})
	}
	ports, err := create(a, SiteDefaultHTTPListenPort, "8080, 8081", "defaults-ports")
	if err != nil || ports.Value != "8080 8081" || ports.ScopeID != f.a.scopeID || ports.DisplayID != "1" {
		t.Fatalf("create = %+v %v", ports, err)
	}
	// Same key, same body: the stored answer; same key, another body: conflict.
	if replay, err := create(a, SiteDefaultHTTPListenPort, "8080 8081", "defaults-ports"); err != nil || replay.ID != ports.ID {
		t.Fatalf("replay = %+v %v", replay, err)
	}
	if _, err := create(a, SiteDefaultHTTPListenPort, "9090", "defaults-ports"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("reused key with another body: %v", err)
	}
	if _, err := create(a, SiteDefaultHTTPListenPort, "9090", "defaults-ports-2"); !errors.Is(err, ErrSiteDefaultConflict) {
		t.Fatalf("second global default of one setting: %v", err)
	}
	if _, err := create(a, SiteDefaultBalanceWay, "ip_hash", "defaults-balance"); err != nil {
		t.Fatal(err)
	}
	if _, err := create(a, SiteDefaultWebSocket, "0", "defaults-ws"); err != nil {
		t.Fatal(err)
	}
	if _, err := create(a, SiteDefaultHSTS, "yes", "defaults-bad"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid value: %v", err)
	}
	// A tenant cannot write into another scope.
	if _, err := f.sites.CreateUserDefault(ctx, b, SiteUserDefaultCreateRequest{TargetScopeID: f.a.scopeID,
		Fields: SiteUserDefaultFields{SettingName: SiteDefaultHSTS, Value: "1"}, IdempotencyKey: "x", RequestID: "x"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant create: %v", err)
	}

	// Isolation: B sees none of A's rows and cannot change or delete them.
	listB, err := f.sites.ListUserDefaults(ctx, b, SiteUserDefaultListFilter{Page: 1, Limit: 10})
	if err != nil || listB.Total != 0 {
		t.Fatalf("tenant B list = %+v %v", listB, err)
	}
	value := "1"
	if _, err := f.sites.UpdateUserDefault(ctx, b, SiteUserDefaultUpdateRequest{ID: ports.ID, ExpectedRevision: 1,
		Value: &value, IdempotencyKey: "b-upd", RequestID: "b-upd"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if err := f.sites.DeleteUserDefault(ctx, b, SiteUserDefaultDeleteRequest{ID: ports.ID, IdempotencyKey: "b-del",
		RequestID: "b-del"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	listA, err := f.sites.ListUserDefaults(ctx, a, SiteUserDefaultListFilter{Page: 1, Limit: 10})
	if err != nil || listA.Total != 3 {
		t.Fatalf("tenant A list = %+v %v", listA, err)
	}

	// A new site of A takes the defaults for what the request leaves out.
	key := f.key("defaults-site")
	created, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key,
		Fields: SiteFields{Domains: []string{"defaults-a.example.test"}, Origins: []string{"192.0.2.1"},
			Enabled: true, Status: StatusActive}})
	if err != nil {
		t.Fatal(err)
	}
	var httpPorts []string
	var balance string
	var websocket bool
	if err := f.pool.QueryRow(ctx, `SELECT s.http_ports, p.balance_method, p.websocket_enabled FROM sites s
		JOIN site_origin_pools p ON p.site_id=s.id WHERE s.id=$1`, created.Site.ID).Scan(&httpPorts, &balance, &websocket); err != nil {
		t.Fatal(err)
	}
	if strings.Join(httpPorts, " ") != "8080 8081" || balance != BalanceIPHash || websocket {
		t.Fatalf("new site of A: ports %v balance %s websocket %v", httpPorts, balance, websocket)
	}
	// What the request names wins over a default.
	key = f.key("defaults-explicit")
	explicit, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key,
		Fields: SiteFields{Domains: []string{"explicit-a.example.test"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			Enabled: true, Status: StatusActive}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT http_ports FROM sites WHERE id=$1`, explicit.Site.ID).Scan(&httpPorts); err != nil ||
		strings.Join(httpPorts, " ") != "80" {
		t.Fatalf("explicit ports = %v %v", httpPorts, err)
	}
	// B's sites are untouched by A's defaults.
	createdB, err := f.createSite(f.b, f.b, "defaults-b.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT p.balance_method FROM site_origin_pools p WHERE p.site_id=$1`, createdB.Site.ID).
		Scan(&balance); err != nil || balance != BalanceRoundRobin {
		t.Fatalf("tenant B balance = %s %v", balance, err)
	}

	// A disabled default no longer applies; a deleted one is gone, and the delete replays.
	enabled := false
	if _, err := f.sites.UpdateUserDefault(ctx, a, SiteUserDefaultUpdateRequest{ID: ports.ID, ExpectedRevision: 1,
		Enabled: &enabled, IdempotencyKey: "a-disable", RequestID: "a-disable"}); err != nil {
		t.Fatal(err)
	}
	key = f.key("defaults-disabled")
	afterDisable, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key,
		Fields: SiteFields{Domains: []string{"disabled-a.example.test"}, Origins: []string{"192.0.2.1"},
			Enabled: true, Status: StatusActive}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT http_ports FROM sites WHERE id=$1`, afterDisable.Site.ID).Scan(&httpPorts); err != nil ||
		strings.Join(httpPorts, " ") != "80" {
		t.Fatalf("disabled default applied: %v %v", httpPorts, err)
	}
	for range 2 {
		if err := f.sites.DeleteUserDefault(ctx, a, SiteUserDefaultDeleteRequest{ID: ports.ID, IdempotencyKey: "a-del",
			RequestID: "a-del"}); err != nil {
			t.Fatalf("delete (or its replay): %v", err)
		}
	}
}

func TestTenantSiteDefaultGroupWinsOverGlobal(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	groupID := uuid.New()
	f.exec(`INSERT INTO site_groups(id,scope_id,name) VALUES($1,$2,'g1')`, groupID, f.a.scopeID)
	for _, fields := range []SiteUserDefaultFields{
		{SettingName: SiteDefaultBalanceWay, Value: BalanceIPHash},
		{SettingName: SiteDefaultBalanceWay, Value: BalanceLeastConn, ScopeName: SiteDefaultScopeGroup, GroupID: &groupID},
	} {
		key := f.key("group-default")
		if _, err := f.sites.CreateUserDefault(ctx, a, SiteUserDefaultCreateRequest{Fields: fields, IdempotencyKey: key, RequestID: key}); err != nil {
			t.Fatal(err)
		}
	}
	key := f.key("group-site")
	created, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key,
		Fields: SiteFields{Domains: []string{"group-a.example.test"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			GroupID: &groupID, GroupName: "g1", Enabled: true, Status: StatusActive}})
	if err != nil {
		t.Fatal(err)
	}
	var balance string
	if err := f.pool.QueryRow(ctx, `SELECT balance_method FROM site_origin_pools WHERE site_id=$1`, created.Site.ID).Scan(&balance); err != nil ||
		balance != BalanceLeastConn {
		t.Fatalf("group site balance = %s %v", balance, err)
	}
}

// fp-site SITE-CURRENT-01: the console's create sends an origin pool (with
// forwarding) but leaves the ports and the load balancing out when the user
// did not set them; the group defaults then apply, and what the user set wins.
func TestTenantSiteDefaultsApplyToConsoleShapedCreate(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	groupID := uuid.New()
	f.exec(`INSERT INTO site_groups(id,scope_id,name) VALUES($1,$2,'g1')`, groupID, f.a.scopeID)
	for _, fields := range []SiteUserDefaultFields{
		{SettingName: SiteDefaultHTTPListenPort, Value: "8080"},
		{SettingName: SiteDefaultBalanceWay, Value: BalanceIPHash},
		{SettingName: SiteDefaultHTTPListenPort, Value: "9090", ScopeName: SiteDefaultScopeGroup, GroupID: &groupID},
		{SettingName: SiteDefaultHTTPSListenPort, Value: "9443", ScopeName: SiteDefaultScopeGroup, GroupID: &groupID},
		{SettingName: SiteDefaultBalanceWay, Value: BalanceLeastConn, ScopeName: SiteDefaultScopeGroup, GroupID: &groupID},
	} {
		key := f.key("console-default")
		if _, err := f.sites.CreateUserDefault(ctx, a, SiteUserDefaultCreateRequest{Fields: fields, IdempotencyKey: key, RequestID: key}); err != nil {
			t.Fatal(err)
		}
	}
	pool := func(balance string) *OriginPool {
		return &OriginPool{Origins: []Origin{{Host: "192.0.2.1", Port: 80, Weight: 1, Enabled: true}}, BalanceMethod: balance,
			FailoverTries: 1, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000}
	}
	read := func(id uuid.UUID) (http, https []string, balance string) {
		if err := f.pool.QueryRow(ctx, `SELECT s.http_ports, s.https_ports, p.balance_method FROM sites s
			JOIN site_origin_pools p ON p.site_id=s.id WHERE s.id=$1`, id).Scan(&http, &https, &balance); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, tc := range []struct {
		name    string
		group   *uuid.UUID
		fields  SiteFields
		balance string
		http    string
		https   string
		want    string
	}{
		{"global", nil, SiteFields{}, "", "8080", "", BalanceIPHash},
		{"group", &groupID, SiteFields{HTTPSEnabled: true}, "", "9090", "9443", BalanceLeastConn},
		{"explicit", &groupID, SiteFields{HTTPPorts: []string{"80"}}, BalanceRoundRobin, "80", "", BalanceRoundRobin},
	} {
		key := f.key("console-site")
		fields := tc.fields
		fields.Domains, fields.Origins = []string{tc.name + "-console.example.test"}, []string{"192.0.2.1"}
		fields.Enabled, fields.Status = true, StatusActive
		if tc.group != nil {
			fields.GroupID, fields.GroupName = tc.group, "g1"
		}
		created, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key, Fields: fields, OriginPool: pool(tc.balance)})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		http, https, balance := read(created.Site.ID)
		if strings.Join(http, " ") != tc.http || strings.Join(https, " ") != tc.https || balance != tc.want {
			t.Fatalf("%s: ports %v / %v balance %s, want %s / %s %s", tc.name, http, https, balance, tc.http, tc.https, tc.want)
		}
	}
}

// autoDNSPointerFake fails the first calls, then succeeds; it records calls.
type autoDNSPointerFake struct {
	mu        sync.Mutex
	failFirst int
	calls     []string
	pointed   map[string]string
}

func (p *autoDNSPointerFake) point(_ context.Context, _, _, providerID uuid.UUID, domain, target string) (string, string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, providerID.String()+" "+domain+" "+target)
	if p.failFirst > 0 {
		p.failFirst--
		return "", "dns_provider_unavailable", true
	}
	before := p.pointed[domain]
	p.pointed[domain] = target // idempotent: pointing again changes nothing
	return before, "", false
}

func (f *trustFixture) insertVerifiedProvider(owner trustActor, name string) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,
			created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cloudflare','test-key',decode(repeat('ab',40),'hex'),$4,$4)`, id, owner.scopeID, name, owner.userID)
	f.exec(`UPDATE dns_providers SET status='verified' WHERE id=$1`, id)
	return id
}

func TestSiteAutoDNSFailureDoesNotBlockCreateAndRetries(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	providerA := f.insertVerifiedProvider(f.a, "a-cloudflare")
	providerB := f.insertVerifiedProvider(f.b, "b-cloudflare")

	createWith := func(provider uuid.UUID, domain string) (WriteResult, error) {
		key := f.key("auto-dns")
		return f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key, DNSProviderID: &provider,
			Fields: SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				CNAME: "a1b2c3.cdn.example.net", Enabled: true, Status: StatusActive}})
	}
	// Another tenant's account is refused (and nothing is created).
	if _, err := createWith(providerB, "cross.example.test"); !errors.Is(err, ErrAutoDNSProvider) {
		t.Fatalf("other tenant's provider: %v", err)
	}
	created, err := createWith(providerA, "www.auto.example.test")
	if err != nil {
		t.Fatalf("create with auto DNS: %v", err)
	}

	fake := &autoDNSPointerFake{failFirst: 1, pointed: map[string]string{}}
	worker := NewAutoDNSWorker(NewStoreWithClock(f.pool, f.clock, nil), fake.point, nil)
	// Round 1: the provider is down. The site is created and enabled; the task waits for a retry.
	if handled, err := worker.RunOnce(ctx); err != nil || handled != 1 {
		t.Fatalf("round 1 = %d %v", handled, err)
	}
	if !f.siteEnabled(created.Site.ID) {
		t.Fatal("auto DNS failure changed the site")
	}
	status := f.autoDNSStatus(a, created.Site.ID)
	if status == nil || status.State != AutoDNSPending || status.Attempts != 1 {
		t.Fatalf("after a temporary failure: %+v", status)
	}
	// Not due yet: nothing happens until the backoff passes.
	if handled, _ := worker.RunOnce(ctx); handled != 0 {
		t.Fatalf("retried before the backoff: %d", handled)
	}
	f.now = f.now.Add(time.Minute)
	if handled, err := worker.RunOnce(ctx); err != nil || handled != 1 {
		t.Fatalf("round 2 = %d %v", handled, err)
	}
	status = f.autoDNSStatus(a, created.Site.ID)
	if status == nil || status.State != AutoDNSDone || status.FailureCode != nil || len(status.Results) != 1 ||
		status.Results[0].Domain != "www.auto.example.test" || status.Results[0].Code != "" {
		t.Fatalf("after success: %+v", status)
	}
	// 同步解析 is idempotent: it runs once more and lands on the same record.
	for range 2 {
		if _, err := f.sites.SyncAutoDNS(ctx, a, SyncAutoDNSRequest{SiteID: created.Site.ID, RequestID: "sync"}); err != nil {
			t.Fatal(err)
		}
	}
	if handled, err := worker.RunOnce(ctx); err != nil || handled != 1 {
		t.Fatalf("after sync = %d %v", handled, err)
	}
	status = f.autoDNSStatus(a, created.Site.ID)
	if status.State != AutoDNSDone || status.Results[0].Before != "a1b2c3.cdn.example.net" {
		t.Fatalf("re-run = %+v", status)
	}
	if got := len(fake.calls); got != 3 || fake.pointed["www.auto.example.test"] != "a1b2c3.cdn.example.net" {
		t.Fatalf("pointer calls = %v", fake.calls)
	}
	// Tenant B cannot see or sync A's site.
	if _, err := f.sites.SyncAutoDNS(ctx, f.b.siteActor(), SyncAutoDNSRequest{SiteID: created.Site.ID,
		RequestID: "b-sync"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant sync: %v", err)
	}
	// A permanent failure ends the task as failed (shown on the site); the site stays.
	fake.mu.Lock()
	fake.failFirst = 0
	fake.mu.Unlock()
	permanent := func(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, string) (string, string, bool) {
		return "", "dns_record_conflict", false
	}
	if _, err := f.sites.SyncAutoDNS(ctx, a, SyncAutoDNSRequest{SiteID: created.Site.ID, RequestID: "sync-2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAutoDNSWorker(NewStoreWithClock(f.pool, f.clock, nil), permanent, nil).RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	status = f.autoDNSStatus(a, created.Site.ID)
	if status.State != AutoDNSFailed || status.FailureCode == nil || *status.FailureCode != "dns_record_conflict" ||
		!f.siteEnabled(created.Site.ID) {
		t.Fatalf("permanent failure = %+v", status)
	}
}

func (f *trustFixture) autoDNSStatus(actor Actor, siteID uuid.UUID) *AutoDNSStatus {
	f.t.Helper()
	list, err := f.sites.List(context.Background(), actor, ListFilter{Page: 1, Limit: 50})
	if err != nil {
		f.t.Fatal(err)
	}
	for _, item := range list.Items {
		if item.ID == siteID {
			return item.AutoDNS
		}
	}
	f.t.Fatalf("site %s not listed", siteID)
	return nil
}

// 验收 acc-cd：CNAME 未就绪的任务把 nil 结果写成 JSON null，违反 492 的数组约束
// （23514），整轮报错，同批其他任务也要等租约过期（约 5 分钟）才重试。
func TestSiteAutoDNSWaitingCNAMEDoesNotFailTheRound(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	provider := f.insertVerifiedProvider(f.a, "a-cloudflare-wait")
	create := func(domain, cname string) uuid.UUID {
		key := f.key("auto-dns-wait")
		created, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key, DNSProviderID: &provider,
			Fields: SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				CNAME: cname, Enabled: true, Status: StatusActive}})
		if err != nil {
			t.Fatalf("create %s: %v", domain, err)
		}
		return created.Site.ID
	}
	waiting := create("wait.auto.example.test", "")
	ready := create("ready.auto.example.test", "r1b2c3.cdn.example.net")
	fake := &autoDNSPointerFake{pointed: map[string]string{}}
	worker := NewAutoDNSWorker(NewStoreWithClock(f.pool, f.clock, nil), fake.point, nil)
	if handled, err := worker.RunOnce(ctx); err != nil || handled != 2 {
		t.Fatalf("round 1 = %d %v", handled, err)
	}
	if status := f.autoDNSStatus(a, waiting); status == nil || status.State != AutoDNSPending ||
		status.Attempts != 1 || len(status.Results) != 0 {
		t.Fatalf("waiting CNAME task = %+v", status)
	}
	if status := f.autoDNSStatus(a, ready); status == nil || status.State != AutoDNSDone || len(status.Results) != 1 {
		t.Fatalf("same-batch task = %+v", status)
	}
}

// DNS-ASYNC-20261027-03: a claim whose lease expired loses the task to the
// next claim of the same generation; its late completion (either order) is
// refused with ErrAutoDNSClaimLost and does not overwrite the current claim.
func TestSiteAutoDNSStaleAttemptCannotCompleteCurrentClaim(t *testing.T) {
	for _, order := range []string{"stale_first", "current_first"} {
		t.Run(order, func(t *testing.T) {
			f := newTrustFixture(t)
			ctx := context.Background()
			a := f.a.siteActor()
			provider := f.insertVerifiedProvider(f.a, "a-cloudflare-stale")
			key := f.key("auto-dns-stale")
			created, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key, DNSProviderID: &provider,
				Fields: SiteFields{Domains: []string{"stale.auto.example.test"}, HTTPPorts: []string{"80"},
					Origins: []string{"192.0.2.1"}, CNAME: "s1b2c3.cdn.example.net", Enabled: true, Status: StatusActive}})
			if err != nil {
				t.Fatal(err)
			}
			store := NewStoreWithClock(f.pool, f.clock, nil)
			first, err := store.ClaimAutoDNS(ctx, 10, time.Minute)
			if err != nil || len(first) != 1 {
				t.Fatalf("claim 1 = %v %v", first, err)
			}
			f.now = f.now.Add(2 * time.Minute) // lease 1 expires
			second, err := store.ClaimAutoDNS(ctx, 10, time.Minute)
			if err != nil || len(second) != 1 || second[0].Generation != first[0].Generation ||
				second[0].Attempts != first[0].Attempts+1 {
				t.Fatalf("claim 2 = %v %v", second, err)
			}
			stale := func() error {
				return store.CompleteAutoDNS(ctx, first[0], AutoDNSOutcome{Code: "dns_record_conflict"})
			}
			current := func() error {
				return store.CompleteAutoDNS(ctx, second[0], AutoDNSOutcome{
					Results: []AutoDNSRecordRow{{Domain: "stale.auto.example.test"}}})
			}
			if order == "stale_first" {
				if err := stale(); !errors.Is(err, ErrAutoDNSClaimLost) {
					t.Fatalf("stale completion = %v, want ErrAutoDNSClaimLost", err)
				}
				if err := current(); err != nil {
					t.Fatalf("current completion = %v", err)
				}
			} else {
				if err := current(); err != nil {
					t.Fatalf("current completion = %v", err)
				}
				if err := stale(); !errors.Is(err, ErrAutoDNSClaimLost) {
					t.Fatalf("stale completion = %v, want ErrAutoDNSClaimLost", err)
				}
			}
			status := f.autoDNSStatus(a, created.Site.ID)
			if status == nil || status.State != AutoDNSDone || status.FailureCode != nil || status.Attempts != 2 {
				t.Fatalf("final = %+v", status)
			}
		})
	}
}
