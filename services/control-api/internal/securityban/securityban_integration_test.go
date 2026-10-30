//go:build integration

package securityban_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		var err error
		if pool, err = pgxpool.New(t.Context(), os.Getenv("TEST_DATABASE_URL")); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := database.Migrate(t.Context(), pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func exec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Join(strings.Fields(query)[:3], " "), err)
	}
}

type tenantFixture struct {
	tenant, scope, owner, site uuid.UUID
}

func seedTenant(t *testing.T, pool *pgxpool.Pool, name string) tenantFixture {
	t.Helper()
	return seedTenantSite(t, pool, name, uuid.New())
}

func seedTenantSite(t *testing.T, pool *pgxpool.Pool, name string, site uuid.UUID) tenantFixture {
	t.Helper()
	value := tenantFixture{uuid.New(), uuid.New(), uuid.New(), site}
	exec(t, pool, `INSERT INTO tenants(id,display_name,status,created_at,updated_at) VALUES($1,$2,'active',now(),now())`, value.tenant, name)
	exec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,now())`, value.scope, value.tenant)
	exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
		VALUES($1,$2,$3,'not-used','active',now(),now())`, value.owner, "sb-"+strings.ReplaceAll(value.owner.String(), "-", "")[:20], name)
	exec(t, pool, `INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',now())`, value.scope, value.owner)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,display_id)
			VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,1)`,
			value.site, value.scope, value.owner, name+".example.com"); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, value.site); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, value.site)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return value
}

// seedNode attaches an active node serving the site through the site's own
// line group.
func seedNode(t *testing.T, pool *pgxpool.Pool, fixture tenantFixture) uuid.UUID {
	t.Helper()
	node, group, endpoint := uuid.New(), uuid.New(), uuid.New()
	name := "sb-" + node.String()[:8]
	type statement struct {
		sql  string
		args []any
	}
	var statements []statement
	for _, statement := range []statement{
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		  VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, []any{node, fixture.scope, name, fixture.owner}},
		{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
		  VALUES($1,$2,$3,1,$4,$4,now(),now())`, []any{group, fixture.scope, name, fixture.owner}},
		{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
		  failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
		  VALUES($1,$2,1,$3,'lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$4,$5,now())`, []any{group, fixture.scope, name, make([]byte, 32), fixture.owner}},
		{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
		  VALUES($1,$2,$3,$4,1,'192.0.2.71',4,443,'','',0,1,true)`, []any{endpoint, node, fixture.scope, group}},
		{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,
		  consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
		  VALUES($1,$2,1,$3,'unknown',0,0,0,now(),1,now(),now())`, []any{fixture.scope, group, endpoint}},
		{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2`, []any{fixture.scope, group}},
		{`UPDATE sites SET node_group_id=$2 WHERE id=$1`, []any{fixture.site, group}},
	} {
		statements = append(statements, statement)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return fmt.Errorf("%s: %w", strings.Join(strings.Fields(statement.sql)[:3], " "), err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return node
}

func platformActor(t *testing.T, pool *pgxpool.Pool) securityban.Actor {
	t.Helper()
	var scope uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&scope); errors.Is(err, pgx.ErrNoRows) {
		scope = uuid.New()
		exec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope)
	} else if err != nil {
		t.Fatal(err)
	}
	admin := uuid.New()
	exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
		VALUES($1,$2,'admin','not-used','active',now(),now())`, admin, "sb-admin-"+admin.String()[:8])
	return securityban.Actor{UserID: admin, ScopeID: scope, ScopeKind: "platform"}
}

func auditCount(t *testing.T, pool *pgxpool.Pool, scope uuid.UUID, action, result string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2 AND result=$3`,
		scope, action, result).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// TestSecurityBanListLifecycle: a manual ban is listed active, a second ban
// of the same client is refused, a release lifts it once; a ban expires on
// its own; a tenant never reaches another tenant's site or ban; a platform
// actor reaches every site; every write and refusal is audited.
func TestSecurityBanListLifecycle(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := &clock{now: time.Now().UTC().Truncate(time.Second)}
	service := securityban.NewService(securityban.NewStore(pool, now.Now))
	a, b := seedTenant(t, pool, "sb-a-"+uuid.NewString()[:6]), seedTenant(t, pool, "sb-b-"+uuid.NewString()[:6])
	actorA := securityban.Actor{UserID: a.owner, ScopeID: a.scope, ScopeKind: "tenant"}
	actorB := securityban.Actor{UserID: b.owner, ScopeID: b.scope, ScopeKind: "tenant"}
	create := func(actor securityban.Actor, site uuid.UUID, client string, seconds int, key string) (securityban.Entry, error) {
		return service.Create(ctx, actor, securityban.CreateRequest{SiteID: site, ClientIP: client, DurationSecond: seconds,
			Reason: "manual test", IdempotencyKey: key, RequestID: "req-" + key})
	}
	entry, err := create(actorA, a.site, "::ffff:198.51.100.9", 600, "k1")
	if err != nil || entry.ClientIP != "198.51.100.9" || entry.State != securityban.StateActive || entry.Source != securityban.SourceManual ||
		!entry.BannedUntil.Equal(entry.BannedAt.Add(10*time.Minute)) {
		t.Fatalf("create = %+v, %v", entry, err)
	}
	if replay, err := create(actorA, a.site, "198.51.100.9", 600, "k1"); err != nil || replay.ID != entry.ID {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	if _, err := create(actorA, a.site, "198.51.100.9", 900, "k1"); !errors.Is(err, securityban.ErrIdempotencyKey) {
		t.Fatalf("key reuse: %v", err)
	}
	if _, err := create(actorA, a.site, "198.51.100.9", 600, "k2"); !errors.Is(err, securityban.ErrAlreadyBanned) {
		t.Fatalf("second ban: %v", err)
	}
	for _, bad := range []struct {
		client  string
		seconds int
	}{{"198.0.0.0/7", 600}, {"127.0.0.0/24", 600}, {"127.0.0.1", 600}, {"198.51.100.9", 59}, {"198.51.100.9", 31 * 86400}} {
		if _, err := create(actorA, a.site, bad.client, bad.seconds, "kbad"); !errors.Is(err, securityban.ErrInvalidInput) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	// Tenant isolation: B cannot ban on A's site, list it or release A's ban.
	if _, err := create(actorB, a.site, "203.0.113.1", 600, "kb"); !errors.Is(err, securityban.ErrSiteNotFound) {
		t.Fatalf("cross-tenant create: %v", err)
	}
	if _, err := service.List(ctx, actorB, securityban.ListFilter{SiteID: &a.site, Page: 1, Limit: 20}); !errors.Is(err, securityban.ErrSiteNotFound) {
		t.Fatalf("cross-tenant list: %v", err)
	}
	if listed, err := service.List(ctx, actorB, securityban.ListFilter{Page: 1, Limit: 20}); err != nil || listed.Total != 0 {
		t.Fatalf("B list = %+v, %v", listed, err)
	}
	if _, err := service.Release(ctx, actorB, securityban.ReleaseRequest{EntryID: entry.ID, RequestID: "rb"}); !errors.Is(err, securityban.ErrNotFound) {
		t.Fatalf("cross-tenant release: %v", err)
	}
	// Platform: bans on B's site, sees both tenants.
	admin := platformActor(t, pool)
	adminEntry, err := create(admin, b.site, "2001:db8::7", 120, "ka")
	if err != nil || adminEntry.TenantScopeID != b.scope {
		t.Fatalf("platform create = %+v, %v", adminEntry, err)
	}
	all, err := service.List(ctx, admin, securityban.ListFilter{State: securityban.StateActive, Page: 1, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uuid.UUID]bool{}
	for _, item := range all.Items {
		seen[item.ID] = true
	}
	if !seen[entry.ID] || !seen[adminEntry.ID] {
		t.Fatalf("platform list = %+v", all)
	}
	// Release once.
	released, err := service.Release(ctx, actorA, securityban.ReleaseRequest{EntryID: entry.ID, RequestID: "r1"})
	if err != nil || released.State != securityban.StateReleased || released.ReleasedBy == nil || *released.ReleasedBy != a.owner {
		t.Fatalf("release = %+v, %v", released, err)
	}
	if _, err := service.Release(ctx, actorA, securityban.ReleaseRequest{EntryID: entry.ID, RequestID: "r2"}); !errors.Is(err, securityban.ErrNotActive) {
		t.Fatalf("second release: %v", err)
	}
	// A new ban of the released client is a new row.
	now.now = now.now.Add(time.Second)
	again, err := create(actorA, a.site, "198.51.100.9", 600, "k3")
	if err != nil || again.ID == entry.ID {
		t.Fatalf("ban after release = %+v, %v", again, err)
	}
	// Expiry: the platform ban on B ends after 120 s and cannot be released.
	now.now = now.now.Add(3 * time.Minute)
	expired, err := service.List(ctx, actorB, securityban.ListFilter{SiteID: &b.site, State: securityban.StateExpired, Page: 1, Limit: 20})
	if err != nil || expired.Total != 1 || expired.Items[0].ID != adminEntry.ID || expired.Items[0].State != securityban.StateExpired {
		t.Fatalf("expired = %+v, %v", expired, err)
	}
	if _, err := service.Release(ctx, admin, securityban.ReleaseRequest{EntryID: adminEntry.ID, RequestID: "r3"}); !errors.Is(err, securityban.ErrNotActive) {
		t.Fatalf("release expired: %v", err)
	}
	byIP, err := service.List(ctx, actorA, securityban.ListFilter{ClientIP: "198.51.100.9", Page: 1, Limit: 20})
	if err != nil || byIP.Total != 2 || byIP.Items[0].ID != again.ID || byIP.Items[1].State != securityban.StateReleased {
		t.Fatalf("by IP = %+v, %v", byIP, err)
	}
	// Audit: creates and releases, refusals as denied.
	if got := auditCount(t, pool, a.scope, securityban.AuditCreate, "success"); got != 2 {
		t.Fatalf("A create audits = %d", got)
	}
	if got := auditCount(t, pool, a.scope, securityban.AuditCreate, "denied"); got != 2 {
		t.Fatalf("A denied create audits (key reuse, already banned) = %d", got)
	}
	if got := auditCount(t, pool, a.scope, securityban.AuditRelease, "success"); got != 1 {
		t.Fatalf("A release audits = %d", got)
	}
	if got := auditCount(t, pool, a.scope, securityban.AuditRelease, "denied"); got != 1 {
		t.Fatalf("A denied release audits = %d", got)
	}
	if got := auditCount(t, pool, b.scope, securityban.AuditCreate, "success") + auditCount(t, pool, b.scope, securityban.AuditRelease, "denied"); got != 2 {
		t.Fatalf("B audits (platform create, expired release) = %d", got)
	}
}

type events struct{ items []analyticslog.TemporaryBanEvent }

func (source *events) ListTemporaryBans(_ context.Context, after, through time.Time, _ uint16) ([]analyticslog.TemporaryBanEvent, error) {
	result := []analyticslog.TemporaryBanEvent{}
	for _, item := range source.items {
		if item.IngestedAt.After(after) && !item.IngestedAt.After(through) {
			result = append(result, item)
		}
	}
	return result, nil
}

// TestSecurityBanSyncFoldsAutomaticBans: a node's temporary_ban becomes a
// row (duration from the published policy, else 3600 s), the same event is
// folded once, a later ban of the banned client extends the row, an event
// naming another tenant's site is dropped, a ban that started before a
// release of the client is not resurrected, and the cursor advances.
func TestSecurityBanSyncFoldsAutomaticBans(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	a, b := seedTenant(t, pool, "sbs-a-"+uuid.NewString()[:6]), seedTenant(t, pool, "sbs-b-"+uuid.NewString()[:6])
	ingested := now.Add(-time.Minute)
	event := func(id, tenant string, site uuid.UUID, kind, client string, occurred time.Time) analyticslog.TemporaryBanEvent {
		ingested = ingested.Add(time.Millisecond)
		return analyticslog.TemporaryBanEvent{EventID: id, TenantID: tenant, SiteID: site.String(), EventType: kind,
			ClientIP: client, RuleID: uuid.NewString(), OccurredAt: occurred, IngestedAt: ingested}
	}
	source := &events{items: []analyticslog.TemporaryBanEvent{
		event("e1", a.tenant.String(), a.site, "waf", "198.51.100.20", now.Add(-2*time.Minute)),
		event("e1", a.tenant.String(), a.site, "waf", "198.51.100.20", now.Add(-2*time.Minute)),
		event("e2", a.tenant.String(), a.site, "cc", "198.51.100.20", now.Add(-time.Minute)),
		event("e3", b.tenant.String(), a.site, "cc", "198.51.100.21", now.Add(-time.Minute)),
		event("e4", a.tenant.String(), a.site, "cc", "2001:db8::20", now.Add(-2*time.Hour)),
	}}
	syncer, err := securityban.NewSyncer(pool, source, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	result, err := syncer.RunOnce(ctx)
	if err != nil || result.Read != 5 || result.Added != 1 || result.Extended != 1 || result.Skipped != 3 {
		t.Fatalf("sync = %+v, %v", result, err)
	}
	service := securityban.NewService(securityban.NewStore(pool, func() time.Time { return now }))
	actorA := securityban.Actor{UserID: a.owner, ScopeID: a.scope, ScopeKind: "tenant"}
	listed, err := service.List(ctx, actorA, securityban.ListFilter{SiteID: &a.site, Page: 1, Limit: 20})
	if err != nil || listed.Total != 1 {
		t.Fatalf("list = %+v, %v", listed, err)
	}
	row := listed.Items[0]
	if row.Source != securityban.SourceWAF || row.ClientIP != "198.51.100.20" || row.State != securityban.StateActive ||
		!row.BannedUntil.Equal(now.Add(-time.Minute).Add(time.Hour)) {
		t.Fatalf("folded row = %+v (want waf, extended to the cc ban's end)", row)
	}
	// Release, then a node's ban that started before the release is old news.
	if _, err := service.Release(ctx, actorA, securityban.ReleaseRequest{EntryID: row.ID, RequestID: "rel"}); err != nil {
		t.Fatal(err)
	}
	late := event("e5", a.tenant.String(), a.site, "waf", "198.51.100.20", now.Add(-30*time.Second))
	late.IngestedAt = now
	source.items = append(source.items, late)
	if result, err := syncer.RunOnce(ctx); err != nil || result.Read != 0 {
		t.Fatalf("sync before the lag = %+v, %v", result, err)
	}
	later := now.Add(time.Minute)
	syncer, _ = securityban.NewSyncer(pool, source, func() time.Time { return later })
	if result, err := syncer.RunOnce(ctx); err != nil || result.Read != 1 || result.Skipped != 1 {
		t.Fatalf("sync after release = %+v, %v", result, err)
	}
	var cursor int64
	if err := pool.QueryRow(ctx, `SELECT ingested_until_ms FROM security_ban_sync_cursor`).Scan(&cursor); err != nil ||
		cursor != later.Add(-securityban.SyncLag).UnixMilli() {
		t.Fatalf("cursor = %d, %v", cursor, err)
	}
}

type captured struct {
	nodeID   string
	revision uint64
	encoded  []byte
}

type transport struct{ published []captured }

func (target *transport) PublishList(_ context.Context, nodeID string, revision uint64, encoded []byte) error {
	target.published = append(target.published, captured{nodeID, revision, append([]byte(nil), encoded...)})
	return nil
}
func (*transport) NextReceipt(context.Context) (securityban.ReceiptDelivery, error) { return nil, nil }

type receipt struct {
	report      *agentv1.SecurityBanStatus
	acked, naks int
}

func (value *receipt) Status() *agentv1.SecurityBanStatus { return value.report }
func (value *receipt) Ack(context.Context) error           { value.acked++; return nil }
func (value *receipt) Nak(context.Context) error           { value.naks++; return nil }

// TestSecurityBanDistributionAndReceipts: the node serving a site gets a
// signed snapshot of its bans; unchanged content is not republished; a
// release republishes with the release and without the ban; the node's
// receipt for the current snapshot is recorded, a stale one is not; a node
// of another tenant never sees the site's bans.
func TestSecurityBanDistributionAndReceipts(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	a, b := seedTenant(t, pool, "sbd-a-"+uuid.NewString()[:6]), seedTenant(t, pool, "sbd-b-"+uuid.NewString()[:6])
	nodeA, nodeB := seedNode(t, pool, a), seedNode(t, pool, b)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &transport{}
	distributor, err := securityban.NewDistributor(securityban.DistributorConfig{Pool: pool, Transport: carrier, KeyID: "test-key",
		Sign: func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(keyID string) (ed25519.PublicKey, bool) { return public, keyID == "test-key" }
	service := securityban.NewService(securityban.NewStore(pool, func() time.Time { return now }))
	actorA := securityban.Actor{UserID: a.owner, ScopeID: a.scope, ScopeKind: "tenant"}
	entry, err := service.Create(ctx, actorA, securityban.CreateRequest{SiteID: a.site, ClientIP: "198.51.100.30",
		DurationSecond: 600, IdempotencyKey: "d1", RequestID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := distributor.PublishOnce(ctx); err != nil {
		t.Fatal(err)
	}
	forNode := func(node uuid.UUID) []captured {
		var result []captured
		for _, item := range carrier.published {
			if item.nodeID == node.String() {
				result = append(result, item)
			}
		}
		return result
	}
	if len(forNode(nodeB)) != 0 || len(forNode(nodeA)) != 1 {
		t.Fatalf("published = %+v", carrier.published)
	}
	first := forNode(nodeA)[0]
	list, err := contract.Open(first.encoded, nodeA.String(), trusted)
	if err != nil || list.Revision != 1 || len(list.Bans) != 1 || list.Bans[0].Client != "198.51.100.30" ||
		list.Bans[0].SiteID != a.site.String() || list.Bans[0].Until != now.Add(10*time.Minute).Unix() || len(list.Releases) != 0 {
		t.Fatalf("snapshot = %+v, %v", list, err)
	}
	// Unchanged and unanswered: not republished before RetryAfter.
	if err := distributor.PublishOnce(ctx); err != nil || len(forNode(nodeA)) != 1 {
		t.Fatalf("republished unchanged: %d, %v", len(forNode(nodeA)), err)
	}
	// A stale receipt (other digest) is not recorded; the current one is.
	stale := &receipt{report: &agentv1.SecurityBanStatus{NodeId: nodeA.String(), Revision: 1, ListSha256: make([]byte, 32), Applied: true, Bans: 1}}
	distributor.HandleReceipt(ctx, stale)
	current := &receipt{report: &agentv1.SecurityBanStatus{NodeId: nodeA.String(), Revision: 1,
		ListSha256: contract.Digest(first.encoded), Applied: true, Bans: 1}}
	distributor.HandleReceipt(ctx, current)
	if stale.acked != 1 || current.acked != 1 {
		t.Fatalf("acks stale=%d current=%d", stale.acked, current.acked)
	}
	var applied int64
	var bans *int64
	if err := pool.QueryRow(ctx, `SELECT applied_revision,applied_bans FROM security_ban_node_state WHERE node_id=$1`, nodeA).
		Scan(&applied, &bans); err != nil || applied != 1 || bans == nil || *bans != 1 {
		t.Fatalf("node state applied=%d bans=%v err=%v", applied, bans, err)
	}
	if err := distributor.PublishOnce(ctx); err != nil || len(forNode(nodeA)) != 1 {
		t.Fatalf("republished applied: %d, %v", len(forNode(nodeA)), err)
	}
	// Release: revision 2 lifts the ban and carries the release.
	if _, err := service.Release(ctx, actorA, securityban.ReleaseRequest{EntryID: entry.ID, RequestID: "d2"}); err != nil {
		t.Fatal(err)
	}
	if err := distributor.PublishOnce(ctx); err != nil || len(forNode(nodeA)) != 2 {
		t.Fatalf("release publish: %d, %v", len(forNode(nodeA)), err)
	}
	second, err := contract.Open(forNode(nodeA)[1].encoded, nodeA.String(), trusted)
	if err != nil || second.Revision != 2 || len(second.Bans) != 0 || len(second.Releases) != 1 ||
		second.Releases[0].Client != "198.51.100.30" || second.Releases[0].ReleasedAt != now.Unix() {
		t.Fatalf("release snapshot = %+v, %v", second, err)
	}
	// A refusal is recorded with its code.
	refused := &receipt{report: &agentv1.SecurityBanStatus{NodeId: nodeA.String(), Revision: 2,
		ListSha256: contract.Digest(forNode(nodeA)[1].encoded), ErrorCode: contract.ErrorRuntime}}
	distributor.HandleReceipt(ctx, refused)
	var code string
	var ok *bool
	if err := pool.QueryRow(ctx, `SELECT applied_revision,applied,error_code FROM security_ban_node_state WHERE node_id=$1`, nodeA).
		Scan(&applied, &ok, &code); err != nil || applied != 1 || ok == nil || *ok || code != contract.ErrorRuntime {
		t.Fatalf("refusal state applied=%d ok=%v code=%q err=%v", applied, ok, code, err)
	}
}
