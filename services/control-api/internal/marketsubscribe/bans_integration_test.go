package marketsubscribe

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// banClock is one clock for both controllers.
type banClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *banClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *banClock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// banBridge is the relay between the two controllers: supply.ban_sync goes
// to the leaf's Handle, everything else to the fake leaf (site commits).
type banBridge struct {
	leaf  *marketsupply.Service
	other *fakeLeaf
	mu    sync.Mutex
	syncs int
	// answer overrides the leaf (version mix): nil uses it.
	answer func() (siteconf.Reply, error)
}

func (b *banBridge) Call(ctx context.Context, leaf Leaf, op string, domains []string, key string, body any) (siteconf.Reply, error) {
	if op != bansync.OpSync {
		return b.other.Call(ctx, leaf, op, domains, key, body)
	}
	b.mu.Lock()
	b.syncs++
	answer := b.answer
	b.mu.Unlock()
	if answer != nil {
		return answer()
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return siteconf.Reply{}, err
	}
	return b.leaf.Handle(ctx, envelope.Header{MessageID: uuid.New(), GrantID: leaf.GrantID, Operation: op}, raw)
}

type leafCarrier struct {
	mu        sync.Mutex
	published [][]byte
}

func (c *leafCarrier) PublishList(_ context.Context, _ string, _ uint64, encoded []byte) error {
	c.mu.Lock()
	c.published = append(c.published, append([]byte(nil), encoded...))
	c.mu.Unlock()
	return nil
}
func (*leafCarrier) NextReceipt(context.Context) (securityban.ReceiptDelivery, error) {
	return nil, nil
}

type leafReceipt struct{ report *agentv1.SecurityBanStatus }

func (r leafReceipt) Status() *agentv1.SecurityBanStatus { return r.report }
func (leafReceipt) Ack(context.Context) error            { return nil }
func (leafReceipt) Nak(context.Context) error            { return nil }

// banLeaf is the seller controller of the test: its market supply with the
// real ban list library, a platform node in the grant's pool and the market
// tenant's leaf site served by it.
type banLeaf struct {
	pool        *pgxpool.Pool
	supply      *marketsupply.Service
	store       *securityban.Store
	distributor *securityban.Distributor
	carrier     *leafCarrier
	grant       grant.Grant
	site, node  uuid.UUID
	public      ed25519.PublicKey
}

func leafPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("MARKET_SUBSCRIBE_LEAF_DATABASE_URL")
	if url == "" {
		t.Skip("MARKET_SUBSCRIBE_LEAF_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func leafExec(t *testing.T, tx pgx.Tx, query string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%.60s: %v", query, err)
	}
}

func newBanLeaf(t *testing.T, pool *pgxpool.Pool, clock *banClock) *banLeaf {
	t.Helper()
	ctx := t.Context()
	tokens, err := identity.NewTokenManager(strings.Repeat("k", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	subs := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, clock.Now))
	supply := marketsupply.New(pool, ids, subs, marketsupply.Config{}).WithClock(clock.Now)
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); err == pgx.ErrNoRows {
		platform = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	service, err := supply.SiteActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	group, node, endpoint, owner := uuid.New(), uuid.New(), uuid.New(), service.UserID
	name := "ban-pool-" + group.String()[:8]
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		leafExec(t, tx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, node, platform, name, owner)
		leafExec(t, tx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,1,$4,$4,now(),now())`, group, platform, name, owner)
		leafExec(t, tx, `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
			failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,$3,'lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$4,$5,now())`, group, platform, name, make([]byte, 32), owner)
		leafExec(t, tx, `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			VALUES($1,$2,$3,$4,1,'192.0.2.81',4,443,'','',0,1,true)`, endpoint, node, platform, group)
		leafExec(t, tx, `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,
			consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			VALUES($1,$2,1,$3,'unknown',0,0,0,now(),1,now(),now())`, platform, group, endpoint)
		leafExec(t, tx, `UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2`, platform, group)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	now := clock.Now()
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: group.String(),
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		IssuedAt: now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	if out, err := supply.Sync(ctx, []grant.Grant{g}); err != nil || out[0].Action == "failed" {
		t.Fatalf("leaf grant sync = %+v, %v", out, err)
	}
	var scope, user uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT membership.scope_id, account.id FROM users account
		JOIN memberships membership ON membership.user_id=account.id WHERE account.username=$1`,
		"mkt-"+marketsupply.Key(g)).Scan(&scope, &user); err != nil {
		t.Fatal(err)
	}
	site := uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		leafExec(t, tx, `WITH display AS (
				INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
				ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1
				RETURNING next_value-1 AS value)
			INSERT INTO sites (id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,
			origin_hosts,https_enabled,enabled,status,created_by_user_id,updated_by_user_id,display_id,node_group_id)
			SELECT $1,$2,$3,$4,$5,$6,$7,$7,false,true,'active',$3,$3,display.value,$8 FROM display`,
			site, scope, user, "leaf-"+site.String()[:8]+".example.cn", []string{"80"}, []string{}, []string{"203.0.113.20"}, group)
		leafExec(t, tx, `INSERT INTO site_origin_pools (site_id) VALUES ($1)`, site)
		leafExec(t, tx, `INSERT INTO site_origins (site_id,position,host,port,weight,enabled) VALUES ($1,1,'203.0.113.20',80,1,true)`, site)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &leafCarrier{}
	distributor, err := securityban.NewDistributor(securityban.DistributorConfig{Pool: pool, Transport: carrier, KeyID: "leaf",
		Sign:     func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Minute, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	store := securityban.NewStore(pool, clock.Now)
	supply.WithBanList(store, distributor)
	return &banLeaf{pool: pool, supply: supply, store: store, distributor: distributor, carrier: carrier, grant: g,
		site: site, node: node, public: public}
}

// publishAndAnswer runs the leaf distributor and the node's receipt.
func (l *banLeaf) publishAndAnswer(t *testing.T) contract.List {
	t.Helper()
	before := len(l.carrier.published)
	if err := l.distributor.PublishOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(l.carrier.published) == before {
		t.Fatal("leaf published nothing")
	}
	encoded := l.carrier.published[len(l.carrier.published)-1]
	list, err := contract.Open(encoded, l.node.String(), func(id string) (ed25519.PublicKey, bool) { return l.public, id == "leaf" })
	if err != nil {
		t.Fatal(err)
	}
	l.distributor.HandleReceipt(t.Context(), leafReceipt{&agentv1.SecurityBanStatus{NodeId: l.node.String(), Revision: list.Revision,
		ListSha256: contract.Digest(encoded), Applied: true, Bans: uint32(len(list.Bans))}})
	return list
}

func (l *banLeaf) marketRows(t *testing.T, now time.Time) (active, released int) {
	t.Helper()
	if err := l.pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE released_at IS NULL AND banned_until > $2),
			count(*) FILTER (WHERE released_at IS NOT NULL)
		FROM security_ban_entries WHERE site_id=$1 AND source='market'`, l.site, now).Scan(&active, &released); err != nil {
		t.Fatal(err)
	}
	return active, released
}

// TestSubscriberBanReachesLeafNodes: a ban the root subscriber adds
// on a site served only by a market leaf reaches the leaf site's ban list
// and, through the leaf's distributor, the node serving it; the subscriber's
// list shows it pending, delivering, then effective. A release and an expiry
// follow; the leaf's refusal shows with its reason; a leaf or market that
// predates the operation shows as unsupported without failing the pass; the
// subscription's end lifts the bans on the leaf and shows as refused.
func TestSubscriberBanReachesLeafNodes(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	clock := &banClock{now: time.Now().UTC().Truncate(time.Second)}
	leaf := newBanLeaf(t, leafPool(t), clock)

	platform, site := seedSite(t, pool)
	sub := uuid.New()
	fake := &fakeLeaf{applied: map[uuid.UUID]siteconf.Config{}, sites: map[uuid.UUID]uuid.UUID{},
		block: map[uuid.UUID]bool{}, failCom: map[uuid.UUID]bool{}}
	bridge := &banBridge{leaf: leaf.supply, other: fake}
	svc := New(pool, fakeMarket{targets: []marketclient.SupplyTarget{
		{SubscriptionID: sub, Aggregate: true, FQDN: "bans.supply.example"},
		{SubscriptionID: sub, LeafMemberID: leaf.grant.LeafMemberID, NodePoolRef: leaf.grant.NodePoolRef, GrantID: &leaf.grant.GrantID},
	}}, bridge)
	svc.now = clock.Now
	if _, err := svc.SyncTargets(ctx, platform); err != nil {
		t.Fatal(err)
	}
	var supply uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM site_supplies WHERE market_subscription_id=$1`, sub).Scan(&supply); err != nil {
		t.Fatal(err)
	}
	if err := svc.Bind(ctx, site, supply, "primary", 10); err != nil {
		t.Fatal(err)
	}
	if r, err := svc.Apply(ctx, site, 1, config("203.0.113.10")); err != nil || !r.Applied {
		t.Fatalf("apply = %+v %v", r, err)
	}
	// The leaf site the leaf returned on commit is its real one.
	if _, err := pool.Exec(ctx, `UPDATE site_supply_leaf_sites SET leaf_site_id=$2 WHERE site_id=$1`, site, leaf.site); err != nil {
		t.Fatal(err)
	}

	store := securityban.NewStore(pool, clock.Now).WithMarketDeliveries(svc)
	store.OnChange(svc.WakeBans)
	bans := securityban.NewService(store)
	var scope, owner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT scope_id, owner_user_id FROM sites WHERE id=$1`, site).Scan(&scope, &owner); err != nil {
		t.Fatal(err)
	}
	actor := securityban.Actor{UserID: owner, ScopeID: scope, ScopeKind: "tenant"}
	create := func(client string, seconds int) securityban.Entry {
		t.Helper()
		key := "b-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
		entry, err := bans.Create(ctx, actor, securityban.CreateRequest{SiteID: site, ClientIP: client, DurationSecond: seconds,
			Reason: "subscriber ban", IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatal(err)
		}
		return entry
	}
	delivery := func(id uuid.UUID) *securityban.Delivery {
		t.Helper()
		listed, err := bans.List(ctx, actor, securityban.ListFilter{SiteID: &site, Page: 1, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range listed.Items {
			if item.ID == id {
				return item.Delivery
			}
		}
		t.Fatalf("entry %s not listed", id)
		return nil
	}
	push := func(want int) {
		t.Helper()
		sent, err := svc.PushBans(ctx)
		if err != nil || sent != want {
			t.Fatalf("push sent %d (want %d): %v", sent, want, err)
		}
	}
	state := func(id uuid.UUID, want, reason string) {
		t.Helper()
		got := delivery(id)
		if got == nil || got.State != want || got.Reason != reason || got.Leaves != 1 {
			t.Fatalf("delivery of %s = %+v, want %s/%q", id, got, want, reason)
		}
	}

	// Added: pending until sent, then the leaf holds it and its node gets it.
	a := create("198.51.100.70", 600)
	state(a.ID, securityban.DeliveryPending, "")
	push(1)
	if active, _ := leaf.marketRows(t, clock.Now()); active != 1 {
		t.Fatalf("leaf market rows after the push = %d", active)
	}
	state(a.ID, securityban.DeliveryDelivering, "")
	list := leaf.publishAndAnswer(t)
	if len(list.Bans) != 1 || list.Bans[0].SiteID != leaf.site.String() || list.Bans[0].Client != "198.51.100.70" ||
		list.Bans[0].Until != a.BannedUntil.Unix() {
		t.Fatalf("leaf node list = %+v", list.Bans)
	}
	push(0) // the probe waits its backoff
	clock.add(banCallTimeout + banProbeFirst)
	push(1)
	state(a.ID, securityban.DeliveryEffective, "")
	if got := delivery(a.ID); got.Effective != 1 || got.OwnNodes != 0 {
		t.Fatalf("effective = %+v", got)
	}
	push(0) // effective: refreshed only after banRefresh

	// Released: the leaf releases it at once; the node list carries the release.
	if _, err := bans.Release(ctx, actor, securityban.ReleaseRequest{EntryID: a.ID, RequestID: "rel-a"}); err != nil {
		t.Fatal(err)
	}
	clock.add(banMinGap)
	push(1)
	if active, released := leaf.marketRows(t, clock.Now()); active != 0 || released != 1 {
		t.Fatalf("after release: active=%d released=%d", active, released)
	}
	if list = leaf.publishAndAnswer(t); len(list.Bans) != 0 || len(list.Releases) != 1 {
		t.Fatalf("release list = %+v", list)
	}
	if got := delivery(a.ID); got != nil {
		t.Fatalf("released entry delivery = %+v", got)
	}

	// Expiry needs nothing sent: both lists end it at the same time.
	clock.add(banMinGap)
	b := create("198.51.100.71", 60)
	push(1)
	if active, _ := leaf.marketRows(t, clock.Now()); active != 1 {
		t.Fatalf("short ban not on the leaf: %d", active)
	}
	clock.add(61 * time.Second)
	if active, _ := leaf.marketRows(t, clock.Now()); active != 0 {
		t.Fatalf("expired ban still active on the leaf: %d", active)
	}
	listed, err := bans.List(ctx, actor, securityban.ListFilter{SiteID: &site, State: securityban.StateExpired, Page: 1, Limit: 10})
	if err != nil || listed.Total != 1 || listed.Items[0].ID != b.ID || listed.Items[0].Delivery != nil {
		t.Fatalf("expired on the subscriber = %+v, %v", listed, err)
	}

	// The leaf's operator released one: refused with the reason.
	c := create("198.51.100.72", 86400)
	push(1)
	var leafEntry uuid.UUID
	if err := leaf.pool.QueryRow(ctx, `SELECT id FROM security_ban_entries WHERE site_id=$1 AND source='market'
		AND released_at IS NULL AND banned_until > $2`, leaf.site, clock.Now()).Scan(&leafEntry); err != nil {
		t.Fatal(err)
	}
	operator := leafOperator(t, leaf.pool)
	if _, err := leaf.store.Release(ctx, operator, securityban.ReleaseRequest{EntryID: leafEntry, RequestID: "op"}); err != nil {
		t.Fatal(err)
	}
	clock.add(banCallTimeout + banProbeFirst)
	push(1)
	state(c.ID, securityban.DeliveryRefused, bansync.RefuseReleasedBySupplier)

	// A leaf or market that predates the operation: unsupported, no failure.
	d := create("198.51.100.73", 86400)
	bridge.answer = func() (siteconf.Reply, error) {
		return siteconf.Reply{Operation: bansync.OpSync, Error: "market supply: operation not supported"}, nil
	}
	clock.add(banMinGap)
	push(1)
	state(d.ID, securityban.DeliveryUnsupported, "peer_unsupported")
	clock.add(banMinGap)
	push(0) // held off for unsupportedFor
	bridge.answer = func() (siteconf.Reply, error) {
		return siteconf.Reply{}, &marketclient.RejectedError{Status: 403, Code: "forbidden"}
	}
	clock.add(unsupportedFor)
	push(1)
	state(d.ID, securityban.DeliveryRefused, BanReasonRelayRefused)
	bridge.answer = nil

	// The subscription ended on the leaf: its bans are lifted there.
	if _, err := leaf.supply.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.supply.RefreshLimits(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if active, _ := leaf.marketRows(t, clock.Now()); active != 0 {
		t.Fatalf("ended subscription still bans on the leaf: %d", active)
	}
	clock.add(banRetryLong)
	push(1)
	state(d.ID, securityban.DeliveryRefused, bansync.ErrCodeEnded)

	// A site with neither own nodes nor market leaves says so.
	_, bare := seedSite(t, pool)
	var bareScope, bareOwner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT scope_id, owner_user_id FROM sites WHERE id=$1`, bare).Scan(&bareScope, &bareOwner); err != nil {
		t.Fatal(err)
	}
	bareActor := securityban.Actor{UserID: bareOwner, ScopeID: bareScope, ScopeKind: "tenant"}
	entry, err := bans.Create(ctx, bareActor, securityban.CreateRequest{SiteID: bare, ClientIP: "198.51.100.74", DurationSecond: 600,
		IdempotencyKey: "bare", RequestID: "bare"})
	if err != nil {
		t.Fatal(err)
	}
	listed, err = bans.List(ctx, bareActor, securityban.ListFilter{SiteID: &bare, Page: 1, Limit: 10})
	if err != nil || listed.Total != 1 || listed.Items[0].ID != entry.ID || listed.Items[0].Delivery == nil ||
		listed.Items[0].Delivery.State != securityban.DeliveryNoNodes {
		t.Fatalf("bare site = %+v, %v", listed, err)
	}
}

func leafOperator(t *testing.T, pool *pgxpool.Pool) securityban.Actor {
	t.Helper()
	var scope uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	user := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'op','hash')`,
		user, fmt.Sprintf("op%s", strings.ReplaceAll(user.String(), "-", "")[:16])); err != nil {
		t.Fatal(err)
	}
	return securityban.Actor{UserID: user, ScopeID: scope, ScopeKind: "platform"}
}
