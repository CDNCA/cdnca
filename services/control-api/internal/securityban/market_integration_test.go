//go:build integration

package securityban_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// marketTenant turns a seeded tenant into a market tenant (its owner is the
// market supply's mkt-<key> account).
func marketTenant(t *testing.T, pool *pgxpool.Pool, fixture tenantFixture) string {
	t.Helper()
	key := strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
	exec(t, pool, `UPDATE users SET username=$2 WHERE id=$1`, fixture.owner, "mkt-"+key)
	return key
}

func marketBan(client string, until time.Time) bansync.Ban {
	return bansync.Ban{Ref: uuid.New(), Client: client, Until: until.Unix(), Source: "manual", Reason: "subscriber"}
}

// TestSecurityBanMarketSnapshotToNodes: a subscriber's snapshot
// becomes source market rows on the leaf site, the distributor sends them to
// the node serving it (as manual on the wire), and SiteDelivery follows the
// node's receipt; a stale snapshot writes nothing; a release and an absent
// entry lift the rows; an entry the operator released is refused afterwards;
// another tenant's site, too many snapshots and an invalid client are refused;
// the subscription's end releases everything and its return bans again.
func TestSecurityBanMarketSnapshotToNodes(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := &clock{now: time.Now().UTC().Truncate(time.Second)}
	store := securityban.NewStore(pool, now.Now)
	leaf, other := seedTenant(t, pool, "sbm-a-"+uuid.NewString()[:6]), seedTenant(t, pool, "sbm-b-"+uuid.NewString()[:6])
	key := marketTenant(t, pool, leaf)
	node := seedNode(t, pool, leaf)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &transport{}
	distributor, err := securityban.NewDistributor(securityban.DistributorConfig{Pool: pool, Transport: carrier, KeyID: "test-key",
		Sign:     func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Minute, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	woken := 0
	store.OnChange(func() { woken++ })
	trusted := func(keyID string) (ed25519.PublicKey, bool) { return public, keyID == "test-key" }
	subscriberSite := uuid.New()
	revision := int64(1000)
	apply := func(bans []bansync.Ban, releases []bansync.Release) (securityban.MarketResult, error) {
		t.Helper()
		revision++
		request := bansync.Request{SiteID: subscriberSite, LeafSiteID: leaf.site, Revision: revision, Bans: bans, Releases: releases}
		if err := request.Normalize(); err != nil {
			t.Fatal(err)
		}
		return store.ApplyMarket(ctx, securityban.MarketSync{TenantScopeID: leaf.scope, Key: key, Request: request, RequestID: "sync"})
	}

	first, second, loop := marketBan("198.51.100.40", now.now.Add(10*time.Minute)),
		marketBan("2001:db8::40", now.now.Add(20*time.Minute)), marketBan("127.0.0.1", now.now.Add(time.Hour))
	result, err := apply([]bansync.Ban{first, second, loop}, nil)
	if err != nil || result.Stale || result.Accepted != 2 || len(result.Refused) != 1 || result.Refused[0].Ref != loop.Ref ||
		result.Refused[0].Code != bansync.RefuseInvalidClient || !result.ChangedAt.Equal(now.now) || woken != 1 {
		t.Fatalf("first snapshot = %+v, %v (woken %d)", result, err, woken)
	}
	admin := platformActor(t, pool)
	listed, err := securityban.NewService(store).List(ctx, admin, securityban.ListFilter{SiteID: &leaf.site, State: securityban.StateActive, Page: 1, Limit: 20})
	if err != nil || listed.Total != 2 {
		t.Fatalf("leaf list = %+v, %v", listed, err)
	}
	for _, item := range listed.Items {
		if item.Source != securityban.SourceMarket || item.Market == nil || item.Market.Subscription != key ||
			item.Market.BuyerSource != "manual" || item.Reason != "subscriber" {
			t.Fatalf("market row = %+v (%+v)", item, item.Market)
		}
	}

	// Not yet sent: delivering. Sent and answered: applied.
	if nodes, err := distributor.SiteDelivery(ctx, leaf.site, result.ChangedAt); err != nil ||
		nodes.State != bansync.NodesDelivering || nodes.Total != 1 || nodes.Applied != 0 {
		t.Fatalf("before the pass: %+v, %v", nodes, err)
	}
	if err := distributor.PublishOnce(ctx); err != nil || len(carrier.published) != 1 || carrier.published[0].nodeID != node.String() {
		t.Fatalf("publish = %+v, %v", carrier.published, err)
	}
	list, err := contract.Open(carrier.published[0].encoded, node.String(), trusted)
	if err != nil || len(list.Bans) != 2 || list.Bans[0].Source != securityban.SourceManual || list.Bans[0].SiteID != leaf.site.String() {
		t.Fatalf("node list = %+v, %v", list, err)
	}
	if nodes, err := distributor.SiteDelivery(ctx, leaf.site, result.ChangedAt); err != nil || nodes.State != bansync.NodesDelivering {
		t.Fatalf("unanswered: %+v, %v", nodes, err)
	}
	distributor.HandleReceipt(ctx, &receipt{report: &agentv1.SecurityBanStatus{NodeId: node.String(), Revision: list.Revision,
		ListSha256: contract.Digest(carrier.published[0].encoded), Applied: true, Bans: 2}})
	if nodes, err := distributor.SiteDelivery(ctx, leaf.site, result.ChangedAt); err != nil ||
		nodes.State != bansync.NodesApplied || nodes.Applied != 1 {
		t.Fatalf("answered: %+v, %v", nodes, err)
	}

	// The same snapshot again changes nothing; an older one is skipped.
	again, err := apply([]bansync.Ban{first, second, loop}, nil)
	if err != nil || again.Stale || !again.ChangedAt.Equal(result.ChangedAt) || woken != 1 {
		t.Fatalf("same snapshot = %+v, %v (woken %d)", again, err, woken)
	}
	old := bansync.Request{SiteID: subscriberSite, LeafSiteID: leaf.site, Revision: 1, Bans: []bansync.Ban{}, Releases: []bansync.Release{}}
	if stale, err := store.ApplyMarket(ctx, securityban.MarketSync{TenantScopeID: leaf.scope, Key: key, Request: old}); err != nil ||
		!stale.Stale || stale.Revision != revision {
		t.Fatalf("stale snapshot = %+v, %v", stale, err)
	}

	// A release releases; an entry the snapshot no longer lists expires now.
	now.now = now.now.Add(time.Minute)
	result, err = apply(nil, []bansync.Release{{Ref: first.Ref, ReleasedAt: now.now.Unix()}})
	if err != nil || len(result.Refused) != 0 || !result.ChangedAt.Equal(now.now) || woken != 2 {
		t.Fatalf("release snapshot = %+v, %v", result, err)
	}
	var released, expired int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE released_at IS NOT NULL),
			count(*) FILTER (WHERE released_at IS NULL AND banned_until <= $2)
		FROM security_ban_entries WHERE site_id=$1 AND source='market'`, leaf.site, now.now).Scan(&released, &expired); err != nil ||
		released != 1 || expired != 1 {
		t.Fatalf("released=%d expired=%d err=%v", released, expired, err)
	}
	// A released entry never bans again; nor does one the operator released.
	third := marketBan("198.51.100.41", now.now.Add(10*time.Minute))
	if result, err = apply([]bansync.Ban{first, third}, nil); err != nil || len(result.Refused) != 0 {
		t.Fatalf("after release = %+v, %v", result, err)
	}
	active, err := securityban.NewService(store).List(ctx, admin, securityban.ListFilter{SiteID: &leaf.site, State: securityban.StateActive, Page: 1, Limit: 20})
	if err != nil || active.Total != 1 || active.Items[0].ClientIP != "198.51.100.41" {
		t.Fatalf("active after release = %+v, %v", active, err)
	}
	if _, err := store.Release(ctx, admin, securityban.ReleaseRequest{EntryID: active.Items[0].ID, RequestID: "op"}); err != nil {
		t.Fatal(err)
	}
	if result, err = apply([]bansync.Ban{third}, nil); err != nil || len(result.Refused) != 1 ||
		result.Refused[0].Code != bansync.RefuseReleasedBySupplier {
		t.Fatalf("after operator release = %+v, %v", result, err)
	}

	// Only the tenant's own live site.
	foreign := bansync.Request{SiteID: subscriberSite, LeafSiteID: other.site, Revision: revision + 100, Bans: []bansync.Ban{}, Releases: []bansync.Release{}}
	if _, err := store.ApplyMarket(ctx, securityban.MarketSync{TenantScopeID: leaf.scope, Key: key, Request: foreign}); !errors.Is(err, securityban.ErrMarketSiteNotFound) {
		t.Fatalf("other tenant's site: %v", err)
	}
	// At most MaxMarketMessagesPerMinute snapshots a minute per site.
	now.now = now.now.Add(time.Minute)
	for i := 0; i < securityban.MaxMarketMessagesPerMinute; i++ {
		if _, err := apply(nil, nil); err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
	}
	if _, err := apply(nil, nil); !errors.Is(err, securityban.ErrMarketRateLimited) {
		t.Fatalf("over the message rate: %v", err)
	}

	// Subscription ended: every active row released; served again, banned again.
	now.now = now.now.Add(time.Minute)
	fourth := marketBan("198.51.100.42", now.now.Add(10*time.Minute))
	if result, err = apply([]bansync.Ban{fourth}, nil); err != nil || len(result.Refused) != 0 {
		t.Fatalf("fourth = %+v, %v", result, err)
	}
	tenants, err := store.ActiveMarketTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tenant := range tenants {
		found = found || tenant.ScopeID == leaf.scope && tenant.Key == key
	}
	if !found {
		t.Fatalf("active market tenants = %+v", tenants)
	}
	if n, err := store.ReleaseMarketTenant(ctx, securityban.MarketTenant{ScopeID: leaf.scope, Key: key}, "subscription_ended"); err != nil || n != 1 {
		t.Fatalf("release tenant = %d, %v", n, err)
	}
	if got := auditCount(t, pool, leaf.scope, securityban.AuditMarketRelease, "success"); got != 1 {
		t.Fatalf("market release audits = %d", got)
	}
	now.now = now.now.Add(time.Second)
	if result, err = apply([]bansync.Ban{fourth}, nil); err != nil || len(result.Refused) != 0 {
		t.Fatalf("after resume = %+v, %v", result, err)
	}
	active, err = securityban.NewService(store).List(ctx, admin, securityban.ListFilter{SiteID: &leaf.site, State: securityban.StateActive, Page: 1, Limit: 20})
	if err != nil || active.Total != 1 || active.Items[0].ClientIP != "198.51.100.42" {
		t.Fatalf("active after resume = %+v, %v", active, err)
	}
	if got := auditCount(t, pool, leaf.scope, securityban.AuditMarketSync, "success"); got < 5 {
		t.Fatalf("market sync audits = %d", got)
	}
}

// TestSecurityBanMarketTenantLimits: new market rows are limited per minute
// over the subscription; what is over is refused and taken on a later
// snapshot.
func TestSecurityBanMarketTenantLimits(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := &clock{now: time.Now().UTC().Truncate(time.Second)}
	store := securityban.NewStore(pool, now.Now)
	leaf := seedTenant(t, pool, "sbl-"+uuid.NewString()[:6])
	key := marketTenant(t, pool, leaf)
	bans := make([]bansync.Ban, 0, securityban.MaxMarketNewPerMinute+5)
	for i := 0; i < securityban.MaxMarketNewPerMinute+5; i++ {
		bans = append(bans, marketBan("198.51."+itoa(100+i/250)+"."+itoa(1+i%250), now.now.Add(time.Hour)))
	}
	request := bansync.Request{SiteID: uuid.New(), LeafSiteID: leaf.site, Revision: 1, Bans: bans}
	if err := request.Normalize(); err != nil {
		t.Fatal(err)
	}
	result, err := store.ApplyMarket(ctx, securityban.MarketSync{TenantScopeID: leaf.scope, Key: key, Request: request})
	if err != nil || result.Accepted != securityban.MaxMarketNewPerMinute || len(result.Refused) != 5 {
		t.Fatalf("over the rate: accepted=%d refused=%d err=%v", result.Accepted, len(result.Refused), err)
	}
	for _, refusal := range result.Refused {
		if refusal.Code != bansync.RefuseRateLimited {
			t.Fatalf("refusal = %+v", refusal)
		}
	}
	now.now = now.now.Add(61 * time.Second)
	request.Revision = 2
	if result, err = store.ApplyMarket(ctx, securityban.MarketSync{TenantScopeID: leaf.scope, Key: key, Request: request}); err != nil ||
		len(result.Refused) != 0 || result.Accepted != len(bans) {
		t.Fatalf("a minute later: accepted=%d refused=%d err=%v", result.Accepted, len(result.Refused), err)
	}
}

func itoa(v int) string {
	const digits = "0123456789"
	if v < 10 {
		return digits[v : v+1]
	}
	return itoa(v/10) + digits[v%10:v%10+1]
}
