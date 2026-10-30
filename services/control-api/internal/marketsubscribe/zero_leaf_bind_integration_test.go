package marketsubscribe

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
)

// Codex triage-2 "零叶子供给仍可绑定": an active market supply whose grants
// are all gone takes no new binding (ErrNoLeaves, before Apply's targets
// would refuse it); a binding made while it had leaves stays, and binding
// works again once the leaves come back.
func TestZeroLeafSupplyRefusesNewBindingKeepsOld(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	platform, site := seedSite(t, pool)
	_, other := seedSite(t, pool)
	sub := uuid.New()
	leaf, grant := uuid.New(), uuid.New()
	withLeaf := fakeMarket{targets: []marketclient.SupplyTarget{
		{SubscriptionID: sub, Aggregate: true, FQDN: "z0leafabcdef.supply.example"},
		{SubscriptionID: sub, LeafMemberID: leaf, NodePoolRef: "pa", GrantID: &grant},
	}}
	noLeaf := fakeMarket{targets: withLeaf.targets[:1]}
	svc := New(pool, withLeaf, &fakeLeaf{})
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

	svc.market = noLeaf
	if _, err := svc.SyncTargets(ctx, platform); err != nil {
		t.Fatal(err)
	}
	if err := svc.Bind(ctx, other, supply, "primary", 10); !errors.Is(err, ErrNoLeaves) {
		t.Fatalf("new binding to a zero-leaf supply: want ErrNoLeaves, got %v", err)
	}
	// The existing binding stays and may still change role/priority.
	if err := svc.Bind(ctx, site, supply, "backup", 20); err != nil {
		t.Fatalf("existing binding update: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_supply_bindings WHERE supply_id=$1`, supply).Scan(&n); err != nil || n != 1 {
		t.Fatalf("bindings = %d, %v", n, err)
	}
	if err := svc.Bind(ctx, uuid.New(), supply, "primary", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown site: %v", err)
	}

	svc.market = withLeaf
	if _, err := svc.SyncTargets(ctx, platform); err != nil {
		t.Fatal(err)
	}
	if err := svc.Bind(ctx, other, supply, "primary", 10); err != nil {
		t.Fatalf("binding after leaves came back: %v", err)
	}
}
