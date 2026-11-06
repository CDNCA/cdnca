package marketsubscribe

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
)

type offerNamesMarket struct{ targets []marketclient.SupplyTarget }

func (m *offerNamesMarket) SupplyTargets(context.Context) ([]marketclient.SupplyTarget, error) {
	return m.targets, nil
}

// A market supply is named by the seller's offer name (supply-targets
// offer_name); a subscription without one keeps the default name, and an older
// market that stops sending it does not erase the name already stored.
func TestMarketSupplyTakesOfferName(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	platform, _ := seedSite(t, pool)
	sub, other, long, leaf, grant := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	market := &offerNamesMarket{targets: []marketclient.SupplyTarget{
		{SubscriptionID: sub, Aggregate: true, FQDN: "names.supply.example", OfferName: "  测试\t· 3b08628a "},
		{SubscriptionID: sub, LeafMemberID: leaf, NodePoolRef: "pn", GrantID: &grant, OfferName: "测试 · 3b08628a"},
		{SubscriptionID: other, Aggregate: true, FQDN: "old.supply.example"},
		{SubscriptionID: long, Aggregate: true, FQDN: "long.supply.example", OfferName: strings.Repeat("名", 130)},
	}}
	svc := New(pool, market, nil)
	if _, err := svc.SyncTargets(ctx, platform); err != nil {
		t.Fatal(err)
	}
	nameOf := func(id uuid.UUID) string {
		t.Helper()
		all, err := svc.Supplies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(all, func(s Supply) bool { return s.MarketSubscriptionID == id })
		if i < 0 {
			t.Fatalf("no supply for %s", id)
		}
		return all[i].Name
	}
	// Control characters become spaces and the ends are trimmed.
	if got := nameOf(sub); got != "测试 · 3b08628a" {
		t.Fatalf("named supply %q", got)
	}
	if got := nameOf(other); got != "市场订阅 "+other.String()[:8] {
		t.Fatalf("supply without offer name %q", got)
	}
	if got := nameOf(long); got != strings.Repeat("名", 128) {
		t.Fatalf("long offer name kept %d runes", len([]rune(got)))
	}
	for i := range market.targets {
		market.targets[i].OfferName = ""
	}
	if _, err := svc.SyncTargets(ctx, platform); err != nil {
		t.Fatal(err)
	}
	if got := nameOf(sub); got != "测试 · 3b08628a" {
		t.Fatalf("older market overwrote the name: %q", got)
	}
}
