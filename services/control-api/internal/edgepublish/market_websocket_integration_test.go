//go:build integration

package edgepublish

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// every market supply includes WebSocket. A hidden
// market product froze its grant's websocket switch, false on grants signed
// before market 077; that switch no longer turns the buyer's WebSocket off.
// An ordinary sold package keeps gating it.
func TestSoldPackageWebSocketIgnoredForMarketSupply(t *testing.T) {
	fixture := newPublishFixture(t)
	site := fixture.createSite(t, "market-ws.example.com", 80, false).Site
	setSpec := func(market bool) {
		t.Helper()
		// The sold snapshot is immutable once sold: the fixture bypasses the triggers.
		if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET product_snapshot=jsonb_set(product_snapshot, '{spec}',
				((product_snapshot->'spec') - 'market')
				|| jsonb_build_object('limits', COALESCE(product_snapshot#>'{spec,limits}', '{}'::jsonb) || '{"websocket":false}'::jsonb)
				|| CASE WHEN $2::boolean THEN '{"market":{"node_pool_ref":"x"}}'::jsonb ELSE '{}'::jsonb END)
				WHERE id=$1`, fixture.subscriptionID, market)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	load := func() soldPackageLimits {
		t.Helper()
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		limits, err := loadSoldPackageLimits(t.Context(), tx, fixture.scopeID)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := limits[site.ID]
		if !ok {
			t.Fatalf("site %s has no sold package limits: %+v", site.ID, limits)
		}
		return got
	}
	setSpec(false)
	if got := load(); got.WebSocket == nil || *got.WebSocket {
		t.Fatalf("ordinary package websocket=false must stay a gate: %+v", got.WebSocket)
	}
	setSpec(true)
	if got := load(); got.WebSocket != nil {
		t.Fatalf("market supply websocket=false must not gate the site: %v", *got.WebSocket)
	}
}
