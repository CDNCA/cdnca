//go:build integration

package acmedispatch

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
)

// fix-autorenew（迁移 537）：续签调度以证书资产层的自动续签为准，
// 订单上的 auto_renew 只是下单快照。
func TestRenewalSchedulerFollowsAssetAutoRenew(t *testing.T) {
	fixture := newDispatchFixture(t, isolatedDispatchPool(t), dispatchFixtureOptions{
		finalizing: true, certificateLifetime: dueRenewalLifetime,
	})
	if err := fixture.store.Save(context.Background(), fixture.lease, fixture.certificate); err != nil {
		t.Fatal(err)
	}
	activateDispatchFixture(t, fixture)
	setAssetAutoRenew := func(enabled bool) {
		t.Helper()
		if _, err := fixture.pool.Exec(context.Background(), `UPDATE certificate_assets asset
			SET auto_renew=$3,revision=asset.revision+1,updated_at=GREATEST(asset.updated_at,statement_timestamp())
			FROM certificate_orders cert_order
			WHERE cert_order.scope_id=$1 AND cert_order.id=$2
			  AND asset.tenant_scope_id=cert_order.scope_id AND asset.id=cert_order.issued_asset_id`,
			fixture.tenant.scopeID, fixture.request.CertificateOrderID, enabled); err != nil {
			t.Fatal(err)
		}
	}
	store := dnsacme.NewStore(fixture.pool)
	setAssetAutoRenew(false)
	if scheduled, err := store.ScheduleDueRenewal(context.Background(), 30*24*time.Hour, 10*time.Minute); err != nil || scheduled {
		t.Fatalf("asset auto-renew off: scheduled=%t error=%v", scheduled, err)
	}
	setAssetAutoRenew(true)
	if scheduled, err := store.ScheduleDueRenewal(context.Background(), 30*24*time.Hour, 10*time.Minute); err != nil || !scheduled {
		t.Fatalf("asset auto-renew on: scheduled=%t error=%v", scheduled, err)
	}
	var childAutoRenew bool
	if err := fixture.pool.QueryRow(context.Background(), `SELECT auto_renew FROM certificate_orders
		WHERE scope_id=$1 AND renewal_of_order_id=$2`, fixture.tenant.scopeID,
		fixture.request.CertificateOrderID).Scan(&childAutoRenew); err != nil || !childAutoRenew {
		t.Fatalf("renewal child auto_renew=%t error=%v", childAutoRenew, err)
	}
}
