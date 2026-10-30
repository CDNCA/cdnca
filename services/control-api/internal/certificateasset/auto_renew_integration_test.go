//go:build integration

package certificateasset

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// fix-autorenew（迁移 537）：自动续签放在证书资产层，可直接开关；
// 列表计数、续签到期判断都读资产层；手动上传证书不可开启。
func TestCertificateAssetAutoRenewToggle(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "autorenew")
	other := createCertificateTenant(t, pool, "autorenew-other")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool), func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	domains := []string{"renew.example.com"}
	pki := newCertificateFixture(t, leafOptions{domains: domains, notAfter: certificateTestNow.Add(60 * 24 * time.Hour)})
	orderID := insertCertificateOrder(t, pool, tenant.actor, domains, pki.leaf.NotAfter)
	acme, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "acme", Source: SourceACME, ACMEOrderID: &orderID,
		CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "autorenew-acme", RequestID: "autorenew-acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	seedCertificateOrderFact(t, pool, `UPDATE certificate_orders SET issued_asset_id=$1,issued_asset_version_id=$2 WHERE id=$3`,
		acme.Asset.ID, acme.Version.ID, orderID)
	uploadedPKI := newCertificateFixture(t, leafOptions{domains: []string{"manual.example.com"}})
	uploaded, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "manual", Source: SourceUploaded,
		CertificatePEM: uploadedPKI.certificatePEM, PrivateKeyPEM: uploadedPKI.privateKeyPEM,
		IdempotencyKey: "autorenew-manual", RequestID: "autorenew-manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	// ACME 资产导入时按签发订单的 auto_renew 记下（订单 auto_renew=true）。
	if acme.Asset.AutoRenew != true || uploaded.Asset.AutoRenew {
		t.Fatalf("initial auto_renew acme=%v uploaded=%v", acme.Asset.AutoRenew, uploaded.Asset.AutoRenew)
	}
	counts := func() ListCounts {
		t.Helper()
		result, err := store.ListPage(ctx, tenant.actor, ListRequest{TenantScopeID: tenant.actor.ScopeID, Page: 1, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		return result.Counts
	}
	due := func() int {
		t.Helper()
		versions, err := store.ListRenewalDue(ctx, tenant.actor, tenant.actor.ScopeID, certificateTestNow.Add(31*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return len(versions)
	}
	if c := counts(); c.AutoRenew != 1 || c.ManualRenew != 1 || due() != 1 {
		t.Fatalf("before toggle counts=%+v due=%d", c, due())
	}

	off, err := store.SetAutoRenew(ctx, tenant.actor, SetAutoRenewRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: acme.Asset.ID, Enabled: false,
		ExpectedRevision: acme.Asset.Revision, IdempotencyKey: "toggle-off", RequestID: "toggle-off",
	})
	if err != nil || off.AutoRenew || off.Revision != acme.Asset.Revision+1 {
		t.Fatalf("toggle off = %+v, %v", off, err)
	}
	if c := counts(); c.AutoRenew != 0 || c.ManualRenew != 2 || due() != 0 {
		t.Fatalf("after off counts=%+v due=%d", c, due())
	}
	// 订单快照不变。
	var orderAutoRenew bool
	if err := pool.QueryRow(ctx, `SELECT auto_renew FROM certificate_orders WHERE id=$1`, orderID).Scan(&orderAutoRenew); err != nil || !orderAutoRenew {
		t.Fatalf("order snapshot auto_renew=%v err=%v", orderAutoRenew, err)
	}
	// 同幂等键重放返回同一结果、不再推进 revision。
	replay, err := store.SetAutoRenew(ctx, tenant.actor, SetAutoRenewRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: acme.Asset.ID, Enabled: false,
		ExpectedRevision: acme.Asset.Revision, IdempotencyKey: "toggle-off", RequestID: "toggle-off-2",
	})
	if err != nil || replay.Revision != off.Revision {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	// 过期 revision 冲突。
	if _, err := store.SetAutoRenew(ctx, tenant.actor, SetAutoRenewRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: acme.Asset.ID, Enabled: true,
		ExpectedRevision: acme.Asset.Revision, IdempotencyKey: "toggle-stale", RequestID: "toggle-stale",
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale = %v", err)
	}
	on, err := store.SetAutoRenew(ctx, tenant.actor, SetAutoRenewRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: acme.Asset.ID, Enabled: true,
		ExpectedRevision: off.Revision, IdempotencyKey: "toggle-on", RequestID: "toggle-on",
	})
	if err != nil || !on.AutoRenew || counts().AutoRenew != 1 || due() != 1 {
		t.Fatalf("toggle on = %+v, %v counts=%+v", on, err, counts())
	}
	// 手动上传证书不可开启。
	if _, err := store.SetAutoRenew(ctx, tenant.actor, SetAutoRenewRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: uploaded.Asset.ID, Enabled: true,
		ExpectedRevision: uploaded.Asset.Revision, IdempotencyKey: "toggle-manual", RequestID: "toggle-manual",
	}); !errors.Is(err, ErrAutoRenewUnsupported) {
		t.Fatalf("uploaded toggle = %v", err)
	}
	// 其他租户不能改。
	if _, err := store.SetAutoRenew(ctx, other.actor, SetAutoRenewRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: acme.Asset.ID, Enabled: false,
		ExpectedRevision: on.Revision, IdempotencyKey: "toggle-other", RequestID: "toggle-other",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant toggle = %v", err)
	}
	// 审计 certificate.auto_renew.update 带前后值。
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='certificate.auto_renew.update'
		AND result='success' AND resource_id=$2 AND changes::text LIKE '%auto_renew%'`,
		tenant.actor.ScopeID, acme.Asset.ID.String()).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("audit count=%d err=%v", auditCount, err)
	}
	// 数据库约束：手动上传资产不能被直接写成自动续签。
	if _, err := pool.Exec(ctx, `UPDATE certificate_assets SET auto_renew=true,revision=revision+1 WHERE id=$1`, uploaded.Asset.ID); err == nil {
		t.Fatal("uploaded asset accepted auto_renew=true")
	}
}
