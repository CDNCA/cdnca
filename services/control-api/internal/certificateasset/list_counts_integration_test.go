//go:build integration

package certificateasset

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// tp-b4b: the list's per-status counts cover every asset (not one page),
// the status filter matches them, and both stay inside the tenant.
func TestCertificateAssetListCountsAndStatusFilter(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenantA := createCertificateTenant(t, pool, "counts-a")
	tenantB := createCertificateTenant(t, pool, "counts-b")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool), func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	importOne := func(tenant certificateTenantFixture, key string, notAfter time.Time) ImportResult {
		t.Helper()
		pki := newCertificateFixture(t, leafOptions{domains: []string{key + ".example.com"}, notAfter: notAfter})
		result, err := store.Import(ctx, tenant.actor, ImportRequest{
			TenantScopeID: tenant.actor.ScopeID, Name: key, Source: SourceUploaded,
			CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
			IdempotencyKey: "counts-" + key, RequestID: "counts-request-" + key,
		})
		if err != nil {
			t.Fatalf("import %s: %v", key, err)
		}
		return result
	}
	day := 24 * time.Hour
	normal := importOne(tenantA, "normal", certificateTestNow.Add(90*day))
	expiring := importOne(tenantA, "expiring", certificateTestNow.Add(10*day))
	expired := importOne(tenantA, "expired", certificateTestNow.Add(60*day))
	// An auto-renewing ACME certificate (migration 537: auto-renew is on the asset,
	// taken from the issuing order; uploaded certificates never auto-renew).
	renewedPKI := newCertificateFixture(t, leafOptions{domains: []string{"renewed.example.com"}, notAfter: certificateTestNow.Add(80 * day)})
	orderID := insertCertificateOrder(t, pool, tenantA.actor, []string{"renewed.example.com"}, renewedPKI.leaf.NotAfter)
	renewed, err := store.Import(ctx, tenantA.actor, ImportRequest{
		TenantScopeID: tenantA.actor.ScopeID, Name: "renewed", Source: SourceACME, ACMEOrderID: &orderID,
		CertificatePEM: renewedPKI.certificatePEM, PrivateKeyPEM: renewedPKI.privateKeyPEM,
		IdempotencyKey: "counts-renewed", RequestID: "counts-request-renewed",
	})
	if err != nil {
		t.Fatalf("import renewed: %v", err)
	}
	importOne(tenantB, "other", certificateTestNow.Add(5*day))
	// Expired: move not_after into the past (an import of an expired leaf is refused).
	setVersionNotAfter(t, pool, expired, certificateTestNow.Add(-day))
	seedCertificateOrderFact(t, pool, `UPDATE certificate_orders SET issued_asset_id=$1 WHERE id=$2`, renewed.Asset.ID, orderID)

	list := func(tenant certificateTenantFixture, status string) ListResult {
		t.Helper()
		result, err := store.ListPage(ctx, tenant.actor, ListRequest{
			TenantScopeID: tenant.actor.ScopeID, Page: 1, Limit: 1, Status: status,
		})
		if err != nil {
			t.Fatalf("list %q: %v", status, err)
		}
		return result
	}
	all := list(tenantA, "")
	want := ListCounts{All: 4, Normal: 2, Expiring: 1, Expired: 1, AutoRenew: 1, ManualRenew: 3}
	if all.Counts != want || all.Total != 4 || len(all.Items) != 1 {
		t.Fatalf("counts = %+v total %d items %d, want %+v", all.Counts, all.Total, len(all.Items), want)
	}
	for status, expected := range map[string][]ImportResult{
		"normal": {normal, renewed}, "expiring": {expiring}, "expired": {expired},
		"auto_renew": {renewed}, "manual_renew": {normal, expiring, expired},
	} {
		result, err := store.ListPage(ctx, tenantA.actor, ListRequest{
			TenantScopeID: tenantA.actor.ScopeID, Page: 1, Limit: 100, Status: status,
		})
		if err != nil || result.Total != int64(len(expected)) || len(result.Items) != len(expected) || result.Counts != want {
			t.Fatalf("status %s = %+v, %v", status, result, err)
		}
		for _, item := range expected {
			if !certificateAssetListed(result.Items, item.Asset.ID) {
				t.Fatalf("status %s misses %s", status, item.Asset.Name)
			}
		}
	}
	// Counts follow the search.
	searched, err := store.ListPage(ctx, tenantA.actor, ListRequest{
		TenantScopeID: tenantA.actor.ScopeID, Page: 1, Limit: 10, Search: "expir",
	})
	if err != nil || searched.Counts != (ListCounts{All: 2, Expiring: 1, Expired: 1, ManualRenew: 2}) {
		t.Fatalf("searched counts = %+v, %v", searched.Counts, err)
	}
	// Tenant B sees only its own asset.
	other := list(tenantB, "")
	if other.Counts != (ListCounts{All: 1, Expiring: 1, ManualRenew: 1}) || other.Total != 1 {
		t.Fatalf("tenant b counts = %+v", other.Counts)
	}
	if _, err := store.ListPage(ctx, tenantB.actor, ListRequest{
		TenantScopeID: tenantA.actor.ScopeID, Page: 1, Limit: 10,
	}); err == nil {
		t.Fatal("tenant b listed tenant a")
	}
	if _, err := store.ListPage(ctx, tenantA.actor, ListRequest{
		TenantScopeID: tenantA.actor.ScopeID, Page: 1, Limit: 10, Status: "bogus",
	}); err != ErrInvalidInput {
		t.Fatalf("bogus status = %v", err)
	}
}

func setVersionNotAfter(t *testing.T, pool *pgxpool.Pool, result ImportResult, notAfter time.Time) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SET LOCAL session_replication_role=replica`); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE certificate_asset_versions SET not_after=$1::timestamptz,
			not_before=LEAST(not_before,$1::timestamptz - interval '30 days') WHERE tenant_scope_id=$2 AND id=$3`,
			notAfter, result.Asset.TenantScopeID, result.Version.ID)
		return err
	}); err != nil {
		t.Fatalf("set not_after: %v", err)
	}
}
