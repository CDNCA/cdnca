//go:build integration

package certificateasset

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// CERT-05（待出包前全量跑，PG）：高级筛选在服务端执行，匹配记录在第二页之后也能查到，
// total 与 counts 按筛选条件计；90 天内到期不含已过期与 91 天；备注可存可查。
func TestCertificateAssetListAdvancedFiltersCoverEveryPage(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "advanced-filters")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool), func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	day := 24 * time.Hour
	importOne := func(key, remark string, notAfter time.Time) ImportResult {
		t.Helper()
		pki := newCertificateFixture(t, leafOptions{domains: []string{key + ".example.com"}, notAfter: notAfter})
		result, err := store.Import(ctx, tenant.actor, ImportRequest{
			TenantScopeID: tenant.actor.ScopeID, Name: key, Remark: remark, Source: SourceUploaded,
			CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
			IdempotencyKey: "filters-" + key, RequestID: "filters-request-" + key,
		})
		if err != nil {
			t.Fatalf("import %s: %v", key, err)
		}
		return result
	}
	// The matches are imported first, so the newest-first list puts them after 25 others.
	within89 := importOne("match-89", "cdn-edge", certificateTestNow.Add(89*day))
	within31 := importOne("match-31", "", certificateTestNow.Add(31*day))
	importOne("outside-91", "", certificateTestNow.Add(91*day))
	for index := 0; index < 25; index++ {
		importOne(fmt.Sprintf("filler-%02d", index), "", certificateTestNow.Add(365*day))
	}
	if within89.Asset.Remark != "cdn-edge" {
		t.Fatalf("remark not returned on import: %#v", within89.Asset)
	}

	list := func(filters ListFilters, page int) ListResult {
		t.Helper()
		result, err := store.ListPage(ctx, tenant.actor, ListRequest{
			TenantScopeID: tenant.actor.ScopeID, Page: page, Limit: 10, Filters: filters,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	within90 := list(ListFilters{Expiry: "within90"}, 1)
	if within90.Total != 2 || len(within90.Items) != 2 || within90.Counts.All != 2 {
		t.Fatalf("within90 = total %d items %d counts %#v", within90.Total, len(within90.Items), within90.Counts)
	}
	ids := map[string]bool{within90.Items[0].ID.String(): true, within90.Items[1].ID.String(): true}
	if !ids[within89.Asset.ID.String()] || !ids[within31.Asset.ID.String()] {
		t.Fatalf("within90 items = %#v", within90.Items)
	}
	if within30 := list(ListFilters{Expiry: "within30"}, 1); within30.Total != 0 {
		t.Fatalf("within30 total = %d", within30.Total)
	}
	remark := list(ListFilters{Remark: "EDGE"}, 1)
	if remark.Total != 1 || remark.Items[0].ID != within89.Asset.ID || remark.Items[0].Remark != "cdn-edge" {
		t.Fatalf("remark = %#v", remark)
	}
	exact := list(ListFilters{Domains: []string{"MATCH-31.example.com"}}, 1)
	if exact.Total != 1 || exact.Items[0].ID != within31.Asset.ID {
		t.Fatalf("exact domains = %#v", exact)
	}
	// Unfiltered, the matches are on page 3 (28 assets, 10 per page).
	if all := list(ListFilters{}, 3); all.Total != 28 || len(all.Items) != 8 {
		t.Fatalf("unfiltered page 3 = total %d items %d", all.Total, len(all.Items))
	}
	if uploaded := list(ListFilters{Source: SourceACME}, 1); uploaded.Total != 0 {
		t.Fatalf("acme source total = %d", uploaded.Total)
	}
	if unbound := list(ListFilters{Sync: "complete"}, 1); unbound.Total != 0 {
		t.Fatalf("an unbound asset matched sync=complete: %d", unbound.Total)
	}
}
