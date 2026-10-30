//go:build integration

package errorpagecontrol

import (
	"bytes"
	"encoding/json"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// fix-usagereport：error_pages.* 六个用量 = 各作用域里最满的那个，口径与守卫相同（被拒/删除的资产不计、
// 已删规则不计、发布按作用域快照算站点数与字节数）。
func TestCountUsageMatchesTheGuardsPostgreSQL(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	limits := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}}
	service, err := NewServiceWithDependencies(fixture.pool, newMemoryContentStore(), &testScanner{name: "test-scanner"},
		limits, audit.New(fixture.pool), time.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	count := func() UsageCounts {
		var result UsageCounts
		if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			result, err = CountUsage(t.Context(), tx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if empty := count(); empty != (UsageCounts{}) {
		t.Fatalf("empty=%+v", empty)
	}

	small := readyAsset(t, service, identities.tenantOwner, identities.tenantScope, "usage-a", []byte("tenant error"), "text/plain")
	big := readyAsset(t, service, identities.tenantOwner, identities.tenantScope, "usage-b", bytes.Repeat([]byte("x"), 300), "text/plain")
	_ = readyAsset(t, service, identities.otherTenantOwner, identities.otherTenantScope, "usage-c", []byte("other"), "text/plain")
	got := count()
	if got.AssetBytes != 300 || got.AssetsCount != 2 || got.TotalBytes != 300+int64(len("tenant error")) {
		t.Fatalf("assets=%+v", got)
	}
	// 删除后资产先进 delete_pending，守卫（asset.go）仍计入额度，清理完成变 deleted 才不计；用量同口径。
	if _, err := service.DeleteAsset(t.Context(), identities.tenantOwner, DeleteAssetRequest{
		AssetID: big.ID, ExpectedRevision: big.Revision, WriteMetadata: writeMetadata("usage-delete"),
	}); err != nil {
		t.Fatal(err)
	}
	if after := count(); after != got {
		t.Fatalf("delete_pending after=%+v before=%+v", after, got)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE error_page_assets SET status='deleted',object_state='absent',
		revision=revision+1 WHERE id=$1`, big.ID); err != nil {
		t.Fatal(err)
	}
	if got = count(); got.AssetBytes != int64(len("tenant error")) || got.AssetsCount != 1 || got.TotalBytes != int64(len("tenant error")) {
		t.Fatalf("after cleanup=%+v", got)
	}

	for index, code := range []int{404, 502} {
		if _, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
			Target:        RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
			Fields:        RuleFields{Category: CategoryEdgeRoute, Match: StatusSelector{Kind: MatchExact, From: code}, AssetID: small.ID, Enabled: true},
			WriteMetadata: writeMetadata("usage-rule-" + string(rune('a'+index))),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got = count()
	if got.RulesPerScope != 2 || got.PublicationSites != 1 || got.PublicationBytes <= 0 {
		t.Fatalf("rules=%+v", got)
	}
	// 发布字节 = 该作用域快照规范 JSON 长度（publication.go validatePublicationLimits 同口径）。
	var revision int64
	var want int
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(), `SELECT max(revision) FROM error_page_publications`).Scan(&revision); err != nil {
			return err
		}
		snapshot, err := buildSnapshotForScope(t.Context(), tx, revision, MaxPublicationSites, MaxEdgeRulesPerScope, identities.tenantScope)
		if err != nil {
			return err
		}
		canonical, err := json.Marshal(snapshot)
		want = len(canonical)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got.PublicationBytes != int64(want) {
		t.Fatalf("publication bytes=%d want %d", got.PublicationBytes, want)
	}
}
