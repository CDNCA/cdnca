//go:build integration

package errorpagecontrol

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// A ready asset's body is read back for editing
// (GET .../assets/{id}/content); a staged one is a conflict; another
// tenant's asset is not found.
func TestErrorPageAssetContentPostgreSQL(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	clock := &testClock{now: time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)}
	limits := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1000, MaxTotalBytes: 8 << 20}}
	service, err := NewServiceWithDependencies(fixture.pool, newMemoryContentStore(), &testScanner{name: "test-scanner"}, limits,
		audit.New(fixture.pool), clock.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("<!doctype html><h1>404 页面不存在</h1>")
	asset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope, "content-read", body, "text/html")
	got, err := service.GetAssetContent(t.Context(), identities.tenantOwner, asset.ID)
	if err != nil || got.Content != string(body) || got.Asset.ID != asset.ID {
		t.Fatalf("content = %+v, %v", got, err)
	}
	if got, err := service.GetAssetContent(t.Context(), identities.tenantViewer, asset.ID); err != nil || got.Content != string(body) {
		t.Fatalf("viewer (error_pages.read) content = %+v, %v", got, err)
	}
	staged := initiateAsset(t, service, identities.tenantOwner, identities.tenantScope, "content-staged", []byte("x"), "text/plain")
	if _, err := service.GetAssetContent(t.Context(), identities.tenantOwner, staged.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("staged asset err = %v, want conflict", err)
	}
	platform := readyAsset(t, service, identities.platform, identities.platformScope, "content-platform", []byte("p"), "text/plain")
	if _, err := service.GetAssetContent(t.Context(), identities.tenantOwner, platform.ID); err == nil {
		t.Fatal("tenant read another scope's asset")
	}
}
