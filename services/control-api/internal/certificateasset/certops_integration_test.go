//go:build integration

package certificateasset

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// fix-certops（迁移 551）：禁用/启用证书与下载证书。
func TestCertificateAssetDisableAndDownload(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "certops")
	other := createCertificateTenant(t, pool, "certops-other")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool), func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	imported, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "edge", Source: SourceUploaded,
		CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "certops-import", RequestID: "certops-import",
	})
	if err != nil {
		t.Fatal(err)
	}
	if imported.Asset.Disabled {
		t.Fatal("new asset is disabled")
	}

	// 下载：fullchain 为规范 PEM，私钥与上传的一致（PKCS#8），写审计。
	material, err := store.Download(ctx, tenant.actor, DownloadRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, RequestID: "certops-download",
	})
	if err != nil || string(material.CertificatePEM) != string(imported.Version.CertificatePEM) ||
		!strings.Contains(string(material.PrivateKeyPEM), "BEGIN PRIVATE KEY") {
		t.Fatalf("download = %+v, %v", material, err)
	}
	var downloads int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='certificate.asset.download'
		AND result='success' AND resource_id=$2`, tenant.actor.ScopeID, imported.Asset.ID.String()).Scan(&downloads); err != nil || downloads != 1 {
		t.Fatalf("download audits=%d err=%v", downloads, err)
	}
	// 其他租户不能下载。
	if _, err := store.Download(ctx, other.actor, DownloadRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, RequestID: "certops-download-other",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant download = %v", err)
	}

	// 已绑定网站：拒绝禁用（服务层与 552 触发器）。
	// 绑定前先激活版本（与其他证书集成用例一致）。
	if _, err := store.Activate(ctx, tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: imported.Asset.Revision, IdempotencyKey: "certops-activate", RequestID: "certops-activate",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Bind(ctx, tenant.actor, BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, ExpectedRevision: 0, Default: true,
		IdempotencyKey: "certops-bind", RequestID: "certops-bind",
	}); err != nil {
		t.Fatal(err)
	}
	bound, err := loadAsset(ctx, pool, tenant.actor.ScopeID, imported.Asset.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetDisabled(ctx, tenant.actor, SetDisabledRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, Disabled: true,
		ExpectedRevision: bound.Revision, IdempotencyKey: "certops-disable-bound", RequestID: "certops-disable-bound",
	}); !errors.Is(err, ErrReferenced) {
		t.Fatalf("disable bound = %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE certificate_assets SET disabled=true,revision=revision+1 WHERE id=$1`, imported.Asset.ID); err == nil ||
		!strings.Contains(err.Error(), "P5511") && !strings.Contains(err.Error(), "bound certificate asset cannot be disabled") {
		t.Fatalf("trigger allowed disabling a bound asset: %v", err)
	}
	if _, err := store.Unbind(ctx, tenant.actor, UnbindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, ExpectedRevision: 1,
		IdempotencyKey: "certops-unbind", RequestID: "certops-unbind",
	}); err != nil {
		t.Fatal(err)
	}
	current, err := loadAsset(ctx, pool, tenant.actor.ScopeID, imported.Asset.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := store.SetDisabled(ctx, tenant.actor, SetDisabledRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, Disabled: true,
		ExpectedRevision: current.Revision, IdempotencyKey: "certops-disable", RequestID: "certops-disable",
	})
	if err != nil || !disabled.Disabled || disabled.Revision != current.Revision+1 {
		t.Fatalf("disable = %+v, %v", disabled, err)
	}
	// 幂等重放。
	if replay, err := store.SetDisabled(ctx, tenant.actor, SetDisabledRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, Disabled: true,
		ExpectedRevision: current.Revision, IdempotencyKey: "certops-disable", RequestID: "certops-disable-2",
	}); err != nil || replay.Revision != disabled.Revision {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	// 禁用后不能绑定。
	if _, err := store.Bind(ctx, tenant.actor, BindRequest{
		TenantScopeID: tenant.actor.ScopeID, SiteID: tenant.siteOne, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, ExpectedRevision: 2, Default: true,
		IdempotencyKey: "certops-bind-disabled", RequestID: "certops-bind-disabled",
	}); !errors.Is(err, ErrAssetDisabled) {
		t.Fatalf("bind disabled = %v", err)
	}
	enabled, err := store.SetDisabled(ctx, tenant.actor, SetDisabledRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, Disabled: false,
		ExpectedRevision: disabled.Revision, IdempotencyKey: "certops-enable", RequestID: "certops-enable",
	})
	if err != nil || enabled.Disabled {
		t.Fatalf("enable = %+v, %v", enabled, err)
	}
	var toggles int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND result='success' AND resource_id=$2
		AND action IN ('certificate.asset.disable','certificate.asset.enable')`,
		tenant.actor.ScopeID, imported.Asset.ID.String()).Scan(&toggles); err != nil || toggles != 2 {
		t.Fatalf("toggle audits=%d err=%v", toggles, err)
	}
}
