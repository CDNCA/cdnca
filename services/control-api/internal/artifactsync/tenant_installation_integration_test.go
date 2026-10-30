//go:build integration

package artifactsync_test

import (
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribehttp"
	"github.com/google/uuid"
)

// recordTenantInstallationOf writes an enabled tenant head (and receipt) bound to another installation
// than the one the current verified catalog is signed for: what a migration or restore keeps from the
// earlier installation B.
func (f *fixture) recordTenantInstallationOf(installation uuid.UUID, pluginID, entrypoint string) uuid.UUID {
	f.t.Helper()
	current := installationID
	installationID = installation
	defer func() { installationID = current }()
	scope, _ := f.recordInstallation(uuid.New(), "tenant", pluginID, "1.0.0", false, entrypoint)
	return scope
}

// assertKeptConfirmation: the old installation's head stays enabled and bound to it (not deleted or rewritten).
func (f *fixture) assertKeptConfirmation(installation uuid.UUID, pluginID string) {
	f.t.Helper()
	if n := f.count(`SELECT count(*) FROM plugin_installation_heads WHERE installation_id=$1 AND plugin_id=$2
		AND status='enabled'`, installation, pluginID); n != 1 {
		f.t.Fatalf("old installation confirmation was rewritten: heads=%d", n)
	}
}

var oldInstallationID = uuid.MustParse("00000000-0000-4000-8000-0000000000b2")

// fix-plugverify2（同复查 A）：迁移/恢复后保留的旧安装 B 的租户 external_https 启用记录不能让当前已验签
// 目录安装目标 A 的 provider 声明物化；旧记录不动，A 的租户确认后才物化。
func TestPluginProvidersIgnoreInstallationOfAnotherControlPlane(t *testing.T) {
	f := newFixture(t)
	content := providerDeclaration(t, "1.0.0")
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginProvider, providerPlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	f.recordTenantInstallationOf(oldInstallationID, providerPlugin, "external_https")
	f.sync()
	if n := f.count(`SELECT count(*) FROM plugin_providers WHERE plugin_id=$1`, providerPlugin); n != 0 {
		t.Fatalf("old installation's head materialized the current installation's provider: %d", n)
	}
	f.assertKeptConfirmation(oldInstallationID, providerPlugin)
	f.recordInstallation(uuid.New(), "tenant", providerPlugin, "1.0.0", false, "external_https")
	f.sync()
	if n := f.count(`SELECT count(*) FROM plugin_providers WHERE plugin_id=$1 AND status='active'`, providerPlugin); n != 1 {
		t.Fatalf("current installation's head did not materialize the provider: %d", n)
	}
	// 已物化后，当前安装的 head 停用、只剩旧安装 B 的启用记录：撤回，不被旧记录续命。
	if _, err := f.pool.Exec(t.Context(), `UPDATE plugin_installation_heads SET status='disabled',revision=revision+1,
		updated_at=now() WHERE installation_id=$1 AND plugin_id=$2`, installationID, providerPlugin); err != nil {
		t.Fatal(err)
	}
	f.sync()
	if n := f.count(`SELECT count(*) FROM plugin_providers WHERE plugin_id=$1 AND status='withdrawn'`, providerPlugin); n != 1 {
		t.Fatalf("provider kept active by another installation's head: withdrawn=%d", n)
	}
	f.assertKeptConfirmation(oldInstallationID, providerPlugin)
}

// fix-plugverify2：同上，ui_page 声明的 origin 不因旧安装 B 的租户启用记录进入 CSP frame-src。
func TestPluginUIPagesIgnoreInstallationOfAnotherControlPlane(t *testing.T) {
	f := newFixture(t)
	content := uiDeclaration(t, uiPlugin, "https://ui.reports.example")
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginUI, uiPlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	f.recordTenantInstallationOf(oldInstallationID, uiPlugin, "ui_page")
	f.sync()
	if got := cspOrigins(t, f); got != "" {
		t.Fatalf("old installation's head put the origin in CSP: %q", got)
	}
	if n := f.count(`SELECT count(*) FROM plugin_ui_pages WHERE plugin_id=$1`, uiPlugin); n != 0 {
		t.Fatalf("old installation's head materialized the ui page: %d", n)
	}
	f.assertKeptConfirmation(oldInstallationID, uiPlugin)
	f.recordInstallation(uuid.New(), "tenant", uiPlugin, "1.0.0", false, "ui_page")
	f.sync()
	if got := cspOrigins(t, f); got != "https://ui.reports.example" {
		t.Fatalf("current installation's head did not enable the ui page: %q", got)
	}
}

// fix-plugverify2：插件库（市场页“已安装/已启用”）只算当前已验签目录安装目标的记录。旧安装 B 的启用记录
// 不显示为已安装，免得管理员据此去操作；没有已应用目录时任何记录都不算；A 确认后才显示已安装、已启用。
func TestPluginLibraryCountsOnlyCurrentInstallation(t *testing.T) {
	f := newFixture(t)
	library := func() (installed, enabled, found bool) {
		t.Helper()
		items, err := marketsubscribehttp.NewPostgresStore(f.pool).Library(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			if item.PluginID == providerPlugin {
				return item.Installed, item.Enabled, true
			}
		}
		return false, false, false
	}
	f.recordTenantInstallationOf(oldInstallationID, providerPlugin, "external_https")
	// 尚无已应用目录：不认任何记录。
	if installed, enabled, _ := library(); installed || enabled {
		t.Fatalf("head counted without an applied catalog: installed=%v enabled=%v", installed, enabled)
	}
	content := providerDeclaration(t, "1.0.0")
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginProvider, providerPlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	f.sync()
	// 声明只在当前安装确认后物化，此时库里可能还没有这一项（found=false）；要求的只是不显示为已安装/已启用。
	if installed, enabled, found := library(); installed || enabled {
		t.Fatalf("old installation's head shown as installed: found=%v installed=%v enabled=%v", found, installed, enabled)
	}
	f.assertKeptConfirmation(oldInstallationID, providerPlugin)
	f.recordInstallation(uuid.New(), "tenant", providerPlugin, "1.0.0", false, "external_https")
	if installed, enabled, _ := library(); !installed || !enabled {
		t.Fatalf("current installation's head not shown: installed=%v enabled=%v", installed, enabled)
	}
}
