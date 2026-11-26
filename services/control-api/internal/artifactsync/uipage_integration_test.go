//go:build integration

package artifactsync_test

import (
	"context"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/pluginui"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginuihttp"
	"github.com/google/uuid"
)

const uiPlugin = "io.cdnca.examples.reports"

func uiDeclaration(t *testing.T, pluginID, origin string) []byte {
	t.Helper()
	_, encoded, err := pluginui.Build(pluginID, "1.0.0", []string{pluginui.Permission, "sites.read"}, pluginui.Entrypoint{
		Type: pluginui.EntrypointType, Origin: origin, APIBaseURL: "https://api.reports.example/v1",
		Pages: []pluginui.Page{{ID: "report", Path: "/report", Mount: pluginui.MountMenu, MenuParent: "monitor",
			Role: pluginui.RoleAdmin, Title: pluginui.Title{ZhCN: "报表"}, RequiredPermission: "sites.read"}}})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func cspOrigins(t *testing.T, f *fixture) string {
	t.Helper()
	plugins, err := pluginuihttp.PostgresStore{Pool: f.pool}.ActivePlugins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return pluginuihttp.CSPOrigins(plugins)
}

// Acceptance : an authorized ui_page plugin's origin enters the CSP
// frame-src only after the installation is confirmed (enabled) here, and
// leaves it as soon as the license service stops serving the declaration;
// a second plugin claiming the same origin is refused.
func TestPluginUIPagesMaterialize(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	content := uiDeclaration(t, uiPlugin, "https://ui.reports.example")
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginUI, uiPlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	f.sync()
	if local := f.local(); local[entry.ArtifactID] != 1 {
		t.Fatalf("plugin_ui not downloaded: %v", local)
	}
	if got := cspOrigins(t, f); got != "" {
		t.Fatalf("origin in CSP before the installation was enabled here: %q", got)
	}

	// plugconfirm3：ui_page 只认租户作用域的 ui_page 启用记录。
	f.recordInstallation(uuid.New(), "tenant", uiPlugin, "1.0.0", false, "ui_page")
	f.sync()
	if got := cspOrigins(t, f); got != "https://ui.reports.example" {
		t.Fatalf("CSP origins after enable = %q", got)
	}
	plugins, err := pluginuihttp.PostgresStore{Pool: f.pool}.ActivePlugins(ctx)
	if err != nil || len(plugins) != 1 || plugins[0].Declaration.APIBaseURL != "https://api.reports.example/v1" ||
		len(plugins[0].Declaration.Pages) != 1 {
		t.Fatalf("active plugins %+v %v", plugins, err)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action='plugin.ui_page.enable' AND resource_id=$1
		AND category='plugin' AND jsonb_array_length(changes) > 0`, uiPlugin); n != 1 {
		t.Fatalf("enable audit = %d", n)
	}

	// Another plugin declaring the same origin is kept out.
	other := "io.cdnca.examples.copycat"
	otherContent := uiDeclaration(t, other, "https://ui.reports.example")
	otherEntry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginUI, other, "1.0.0", 2, otherContent, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(otherEntry, otherContent)
	f.recordInstallation(uuid.New(), "tenant", other, "1.0.0", false, "ui_page")
	f.sync()
	if n := f.count(`SELECT count(*) FROM plugin_ui_pages WHERE plugin_id=$1`, other); n != 0 {
		t.Fatalf("second plugin took a live origin")
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action='plugin.ui_page.reject' AND resource_id=$1`, other); n < 1 {
		t.Fatalf("reject audit = %d", n)
	}

	// Authorization disabled at the license service: no longer served.
	f.license.Withdraw(entry.ArtifactID)
	f.sync()
	if got := cspOrigins(t, f); strings.Contains(got, "ui.reports.example") && f.count(
		`SELECT count(*) FROM plugin_ui_pages WHERE plugin_id=$1 AND status='active'`, uiPlugin) != 0 {
		t.Fatalf("withdrawn plugin origin still in CSP: %q", got)
	}
	if n := f.count(`SELECT count(*) FROM audit_events WHERE action='plugin.ui_page.withdraw' AND resource_id=$1
		AND jsonb_array_length(changes) > 0`, uiPlugin); n != 1 {
		t.Fatalf("withdraw audit = %d", n)
	}
	// The copycat may now claim the free origin on the next sync.
	f.sync()
	if got := cspOrigins(t, f); got != "https://ui.reports.example" ||
		f.count(`SELECT count(*) FROM plugin_ui_pages WHERE plugin_id=$1 AND status='active'`, other) != 1 {
		t.Fatalf("freed origin not reusable: %q", got)
	}
}

// KnownPlugins 给出本主控持有声明但不提供的页面插件及其原因来源——已下载未安装、授权收回后撤下、
// 本地停用；正在提供的不列出。
func TestPluginUIKnownPlugins(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	store := pluginuihttp.PostgresStore{Pool: f.pool}
	known := func() []pluginuihttp.KnownPlugin {
		t.Helper()
		plugins, err := store.KnownPlugins(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return plugins
	}
	content := uiDeclaration(t, uiPlugin, "https://ui.reports.example")
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginUI, uiPlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	f.sync()
	if got := known(); len(got) != 1 || got[0].Declaration.PluginID != uiPlugin || !got[0].Licensed ||
		got[0].InstallStatus != "" || len(got[0].Authorizations) != 0 || len(got[0].Declaration.Pages) != 1 {
		t.Fatalf("downloaded, not installed: %+v", got)
	}

	_, authorization := f.recordInstallation(uuid.New(), "tenant", uiPlugin, "1.0.0", false, "ui_page")
	f.sync()
	if got := known(); len(got) != 0 {
		t.Fatalf("served plugin listed as known: %+v", got)
	}

	f.license.Withdraw(entry.ArtifactID)
	f.sync()
	got := known()
	if len(got) != 1 || got[0].Licensed || got[0].InstallStatus != "enabled" || len(got[0].Authorizations) != 1 ||
		got[0].Authorizations[0] != authorization {
		t.Fatalf("withdrawn by the license service: %+v", got)
	}
	reasons := pluginuihttp.UnavailableFor(nil, got, "admin", nil, nil, func(pluginuihttp.KnownPlugin) bool { return true })
	if len(reasons) != 1 || reasons[0].Reason != pluginuihttp.ReasonNotLicensed || reasons[0].PageID != "report" {
		t.Fatalf("admin reasons %+v", reasons)
	}
}

// 本机暂停 ui_page 插件后，不等下一轮制品同步撤下页面行，下一次读取页面清单就不再提供它
// （菜单、CSP、代理同源），并给出 disabled 原因，已打开的插件页按同一机制退出；恢复后同样立即回来。
func TestPluginUIPagePausedLocallyLeavesOnNextRead(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	store := pluginuihttp.PostgresStore{Pool: f.pool}
	content := uiDeclaration(t, uiPlugin, "https://ui.reports.example")
	entry, err := artifactcatalog.DataPackEntry(artifactcatalog.KindPluginUI, uiPlugin, "1.0.0", 1, content, "")
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, content)
	_, authorization := f.recordInstallation(uuid.New(), "tenant", uiPlugin, "1.0.0", false, "ui_page")
	f.sync()
	if got := cspOrigins(t, f); got != "https://ui.reports.example" {
		t.Fatalf("enabled plugin not served: %q", got)
	}
	setStatus := func(status string) {
		t.Helper()
		if _, err := f.pool.Exec(ctx, `UPDATE plugin_installation_heads SET status=$2,revision=revision+1,
			identity_generation=identity_generation+1,updated_at=now() WHERE authorization_id=$1`, authorization, status); err != nil {
			t.Fatal(err)
		}
	}
	setStatus("disabled")
	// No sync in between: the plugin_ui_pages row is still active.
	if n := f.count(`SELECT count(*) FROM plugin_ui_pages WHERE plugin_id=$1 AND status='active'`, uiPlugin); n != 1 {
		t.Fatalf("active rows=%d", n)
	}
	if got := cspOrigins(t, f); got != "" {
		t.Fatalf("paused plugin still served: %q", got)
	}
	known, err := store.KnownPlugins(ctx)
	if err != nil || len(known) != 1 || known[0].InstallStatus != "disabled" {
		t.Fatalf("known after pause %+v %v", known, err)
	}
	reasons := pluginuihttp.UnavailableFor(nil, known, "admin", nil, nil, func(pluginuihttp.KnownPlugin) bool { return true })
	if len(reasons) != 1 || reasons[0].Reason != pluginuihttp.ReasonDisabled {
		t.Fatalf("admin reasons after pause %+v", reasons)
	}
	setStatus("enabled")
	if got := cspOrigins(t, f); got != "https://ui.reports.example" {
		t.Fatalf("resumed plugin not served again: %q", got)
	}
}
