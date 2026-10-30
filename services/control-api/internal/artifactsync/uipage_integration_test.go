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

// Acceptance (PA-19): an authorized ui_page plugin's origin enters the CSP
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
