package pluginuihttp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/pluginui"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

var adminSettings = pluginui.Page{ID: "settings", Path: "/admin", Mount: pluginui.MountPluginSettings,
	Role: pluginui.RoleAdmin, Title: pluginui.Title{ZhCN: "设置"}}

func settingsFixture(t *testing.T, principal identity.Principal) fixture {
	t.Helper()
	f := newFixture(t, principal, nil)
	f.handler.config.Store = storeStub{plugins: []ActivePlugin{{Declaration: declaration(t, "acme.reports",
		"https://ui.acme.example", "https://api.acme.example/v1", adminReport, adminSettings)}}}
	return f
}

// The plugin_settings page is listed for the platform administrator only (the web app shows it in the plugin
// market detail, not in a menu).
func TestPagesListPluginSettingsForAdminOnly(t *testing.T) {
	var body struct{ Items []Page }
	f := settingsFixture(t, adminPrincipal())
	_ = json.Unmarshal(f.call(t, http.MethodGet, PagesRoute, "good", nil).Body.Bytes(), &body)
	var settings *Page
	for index := range body.Items {
		if body.Items[index].PageID == "settings" {
			settings = &body.Items[index]
		}
	}
	if settings == nil || settings.Mount != pluginui.MountPluginSettings || settings.MenuParent != "" ||
		settings.URL != "https://ui.acme.example/admin" || settings.Role != "admin" || !settings.HasAPI {
		t.Fatalf("admin pages %+v", body.Items)
	}
	tenant := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Permissions: []string{"sites.read", "plugin_installations.manage"}}
	body.Items = nil
	_ = json.Unmarshal(settingsFixture(t, tenant).call(t, http.MethodGet, PagesRoute, "good", nil).Body.Bytes(), &body)
	if len(body.Items) != 0 {
		t.Fatalf("tenant sees admin pages %+v", body.Items)
	}
}
