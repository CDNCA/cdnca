package marketsubscribehttp

import (
	"strings"
	"testing"
)

// 重新安装 is the plugin download with reinstall=true. Only a platform session that may take
// licences reaches the market with it, and the body goes through as sent; a browse-only or tenant session is refused
// before anything is forwarded.
func TestPluginReinstallDownloadAccess(t *testing.T) {
	f := &scriptedForwarder{status: 200, body: `{"plugin_id":"io.cdnca.cf-optimize","source":"licensed"}`}
	body := `{"plugin_id":"io.cdnca.cf-optimize","reinstall":true}`
	for _, refused := range []struct{ scope, permission string }{
		{"platform", PermissionBrowse}, {"tenant", "plugin_installations.manage"}, {"tenant", PermissionPurchase},
	} {
		current := caller(refused.scope, refused.permission)
		if w := request(buyerHandler(&current, f, &libraryStore{}), "POST", "/v1/admin/market/plugin-downloads", body, nil); w.Code != 403 {
			t.Fatalf("%s %s reinstall: %d %s", refused.scope, refused.permission, w.Code, w.Body)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("refused reinstall forwarded: %v", f.calls)
	}
	current := caller("platform", PermissionPurchase)
	if w := request(buyerHandler(&current, f, &libraryStore{}), "POST", "/v1/admin/market/plugin-downloads", body, nil); w.Code != 200 ||
		strings.Join(f.calls, "") != `POST /v1/plugin-downloads key= `+body {
		t.Fatalf("reinstall: %d %v", w.Code, f.calls)
	}
}
