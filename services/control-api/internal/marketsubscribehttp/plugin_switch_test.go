package marketsubscribehttp

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

type switchStore struct {
	libraryStore
	calls []string
	err   error
}

func (s *switchStore) DisablePlugin(_ context.Context, c Caller, key string, input entitlementguard.LocalDisableInput) (entitlementguard.LocalDisable, error) {
	s.calls = append(s.calls, "disable "+c.UserID.String()+" "+key+" "+input.PluginID+" "+input.FeatureCode)
	return entitlementguard.LocalDisable{PluginID: input.PluginID, FeatureCode: input.FeatureCode, Disabled: true}, s.err
}

func (s *switchStore) EnablePlugin(_ context.Context, c Caller, key, pluginID string) (entitlementguard.LocalDisable, error) {
	s.calls = append(s.calls, "enable "+c.UserID.String()+" "+key+" "+pluginID)
	return entitlementguard.LocalDisable{PluginID: pluginID, FeatureCode: "module.probe.dnspup"}, s.err
}

// the platform administrator (plugin_installations.platform.manage, or
// the platform admin gate) stops and enables a plugin on this controller with an
// Idempotency-Key; nobody else can, and the library says which are stopped.
func TestPluginLocalSwitchRoutes(t *testing.T) {
	store := &switchStore{libraryStore: libraryStore{items: []LibraryItem{{PluginID: "io.cdnca.probe-dnspup", LocallyDisabled: true}}}}
	current := caller("platform", "plugin_installations.platform.manage")
	h := buyerHandler(&current, &scriptedForwarder{status: 200, body: `{}`}, store)
	key := map[string]string{"Idempotency-Key": "k-1"}
	body := `{"feature_code":"module.probe.dnspup"}`
	disable := "/v1/admin/market/plugin-library/io.cdnca.probe-dnspup/disable"
	enable := "/v1/admin/market/plugin-library/io.cdnca.probe-dnspup/enable"

	if w := request(h, "POST", disable, body, key); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"locally_disabled":true`) {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", enable, `{}`, key); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"locally_disabled":false`) {
		t.Fatalf("enable: %d %s", w.Code, w.Body)
	}
	want := "disable " + current.UserID.String() + " k-1 io.cdnca.probe-dnspup module.probe.dnspup\n" +
		"enable " + current.UserID.String() + " k-1 io.cdnca.probe-dnspup"
	if got := strings.Join(store.calls, "\n"); got != want {
		t.Fatalf("store calls:\n%s\nwant\n%s", got, want)
	}
	if w := request(h, "POST", disable, body, nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "idempotency_key_required") {
		t.Fatalf("no key: %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/v1/admin/market/plugin-library/Bad_ID/disable", body, key); w.Code != http.StatusBadRequest {
		t.Fatalf("bad plugin id: %d", w.Code)
	}
	if w := request(h, "POST", disable, `{"feature_code":"module.probe.dnspup","extra":1}`, key); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", w.Code)
	}
	// The stop takes no reason; a body that still sends one is refused, not stored.
	if w := request(h, "POST", disable, `{"feature_code":"module.probe.dnspup","reason":"x"}`, key); w.Code != http.StatusBadRequest {
		t.Fatalf("reason field: %d %s", w.Code, w.Body)
	}
	if w := request(h, "GET", "/v1/admin/market/plugin-library", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("manage-only session reads the library: %d", w.Code)
	}
	for name, err := range map[string]error{"invalid": entitlementguard.ErrLocalDisableInvalid,
		"idempotency_conflict": entitlementguard.ErrLocalDisableIdempotency} {
		store.err = err
		want := map[string]int{"invalid": 400, "idempotency_conflict": 409}[name]
		if w := request(h, "POST", disable, body, key); w.Code != want || !strings.Contains(w.Body.String(), name) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	store.err = nil
	calls := len(store.calls)
	for _, denied := range []Caller{caller("platform", PermissionBrowse, PermissionPurchase), caller("tenant", "plugin_installations.manage"),
		caller("tenant", "plugin_installations.platform.manage")} {
		current = denied
		if w := request(h, "POST", disable, body, key); w.Code != http.StatusForbidden {
			t.Errorf("%s %v disable: %d", denied.ScopeKind, denied.Permissions, w.Code)
		}
		if w := request(h, "POST", enable, `{}`, key); w.Code != http.StatusForbidden {
			t.Errorf("%s %v enable: %d", denied.ScopeKind, denied.Permissions, w.Code)
		}
	}
	if len(store.calls) != calls {
		t.Fatalf("denied sessions reached the store: %v", store.calls[calls:])
	}
	current = caller("platform", "platform.admin")
	if w := request(h, "POST", enable, `{}`, key); w.Code != http.StatusOK {
		t.Fatalf("platform admin enable: %d", w.Code)
	}
	current = caller("platform", PermissionBrowse)
	if w := request(h, "GET", "/v1/admin/market/plugin-library", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"locally_disabled":true`) {
		t.Fatalf("library: %d %s", w.Code, w.Body)
	}
}
