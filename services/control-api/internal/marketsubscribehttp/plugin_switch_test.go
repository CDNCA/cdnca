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

const probeCatalog = `{"items":[{"plugin_id":"io.cdnca.probe-dnspup","feature_code":"module.probe.dnspup"}],"next_cursor":null}`

// the platform administrator (plugin_installations.platform.manage, or
// the platform admin gate) stops and enables a plugin on this controller with an
// Idempotency-Key; nobody else can, and the library says which are stopped.
func TestPluginLocalSwitchRoutes(t *testing.T) {
	store := &switchStore{libraryStore: libraryStore{items: []LibraryItem{{PluginID: "io.cdnca.probe-dnspup", LocallyDisabled: true}}}}
	current := caller("platform", "plugin_installations.platform.manage")
	h := buyerHandler(&current, &scriptedForwarder{status: 200, body: probeCatalog}, store)
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

// The stop takes the feature code the market catalogue gives
// the plugin, not whatever the body says. A code the catalogue does not give
// this plugin (or a plugin not in the catalogue) is 422 and nothing is
// written; with the catalogue unreachable it is 502 (the stop is not guessed).
func TestPluginLocalDisableChecksCatalogFeatureCode(t *testing.T) {
	current := caller("platform", "plugin_installations.platform.manage")
	key := map[string]string{"Idempotency-Key": "k-1"}
	disable := "/v1/admin/market/plugin-library/io.cdnca.probe-dnspup/disable"
	for name, tc := range map[string]struct {
		catalog, body, code string
		status              int
	}{
		"other plugin's code": {probeCatalog, `{"feature_code":"module.autodefense"}`, "feature_code_mismatch", 422},
		"catalogue has none":  {`{"items":[{"plugin_id":"io.cdnca.probe-dnspup","feature_code":null}],"next_cursor":null}`, `{"feature_code":"module.probe.dnspup"}`, "feature_code_mismatch", 422},
		"not in catalogue":    {`{"items":[],"next_cursor":null}`, `{"feature_code":"module.probe.dnspup"}`, "feature_code_mismatch", 422},
		"other plugin listed": {`{"items":[{"plugin_id":"io.cdnca.other","feature_code":"module.probe.dnspup"}],"next_cursor":null}`, `{"feature_code":"module.probe.dnspup"}`, "feature_code_mismatch", 422},
	} {
		store := &switchStore{}
		forwarder := &scriptedForwarder{status: 200, body: tc.catalog}
		h := buyerHandler(&current, forwarder, store)
		w := request(h, "POST", disable, tc.body, key)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if len(store.calls) != 0 {
			t.Errorf("%s: reached the store: %v", name, store.calls)
		}
		if want := []string{"GET /v1/plugins?plugin_ids=io.cdnca.probe-dnspup key= "}; strings.Join(forwarder.calls, "|") != want[0] {
			t.Errorf("%s: catalogue lookup %v, want %v", name, forwarder.calls, want)
		}
	}
	for name, f := range map[string]Forwarder{"market 503": &scriptedForwarder{status: 503, body: `{"error":"x"}`},
		"market down": failingForwarder{}} {
		store := &switchStore{}
		w := request(buyerHandler(&current, f, store), "POST", disable, `{"feature_code":"module.probe.dnspup"}`, key)
		if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "market_unavailable") || len(store.calls) != 0 {
			t.Errorf("%s: %d %s %v", name, w.Code, w.Body, store.calls)
		}
	}
}
