package pluginuihttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/pluginui"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type storeStub struct{ plugins []ActivePlugin }

func (stub storeStub) ActivePlugins(context.Context) ([]ActivePlugin, error) { return stub.plugins, nil }

type sitesStub struct{ allowed map[uuid.UUID]bool }

func (stub sitesStub) CanAccessSite(_ context.Context, _ identity.Principal, id uuid.UUID) (bool, error) {
	return stub.allowed[id], nil
}

type auditStub struct{ events []audit.Event }

func (stub *auditStub) Record(_ context.Context, event audit.Event) error {
	stub.events = append(stub.events, event)
	return nil
}

type forwardStub struct {
	requests []*http.Request
	bodies   [][]byte
	status   int
	body     string
	err      error
}

func (stub *forwardStub) Do(request *http.Request) (*http.Response, error) {
	if stub.err != nil {
		return nil, stub.err
	}
	body, _ := io.ReadAll(request.Body)
	stub.requests, stub.bodies = append(stub.requests, request), append(stub.bodies, body)
	return &http.Response{StatusCode: stub.status, Body: io.NopCloser(strings.NewReader(stub.body)), Header: http.Header{}}, nil
}

func declaration(t *testing.T, pluginID, origin, apiBase string, pages ...pluginui.Page) pluginui.Declaration {
	t.Helper()
	value, _, err := pluginui.Build(pluginID, "1.0.0", []string{pluginui.Permission}, pluginui.Entrypoint{
		Type: pluginui.EntrypointType, Origin: origin, APIBaseURL: apiBase, Pages: pages})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

var (
	adminReport = pluginui.Page{ID: "report", Path: "/report", Mount: pluginui.MountMenu, MenuParent: "monitor",
		Role: pluginui.RoleAdmin, Title: pluginui.Title{ZhCN: "报表"}, RequiredPermission: "sites.read"}
	userTab = pluginui.Page{ID: "site-tools", Path: "/site", Mount: pluginui.MountSiteTab, Role: pluginui.RoleUser,
		Title: pluginui.Title{ZhCN: "站点工具"}, RequiredModule: "module.acme_tools"}
)

type fixture struct {
	handler *Handler
	audit   *auditStub
	forward *forwardStub
	public  ed25519.PublicKey
	site    uuid.UUID
}

func newFixture(t *testing.T, principal identity.Principal, modules []string) fixture {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	site := uuid.New()
	f := fixture{audit: &auditStub{}, forward: &forwardStub{status: 200, body: `{"ok":true}`}, public: public, site: site}
	plugins := []ActivePlugin{
		{Declaration: declaration(t, "acme.reports", "https://ui.acme.example", "https://api.acme.example/v1", adminReport, userTab)},
		{Declaration: declaration(t, "beta.tools", "https://beta.example", "", userTab)},
	}
	handler, err := New(Config{Store: storeStub{plugins: plugins},
		Authenticate: func(_ *http.Request, raw string) (identity.AuthenticatedSession, error) {
			if raw != "good" {
				return identity.AuthenticatedSession{}, errors.New("bad session")
			}
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
		},
		Modules: func(context.Context) ([]string, error) { return modules, nil },
		Sites:   sitesStub{allowed: map[uuid.UUID]bool{site: true}}, Auditor: f.audit,
		Signer:    &Signer{InstallationID: uuid.New(), PrivateKey: private},
		Forwarder: f.forward, Now: func() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	f.handler = handler
	return f
}

func adminPrincipal() identity.Principal {
	return identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", DisplayName: "管理员",
		Permissions: []string{"sites.read", "platform.admin"}}
}

func (f fixture) call(t *testing.T, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, _ := json.Marshal(body)
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, reader)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func TestPagesFiltersByRolePermissionAndModule(t *testing.T) {
	f := newFixture(t, adminPrincipal(), nil)
	if response := f.call(t, http.MethodGet, PagesRoute, "", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status %d", response.Code)
	}
	response := f.call(t, http.MethodGet, PagesRoute, "good", nil)
	var body struct{ Items []Page }
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != 200 {
		t.Fatalf("status %d %v", response.Code, err)
	}
	if len(body.Items) != 1 || body.Items[0].PageID != "report" || body.Items[0].URL != "https://ui.acme.example/report" ||
		!body.Items[0].HasAPI {
		t.Fatalf("admin pages %+v", body.Items)
	}
	tenant := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{"sites.read"}}
	f = newFixture(t, tenant, nil)
	_ = json.Unmarshal(f.call(t, http.MethodGet, PagesRoute, "good", nil).Body.Bytes(), &body)
	if len(body.Items) != 0 {
		t.Fatalf("module-gated pages shown without the module: %+v", body.Items)
	}
	f = newFixture(t, tenant, []string{"module.acme_tools"})
	_ = json.Unmarshal(f.call(t, http.MethodGet, PagesRoute, "good", nil).Body.Bytes(), &body)
	if len(body.Items) != 2 || body.Items[0].Mount != pluginui.MountSiteTab {
		t.Fatalf("tenant pages %+v", body.Items)
	}
}

func TestCSPOriginsOnlyEnabledPlugins(t *testing.T) {
	plugins := []ActivePlugin{
		{Declaration: declaration(t, "acme.reports", "https://ui.acme.example", "", adminReport)},
		{Declaration: declaration(t, "beta.tools", "https://beta.example", "", adminReport)},
	}
	if got := CSPOrigins(plugins); got != "https://beta.example https://ui.acme.example" {
		t.Fatalf("CSPOrigins = %q", got)
	}
	if got := CSPOrigins(nil); got != "" {
		t.Fatalf("CSPOrigins(none) = %q", got)
	}
}

// The proxy signs a non-sensitive context instead of forwarding any user
// credential, only reaches a declared backend for a page the caller can
// open, and audits writes and refusals.
func TestProxySignsContextWithoutUserCredentials(t *testing.T) {
	principal := adminPrincipal()
	f := newFixture(t, principal, nil)
	response := f.call(t, http.MethodPost, "/v1/plugin-ui/acme.reports/proxy", "good", map[string]any{
		"method": "POST", "path": "/reports", "query": "range=7d", "body": map[string]any{"name": "x"},
		"page_id": "report", "site_id": f.site})
	if response.Code != http.StatusOK || len(f.forward.requests) != 1 {
		t.Fatalf("status %d body %s", response.Code, response.Body.String())
	}
	outbound := f.forward.requests[0]
	if outbound.URL.String() != "https://api.acme.example/v1/reports?range=7d" || outbound.Header.Get("Authorization") != "" ||
		outbound.Header.Get("Cookie") != "" {
		t.Fatalf("outbound %s headers %v", outbound.URL, outbound.Header)
	}
	contextHeader := outbound.Header.Get("X-Cdnca-Plugin-Context")
	signature, _ := base64.RawURLEncoding.DecodeString(outbound.Header.Get("X-Cdnca-Plugin-Signature"))
	if !ed25519.Verify(f.public, SignatureMessage("POST", "/reports?range=7d", f.forward.bodies[0], contextHeader), signature) {
		t.Fatal("signature does not verify")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(contextHeader)
	var signed Context
	if err := json.Unmarshal(raw, &signed); err != nil || signed.UserID != principal.UserID || signed.PluginID != "acme.reports" ||
		signed.Role != "admin" || signed.SiteID == nil || *signed.SiteID != f.site || !signed.ExpiresAt.After(signed.IssuedAt) ||
		signed.Nonce == "" || signed.Schema != ContextSchema {
		t.Fatalf("context %+v %v", signed, err)
	}
	if strings.Contains(string(raw), "good") || strings.Contains(string(raw), "token") {
		t.Fatalf("context leaks a credential: %s", raw)
	}
	var relayed ProxyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &relayed); err != nil || relayed.Status != 200 || string(relayed.Body) != `{"ok":true}` {
		t.Fatalf("relayed %+v %v", relayed, err)
	}
	if len(f.audit.events) != 1 || f.audit.events[0].Action != "plugin.ui_page.proxy" || f.audit.events[0].Result != "success" {
		t.Fatalf("audit %+v", f.audit.events)
	}
}

func TestProxyRefusesUndeclaredAndForbiddenCalls(t *testing.T) {
	f := newFixture(t, adminPrincipal(), nil)
	cases := []struct {
		name   string
		path   string
		body   map[string]any
		status int
		code   string
	}{
		{"unknown plugin", "/v1/plugin-ui/nobody.here/proxy", map[string]any{"method": "GET", "path": "/x", "page_id": "report"}, 404, "plugin_ui_not_found"},
		{"page the caller cannot open", "/v1/plugin-ui/acme.reports/proxy", map[string]any{"method": "GET", "path": "/x", "page_id": "site-tools"}, 404, "plugin_ui_not_found"},
		{"no backend declared", "/v1/plugin-ui/beta.tools/proxy", map[string]any{"method": "GET", "path": "/x", "page_id": "site-tools"}, 404, "plugin_ui_not_found"},
		{"foreign site", "/v1/plugin-ui/acme.reports/proxy", map[string]any{"method": "GET", "path": "/x", "page_id": "report", "site_id": uuid.New()}, 403, "plugin_ui_site_denied"},
		{"path traversal", "/v1/plugin-ui/acme.reports/proxy", map[string]any{"method": "GET", "path": "/../admin", "page_id": "report"}, 400, "plugin_ui_request_invalid"},
		{"absolute url", "/v1/plugin-ui/acme.reports/proxy", map[string]any{"method": "GET", "path": "https://evil.example/", "page_id": "report"}, 400, "plugin_ui_request_invalid"},
		{"unknown field", "/v1/plugin-ui/acme.reports/proxy", map[string]any{"method": "GET", "path": "/x", "page_id": "report", "headers": map[string]string{"Authorization": "x"}}, 400, "plugin_ui_request_invalid"},
		{"method", "/v1/plugin-ui/acme.reports/proxy", map[string]any{"method": "TRACE", "path": "/x", "page_id": "report"}, 400, "plugin_ui_request_invalid"},
	}
	for _, item := range cases {
		response := f.call(t, http.MethodPost, item.path, "good", item.body)
		var envelope struct{ Error struct{ Code string } }
		_ = json.Unmarshal(response.Body.Bytes(), &envelope)
		if response.Code != item.status || envelope.Error.Code != item.code {
			t.Errorf("%s: status %d code %q", item.name, response.Code, envelope.Error.Code)
		}
	}
	if len(f.forward.requests) != 0 {
		t.Fatalf("refused calls reached the backend: %d", len(f.forward.requests))
	}
	if response := f.call(t, http.MethodPost, "/v1/plugin-ui/acme.reports/proxy", "bad", map[string]any{
		"method": "GET", "path": "/x", "page_id": "report"}); response.Code != http.StatusUnauthorized {
		t.Fatalf("bad session status %d", response.Code)
	}
	denied := 0
	for _, event := range f.audit.events {
		if event.Result == "denied" {
			denied++
		}
	}
	if denied != 4 {
		t.Fatalf("denied audit events = %d, want 4 (%+v)", denied, f.audit.events)
	}
}

func TestProxyRejectsNonJSONBackendAnswer(t *testing.T) {
	f := newFixture(t, adminPrincipal(), nil)
	f.forward.body = "<script>alert(1)</script>"
	response := f.call(t, http.MethodPost, "/v1/plugin-ui/acme.reports/proxy", "good",
		map[string]any{"method": "GET", "path": "/x", "page_id": "report"})
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status %d body %s", response.Code, response.Body.String())
	}
}

func TestPublicAddressRefusesInternalNetworks(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"::1", "fd00::1", "fe80::1", "0.0.0.0"} {
		if publicAddress(netip.MustParseAddr(address)) {
			t.Errorf("%s treated as public", address)
		}
	}
	if !publicAddress(netip.MustParseAddr("203.0.113.10")) && !publicAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address refused")
	}
}

func TestSigningKeyShowsInstallationPublicKey(t *testing.T) {
	f := newFixture(t, adminPrincipal(), nil)
	if response := f.call(t, http.MethodGet, SigningKeyRoute, "", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status %d", response.Code)
	}
	response := f.call(t, http.MethodGet, SigningKeyRoute, "good", nil)
	var body SigningKey
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK {
		t.Fatalf("status %d %s", response.Code, response.Body.String())
	}
	if body.PublicKey != base64.RawURLEncoding.EncodeToString(f.public) || body.Algorithm != "Ed25519" ||
		body.SignatureDomain != ProxySignatureDomain || len(body.KeyID) != 16 || body.InstallationID == uuid.Nil {
		t.Fatalf("signing key %+v", body)
	}
	if strings.Contains(response.Body.String(), "private") {
		t.Fatalf("private material in response: %s", response.Body.String())
	}

	// A tenant that installs plugins reads it; one without the permission does not.
	installer := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Permissions: []string{"plugin_installations.read"}}
	if response := newFixture(t, installer, nil).call(t, http.MethodGet, SigningKeyRoute, "good", nil); response.Code != http.StatusOK {
		t.Fatalf("installer status %d", response.Code)
	}
	viewer := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{"sites.read"}}
	if response := newFixture(t, viewer, nil).call(t, http.MethodGet, SigningKeyRoute, "good", nil); response.Code != http.StatusForbidden {
		t.Fatalf("viewer status %d", response.Code)
	}

	// No installation key configured: 503, pages still work.
	f = newFixture(t, adminPrincipal(), nil)
	f.handler.config.Signer = nil
	response = f.call(t, http.MethodGet, SigningKeyRoute, "good", nil)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "plugin_ui_proxy_unavailable") {
		t.Fatalf("unconfigured status %d %s", response.Code, response.Body.String())
	}
}
