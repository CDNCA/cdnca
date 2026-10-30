package systemsettingshttp

import (
	"bytes"
	"context"
	"errors"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemsettings"
	"github.com/google/uuid"
)

type handlerServiceStub struct {
	document  systemsettings.Document
	getErr    error
	saveErr   error
	public    systemsettings.PublicSettings
	publicErr error
	cspHosts  string
	cspErr    error
}

func (stub *handlerServiceStub) CSPReportHosts(context.Context) (string, error) {
	return stub.cspHosts, stub.cspErr
}

func (stub *handlerServiceStub) Public(context.Context) (systemsettings.PublicSettings, error) {
	return stub.public, stub.publicErr
}

func (stub *handlerServiceStub) Get(context.Context, systemsettings.Actor) (systemsettings.Document, error) {
	return stub.document, stub.getErr
}

func (stub *handlerServiceStub) Save(context.Context, systemsettings.Actor, systemsettings.SaveRequest) (systemsettings.Document, error) {
	return stub.document, stub.saveErr
}

func testSession() identity.AuthenticatedSession {
	return identity.AuthenticatedSession{
		SessionID: uuid.New(),
		Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"},
	}
}

func testDocument() systemsettings.Document {
	return systemsettings.Document{Schema: systemsettings.Schema(), Revision: 0, Value: systemsettings.DefaultSettings()}
}

func TestHandlerRejectsMissingBearer(t *testing.T) {
	handler, err := New(&handlerServiceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		t.Fatal("authenticate must not run")
		return identity.AuthenticatedSession{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, route, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestHandlerReturnsDocumentAndETag(t *testing.T) {
	session := testSession()
	handler, err := New(&handlerServiceStub{document: testDocument()}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, route, nil)
	request.Header.Set("Authorization", "Bearer session-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"0"` {
		t.Fatalf("status=%d etag=%q", response.Code, response.Header().Get("ETag"))
	}
	var document systemsettings.Document
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != systemsettings.Schema() {
		t.Fatalf("schema=%q", document.Schema)
	}
}

func TestHandlerRequiresStrictWriteMetadata(t *testing.T) {
	session := testSession()
	handler, err := New(&handlerServiceStub{document: systemsettings.Document{Schema: systemsettings.Schema(), Revision: 1, UpdatedAt: time.Now(), Value: systemsettings.DefaultSettings()}}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, route, nil)
	request.Header.Set("Authorization", "Bearer session-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestHandlerMapsRevisionConflict(t *testing.T) {
	session := testSession()
	stub := &handlerServiceStub{saveErr: systemsettings.ErrRevisionConflict}
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"value": systemsettings.DefaultSettings()})
	request := httptest.NewRequest(http.MethodPut, route, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer session-token")
	request.Header.Set("If-Match", `"0"`)
	request.Header.Set("Idempotency-Key", "system-settings-test")
	request.Header.Set("X-Request-ID", "system-settings-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestHandlerDistinguishesTenantDenialFromInvalidSession(t *testing.T) {
	tenantID := uuid.New()
	validTenant := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenantID}}
	for _, tc := range []struct {
		name    string
		session identity.AuthenticatedSession
		status  int
	}{
		{"authenticated tenant", validTenant, http.StatusForbidden},
		{"missing session", identity.AuthenticatedSession{Principal: validTenant.Principal}, http.StatusUnauthorized},
		{"missing identity", identity.AuthenticatedSession{SessionID: uuid.New()}, http.StatusUnauthorized},
	} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				handler, err := New(&handlerServiceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return tc.session, nil })
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(method, route, nil)
				request.Header.Set("Authorization", "Bearer test-session")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != tc.status {
					t.Fatalf("status=%d want=%d body=%s", response.Code, tc.status, response.Body.String())
				}
			})
		}
	}
}

func TestHandlerMapsUnavailableToServiceUnavailable(t *testing.T) {
	handler, err := New(&handlerServiceStub{getErr: systemsettings.ErrUnavailable}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, route, nil)
	request.Header.Set("Authorization", "Bearer session-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// FX61/NF26：租户用户也能读到购买说明与全站 JS，但只拿到这两个字段，且仍需有效会话。
func TestHandlerPublicSettingsForAnyAuthenticatedSession(t *testing.T) {
	tenantID := uuid.New()
	tenant := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: "tenant", TenantID: &tenantID}}
	stub := &handlerServiceStub{public: systemsettings.PublicSettings{
		PublicBranding: systemsettings.PublicBranding{SystemName: "云盾", UserTitle: "云盾用户控制台", AdminTitle: "云盾管理后台"},
		PurchaseNotice: "<p>说明</p>", GlobalJS: "console.log(1)",
	}}
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return tenant, nil })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, publicRoute, nil)
	request.Header.Set("Authorization", "Bearer tenant-session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 5 || body["purchase_notice"] != "<p>说明</p>" || body["global_js"] != "console.log(1)" ||
		body["system_name"] != "云盾" || body["user_title"] != "云盾用户控制台" || body["admin_title"] != "云盾管理后台" {
		t.Fatalf("public body=%v", body)
	}

	for _, tc := range []struct {
		name, method string
		bearer       bool
		status       int
	}{
		{"write rejected", http.MethodPut, true, http.StatusMethodNotAllowed},
		{"anonymous write rejected", http.MethodPut, false, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, publicRoute, nil)
			if tc.bearer {
				request.Header.Set("Authorization", "Bearer tenant-session")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status=%d want=%d", response.Code, tc.status)
			}
		})
	}

	stub.publicErr = systemsettings.ErrUnavailable
	request = httptest.NewRequest(http.MethodGet, publicRoute, nil)
	request.Header.Set("Authorization", "Bearer tenant-session")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status=%d", response.Code)
	}
}

// 登录页没有会话也要显示系统名称。无 Authorization 头时只回
// 系统名称与两个标题（白名单），购买说明、全站 JS 及任何内部配置都不带；带了无效 bearer 仍 401。
func TestHandlerPublicSettingsAnonymousBrandingWhitelist(t *testing.T) {
	stub := &handlerServiceStub{public: systemsettings.PublicSettings{
		PublicBranding: systemsettings.PublicBranding{SystemName: "云盾", UserTitle: "云盾用户控制台", AdminTitle: "云盾管理后台"},
		PurchaseNotice: "<p>内部说明</p>", GlobalJS: "secret()",
	}}
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, errors.New("invalid session")
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, publicRoute, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("anonymous status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"system_name": "云盾", "user_title": "云盾用户控制台", "admin_title": "云盾管理后台"}
	if len(body) != len(want) {
		t.Fatalf("anonymous body has non-whitelisted fields: %v", body)
	}
	for key, value := range want {
		if body[key] != value {
			t.Fatalf("anonymous %s=%v want %v (body=%v)", key, body[key], value, body)
		}
	}
	for _, leaked := range []string{"purchase_notice", "global_js", "内部说明", "secret()", "bound_domains", "certificate", "private_key", "global_js_report_hosts"} {
		if bytes.Contains(response.Body.Bytes(), []byte(leaked)) {
			t.Fatalf("anonymous body leaked %q: %s", leaked, response.Body.String())
		}
	}

	for name, header := range map[string]string{"invalid bearer": "Bearer expired", "malformed": "Basic abc"} {
		request := httptest.NewRequest(http.MethodGet, publicRoute, nil)
		request.Header.Set("Authorization", header)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s status=%d", name, response.Code)
		}
	}
	request = httptest.NewRequest(http.MethodGet, publicRoute+"?x=1", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("anonymous query status=%d", response.Code)
	}
	stub.publicErr = systemsettings.ErrUnavailable
	request = httptest.NewRequest(http.MethodGet, publicRoute, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("anonymous unavailable status=%d", response.Code)
	}
}

// The web container's nginx reads the global JS report hosts before it serves
// index.html (auth_request), before any session exists.
func TestHandlerServesCSPReportHostsWithoutSession(t *testing.T) {
	stub := &handlerServiceStub{cspHosts: "https://hm.baidu.com https://stats.example.com"}
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		t.Fatal("CSP host lookup must not authenticate")
		return identity.AuthenticatedSession{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, cspHostsRoute, nil))
	if response.Code != http.StatusNoContent || response.Header().Get(cspHostsHeader) != stub.cspHosts ||
		response.Header().Get("Cache-Control") != "no-store" || response.Body.Len() != 0 {
		t.Fatalf("status=%d header=%q cache=%q body=%q", response.Code, response.Header().Get(cspHostsHeader),
			response.Header().Get("Cache-Control"), response.Body.String())
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, cspHostsRoute, nil),
		httptest.NewRequest(http.MethodGet, cspHostsRoute+"?x=1", nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusNoContent || response.Header().Get(cspHostsHeader) != "" {
			t.Fatalf("%s %s status=%d", request.Method, request.URL, response.Code)
		}
	}
	stub.cspErr = systemsettings.ErrUnavailable
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, cspHostsRoute, nil))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get(cspHostsHeader) != "" {
		t.Fatalf("unavailable status=%d", response.Code)
	}
}

// PA-19: the enabled ui_page plugin origins ride the same lookup in their
// own header (frame-src only); a failing lookup drops them.
func TestHandlerServesPluginUIOriginsForCSP(t *testing.T) {
	stub := &handlerServiceStub{cspHosts: ""}
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, errors.New("no session")
	})
	if err != nil {
		t.Fatal(err)
	}
	origins, originsErr := "https://ui.acme.example", error(nil)
	handler.WithPluginOrigins(func(context.Context) (string, error) { return origins, originsErr })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, cspHostsRoute, nil))
	if response.Code != http.StatusNoContent || response.Header().Get(cspPluginOriginsHeader) != origins {
		t.Fatalf("status=%d origins=%q", response.Code, response.Header().Get(cspPluginOriginsHeader))
	}
	originsErr = errors.New("database down")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, cspHostsRoute, nil))
	if response.Code != http.StatusNoContent || response.Header().Values(cspPluginOriginsHeader) != nil {
		t.Fatalf("failing lookup status=%d origins=%v", response.Code, response.Header().Values(cspPluginOriginsHeader))
	}
}
