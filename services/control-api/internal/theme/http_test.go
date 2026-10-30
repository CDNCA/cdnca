package theme

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type fakeHTTPService struct {
	actor    Actor
	expected int64
	upload   error
	current  CurrentRequest
	slot     string
}

func (f *fakeHTTPService) Catalog(_ context.Context, actor Actor) (CatalogView, error) {
	f.actor = actor
	return CatalogView{Schema: "cdnca.theme.catalog/v1"}, nil
}
func (f *fakeHTTPService) Download(_ context.Context, actor Actor, id string) (PackageView, error) {
	f.actor = actor
	return PackageView{ThemeID: id}, nil
}
func (f *fakeHTTPService) Upload(context.Context, Actor, []byte) (PackageView, error) {
	return PackageView{}, f.upload
}
func (f *fakeHTTPService) Activate(_ context.Context, _ Actor, sha string, expected int64) (ActivationResult, error) {
	f.expected = expected
	return ActivationResult{Revision: expected + 1, PackageSHA256: sha}, nil
}
func (f *fakeHTTPService) ActivateSlot(_ context.Context, _ Actor, sha string, expected int64, slot string) (ActivationResult, error) {
	f.expected, f.slot = expected, slot
	return ActivationResult{Revision: expected + 1, PackageSHA256: sha, Slot: slot}, nil
}
func (f *fakeHTTPService) UserAuthStyle(context.Context) (AuthStyle, error) {
	return AuthStyle{CSS: ".login{color:#123456}", Images: map[string]string{"bg": AuthStylePath + "/assets/" + strings.Repeat("e", 64)}}, nil
}
func (f *fakeHTTPService) AuthStyleAsset(_ context.Context, sha string) (string, []byte, error) {
	if sha == strings.Repeat("e", 64) {
		return "image/png", []byte("png"), nil
	}
	return "", nil, ErrNotFound
}
func (f *fakeHTTPService) Remove(context.Context, Actor, string) error { return ErrActivePackage }
func (f *fakeHTTPService) PackageBody(_ context.Context, actor Actor, sha string) ([]byte, error) {
	f.actor = actor
	if sha == strings.Repeat("d", 64) {
		return []byte(`{"schema":"cdnca.theme/v1"}`), nil
	}
	return nil, ErrNotFound
}
func (f *fakeHTTPService) Current(_ context.Context, request CurrentRequest) (Current, error) {
	f.current = request
	return Current{Schema: CurrentSchema, ThemeID: DefaultThemeID}, nil
}
func (f *fakeHTTPService) File(_ context.Context, kind, sha string) ([]byte, error) {
	if kind == FileStylesheet && sha == strings.Repeat("a", 64) {
		return []byte(":root[data-cdnca-theme] {}\n"), nil
	}
	return nil, ErrNotFound
}
func (f *fakeHTTPService) Asset(context.Context, string) (string, []byte, error) {
	return "", nil, ErrNotFound
}

func newTestHandler(t *testing.T, service *fakeHTTPService, scopeKind string) *Handler {
	t.Helper()
	handler, err := NewHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
			UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: scopeKind,
		}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serve(handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestHandlerPublicRoutes(t *testing.T) {
	handler := newTestHandler(t, &fakeHTTPService{}, "platform")
	current := serve(handler, http.MethodGet, "/v1/theme/current", "", nil)
	if current.Code != http.StatusOK || current.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("current = %d %v", current.Code, current.Header())
	}
	css := serve(handler, http.MethodGet, "/v1/theme/theme."+strings.Repeat("a", 64)+".css", "", nil)
	if css.Code != http.StatusOK || css.Header().Get("Content-Type") != "text/css; charset=utf-8" ||
		!strings.Contains(css.Header().Get("Cache-Control"), "immutable") || css.Header().Get("Content-Security-Policy") != "" {
		t.Fatalf("css = %d %v", css.Code, css.Header())
	}
	notModified := serve(handler, http.MethodGet, "/v1/theme/theme."+strings.Repeat("a", 64)+".css", "", map[string]string{"If-None-Match": `"` + strings.Repeat("a", 64) + `"`})
	if notModified.Code != http.StatusNotModified {
		t.Fatalf("conditional = %d", notModified.Code)
	}
	for _, path := range []string{"/v1/theme/theme." + strings.Repeat("b", 64) + ".css", "/v1/theme/theme.ABC.css", "/v1/theme/x"} {
		if recorder := serve(handler, http.MethodGet, path, "", nil); recorder.Code != http.StatusNotFound {
			t.Errorf("%s = %d", path, recorder.Code)
		}
	}
	if recorder := serve(handler, http.MethodPost, "/v1/theme/current", "", nil); recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post public = %d", recorder.Code)
	}
}

func TestHandlerAdminRoutes(t *testing.T) {
	service := &fakeHTTPService{upload: &ValidationError{Code: "external_reference", Field: "templates.styles[0]"}}
	handler := newTestHandler(t, service, "platform")
	auth := map[string]string{"Authorization": "Bearer token", "X-Request-ID": "req-1"}
	if recorder := serve(handler, http.MethodGet, "/v1/admin/themes", "", nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", recorder.Code)
	}
	if recorder := serve(newTestHandler(t, &fakeHTTPService{}, "tenant"), http.MethodGet, "/v1/admin/themes", "", auth); recorder.Code != http.StatusForbidden {
		t.Fatalf("tenant = %d", recorder.Code)
	}
	if recorder := serve(handler, http.MethodGet, "/v1/admin/themes", "", auth); recorder.Code != http.StatusOK || service.actor.RequestID != "req-1" ||
		// F2: the user console pointer is always present ("" before any activation), as the OpenAPI Catalog requires.
		!strings.Contains(recorder.Body.String(), `"user_package_sha256":""`) {
		t.Fatalf("catalog = %d actor=%+v body=%s", recorder.Code, service.actor, recorder.Body.String())
	}
	if recorder := serve(handler, http.MethodPost, "/v1/admin/themes/catalog/official.slate/download", "", auth); recorder.Code != http.StatusOK {
		t.Fatalf("download = %d", recorder.Code)
	}
	if recorder := serve(handler, http.MethodPost, "/v1/admin/themes/catalog/custom.x/download", "", auth); recorder.Code != http.StatusBadRequest {
		t.Fatalf("download custom = %d", recorder.Code)
	}
	uploadHeaders := map[string]string{"Authorization": "Bearer token", "Content-Type": "application/json"}
	upload := serve(handler, http.MethodPost, "/v1/admin/themes/packages", "{}", uploadHeaders)
	var envelope struct {
		Error map[string]string `json:"error"`
	}
	if err := json.Unmarshal(upload.Body.Bytes(), &envelope); err != nil || upload.Code != http.StatusUnprocessableEntity ||
		envelope.Error["reason"] != "external_reference" || envelope.Error["field"] != "templates.styles[0]" {
		t.Fatalf("upload = %d %s", upload.Code, upload.Body.String())
	}
	sha := strings.Repeat("c", 64)
	activate := serve(handler, http.MethodPost, "/v1/admin/themes/packages/"+sha+"/activate", "", map[string]string{"Authorization": "Bearer token", "If-Match": `"3"`})
	if activate.Code != http.StatusOK || service.expected != 3 || activate.Header().Get("ETag") != `"4"` {
		t.Fatalf("activate = %d expected=%d etag=%s", activate.Code, service.expected, activate.Header().Get("ETag"))
	}
	if recorder := serve(handler, http.MethodPost, "/v1/admin/themes/packages/"+sha+"/activate", "", auth); recorder.Code != http.StatusBadRequest {
		t.Fatalf("activate without If-Match = %d", recorder.Code)
	}
	if recorder := serve(handler, http.MethodDelete, "/v1/admin/themes/packages/"+sha, "", auth); recorder.Code != http.StatusConflict {
		t.Fatalf("remove active = %d", recorder.Code)
	}
	// Customize reads the package JSON byte for byte.
	body := serve(handler, http.MethodGet, "/v1/admin/themes/packages/"+strings.Repeat("d", 64), "", auth)
	if body.Code != http.StatusOK || body.Body.String() != `{"schema":"cdnca.theme/v1"}` || body.Header().Get("Cache-Control") != "no-store" ||
		body.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("package body = %d %v %s", body.Code, body.Header(), body.Body.String())
	}
	if recorder := serve(handler, http.MethodGet, "/v1/admin/themes/packages/"+sha, "", auth); recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown package body = %d", recorder.Code)
	}
	if recorder := serve(handler, http.MethodGet, "/v1/admin/themes/packages/ABC", "", auth); recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad digest = %d", recorder.Code)
	}
	if recorder := serve(handler, http.MethodGet, "/v1/admin/themes/packages/"+strings.Repeat("d", 64), "", nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous package body = %d", recorder.Code)
	}
	if !errors.Is(&ValidationError{Code: "x"}, ErrInvalidPackage) {
		t.Fatal("validation error does not unwrap to ErrInvalidPackage")
	}
}

func newPrincipalHandler(t *testing.T, service *fakeHTTPService, principal identity.Principal) *Handler {
	t.Helper()
	handler, err := NewHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

// PA-26: /v1/theme/current resolves the tenant session's theme, else the
// Host's bound tenant; the platform console always gets the platform theme.
// Community edition: no tenant themes; a platform administrator sees the
// admin console theme, every other caller the user console theme.
func TestHandlerCurrentResolvesConsole(t *testing.T) {
	tenantID, scopeID := uuid.New(), uuid.New()
	service := &fakeHTTPService{}
	handler := newPrincipalHandler(t, service, identity.Principal{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID})
	request := httptest.NewRequest(http.MethodGet, "/v1/theme/current", nil)
	request.Header.Set("Authorization", "Bearer token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.current != (CurrentRequest{}) {
		t.Fatalf("tenant session current = %d %+v", recorder.Code, service.current)
	}
	platform := newTestHandler(t, service, "platform")
	request = httptest.NewRequest(http.MethodGet, "/v1/theme/current", nil)
	request.Header.Set("Authorization", "Bearer token")
	platform.ServeHTTP(httptest.NewRecorder(), request)
	if service.current != (CurrentRequest{Platform: true}) {
		t.Fatalf("platform current = %+v", service.current)
	}
	if recorder := serve(platform, http.MethodGet, "/v1/admin/themes/tenant-policy", "", map[string]string{"Authorization": "Bearer token"}); recorder.Code == http.StatusOK {
		t.Fatalf("tenant policy route still served: %d", recorder.Code)
	}
}

