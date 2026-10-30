package pluginproviders

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// Only platform administrators with the plugin installation permissions (or
// platform.admin) reach the provider routes.
func TestHandlerRequiresPlatformPermission(t *testing.T) {
	tenant := uuid.New()
	sessions := map[string]identity.Principal{
		"tenant":   {UserID: uuid.New(), ScopeID: tenant, ScopeKind: "tenant", TenantID: &tenant, Permissions: []string{PermissionManage}},
		"reader":   {UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionRead}},
		"no-perms": {UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"},
	}
	handler, err := NewHandler(&Service{Store: &Store{}}, func(_ *http.Request, raw string) (identity.AuthenticatedSession, error) {
		principal, ok := sessions[raw]
		if !ok {
			return identity.AuthenticatedSession{}, errors.New("unknown")
		}
		return identity.AuthenticatedSession{Principal: principal}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		method, path, token string
		want                int
	}{
		{http.MethodGet, ListRoute, "", http.StatusUnauthorized},
		{http.MethodGet, ListRoute, "bogus", http.StatusUnauthorized},
		{http.MethodGet, ListRoute, "tenant", http.StatusForbidden},
		{http.MethodGet, ListRoute, "no-perms", http.StatusForbidden},
		{http.MethodPost, ListRoute + "/com.example.dns/enable", "reader", http.StatusForbidden},
		{http.MethodPost, ListRoute + "/com.example.dns/enable", "tenant", http.StatusForbidden},
	} {
		request := httptest.NewRequest(c.method, c.path, nil)
		if c.token != "" {
			request.Header.Set("Authorization", "Bearer "+c.token)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != c.want {
			t.Errorf("%s %s as %q = %d, want %d", c.method, c.path, c.token, recorder.Code, c.want)
		}
	}
}

// The enable body is strict: unknown fields or a huge token are refused
// before anything runs (PA-23).
func TestHandlerEnableBodyIsStrict(t *testing.T) {
	admin := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionManage}}
	handler, err := NewHandler(&Service{Store: &Store{}}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: admin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"risk_acknowledged":true,"extra":1}`, `{"step_up_token":"` + strings.Repeat("a", 5000) + `"}`, `[`} {
		request := httptest.NewRequest(http.MethodPost, ListRoute+"/com.example.pay/enable", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer admin")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("body %.40q = %d, want 400", body, recorder.Code)
		}
	}
}

func TestPaymentBindingDigestBindsPluginAndDeclaration(t *testing.T) {
	a := PaymentBindingDigest("com.example.pay", strings.Repeat("a", 64))
	if a == PaymentBindingDigest("com.example.pay", strings.Repeat("b", 64)) ||
		a == PaymentBindingDigest("com.example.other", strings.Repeat("a", 64)) {
		t.Fatal("binding digest does not separate plugins or declarations")
	}
}
