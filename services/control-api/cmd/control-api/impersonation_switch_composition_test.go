package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
	"github.com/google/uuid"
)

// This composes the production builders: the user list "switch" action creates
// a grant with no ticket, reason or MFA step-up, and exchanges it once.
func TestImpersonationProductionDirectSwitchComposition(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	random := func() []byte {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		return key
	}
	password := base64.RawURLEncoding.EncodeToString(random())
	hash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	_, err = identity.NewStore(pool).BootstrapPlatformUserWithEmail(t.Context(), "composition-admin", "切换组合管理员", "composition@example.invalid", hash, "composition-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(base64.RawURLEncoding.EncodeToString(random()), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pepper := random()
	factory, readiness, err := buildAndClearImpersonationRuntime(&impersonationRuntimeConfig{HMACKey: random()}, impersonationRuntimeDependencies{Pool: pool, Identity: service, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := readiness.Ready(); err != nil {
		t.Fatal(err)
	}
	api := httpapi.New(pool, service, httpapi.Config{APIKeyPepper: pepper, ImpersonationHandlerFactory: factory})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	call := func(token, method, path, key string, body, result any, want int) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Request-ID", key)
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("Traceparent", "00-"+fmt.Sprintf("%x", random()[:16])+"-"+fmt.Sprintf("%x", random()[:8])+"-01")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("%s %s status=%d want=%d", method, path, response.Code, want)
		}
		if result != nil {
			if err := json.Unmarshal(response.Body.Bytes(), result); err != nil {
				t.Fatal(err)
			}
		}
		return response
	}
	var login struct {
		AccessToken string `json:"access_token"`
	}
	call("", "POST", "/v1/auth/login", "composition-login", map[string]any{"username": "composition-admin", "password": password}, &login, 200)
	var target struct {
		ID       uuid.UUID `json:"id"`
		TenantID uuid.UUID `json:"tenant_id"`
		ScopeID  uuid.UUID `json:"scope_id"`
	}
	call(login.AccessToken, "POST", "/v1/admin/users", "composition-user", map[string]any{"username": "composition-user", "password": password, "display_name": "组合目标", "email": "composition-user@example.invalid", "phone": nil, "role": "tenant_viewer"}, &target, 201)
	body := map[string]any{"tenant_id": target.TenantID, "tenant_scope_id": target.ScopeID, "subject_user_id": target.ID}
	count := func(table string, want int) {
		t.Helper()
		var got int
		if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s count=%d want=%d", table, got, want)
		}
	}
	// A failure while inserting the grant rolls back its audit event too.
	_, err = pool.Exec(t.Context(), `CREATE FUNCTION reject_composition_grant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'composition rollback probe'; END $$;
		CREATE TRIGGER reject_composition_grant BEFORE INSERT ON admin_impersonation_grants FOR EACH ROW EXECUTE FUNCTION reject_composition_grant()`)
	if err != nil {
		t.Fatal(err)
	}
	call(login.AccessToken, "POST", "/v1/admin/impersonation/grants", "composition-grant", body, nil, 503)
	count("admin_impersonation_grants", 0)
	count("audit_events WHERE action='identity.impersonation.create'", 0)
	if _, err := pool.Exec(t.Context(), "DROP TRIGGER reject_composition_grant ON admin_impersonation_grants; DROP FUNCTION reject_composition_grant()"); err != nil {
		t.Fatal(err)
	}
	var grant struct {
		Grant             impersonation.Grant `json:"grant"`
		AuthorizationCode string              `json:"authorization_code"`
	}
	call(login.AccessToken, "POST", "/v1/admin/impersonation/grants", "composition-grant", body, &grant, 201)
	call(login.AccessToken, "POST", "/v1/admin/impersonation/grants", "composition-grant", body, nil, 200)
	count("admin_impersonation_grants", 1)
	count("audit_events WHERE action='identity.impersonation.create' AND result='success'", 1)
	var reason string
	if err := pool.QueryRow(t.Context(), "SELECT reason FROM admin_impersonation_grants").Scan(&reason); err != nil ||
		reason != impersonation.SwitchReason {
		t.Fatalf("grant reason=%q err=%v", reason, err)
	}
	var tenantLogin struct {
		AccessToken string `json:"access_token"`
	}
	call("", "POST", "/v1/auth/login", "composition-tenant-login", map[string]any{"username": "composition-user", "password": password}, &tenantLogin, 200)
	// The dedicated handler rejects non-platform primary sessions at authentication.
	call(tenantLogin.AccessToken, "POST", "/v1/admin/impersonation/grants", "composition-denied", body, nil, 401)
	exchangeBody := map[string]any{"tenant_id": target.TenantID, "tenant_scope_id": target.ScopeID, "authorization_code": grant.AuthorizationCode}
	response := call("", "POST", "/v1/admin/impersonation/exchanges", "composition-exchange", exchangeBody, nil, 201)
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("impersonation cookie security contract changed")
	}
	call("", "POST", "/v1/admin/impersonation/exchanges", "composition-exchange", exchangeBody, nil, 200)
	call("", "POST", "/v1/admin/impersonation/exchanges", "composition-code-reused", exchangeBody, nil, 409)
	count("admin_impersonation_sessions", 1)
}
