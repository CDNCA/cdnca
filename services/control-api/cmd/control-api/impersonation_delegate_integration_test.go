//go:build integration

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

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
)

// 1.0.35: while an administrator acts as a tenant owner, the
// tenant pages that authenticate with the Bearer only (tickets), re-verify the
// raw token in their transaction (dashboard / iamlock) or the session ID
// (announcements / rbacmanager) answer as the target user, reads and writes.
func TestImpersonationDelegateServesTenantPagesAsTarget(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	random := func(n int) []byte {
		key := make([]byte, n)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		return key
	}
	password := base64.RawURLEncoding.EncodeToString(random(32))
	hash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStore(pool).BootstrapPlatformUserWithEmail(t.Context(), "delegate-admin", "代登录管理员",
		"delegate-admin@example.invalid", hash, "delegate-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(base64.RawURLEncoding.EncodeToString(random(32)), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	factory, _, err := buildAndClearImpersonationRuntime(&impersonationRuntimeConfig{HMACKey: random(32)},
		impersonationRuntimeDependencies{Pool: pool, Identity: service, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(random(32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	dashboardHandler, err := newDashboardHandler(pool, service, iam, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, ticketFactory, err := buildTicketRuntime(pool, service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	announcements, err := openAnnouncementRuntime(t.Context(), pool, integrationAnnouncementRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = announcements.Close() })
	api := httpapi.New(pool, service, httpapi.Config{APIKeyPepper: random(32), ImpersonationHandlerFactory: factory,
		AdminDashboardHandler: dashboardHandler, TenantDashboardHandler: dashboardHandler,
		TicketHandlerFactory: ticketFactory, AnnouncementHandlerFactory: announcements.HandlerFactory()})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	handler := api.WithImpersonationDelegate(api.Handler())
	var cookie *http.Cookie
	call := func(token, method, path string, body, result any, want int) {
		t.Helper()
		var reader *bytes.Reader
		if body == nil {
			reader = bytes.NewReader(nil)
		} else {
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(encoded)
		}
		request := httptest.NewRequest(method, path, reader)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		key := uuid.NewString()
		request.Header.Set("X-Request-ID", key)
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("Traceparent", "00-"+fmt.Sprintf("%x", random(16))+"-"+fmt.Sprintf("%x", random(8))+"-01")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		if result != nil {
			if err := json.Unmarshal(response.Body.Bytes(), result); err != nil {
				t.Fatal(err)
			}
		}
	}
	var login struct {
		AccessToken string `json:"access_token"`
	}
	call("", "POST", "/v1/auth/login", map[string]any{"username": "delegate-admin", "password": password}, &login, 200)
	var target struct {
		ID       uuid.UUID `json:"id"`
		TenantID uuid.UUID `json:"tenant_id"`
		ScopeID  uuid.UUID `json:"scope_id"`
	}
	call(login.AccessToken, "POST", "/v1/admin/users", map[string]any{"username": "delegate-owner", "password": password,
		"display_name": "代登录目标", "email": "delegate-owner@example.invalid", "phone": nil, "role": identity.UserRoleOwner}, &target, 201)
	var grant struct {
		AuthorizationCode string `json:"authorization_code"`
	}
	call(login.AccessToken, "POST", "/v1/admin/impersonation/grants", map[string]any{"tenant_id": target.TenantID,
		"tenant_scope_id": target.ScopeID, "subject_user_id": target.ID}, &grant, 201)
	exchange := httptest.NewRequest("POST", "/v1/admin/impersonation/exchanges", bytes.NewReader(delegateJSON(t, map[string]any{
		"tenant_id": target.TenantID, "tenant_scope_id": target.ScopeID, "authorization_code": grant.AuthorizationCode})))
	exchange.Header.Set("Content-Type", "application/json")
	exchange.Header.Set("X-Request-ID", "delegate-exchange")
	exchange.Header.Set("Idempotency-Key", "delegate-exchange")
	exchange.Header.Set("Traceparent", "00-"+fmt.Sprintf("%x", random(16))+"-"+fmt.Sprintf("%x", random(8))+"-01")
	exchanged := httptest.NewRecorder()
	handler.ServeHTTP(exchanged, exchange)
	if exchanged.Code != http.StatusCreated || len(exchanged.Result().Cookies()) != 1 {
		t.Fatalf("exchange status=%d body=%s", exchanged.Code, exchanged.Body.String())
	}
	cookie = exchanged.Result().Cookies()[0]

	// The browser keeps sending the administrator's access token.
	var me struct {
		UserID uuid.UUID `json:"user_id"`
	}
	call(login.AccessToken, "GET", "/v1/auth/me", nil, &me, 200)
	if me.UserID != target.ID {
		t.Fatalf("auth/me principal=%s want target %s", me.UserID, target.ID)
	}
	call(login.AccessToken, "GET", "/v1/dashboard?range=today&timezone=UTC", nil, nil, 200)
	call(login.AccessToken, "GET", "/v1/tickets", nil, nil, 200)
	call(login.AccessToken, "GET", "/v1/tickets/summary", nil, nil, 200)
	call(login.AccessToken, "GET", "/v1/account/messages", nil, nil, 200)
	call(login.AccessToken, "POST", "/v1/tickets", map[string]any{"category": "technical", "subject": "代登录工单",
		"body": "代登录写操作"}, nil, 201)
	var owner uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT user_id FROM tickets`).Scan(&owner); err != nil || owner != target.ID {
		t.Fatalf("ticket owner=%s err=%v want target", owner, err)
	}
	var used int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action='identity.impersonation.use' AND result='success'`).Scan(&used); err != nil || used < 6 {
		t.Fatalf("impersonation use audit rows=%d err=%v", used, err)
	}
	// A sensitive identity action stays refused while impersonating.
	call(login.AccessToken, "POST", "/v1/account/password", map[string]any{"current_password": password,
		"new_password": password + "x"}, nil, 401)
	// Without the cookie the administrator is still the administrator.
	cookie = nil
	call(login.AccessToken, "GET", "/v1/tickets", nil, nil, 403)
}

// Leaving an impersonation ends it at once instead
// of letting it run out its 15 minutes. Both exits are covered: the banner's
// "exit impersonation" (grant revocation) and a plain sign-out (/v1/auth/logout)
// made while the impersonation cookie is still present. Afterwards the old
// cookie is refused on every route and the target's delegate session row is
// revoked too (it no longer shows as active in the target's session list).
func TestImpersonationExitRevokesSessionImmediately(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	random := func(n int) []byte {
		key := make([]byte, n)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		return key
	}
	password := base64.RawURLEncoding.EncodeToString(random(32))
	hash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStore(pool).BootstrapPlatformUserWithEmail(t.Context(), "exit-admin", "退出代登录管理员",
		"exit-admin@example.invalid", hash, "exit-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(base64.RawURLEncoding.EncodeToString(random(32)), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	factory, _, err := buildAndClearImpersonationRuntime(&impersonationRuntimeConfig{HMACKey: random(32)},
		impersonationRuntimeDependencies{Pool: pool, Identity: service, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	_, ticketFactory, err := buildTicketRuntime(pool, service, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	api := httpapi.New(pool, service, httpapi.Config{APIKeyPepper: random(32), ImpersonationHandlerFactory: factory,
		TicketHandlerFactory: ticketFactory})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	handler := api.WithImpersonationDelegate(api.Handler())
	call := func(token string, cookies []*http.Cookie, method, path string, body, result any, want int) *httptest.ResponseRecorder {
		t.Helper()
		reader := bytes.NewReader(nil)
		if body != nil {
			reader = bytes.NewReader(delegateJSON(t, body))
		}
		request := httptest.NewRequest(method, path, reader)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		key := uuid.NewString()
		request.Header.Set("X-Request-ID", key)
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("Traceparent", "00-"+fmt.Sprintf("%x", random(16))+"-"+fmt.Sprintf("%x", random(8))+"-01")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.Code, want, response.Body.String())
		}
		if result != nil {
			if err := json.Unmarshal(response.Body.Bytes(), result); err != nil {
				t.Fatal(err)
			}
		}
		return response
	}
	cookieNamed := func(response *httptest.ResponseRecorder, name string) *http.Cookie {
		t.Helper()
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == name && cookie.Value != "" {
				return cookie
			}
		}
		t.Fatalf("response has no %s cookie", name)
		return nil
	}
	var target struct {
		ID       uuid.UUID `json:"id"`
		TenantID uuid.UUID `json:"tenant_id"`
		ScopeID  uuid.UUID `json:"scope_id"`
	}
	type started struct {
		accessToken string
		refresh     *http.Cookie
		cookie      *http.Cookie
		grantID     uuid.UUID
	}
	start := func(createTarget bool) started {
		t.Helper()
		var login struct {
			AccessToken string `json:"access_token"`
		}
		response := call("", nil, "POST", "/v1/auth/login", map[string]any{"username": "exit-admin", "password": password}, &login, 200)
		refresh := cookieNamed(response, "cdnca_refresh")
		if createTarget {
			call(login.AccessToken, nil, "POST", "/v1/admin/users", map[string]any{"username": "exit-owner", "password": password,
				"display_name": "退出代登录目标", "email": "exit-owner@example.invalid", "phone": nil, "role": identity.UserRoleOwner}, &target, 201)
		}
		var grant struct {
			Grant struct {
				ID uuid.UUID `json:"id"`
			} `json:"grant"`
			AuthorizationCode string `json:"authorization_code"`
		}
		call(login.AccessToken, nil, "POST", "/v1/admin/impersonation/grants", map[string]any{"tenant_id": target.TenantID,
			"tenant_scope_id": target.ScopeID, "subject_user_id": target.ID}, &grant, 201)
		exchanged := call("", nil, "POST", "/v1/admin/impersonation/exchanges", map[string]any{"tenant_id": target.TenantID,
			"tenant_scope_id": target.ScopeID, "authorization_code": grant.AuthorizationCode}, nil, 201)
		cookie := cookieNamed(exchanged, "cdnca_impersonation")
		// The impersonation works and has created the target's delegate session row.
		call(login.AccessToken, []*http.Cookie{cookie}, "GET", "/v1/tickets", nil, nil, 200)
		return started{accessToken: login.AccessToken, refresh: refresh, cookie: cookie, grantID: grant.Grant.ID}
	}
	assertEnded := func(current started, bearer string) {
		t.Helper()
		var revocations int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM admin_impersonation_revocations WHERE grant_id=$1`,
			current.grantID).Scan(&revocations); err != nil || revocations != 1 {
			t.Fatalf("grant %s revocations=%d err=%v want 1", current.grantID, revocations, err)
		}
		var activeDelegates int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_sessions auth
			JOIN admin_impersonation_sessions session ON session.id=auth.id
			WHERE session.grant_id=$1 AND auth.revoked_at IS NULL`, current.grantID).Scan(&activeDelegates); err != nil || activeDelegates != 0 {
			t.Fatalf("grant %s active delegate sessions=%d err=%v want 0", current.grantID, activeDelegates, err)
		}
		// The same cookie is refused at once, on the delegated routes and on /v1/auth/me.
		call(bearer, []*http.Cookie{current.cookie}, "GET", "/v1/tickets", nil, nil, 401)
		call(bearer, []*http.Cookie{current.cookie}, "GET", "/v1/auth/me", nil, nil, 401)
	}

	// Exit through the banner: revoke the grant with the administrator's token.
	first := start(true)
	call(first.accessToken, []*http.Cookie{first.cookie}, "POST",
		"/v1/admin/impersonation/grants/"+first.grantID.String()+"/revocations",
		map[string]any{"tenant_id": target.TenantID, "tenant_scope_id": target.ScopeID, "reason": "operator_exit"}, nil, 200)
	assertEnded(first, first.accessToken)
	// The administrator is the administrator again.
	call(first.accessToken, nil, "GET", "/v1/auth/me", nil, nil, 200)

	// Sign out while still impersonating: the impersonation is revoked too.
	second := start(false)
	call("", []*http.Cookie{second.refresh, second.cookie}, "POST", "/v1/auth/logout", nil, nil, 204)
	assertEnded(second, second.accessToken)
	var reason string
	if err := pool.QueryRow(t.Context(), `SELECT reason FROM admin_impersonation_revocations WHERE grant_id=$1`,
		second.grantID).Scan(&reason); err != nil || reason != "logout" {
		t.Fatalf("logout revocation reason=%q err=%v", reason, err)
	}
}

func delegateJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
