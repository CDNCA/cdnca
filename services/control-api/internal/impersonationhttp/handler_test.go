package impersonationhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
	"github.com/google/uuid"
)

const testTraceparent = "00-abcdefabcdefabcdefabcdefabcdefab-abcdefabcdefabcd-01"

type serviceStub struct {
	create    func(context.Context, impersonation.Actor, impersonation.CreateRequest) (impersonation.CreateResult, error)
	exchange  func(context.Context, impersonation.ExchangeRequest) (impersonation.Session, error)
	authorize func(context.Context, impersonation.UseRequest) (impersonation.EffectiveIdentity, error)
	revoke    func(context.Context, impersonation.Actor, impersonation.RevokeRequest) (impersonation.Revocation, error)
}

func (stub *serviceStub) Create(ctx context.Context, actor impersonation.Actor, request impersonation.CreateRequest) (impersonation.CreateResult, error) {
	return stub.create(ctx, actor, request)
}
func (stub *serviceStub) Exchange(ctx context.Context, request impersonation.ExchangeRequest) (impersonation.Session, error) {
	return stub.exchange(ctx, request)
}
func (stub *serviceStub) Authorize(ctx context.Context, request impersonation.UseRequest) (impersonation.EffectiveIdentity, error) {
	return stub.authorize(ctx, request)
}
func (stub *serviceStub) Revoke(ctx context.Context, actor impersonation.Actor, request impersonation.RevokeRequest) (impersonation.Revocation, error) {
	return stub.revoke(ctx, actor, request)
}

type issuerStub func(context.Context, impersonation.Session) (string, error)

func (stub issuerStub) Issue(ctx context.Context, session impersonation.Session) (string, error) {
	return stub(ctx, session)
}

func TestHandlerCreateExchangeAndRevokeLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)
	actorID, actorScopeID, primarySessionID := uuid.New(), uuid.New(), uuid.New()
	tenantID, tenantScopeID, subjectID, grantID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	principal := identity.Principal{UserID: actorID, ScopeID: actorScopeID, ScopeKind: "platform", Permissions: []string{impersonation.ManagePermission}}
	authenticated := identity.AuthenticatedSession{SessionID: primarySessionID, Principal: principal}
	var createCalls atomic.Int32
	service := &serviceStub{}
	service.create = func(_ context.Context, actor impersonation.Actor, request impersonation.CreateRequest) (impersonation.CreateResult, error) {
		if actor.UserID != actorID || actor.ScopeID != actorScopeID || actor.PrimaryAuthSessionID != primarySessionID || actor.SessionKind != impersonation.SessionKindPrimary {
			t.Fatalf("actor binding = %#v", actor)
		}
		if request.TenantID != tenantID || request.TenantScopeID != tenantScopeID || request.SubjectUserID != subjectID {
			t.Fatalf("create binding = %#v", request)
		}
		replayed := createCalls.Add(1) > 1
		return impersonation.CreateResult{Grant: impersonation.Grant{ID: grantID, TenantID: tenantID, TenantScopeID: tenantScopeID, ActorUserID: actorID, ActorScopeID: actorScopeID, SubjectUserID: subjectID, CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute)}, AuthorizationCode: "authorization-secret", Replayed: replayed}, nil
	}
	service.exchange = func(_ context.Context, request impersonation.ExchangeRequest) (impersonation.Session, error) {
		if request.AuthorizationCode != "authorization-secret" || request.TenantID != tenantID || request.TenantScopeID != tenantScopeID {
			t.Fatalf("exchange binding = %#v", request)
		}
		return impersonation.Session{ID: sessionID, GrantID: grantID, ActorUserID: actorID, ActorScopeID: actorScopeID, SubjectUserID: subjectID, TenantID: tenantID, TenantScopeID: tenantScopeID, CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute), Refreshable: false, Banner: impersonation.BannerClaims{GrantID: grantID, ActorUserID: actorID, ActorDisplayName: "Support Admin", SubjectUserID: subjectID, SubjectDisplayName: "Tenant User", TenantID: tenantID, ExpiresAt: now.Add(15 * time.Minute)}, Principal: impersonation.SubjectPrincipal{UserID: subjectID, ScopeID: tenantScopeID, TenantID: tenantID, ScopeKind: "tenant", Username: "tenant-user", DisplayName: "Tenant User", Roles: []string{"user"}, Permissions: []string{"sites.read"}}}, nil
	}
	service.revoke = func(_ context.Context, actor impersonation.Actor, request impersonation.RevokeRequest) (impersonation.Revocation, error) {
		if actor.UserID != actorID || actor.SessionKind != impersonation.SessionKindPrimary || request.GrantID != grantID || request.TenantID != tenantID || request.TenantScopeID != tenantScopeID || request.Reason != "support complete" {
			t.Fatalf("revoke binding = actor=%#v request=%#v", actor, request)
		}
		return impersonation.Revocation{ID: uuid.New(), GrantID: grantID, RevokedBy: actorID, Reason: request.Reason, RevokedAt: now}, nil
	}
	handler, err := newHandler(service, func(_ *http.Request, raw string) (identity.AuthenticatedSession, error) {
		if raw != "primary-session" {
			return identity.AuthenticatedSession{}, errors.New("bad session")
		}
		return authenticated, nil
	}, issuerStub(func(_ context.Context, session impersonation.Session) (string, error) {
		if session.ID != sessionID {
			t.Fatalf("issued session = %s", session.ID)
		}
		return "impersonation-cookie-secret", nil
	}), HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}

	createBody := `{"tenant_id":"` + tenantID.String() + `","tenant_scope_id":"` + tenantScopeID.String() + `","subject_user_id":"` + subjectID.String() + `"}`
	first := serve(t, handler, http.MethodPost, "/v1/admin/impersonation/grants", createBody, true)
	assertStatusCode(t, first, http.StatusCreated)
	assertJSONPresence(t, first.Body.Bytes(), "authorization_code", true)
	replay := serve(t, handler, http.MethodPost, "/v1/admin/impersonation/grants", createBody, true)
	assertStatusCode(t, replay, http.StatusOK)
	assertJSONPresence(t, replay.Body.Bytes(), "authorization_code", true)

	exchangeBody := `{"tenant_id":"` + tenantID.String() + `","tenant_scope_id":"` + tenantScopeID.String() + `","authorization_code":"authorization-secret"}`
	exchanged := serve(t, handler, http.MethodPost, "/v1/admin/impersonation/exchanges", exchangeBody, false)
	assertStatusCode(t, exchanged, http.StatusCreated)
	cookies := exchanged.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CookieName || cookies[0].Value != "impersonation-cookie-secret" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("impersonation cookie = %#v", cookies)
	}
	responseText := exchanged.Body.String()
	for _, secret := range []string{"impersonation-cookie-secret", "authorization-secret", "opaque-proof"} {
		if strings.Contains(responseText, secret) {
			t.Fatalf("response leaked %q", secret)
		}
	}
	if !strings.Contains(responseText, `"refreshable":false`) || !strings.Contains(responseText, `"scope_kind":"tenant"`) {
		t.Fatalf("exchange response = %s", responseText)
	}

	revokeBody := `{"tenant_id":"` + tenantID.String() + `","tenant_scope_id":"` + tenantScopeID.String() + `","reason":"support complete"}`
	revoked := serve(t, handler, http.MethodPost, "/v1/admin/impersonation/grants/"+grantID.String()+"/revocations", revokeBody, true)
	assertStatusCode(t, revoked, http.StatusOK)
	cleared := revoked.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != CookieName || cleared[0].MaxAge >= 0 {
		t.Fatalf("cleared cookie = %#v", cleared)
	}
}

type decoderStub func(context.Context, string) (impersonation.Session, error)

func (stub decoderStub) Decode(ctx context.Context, credential string) (impersonation.Session, error) {
	return stub(ctx, credential)
}

func TestSessionAuthorizerRevalidatesOpaqueCookieForEveryAction(t *testing.T) {
	tenantID, tenantScopeID, subjectID := uuid.New(), uuid.New(), uuid.New()
	grantID := uuid.New()
	session := impersonation.Session{
		ID: uuid.New(), GrantID: grantID, ActorUserID: uuid.New(), ActorScopeID: uuid.New(),
		SubjectUserID: subjectID, TenantID: tenantID, TenantScopeID: tenantScopeID,
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
		Principal: impersonation.SubjectPrincipal{
			UserID: subjectID, DisplayID: "100023", ScopeID: tenantScopeID, TenantID: tenantID, ScopeKind: "tenant",
			Username: "tenant-user", DisplayName: "Tenant User", Roles: []string{"tenant_viewer"},
			Permissions: []string{"sites.read"},
		},
		Banner: impersonation.BannerClaims{GrantID: grantID, ActorUserID: uuid.New(),
			ActorDisplayName: "Support Admin", SubjectUserID: subjectID,
			SubjectDisplayName: "Tenant User", TenantID: tenantID, ExpiresAt: time.Now().UTC().Add(15 * time.Minute)},
	}
	service := &serviceStub{authorize: func(_ context.Context, request impersonation.UseRequest) (impersonation.EffectiveIdentity, error) {
		if request.Session.ID != session.ID || request.Action != "sites.read" ||
			request.Context.RequestID != "authorize-1" || request.Context.TraceID != "abcdefabcdefabcdefabcdefabcdefab" {
			t.Fatalf("authorize request = %#v", request)
		}
		return impersonation.EffectiveIdentity{Session: session, Permissions: []string{"sites.read"}}, nil
	}}
	authorizer, err := NewSessionAuthorizer(service, decoderStub(func(_ context.Context, credential string) (impersonation.Session, error) {
		if credential != "opaque-session" {
			t.Fatalf("credential = %q", credential)
		}
		return session, nil
	}), HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/sites", nil)
	request.Header.Set("X-Request-ID", "authorize-1")
	request.Header.Set("Traceparent", testTraceparent)
	request.AddCookie(&http.Cookie{Name: CookieName, Value: "opaque-session"})
	authorized, err := authorizer.Authorize(request, "sites.read")
	if err != nil {
		t.Fatal(err)
	}
	// fix-overview：代登录的用户概览「账号 ID」读 principal.display_id，不能在转成 identity.Principal 时丢失。
	if authorized.Principal.DisplayID != "100023" {
		t.Fatalf("impersonated principal display_id = %q", authorized.Principal.DisplayID)
	}
	if authorized.SessionID != session.ID || authorized.Principal.UserID != subjectID ||
		authorized.Principal.ScopeID != tenantScopeID || authorized.Principal.TenantID == nil ||
		*authorized.Principal.TenantID != tenantID || authorized.Banner.GrantID != session.GrantID {
		t.Fatalf("authorized session = %#v", authorized)
	}
}

func TestHandlerMapsSecurityFailuresAndRejectsNestedOrAmbiguousRequests(t *testing.T) {
	actorID, scopeID := uuid.New(), uuid.New()
	authenticated := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: actorID, ScopeID: scopeID, ScopeKind: "platform", Permissions: []string{impersonation.ManagePermission}}}
	service := &serviceStub{create: func(_ context.Context, _ impersonation.Actor, _ impersonation.CreateRequest) (impersonation.CreateResult, error) {
		return impersonation.CreateResult{}, impersonation.ErrPrincipalChanged
	}}
	handler, err := newHandler(service, func(_ *http.Request, _ string) (identity.AuthenticatedSession, error) { return authenticated, nil }, issuerStub(func(context.Context, impersonation.Session) (string, error) { return "credential", nil }), HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"tenant_id":"` + uuid.NewString() + `","tenant_scope_id":"` + uuid.NewString() + `","subject_user_id":"` + uuid.NewString() + `"}`
	changed := serve(t, handler, http.MethodPost, "/v1/admin/impersonation/grants", body, true)
	assertError(t, changed, http.StatusForbidden, "impersonation_principal_changed")

	nestedRequest := request(t, http.MethodPost, "/v1/admin/impersonation/grants", body, true)
	nestedRequest.AddCookie(&http.Cookie{Name: CookieName, Value: "existing"})
	nested := httptest.NewRecorder()
	handler.ServeHTTP(nested, nestedRequest)
	assertError(t, nested, http.StatusForbidden, "impersonation_nested_denied")

	duplicate := request(t, http.MethodPost, "/v1/admin/impersonation/grants", body, true)
	duplicate.Header.Add("Authorization", "Bearer second")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, duplicate)
	assertError(t, response, http.StatusUnauthorized, "impersonation_unauthenticated")
}

func TestOpenAPIContractFreezesOneTimeCookieAndStableErrors(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/control-impersonation.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, fragment := range []string{"/v1/admin/impersonation/grants:", "/v1/admin/impersonation/exchanges:", "/v1/admin/impersonation/grants/{grant_id}/revocations:", "identity.impersonation.manage", "Idempotency-Key", "X-Request-ID", "Traceparent", "authorization_code", "refreshable", "Set-Cookie", "impersonation_code_replay", "impersonation_grant_expired", "impersonation_principal_changed"} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("OpenAPI missing %q", fragment)
		}
	}
}

func request(t *testing.T, method, path, body string, authenticated bool) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-ID", "request-1")
	r.Header.Set("Traceparent", testTraceparent)
	r.Header.Set("Idempotency-Key", "idempotency-1")
	if authenticated {
		r.Header.Set("Authorization", "Bearer primary-session")
	}
	return r
}
func serve(t *testing.T, handler http.Handler, method, path, body string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request(t, method, path, body, authenticated))
	return w
}
func assertStatusCode(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
	}
}
func assertJSONPresence(t *testing.T, raw []byte, field string, want bool) {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	_, got := value[field]
	if got != want {
		t.Fatalf("field %s presence=%v want=%v body=%s", field, got, want, raw)
	}
}
func assertError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	assertStatusCode(t, response, status)
	if !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("error body=%s", response.Body.String())
	}
}

// TestHandlerAdmitsResellerSessionsOnly (ADR 0018 RS-07): a tenant session
// reaches the service only with reseller.customers.manage (the service then
// checks the reseller is active and the target is its customer); other
// tenant sessions stay unauthenticated.
func TestHandlerAdmitsResellerSessionsOnly(t *testing.T) {
	tenantID := uuid.New()
	for _, tc := range []struct {
		name        string
		permissions []string
		forwarded   bool
	}{
		{"reseller with reseller.customers.manage", []string{impersonation.ResellerPermission}, true},
		{"tenant with the platform permission name", []string{impersonation.ManagePermission}, false},
		{"plain tenant", []string{"sites.read"}, false},
	} {
		principal := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenantID,
			Permissions: tc.permissions}
		var got impersonation.Actor
		forwarded := false
		service := &serviceStub{create: func(_ context.Context, actor impersonation.Actor, _ impersonation.CreateRequest) (impersonation.CreateResult, error) {
			forwarded, got = true, actor
			return impersonation.CreateResult{}, impersonation.ErrPermissionDenied
		}}
		handler, err := newHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
		}, issuerStub(func(context.Context, impersonation.Session) (string, error) { return "credential", nil }), HandlerConfig{})
		if err != nil {
			t.Fatal(err)
		}
		body := `{"tenant_id":"` + uuid.NewString() + `","tenant_scope_id":"` + uuid.NewString() + `","subject_user_id":"` + uuid.NewString() + `"}`
		response := serve(t, handler, http.MethodPost, "/v1/admin/impersonation/grants", body, true)
		if forwarded != tc.forwarded {
			t.Fatalf("%s: forwarded=%v status=%d", tc.name, forwarded, response.Code)
		}
		if tc.forwarded {
			assertError(t, response, http.StatusForbidden, "impersonation_permission_denied")
			if got.ScopeKind != "tenant" || got.ScopeID != principal.ScopeID || got.SessionKind != impersonation.SessionKindPrimary {
				t.Fatalf("%s: actor = %+v", tc.name, got)
			}
		} else {
			assertError(t, response, http.StatusUnauthorized, "impersonation_unauthenticated")
		}
	}
}
