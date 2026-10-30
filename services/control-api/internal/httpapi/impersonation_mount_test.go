package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
	"github.com/google/uuid"
)

type impersonationMountAuthorizer func(*http.Request, string) (impersonationhttp.AuthorizedSession, error)

func (authorize impersonationMountAuthorizer) Authorize(request *http.Request, action string) (impersonationhttp.AuthorizedSession, error) {
	return authorize(request, action)
}

type typedNilImpersonationMountHandler struct{}

func (*typedNilImpersonationMountHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestImpersonationMountForwardsOnlyExactOpenAPIRoutes(t *testing.T) {
	var paths []string
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		writer.WriteHeader(http.StatusNoContent)
	})
	authorizer := impersonationMountAuthorizer(func(*http.Request, string) (impersonationhttp.AuthorizedSession, error) {
		return impersonationhttp.AuthorizedSession{}, impersonationhttp.ErrUnauthenticated
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ImpersonationHandlerFactory: func(authenticate impersonationhttp.AuthenticateFunc) (http.Handler, ImpersonationSessionAuthorizer, error) {
		if authenticate == nil {
			t.Fatal("impersonation factory received nil primary-session authentication")
		}
		return handler, authorizer, nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	grantID := "11111111-1111-4111-8111-111111111111"
	for _, path := range []string{
		"/v1/admin/impersonation/grants",
		"/v1/admin/impersonation/exchanges",
		"/v1/admin/impersonation/grants/" + grantID + "/revocations",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("mounted route %s status=%d", path, response.Code)
		}
	}
	for _, path := range []string{
		"/v1/impersonation/exchange",
		"/v1/admin/impersonation/exchange",
		"/v1/admin/impersonation/grants/" + grantID + "/revoke",
		"/v1/admin/impersonation/grants/" + grantID,
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code == http.StatusNoContent {
			t.Fatalf("adjacent route %s reached impersonation handler", path)
		}
	}
	if len(paths) != 3 {
		t.Fatalf("forwarded paths=%v", paths)
	}
}

func TestImpersonationMountFactoryAndCookieAuthorizationFailClosed(t *testing.T) {
	for name, factory := range map[string]ImpersonationHandlerFactory{
		"factory error": func(impersonationhttp.AuthenticateFunc) (http.Handler, ImpersonationSessionAuthorizer, error) {
			return nil, nil, errors.New("impersonation unavailable")
		},
		"nil handler": func(impersonationhttp.AuthenticateFunc) (http.Handler, ImpersonationSessionAuthorizer, error) {
			var handler *typedNilImpersonationMountHandler
			return handler, impersonationMountAuthorizer(func(*http.Request, string) (impersonationhttp.AuthorizedSession, error) {
				return impersonationhttp.AuthorizedSession{}, nil
			}), nil
		},
		"nil authorizer": func(impersonationhttp.AuthenticateFunc) (http.Handler, ImpersonationSessionAuthorizer, error) {
			var authorizer *impersonationMountAuthorizer
			return http.NotFoundHandler(), authorizer, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ImpersonationHandlerFactory: factory}).InitializationError(); err == nil {
				t.Fatal("invalid impersonation factory initialized")
			}
		})
	}

	tenantID, scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	calls := 0
	authorizer := impersonationMountAuthorizer(func(request *http.Request, action string) (impersonationhttp.AuthorizedSession, error) {
		calls++
		if action != "identity.self.read" || request.Header.Get("Authorization") != "Bearer primary-session" {
			t.Fatalf("cookie authorization action=%q authorization=%q", action, request.Header.Get("Authorization"))
		}
		if !requestIDPattern.MatchString(request.Header.Get("X-Request-ID")) ||
			!strings.HasPrefix(request.Header.Get("Traceparent"), "00-") {
			t.Fatalf("missing synthesized audit metadata: headers=%v", request.Header)
		}
		return impersonationhttp.AuthorizedSession{AuthenticatedSession: identity.AuthenticatedSession{
			SessionID: sessionID,
			Principal: identity.Principal{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID,
				Permissions: []string{"identity.self.read"}},
		}, Banner: impersonation.BannerClaims{GrantID: uuid.New(), ActorUserID: uuid.New(),
			SubjectUserID: userID, TenantID: tenantID, ActorDisplayName: "Support Admin",
			SubjectDisplayName: "Tenant User"}}, nil
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ImpersonationHandlerFactory: func(impersonationhttp.AuthenticateFunc) (http.Handler, ImpersonationSessionAuthorizer, error) {
		return http.NotFoundHandler(), authorizer, nil
	}})
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	request.Header.Set("Authorization", "Bearer primary-session")
	request.AddCookie(&http.Cookie{Name: impersonationhttp.CookieName, Value: "opaque-session"})
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || calls != 1 {
		t.Fatalf("cookie-authorized response=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"impersonation"`) ||
		!strings.Contains(response.Body.String(), `"subject_display_name":"Tenant User"`) {
		t.Fatalf("missing non-sensitive impersonation marker: %s", response.Body.String())
	}
}

func TestAuthResultWithImpersonationUsesTheExactTargetPrincipalAndMarker(t *testing.T) {
	primary := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	targetTenantID := uuid.New()
	target := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		TenantID: &targetTenantID, Username: "tenant-user", DisplayName: "Tenant User",
		Roles: []string{"tenant_viewer"}, Permissions: []string{"identity.self.read"}}
	result := identity.AuthResult{AccessToken: "primary-access-token", Principal: primary}

	unchanged, marker := authResultWithImpersonation(result, nil)
	if !reflect.DeepEqual(unchanged.Principal, primary) || marker != nil {
		t.Fatalf("primary result changed without impersonation: principal=%+v marker=%+v", unchanged.Principal, marker)
	}

	grantID, actorID := uuid.New(), uuid.New()
	session := impersonationhttp.AuthorizedSession{AuthenticatedSession: identity.AuthenticatedSession{
		SessionID: uuid.New(), Principal: target,
	}, Banner: impersonation.BannerClaims{GrantID: grantID, ActorUserID: actorID,
		SubjectUserID: target.UserID, TenantID: targetTenantID, ActorDisplayName: "Support Admin",
		SubjectDisplayName: target.DisplayName}}
	effective, marker := authResultWithImpersonation(result, &session)
	if effective.AccessToken != result.AccessToken || !reflect.DeepEqual(effective.Principal, target) {
		t.Fatalf("refresh result does not preserve token and replace only principal: %+v", effective)
	}
	if marker == nil || marker.GrantID != grantID || marker.SubjectUserID != target.UserID {
		t.Fatalf("refresh result missing non-sensitive marker: %+v", marker)
	}
}

func TestImpersonationRoutesAreAbsentWithoutFactory(t *testing.T) {
	response := httptest.NewRecorder()
	New(nil, nil, Config{}).Handler().ServeHTTP(response,
		httptest.NewRequest(http.MethodPost, "/v1/admin/impersonation/grants", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled impersonation route status=%d", response.Code)
	}
}
