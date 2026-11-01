package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
)

// ID-06 / AA-KEY-02：代登录期间被拒的敏感写（创建/轮换 API 密钥等）必须返回 403
// impersonation_sensitive_action_denied，不能折成 401 invalid_session 让前端误报登录失效；
// 真正失效的代登录 Cookie 仍是 401，且两种情况都不回退到管理员 Bearer。
func TestImpersonationSensitiveActionDeniedIsNotInvalidSession(t *testing.T) {
	tokens, err := identity.NewTokenManager(string(bytes.Repeat([]byte{0x61}, 32)), 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(nil), tokens, 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	expired := false
	authorizer := impersonationMountAuthorizer(func(_ *http.Request, action string) (impersonationhttp.AuthorizedSession, error) {
		if expired {
			return impersonationhttp.AuthorizedSession{}, impersonationhttp.ErrUnauthenticated
		}
		if impersonation.SensitiveAction(action) {
			// The production service wraps nothing here, but a wrapped error must still map.
			return impersonationhttp.AuthorizedSession{}, fmt.Errorf("authorize: %w", impersonation.ErrSensitiveAction)
		}
		return impersonationhttp.AuthorizedSession{}, impersonationhttp.ErrUnauthenticated
	})
	api := New(nil, service, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ImpersonationHandlerFactory: func(impersonationhttp.AuthenticateFunc) (http.Handler, ImpersonationSessionAuthorizer, error) {
		return http.NotFoundHandler(), authorizer, nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	send := func(method, path string) (int, string, []*http.Cookie) {
		request := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer admin-token")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "api-key-create-11111111-1111-4111-8111-111111111111")
		request.Header.Set("If-Match", `"0"`)
		request.AddCookie(&http.Cookie{Name: impersonationhttp.CookieName, Value: "opaque"})
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &envelope)
		return response.Code, envelope.Error.Code, response.Result().Cookies()
	}
	for _, path := range []string{"/v1/account/api-keys", "/v1/account/api-keys/33333333-3333-4333-8333-333333333333/rotate"} {
		status, code, cookies := send(http.MethodPost, path)
		if status != http.StatusForbidden || code != "impersonation_sensitive_action_denied" {
			t.Fatalf("%s status=%d code=%q, want 403 impersonation_sensitive_action_denied", path, status, code)
		}
		for _, cookie := range cookies {
			if cookie.Name == impersonationhttp.CookieName && cookie.MaxAge < 0 {
				t.Fatalf("%s cleared the impersonation cookie on a sensitive refusal", path)
			}
		}
	}
	expired = true
	if status, code, _ := send(http.MethodPost, "/v1/account/api-keys"); status != http.StatusUnauthorized || code != "invalid_session" {
		t.Fatalf("expired cookie status=%d code=%q, want 401 invalid_session", status, code)
	}
}
