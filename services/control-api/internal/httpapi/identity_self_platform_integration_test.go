package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// fp-role ID-04/05（10-25 角色入口审测）：平台管理员自己的账户。改密门禁、取凭据与改密事务原先只认
// tenant，管理员改密 403、换手机/邮箱 401 invalid_session。需 PG：待出包前全量跑。
func TestPlatformAdminSelfServiceAccountHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	adminHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(
		context.Background(), "admin", "Platform Admin", adminHash, "self-platform-bootstrap",
	); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("identity-self-platform-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32), CookieSecure: false}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginWithPassword(t, client, server.URL, "admin", testPassword)

	profile := func(token, requestID string) identity.AccountProfile {
		t.Helper()
		response := identityRequest(t, client, http.MethodGet, server.URL+"/v1/account/profile", nil, token, "", requestID)
		var result identity.AccountProfile
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		return result
	}

	t.Run("contact change reauthenticates the administrator", func(t *testing.T) {
		current := profile(admin.AccessToken, "self-platform-read")
		wrong := identityRequest(t, client, http.MethodPatch, server.URL+"/v1/account/profile", map[string]any{
			"expected_revision": current.Revision, "display_name": current.DisplayName,
			"email": "admin@example.com", "current_password": "wrong-password",
		}, admin.AccessToken, "self-platform-contact-wrong", "self-platform-contact-wrong")
		assertError(t, wrong, http.StatusUnauthorized, "invalid_credentials", "self-platform-contact-wrong")
		wrong.Body.Close()
		changed := identityRequest(t, client, http.MethodPatch, server.URL+"/v1/account/profile", map[string]any{
			"expected_revision": current.Revision, "display_name": current.DisplayName,
			"email": "admin@example.com", "current_password": testPassword,
		}, admin.AccessToken, "self-platform-contact", "self-platform-contact")
		var updated identity.AccountProfile
		decodeResponse(t, changed, http.StatusOK, &updated)
		changed.Body.Close()
		if updated.Email == nil || *updated.Email != "admin@example.com" || updated.Revision != current.Revision+1 {
			t.Fatalf("administrator contact update = %#v", updated)
		}
		if reread := profile(admin.AccessToken, "self-platform-reread"); reread.Email == nil || *reread.Email != "admin@example.com" {
			t.Fatalf("administrator contact reread = %#v", reread)
		}
	})

	t.Run("password change revokes every administrator session", func(t *testing.T) {
		const newPassword = "new-platform-admin-password-long"
		current, cookie := loginWithPassword(t, client, server.URL, "admin", testPassword)
		wrong := identityRequest(t, client, http.MethodPost, server.URL+"/v1/account/password",
			map[string]any{"current_password": "wrong-password", "new_password": newPassword},
			current.AccessToken, "", "self-platform-password-wrong")
		assertError(t, wrong, http.StatusUnauthorized, "invalid_credentials", "self-platform-password-wrong")
		wrong.Body.Close()
		changed := identityRequest(t, client, http.MethodPost, server.URL+"/v1/account/password",
			map[string]any{"current_password": testPassword, "new_password": newPassword},
			current.AccessToken, "", "self-platform-password")
		if changed.StatusCode != http.StatusNoContent {
			t.Fatalf("administrator password change status = %d, body = %s", changed.StatusCode, readBody(changed.Body))
		}
		changed.Body.Close()
		for index, token := range []string{admin.AccessToken, current.AccessToken} {
			requestID := "self-platform-old-access-" + string(rune('a'+index))
			access := identityRequest(t, client, http.MethodGet, server.URL+"/v1/account/profile", nil, token, "", requestID)
			assertError(t, access, http.StatusUnauthorized, "invalid_session", requestID)
			access.Body.Close()
		}
		refresh := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, cookie, "", "self-platform-old-refresh")
		assertError(t, refresh, http.StatusUnauthorized, "invalid_session", "self-platform-old-refresh")
		refresh.Body.Close()
		oldLogin := postLogin(t, client, server.URL, map[string]any{"username": "admin", "password": testPassword}, "self-platform-old-login")
		assertError(t, oldLogin, http.StatusUnauthorized, "invalid_credentials", "self-platform-old-login")
		oldLogin.Body.Close()
		if next, _ := loginWithPassword(t, client, server.URL, "admin", newPassword); next.Principal.ScopeKind != "platform" {
			t.Fatalf("new password principal = %#v", next.Principal)
		}
	})
}
