package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// TestAccountLocaleHTTP: a signed-in user stores the console
// language that picks the template language of their notifications.
func TestAccountLocaleHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	hash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(t.Context(), "locale-admin", "Locale admin", hash, "locale-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("account-locale-test-signing-key-at-least-thirty-two-bytes", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, service, Config{CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x5a}, 32)})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth, _ := loginWithPassword(t, client, server.URL, "locale-admin", testPassword)
	path := server.URL + "/v1/account/locale"
	locale := func() *string {
		t.Helper()
		var value *string
		if err := pool.QueryRow(t.Context(), `SELECT locale FROM users WHERE username='locale-admin'`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if locale() != nil {
		t.Fatal("a new user already has a language")
	}
	for _, value := range []string{"en-US", "en-US", "zh-TW"} {
		response := identityRequest(t, client, http.MethodPut, path, map[string]any{"locale": value}, auth.AccessToken, "", "locale-put")
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("PUT locale %s status=%d, want 204", value, response.StatusCode)
		}
		if got := locale(); got == nil || *got != value {
			t.Fatalf("stored locale = %v, want %s", got, value)
		}
	}
	response := identityRequest(t, client, http.MethodPut, path, map[string]any{"locale": "fr-FR"}, auth.AccessToken, "", "locale-invalid")
	assertError(t, response, http.StatusBadRequest, "validation_error", "locale-invalid")
	response.Body.Close()
	response = identityRequest(t, client, http.MethodPut, path, map[string]any{"locale": "en-US"}, "", "", "locale-anonymous")
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous PUT locale status=%d, want 401", response.StatusCode)
	}
	if got := locale(); got == nil || *got != "zh-TW" {
		t.Fatalf("refused requests changed the stored locale to %v", got)
	}
}
