package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// a source that explains a sign-up that is not ready.
type registrationDiagnosticsStub struct {
	registrationConfigStub
	reasons []string
	calls   *int
}

func (stub registrationDiagnosticsStub) RegistrationReasons(context.Context) ([]string, error) {
	if stub.calls != nil {
		*stub.calls++
	}
	return stub.reasons, nil
}

func readRegistrationConfig(t *testing.T, api http.Handler, authorization string) map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/registration-config", nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Data
}

func notReadyRegistrationStub(calls *int) registrationDiagnosticsStub {
	return registrationDiagnosticsStub{registrationConfigStub: registrationConfigStub{RegistrationConfig{
		RegistrationEnabled: true, Mode: "builtin", HumanCheck: "builtin_captcha", Ready: false,
		Email: RegistrationChannel{Required: true, Available: false},
		// a source must not leak reasons through RegistrationConfig either
		Reasons: []string{"leaked"},
	}}, reasons: []string{"email_channel_disabled", "email_sender_unavailable"}, calls: calls}
}

// Visitors (no session, a malformed or unknown token) never get reasons, and
// the diagnosis is not even run for them.
func TestRegistrationConfigVisitorGetsNoReasons(t *testing.T) {
	calls := 0
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		RegistrationConfig: notReadyRegistrationStub(&calls)}).Handler()
	for _, authorization := range []string{"", "Bearer not-a-session", "Basic Zm9vOmJhcg=="} {
		data := readRegistrationConfig(t, api, authorization)
		if _, present := data["reasons"]; present {
			t.Fatalf("authorization %q: visitor got reasons %v", authorization, data["reasons"])
		}
		if data["ready"] != false {
			t.Fatalf("authorization %q: ready=%v", authorization, data["ready"])
		}
	}
	if calls != 0 {
		t.Fatalf("diagnosis ran %d times for visitors", calls)
	}
}

// A platform administrator's session gets the reason codes; a platform user
// without the system configuration permission does not.
func TestRegistrationConfigAdministratorGetsReasons(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(context.Background(), "admin", "Platform Admin", passwordHash, "registration-ready")
	if err != nil {
		t.Fatal(err)
	}
	if insertTestUser(t, pool, bootstrap.ScopeID, "viewer", "No Role User", passwordHash, "active") == uuid.Nil {
		t.Fatal("viewer not created")
	}
	tokens, err := identity.NewTokenManager("registration-ready-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32),
		RegistrationConfig: notReadyRegistrationStub(&calls)}).Handler())
	t.Cleanup(server.Close)
	api := server.Config.Handler

	admin, _ := loginOK(t, server.Client(), server.URL, "admin")
	if !slices.Contains(admin.Principal.Permissions, "platform.admin") &&
		!slices.Contains(admin.Principal.Permissions, "system_configuration.read") {
		t.Fatalf("bootstrap admin lacks the system configuration permission: %v", admin.Principal.Permissions)
	}
	data := readRegistrationConfig(t, api, "Bearer "+admin.AccessToken)
	reasons, _ := data["reasons"].([]any)
	if len(reasons) != 2 || reasons[0] != "email_channel_disabled" || reasons[1] != "email_sender_unavailable" {
		t.Fatalf("administrator reasons = %v", data["reasons"])
	}

	viewer, _ := loginOK(t, server.Client(), server.URL, "viewer")
	if data := readRegistrationConfig(t, api, "Bearer "+viewer.AccessToken); data["reasons"] != nil {
		t.Fatalf("user without permission got reasons %v", data["reasons"])
	}
	if data := readRegistrationConfig(t, api, ""); data["reasons"] != nil {
		t.Fatalf("visitor got reasons %v", data["reasons"])
	}
	if calls != 1 {
		t.Fatalf("diagnosis ran %d times, want once (administrator only)", calls)
	}
}
