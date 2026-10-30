package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

func TestIdentityProfileContactConflictHTTP(t *testing.T) {
	for _, field := range []string{"email", "phone"} {
		t.Run(field, func(t *testing.T) {
			pool := isolatedTestPool(t)
			hash, err := identity.HashPassword(testPassword)
			if err != nil {
				t.Fatal(err)
			}
			store := identity.NewStore(pool)
			if _, err := store.BootstrapPlatformUser(t.Context(), "contact-admin", "Contact admin", hash, "contact-bootstrap"); err != nil {
				t.Fatal(err)
			}
			tokens, err := identity.NewTokenManager("profile-contact-test-signing-key-at-least-thirty-two-bytes", time.Hour)
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
			admin, _ := loginWithPassword(t, client, server.URL, "contact-admin", testPassword)
			createManagedUser(t, client, server.URL, admin.AccessToken, "contact-reserved-create", map[string]any{
				"username": "contact-reserved", "password": tenantPassword, "display_name": "Reserved contact",
				"email": "reserved@example.invalid", "phone": "+8613800000101", "role": identity.UserRoleViewer,
			})
			subject := createManagedUser(t, client, server.URL, admin.AccessToken, "contact-subject-create", map[string]any{
				"username": "contact-subject", "password": tenantPassword, "display_name": "Subject contact",
				"email": "subject@example.invalid", "phone": "+8613800000102", "role": identity.UserRoleViewer,
			})
			auth, _ := loginWithPassword(t, client, server.URL, subject.Username, tenantPassword)
			body := map[string]any{"expected_revision": subject.Revision, "display_name": subject.DisplayName,
				"email": *subject.Email, "phone": *subject.Phone, "current_password": "wrong-password"}
			if field == "email" {
				body[field] = "reserved@example.invalid"
			} else {
				body[field] = "+8613800000101"
			}
			path := server.URL + "/v1/account/profile"
			response := identityRequest(t, client, http.MethodPatch, path, body, auth.AccessToken, "contact-wrong-password", "contact-wrong-password")
			assertError(t, response, http.StatusUnauthorized, "invalid_credentials", "contact-wrong-password")
			response.Body.Close()
			body["current_password"] = tenantPassword
			for attempt := 0; attempt < 2; attempt++ {
				response = identityRequest(t, client, http.MethodPatch, path, body, auth.AccessToken, "contact-collision", "contact-collision")
				encoded := readBody(response.Body)
				response.Body.Close()
				var envelope struct {
					Error struct {
						Code string `json:"code"`
					} `json:"error"`
				}
				if response.StatusCode != http.StatusBadRequest || json.Unmarshal([]byte(encoded), &envelope) != nil || envelope.Error.Code != "validation_error" {
					t.Fatalf("duplicate %s attempt%d status=%d body=%s, want400 validation_error", field, attempt, response.StatusCode, encoded)
				}
				for _, sensitive := range []string{"SQLSTATE", "users_email_registration_unique_159", "users_phone_registration_unique_159", "reserved@example.invalid", "+8613800000101"} {
					if strings.Contains(encoded, sensitive) {
						t.Fatalf("duplicate contact response disclosed internal or another account data: %s", encoded)
					}
				}
			}
			var revision int64
			var email, phone string
			if err := pool.QueryRow(t.Context(), `SELECT revision,email,phone FROM users WHERE id=$1`, subject.ID).Scan(&revision, &email, &phone); err != nil {
				t.Fatal(err)
			}
			if revision != subject.Revision || email != *subject.Email || phone != *subject.Phone {
				t.Fatalf("rejected update changed subject: revision=%d email=%s phone=%s", revision, email, phone)
			}
			var receipts, audits int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM identity_write_requests WHERE actor_user_id=$1 AND operation='identity.self.update'`, subject.ID).Scan(&receipts); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE actor_user_id=$1 AND action='identity.self.update'`, subject.ID).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if receipts != 0 || audits != 0 {
				t.Fatalf("failed contact transaction left receipts=%d audits=%d", receipts, audits)
			}
			if field == "email" {
				body[field] = "available@example.invalid"
			} else {
				body[field] = "+8613800000103"
			}
			for attempt := 0; attempt < 2; attempt++ {
				response = identityRequest(t, client, http.MethodPatch, path, body, auth.AccessToken, "contact-collision", "contact-recovery")
				var profile identity.AccountProfile
				decodeResponse(t, response, http.StatusOK, &profile)
				response.Body.Close()
				if profile.Revision != subject.Revision+1 || (field == "email" && *profile.Email != body[field]) || (field == "phone" && *profile.Phone != body[field]) {
					t.Fatalf("contact recovery/replay=%#v", profile)
				}
			}
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM identity_write_requests WHERE actor_user_id=$1 AND operation='identity.self.update' AND completed_at IS NOT NULL`, subject.ID).Scan(&receipts); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE actor_user_id=$1 AND action='identity.self.update' AND result='success'`, subject.ID).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if receipts != 1 || audits != 1 {
				t.Fatalf("successful recovery/replay receipts=%d audits=%d, want1/1", receipts, audits)
			}
			t.Logf("%s: duplicate400 x2; wrong password401; unchanged user/zero failed receipts/audits; valid recovery200 x2; one committed receipt/audit", field)
		})
	}
}
