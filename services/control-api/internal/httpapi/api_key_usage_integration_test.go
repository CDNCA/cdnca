package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type apiKeyUsageRecorderSpy struct {
	mu     sync.Mutex
	accept bool
	calls  []apiKeyUsageObservation
}

type apiKeyUsageObservation struct {
	keyID      uuid.UUID
	observedAt time.Time
}

func (recorder *apiKeyUsageRecorderSpy) TryRecord(keyID uuid.UUID, observedAt time.Time) bool {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.calls = append(recorder.calls, apiKeyUsageObservation{keyID: keyID, observedAt: observedAt})
	return recorder.accept
}

func (recorder *apiKeyUsageRecorderSpy) snapshot() []apiKeyUsageObservation {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]apiKeyUsageObservation(nil), recorder.calls...)
}

func TestAPIKeyUsageRecordsSuccessfulAuthenticationOnly(t *testing.T) {
	pool := isolatedTestPool(t)
	adminHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(
		context.Background(), "usage-admin", "Usage Admin", adminHash, "usage-bootstrap",
	); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("api-key-usage-access-secret-more-than-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	currentNow := time.Now().In(time.FixedZone("usage-offset", 8*60*60)).Truncate(time.Microsecond)
	recorder := &apiKeyUsageRecorderSpy{accept: true}
	pepper := bytes.Repeat([]byte{0x73}, 32)
	server := httptest.NewServer(New(pool, identityService, Config{
		APIKeyPepper: pepper, Now: func() time.Time { return currentNow },
		APIKeyUsageRecorder: recorder,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginWithPassword(t, client, server.URL, "usage-admin", testPassword)
	alice := createManagedUser(t, client, server.URL, admin.AccessToken, "usage-create-alice", map[string]any{
		"username": "usage-alice", "password": tenantPassword, "display_name": "Usage Alice",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	aliceAuth, _ := loginWithPassword(t, client, server.URL, "usage-alice", tenantPassword)
	issued := createSelfAPIKey(t, client, server.URL, aliceAuth.AccessToken, "usage-create-key", map[string]any{
		"name": "usage key", "scopes": []string{"sites.read"},
		"expires_at": currentNow.Add(24 * time.Hour).Format(time.RFC3339Nano),
	})
	credential := issued.Key.KeyID + "." + issued.Secret
	keyExpiresAt := *issued.Key.ExpiresAt

	assertCallCount := func(want int) []apiKeyUsageObservation {
		t.Helper()
		calls := recorder.snapshot()
		if len(calls) != want {
			t.Fatalf("usage calls = %d, want %d: %#v", len(calls), want, calls)
		}
		return calls
	}

	success := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		"", credential, "", "", "usage-success")
	if success.StatusCode != http.StatusOK {
		t.Fatalf("successful API-key request status=%d body=%s", success.StatusCode, readBody(success.Body))
	}
	success.Body.Close()
	calls := assertCallCount(1)
	if calls[0].keyID != issued.Key.ID || calls[0].observedAt.Location() != time.UTC ||
		!calls[0].observedAt.Equal(currentNow) {
		t.Fatalf("successful observation = %#v, want key=%s at=%s UTC", calls[0], issued.Key.ID, currentNow)
	}

	denied := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/account/balance", nil,
		"", credential, "", "", "usage-downstream-denied")
	assertError(t, denied, http.StatusForbidden, "permission_denied", "usage-downstream-denied")
	denied.Body.Close()
	assertCallCount(2)

	wrongSecret := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		"", issued.Key.KeyID+"."+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "", "usage-wrong-secret")
	assertError(t, wrongSecret, http.StatusUnauthorized, "invalid_session", "usage-wrong-secret")
	wrongSecret.Body.Close()
	malformed := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		"", "malformed", "", "", "usage-malformed")
	assertError(t, malformed, http.StatusUnauthorized, "invalid_session", "usage-malformed")
	malformed.Body.Close()
	unknown := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		"", "cfk_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "", "usage-unknown")
	assertError(t, unknown, http.StatusUnauthorized, "invalid_session", "usage-unknown")
	unknown.Body.Close()
	bearer := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		aliceAuth.AccessToken, "", "", "", "usage-bearer")
	if bearer.StatusCode != http.StatusOK {
		t.Fatalf("Bearer request status=%d body=%s", bearer.StatusCode, readBody(bearer.Body))
	}
	bearer.Body.Close()
	assertCallCount(2)

	recorder.mu.Lock()
	recorder.accept = false
	recorder.mu.Unlock()
	for index, state := range []string{"false", "full", "closed", "database-failure"} {
		dropped := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
			"", credential, "", "", "usage-recorder-"+state)
		if dropped.StatusCode != http.StatusOK {
			t.Fatalf("%s recorder rejection changed status=%d body=%s",
				state, dropped.StatusCode, readBody(dropped.Body))
		}
		dropped.Body.Close()
		assertCallCount(3 + index)
	}

	boundaryRecorder := &apiKeyUsageRecorderSpy{accept: true}
	boundaryBase := keyExpiresAt.Add(-time.Nanosecond)
	boundaryCalls := 0
	boundaryServer := httptest.NewServer(New(pool, identityService, Config{
		APIKeyPepper: pepper,
		Now: func() time.Time {
			boundaryCalls++
			if boundaryCalls == 1 {
				return boundaryBase
			}
			return boundaryBase.Add(time.Hour)
		},
		APIKeyUsageRecorder: boundaryRecorder,
	}).Handler())
	t.Cleanup(boundaryServer.Close)
	justBeforeExpiry := apiKeyRequest(t, boundaryServer.Client(), http.MethodGet,
		boundaryServer.URL+"/v1/sites", nil, "", credential, "", "", "usage-expiry-minus-ns")
	if justBeforeExpiry.StatusCode != http.StatusOK {
		t.Fatalf("expiry -1ns status=%d body=%s", justBeforeExpiry.StatusCode, readBody(justBeforeExpiry.Body))
	}
	justBeforeExpiry.Body.Close()
	boundaryObservations := boundaryRecorder.snapshot()
	if len(boundaryObservations) != 1 || !boundaryObservations[0].observedAt.Equal(boundaryBase) {
		t.Fatalf("expiry -1ns observations = %#v, want one at %v", boundaryObservations, boundaryBase)
	}
	boundaryBase = keyExpiresAt
	boundaryCalls = 0
	exactExpiry := apiKeyRequest(t, boundaryServer.Client(), http.MethodGet,
		boundaryServer.URL+"/v1/sites", nil, "", credential, "", "", "usage-exact-expiry")
	assertError(t, exactExpiry, http.StatusUnauthorized, "invalid_session", "usage-exact-expiry")
	exactExpiry.Body.Close()
	if len(boundaryRecorder.snapshot()) != 1 {
		t.Fatal("exact-expiry authentication attempted usage recording")
	}

	currentNow = keyExpiresAt
	expired := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		"", credential, "", "", "usage-expired")
	assertError(t, expired, http.StatusUnauthorized, "invalid_session", "usage-expired")
	expired.Body.Close()
	currentNow = keyExpiresAt.Add(-24 * time.Hour)
	assertCallCount(6)

	revokedKey := createSelfAPIKey(t, client, server.URL, aliceAuth.AccessToken, "usage-create-revoked", map[string]any{
		"name": "revoked usage key", "scopes": []string{"sites.read"},
		"expires_at": currentNow.Add(24 * time.Hour).Format(time.RFC3339Nano),
	})
	revoke := apiKeyRequest(t, client, http.MethodPost,
		server.URL+"/v1/account/api-keys/"+revokedKey.Key.ID.String()+"/revoke", map[string]any{},
		aliceAuth.AccessToken, "", "usage-revoke", `"1"`, "usage-revoke")
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoke.StatusCode, readBody(revoke.Body))
	}
	revoke.Body.Close()
	revokedCredential := revokedKey.Key.KeyID + "." + revokedKey.Secret
	revoked := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		"", revokedCredential, "", "", "usage-revoked")
	assertError(t, revoked, http.StatusUnauthorized, "invalid_session", "usage-revoked")
	revoked.Body.Close()
	assertCallCount(6)

	var roleID uuid.UUID
	if err := pool.QueryRow(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 RETURNING role_id`, alice.ScopeID, alice.ID).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	noEffectiveScope := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		"", credential, "", "", "usage-no-effective-scope")
	assertError(t, noEffectiveScope, http.StatusUnauthorized, "invalid_session", "usage-no-effective-scope")
	noEffectiveScope.Body.Close()
	assertCallCount(6)
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at)
		VALUES($1,$2,$3,$4)`, alice.ScopeID, alice.ID, roleID, currentNow); err != nil {
		t.Fatal(err)
	}

	nilClockRecorder := &apiKeyUsageRecorderSpy{accept: true}
	nilClockServer := httptest.NewServer(New(pool, identityService, Config{
		APIKeyPepper: pepper, APIKeyUsageRecorder: nilClockRecorder,
	}).Handler())
	t.Cleanup(nilClockServer.Close)
	nilClockStart := time.Now()
	nilClock := apiKeyRequest(t, nilClockServer.Client(), http.MethodGet,
		nilClockServer.URL+"/v1/sites", nil, "", credential, "", "", "usage-nil-clock")
	if nilClock.StatusCode != http.StatusOK {
		t.Fatalf("nil-clock status=%d body=%s", nilClock.StatusCode, readBody(nilClock.Body))
	}
	nilClock.Body.Close()
	nilClockCalls := nilClockRecorder.snapshot()
	if len(nilClockCalls) != 1 || nilClockCalls[0].observedAt.Before(nilClockStart) ||
		nilClockCalls[0].observedAt.After(time.Now()) {
		t.Fatalf("nil-clock observation = %#v, request started at %v", nilClockCalls, nilClockStart)
	}

	pool.Close()
	databaseFailure := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil,
		"", credential, "", "", "usage-database-failure")
	assertError(t, databaseFailure, http.StatusUnauthorized, "invalid_session", "usage-database-failure")
	databaseFailure.Body.Close()
	assertCallCount(6)
}

func TestAPIKeyUsageRecorderTypedNilIsRejected(t *testing.T) {
	var recorder *apiKeyUsageRecorderSpy
	server := New(nil, nil, Config{APIKeyUsageRecorder: recorder})
	if server.InitializationError() == nil {
		t.Fatal("typed-nil API key usage recorder was accepted")
	}
}
