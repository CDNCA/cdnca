package identitysessionhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestHandlerListsRedactedSessionFamilies(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	session := testAuthenticatedSession()
	store := &fakeSessionStore{listResult: ListResult{
		Items: []SessionFamily{{FamilyID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
			Current: true, Active: true, DeviceLabel: "Chrome on macOS", IPPrefix: "203.0.113.0/24",
			CreatedAt: now.Add(-time.Hour), LastUsedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
			SessionCount: 2, Revision: 2}},
		NextCursor: "cursor-next",
	}}
	handler, err := NewHandler(store, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return session, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/identity/sessions?limit=25&cursor=cursor-in", nil)
	request.Header.Set("Authorization", "Bearer access-token-must-never-echo")
	request.Header.Set("X-Request-ID", "018f47de-5ad5-7d5c-9c45-8f8f8f8f8f8f")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if store.listCalls != 1 || store.listRequest.Actor.SessionID != session.SessionID ||
		store.listRequest.Actor.ScopeID != session.Principal.ScopeID || store.listRequest.Actor.UserID != session.Principal.UserID ||
		store.listRequest.Limit != 25 || store.listRequest.Cursor != "cursor-in" {
		t.Fatalf("list request=%+v calls=%d", store.listRequest, store.listCalls)
	}
	body := response.Body.String()
	for _, forbidden := range []string{"access-token-must-never-echo", "refresh_token", "token_hash", "203.0.113.47"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
	for _, required := range []string{`"family_id":"11111111-1111-4111-8111-111111111111"`,
		`"ip_prefix":"203.0.113.0/24"`, `"current":true`, `"revision":2`, `"next_cursor":"cursor-next"`} {
		if !strings.Contains(body, required) {
			t.Fatalf("response missing %s: %s", required, body)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers=%v", response.Header())
	}
}

func TestHandlerRejectsInvalidBearerAndListQueryBeforeStore(t *testing.T) {
	session := testAuthenticatedSession()
	for name, mutate := range map[string]func(*http.Request){
		"missing bearer":   func(request *http.Request) { request.Header.Del("Authorization") },
		"duplicate bearer": func(request *http.Request) { request.Header.Add("Authorization", "Bearer second") },
		"wrong scheme":     func(request *http.Request) { request.Header.Set("Authorization", "Basic token") },
		"empty token":      func(request *http.Request) { request.Header.Set("Authorization", "Bearer ") },
	} {
		t.Run(name, func(t *testing.T) {
			store := &fakeSessionStore{}
			handler, err := NewHandler(store, func(context.Context, string) (identity.AuthenticatedSession, error) {
				return session, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/v1/identity/sessions", nil)
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("X-Request-ID", uuid.NewString())
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || store.listCalls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, store.listCalls, response.Body.String())
			}
		})
	}

	for _, target := range []string{
		"/v1/identity/sessions?limit=0",
		"/v1/identity/sessions?limit=101",
		"/v1/identity/sessions?limit=20&limit=21",
		"/v1/identity/sessions?unknown=value",
	} {
		store := &fakeSessionStore{}
		handler, err := NewHandler(store, func(context.Context, string) (identity.AuthenticatedSession, error) {
			return session, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		request := newAuthenticatedRequest(t, http.MethodGet, target)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || store.listCalls != 0 {
			t.Fatalf("target=%s status=%d calls=%d", target, response.Code, store.listCalls)
		}
	}
}

func TestHandlerRevokesCurrentOrOtherSessionFamilyWithExactMetadata(t *testing.T) {
	session := testAuthenticatedSession()
	familyID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	revokedAt := time.Date(2026, 8, 8, 12, 30, 0, 0, time.UTC)
	store := &fakeSessionStore{revokeResult: RevokeResult{FamilyID: familyID, Revision: 4,
		RevokedAt: revokedAt, Current: true}}
	handler, err := NewHandler(store, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return session, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := newAuthenticatedRequest(t, http.MethodDelete, "/v1/identity/session-families/"+familyID.String())
	request.Header.Set("If-Match", `"3"`)
	request.Header.Set("Idempotency-Key", "revoke-device-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || store.revokeCalls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, store.revokeCalls, response.Body.String())
	}
	input := store.revokeRequest
	if input.Actor.SessionID != session.SessionID || input.FamilyID != familyID || input.ExpectedRevision != 3 ||
		input.IdempotencyKey != "revoke-device-1" || input.RequestID != request.Header.Get("X-Request-ID") {
		t.Fatalf("revoke request=%+v", input)
	}
	if response.Header().Get("ETag") != `"4"` || !strings.Contains(response.Body.String(), `"current":true`) {
		t.Fatalf("headers=%v body=%s", response.Header(), response.Body.String())
	}
}

func TestHandlerRejectsInvalidRevokeMetadataBeforeStore(t *testing.T) {
	session := testAuthenticatedSession()
	familyID := uuid.NewString()
	mutations := map[string]func(*http.Request){
		"missing if match":    func(request *http.Request) { request.Header.Del("If-Match") },
		"weak if match":       func(request *http.Request) { request.Header.Set("If-Match", "3") },
		"duplicate if match":  func(request *http.Request) { request.Header.Add("If-Match", `"3"`) },
		"missing idempotency": func(request *http.Request) { request.Header.Del("Idempotency-Key") },
		"invalid idempotency": func(request *http.Request) { request.Header.Set("Idempotency-Key", "bad key") },
		"body forbidden":      func(request *http.Request) { request.Body = ioNopCloser("{}") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store := &fakeSessionStore{}
			handler, err := NewHandler(store, func(context.Context, string) (identity.AuthenticatedSession, error) {
				return session, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			request := newAuthenticatedRequest(t, http.MethodDelete, "/v1/identity/session-families/"+familyID)
			request.Header.Set("If-Match", `"3"`)
			request.Header.Set("Idempotency-Key", "revoke-device-1")
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || store.revokeCalls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, store.revokeCalls, response.Body.String())
			}
		})
	}
}

func TestHandlerStableErrorMappingAndAuthenticationFence(t *testing.T) {
	tests := []struct {
		err  error
		code int
		key  string
	}{
		{ErrUnauthenticated, http.StatusUnauthorized, "identity_session_unauthenticated"},
		{ErrNotFound, http.StatusNotFound, "identity_session_not_found"},
		{ErrRevisionConflict, http.StatusConflict, "identity_session_revision_conflict"},
		{ErrIdempotencyConflict, http.StatusConflict, "identity_session_idempotency_conflict"},
		{ErrAlreadyRevoked, http.StatusConflict, "identity_session_already_revoked"},
		{ErrUnavailable, http.StatusServiceUnavailable, "identity_session_unavailable"},
	}
	for _, test := range tests {
		store := &fakeSessionStore{revokeErr: test.err}
		handler, err := NewHandler(store, func(context.Context, string) (identity.AuthenticatedSession, error) {
			return testAuthenticatedSession(), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		request := newAuthenticatedRequest(t, http.MethodDelete, "/v1/identity/session-families/"+uuid.NewString())
		request.Header.Set("If-Match", `"1"`)
		request.Header.Set("Idempotency-Key", "same-key")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.code || !strings.Contains(response.Body.String(), `"code":"`+test.key+`"`) {
			t.Fatalf("err=%v status=%d body=%s", test.err, response.Code, response.Body.String())
		}
	}

	store := &fakeSessionStore{}
	handler, err := NewHandler(store, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	})
	if err != nil {
		t.Fatal(err)
	}
	request := newAuthenticatedRequest(t, http.MethodDelete, "/v1/identity/session-families/"+uuid.NewString())
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "same-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || store.revokeCalls != 0 {
		t.Fatalf("invalid caller status=%d calls=%d", response.Code, store.revokeCalls)
	}
}

type fakeSessionStore struct {
	listResult    ListResult
	listErr       error
	listRequest   ListRequest
	listCalls     int
	revokeResult  RevokeResult
	revokeErr     error
	revokeRequest RevokeRequest
	revokeCalls   int
}

func (store *fakeSessionStore) List(_ context.Context, request ListRequest) (ListResult, error) {
	store.listCalls++
	store.listRequest = request
	return store.listResult, store.listErr
}

func (store *fakeSessionStore) Revoke(_ context.Context, request RevokeRequest) (RevokeResult, error) {
	store.revokeCalls++
	store.revokeRequest = request
	return store.revokeResult, store.revokeErr
}

func testAuthenticatedSession() identity.AuthenticatedSession {
	return identity.AuthenticatedSession{SessionID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Principal: identity.Principal{UserID: uuid.MustParse("44444444-4444-4444-8444-444444444444"),
			ScopeID: uuid.MustParse("55555555-5555-4555-8555-555555555555"), ScopeKind: "tenant"}}
}

func newAuthenticatedRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("X-Request-ID", uuid.NewString())
	return request
}

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

func ioNopCloser(value string) *readCloser { return &readCloser{Reader: strings.NewReader(value)} }

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatal(err)
	}
}

var _ = errors.Is
