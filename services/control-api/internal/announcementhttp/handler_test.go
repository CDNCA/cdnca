package announcementhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := New(nil, nil); err == nil {
		t.Fatal("New accepted missing dependencies")
	}
	if _, err := New(&announcement.Store{}, nil); err == nil {
		t.Fatal("New accepted missing session authenticator")
	}
}

func TestZeroSessionEnvelopeFailsClosed(t *testing.T) {
	handler, err := New(&announcement.Store{}, AuthenticateFunc(func(*http.Request) (SessionEnvelope, error) {
		return SessionEnvelope{Principal: identity.Principal{
			UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{"announcements.manage"},
		}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/announcements", nil)
	writer := httptest.NewRecorder()
	handler.Handler().ServeHTTP(writer, request)
	if writer.Code != http.StatusUnauthorized || !strings.Contains(writer.Body.String(), `"code":"invalid_session"`) {
		t.Fatalf("zero session response = %d %s", writer.Code, writer.Body.String())
	}
}

func TestAuthenticateFailureIsUnauthorized(t *testing.T) {
	handler, err := New(&announcement.Store{}, AuthenticateFunc(func(*http.Request) (SessionEnvelope, error) {
		return SessionEnvelope{}, errors.New("revoked")
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/account/messages", nil)
	writer := httptest.NewRecorder()
	handler.Handler().ServeHTTP(writer, request)
	if writer.Code != http.StatusUnauthorized {
		t.Fatalf("authentication failure status = %d", writer.Code)
	}
}

func TestIdempotencyAndIfMatchRejectMalformedHeaders(t *testing.T) {
	request := httptest.NewRequest("POST", "/", nil)
	writer := httptest.NewRecorder()
	if _, ok := idempotencyKey(writer, request); ok || writer.Code != 400 {
		t.Fatalf("missing idempotency key accepted: ok=%v status=%d", ok, writer.Code)
	}
	request.Header.Set("Idempotency-Key", "fixed-key")
	writer = httptest.NewRecorder()
	if _, ok := ifMatch(writer, request); ok || writer.Code != 400 {
		t.Fatalf("missing If-Match accepted: ok=%v status=%d", ok, writer.Code)
	}
	request.Header.Set("If-Match", `"2"`)
	writer = httptest.NewRecorder()
	if key, ok := idempotencyKey(writer, request); !ok || key != "fixed-key" {
		t.Fatalf("valid idempotency key rejected: key=%q ok=%v", key, ok)
	}
	if revision, ok := ifMatch(writer, request); !ok || revision != 2 {
		t.Fatalf("valid If-Match rejected: revision=%d ok=%v", revision, ok)
	}
}

func TestPathUUIDRejectsNilAndMalformedValues(t *testing.T) {
	for _, value := range []string{"not-a-uuid", uuid.Nil.String()} {
		request := httptest.NewRequest("GET", "/"+value, nil)
		request.SetPathValue("id", value)
		writer := httptest.NewRecorder()
		if _, ok := pathUUID(writer, request, "id"); ok || writer.Code != 400 {
			t.Fatalf("path ID %q accepted: ok=%v status=%d", value, ok, writer.Code)
		}
	}
}

func TestAnnouncementOpenAPIExpressesByteAndCombinedAudienceLimits(t *testing.T) {
	script, err := os.ReadFile("../../../../api/control-announcements.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	if strings.Contains(text, "body: { type: string, minLength: 1, maxLength: 65536 }") ||
		!strings.Contains(text, "x-max-bytes: 65536") ||
		!strings.Contains(text, "UTF-8 encoded body must not exceed 65536 bytes") {
		t.Fatal("OpenAPI body must describe the implemented UTF-8 byte limit without a character maxLength")
	}
	if strings.Count(text, "maxItems: 10000") < 4 ||
		!strings.Contains(text, "user_ids and group_ids combined must contain at most 10000 entries") {
		t.Fatal("OpenAPI must bound each audience array and document the combined Go limit")
	}
}

func TestGlobalAnnouncementContractAndScopeBoundary(t *testing.T) {
	script, err := os.ReadFile("../../../../api/control-announcements.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, fragment := range []string{
		"/v1/admin/announcements/global:",
		"/v1/admin/announcements/global/{id}:",
		"/v1/admin/announcements/global/{id}/publish:",
		"/v1/admin/announcements/global/{id}/withdraw:",
		"all_tenants", "tenant_scope_ids", "role_targets", "user_targets",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("global announcement OpenAPI missing %q", fragment)
		}
	}

	tenant := identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Permissions: []string{"announcements.manage"},
	}
	handler := (&Handler{
		authenticate: func(*http.Request) (SessionEnvelope, error) {
			return SessionEnvelope{Principal: tenant, SessionID: uuid.New()}, nil
		},
		maxBodyBytes: 1 << 20,
	}).Handler()
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/announcements/global", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"permission_denied"`) {
		t.Fatalf("tenant global response = %d %s", response.Code, response.Body.String())
	}
}

func TestAudienceArraysMustBePresentAndNonNullBeforeStore(t *testing.T) {
	principal := identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Permissions: []string{"announcements.manage"},
	}
	handler := (&Handler{
		authenticate: func(*http.Request) (SessionEnvelope, error) {
			return SessionEnvelope{Principal: principal, SessionID: uuid.New()}, nil
		},
		maxBodyBytes: 1 << 20,
	}).Handler()
	announcementID := uuid.NewString()
	tests := []struct {
		name, method, path, body string
		ifMatch                  bool
	}{
		{name: "create missing user_ids", method: http.MethodPost, path: "/v1/admin/announcements", body: `{"title":"title","body":"body","all":true,"group_ids":[],"withdrawal_visibility":"retain"}`},
		{name: "create null group_ids", method: http.MethodPost, path: "/v1/admin/announcements", body: `{"title":"title","body":"body","all":true,"user_ids":[],"group_ids":null,"withdrawal_visibility":"retain"}`},
		{name: "update null user_ids", method: http.MethodPatch, path: "/v1/admin/announcements/" + announcementID, body: `{"version":1,"expected_revision":1,"title":"title","body":"body","all":true,"user_ids":null,"group_ids":[],"withdrawal_visibility":"retain"}`, ifMatch: true},
		{name: "update missing group_ids", method: http.MethodPatch, path: "/v1/admin/announcements/" + announcementID, body: `{"version":1,"expected_revision":1,"title":"title","body":"body","all":true,"user_ids":[],"withdrawal_visibility":"retain"}`, ifMatch: true},
		{name: "revise missing user_ids", method: http.MethodPost, path: "/v1/admin/announcements/" + announcementID + "/revise", body: `{"expected_head_version":1,"title":"title","body":"body","all":true,"group_ids":[],"withdrawal_visibility":"retain"}`, ifMatch: true},
		{name: "revise null group_ids", method: http.MethodPost, path: "/v1/admin/announcements/" + announcementID + "/revise", body: `{"expected_head_version":1,"title":"title","body":"body","all":true,"user_ids":[],"group_ids":null,"withdrawal_visibility":"retain"}`, ifMatch: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "required-arrays")
			request.Header.Set("X-Request-ID", "req-required-arrays")
			if test.ifMatch {
				request.Header.Set("If-Match", `"1"`)
			}
			response := httptest.NewRecorder()
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("invalid request reached the store: %v", recovered)
				}
			}()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAudienceJSONFieldPolicy(t *testing.T) {
	handler := &Handler{maxBodyBytes: 1 << 20}
	t.Run("unknown field rejected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"title":"title","body":"body","all":true,"user_ids":[],"group_ids":[],"withdrawal_visibility":"retain","unknown":true}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var body createRequest
		if handler.decode(response, request, &body) || response.Code != http.StatusBadRequest {
			t.Fatalf("unknown field decode status=%d", response.Code)
		}
	})
	t.Run("duplicate field rejected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"title":"title","body":"body","all":true,"user_ids":null,"user_ids":[],"group_ids":[],"withdrawal_visibility":"retain"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var body createRequest
		if handler.decode(response, request, &body) || response.Code != http.StatusBadRequest ||
			!strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
			t.Fatalf("duplicate field policy status=%d body=%s", response.Code, response.Body.String())
		}
	})
	t.Run("nested duplicate field rejected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"outer":{"value":1,"value":2}}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var body map[string]any
		if handler.decode(response, request, &body) || response.Code != http.StatusBadRequest ||
			!strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
			t.Fatalf("nested duplicate field policy status=%d body=%s", response.Code, response.Body.String())
		}
	})
	t.Run("escape equivalent duplicate field rejected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":1,"\u0076alue":2}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var body map[string]any
		if handler.decode(response, request, &body) || response.Code != http.StatusBadRequest ||
			!strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
			t.Fatalf("escape-equivalent duplicate policy status=%d body=%s", response.Code, response.Body.String())
		}
	})
	t.Run("same field in separate objects accepted", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
			`{"left":{"value":1},"right":{"value":2},"items":[{"value":3},{"value":4}]}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var body map[string]any
		if !handler.decode(response, request, &body) || len(body) != 3 {
			t.Fatalf("separate object keys response=%d body=%s decoded=%v", response.Code, response.Body.String(), body)
		}
	})
}

func TestWriteRoutesRejectAmbiguousJSONBeforeStore(t *testing.T) {
	principal := identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Permissions: []string{"announcements.manage", "announcements.read"},
	}
	handler := (&Handler{
		authenticate: func(*http.Request) (SessionEnvelope, error) {
			return SessionEnvelope{Principal: principal, SessionID: uuid.New()}, nil
		},
		maxBodyBytes: 1 << 20,
	}).Handler()
	announcementID, eventID := uuid.NewString(), uuid.NewString()
	tests := []struct {
		name, method, path, body string
		ifMatch                  bool
	}{
		{name: "create", method: http.MethodPost, path: "/v1/admin/announcements", body: `{"title":"one","title":"two","body":"body","all":true,"user_ids":[],"group_ids":[],"withdrawal_visibility":"retain"}`},
		{name: "update", method: http.MethodPatch, path: "/v1/admin/announcements/" + announcementID, body: `{"version":1,"version":2,"expected_revision":1,"title":"title","body":"body","all":true,"user_ids":[],"group_ids":[],"withdrawal_visibility":"retain"}`, ifMatch: true},
		{name: "schedule", method: http.MethodPost, path: "/v1/admin/announcements/" + announcementID + "/schedule", body: `{"version":1,"expected_revision":1,"publish_at":"2026-08-06T00:00:00Z","publish_at":"2026-08-07T00:00:00Z"}`, ifMatch: true},
		{name: "publish", method: http.MethodPost, path: "/v1/admin/announcements/" + announcementID + "/publish", body: `{"version":1,"version":2,"expected_revision":1}`, ifMatch: true},
		{name: "revise", method: http.MethodPost, path: "/v1/admin/announcements/" + announcementID + "/revise", body: `{"expected_head_version":1,"title":"one","title":"two","body":"body","all":true,"user_ids":[],"group_ids":[],"withdrawal_visibility":"retain"}`, ifMatch: true},
		{name: "withdraw", method: http.MethodPost, path: "/v1/admin/announcements/" + announcementID + "/withdraw", body: `{"version":1,"version":2,"expected_revision":1}`, ifMatch: true},
		{name: "delivered", method: http.MethodPost, path: "/v1/account/messages/" + eventID + "/delivered", body: `{"expected_revision":1,"expected_revision":2}`, ifMatch: true},
		{name: "read", method: http.MethodPost, path: "/v1/account/messages/" + eventID + "/read", body: `{"expected_revision":1,"expected_revision":2}`, ifMatch: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "ambiguous-json")
			request.Header.Set("X-Request-ID", "req-ambiguous-json")
			if test.ifMatch {
				request.Header.Set("If-Match", `"1"`)
			}
			response := httptest.NewRecorder()
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("ambiguous request reached the store: %v", recovered)
				}
			}()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestDecodeRequiresApplicationJSON(t *testing.T) {
	handler := &Handler{maxBodyBytes: 1 << 20}
	for _, contentType := range []string{
		"", "text/plain", "application/json, text/plain", "application/json; charset",
		"application/json; charset=utf-8; broken",
	} {
		t.Run(contentType, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"expected_revision":1}`))
			if contentType != "" {
				request.Header.Set("Content-Type", contentType)
			}
			response := httptest.NewRecorder()
			var body stateRequest
			if handler.decode(response, request, &body) || response.Code != http.StatusUnsupportedMediaType ||
				!strings.Contains(response.Body.String(), `"code":"unsupported_media_type"`) {
				t.Fatalf("content type %q response = %d %s", contentType, response.Code, response.Body.String())
			}
		})
	}
	t.Run("two header fields", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"expected_revision":1}`))
		request.Header.Add("Content-Type", "application/json")
		request.Header.Add("Content-Type", "application/json; charset=utf-8")
		response := httptest.NewRecorder()
		var body stateRequest
		if handler.decode(response, request, &body) || response.Code != http.StatusUnsupportedMediaType ||
			!strings.Contains(response.Body.String(), `"code":"unsupported_media_type"`) {
			t.Fatalf("duplicate Content-Type response = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("canonical with charset", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"expected_revision":1}`))
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
		response := httptest.NewRecorder()
		var body stateRequest
		if !handler.decode(response, request, &body) || body.ExpectedRevision != 1 {
			t.Fatalf("canonical content type response = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestDecodePreservesBodySizeAndTrailingValueRejection(t *testing.T) {
	t.Run("body size", func(t *testing.T) {
		handler := &Handler{maxBodyBytes: 32}
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
			`{"expected_revision":1,"padding":"012345678901234567890123456789"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var body map[string]any
		if handler.decode(response, request, &body) || response.Code != http.StatusBadRequest ||
			!strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
			t.Fatalf("oversized body response = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("trailing value", func(t *testing.T) {
		handler := &Handler{maxBodyBytes: 1 << 20}
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
			`{"expected_revision":1} {"expected_revision":2}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var body stateRequest
		if handler.decode(response, request, &body) || response.Code != http.StatusBadRequest ||
			!strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
			t.Fatalf("trailing value response = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestWriteJSONFailuresUseStableErrorSchema(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{name: "marshal failure", value: make(chan int)},
		{name: "newline exceeds byte cap", value: strings.Repeat("x", maxResponseBytes-2)},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("X-Request-ID", "req-write-json")
			response := httptest.NewRecorder()
			writeJSON(response, request, http.StatusOK, test.value)
			if response.Code != http.StatusInternalServerError || response.Body.Len() > maxResponseBytes {
				t.Fatalf("response status=%d bytes=%d", response.Code, response.Body.Len())
			}
			var envelope struct {
				Error struct {
					Code      string `json:"code"`
					Message   string `json:"message"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error.Code != "internal_error" || envelope.Error.Message == "" || envelope.Error.RequestID != "req-write-json" {
				t.Fatalf("error envelope = %+v", envelope.Error)
			}
		})
	}
}

var _ = announcement.DefaultPageSize
