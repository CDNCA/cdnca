package originauthcontrol

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestHandlerRejectsUnknownAndDuplicateFields(t *testing.T) {
	handler := &Handler{maxRequestBytes: defaultMaxRequestBytes, maxResponseBytes: defaultMaxResponseBytes}
	for name, body := range map[string]string{
		"unknown":   `{"provider":"s3","extra":"secret"}`,
		"duplicate": `{"provider":"s3","provider":"oss"}`,
		"trailing":  `{"provider":"s3"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/", strings.NewReader(body))
			response := httptest.NewRecorder()
			var destination struct {
				Provider string `json:"provider"`
			}
			if err := handler.decodeBody(response, request, &destination); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("decodeBody() error = %v", err)
			}
		})
	}
}

func TestHandlerErrorNeverReflectsInternalDetails(t *testing.T) {
	handler := &Handler{maxResponseBytes: defaultMaxResponseBytes}
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-Request-ID", "request-1")
	request.Header.Set("X-Trace-ID", "trace-1")
	response := httptest.NewRecorder()
	handler.writeError(response, request, errors.New("AKIA-DO-NOT-LEAK ciphertext endpoint /private/object"))
	body := response.Body.String()
	for _, forbidden := range []string{"AKIA", "ciphertext", "/private/object"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("error response leaked %q: %s", forbidden, body)
		}
	}
	if response.Code != 503 || !strings.Contains(body, `"code":"service_unavailable"`) {
		t.Fatalf("response = %d %s", response.Code, body)
	}
}

func TestHandlerPreservesAuthenticationErrorClassification(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "invalid credential", err: ErrUnauthenticated, wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		{name: "dependency unavailable", err: ErrUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := &Handler{
				authenticator: AuthenticatorFunc(func(*http.Request) (Actor, error) {
					return Actor{}, test.err
				}),
				maxResponseBytes: defaultMaxResponseBytes,
			}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if _, _, ok := handler.authorize(response, request); ok {
				t.Fatal("authorize() succeeded, want rejection")
			}
			var envelope errorEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.wantStatus || envelope.Error.Code != test.wantCode {
				t.Fatalf("authorize() response = %d %q, want %d %q", response.Code, envelope.Error.Code, test.wantStatus, test.wantCode)
			}
		})
	}
}

func TestHandlerMethodNotAllowedMatrix(t *testing.T) {
	dependencies := runtimeTestDependencies(t)
	tenantID := uuid.MustParse("018f9d7e-4a1b-7a2c-8d3e-111111111111")
	resourceID := "018f9d7e-4a1b-7a2c-8d3e-222222222222"
	actor := Actor{
		UserID:  uuid.MustParse("018f9d7e-4a1b-7a2c-8d3e-333333333333"),
		ScopeID: tenantID, ScopeKind: "tenant", tenantID: &tenantID,
		Permissions: []string{PermissionRead, PermissionManage},
	}
	handler, err := NewHandler(&Service{pool: dependencies.Pool}, AuthenticatorFunc(func(*http.Request) (Actor, error) {
		return actor, nil
	}), HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/tenant-scopes/" + tenantID.String() + "/origin-auth"
	for _, test := range []struct {
		operationID string
		method      string
		path        string
		allow       string
	}{
		{"listOriginAuthCredentials", http.MethodPatch, base + "/credentials", "GET, POST"},
		{"createOriginAuthCredential", http.MethodPatch, base + "/credentials", "GET, POST"},
		{"getOriginAuthCredential", http.MethodPost, base + "/credentials/" + resourceID, "DELETE, GET"},
		{"deleteOriginAuthCredential", http.MethodPost, base + "/credentials/" + resourceID, "DELETE, GET"},
		{"replaceOriginAuthCredential", http.MethodGet, base + "/credentials/" + resourceID + "/replace", "POST"},
		{"verifyOriginAuthCredential", http.MethodGet, base + "/credentials/" + resourceID + "/verify", "POST"},
		{"disableOriginAuthCredential", http.MethodGet, base + "/credentials/" + resourceID + "/disable", "POST"},
		{"listOriginAuthRules", http.MethodPut, base + "/rules", "GET, POST"},
		{"createOriginAuthRule", http.MethodPut, base + "/rules", "GET, POST"},
		{"getOriginAuthRule", http.MethodPost, base + "/rules/" + resourceID, "DELETE, GET, PATCH"},
		{"updateOriginAuthRule", http.MethodPost, base + "/rules/" + resourceID, "DELETE, GET, PATCH"},
		{"deleteOriginAuthRule", http.MethodPost, base + "/rules/" + resourceID, "DELETE, GET, PATCH"},
		{"enableOriginAuthRule", http.MethodGet, base + "/rules/" + resourceID + "/enable", "POST"},
		{"disableOriginAuthRule", http.MethodGet, base + "/rules/" + resourceID + "/disable", "POST"},
		{"rotateOriginAuthRuleCredential", http.MethodGet, base + "/rules/" + resourceID + "/rotate", "POST"},
		{"getLatestOriginAuthPublication", http.MethodDelete, base + "/publications", "GET, POST"},
		{"createOriginAuthPublication", http.MethodDelete, base + "/publications", "GET, POST"},
	} {
		t.Run(test.operationID, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != test.allow {
				t.Fatalf("response = %d Allow=%q body=%s", response.Code, response.Header().Get("Allow"), response.Body)
			}
			var envelope errorEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error.Code != "method_not_allowed" || envelope.Error.RequestID == "" || envelope.Error.TraceID == "" {
				t.Fatalf("error envelope = %+v", envelope)
			}
		})
	}
}
