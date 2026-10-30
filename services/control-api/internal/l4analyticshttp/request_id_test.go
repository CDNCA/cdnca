package l4analyticshttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestRequestIDUsesMiddlewareHeaderOrSafeStandaloneFallback(t *testing.T) {
	handler, err := NewHandler(&readerStub{}, func(*http.Request) (identity.Principal, error) {
		t.Fatal("invalid method must not authenticate")
		return identity.Principal{}, nil
	}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, responseID, wantID string
		headers                  []string
		nilRequest               bool
	}{
		{name: "middleware ID wins", responseID: "middleware.request-1", headers: []string{"client-request"}, wantID: "middleware.request-1"},
		{name: "single client ID", headers: []string{"client_request-2.3"}, wantID: "client_request-2.3"},
		{name: "trim client ID", headers: []string{" client-request "}, wantID: "client-request"},
		{name: "maximum length", headers: []string{strings.Repeat("x", 128)}, wantID: strings.Repeat("x", 128)},
		{name: "invalid response fallback", responseID: "bad/id", headers: []string{"client-request"}, wantID: "client-request"},
		{name: "malformed client ID", headers: []string{"bad/id"}},
		{name: "too long", headers: []string{strings.Repeat("x", 129)}},
		{name: "duplicate client IDs", headers: []string{"client-1", "client-2"}},
		{name: "missing client ID"},
		{name: "nil request", nilRequest: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/analytics/l4-realtime", nil)
			for _, value := range test.headers {
				request.Header.Add("X-Request-ID", value)
			}
			if test.nilRequest {
				request = nil
			}
			response := httptest.NewRecorder()
			response.Header().Set("X-Request-ID", test.responseID)
			handler.ServeHTTP(response, request)
			id := response.Header().Get("X-Request-ID")
			if test.wantID != "" {
				if id != test.wantID {
					t.Fatalf("request ID=%q want=%q", id, test.wantID)
				}
			} else if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil {
				t.Fatalf("generated request ID=%q error=%v", id, err)
			}
			var body struct {
				Error struct {
					Code      string `json:"code"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusBadRequest ||
				body.Error.Code != "l4_analytics_invalid_request" || body.Error.RequestID != id {
				t.Fatalf("status=%d body=%s error=%v", response.Code, response.Body.String(), err)
			}
		})
	}
}
