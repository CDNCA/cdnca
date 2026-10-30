package analyticslog

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWriteResultRejectsPostServiceContextFailure(t *testing.T) {
	value := map[string]any{"data": []string{"valid"}}
	cases := []struct {
		name      string
		request   *http.Request
		wantCode  int
		wantError string
	}{
		{
			name: "canceled",
			request: func() *http.Request {
				request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil)
				ctx, cancel := context.WithCancel(request.Context())
				cancel()
				return request.WithContext(ctx)
			}(),
			wantCode:  http.StatusGatewayTimeout,
			wantError: `"code":"analytics_logs_query_timeout"`,
		},
		{
			name: "deadline exceeded",
			request: func() *http.Request {
				request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil)
				ctx, cancel := context.WithDeadline(request.Context(), time.Now().Add(-time.Second))
				cancel()
				return request.WithContext(ctx)
			}(),
			wantCode:  http.StatusGatewayTimeout,
			wantError: `"code":"analytics_logs_query_timeout"`,
		},
		{
			name:     "active request",
			request:  httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil),
			wantCode: http.StatusOK,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := newWriteResultTestHandler(maximumHandlerResponse)
			response := httptest.NewRecorder()
			handler.writeResult(response, testCase.request, value)

			if response.Code != testCase.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, testCase.wantCode, response.Body.String())
			}
			body := response.Body.String()
			if testCase.wantError != "" {
				if !strings.Contains(body, testCase.wantError) {
					t.Fatalf("body = %s, want stable timeout error", body)
				}
				if strings.Contains(body, `"data"`) || strings.Contains(body, "valid") {
					t.Fatalf("body leaked success payload: %s", body)
				}
			} else if !strings.Contains(body, `"data"`) || !strings.Contains(body, "valid") {
				t.Fatalf("active body = %s, want success payload", body)
			}
		})
	}
}

func TestWriteResultPreservesResponseCapacityFence(t *testing.T) {
	handler := newWriteResultTestHandler(512)
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil)
	response := httptest.NewRecorder()
	handler.writeResult(response, request, map[string]string{"data": strings.Repeat("x", 512)})

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"analytics_logs_storage_unavailable"`) ||
		strings.Contains(response.Body.String(), strings.Repeat("x", 32)) {
		t.Fatalf("capacity response = %s, want stable error without payload", response.Body.String())
	}
}

func newWriteResultTestHandler(maxResponseBytes int) *Handler {
	return &Handler{
		maxResponseBytes: maxResponseBytes,
		logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}
