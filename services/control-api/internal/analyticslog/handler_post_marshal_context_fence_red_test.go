package analyticslog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type cancelDuringMarshalValue struct {
	cancel context.CancelFunc
}

func (value cancelDuringMarshalValue) MarshalJSON() ([]byte, error) {
	value.cancel()
	return []byte(`{"data":["valid"]}`), nil
}

func TestWriteResultRejectsContextFailureAfterMarshal(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	handler := newWriteResultTestHandler(maximumHandlerResponse)

	handler.writeResult(response, request, cancelDuringMarshalValue{cancel: cancel})

	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusGatewayTimeout, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"code":"analytics_logs_query_timeout"`) {
		t.Fatalf("body = %s, want stable timeout error", body)
	}
	if strings.Contains(body, `"data"`) || strings.Contains(body, "valid") {
		t.Fatalf("body leaked success payload: %s", body)
	}
}
