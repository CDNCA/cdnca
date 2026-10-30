package observabilityloghttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/observabilitylog"
	"github.com/google/uuid"
)

// approval-center3：kind=backup 经真实 Service 返回 400 observability_logs_invalid_request。
func TestObservabilityLogsBackupKindIsBadRequest(t *testing.T) {
	service, err := observabilitylog.NewService(&pageLimitRepository{pages: [][]observabilitylog.Fact{{}}}, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	scopeID := uuid.New()
	handler := handler09(t, service, tenantSession09(scopeID, uuid.New(), uuid.New()))
	for _, kind := range []string{"backup", "operation,backup"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request09(http.MethodGet, "/v1/observability/logs?kind="+kind, ""))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "observability_logs_invalid_request") {
			t.Fatalf("kind=%s code=%d body=%s", kind, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request09(http.MethodGet, "/v1/observability/logs?kind=operation", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("kind=operation code=%d body=%s", response.Code, response.Body.String())
	}
}
