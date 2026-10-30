package nodeschedulerhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// 卡 52：排序契约最小为 1。显式 0 不再被静默改成 100，而是返回明确错误码；
// 省略字段仍按契约默认 100。
func TestLineGroupWriteRejectsExplicitZeroSortOrder(t *testing.T) {
	endpoint := func(sort string) string {
		return `{"id":"` + uuid.NewString() + `","node_id":"` + uuid.NewString() + `","address":"192.0.2.10","port":443,"region":"","carrier":"","priority":0` + sort + `,"weight":10,"enabled":true}`
	}
	policy := `"health_policy":{"probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0}`
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "endpoint zero", body: `{"name":"线路",` + policy + `,"endpoints":[` + endpoint(`,"sort_order":0`) + `]}`, wantStatus: http.StatusBadRequest, wantCode: "node_scheduling_invalid_sort_order"},
		{name: "group zero", body: `{"name":"线路","sort_order":0,` + policy + `,"endpoints":[]}`, wantStatus: http.StatusBadRequest, wantCode: "node_scheduling_invalid_sort_order"},
		{name: "endpoint one", body: `{"name":"线路",` + policy + `,"endpoints":[` + endpoint(`,"sort_order":1`) + `]}`, wantStatus: http.StatusCreated},
		{name: "omitted", body: `{"name":"线路",` + policy + `,"endpoints":[` + endpoint(``) + `]}`, wantStatus: http.StatusCreated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{group: nodescheduler.LineGroupRevision{GroupID: uuid.New(), Revision: 1}}
			handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", `"0"`)
			request.Header.Set("Idempotency-Key", "sort-order-key")
			request.Header.Set("X-Request-ID", "sort-order-request")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if test.wantCode != "" {
				assertErrorCode(t, response, test.wantStatus, test.wantCode)
				if service.putRequest.IdempotencyKey != "" {
					t.Fatal("zero sort order reached the service")
				}
				return
			}
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
