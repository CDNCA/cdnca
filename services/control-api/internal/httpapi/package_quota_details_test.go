package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
)

// 409 package_resource_quota_exceeded 在 details 写明
// resource/limit/used/requested；未写明资源的拒绝保持原样（不带 details）。
func TestPackageQuotaExceededCarriesResourceDetails(t *testing.T) {
	server := &Server{}
	for name, check := range map[string]struct {
		err  error
		want string
	}{
		"domains": {fmt.Errorf("update: %w", &packageaddon.QuotaExceededError{Resource: packageaddon.QuotaResourceDomains, Limit: 1, Used: 1, Requested: 1}),
			`{"resource":"domains","limit":1,"used":1,"requested":1}`},
		"root_domains": {&packageaddon.QuotaExceededError{Resource: packageaddon.QuotaResourceRootDomains, Limit: 2, Used: 2, Requested: 1},
			`{"resource":"root_domains","limit":2,"used":2,"requested":1}`},
		"sites": {&packageaddon.QuotaExceededError{Resource: packageaddon.QuotaResourceSites, Limit: 3, Used: 3, Requested: 1},
			`{"resource":"sites","limit":3,"used":3,"requested":1}`},
		"stream_ports": {&packageaddon.QuotaExceededError{Resource: packageaddon.QuotaResourceStreamPorts, Limit: 10, Used: 8, Requested: 5},
			`{"resource":"stream_ports","limit":10,"used":8,"requested":5}`},
		"unnamed": {packageaddon.ErrQuotaExceeded, ``},
	} {
		recorder := httptest.NewRecorder()
		server.writeError(recorder, httptest.NewRequest(http.MethodPatch, "/v1/sites/x", nil), check.err)
		var body struct {
			Error struct {
				Code      string          `json:"code"`
				Message   string          `json:"message"`
				RequestID *string         `json:"request_id"`
				Details   json.RawMessage `json:"details"`
			} `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusConflict || body.Error.Code != "package_resource_quota_exceeded" ||
			string(body.Error.Details) != check.want || body.Error.Message == "" || body.Error.RequestID == nil {
			t.Fatalf("%s: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
}
