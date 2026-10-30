package analyticslog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// LOG-02：申请记录带回服务端冻结的原查询条件（与创建请求同一字段契约），
// 前端据此展示"原查询摘要"，而不是用当前页面条件冒充。
func TestExportFilterSummaryRoundTripsCreateBody(t *testing.T) {
	body := `{"filter":{"from":"2026-10-28T00:00:00Z","to":"2026-10-28T01:00:00Z","host":"a.example.test b.example.test",` +
		`"client_ip":"203.0.113.7","uri_path":"/a","uri_path_match":"prefix","status_code":404,"ja4":"t13d1516h2_8daaf6152771_02713d6af862",` +
		`"request_bytes_min":10}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/analytics/logs/access/exports", strings.NewReader(body))
	filter, err := decodeExportCreate(request)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(struct {
		Version  int    `json:"version"`
		TenantID string `json:"tenant_id"`
		Filter   Filter `json:"filter"`
	}{Version: 1, TenantID: "t", Filter: normalizeFilter(filter)})
	if err != nil {
		t.Fatal(err)
	}
	summary, ok := exportFilterSummary(stored)
	if !ok {
		t.Fatal("stored filter not decoded")
	}
	encoded, _ := json.Marshal(summary)
	want := `{"from":"2026-10-28T00:00:00Z","to":"2026-10-28T01:00:00Z","host":"a.example.test b.example.test",` +
		`"client_ip":"203.0.113.7","uri_path":"/a","uri_path_match":"prefix","status_code":404,` +
		`"request_bytes_min":10,"ja4":"t13d1516h2_8daaf6152771_02713d6af862"}`
	if string(encoded) != want {
		t.Fatalf("summary = %s\nwant      %s", encoded, want)
	}
}

func TestExportFilterSummaryRejectsUnknownDocument(t *testing.T) {
	for _, stored := range []string{`{}`, `{"version":2,"filter":{}}`, `not json`} {
		if _, ok := exportFilterSummary([]byte(stored)); ok {
			t.Fatalf("accepted %s", stored)
		}
	}
	exact := Filter{From: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC), URIPath: "/a"}
	stored, _ := json.Marshal(map[string]any{"version": 1, "tenant_id": "t", "filter": exact})
	summary, ok := exportFilterSummary(stored)
	if !ok || summary.URIPathMatch != "" || summary.StatusCode != nil {
		t.Fatalf("exact path summary = %+v %v", summary, ok)
	}
}
