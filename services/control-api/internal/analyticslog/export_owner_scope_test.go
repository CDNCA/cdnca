package analyticslog

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// LOG-01：同一账号 + 同一查询范围只保留一份有效申请。最新一代仍在处理或产物
// 未过期就复用；失败且统一任务还能重试就在原申请上重试（同一编号）；产物已
// 过期或重试用尽才建新一代。
func TestExportScopeDecision(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	live, expired := now.Add(time.Minute), now.Add(-time.Second)
	for _, test := range []struct {
		name   string
		latest *exportScopeLatest
		want   exportScopeAction
	}{
		{"none", nil, exportScopeCreate},
		{"pending", &exportScopeLatest{Status: ExportPending}, exportScopeReuse},
		{"running", &exportScopeLatest{Status: ExportRunning}, exportScopeReuse},
		{"completed live", &exportScopeLatest{Status: ExportCompleted, ArtifactExpiresAt: &live}, exportScopeReuse},
		{"completed expired", &exportScopeLatest{Status: ExportCompleted, ArtifactExpiresAt: &expired}, exportScopeCreate},
		{"completed cleaned", &exportScopeLatest{Status: ExportCompleted}, exportScopeCreate},
		{"failed retryable", &exportScopeLatest{Status: ExportFailed, JobState: "failed", Attempt: 1, MaxAttempts: 10}, exportScopeRetry},
		{"failed exhausted", &exportScopeLatest{Status: ExportFailed, JobState: "failed", Attempt: 10, MaxAttempts: 10}, exportScopeCreate},
		{"failed job not failed", &exportScopeLatest{Status: ExportFailed, JobState: "running", Attempt: 1, MaxAttempts: 10}, exportScopeCreate},
	} {
		if got := decideExportScope(test.latest, now); got != test.want {
			t.Errorf("%s: decideExportScope() = %v, want %v", test.name, got, test.want)
		}
	}
}

// 日志视图按当前查询条件找回申请：GET 查询串与 POST body 规范化后必须得到同
// 一个范围摘要，否则重新登录后对不上原申请。
func TestExportScopeDigestSameForListQueryAndCreateBody(t *testing.T) {
	body := `{"filter":{"from":"2026-10-28T00:00:00Z","to":"2026-10-28T01:00:00Z","host":"A.Example.test",` +
		`"uri_path":"/api","uri_path_match":"prefix","status_code":404,"method":"GET","content_type":"text/html"}}`
	create := httptest.NewRequest(http.MethodPost, "/v1/analytics/logs/access/exports", strings.NewReader(body))
	createFilter, err := decodeExportCreate(create)
	if err != nil {
		t.Fatal(err)
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/exports?from=2026-10-28T00:00:00Z&to=2026-10-28T01:00:00Z"+
		"&host=a.example.test&uri_path=/api&uri_path_match=prefix&status_code=404&method=GET&content_type=text/html", nil)
	tenantID, listFilter, scoped, err := parseExportListScope(list, AudienceTenant)
	if err != nil || !scoped || tenantID != "" {
		t.Fatalf("parseExportListScope() = (%q, %v, %v)", tenantID, scoped, err)
	}
	tenant := "018f0000-0000-7000-8000-000000000010"
	createDigest, err := exportScopeDigest(tenant, createFilter)
	if err != nil {
		t.Fatal(err)
	}
	listDigest, err := exportScopeDigest(tenant, normalizeFilter(listFilter))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(createDigest.digest[:], listDigest.digest[:]) {
		t.Fatalf("list digest %x != create digest %x", listDigest.digest, createDigest.digest)
	}
	other, _ := exportScopeDigest("018f0000-0000-7000-8000-000000000011", createFilter)
	if bytes.Equal(other.digest[:], createDigest.digest[:]) {
		t.Fatal("different tenants share a scope digest")
	}
}

func TestParseExportListScope(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/exports", nil)
	if _, _, scoped, err := parseExportListScope(plain, AudienceTenant); err != nil || scoped {
		t.Fatalf("plain list = (%v, %v), want unscoped", scoped, err)
	}
	for _, raw := range []string{
		"limit=1&from=2026-10-28T00:00:00Z&to=2026-10-28T01:00:00Z",
		"cursor=x&from=2026-10-28T00:00:00Z&to=2026-10-28T01:00:00Z",
		"from=2026-10-28T00:00:00Z",
		"tenant_id=018f0000-0000-7000-8000-000000000010&from=2026-10-28T00:00:00Z&to=2026-10-28T01:00:00Z",
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access/exports?"+raw, nil)
		if _, _, _, err := parseExportListScope(request, AudienceTenant); err == nil {
			t.Errorf("parseExportListScope(%q) accepted", raw)
		}
	}
	admin := httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/logs/access/exports?tenant_id=018f0000-0000-7000-8000-000000000010"+
		"&from=2026-10-28T00:00:00Z&to=2026-10-28T01:00:00Z", nil)
	if tenant, _, scoped, err := parseExportListScope(admin, AudiencePlatform); err != nil || !scoped ||
		tenant != "018f0000-0000-7000-8000-000000000010" {
		t.Fatalf("admin scoped list = (%q, %v, %v)", tenant, scoped, err)
	}
}
