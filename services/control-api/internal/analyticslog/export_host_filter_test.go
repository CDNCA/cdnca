package analyticslog

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// LOG-02：导出 body 与列表 GET 用同一 host 条件（规范化为小写，多域名空格分隔），
// 冻结进导出 filter；非法 host 拒绝。
func TestDecodeExportCreateAcceptsHost(t *testing.T) {
	decode := func(host string) (Filter, error) {
		body := `{"filter":{"from":"2026-10-28T00:00:00Z","to":"2026-10-28T01:00:00Z","host":` + host + `}}`
		request := httptest.NewRequest(http.MethodPost, "/v1/analytics/logs/access/exports", strings.NewReader(body))
		return decodeExportCreate(request)
	}
	filter, err := decode(`"A.Example.test b.example.test"`)
	if err != nil || filter.Host != "a.example.test b.example.test" {
		t.Fatalf("host filter = %q, %v", filter.Host, err)
	}
	if _, err := decode(`"bad host\n"`); err == nil {
		t.Fatal("invalid host accepted")
	}
}
