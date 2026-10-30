package analytics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fix-usagereport：monthly_traffic_bytes = 全部套餐订阅的七层（请求+响应字节，FX60 拉黑页开关）+ 四层（上+下行，
// 只计已归属套餐的会话），与套餐流量同口径，不按租户/订阅过滤。
func TestInstallationTrafficBytesUsesThePackageTrafficBasis(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		for _, token := range []string{"package_metric_access_facts_v1 FINAL", "toUInt128(request_bytes)+toUInt128(response_bytes)",
			"NOT ({exclude_blocked:UInt8}=1 AND blocked)", "l4_session_facts_v1 FINAL", "toUInt128(up)+toUInt128(down)", "l4_usage_checkpoints_v1 FINAL",
			"package_subscription_id!=toUUID('00000000-0000-0000-0000-000000000000')", "toUInt128(9007199254740991)"} {
			if !strings.Contains(string(body), token) {
				t.Errorf("query missing %q", token)
			}
		}
		if strings.Contains(string(body), "tenant_id=") {
			t.Error("installation traffic must not filter by tenant")
		}
		parameters := request.URL.Query()
		if parameters.Get("param_from") != clickHouseTime(from) || parameters.Get("param_to") != clickHouseTime(to) ||
			parameters.Get("param_exclude_blocked") != "1" {
			t.Errorf("parameters=%v", parameters)
		}
		_, _ = io.WriteString(writer, "{\"traffic_bytes\":987654321}\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	value, err := client.InstallationTrafficBytes(context.Background(), from, to, true)
	if err != nil || value != 987654321 {
		t.Fatalf("value=%d err=%v", value, err)
	}
	if _, err := client.InstallationTrafficBytes(context.Background(), to, from, false); err != ErrInvalidInput {
		t.Fatalf("reversed err=%v", err)
	}
	if _, err := client.InstallationTrafficBytes(context.Background(), from.Add(-500*24*time.Hour), to, false); err != ErrInvalidInput {
		t.Fatalf("beyond retention err=%v", err)
	}
}
