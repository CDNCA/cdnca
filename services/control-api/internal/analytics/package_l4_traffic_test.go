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

const (
	testL4TenantID       = "10000000-0000-4000-8000-0000000000aa"
	testL4SubscriptionID = "20000000-0000-4000-8000-0000000000b1"
)

// 四层字节按事实上记的套餐（发生时刻）归属，按 tenants.id + package_subscription_id 查
// l4_session_facts_v1，不再按套餐当前的转发列表查。
func TestPackageL4TrafficSumsTheFactsAttributedToTheSubscription(t *testing.T) {
	from := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		body, _ := io.ReadAll(request.Body)
		for _, token := range []string{"l4_session_facts_v1 FINAL", "sum(up + down)", "l4_usage_checkpoints_v1 FINAL", "package_subscription_id={subscription_id:UUID}",
			"tenant_id={l4_tenant_id:UUID}", "finalized_at>={from:DateTime64(3,'UTC')}", "finalized_at<{to:DateTime64(3,'UTC')}"} {
			if !strings.Contains(string(body), token) {
				t.Errorf("query missing %q", token)
			}
		}
		if strings.Contains(string(body), "stream_id") {
			t.Errorf("query still filters by the subscription's current forwards")
		}
		parameters := request.URL.Query()
		if parameters.Get("param_l4_tenant_id") != testL4TenantID || parameters.Get("param_subscription_id") != testL4SubscriptionID ||
			parameters.Get("param_from") != clickHouseTime(from) || parameters.Get("param_to") != clickHouseTime(to) {
			t.Errorf("parameters=%v", parameters)
		}
		_, _ = io.WriteString(writer, "{\"traffic_bytes\":4096}\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	value, err := client.PackageL4Traffic(context.Background(), testL4TenantID, testL4SubscriptionID, from, to)
	if err != nil || value != 4096 || calls != 1 {
		t.Fatalf("value=%d err=%v calls=%d", value, err, calls)
	}
	// 作用域不是租户（无 tenants.id）：不查 ClickHouse，四层为 0。
	if value, err := client.PackageL4Traffic(context.Background(), "", testL4SubscriptionID, from, to); err != nil || value != 0 || calls != 1 {
		t.Fatalf("no tenant value=%d err=%v calls=%d", value, err, calls)
	}
	for name, bad := range map[string][2]string{
		"tenant":           {"bad", testL4SubscriptionID},
		"nil tenant":       {nilUUIDString, testL4SubscriptionID},
		"subscription":     {testL4TenantID, "x'); DROP TABLE t; --"},
		"nil subscription": {testL4TenantID, nilUUIDString},
	} {
		if _, err := client.PackageL4Traffic(context.Background(), bad[0], bad[1], from, to); err != ErrInvalidInput {
			t.Errorf("%s err=%v", name, err)
		}
	}
}

// 套餐用量合计 = 七层 + 四层，分项原样返回；按网站筛选时四层子查询被 has_site 关掉。
func TestPackageUsageAddsL4TrafficToTheTotal(t *testing.T) {
	from := time.Date(2026, 8, 1, 16, 0, 0, 0, time.UTC)
	to := from.Add(48 * time.Hour)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		body, _ := io.ReadAll(request.Body)
		if request.URL.Query().Get("param_l4_tenant_id") != testL4TenantID {
			t.Errorf("l4 tenant=%q", request.URL.Query().Get("param_l4_tenant_id"))
		}
		switch calls {
		case 1:
			_, _ = io.WriteString(writer, "{\"access_snapshot_ms\":1785600000000,\"connection_snapshot_ms\":1785600001000}\n")
		case 2:
			if !strings.Contains(string(body), "l4_session_facts_v1 FINAL") ||
				!strings.Contains(string(body), "{has_site:UInt8}=0 AND tenant_id={l4_tenant_id:UUID} AND package_subscription_id={subscription_id:UUID}") {
				t.Errorf("summary query has no L4 facts")
			}
			_, _ = io.WriteString(writer, "{\"traffic_bytes\":1000,\"l4_traffic_bytes\":500,\"peak_bandwidth_bps\":0,\"bandwidth_95th_bps\":0,\"connections\":0,\"source_watermark\":0,\"finalized_through_ms\":1785772800000}\n")
		case 3:
			if !strings.Contains(string(body), "l4_session_facts_v1 FINAL") || !strings.Contains(string(body), "LEFT JOIN l4 ON l4.bucket=buckets.bucket") {
				t.Errorf("series query has no L4 facts")
			}
			_, _ = io.WriteString(writer, "{\"bucket_ms\":1785600000000,\"traffic_bytes\":0,\"l4_traffic_bytes\":500,\"bandwidth_bps\":0,\"connections\":0}\n")
		}
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	result, err := client.PackageUsage(context.Background(), PackageUsageRequest{
		TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, From: from, To: to,
		Timezone: "Asia/Shanghai", Bucket: PackageUsageBucketHour, Limit: 24,
		L4TenantID: testL4TenantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TrafficBytes != 1500 || result.HTTPTrafficBytes != 1000 || result.L4TrafficBytes != 500 || len(result.Series) != 1 ||
		result.Series[0].TrafficBytes != 500 || result.Series[0].HTTPTrafficBytes != 0 || result.Series[0].L4TrafficBytes != 500 {
		t.Fatalf("result=%+v", result)
	}
}

func TestAddTrafficRejectsOverflow(t *testing.T) {
	if _, ok := addTraffic(^uint64(0), 1); ok {
		t.Fatal("overflow accepted")
	}
	if total, ok := addTraffic(2, 3); !ok || total != 5 {
		t.Fatalf("total=%d ok=%v", total, ok)
	}
}
