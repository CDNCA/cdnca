package analytics

import (
	"net/http"
	"testing"
	"time"
)

type l4SessionFactRow struct {
	TenantID              string    `json:"tenant_id"`
	StreamID              string    `json:"stream_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	EventID               string    `json:"event_id"`
	FinalizedAt           time.Time `json:"finalized_at"`
	BytesUp               uint64    `json:"bytes_up"`
	BytesDown             uint64    `json:"bytes_down"`
	SourceWatermark       uint64    `json:"source_watermark"`
}

// TestPackageUsageL4TrafficClickHouseIntegration（待出包前全量跑）：真 ClickHouse
// 全量迁移（含 027 package_subscription_id 列）下，套餐用量 = 七层
// （package_metric_access_facts_v1，由 access_events MV 生成）+ 四层
// （l4_session_facts_v1 上记为本套餐的事实），分项与合计一致；按网站筛选不含四层；
// 别的套餐/别的租户/重复事件不计入。七层与四层事实都按 tenants.id 落库（pkg-tenantid
// 口径），七层读取经 TenantResolver 把作用域换算成 tenants.id。转发换套餐后，
// 换之前的会话仍记在旧套餐，换之后的记在新套餐。
func TestPackageUsageL4TrafficClickHouseIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)

	const (
		scopeID        = "10000000-0000-4000-8000-0000000004a1"
		tenantID       = "10000000-0000-4000-8000-0000000004a2" // tenants.id，七层/四层事实都携带
		otherTenantID  = "10000000-0000-4000-8000-0000000004a3"
		onlyL4ScopeID  = "10000000-0000-4000-8000-0000000004ff" // 另一作用域：本时段无七层事实
		onlyL4TenantID = "10000000-0000-4000-8000-0000000004fe"
		subscriptionID = "20000000-0000-4000-8000-0000000004a1"
		otherPackage   = "20000000-0000-4000-8000-0000000004a2"
		siteID         = "30000000-0000-4000-8000-0000000004a1"
		nodeID         = "40000000-0000-4000-8000-0000000004a1"
		streamA        = "50000000-0000-4000-8000-0000000004a1"
		streamB        = "50000000-0000-4000-8000-0000000004a2"
		streamOther    = "50000000-0000-4000-8000-0000000004a3"
	)
	from := time.Now().UTC().Truncate(time.Hour).Add(-4 * time.Hour)
	to := from.Add(2 * time.Hour)
	access := func(id string, at time.Time, request, response uint64) spreadAccessRow {
		return spreadAccessRow{
			MetricVersion: 1, EventID: id, OccurredAt: at, IngestedAt: at.Add(time.Second), TenantID: tenantID,
			PackageSubscriptionID: subscriptionID, SiteID: siteID, NodeID: nodeID, Host: "l4mix.example.test",
			Path: "/", ClientIP: "192.0.2.10", Method: "GET", Protocol: "HTTP/1.1", CacheStatus: "MISS",
			StatusCode: 200, RequestBytes: request, ResponseBytes: response,
		}
	}
	insertRankRows(t, database, `INSERT INTO access_events
		(metric_version,event_id,occurred_at,ingested_at,tenant_id,package_subscription_id,site_id,node_id,
		 host,path,client_ip,method,protocol,cache_status,status_code,request_bytes,response_bytes,duration_us)
		FORMAT JSONEachRow`, []spreadAccessRow{
		access("h1", from.Add(10*time.Minute), 100, 900),    // 第一小时 1000
		access("h2", from.Add(70*time.Minute), 200, 1800),   // 第二小时 2000
		access("h-out", to.Add(10*time.Minute), 5000, 5000), // 范围外
	})
	l4 := func(tenant, stream, subscription, id string, at time.Time, up, down, watermark uint64) l4SessionFactRow {
		return l4SessionFactRow{TenantID: tenant, StreamID: stream, PackageSubscriptionID: subscription, EventID: id,
			FinalizedAt: at, BytesUp: up, BytesDown: down, SourceWatermark: watermark}
	}
	insertRankRows(t, database, `INSERT INTO l4_session_facts_v1
		(tenant_id,stream_id,package_subscription_id,event_id,finalized_at,bytes_up,bytes_down,source_watermark) FORMAT JSONEachRow`, []l4SessionFactRow{
		l4(tenantID, streamA, subscriptionID, "s1", from.Add(20*time.Minute), 30, 70, 1),          // 第一小时 100
		l4(tenantID, streamA, subscriptionID, "s1", from.Add(20*time.Minute), 30, 70, 2),          // 同事件重放：去重
		l4(tenantID, streamB, subscriptionID, "s2", from.Add(80*time.Minute), 100, 300, 1),        // 第二小时 400
		l4(tenantID, streamOther, otherPackage, "s3", from.Add(30*time.Minute), 9000, 9000, 1),    // 别的套餐
		l4(otherTenantID, streamA, subscriptionID, "s4", from.Add(30*time.Minute), 7000, 7000, 1), // 别的租户同 ID
		l4(tenantID, streamA, subscriptionID, "s5", to.Add(5*time.Minute), 8000, 8000, 1),         // 范围外
		// L1：streamB 之后改到 otherPackage，换之后的会话记在新套餐，不进本套餐。
		l4(tenantID, streamB, otherPackage, "s6", from.Add(90*time.Minute), 600, 600, 1),
		l4(tenantID, streamOther, nilUUIDString, "s7", from.Add(40*time.Minute), 50, 50, 1), // 无套餐的转发
	})

	client, err := NewClient(Config{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 5 * time.Second,
	}, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.WithTenantResolver(mapTenants{scopeID: tenantID, onlyL4ScopeID: onlyL4TenantID})
	// 执行链：四层单独合计。
	l4Total, err := client.PackageL4Traffic(t.Context(), tenantID, subscriptionID, from, to)
	if err != nil || l4Total != 500 {
		t.Fatalf("PackageL4Traffic = %d, %v; want 500", l4Total, err)
	}
	// 转发换过去的新套餐：只算换之后的 s6 + 本来就属于它的 s3。
	if moved, err := client.PackageL4Traffic(t.Context(), tenantID, otherPackage, from, to); err != nil || moved != 18000+1200 {
		t.Fatalf("new package = %d, %v; want 19200", moved, err)
	}
	if none, err := client.PackageL4Traffic(t.Context(), "", subscriptionID, from, to); err != nil || none != 0 {
		t.Fatalf("no tenant = %d, %v; want 0", none, err)
	}

	request := PackageUsageRequest{
		TenantScopeID: scopeID, SubscriptionID: subscriptionID, From: from, To: to,
		Timezone: "UTC", Bucket: PackageUsageBucketHour, Limit: 24, L4TenantID: tenantID,
	}
	usage, err := client.PackageUsage(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if usage.HTTPTrafficBytes != 3000 || usage.L4TrafficBytes != 500 || usage.TrafficBytes != 3500 {
		t.Fatalf("summary http=%d l4=%d total=%d; want 3000/500/3500", usage.HTTPTrafficBytes, usage.L4TrafficBytes, usage.TrafficBytes)
	}
	want := []PackageUsagePoint{
		{Bucket: from, HTTPTrafficBytes: 1000, L4TrafficBytes: 100, TrafficBytes: 1100},
		{Bucket: from.Add(time.Hour), HTTPTrafficBytes: 2000, L4TrafficBytes: 400, TrafficBytes: 2400},
	}
	if len(usage.Series) != len(want) {
		t.Fatalf("series = %#v", usage.Series)
	}
	for index, point := range usage.Series {
		if !point.Bucket.Equal(want[index].Bucket) || point.HTTPTrafficBytes != want[index].HTTPTrafficBytes ||
			point.L4TrafficBytes != want[index].L4TrafficBytes || point.TrafficBytes != want[index].TrafficBytes {
			t.Fatalf("series[%d] = %#v, want %#v", index, point, want[index])
		}
	}

	// 只有四层的时段也出现在序列里（另一作用域换算成它自己的 tenants.id，无七层事实；
	// 四层按 L4TenantID 记在本套餐）。
	onlyL4 := request
	onlyL4.TenantScopeID = onlyL4ScopeID
	usage, err = client.PackageUsage(t.Context(), onlyL4)
	if err != nil || usage.HTTPTrafficBytes != 0 || usage.L4TrafficBytes != 500 || len(usage.Series) != 2 {
		t.Fatalf("L4 only = %#v, %v", usage, err)
	}

	// 按网站筛选：四层转发不属于网站，不计入。
	bySite := request
	bySite.SiteID = siteID
	usage, err = client.PackageUsage(t.Context(), bySite)
	if err != nil {
		t.Fatal(err)
	}
	if usage.HTTPTrafficBytes != 3000 || usage.L4TrafficBytes != 0 || usage.TrafficBytes != 3000 {
		t.Fatalf("site filter http=%d l4=%d total=%d; want 3000/0/3000", usage.HTTPTrafficBytes, usage.L4TrafficBytes, usage.TrafficBytes)
	}
	for _, point := range usage.Series {
		if point.L4TrafficBytes != 0 {
			t.Fatalf("site filter series carries L4: %#v", point)
		}
	}
}
