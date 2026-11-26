package analytics

import (
	"testing"
	"time"
)

// 真实 ClickHouse 上，同站两域名、多端口、站点+域名
// 组合与空结果下，摘要的请求数/流量与同一筛选条件下域名排行的合计一致；收窄后安全
// 事件计数为 null。
func TestAnalyticsClickHouseSummaryDomainPortScopeIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)

	from := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	to := from.Add(time.Hour)
	ingested := time.Now().UTC().Add(-10 * time.Second).Truncate(time.Millisecond)
	row := func(eventID string, minute int, siteID, nodeID, host string, port uint16, responseBytes uint64) rankAccessRow {
		access := rankAccessRow{
			AccessEvent: rankAccessEvent(eventID, from.Add(time.Duration(minute)*time.Minute), rankTenantA, siteID, nodeID,
				host, "/"+eventID, "2001:db8::"+string(rune('a'+minute%6)), "CN", "carrier-a", 200, 10, responseBytes),
			IngestedAt: ingested,
		}
		access.ListenPort = port
		return access
	}
	insertRankRows(t, database, insertRankAccessSQL, []rankAccessRow{
		row("scope-cdn-443-a", 1, rankSiteA1, rankNodeA1, "cdn.example.test", 443, 100),
		row("scope-cdn-443-b", 2, rankSiteA1, rankNodeA1, "CDN.example.test", 443, 200),
		row("scope-cdn-8443", 3, rankSiteA1, rankNodeA1, "cdn.example.test", 8443, 400),
		row("scope-static-443", 4, rankSiteA1, rankNodeA1, "static.example.test", 443, 800),
		row("scope-other-site", 5, rankSiteA2, rankNodeA2, "other.example.test", 443, 1600),
	})
	insertRankRows(t, database, insertRankSecuritySQL, []rankSecurityRow{{
		SecurityEvent: rankSecurityEvent("scope-security", from.Add(6*time.Minute), rankTenantA, rankSiteA1, rankNodeA1, "block"),
		IngestedAt:    ingested,
	}})

	service, err := NewService(newRankIntegrationClient(t, database))
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{ScopeKind: "tenant", TenantID: rankTenantA, Permissions: []string{ReadPermission}}
	handler := newRankIntegrationHandler(t, service, actor, HandlerConfig{})
	tests := []struct {
		name                 string
		site, domain, port   string
		wantRequests         uint64
		wantResponseBytes    uint64
		wantSecurityPresent  bool
		wantSecurityRequests uint64
	}{
		{name: "whole tenant", wantRequests: 5, wantResponseBytes: 3100, wantSecurityPresent: true, wantSecurityRequests: 1},
		{name: "one domain", domain: "cdn.example.test", wantRequests: 3, wantResponseBytes: 700},
		{name: "two domains of one site", domain: "cdn.example.test static.example.test", wantRequests: 4, wantResponseBytes: 1500},
		{name: "port", port: "443", wantRequests: 4, wantResponseBytes: 2700},
		{name: "domain and port", domain: "cdn.example.test", port: "8443", wantRequests: 1, wantResponseBytes: 400},
		{name: "site and domain", site: rankSiteA1, domain: "static.example.test", wantRequests: 1, wantResponseBytes: 800},
		{name: "foreign site and domain", site: rankSiteA2, domain: "static.example.test"},
		{name: "unknown domain", domain: "missing.example.test"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := rankQueryValues(from, to)
			for key, value := range map[string]string{"site_id": test.site, "domain": test.domain, "listen_port": test.port} {
				if value != "" {
					values.Set(key, value)
				}
			}
			var summary analyticsSummaryResponse
			rankDecodeOK(t, rankGET(t, handler, "/v1/analytics/summary", values), &summary)
			if summary.Data.RequestCount != test.wantRequests || summary.Data.ResponseBytes != test.wantResponseBytes {
				t.Fatalf("summary = %#v", summary.Data.Summary)
			}
			if test.wantSecurityPresent {
				if summary.Data.SecurityEvents == nil || *summary.Data.SecurityEvents != test.wantSecurityRequests {
					t.Fatalf("security events = %v", summary.Data.SecurityEvents)
				}
			} else if summary.Data.SecurityEvents != nil || summary.Data.SecurityEventRows != nil {
				t.Fatalf("narrowed summary reports security counts: %v %v", summary.Data.SecurityEvents, summary.Data.SecurityEventRows)
			}

			values.Set("limit", "100")
			page := rankDecodePage(t, rankGET(t, handler, "/v1/analytics/top/domain", values))
			var requests, responseBytes uint64
			for _, item := range page.Data {
				requests += item.RequestCount
				responseBytes += item.ResponseBytes
			}
			if requests != summary.Data.RequestCount || responseBytes != summary.Data.ResponseBytes {
				t.Fatalf("rank covers %d requests / %d bytes, summary %d / %d", requests, responseBytes,
					summary.Data.RequestCount, summary.Data.ResponseBytes)
			}
		})
	}
}
