package analyticslog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// WAF 安全概览统计到的每一条命中（含观察
// action=log、自动封禁 temporary_ban）在日志明细里都能查到；明细可按事件类型
// 与概览同样的多域名筛选收窄。
func TestSecurityLogListsEveryOverviewAction(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	for _, item := range []struct {
		action, filter string
		want           bool
	}{
		{"log", "", true}, {"temporary_ban", "", true}, {"allow", "", false},
		{"log", "log", true}, {"block", "log", false}, {"temporary_ban", "temporary_ban", true}, {"log", "temporary_ban", false},
	} {
		if got := blockEventRowMatches(blockEventRow{Action: item.action}, ip, Filter{Action: item.filter}); got != item.want {
			t.Errorf("action %q filter %q = %v", item.action, item.filter, got)
		}
	}
	for _, clause := range []string{
		"tupleElement(latest_filter, 9) IN ('block', 'challenge', 'log', 'temporary_ban')",
		"({has_event_type:UInt8} = 0 OR tupleElement(latest_filter, 8) = {event_type:String})",
		"({has_host:UInt8} = 0 OR event_id IN (SELECT event_id FROM host_event_ids))",
	} {
		if !strings.Contains(blockEventPageSQL, clause) {
			t.Errorf("security page query lacks %q", clause)
		}
	}
}

func TestSecurityLogParsesOverviewFilters(t *testing.T) {
	from, to := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)
	route := handlerRoute{audience: AudienceTenant, kind: routeBlockEvent}
	for raw, ok := range map[string]bool{
		"action=log": true, "action=temporary_ban": true, "action=allow": false,
		"event_type=waf": true, "event_type=cc": true, "event_type=bad%20type": false,
		"host=a.example.test%20b.example.test": true, "host=a.example.test%20a.example.test": false, "host=a.example.test%20bad": false,
	} {
		request := httptest.NewRequest("GET", "/v1/analytics/logs/block-events?from="+from+"&to="+to+"&"+raw, nil)
		query, err := parseQuery(request, route)
		if err == nil {
			_, _, err = authorizeQuery(Actor{ScopeKind: "tenant", TenantID: "10000000-0000-4000-8000-000000000001",
				Permissions: []string{ReadPermission}}, query)
		}
		if (err == nil) != ok {
			t.Errorf("%s: err=%v", raw, err)
		}
	}
	access := httptest.NewRequest("GET", "/v1/analytics/logs/access?from="+from+"&to="+to+"&event_type=waf", nil)
	if _, err := parseQuery(access, handlerRoute{audience: AudienceTenant, kind: routeAccess}); err == nil {
		t.Error("access log accepted event_type")
	}
	values := filterParameters(scope{tenantID: "t"}, Filter{EventType: "waf", Host: "a.example.test b.example.test"}, 10)
	if values.Get("param_has_event_type") != "1" || values.Get("param_event_type") != "waf" ||
		values.Get("param_has_host") != "1" || values.Get("param_host") != "a.example.test b.example.test" {
		t.Errorf("parameters %v", values)
	}
	if empty := filterParameters(scope{tenantID: "t"}, Filter{}, 10); empty.Get("param_has_event_type") != "0" || empty.Get("param_has_host") != "0" {
		t.Errorf("empty parameters %v", empty)
	}
}

func TestSecurityLogReturnsObservedHitsForEveryOverviewDomain(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		query = string(body)
		_ = json.NewEncoder(writer).Encode(blockEventRow{
			EventID: "evt-observed", OccurredAtMS: now.Add(-time.Minute).UnixMilli(), SiteID: siteA, NodeID: nodeA,
			RequestID: requiredString("request-observed"), TraceID: requiredString("trace-observed"), ConfigVersion: requiredString(configA),
			Host: "B.example.test", URIPath: "/.env", ClientIP: "2001:db8::1", CountryCode: "CN",
			Carrier: "carrier-a", EventType: "waf", Action: "log", Severity: "info", VersionCount: 1, Count: 1,
		})
	}))
	defer server.Close()
	client := newUnitClient(t, server, time.Second)
	filter := Filter{From: now.Add(-time.Hour), To: now, Host: "a.example.test b.example.test", EventType: "waf", Action: "log"}
	page, err := client.ListBlockEvents(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].Action != "log" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if !strings.Contains(query, "host_event_ids AS") {
		t.Fatalf("query did not narrow by host: %s", query)
	}
	if blockEventRowMatches(blockEventRow{Action: "log", Host: "c.example.test", EventType: "waf"}, netip.MustParseAddr("2001:db8::1"), filter) {
		t.Error("row outside the domain list matched")
	}
	if blockEventRowMatches(blockEventRow{Action: "log", Host: "a.example.test", EventType: "cc"}, netip.MustParseAddr("2001:db8::1"), filter) {
		t.Error("row of another event type matched")
	}
}
