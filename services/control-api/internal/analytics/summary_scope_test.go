package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// 数据分析页按域名/端口筛选时，摘要与排行必须覆盖
// 同一批请求。摘要接口放行 domain/listen_port，按与排行相同的规范化与 SQL 条件收窄；
// 安全事件小时事实表没有 host/port，收窄后安全事件计数返回 null，不回落为全租户值。

func TestSummaryHandlerAcceptsRankDomainAndListenPortFilters(t *testing.T) {
	t.Parallel()
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	summary := Summary{MetricVersion: MetricVersion, RequestCount: 7, SecurityEvents: 3, SecurityEventRows: 2}
	tests := []struct {
		name         string
		extra        string
		wantDomain   string
		wantPort     uint16
		wantSecurity bool
	}{
		{name: "no narrowing", wantSecurity: true},
		{name: "site only", extra: "site_id=" + testSiteID, wantSecurity: true},
		{name: "domain set", extra: "domain=" + url.QueryEscape("CDN.Example.Test. cdn.example.test static.example.test"),
			wantDomain: "cdn.example.test static.example.test"},
		{name: "listen port", extra: "listen_port=8443", wantPort: 8443},
		{name: "site domain and port", extra: "site_id=" + testSiteID + "&domain=cdn.example.test&listen_port=443",
			wantDomain: "cdn.example.test", wantPort: 443},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingQueryStore{summary: summary}
			handler := mustHandler(t, store, actor, HandlerConfig{})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/analytics/summary", test.extra), nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
			}
			if store.filter.Domain != test.wantDomain || store.filter.ListenPort != test.wantPort {
				t.Fatalf("filter domain=%q port=%d, want %q %d", store.filter.Domain, store.filter.ListenPort, test.wantDomain, test.wantPort)
			}
			var body struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			wantEvents, wantRows := "null", "null"
			if test.wantSecurity {
				wantEvents, wantRows = "3", "2"
			}
			if string(body.Data["security_events"]) != wantEvents || string(body.Data["security_event_rows"]) != wantRows ||
				string(body.Data["request_count"]) != "7" {
				t.Fatalf("data = %s", response.Body.String())
			}
			if len(body.Data) != 15 {
				t.Fatalf("summary keys = %d, want 15: %s", len(body.Data), response.Body.String())
			}
		})
	}
}

func TestSummaryHandlerRejectsInvalidDomainAndListenPort(t *testing.T) {
	t.Parallel()
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	for name, extra := range map[string]string{
		"port zero":        "listen_port=0",
		"port too large":   "listen_port=65536",
		"port not numeric": "listen_port=https",
		"duplicate port":   "listen_port=443&listen_port=443",
		"invalid domain":   "domain=bad_domain",
		"domain set >64":   "domain=" + url.QueryEscape(strings.Repeat("a.example.test ", 64)+"b.example.test"),
		"limit":            "limit=10",
		"cursor":           "cursor=abc",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := &recordingQueryStore{}
			handler := mustHandler(t, store, actor, HandlerConfig{})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/analytics/summary", extra), nil))
			if response.Code != http.StatusBadRequest || store.queryCalled {
				t.Fatalf("status = %d called=%v body = %s", response.Code, store.queryCalled, response.Body.String())
			}
		})
	}
}

// The trend keeps its contract: no domain or port narrowing.
func TestTrendHandlerStillRejectsDomainAndListenPort(t *testing.T) {
	t.Parallel()
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	for _, extra := range []string{"domain=cdn.example.test", "listen_port=443"} {
		store := &recordingQueryStore{}
		handler := mustHandler(t, store, actor, HandlerConfig{})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/analytics/hourly-trend", extra), nil))
		if response.Code != http.StatusBadRequest || store.queryCalled {
			t.Fatalf("%s: status = %d", extra, response.Code)
		}
	}
}

func TestSummaryBindsTheRankDomainAndListenPortParameters(t *testing.T) {
	t.Parallel()
	var query string
	var parameters url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		query, parameters = string(body), request.URL.Query()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, summaryResponse())
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	filter := validFilter()
	filter.SiteID = testSiteID
	filter.Domain = "CDN.Example.Test. cdn.example.test STATIC.example.test"
	filter.ListenPort = 443
	if _, err := client.Summary(context.Background(), AdminScope(), filter); err != nil {
		t.Fatal(err)
	}
	rankParameters, err := rankQueryParameters(AdminScope(), filter)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"param_has_domain", "param_domain", "param_has_listen_port", "param_listen_port",
		"param_has_site", "param_site_id", "param_tenant_scoped", "param_from_ms", "param_to_ms",
	} {
		if parameters.Get(key) != rankParameters.Get(key) {
			t.Fatalf("%s = %q, rank binds %q", key, parameters.Get(key), rankParameters.Get(key))
		}
	}
	for key, want := range map[string]string{
		"param_has_domain": "1", "param_domain": "cdn.example.test static.example.test",
		"param_has_listen_port": "1", "param_listen_port": "443",
	} {
		if parameters.Get(key) != want {
			t.Fatalf("%s = %q, want %q", key, parameters.Get(key), want)
		}
	}
	for _, token := range []string{
		"client_ip, host, listen_port)",
		"AND ({has_domain:UInt8} = 0 OR has(splitByChar(' ', {domain:String}), lower(tupleElement(latest, 9))))",
		"AND ({has_listen_port:UInt8} = 0 OR tupleElement(latest, 10) = {listen_port:UInt16})",
		"AND {has_domain:UInt8} = 0 AND {has_listen_port:UInt8} = 0",
	} {
		if !strings.Contains(query, token) {
			t.Fatalf("summary SQL lacks %q", token)
		}
	}

	filter.Domain, filter.ListenPort = "", 0
	if _, err := client.Summary(context.Background(), AdminScope(), filter); err != nil {
		t.Fatal(err)
	}
	if parameters.Get("param_has_domain") != "0" || parameters.Get("param_has_listen_port") != "0" {
		t.Fatalf("unnarrowed parameters = %v", parameters)
	}
}

func TestSummaryRejectsInvalidDomainSetsBeforeDispatch(t *testing.T) {
	t.Parallel()
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	filter := validFilter()
	filter.Domain = "valid.example.test bad_domain"
	if _, err := client.Summary(context.Background(), AdminScope(), filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid domain set error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("storage requests = %d", requests)
	}
}

// summaryFromResponse rebuilds the Summary a handler response carries; the
// security counts must be present (unnarrowed query).
func summaryFromResponse(t *testing.T, data analyticsSummaryData) Summary {
	t.Helper()
	if data.SecurityEvents == nil || data.SecurityEventRows == nil {
		t.Fatalf("summary security counts are null: %#v", data)
	}
	summary := data.Summary
	summary.SecurityEvents, summary.SecurityEventRows = *data.SecurityEvents, *data.SecurityEventRows
	return summary
}
