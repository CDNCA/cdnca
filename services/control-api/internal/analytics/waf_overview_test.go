package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

type wafOverviewStoreStub struct {
	QueryStore
	overview WAFOverview
	filter   Filter
}

func (store *wafOverviewStoreStub) WAFOverview(_ context.Context, _ Scope, filter Filter) (WAFOverview, error) {
	store.filter = filter
	return store.overview, nil
}

func TestWAFOverviewClientSeparatesWAFFactsAndCarriesDomain(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		body, _ := io.ReadAll(request.Body)
		query := string(body)
		if !strings.Contains(query, "event_type = 'waf'") || strings.Contains(query, "event_type = 'global_firewall'") ||
			!strings.Contains(query, "{has_domain:UInt8}") || !strings.Contains(query, "splitByChar(' ', {domain:String})") {
			t.Fatalf("WAF query lost event/domain scope: %s", query)
		}
		if requests == 3 && (!strings.Contains(query, "if(empty(host), '__unknown__', lower(host))") ||
			!strings.Contains(query, "if(empty(path), '__unknown__', path)")) {
			t.Fatalf("WAF breakdown query lost canonical empty-value mapping: %s", query)
		}
		if got := request.URL.Query().Get("param_domain"); got != "cdn.example.test static.example.test" {
			t.Fatalf("param_domain = %q", got)
		}
		writer.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			payload := `{"attacks":4,"blocked":1,"intercepted":1,"observed":1,"auto_blocked":1,"clients":3}
`
			_, _ = io.WriteString(writer, payload)
		case 2:
			payload := `{"bucket_unix":4070908800,"attacks":4,"blocked":1,"intercepted":1,"observed":1,"auto_blocked":1,"clients":3}
`
			_, _ = io.WriteString(writer, payload)
		case 3:
			payload := `{"dimension":"attack_type","key":"sql-injection","count":2}
{"dimension":"carrier","key":"CMCC","count":1}
{"dimension":"client","key":"203.0.113.7","count":2}
{"dimension":"country","key":"CN","count":3}
{"dimension":"domain","key":"cdn.example.test","count":4}
{"dimension":"domain","key":"__unknown__","count":1}
{"dimension":"uri","key":"/login","count":2}
{"dimension":"uri","key":"__unknown__","count":1}
`
			_, _ = io.WriteString(writer, payload)
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	scope, err := TenantScope(testTenantID)
	if err != nil {
		t.Fatal(err)
	}
	filter := validFilter()
	filter.From = time.Unix(4070908800, 0).UTC()
	filter.To = filter.From.Add(2 * time.Hour)
	filter.Domain = "CDN.example.test"
	if _, err := client.WAFOverview(context.Background(), scope, filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-canonical domain error = %v", err)
	}
	filter.Domain = "cdn.example.test static.example.test"
	overview, err := client.WAFOverview(context.Background(), scope, filter)
	if err != nil || overview.Attacks != 4 || overview.Blocked != 1 || overview.Intercepted != 1 || overview.AutoBlocked != 1 || overview.Clients != 3 ||
		len(overview.Trend) != 1 || overview.Trend[0].Hour.IsZero() || len(overview.AttackTypes) != 1 ||
		overview.AttackTypes[0].Key != "sql-injection" || len(overview.TopDomains) != 2 ||
		overview.TopDomains[1].Key != "__unknown__" || len(overview.TopProvinces) != 0 ||
		len(overview.TopURIs) != 2 || overview.TopURIs[0].Key != "/login" || overview.TopURIs[1].Key != "__unknown__" {
		t.Fatalf("WAFOverview() = %#v, %v", overview, err)
	}
	if requests != 3 {
		t.Fatalf("WAFOverview requests = %d, want 3", requests)
	}
}

func TestWAFOverviewClientReturnsTypedEmptyBreakdowns(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = io.WriteString(writer, `{"attacks":0,"blocked":0,"intercepted":0,"observed":0,"auto_blocked":0,"clients":0}`+"\n")
		}
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	overview, err := client.WAFOverview(context.Background(), AdminScope(), validFilter())
	if err != nil || overview.Trend == nil || overview.AttackTypes == nil || overview.TopDomains == nil ||
		overview.TopClients == nil || overview.TopCountries == nil || overview.TopProvinces == nil ||
		overview.TopCarriers == nil || overview.TopURIs == nil {
		t.Fatalf("WAFOverview() = %#v, %v", overview, err)
	}
}

func TestWAFOverviewClientPropagatesBreakdownDependencyFailure(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 3 {
			http.Error(writer, "private analytics failure", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = io.WriteString(writer, `{"attacks":0,"blocked":0,"intercepted":0,"observed":0,"auto_blocked":0,"clients":0}`+"\n")
		}
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if _, err := client.WAFOverview(context.Background(), AdminScope(), validFilter()); err == nil {
		t.Fatal("WAFOverview() error = nil")
	}
}

func TestWAFBreakdownsRejectInvalidRows(t *testing.T) {
	value := func(input string) *string { return &input }
	count := func(input uint64) *uint64 { return &input }
	tests := []struct {
		name string
		rows []wafBreakdownResponseRow
	}{
		{name: "unknown dimension", rows: []wafBreakdownResponseRow{{Dimension: value("province"), Key: value("HN"), Count: count(1)}}},
		{name: "zero count", rows: []wafBreakdownResponseRow{{Dimension: value("domain"), Key: value("cdn.example.test"), Count: count(0)}}},
		{name: "control character", rows: []wafBreakdownResponseRow{{Dimension: value("domain"), Key: value("cdn.example.test\n"), Count: count(1)}}},
		{name: "wrong order", rows: []wafBreakdownResponseRow{
			{Dimension: value("domain"), Key: value("b.example.test"), Count: count(1)},
			{Dimension: value("domain"), Key: value("a.example.test"), Count: count(2)},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := wafBreakdowns(test.rows); ok {
				t.Fatal("wafBreakdowns() accepted invalid rows")
			}
		})
	}
}

func TestWAFOverviewHandlerReturnsHourAndCounters(t *testing.T) {
	from := time.Unix(4070908800, 0).UTC()
	store := &wafOverviewStoreStub{QueryStore: &recordingQueryStore{}, overview: WAFOverview{
		Attacks: 7, Blocked: 3, Intercepted: 2, Observed: 2, AutoBlocked: 1, Clients: 4,
		Trend:       []WAFTrendPoint{{Hour: from, Attacks: 7, Blocked: 3, Intercepted: 2, Observed: 2, AutoBlocked: 1, Clients: 4}},
		AttackTypes: []WAFRankItem{{Key: "sql-injection", Count: 3}},
		TopDomains:  []WAFRankItem{{Key: "cdn.example.test", Count: 7}},
		TopClients:  []WAFRankItem{}, TopCountries: []WAFRankItem{}, TopProvinces: []WAFRankItem{}, TopCarriers: []WAFRankItem{},
		TopURIs: []WAFRankItem{{Key: "/login", Count: 2}},
	}}
	handler := mustHandler(t, store, Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, HandlerConfig{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		handlerURL("/v1/admin/analytics/waf-overview", "domain=cdn.example.test+static.example.test"), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Data WAFOverview   `json:"data"`
		Meta queryMetadata `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Attacks != 7 || body.Data.AutoBlocked != 1 || len(body.Data.Trend) != 1 ||
		body.Data.Trend[0].Hour.Format(time.RFC3339) != from.Format(time.RFC3339) || len(body.Data.AttackTypes) != 1 ||
		body.Data.AttackTypes[0].Key != "sql-injection" || len(body.Data.TopURIs) != 1 ||
		store.filter.Domain != "cdn.example.test static.example.test" || body.Meta.Timezone != "UTC" {
		t.Fatalf("body = %#v", body)
	}
}

type ruleNameLookupStub struct{ refs []analyticslog.EventNameRef }

func (stub *ruleNameLookupStub) Lookup(_ context.Context, _ string, refs []analyticslog.EventNameRef) analyticslog.EventNames {
	stub.refs = refs
	return analyticslog.EventNames{Rules: map[string]map[string]string{
		"44444444-4444-4444-8444-444444444444": {"01a16c0c-8a4e-73f2-9814-cd935d0a6381": "文件包含 · 敏感系统文件"},
	}}
}

// ui-errmsg-1024: the overview's attack types carry the rule name the block
// event list shows (policy rule name, OWASP CRS #<id> · <msg>).
func TestWAFOverviewNamesAttackTypes(t *testing.T) {
	store := &wafOverviewStoreStub{QueryStore: &recordingQueryStore{}, overview: WAFOverview{
		AttackTypes: []WAFRankItem{{Key: "01a16c0c-8a4e-73f2-9814-cd935d0a6381", Count: 5}, {Key: "942100", Count: 3}, {Key: "__unknown__", Count: 1}},
	}}
	lookup := &ruleNameLookupStub{}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	service.SetRuleNameLookup(lookup)
	handler, err := NewHandler(service, func(*http.Request) (Actor, error) {
		return Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, nil
	}, HandlerConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/admin/analytics/waf-overview", ""), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Data WAFOverview `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	types := body.Data.AttackTypes
	if len(types) != 3 || types[0].Name != "文件包含 · 敏感系统文件" || !strings.HasPrefix(types[1].Name, "OWASP CRS #942100") ||
		types[2].Name != "" || len(lookup.refs) != 3 || lookup.refs[0].RuleID != types[0].Key {
		t.Fatalf("attack types = %#v refs = %#v", types, lookup.refs)
	}
	if strings.Contains(response.Body.String(), `"name":""`) {
		t.Fatalf("unknown name must be omitted: %s", response.Body.String())
	}
}

type sameNameLookupStub struct{}

func (sameNameLookupStub) Lookup(context.Context, string, []analyticslog.EventNameRef) analyticslog.EventNames {
	return analyticslog.EventNames{Rules: map[string]map[string]string{"p1": {
		"018f0000-0000-7000-8000-0000000000a1": "登录限频", "028f0000-0000-7000-8000-0000000000a2": "登录限频",
		"038f0000-0000-7000-8000-0000000000a3": "SQL 注入",
	}}}
}

// fix-wafname: attack types stay one row per rule ID (the drill-down filters
// by it, ClickHouse ranks the top 10 by it); rows sharing a name are told
// apart by the rule ID's first 8 characters.
func TestWAFOverviewDistinguishesSameNamedAttackTypes(t *testing.T) {
	service, err := NewService(&wafOverviewStoreStub{QueryStore: &recordingQueryStore{}})
	if err != nil {
		t.Fatal(err)
	}
	service.SetRuleNameLookup(sameNameLookupStub{})
	items := []WAFRankItem{{Key: "018f0000-0000-7000-8000-0000000000a1", Count: 5},
		{Key: "028f0000-0000-7000-8000-0000000000a2", Count: 3}, {Key: "038f0000-0000-7000-8000-0000000000a3", Count: 1}}
	service.nameAttackTypes(context.Background(), Scope{}, items)
	if items[0].Name != "登录限频（018f0000）" || items[1].Name != "登录限频（028f0000）" || items[2].Name != "SQL 注入" {
		t.Fatalf("attack types = %#v", items)
	}
}

// fix-waflogdetail：概览与日志明细同一动作口径——只数明细列出的四种命中
// （拦截 block、挑战 challenge、观察 log、自动封禁 temporary_ban），allow
// （白名单命中）不算攻击；自动封禁按节点实际上报的 temporary_ban 计。
func TestWAFOverviewCountsTheSecurityLogActions(t *testing.T) {
	scope := "action IN ('block', 'challenge', 'log', 'temporary_ban')"
	for name, query := range map[string]string{"summary": wafOverviewSQL, "trend": wafTrendSQL, "breakdown": wafBreakdownSQL} {
		if !strings.Contains(query, scope) {
			t.Errorf("%s query lacks %q", name, scope)
		}
	}
	for name, query := range map[string]string{"summary": wafOverviewSQL, "trend": wafTrendSQL} {
		for _, clause := range []string{
			"countIf(action = 'block')) AS blocked", "countIf(action = 'challenge')) AS intercepted",
			"countIf(action = 'log')) AS observed", "countIf(action = 'temporary_ban')) AS auto_blocked",
		} {
			if !strings.Contains(query, clause) {
				t.Errorf("%s query lacks %q", name, clause)
			}
		}
	}
	if got, want := strings.Join(analyticslog.SecurityLogActions, ","), "block,challenge,log,temporary_ban"; got != want {
		t.Errorf("security log actions = %s, want %s", got, want)
	}
}

// fix-waflogdetail2：概览各动作（拦截/人机验证/观察/自动封禁）之和必须等于攻击
// 总数，汇总与每小时趋势都一样；对不上的响应整体拒绝，页面不出现无法对应的数字。
func TestWAFOverviewRejectsActionCountsThatDoNotAddUp(t *testing.T) {
	summary := `{"attacks":4,"blocked":1,"intercepted":1,"observed":1,"auto_blocked":1,"clients":3}`
	trend := `{"bucket_unix":4070908800,"attacks":4,"blocked":1,"intercepted":1,"observed":1,"auto_blocked":1,"clients":3}`
	for name, rows := range map[string][2]string{
		"consistent":     {summary, trend},
		"summary excess": {strings.Replace(summary, `"attacks":4`, `"attacks":5`, 1), trend},
		"summary short":  {strings.Replace(summary, `"blocked":1`, `"blocked":2`, 1), trend},
		"trend mismatch": {summary, strings.Replace(trend, `"intercepted":1`, `"intercepted":0`, 1)},
	} {
		t.Run(name, func(t *testing.T) {
			var requests int
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				requests++
				writer.Header().Set("Content-Type", "application/json")
				if requests <= 2 {
					_, _ = io.WriteString(writer, rows[requests-1]+"\n")
				}
			}))
			defer server.Close()
			client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
			filter := validFilter()
			filter.From = time.Unix(4070908800, 0).UTC()
			filter.To = filter.From.Add(2 * time.Hour)
			_, err := client.WAFOverview(context.Background(), AdminScope(), filter)
			if consistent := name == "consistent"; consistent != (err == nil) || (!consistent && !errors.Is(err, ErrInvalidResponse)) {
				t.Fatalf("WAFOverview() error = %v", err)
			}
		})
	}
}
