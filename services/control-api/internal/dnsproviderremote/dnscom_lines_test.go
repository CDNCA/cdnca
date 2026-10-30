package dnsproviderremote

import (
	"maps"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// dnsComLineZone is a fake openapi.dns.com shaped by the public docs
// (docs/7/11 getView, docs/12/14-16 record lists/create/update): ids come
// back as numbers, view names in Chinese with an English twin.
type dnsComLineZone struct {
	t        *testing.T
	mu       sync.Mutex
	views    []map[string]any
	refuse   map[string]bool // view_id -> create/update answers code 1
	getViews int
	writes   []map[string]string
	records  []map[string]any
}

func (zone *dnsComLineZone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zone.mu.Lock()
	defer zone.mu.Unlock()
	query := r.URL.Query()
	parameters := map[string]string{}
	for name := range query {
		if name != "sign" {
			parameters[name] = query.Get(name)
		}
	}
	if query.Get("api_key") != "provider-key" || query.Get("sign") != signDNSCom(parameters, "provider-secret") {
		zone.t.Errorf("unsigned %s", r.URL.RequestURI())
	}
	switch r.URL.Path {
	case "/api/domain/getView/":
		zone.getViews++
		if query.Get("domain") != testZone {
			zone.t.Errorf("getView domain = %q", query.Get("domain"))
		}
		writeTestJSON(zone.t, w, map[string]any{"code": 0, "message": "", "data": zone.views})
	case "/api/record/create/", "/api/record/update/":
		delete(parameters, "api_key")
		delete(parameters, "timestamp")
		zone.writes = append(zone.writes, parameters)
		if zone.refuse[query.Get("view_id")] {
			writeTestJSON(zone.t, w, map[string]any{"code": 1, "message": "套餐不支持该线路", "data": []any{}})
			return
		}
		writeTestJSON(zone.t, w, map[string]any{"code": 0, "data": map[string]any{"domain_id": 7001, "record_id": "9001",
			"record": query.Get("record"), "type": query.Get("type"), "value": query.Get("value"), "view_id": query.Get("view_id"),
			"status": 1, "ttl": 300}})
	case "/api/record/lists/":
		writeTestJSON(zone.t, w, map[string]any{"code": 0, "data": map[string]any{"total": len(zone.records), "data": zone.records}})
	default:
		zone.t.Errorf("unexpected DNS.COM request %s", r.URL.RequestURI())
		w.WriteHeader(http.StatusNotFound)
	}
}

func dnsComTestViews() []map[string]any {
	return []map[string]any{
		{"id": 0, "parent_id": "0", "view_name": "默认", "view_name_en": "Default", "sort": "1", "enable": "1"},
		{"id": 285344, "parent_id": "0", "view_name": "中国电信", "view_name_en": "China Telecom", "sort": "2", "enable": "1"},
		{"id": "285345", "parent_id": 0, "view_name": "联通", "view_name_en": "", "sort": 3, "enable": 1},
		{"id": 285346, "parent_id": "0", "view_name": "移动", "view_name_en": "China Mobile", "sort": "4", "enable": "1"},
		{"id": 285400, "parent_id": "285344", "view_name": "电信_广东", "view_name_en": "Telecom Guangdong", "sort": "9", "enable": "1"},
		{"id": 285500, "parent_id": "0", "view_name": "海外", "view_name_en": "Overseas", "sort": "5", "enable": "1"},
		{"id": 285501, "parent_id": "0", "view_name": "教育网", "view_name_en": "CERNET", "sort": "6", "enable": "0"},
	}
}

func newDNSComLineRemote(t *testing.T, plan string) (*dnsComLineZone, *providerReconcileRemote, ProviderConfig) {
	zone := &dnsComLineZone{t: t, views: dnsComTestViews(), refuse: map[string]bool{}}
	config := reconcileHTTPProviderConfig(providerDNSCom)
	if plan != "" {
		config.Credentials[DNSComPlanField] = plan
	}
	providerAdapter, _ := newProviderTestAdapter(t, config, zone, time.Second)
	return zone, &providerReconcileRemote{adapter: providerAdapter}, completeTestConfig(config)
}

func dnsComCreate(line string) dnscheck.ProviderOperation {
	return dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
		Value: "192.0.2.10", TTL: 300, Line: line}
}

// Free opens 默认+三网; enterprise adds the 拓展/区域/大洲 lines; flagship
// adds 境外 as well. A line outside the tier fails as
// not-in-plan before any request.
func TestDNSComPlanTierLines(t *testing.T) {
	enterprise := []string{"教育网", "华南", "亚洲"}
	allLines := append([]string{LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas}, enterprise...)
	base := map[string]bool{LineDefault: true, LineTelecom: true, LineUnicom: true, LineMobile: true}
	withEnterprise := maps.Clone(base)
	for _, line := range enterprise {
		withEnterprise[line] = true
	}
	withOverseas := maps.Clone(withEnterprise)
	withOverseas[LineOverseas] = true
	for _, tier := range []struct {
		plan    string
		allowed map[string]bool
		lines   int
	}{
		{"", base, 4},
		{DNSComPlanFree, base, 4},
		{DNSComPlanEnterprise, withEnterprise, 4 + len(dnsComEnterpriseLines)},
		{DNSComPlanFlagship, withOverseas, 5 + len(dnsComEnterpriseLines)},
	} {
		for _, line := range allLines {
			zone, remote, config := newDNSComLineRemote(t, tier.plan)
			for index, name := range enterprise[1:] { // 教育网 is in the fixture, disabled
				zone.views = append(zone.views, map[string]any{"id": 286000 + index, "parent_id": "0", "view_name": name,
					"sort": "40", "enable": "1"})
			}
			zone.views[6]["enable"] = "1" // 教育网
			_, err := remote.Mutate(t.Context(), config, dnsComCreate(line))
			if tier.allowed[line] {
				if err != nil || len(zone.writes) != 1 {
					t.Fatalf("plan %q line %s: Mutate() = %v writes %d", tier.plan, line, err, len(zone.writes))
				}
				continue
			}
			if ErrorCodeOf(err) != CodeLineNotInPlan || len(zone.writes) != 0 || zone.getViews != 0 {
				t.Fatalf("plan %q line %s: Mutate() = %v writes %d getView %d, want not-in-plan before network",
					tier.plan, line, err, len(zone.writes), zone.getViews)
			}
		}
		if got := len(DNSComPlanLines(tier.plan)); got != tier.lines {
			t.Fatalf("DNSComPlanLines(%q) = %d lines, want %d", tier.plan, got, tier.lines)
		}
	}
	// Enterprise lines are DNS.COM's own: no other adapter writes them and
	// the unified line set (cnamelines, aggregated edge) is unchanged.
	if writableLine(providerAliyun, "华南") || writableLine(providerCustomHTTP, "华南") {
		t.Fatal("an enterprise DNS.COM line is writable on another provider")
	}
	if got := SupportedLines(providerDNSCom); len(got) != 5 {
		t.Fatalf("SupportedLines(dns_com) = %v", got)
	}
}

// Enterprise lines resolve their view_id by the getView name (中文 or
// English twin) like the unified lines; read back they keep their name; a
// name the account does not list (or lists disabled) is not in plan.
func TestDNSComEnterpriseLinesResolvedByName(t *testing.T) {
	zone, remote, config := newDNSComLineRemote(t, DNSComPlanEnterprise)
	zone.views = append(zone.views,
		map[string]any{"id": 285600, "parent_id": "0", "view_name": "华南", "view_name_en": "South China", "sort": "20", "enable": "1"},
		map[string]any{"id": 285700, "parent_id": "0", "view_name": "", "view_name_en": "Asia", "sort": "30", "enable": "1"},
	)
	for line, want := range map[string]string{"华南": "285600", "亚洲": "285700"} {
		zone.writes = nil
		if _, err := remote.Mutate(t.Context(), config, dnsComCreate(line)); err != nil || len(zone.writes) != 1 ||
			zone.writes[0]["view_id"] != want {
			t.Fatalf("%s: err %v writes %v, want view_id %s", line, err, zone.writes, want)
		}
	}
	zone.records = []map[string]any{{"domain_id": 7001, "record_id": "9100", "record": "www", "type": "A", "value": "192.0.2.10",
		"ttl": 300, "view_id": "285600", "status": 1}}
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil || len(records) != 1 || records[0].Line != "华南" {
		t.Fatalf("records %+v %v", records, err)
	}
	// 教育网 is listed disabled in the fixture
	zone.writes = nil
	if _, err := remote.Mutate(t.Context(), config, dnsComCreate("教育网")); ErrorCodeOf(err) != CodeLineNotInPlan || len(zone.writes) != 0 {
		t.Fatalf("disabled enterprise line: %v writes %v", err, zone.writes)
	}
}

// view_id comes from getView by name (中文 or English twin), only enabled
// entries, cached per account and domain; the default line omits view_id.
func TestDNSComViewIDResolvedByNameAndCached(t *testing.T) {
	zone, remote, config := newDNSComLineRemote(t, DNSComPlanFlagship)
	want := map[string]string{LineDefault: "", LineTelecom: "285344", LineUnicom: "285345", LineMobile: "285346", LineOverseas: "285500"}
	for _, line := range []string{LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas} {
		if _, err := remote.Mutate(t.Context(), config, dnsComCreate(line)); err != nil {
			t.Fatalf("Mutate(%s) error = %v", line, err)
		}
	}
	for index, line := range []string{LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas} {
		got, present := zone.writes[index]["view_id"]
		if want[line] == "" && present || want[line] != "" && got != want[line] {
			t.Fatalf("%s view_id = %q (present %v), want %q", line, got, present, want[line])
		}
	}
	if zone.getViews != 1 {
		t.Fatalf("getView calls = %d, want 1 (cached)", zone.getViews)
	}

	views, err := parseDNSComViews([]byte(`[{"id":1,"view_name":"境外","view_name_en":"Abroad","enable":"1"},
		{"id":2,"view_name":"教育网","enable":"0"},{"id":3,"view_name":"电信","enable":null}]`))
	if err != nil || views.ids[LineOverseas] != "1" || views.ids[LineTelecom] != "3" || len(views.ids) != 2 {
		t.Fatalf("parseDNSComViews() = (%+v, %v)", views, err)
	}
	if _, err := parseDNSComViews([]byte(`[{"id":1,"view_name":"电信"},{"id":2,"view_name":"中国电信"}]`)); ErrorCodeOf(err) != CodeInvalidResponse {
		t.Fatalf("two telecom entries error = %v, want invalid response", err)
	}
}

// The tier allows the line but the account does not have it: getView does
// not list it, or the write is refused. Either reads as not-in-plan (the
// line then answers with the default line), never as a provider failure.
func TestDNSComLineMissingFromAccountIsNotInPlan(t *testing.T) {
	zone, remote, config := newDNSComLineRemote(t, DNSComPlanFlagship)
	zone.views = zone.views[:4] // no 海外
	if _, err := remote.Mutate(t.Context(), config, dnsComCreate(LineOverseas)); ErrorCodeOf(err) != CodeLineNotInPlan {
		t.Fatalf("unlisted line error = %v, want not-in-plan", err)
	}
	if len(zone.writes) != 0 {
		t.Fatalf("writes = %v", zone.writes)
	}

	zone, remote, config = newDNSComLineRemote(t, DNSComPlanFree)
	zone.refuse["285346"] = true
	if _, err := remote.Mutate(t.Context(), config, dnsComCreate(LineMobile)); ErrorCodeOf(err) != CodeLineNotInPlan {
		t.Fatalf("refused line error = %v, want not-in-plan", err)
	}
	// A refused default-line write stays a provider failure.
	zone.refuse[""] = true
	if _, err := remote.Mutate(t.Context(), config, dnsComCreate(LineDefault)); ErrorCodeOf(err) != CodeInvalidResponse {
		t.Fatalf("refused default write error = %v, want invalid response", err)
	}
}

// Records read back carry their unified line; creates only see their line.
func TestDNSComRecordsReadBackLines(t *testing.T) {
	zone, remote, config := newDNSComLineRemote(t, DNSComPlanFree)
	record := func(id, value string, viewID any) map[string]any {
		return map[string]any{"domain_id": 7001, "record_id": id, "record": "www", "type": "A", "value": value,
			"view_id": viewID, "status": 1, "ttl": 300}
	}
	zone.records = []map[string]any{record("1", "192.0.2.10", "285344"), record("2", "192.0.2.20", 0),
		record("3", "192.0.2.30", "285400")}
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil || len(records) != 3 {
		t.Fatalf("ListZoneRecords() = (%+v, %v)", records, err)
	}
	if records[0].Line != LineTelecom || records[1].Line != LineDefault || records[2].Line != "dns_com:285400" {
		t.Fatalf("lines = %q %q %q", records[0].Line, records[1].Line, records[2].Line)
	}
	lookup, err := remote.Lookup(t.Context(), config, dnsComCreate(LineTelecom))
	if err != nil || !lookup.TargetComplete || lookup.RecordID != "1" {
		t.Fatalf("telecom Lookup() = (%+v, %v)", lookup, err)
	}
	lookup, err = remote.Lookup(t.Context(), config, dnsComCreate(LineDefault))
	if err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("default Lookup() of a telecom value = (%+v, %v), want absent", lookup, err)
	}
	if zone.getViews != 1 {
		t.Fatalf("getView calls = %d, want 1", zone.getViews)
	}
}

func TestDNSComPlanCredentialValidation(t *testing.T) {
	base := map[string]string{"api_key": "provider-key", "api_secret": "provider-secret"}
	for plan, valid := range map[string]bool{"": false, "free": true, "enterprise": true, "flagship": true, "custom": false} {
		credentials := map[string]string{DNSComPlanField: plan}
		for name, value := range base {
			credentials[name] = value
		}
		if err := validateCredentials(providerDNSCom, credentials); (err == nil) != valid {
			t.Fatalf("plan %q error = %v, want valid %v", plan, err, valid)
		}
	}
	if err := validateCredentials(providerDNSCom, base); err != nil {
		t.Fatalf("no plan error = %v", err)
	}
}

// 解析列表 is /api/record/lists/ paged by page+paginate with records in
// data.data (docs/12/14). The old list/page_size shape is refused, not read
// as an empty zone.
func TestDNSComRecordListUsesDocumentedShape(t *testing.T) {
	var queries []string
	shape := "data"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/record/lists/" {
			t.Errorf("list path = %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		query := r.URL.Query()
		queries = append(queries, query.Get("page")+"/"+query.Get("paginate")+"/"+query.Get("page_size"))
		writeTestJSON(t, w, map[string]any{"code": 0, "data": map[string]any{"total": 1, shape: []any{map[string]any{
			"domain_id": 7001, "record_id": "1", "record": "www", "type": "A", "value": "192.0.2.10", "view_id": "",
			"status": 1, "ttl": 300}}}})
	})
	config := reconcileHTTPProviderConfig(providerDNSCom)
	providerAdapter, _ := newProviderTestAdapter(t, config, handler, time.Second)
	remote := &providerReconcileRemote{adapter: providerAdapter}
	config = completeTestConfig(config)
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil || len(records) != 1 || records[0].Line != LineDefault {
		t.Fatalf("ListZoneRecords() = (%+v, %v)", records, err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, dnsComCreate(LineDefault)); err != nil || !lookup.TargetComplete {
		t.Fatalf("Lookup() = (%+v, %v)", lookup, err)
	}
	for _, query := range queries {
		if query != "1/100/" {
			t.Fatalf("page/paginate/page_size = %s, want 1/100/", query)
		}
	}
	shape = "list"
	if _, err := remote.ListZoneRecords(t.Context(), config, "www.example.test."); ErrorCodeOf(err) != CodeInvalidResponse {
		t.Fatalf("old list shape ListZoneRecords() error = %v, want invalid response", err)
	}
	if _, err := remote.Lookup(t.Context(), config, dnsComCreate(LineDefault)); ErrorCodeOf(err) != CodeInvalidResponse {
		t.Fatalf("old list shape Lookup() error = %v, want invalid response", err)
	}
}

// 添加解析 / 修改解析 parameters (docs/12/15, 12/16).
func TestDNSComWriteParametersFollowDocs(t *testing.T) {
	zone, remote, config := newDNSComLineRemote(t, DNSComPlanFree)
	if _, err := remote.Mutate(t.Context(), config, dnsComCreate(LineTelecom)); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"domain": testZone, "record": "www", "type": "A", "value": "192.0.2.10", "ttl": "300", "view_id": "285344"}
	got := zone.writes[0]
	if len(got) != len(want) {
		t.Fatalf("create parameters = %v, want %v", got, want)
	}
	for name, value := range want {
		if got[name] != value {
			t.Fatalf("create %s = %q, want %q (all %v)", name, got[name], value, got)
		}
	}
}
