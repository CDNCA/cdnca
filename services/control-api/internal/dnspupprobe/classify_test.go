package dnspupprobe

import (
	"slices"
	"testing"
	"time"
)

func TestPlaceOfCheckpoint(t *testing.T) {
	for _, item := range []struct {
		region, location, isp string
		want                  Place
	}{
		{"广东", "广州电信", "电信", Place{AreaMainland, CarrierTelecom, "广东"}},
		{"中国北京", "", "中国教育网", Place{AreaMainland, CarrierEdu, "北京"}},
		{"上海", "", "CERNET", Place{AreaMainland, CarrierEdu, "上海"}},
		{"江苏", "", "BGP多线", Place{AreaMainland, CarrierBGP, "江苏"}},
		{"香港", "", "PCCW", Place{AreaHKMOTW, CarrierOther, "hk"}},
		{"美国", "洛杉矶", "", Place{AreaOverseas, CarrierOther, "us"}},
		{"", "浙江移动", "移动", Place{AreaMainland, CarrierMobile, "浙江"}},
	} {
		if got := PlaceOf(item.region, item.location, item.isp); got != item.want {
			t.Errorf("PlaceOf(%q,%q,%q) = %+v, want %+v", item.region, item.location, item.isp, got, item.want)
		}
	}
}

func checkpointsFixture() []Checkpoint {
	return []Checkpoint{
		{ID: "t1", Region: "广东", ISP: "电信", Status: "online"}, {ID: "t2", Region: "江苏", ISP: "电信", Status: "online"},
		{ID: "t3", Region: "四川", ISP: "电信", Status: "online"}, {ID: "u1", Region: "广东", ISP: "联通", Status: "online"},
		{ID: "m1", Region: "广东", ISP: "移动", Status: "online"}, {ID: "m2", Region: "北京", ISP: "移动", Status: "offline"},
		{ID: "e1", Region: "北京", ISP: "教育网", Status: "online"}, {ID: "h1", Region: "香港", ISP: "HKBN"},
		{ID: "o1", Region: "日本", ISP: "NTT"},
	}
}

func ids(picked []Picked) []string {
	out := make([]string, 0, len(picked))
	for _, item := range picked {
		out = append(out, item.ID)
	}
	slices.Sort(out)
	return out
}

func TestSelectIncludeExcludeAndRotate(t *testing.T) {
	all := checkpointsFixture()
	got := ids(Select(all, Selection{Carriers: []string{CarrierTelecom}, PointsPerGroup: 2}, 0))
	if !slices.Equal(got, []string{"t1", "t2"}) {
		t.Fatalf("fixed telecom 2 = %v", got)
	}
	rotated := ids(Select(all, Selection{Carriers: []string{CarrierTelecom}, PointsPerGroup: 2, Rotate: true}, 1))
	if !slices.Equal(rotated, []string{"t2", "t3"}) {
		t.Fatalf("rotated round 1 = %v", rotated)
	}
	got = ids(Select(all, Selection{Areas: []string{AreaMainland}, ExcludeProvinces: []string{"广东"}, PointsPerGroup: 5}, 0))
	if !slices.Equal(got, []string{"e1", "t2", "t3"}) {
		t.Fatalf("mainland without 广东 (offline m2 dropped) = %v", got)
	}
	got = ids(Select(all, Selection{IncludeProvinces: []string{"广东"}, ExcludeCheckpoints: []string{"u1"}, PointsPerGroup: 5}, 0))
	if !slices.Equal(got, []string{"m1", "t1"}) {
		t.Fatalf("only 广东 without u1 = %v", got)
	}
	got = ids(Select(all, Selection{Areas: []string{AreaHKMOTW, AreaOverseas}, PointsPerGroup: 1}, 0))
	if !slices.Equal(got, []string{"h1", "o1"}) {
		t.Fatalf("hkmotw + overseas = %v", got)
	}
}

func TestSelectionValidate(t *testing.T) {
	if err := (Selection{PointsPerGroup: 3, Carriers: []string{CarrierEdu, CarrierBGP}}).Validate(); err != nil {
		t.Fatalf("valid selection refused: %v", err)
	}
	for _, bad := range []Selection{
		{PointsPerGroup: 0}, {PointsPerGroup: 21}, {PointsPerGroup: 1, Areas: []string{"mars"}},
		{PointsPerGroup: 1, Carriers: []string{"telecom", "telecom"}}, {PointsPerGroup: 1, IncludeProvinces: []string{"<x>"}},
	} {
		if bad.Validate() == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
}

func TestJudgeFailureCategories(t *testing.T) {
	for _, item := range []struct {
		kind    string
		result  Result
		expect  []string
		voted   bool
		ok      bool
		failure string
	}{
		{"tcping", Result{Status: "ok", AvgLatency: 12}, nil, true, true, FailureOK},
		{"tcping", Result{Status: "bad", ErrorCode: "tcp_connect_refused"}, nil, true, false, FailureRefused},
		{"tcping", Result{Status: "timeout", ErrorCode: "tcp_connect_timeout"}, nil, true, false, FailureTimeout},
		{"tcping", Result{Status: "unavailable"}, nil, false, false, ""},
		{"ping", Result{Status: "bad", ErrorCode: "icmp_timeout"}, nil, true, false, FailureTimeout},
		{"http", Result{Status: "bad", Error: "read tcp 1.2.3.4:5->6.7.8.9:443: read: connection reset by peer"}, nil, true, false, FailureReset},
		{"https", Result{Status: "bad", Error: "tls: failed to verify certificate: x509: certificate is valid for a.com"}, nil, true, false, FailureTLS},
		{"http", Result{Status: "bad", HTTPStatus: 502}, nil, true, false, FailureHTTP},
		{"http", Result{Status: "bad", HTTPStatus: 404}, nil, true, true, FailureOK},
		{"http", Result{Status: "bad", Error: "dial tcp: lookup a.example: no such host"}, nil, true, false, FailureDNS},
		{"dns", Result{Status: "ok", Values: []string{"1.1.1.1"}}, []string{"2.2.2.2"}, true, false, FailureDNS},
		{"dns", Result{Status: "ok", Values: []string{"1.1.1.1", "2.2.2.2"}}, []string{"2.2.2.2"}, true, true, FailureOK},
		{"dns", Result{Status: "bad", ErrorCode: "dns_timeout"}, nil, true, false, FailureTimeout},
		{"tcping", Result{Status: "bad", Error: "something odd"}, nil, true, false, FailureOther},
	} {
		voted, ok, failure := Judge(item.kind, item.result, item.expect)
		if voted != item.voted || ok != item.ok || failure != item.failure {
			t.Errorf("Judge(%s, %+v) = %v %v %q, want %v %v %q", item.kind, item.result, voted, ok, failure,
				item.voted, item.ok, item.failure)
		}
	}
	for _, code := range []string{FailureRefused, FailureTimeout, FailureReset, FailureTLS, FailureHTTP, FailureDNS, FailureOther} {
		if FailureTexts[code] == "" {
			t.Errorf("no Chinese text for %s", code)
		}
	}
}

func TestPlanBudgetDegradesByPriority(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC) // 10 days elapsed, 20 left
	purposes := []Purpose{
		{Name: PurposeNodeAvailability, Class: ClassAvailability, Enabled: true, Used: 1000},
		{Name: PurposeEdgeHealth, Class: ClassSchedule, Enabled: true, Used: 600},
		{Name: PurposeDiagnose, Class: ClassReport, Enabled: true, Used: 300, MonthlyCap: 300},
		{Name: PurposePlugin, Class: ClassSchedule, Enabled: false, Used: 0},
	}
	plan := PlanBudget(purposes, 0, 1900, now)
	if plan[PurposeEdgeHealth].Factor != 1 || plan[PurposeEdgeHealth].Stopped {
		t.Fatalf("unlimited account degraded edge: %+v", plan[PurposeEdgeHealth])
	}
	if !plan[PurposeDiagnose].Stopped || plan[PurposeDiagnose].Reason != "monthly_cap" {
		t.Fatalf("diagnose at cap: %+v", plan[PurposeDiagnose])
	}
	if !plan[PurposePlugin].Stopped || plan[PurposePlugin].Reason != "disabled" {
		t.Fatalf("disabled plugin: %+v", plan[PurposePlugin])
	}
	if got := plan[PurposeNodeAvailability].ProjectedMonthly; got != 3000 {
		t.Fatalf("projected node = %d, want 3000", got)
	}
	// Need: node 2000 + edge 1200 = 3200 for the rest of the month. Remaining 2900: schedule ×3 (400) fits.
	plan = PlanBudget(purposes, 4800, 1900, now)
	if plan[PurposeEdgeHealth].Factor != 3 || plan[PurposeNodeAvailability].Factor != 1 {
		t.Fatalf("remaining 2900: edge %+v node %+v", plan[PurposeEdgeHealth], plan[PurposeNodeAvailability])
	}
	// Remaining 2100: schedule stopped, availability untouched.
	plan = PlanBudget(purposes, 4000, 1900, now)
	if !plan[PurposeEdgeHealth].Stopped || plan[PurposeEdgeHealth].Reason != "account_budget" ||
		plan[PurposeNodeAvailability].Stopped || plan[PurposeNodeAvailability].Factor != 1 {
		t.Fatalf("remaining 2100: edge %+v node %+v", plan[PurposeEdgeHealth], plan[PurposeNodeAvailability])
	}
}
