package nodednspupprobe

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/google/uuid"
)

func TestRoundRecordsFailureAreaAndLine(t *testing.T) {
	settings := DefaultSettings()
	round := Round([]dnspupprobe.Result{
		{NodeID: "gd-cm-1", Region: "广东", ISP: "移动", Status: "timeout", ErrorCode: "tcp_connect_timeout"},
		{NodeID: "gd-ct-1", Region: "广东", ISP: "电信", Status: "ok", AvgLatency: 20},
		{NodeID: "bj-edu", Region: "北京", ISP: "教育网", Status: "bad", ErrorCode: "tcp_connect_refused"},
		{NodeID: "gone", Region: "上海", ISP: "联通", Status: "unavailable"},
	}, settings)
	// Groups telecom/unicom/mobile: the edu point is not in them, "gone" did not answer.
	if round.Total != 2 || round.Failed != 1 {
		t.Fatalf("legacy groups round = %+v", round)
	}
	if point := round.Checkpoints[0]; point.Failure != dnspupprobe.FailureTimeout || point.Area != dnspupprobe.AreaMainland ||
		point.Line != dnspupprobe.CarrierMobile || point.Province != "广东" || point.Carrier != "mobile" {
		t.Fatalf("checkpoint = %+v", point)
	}
	settings.Selection = &dnspupprobe.Selection{PointsPerGroup: 3}
	if round := Round([]dnspupprobe.Result{{NodeID: "bj-edu", Region: "北京", ISP: "教育网", Status: "bad",
		ErrorCode: "tcp_connect_refused"}}, settings); round.Total != 1 || round.Checkpoints[0].Line != dnspupprobe.CarrierEdu ||
		round.Checkpoints[0].Failure != dnspupprobe.FailureRefused {
		t.Fatalf("selection round = %+v", round)
	}
	settings.ProbeType = ProbeHTTP
	if round := Round([]dnspupprobe.Result{{NodeID: "gd-ct-1", Region: "广东", ISP: "电信", Status: "bad", HTTPStatus: 503}},
		settings); round.Failed != 0 || round.Total != 1 {
		t.Fatalf("http: any answer is reachable, got %+v", round)
	}
}

func TestLineCellsAlertThresholdAndText(t *testing.T) {
	settings := DefaultSettings() // min 3 points, > 50 %
	point := func(id string, ok bool, address int) RoundResult {
		return RoundResult{Checkpoints: []Checkpoint{{ID: id, Area: dnspupprobe.AreaMainland, Region: "cn", Province: "广东",
			Line: dnspupprobe.CarrierMobile, OK: ok, Failure: map[bool]string{false: dnspupprobe.FailureTimeout}[ok]}}}
	}
	rounds := []RoundResult{point("a", false, 1), point("b", false, 1), point("c", false, 1), point("d", true, 1),
		// a answers on the node's second address: it is not a failed point.
		point("a", true, 2)}
	cells := LineCells(rounds)
	cell := cells[[2]string{dnspupprobe.CarrierMobile, "广东"}]
	if cell == nil || cell.Total != 4 || cell.Failed != 2 || cell.Failing(settings) {
		t.Fatalf("cell = %+v", cell)
	}
	cells = LineCells(rounds[:4])
	cell = cells[[2]string{dnspupprobe.CarrierMobile, "广东"}]
	if !cell.Failing(settings) || cell.TopFailure() != dnspupprobe.FailureTimeout || !slices.Equal(cell.FailedIDs, []string{"a", "b", "c"}) {
		t.Fatalf("failing cell = %+v", cell)
	}
	if got := LineText(dnspupprobe.CarrierMobile, "广东"); got != "移动 · 广东" {
		t.Fatalf("LineText = %q", got)
	}
	if got := LineText(dnspupprobe.CarrierOther, "hk"); got != "其他运营商 · 香港" {
		t.Fatalf("LineText hk = %q", got)
	}
}

func TestEffectiveOverrideOrder(t *testing.T) {
	global := DefaultSettings()
	node, groupA, groupB := uuid.New(), uuid.MustParse("00000000-0000-0000-0000-00000000000a"),
		uuid.MustParse("00000000-0000-0000-0000-00000000000b")
	ping, http := ProbePing, ProbeHTTP
	edu := &dnspupprobe.Selection{Carriers: []string{dnspupprobe.CarrierEdu}, PointsPerGroup: 2}
	overrides := []Override{
		{SubjectKind: "line_group", LineGroupID: &groupB, ProbeType: &http},
		{SubjectKind: "line_group", LineGroupID: &groupA, ProbeType: &ping},
		{SubjectKind: "node", NodeID: &node, Selection: edu},
	}
	value, source := Effective(global, overrides, uuid.New(), []uuid.UUID{groupB, groupA})
	if value.ProbeType != ProbePing || source != "line_group:"+groupA.String() || value.Selection != nil {
		t.Fatalf("smallest line group wins: %+v %s", value, source)
	}
	value, source = Effective(global, overrides, node, []uuid.UUID{groupB})
	if value.ProbeType != ProbeHTTP || value.Selection != edu || source != "node" {
		t.Fatalf("node override on top of its group: %+v %s", value, source)
	}
	if value, source = Effective(global, nil, node, nil); value.ProbeType != ProbeTCPing || source != "global" {
		t.Fatalf("global: %+v %s", value, source)
	}
}

func TestRequestOfProbeTypes(t *testing.T) {
	target := Target{Address: netip.MustParseAddr("203.0.113.9"), Port: 8443}
	if request := requestOf(target, ProbeTCPing, []string{"x"}); request.Type != "tcping" || request.Port != 8443 ||
		request.Target != "203.0.113.9" {
		t.Fatalf("tcping = %+v", request)
	}
	if request := requestOf(target, ProbePing, nil); request.Type != "ping" || request.Port != 0 || request.Count != 4 {
		t.Fatalf("ping = %+v", request)
	}
	if request := requestOf(target, ProbeHTTP, nil); request.Type != "http" || request.Target != "http://203.0.113.9:8443/" {
		t.Fatalf("http = %+v", request)
	}
	v6 := Target{Address: netip.MustParseAddr("2001:db8::1"), Port: 80}
	if request := requestOf(v6, ProbeHTTP, nil); request.IPVersion != "6" || request.Target != "http://[2001:db8::1]:80/" {
		t.Fatalf("http v6 = %+v", request)
	}
}

func TestValidateProbePlusFields(t *testing.T) {
	value := DefaultSettings()
	if err := Validate(value); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	for _, change := range []func(*Settings){
		func(s *Settings) { s.ProbeType = "https" },
		func(s *Settings) { s.LineAlertMinPoints = 0 },
		func(s *Settings) { s.LineAlertRounds = 11 },
		func(s *Settings) { s.Selection = &dnspupprobe.Selection{PointsPerGroup: 0} },
	} {
		bad := DefaultSettings()
		change(&bad)
		if Validate(bad) == nil {
			t.Errorf("Validate accepted %+v", bad)
		}
	}
}
