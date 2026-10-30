package autodefense

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func testReports() map[string]Report {
	base := Report{Schema: ReportSchema, NodeID: testNode, SiteID: testSite, TenantID: testTenant, Seq: 5, At: testNow, Revision: 3}
	minute := base
	minute.Kind = ReportMinute
	minute.Minute = &Minute{Minute: testNow - testNow%60, Counts: map[string]int64{"requests": 1200, "status_5xx": 3},
		Values:   map[string]int64{"request_rate": 20000, "unique_ip": 40000},
		Sketches: []Sketch{{Name: "count_min_ip", Format: "cm2048x4/v1", State: []byte{1, 2}}, {Name: "unique_ip", Format: "hll12/v1", State: []byte{3}}},
		TopK:     []TopK{{Feature: "ja4", Values: []Count{{Value: testJA4, Count: 900}}, Tail: 300}}}
	state := base
	state.Kind = ReportState
	state.State = &StateChange{From: StateNormal, To: StateAttack, Level: LevelChallenge, Reason: "request_rate z=9.1"}
	candidate := base
	candidate.Kind = ReportCandidate
	site := testSiteState(testSite)
	site.canonical()
	signature := site.Signatures[0]
	signature.Stage = StageShadow
	candidate.Candidate = &signature
	verdicts := base
	verdicts.Kind = ReportVerdicts
	verdicts.Verdicts = []Verdict{{Kind: TargetIP, Target: "198.51.100.7", Score: 85, Level: LevelBan, Until: testNow + 600, Reason: "rate_outlier"}}
	adjust := base
	adjust.Kind = ReportAdjust
	adjust.Adjustment = []Adjustment{{Module: ModuleCC, Field: "cc.per_ip_requests", From: 100, To: 40, Reason: "baseline p99 x 1.5"},
		{Module: ModuleCC, Field: "cc.ban_seconds", From: 600, To: 1200, Reason: "state=attack", FrozenUntil: testNow + 3600},
		{Module: ModuleCC, Field: "cc.challenge", From: 0, To: 1, Reason: "state=attack", Suggest: true}}
	l4 := Report{Schema: ReportSchema, NodeID: testNode, PortGroup: "tcp-443", Seq: 1, At: testNow, Kind: ReportAdjust,
		Adjustment: []Adjustment{{Module: ModuleL4, Field: "l4.syn_tier", From: 0, To: 1, Reason: "syn_rate z=12"}}}
	event := Report{Schema: ReportSchema, NodeID: testNode, Seq: 1, At: testNow, Kind: ReportNodeEvent,
		NodeEvent: &NodeEvent{Source: "ddos", Kind: "empty_connection_ban", Client: "198.51.100.7", Count: 12, DurationSeconds: 600,
			Level: LevelKernel, Reason: "empty_connections"}}
	cc := Report{Schema: ReportSchema, NodeID: testNode, Seq: 1, At: testNow, Kind: ReportCCStats, CCStats: []CCStat{
		{TenantID: testTenant, SiteID: testSite, PolicyID: testSite2, PolicyVersion: 2, RuleID: testNode, Minute: testNow - testNow%60,
			Matched: 40, Triggered: 7, Challenged: 5, Blocked: 2, Passed: 30,
			TopClients: []Count{{Value: "198.51.100.7", Count: 6}, {Value: "2001:db8::1", Count: 1}},
			TopPaths:   []Count{{Value: "/a", Count: 7}}},
		{TenantID: testTenant, SiteID: testSite, PolicyID: testSite2, PolicyVersion: 2, Minute: testNow - testNow%60, Passed: 3,
			TopClients: []Count{}, TopPaths: []Count{}},
	}}
	drift := base
	drift.Kind = ReportDrift
	drift.Drift = &Drift{Metrics: []string{"ratio_404", "request_rate"}, Days: 3}
	rate := event
	rate.NodeEvent = &NodeEvent{Source: "ddos", Kind: "rate_ban", Client: "198.51.100.8", Count: 1, DurationSeconds: 600,
		Level: LevelKernel, Reason: "new_connection_rate"}
	return map[string]Report{"minute": minute, "state": state, "candidate": candidate, "verdicts": verdicts, "adjust": adjust, "l4": l4,
		"node_event": event, "rate_ban": rate, "drift": drift, "cc_stats": cc}
}

func TestReportRoundTrip(t *testing.T) {
	for name, report := range testReports() {
		encoded, err := EncodeReport(report)
		if err != nil {
			t.Fatalf("%s: encode: %v", name, err)
		}
		decoded, err := DecodeReport(encoded)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		again, _ := json.Marshal(decoded)
		if !bytes.Equal(again, encoded) {
			t.Errorf("%s: round trip differs", name)
		}
	}
}

func TestReportRejects(t *testing.T) {
	cases := map[string]struct {
		base   string
		mutate func(*Report)
	}{
		"schema":            {"state", func(r *Report) { r.Schema = Schema }},
		"frozen suggestion": {"adjust", func(r *Report) { r.Adjustment[0].Suggest, r.Adjustment[0].FrozenUntil = true, r.At+60 }},
		"frozen past":       {"adjust", func(r *Report) { r.Adjustment[0].FrozenUntil = r.At }},
		"frozen too long":   {"adjust", func(r *Report) { r.Adjustment[0].FrozenUntil = r.At + 3601 }},
		"seq zero":          {"state", func(r *Report) { r.Seq = 0 }},
		"two payloads":      {"state", func(r *Report) { r.Verdicts = testReports()["verdicts"].Verdicts }},
		"kind mismatch":     {"state", func(r *Report) { r.Kind = ReportMinute }},
		"no tenant":         {"state", func(r *Report) { r.TenantID = "" }},
		"site and group":    {"state", func(r *Report) { r.PortGroup = "tcp-443" }},
		"same state":        {"state", func(r *Report) { r.State.To = StateNormal }},
		"unknown state":     {"state", func(r *Report) { r.State.To = "panic" }},
		"minute misaligned": {"minute", func(r *Report) { r.Minute.Minute++ }},
		"minute feature":    {"minute", func(r *Report) { r.Minute.Values["syn_rate"] = 1 }},
		"sketch format":     {"minute", func(r *Report) { r.Minute.Sketches[0].Format = "hll" }},
		"sketch order":      {"minute", func(r *Report) { s := r.Minute.Sketches; s[0], s[1] = s[1], s[0] }},
		"sketch empty":      {"minute", func(r *Report) { r.Minute.Sketches[0].State = nil }},
		"topk feature":      {"minute", func(r *Report) { r.Minute.TopK[0].Feature = "host" }},
		"candidate stage":   {"candidate", func(r *Report) { r.Candidate.Stage = StageBlock }},
		"candidate origin":  {"candidate", func(r *Report) { r.Candidate.OriginNodeID = testSite2 }},
		"verdict below L2":  {"verdicts", func(r *Report) { r.Verdicts[0].Level = LevelChallenge }},
		"verdict until":     {"verdicts", func(r *Report) { r.Verdicts[0].Until = testNow }},
		"verdict target":    {"verdicts", func(r *Report) { r.Verdicts[0].Target = "198.51.100.07" }},
		"adjust same":       {"adjust", func(r *Report) { r.Adjustment[0].To = 100 }},
		"adjust module":     {"adjust", func(r *Report) { r.Adjustment[0].Module = ModuleWAF }},
		"adjust beyond":     {"adjust", func(r *Report) { r.Adjustment[0].To = 0 }},
		"l4 adjust on site": {"l4", func(r *Report) { r.SiteID, r.TenantID, r.PortGroup = testSite, testTenant, "" }},
		"event on site":     {"node_event", func(r *Report) { r.SiteID, r.TenantID = testSite, testTenant }},
		"event port group":  {"node_event", func(r *Report) { r.PortGroup = "tcp-443" }},
		"event source":      {"node_event", func(r *Report) { r.NodeEvent.Source = "x" }},
		"event client":      {"node_event", func(r *Report) { r.NodeEvent.Client = "198.51.100.07" }},
		"event duration":    {"node_event", func(r *Report) { r.NodeEvent.DurationSeconds = MaxMitigationSeconds + 1 }},
		"event payload":     {"node_event", func(r *Report) { r.NodeEvent = nil }},
		"event on verdicts": {"verdicts", func(r *Report) { r.NodeEvent = testReports()["node_event"].NodeEvent }},
		"cc on site":        {"cc_stats", func(r *Report) { r.SiteID, r.TenantID = testSite, testTenant }},
		"cc empty":          {"cc_stats", func(r *Report) { r.CCStats = []CCStat{} }},
		"cc on state":       {"state", func(r *Report) { r.CCStats = testReports()["cc_stats"].CCStats }},
		"cc duplicate key":  {"cc_stats", func(r *Report) { r.CCStats[1].RuleID = testNode }},
		"cc rule id":        {"cc_stats", func(r *Report) { r.CCStats[0].RuleID = "r1" }},
		"cc policy version": {"cc_stats", func(r *Report) { r.CCStats[0].PolicyVersion = 0 }},
		"cc minute":         {"cc_stats", func(r *Report) { r.CCStats[0].Minute++ }},
		"cc future minute":  {"cc_stats", func(r *Report) { r.CCStats[0].Minute = testNow - testNow%60 + 60 }},
		"cc all zero":       {"cc_stats", func(r *Report) { r.CCStats[1].Passed = 0 }},
		"cc nil top":        {"cc_stats", func(r *Report) { r.CCStats[1].TopPaths = nil }},
		"cc top order":      {"cc_stats", func(r *Report) { t := r.CCStats[0].TopClients; t[0], t[1] = t[1], t[0] }},
		"cc top over":       {"cc_stats", func(r *Report) { r.CCStats[0].TopPaths[0].Count = 8 }},
		"cc top client":     {"cc_stats", func(r *Report) { r.CCStats[0].TopClients[0].Value = "198.51.100.07" }},
		"cc top path":       {"cc_stats", func(r *Report) { r.CCStats[0].TopPaths[0].Value = "a" }},
		"cc negative":       {"cc_stats", func(r *Report) { r.CCStats[0].Blocked = -1 }},
		"drift no site":     {"drift", func(r *Report) { r.SiteID, r.TenantID, r.PortGroup = "", "", "tcp-443" }},
		"drift metric":      {"drift", func(r *Report) { r.Drift.Metrics = []string{"syn_rate"} }},
		"drift order":       {"drift", func(r *Report) { r.Drift.Metrics = []string{"request_rate", "ratio_404"} }},
		"drift empty":       {"drift", func(r *Report) { r.Drift.Metrics = nil }},
		"drift days":        {"drift", func(r *Report) { r.Drift.Days = 0 }},
		"drift payload":     {"drift", func(r *Report) { r.Drift = nil }},
		"drift on state":    {"state", func(r *Report) { r.Drift = testReports()["drift"].Drift }},
	}
	for name, test := range cases {
		report := clone(t, testReports()[test.base])
		test.mutate(&report)
		if _, err := EncodeReport(report); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted", name)
		}
	}
	encoded, _ := EncodeReport(testReports()["state"])
	for name, bad := range map[string][]byte{
		"unknown field": bytes.Replace(encoded, []byte(`{"schema"`), []byte(`{"x":1,"schema"`), 1),
		"trailing":      append(append([]byte(nil), encoded...), '1'),
		"empty":         nil,
	} {
		if _, err := DecodeReport(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("decode %s: accepted", name)
		}
	}
}

func clone(t *testing.T, report Report) Report {
	t.Helper()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var out Report
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func testFrame() Frame {
	return Frame{Schema: FrameSchema, Worker: 2, PID: 4321, Second: testNow, Revision: 3, Sites: []FrameSite{{
		SiteID: testSite, Requests: 100, Status2xx: 90, Status4xx: 10, Status404: 4, Bytes: 123456,
		Latency: make([]int64, LatencyBuckets), Challenged: 3, ChallengePass: 1,
		SignatureHits: map[string]int64{"0123456789abcdef": 7},
		IPs:           map[string]int64{"198.51.100.7": 60, "2001:db8::1": 40},
		Behavior: []FrameBehavior{{Client: "198.51.100.7", Requests: 60, IntervalN: 59, IntervalAvg: 16000, IntervalM2: 1000,
			Paths: 1, NoReferer: 60, NoCookie: 60}},
		Samples: []FrameSample{{Client: "198.51.100.7", CIDR: "198.51.100.0/24", ASN: "4134", Tags: []string{"idc"}, Country: "CN",
			JA4: testJA4, UAFamily: "chrome", UAHash: "0123456789abcdef", PathTemplate: "/api/search", QueryNamesHash: "0011223344556677",
			QueryEntropy: 3, Method: "GET", HTTPVersion: "2", HeaderOrderHash: "8899aabbccddeeff", Missing: []string{"referer"},
			Status: 200, CacheStatus: "MISS", BytesBucket: 10}},
	}}}
}

func TestFrameDecode(t *testing.T) {
	encoded, err := json.Marshal(testFrame())
	if err != nil {
		t.Fatal(err)
	}
	frame, err := DecodeFrame(encoded)
	if err != nil || frame.Sites[0].IPs["2001:db8::1"] != 40 {
		t.Fatalf("decode: %v", err)
	}
	cases := map[string]func(*Frame){
		"schema":        func(f *Frame) { f.Schema = Schema },
		"pid":           func(f *Frame) { f.PID = 0 },
		"sites nil":     func(f *Frame) { f.Sites = nil },
		"duplicate":     func(f *Frame) { f.Sites = append(f.Sites, f.Sites[0]) },
		"latency size":  func(f *Frame) { f.Sites[0].Latency = f.Sites[0].Latency[:15] },
		"404 over 4xx":  func(f *Frame) { f.Sites[0].Status404 = 11 },
		"ip not canon":  func(f *Frame) { f.Sites[0].IPs["::ffff:1.2.3.4"] = 1 },
		"signature id":  func(f *Frame) { f.Sites[0].SignatureHits["xyz"] = 1 },
		"negative":      func(f *Frame) { f.Sites[0].Requests = -1 },
		"sample cidr":   func(f *Frame) { f.Sites[0].Samples[0].CIDR = "198.51.100.0/25" },
		"sample status": func(f *Frame) { f.Sites[0].Samples[0].Status = 99 },
		"sample tag":    func(f *Frame) { f.Sites[0].Samples[0].Tags = []string{"IDC"} },
		"sample ja4":    func(f *Frame) { f.Sites[0].Samples[0].JA4 = "bogus" },
		"missing hdr":   func(f *Frame) { f.Sites[0].Samples[0].Missing = []string{"host"} },
		"behavior ip":   func(f *Frame) { f.Sites[0].Behavior[0].Client = "x" },
	}
	for name, mutate := range cases {
		frame := testFrame()
		mutate(&frame)
		encoded, _ := json.Marshal(frame)
		if _, err := DecodeFrame(encoded); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted", name)
		}
	}
	// QUIC: JA4 empty is accepted.
	frame = testFrame()
	frame.Sites[0].Samples[0].JA4 = ""
	encoded, _ = json.Marshal(frame)
	if _, err := DecodeFrame(encoded); err != nil {
		t.Errorf("empty ja4 rejected: %v", err)
	}
	if _, err := DecodeFrame(append(encoded, []byte(`{}`)...)); !errors.Is(err, ErrInvalid) {
		t.Error("trailing frame accepted")
	}
}
