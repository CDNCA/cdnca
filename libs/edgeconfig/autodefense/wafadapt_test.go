package autodefense

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func testParam(location, name string) WAFParam { return WAFParam{Location: location, Name: name} }

func testExclusion(rule int64, param WAFParam, stage string) WAFExclusion {
	return WAFExclusion{ID: WAFExclusionID(rule, param), Rule: rule, Param: param, Stage: stage, Since: testNow - 3600, Until: testNow + 30*86400}
}

// rankActive ranks the active exclusions 1..n in list order (the control
// plane ranks by value; any permutation is valid).
func rankActive(exclusions []WAFExclusion) []WAFExclusion {
	rank := 0
	for index := range exclusions {
		if exclusions[index].Stage == WAFExclusionActive {
			rank++
			exclusions[index].Rank = rank
		}
	}
	return exclusions
}

func testWAFAdapt() *WAFAdapt {
	return &WAFAdapt{GreyChallenge: true,
		Exclusions: rankActive([]WAFExclusion{testExclusion(942100, testParam("args", "json.q"), WAFExclusionActive),
			testExclusion(942100, testParam("args", "q"), WAFExclusionShadow),
			testExclusion(942430, testParam("cookie", "session"), WAFExclusionActive)}),
		TypedParams: []WAFTypedParam{{Key: WAFParamKey("/item/{n}", "args", "id"), Type: "number", MaxLenBucket: 4, Charset: 0},
			{Key: WAFParamKey("", "args", "token"), Type: "ident", MaxLenBucket: 6, Charset: 0}}}
}

func testWAFEvidenceReport() Report {
	key := WAFParamKey("/search", "args", "q")
	return Report{Schema: ReportSchema, Kind: ReportWAFEvidence, NodeID: testNode, SiteID: testSite, TenantID: testTenant, Seq: 9,
		At: testNow, Revision: 3, WAFEvidence: &WAFEvidence{Hour: testNow - testNow%3600,
			Pack: WAFPackRef{PackID: "system/crs-pl2", Version: "1.2.0"},
			Items: []WAFEvidenceItem{
				{Key: key, Param: testParam("args", "q"), Type: "text", LenBucket: 5, Charset: 1<<0 | 1<<9, Rule: 942430, Hits: 512,
					Sources: "00ff00ff00ff00ff", Days: 0b1111, Challenged: 300, Passed: 291, FailedSources: 2, Clean: 498, StageHint: "candidate"},
				{Key: key, Param: testParam("args", "q"), Type: "text", LenBucket: 5, Charset: 1, Rule: 942440, Hits: 3,
					Sources: "0000000000000001", Days: 1, StageHint: "observe"},
			},
			Tighten:    []WAFTightenState{{Set: "crs_sqli", Reason: "attack_ratio", Since: testNow - 600}},
			Exclusions: []WAFExclusionResult{{ID: WAFExclusionID(942100, testParam("args", "q")), Flipped: 88}}}}
}

func TestWAFEvidenceRoundTrip(t *testing.T) {
	report := testWAFEvidenceReport()
	encoded, err := EncodeReport(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReport(encoded)
	if err != nil || !reflect.DeepEqual(decoded, report) {
		t.Fatalf("decode: %+v %v", decoded, err)
	}
	for _, forbidden := range []string{"198.51.100", "value", "user_agent", "/search"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("evidence carries %q", forbidden)
		}
	}
	// only tighten / exclusion results: still a report
	report.WAFEvidence.Items = []WAFEvidenceItem{}
	if _, err := EncodeReport(report); err != nil {
		t.Fatalf("no items: %v", err)
	}
}

func TestWAFEvidenceRejects(t *testing.T) {
	cases := map[string]func(*Report){
		"no payload":        func(r *Report) { r.WAFEvidence = nil },
		"node scope":        func(r *Report) { r.SiteID, r.TenantID = "", "" },
		"port group":        func(r *Report) { r.SiteID, r.TenantID, r.PortGroup = "", "", "tcp-443" },
		"second payload":    func(r *Report) { r.Drift = &Drift{Metrics: []string{"ratio_404"}, Days: 1} },
		"on other kind":     func(r *Report) { r.Kind = ReportDrift; r.Drift = &Drift{Metrics: []string{"ratio_404"}, Days: 1} },
		"hour unaligned":    func(r *Report) { r.WAFEvidence.Hour++ },
		"hour future":       func(r *Report) { r.WAFEvidence.Hour = r.At - r.At%3600 + 3600 },
		"pack":              func(r *Report) { r.WAFEvidence.Pack.PackID = "system/sqli" },
		"pack version":      func(r *Report) { r.WAFEvidence.Pack.Version = "1.3" },
		"empty":             func(r *Report) { r.WAFEvidence.Items, r.WAFEvidence.Tighten, r.WAFEvidence.Exclusions = nil, nil, nil },
		"items nil":         func(r *Report) { r.WAFEvidence.Items = nil },
		"key low half":      func(r *Report) { r.WAFEvidence.Items[0].Key = r.WAFEvidence.Items[0].Key[:8] + "00000000" },
		"key upper":         func(r *Report) { r.WAFEvidence.Items[0].Key = strings.ToUpper(r.WAFEvidence.Items[0].Key) },
		"location":          func(r *Report) { r.WAFEvidence.Items[0].Param.Location = "query" },
		"name space":        func(r *Report) { r.WAFEvidence.Items[0].Param.Name = "a b" },
		"name long":         func(r *Report) { r.WAFEvidence.Items[0].Param.Name = strings.Repeat("a", 65) },
		"type":              func(r *Report) { r.WAFEvidence.Items[0].Type = "free_text" },
		"len bucket":        func(r *Report) { r.WAFEvidence.Items[0].LenBucket = WAFLenBuckets },
		"charset":           func(r *Report) { r.WAFEvidence.Items[0].Charset = WAFCharsetMask + 1 },
		"rule":              func(r *Report) { r.WAFEvidence.Items[0].Rule = 42430 },
		"hits zero":         func(r *Report) { r.WAFEvidence.Items[0].Hits = 0 },
		"sources":           func(r *Report) { r.WAFEvidence.Items[0].Sources = "xyz" },
		"days zero":         func(r *Report) { r.WAFEvidence.Items[0].Days = 0 },
		"days wide":         func(r *Report) { r.WAFEvidence.Items[0].Days = 1 << MaxWAFRuleDays },
		"passed over hits":  func(r *Report) { r.WAFEvidence.Items[0].Passed = 513 },
		"failed over chall": func(r *Report) { r.WAFEvidence.Items[0].FailedSources = 301 },
		"stage hint":        func(r *Report) { r.WAFEvidence.Items[0].StageHint = "shadow" },
		"item order": func(r *Report) {
			r.WAFEvidence.Items[0], r.WAFEvidence.Items[1] = r.WAFEvidence.Items[1], r.WAFEvidence.Items[0]
		},
		"item twice":       func(r *Report) { r.WAFEvidence.Items[1] = r.WAFEvidence.Items[0] },
		"tighten set":      func(r *Report) { r.WAFEvidence.Tighten[0].Set = "waf_set:crs_sqli" },
		"tighten reason":   func(r *Report) { r.WAFEvidence.Tighten[0].Reason = "manual" },
		"tighten future":   func(r *Report) { r.WAFEvidence.Tighten[0].Since = r.At + 1 },
		"exclusion id":     func(r *Report) { r.WAFEvidence.Exclusions[0].ID = "x" },
		"attack over flip": func(r *Report) { r.WAFEvidence.Exclusions[0].AttackAfter = 89 },
		"dropped":          func(r *Report) { r.WAFEvidence.Dropped = -1 },
	}
	for name, mutate := range cases {
		report := testWAFEvidenceReport()
		evidence := *report.WAFEvidence
		evidence.Items = append([]WAFEvidenceItem(nil), evidence.Items...)
		evidence.Tighten = append([]WAFTightenState(nil), evidence.Tighten...)
		evidence.Exclusions = append([]WAFExclusionResult(nil), evidence.Exclusions...)
		report.WAFEvidence = &evidence
		mutate(&report)
		if err := ValidateReport(report); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted", name)
		}
	}
	// unknown field
	encoded, _ := EncodeReport(testWAFEvidenceReport())
	bad := bytes.Replace(encoded, []byte(`"dropped":0`), []byte(`"dropped":0,"value":"x"`), 1)
	if _, err := DecodeReport(bad); !errors.Is(err, ErrInvalid) {
		t.Error("unknown field accepted")
	}
}

// TestWAFEvidenceBounds: 128 items, 10 tightened sets and 64 exclusion
// results, all at their longest, encode within MaxWAFEvidenceBytes; one
// more of each list is refused.
// fullWAFEvidenceReport has every list of the evidence at its bound, names at full length.
func fullWAFEvidenceReport() Report {
	report := testWAFEvidenceReport()
	evidence := report.WAFEvidence
	evidence.Items, evidence.Tighten, evidence.Exclusions = nil, nil, nil
	for index := 0; index < MaxWAFEvidenceItems; index++ {
		param := testParam("header", fmt.Sprintf("%s%03d", strings.Repeat("h", 61), index))
		evidence.Items = append(evidence.Items, WAFEvidenceItem{Key: WAFParamKey("", param.Location, param.Name), Param: param,
			Type: "binary", LenBucket: 7, Charset: WAFCharsetMask, Rule: 999999, Hits: MaxValue, Sources: "ffffffffffffffff",
			Days: 1<<MaxWAFRuleDays - 1, Challenged: MaxValue, Passed: MaxValue, FailedSources: MaxValue, Clean: MaxValue,
			AttackAfter: MaxValue, StageHint: "candidate"})
	}
	sort.Slice(evidence.Items, func(i, j int) bool { return evidence.Items[i].Key < evidence.Items[j].Key })
	for index := 0; index < MaxWAFEvidenceTighten; index++ {
		evidence.Tighten = append(evidence.Tighten, WAFTightenState{Set: fmt.Sprintf("%s%02d", strings.Repeat("s", 62), index),
			Reason: "challenge_failed", Since: testNow})
	}
	for index := 0; index < MaxWAFEvidenceExclusions; index++ {
		evidence.Exclusions = append(evidence.Exclusions, WAFExclusionResult{ID: fmt.Sprintf("%016x", index), Flipped: MaxValue,
			AttackAfter: MaxValue, Paused: true})
	}
	for index := 0; index < MaxWAFCookieNames; index++ {
		evidence.Cookies = append(evidence.Cookies, WAFCookieSample{Key: fmt.Sprintf("00000000%08x", index), Type: "binary",
			LenBucket: 7, Charset: WAFCharsetMask, Seen: MaxValue, Sources: "ffffffffffffffff"})
	}
	evidence.CookieSamples = MaxValue
	for index := 0; index < MaxWAFHeaderNames; index++ {
		evidence.Headers = append(evidence.Headers, WAFCookieSample{Key: fmt.Sprintf("00000000%08x", index), Type: "binary",
			LenBucket: 7, Charset: WAFCharsetMask, Seen: MaxValue, Sources: "ffffffffffffffff"})
	}
	evidence.Dropped = MaxValue
	return report
}

func TestWAFEvidenceBounds(t *testing.T) {
	report := fullWAFEvidenceReport()
	encoded, err := EncodeReport(report)
	if err != nil || len(encoded) > MaxWAFEvidenceBytes {
		t.Fatalf("full evidence: %d bytes: %v", len(encoded), err)
	}
	t.Logf("full waf_evidence: %d bytes", len(encoded))
	if _, err := DecodeReport(encoded); err != nil {
		t.Fatal(err)
	}
	over := clone(t, report)
	last := over.WAFEvidence.Items[len(over.WAFEvidence.Items)-1]
	last.Rule = 999998
	over.WAFEvidence.Items = append(over.WAFEvidence.Items, last)
	sort.Slice(over.WAFEvidence.Items, func(i, j int) bool {
		a, b := over.WAFEvidence.Items[i], over.WAFEvidence.Items[j]
		return a.Key < b.Key || a.Key == b.Key && a.Rule < b.Rule
	})
	if ValidateReport(over) == nil {
		t.Error("129 items accepted")
	}
	over = clone(t, report)
	over.WAFEvidence.Tighten = append(over.WAFEvidence.Tighten, WAFTightenState{Set: "zz", Reason: "attack_ratio", Since: testNow})
	if ValidateReport(over) == nil {
		t.Error("11 tightened sets accepted")
	}
	over = clone(t, report)
	over.WAFEvidence.Cookies = append(over.WAFEvidence.Cookies, WAFCookieSample{Key: "00000000ffffffff", Type: "text", Seen: 1,
		Sources: "0000000000000001"})
	if ValidateReport(over) == nil {
		t.Error("65 cookies accepted")
	}
	over = clone(t, report)
	over.WAFEvidence.Headers = append(over.WAFEvidence.Headers, WAFCookieSample{Key: "00000000ffffffff", Type: "text", Seen: 1,
		Sources: "0000000000000001"})
	if ValidateReport(over) == nil {
		t.Error("33 headers accepted")
	}
	over = clone(t, report)
	over.WAFEvidence.Exclusions = append(over.WAFEvidence.Exclusions, WAFExclusionResult{ID: "ffffffffffffffff"})
	if ValidateReport(over) == nil {
		t.Error("65 exclusion results accepted")
	}
	// a report over the byte bound is refused
	big := []byte(strings.Replace(string(encoded), `"dropped":`, strings.Repeat(" ", MaxWAFEvidenceBytes)+`"dropped":`, 1))
	if _, err := DecodeReport(big); !errors.Is(err, ErrInvalid) {
		t.Error("evidence over the byte bound decoded")
	}
}

func TestWAFAdaptSnapshot(t *testing.T) {
	public, private := testKey(t)
	snapshot := testSnapshot()
	snapshot.Sites[1].WAFAdapt = testWAFAdapt()
	// shuffled lists: Canonical orders them
	adapt := snapshot.Sites[1].WAFAdapt
	adapt.Exclusions[0], adapt.Exclusions[2] = adapt.Exclusions[2], adapt.Exclusions[0]
	adapt.TypedParams[0], adapt.TypedParams[1] = adapt.TypedParams[1], adapt.TypedParams[0]
	encoded, err := Sign(snapshot, testKeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(encoded, testNode, trusted(public))
	if err != nil {
		t.Fatal(err)
	}
	var site Site
	for _, candidate := range opened.Sites {
		if candidate.WAFAdapt != nil {
			site = candidate
		}
	}
	if site.WAFAdapt == nil || site.WAFAdapt.Exclusions[0].Param.Name != "json.q" {
		t.Fatalf("waf_adapt %+v", site.WAFAdapt)
	}
	want := []edgeconfig.DynamicWAFTarget{{Rule: 942100, Location: "args", Name: "json.q"}, {Rule: 942430, Location: "cookie", Name: "session"}}
	if got := site.WAFAdapt.ActiveTargets(testNow); !reflect.DeepEqual(got, want) {
		t.Fatalf("active targets %+v", got)
	}
	if got := site.WAFAdapt.ActiveTargets(testNow + 31*86400); len(got) != 0 {
		t.Fatalf("expired exclusions still active: %+v", got)
	}
	// a site without waf_adapt does not carry the key
	if bytes.Count(encoded, []byte(`"waf_adapt"`)) != 1 {
		t.Fatal("waf_adapt on a site that has none")
	}
}

func TestWAFAdaptRejects(t *testing.T) {
	cases := map[string]func(*WAFAdapt){
		"id":             func(a *WAFAdapt) { a.Exclusions[0].ID = "0000000000000000" },
		"rule":           func(a *WAFAdapt) { a.Exclusions[0].Rule = 42100 },
		"location":       func(a *WAFAdapt) { a.Exclusions[0].Param.Location = "body" },
		"name":           func(a *WAFAdapt) { a.Exclusions[0].Param.Name = "q%20" },
		"stage":          func(a *WAFAdapt) { a.Exclusions[0].Stage = "candidate" },
		"until":          func(a *WAFAdapt) { a.Exclusions[0].Until = a.Exclusions[0].Since },
		"span":           func(a *WAFAdapt) { a.Exclusions[0].Until = a.Exclusions[0].Since + maxWAFExclusionSeconds + 1 },
		"order":          func(a *WAFAdapt) { a.Exclusions[0], a.Exclusions[1] = a.Exclusions[1], a.Exclusions[0] },
		"twice":          func(a *WAFAdapt) { a.Exclusions[1] = a.Exclusions[0] },
		"typed key":      func(a *WAFAdapt) { a.TypedParams[0].Key = "x" },
		"typed text":     func(a *WAFAdapt) { a.TypedParams[0].Type = "text" },
		"typed len":      func(a *WAFAdapt) { a.TypedParams[0].MaxLenBucket = 8 },
		"typed charset":  func(a *WAFAdapt) { a.TypedParams[0].Charset = -1 },
		"typed order":    func(a *WAFAdapt) { a.TypedParams[0], a.TypedParams[1] = a.TypedParams[1], a.TypedParams[0] },
		"too many typed": func(a *WAFAdapt) { a.TypedParams = make([]WAFTypedParam, MaxWAFTypedParams+1) },
		"too many active": func(a *WAFAdapt) {
			a.Exclusions = manyExclusions(edgeconfig.DynamicWAFMaxTargets+1, WAFExclusionActive)
		},
		"too many":              func(a *WAFAdapt) { a.Exclusions = manyExclusions(MaxWAFAdaptExclusions+1, WAFExclusionShadow) },
		"grey floor":            func(a *WAFAdapt) { a.GreyFloor = edgeconfig.DynamicWAFMaxGreyFloor + 1 },
		"negative floor":        func(a *WAFAdapt) { a.GreyFloor = -1 },
		"repeat threshold only": func(a *WAFAdapt) { a.RepeatThreshold = 20 },
		"repeat window only":    func(a *WAFAdapt) { a.RepeatWindow = 60 },
		"repeat threshold low": func(a *WAFAdapt) {
			a.RepeatThreshold, a.RepeatWindow = edgeconfig.DynamicWAFRepeatThresholdMin-1, 60
		},
		"repeat threshold high": func(a *WAFAdapt) {
			a.RepeatThreshold, a.RepeatWindow = edgeconfig.DynamicWAFRepeatThresholdMax+1, 60
		},
		"repeat window low":       func(a *WAFAdapt) { a.RepeatThreshold, a.RepeatWindow = 20, edgeconfig.DynamicWAFRepeatWindowMin-1 },
		"repeat window high":      func(a *WAFAdapt) { a.RepeatThreshold, a.RepeatWindow = 20, edgeconfig.DynamicWAFRepeatWindowMax+1 },
		"cookie names not mature": func(a *WAFAdapt) { a.CookieNames = []string{"0000000a"} },
		"cookie mature no names":  func(a *WAFAdapt) { a.CookieMature = true },
		"cookie name form":        func(a *WAFAdapt) { a.CookieMature, a.CookieNames = true, []string{"0000000A"} },
		"cookie name order": func(a *WAFAdapt) {
			a.CookieMature, a.CookieNames = true, []string{"0000000b", "0000000a"}
		},
		"too many cookie names": func(a *WAFAdapt) {
			a.CookieMature = true
			for index := 0; index <= MaxWAFCookieNames; index++ {
				a.CookieNames = append(a.CookieNames, fmt.Sprintf("%08x", index))
			}
		},
	}
	for name, mutate := range cases {
		adapt := testWAFAdapt()
		adapt.canonical()
		mutate(adapt)
		snapshot := testSnapshot()
		snapshot.Canonical()
		snapshot.Sites[0].WAFAdapt = adapt
		if snapshot.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// at the bounds: 32 active + 32 shadow, 32 typed parameters
	adapt := &WAFAdapt{Exclusions: append(manyExclusions(edgeconfig.DynamicWAFMaxTargets, WAFExclusionActive),
		manyExclusionsFrom(950000, MaxWAFAdaptExclusions-edgeconfig.DynamicWAFMaxTargets, WAFExclusionShadow)...)}
	for index := 0; index < MaxWAFTypedParams; index++ {
		adapt.TypedParams = append(adapt.TypedParams, WAFTypedParam{Key: fmt.Sprintf("%016x", index), Type: "binary", MaxLenBucket: 7, Charset: WAFCharsetMask})
	}
	adapt.RepeatThreshold, adapt.RepeatWindow = edgeconfig.DynamicWAFRepeatThresholdMax, edgeconfig.DynamicWAFRepeatWindowMax
	adapt.CookieMature = true
	for index := 0; index < MaxWAFCookieNames; index++ {
		adapt.CookieNames = append(adapt.CookieNames, fmt.Sprintf("%08x", index))
	}
	snapshot := testSnapshot()
	snapshot.Canonical()
	snapshot.Sites[0].WAFAdapt = adapt
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("bounds refused: %v", err)
	}
}

func manyExclusions(count int, stage string) []WAFExclusion {
	return manyExclusionsFrom(940000, count, stage)
}

func manyExclusionsFrom(rule int64, count int, stage string) []WAFExclusion {
	out := []WAFExclusion{}
	for index := 0; index < count; index++ {
		out = append(out, testExclusion(rule+int64(index), testParam("args", strings.Repeat("p", 64)), stage))
	}
	return rankActive(out)
}

// TestWAFAdaptManySites: the node total has no pair bound (sites' exclusions are in buckets of 32 sites, a request pays
// only for its bucket's): 100 sites at the per site bound validate.
func TestWAFAdaptManySites(t *testing.T) {
	_, private := testKey(t)
	snapshot := testSnapshot()
	snapshot.Sites = nil
	for index := 0; index < 100; index++ {
		site := testSiteState(fmt.Sprintf("33333333-3333-4333-8333-%012d", index))
		site.Mitigations, site.Signatures = nil, nil
		site.WAFAdapt = &WAFAdapt{Exclusions: manyExclusionsFrom(900000+int64(index)*MaxWAFAdaptExclusions, MaxWAFAdaptExclusions, WAFExclusionShadow)}
		snapshot.Sites = append(snapshot.Sites, site)
	}
	snapshot.Canonical()
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("6400 pairs over 100 sites refused: %v", err)
	}
	parts, err := Split(snapshot, testKeyID)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	for _, part := range parts {
		if _, err := Sign(part, testKeyID, private); err != nil {
			t.Fatalf("part %d of %d refused: %v", part.Part, part.Parts, err)
		}
	}
}

// TestGreyFloorFromP99: the floor is one above the p99 of a mature
// profile's normal weak scores, below the weak threshold; 0 otherwise.
func TestGreyFloorFromP99(t *testing.T) {
	mature := func(p99 int) GreyFloorProfile {
		return GreyFloorProfile{Mature: true, Requests: MinGreyFloorRequests, WeakP99: p99}
	}
	for name, test := range map[string]struct {
		profile GreyFloorProfile
		weak    int
		want    int
	}{
		"not mature":     {GreyFloorProfile{Requests: 1 << 20, WeakP99: 5}, 10, 0},
		"too few":        {GreyFloorProfile{Mature: true, Requests: MinGreyFloorRequests - 1, WeakP99: 5}, 10, 0},
		"p99 zero":       {mature(0), 10, 0},
		"p99 3":          {mature(3), 10, 4},
		"p99 5":          {mature(5), 10, 6},
		"p99 at line":    {mature(9), 10, 9},
		"p99 over line":  {mature(40), 10, 9},
		"one level tier": {mature(5), 0, 0},
		"bound":          {mature(500), 1000, edgeconfig.DynamicWAFMaxGreyFloor},
	} {
		if got := GreyFloorFromP99(test.profile, test.weak); got != test.want {
			t.Errorf("%s: floor %d, want %d", name, got, test.want)
		}
	}
	// the floor goes into the snapshot and the request context
	adapt := testWAFAdapt()
	adapt.canonical()
	adapt.GreyFloor = GreyFloorFromP99(mature(5), 10)
	snapshot := testSnapshot()
	snapshot.Canonical()
	snapshot.Sites[0].WAFAdapt = adapt
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("grey floor refused: %v", err)
	}
	context := edgeconfig.DynamicWAFContext{SiteID: testSite, GreyFloor: adapt.GreyFloor, RequestID: "a"}
	if parsed, ok := edgeconfig.ParseDynamicWAFContext(context.String()); !ok || parsed.GreyFloor != 6 {
		t.Fatalf("context %q", context.String())
	}
}

func TestFrameParams(t *testing.T) {
	frame := testFrame()
	frame.Sites[0].Params = []FrameParamSample{{CIDR: "198.51.100.0/24", Params: []FrameParam{
		{Key: WAFParamKey("/api/search", "args", "q"), WAFParam: testParam("args", "q"), Type: "text", LenBucket: WAFLenBucket(9), Charset: 1 << 9},
		{Key: WAFParamKey("/api/search", "cookie", "sid"), WAFParam: testParam("cookie", "sid"), Type: "ident", LenBucket: 6},
	}}}
	encoded, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeFrame(encoded)
	if err != nil || !reflect.DeepEqual(decoded.Sites[0].Params, frame.Sites[0].Params) {
		t.Fatalf("decode: %v", err)
	}
	// a frame without params (the Lua producer before RI-05) still decodes
	plain, _ := json.Marshal(testFrame())
	if bytes.Contains(plain, []byte(`"params"`)) {
		t.Fatal("empty params encoded")
	}
	if _, err := DecodeFrame(plain); err != nil {
		t.Fatalf("frame without params: %v", err)
	}
	cases := map[string]func(*FrameParamSample){
		"cidr":      func(s *FrameParamSample) { s.CIDR = "198.51.100.7" },
		"empty":     func(s *FrameParamSample) { s.Params = nil },
		"key":       func(s *FrameParamSample) { s.Params[0].Key = WAFParamKey("/api/search", "args", "r") },
		"location":  func(s *FrameParamSample) { s.Params[0].Location = "query" },
		"name":      func(s *FrameParamSample) { s.Params[0].Name = "" },
		"type":      func(s *FrameParamSample) { s.Params[0].Type = "date" },
		"len":       func(s *FrameParamSample) { s.Params[0].LenBucket = -1 },
		"charset":   func(s *FrameParamSample) { s.Params[0].Charset = 1 << 13 },
		"twice":     func(s *FrameParamSample) { s.Params[1] = s.Params[0] },
		"too many":  func(s *FrameParamSample) { s.Params = manyParams(MaxFrameRequestParams + 1) },
		"value key": func(s *FrameParamSample) {},
	}
	for name, mutate := range cases {
		sample := frame.Sites[0].Params[0]
		sample.Params = append([]FrameParam(nil), sample.Params...)
		mutate(&sample)
		bad := testFrame()
		bad.Sites[0].Params = []FrameParamSample{sample}
		encoded, _ := json.Marshal(bad)
		if name == "value key" {
			encoded = bytes.Replace(encoded, []byte(`"charset":512`), []byte(`"charset":512,"value":"x"`), 1)
		}
		if _, err := DecodeFrame(encoded); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted", name)
		}
	}
	full := testFrame()
	for index := 0; index < MaxFrameParamSamples; index++ {
		full.Sites[0].Params = append(full.Sites[0].Params, FrameParamSample{CIDR: "198.51.100.0/24", Params: manyParams(MaxFrameRequestParams)})
	}
	encoded, _ = json.Marshal(full)
	if _, err := DecodeFrame(encoded); err != nil {
		t.Fatalf("full params: %v", err)
	}
	t.Logf("full params of one site: %d bytes", len(encoded)-len(plain))
	full.Sites[0].Params = append(full.Sites[0].Params, full.Sites[0].Params[0])
	encoded, _ = json.Marshal(full)
	if _, err := DecodeFrame(encoded); !errors.Is(err, ErrInvalid) {
		t.Error("65 param samples accepted")
	}
}

func manyParams(count int) []FrameParam {
	out := []FrameParam{}
	for index := 0; index < count; index++ {
		param := testParam("args", fmt.Sprintf("%s%02d", strings.Repeat("a", 62), index))
		out = append(out, FrameParam{Key: WAFParamKey("/x", param.Location, param.Name), WAFParam: param, Type: "url", LenBucket: 7, Charset: WAFCharsetMask})
	}
	return out
}

func TestWAFHelpers(t *testing.T) {
	for length, want := range map[int]int64{0: 0, 1: 1, 2: 2, 3: 2, 4: 3, 63: 6, 64: 7, 1 << 20: 7} {
		if got := WAFLenBucket(length); got != want {
			t.Errorf("len bucket %d = %d, want %d", length, got, want)
		}
	}
	// key: CRC-32 (IEEE, as Lua ngx.crc32_long) halves
	if key := WAFParamKey("/search", "args", "q"); len(key) != 16 || key[:8] == "00000000" || WAFParamKey("", "args", "q")[:8] != "00000000" ||
		key[8:] != WAFParamKey("", "args", "q")[8:] {
		t.Fatalf("param key %q", key)
	}
	if WAFParamKey("", "args", "q") != "00000000"+fmt.Sprintf("%08x", 0x03954893) {
		t.Fatalf("param key %q", WAFParamKey("", "args", "q"))
	}
	if QueryNamesHash(nil) != "" || QueryNamesHash([]string{"b", "a", "b"}) != QueryNamesHash([]string{"a", "b"}) ||
		!ValidCondition(DimQueryNamesHash, QueryNamesHash([]string{"q"})) {
		t.Fatal("query names hash")
	}
	if crsPackIDPattern.String() != "^system/crs-[a-z0-9][a-z0-9-]{0,59}$" || packVersionPattern.String() != `^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$` {
		t.Fatal("pack patterns drifted from edgeconfig")
	}
	spec, ok := LookupField("waf.tighten:crs_sqli")
	if !ok || spec.Module != ModuleWAF || spec.Kind != FieldBool {
		t.Fatalf("waf.tighten field %+v %v", spec, ok)
	}
	if _, ok := LookupField("waf.tighten"); ok {
		t.Fatal("waf.tighten without a set")
	}
	if len(WAFCharsetClasses) != 13 || WAFCharsetMask != 1<<len(WAFCharsetClasses)-1 || len(WAFValueTypes) != 6 {
		t.Fatal("frozen enums")
	}
}

// FuzzDecodeWAFEvidence: whatever decodes re-encodes to a report that
// decodes to the same value, within bounds.
func FuzzDecodeWAFEvidence(f *testing.F) {
	seed, _ := EncodeReport(testWAFEvidenceReport())
	f.Add(seed)
	f.Add([]byte(`{"schema":"cdnca.autodefense.report/v1","kind":"waf_evidence"}`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		report, err := DecodeReport(encoded)
		if err != nil || report.Kind != ReportWAFEvidence {
			return
		}
		again, err := EncodeReport(report)
		if err != nil || len(again) > MaxWAFEvidenceBytes {
			t.Fatalf("re-encode: %v", err)
		}
		back, err := DecodeReport(again)
		if err != nil || !reflect.DeepEqual(back, report) {
			t.Fatalf("round trip: %v", err)
		}
		if len(report.WAFEvidence.Items) > MaxWAFEvidenceItems {
			t.Fatal("bounds")
		}
	})
}

// FuzzWAFAdaptSnapshot: a snapshot site's waf_adapt that validates has its
// grey floor accepted in a request context and its active targets fit a
// site rule file (at most DynamicWAFMaxTargets, sorted).
func FuzzWAFAdaptSnapshot(f *testing.F) {
	seed, _ := json.Marshal(testWAFAdapt())
	f.Add(seed)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		var adapt WAFAdapt
		if decoder.Decode(&adapt) != nil || !validWAFAdapt(adapt) {
			return
		}
		context := edgeconfig.DynamicWAFContext{SiteID: testSite, GreyFloor: adapt.GreyFloor, RequestID: "a"}
		if _, ok := edgeconfig.ParseDynamicWAFContext(context.String()); !ok {
			t.Fatalf("grey floor of a valid waf_adapt refused: %q", context.String())
		}
		for _, now := range []int64{testNow, 1, MaxValue} {
			if targets := adapt.ActiveTargets(now); len(targets) > edgeconfig.DynamicWAFMaxTargets {
				t.Fatalf("%d active targets", len(targets))
			}
		}
	})
}

// Header samples (ri-gaps2 A4): site level keys of the lower-case name, in
// order, alone enough for a report; no name in the report.
func TestWAFEvidenceHeaders(t *testing.T) {
	if WAFHeaderKey("X-Device-ID") != WAFParamKey("", "header", "x-device-id") {
		t.Fatal("header key is not of the lower-case name")
	}
	report := testWAFEvidenceReport()
	report.WAFEvidence.Items, report.WAFEvidence.Tighten, report.WAFEvidence.Exclusions =
		[]WAFEvidenceItem{}, []WAFTightenState{}, []WAFExclusionResult{}
	report.WAFEvidence.Headers = []WAFCookieSample{
		{Key: WAFHeaderKey("x-device-id"), Type: "ident", LenBucket: 5, Seen: 1200, Sources: "00000000ffffffff"},
		{Key: WAFHeaderKey("x-app-version"), Type: "number", LenBucket: 2, Seen: 1100, Sources: "00000000ffffffff"}}
	sort.Slice(report.WAFEvidence.Headers, func(i, j int) bool { return report.WAFEvidence.Headers[i].Key < report.WAFEvidence.Headers[j].Key })
	encoded, err := EncodeReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeReport(encoded); err != nil || !reflect.DeepEqual(decoded, report) {
		t.Fatalf("decode: %+v %v", decoded, err)
	}
	if strings.Contains(string(encoded), "device") {
		t.Fatal("header name in the report")
	}
	cases := map[string]func(*WAFEvidence){
		"path key":   func(e *WAFEvidence) { e.Headers[0].Key = "ffffffff" + e.Headers[0].Key[8:] },
		"order":      func(e *WAFEvidence) { e.Headers[0], e.Headers[1] = e.Headers[1], e.Headers[0] },
		"zero seen":  func(e *WAFEvidence) { e.Headers[0].Seen = 0 },
		"type":       func(e *WAFEvidence) { e.Headers[0].Type = "word" },
		"empty list": func(e *WAFEvidence) { e.Headers = []WAFCookieSample{} },
		"sources":    func(e *WAFEvidence) { e.Headers[0].Sources = "x" },
	}
	for name, mutate := range cases {
		bad := clone(t, report)
		mutate(bad.WAFEvidence)
		if ValidateReport(bad) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Cookie samples: site level keys in order, seen within the cookie samples.
func TestWAFEvidenceCookies(t *testing.T) {
	report := testWAFEvidenceReport()
	report.WAFEvidence.Cookies = []WAFCookieSample{
		{Key: WAFCookieKey("pref"), Type: "ident", LenBucket: 3, Seen: 40, Sources: "00000000000000ff"},
		{Key: WAFCookieKey("sid"), Type: "binary", LenBucket: 5, Seen: 50, Sources: "000000000000ffff"}}
	sort.Slice(report.WAFEvidence.Cookies, func(i, j int) bool { return report.WAFEvidence.Cookies[i].Key < report.WAFEvidence.Cookies[j].Key })
	report.WAFEvidence.CookieSamples = 50
	encoded, err := EncodeReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeReport(encoded); err != nil || !reflect.DeepEqual(decoded, report) {
		t.Fatalf("decode: %+v %v", decoded, err)
	}
	if strings.Contains(string(encoded), "pref") {
		t.Fatal("cookie name in the report")
	}
	cases := map[string]func(*WAFEvidence){
		"path key":     func(e *WAFEvidence) { e.Cookies[0].Key = "ffffffff" + e.Cookies[0].Key[8:] },
		"order":        func(e *WAFEvidence) { e.Cookies[0], e.Cookies[1] = e.Cookies[1], e.Cookies[0] },
		"seen":         func(e *WAFEvidence) { e.Cookies[0].Seen = 51 },
		"zero seen":    func(e *WAFEvidence) { e.Cookies[0].Seen = 0 },
		"type":         func(e *WAFEvidence) { e.Cookies[0].Type = "word" },
		"no samples":   func(e *WAFEvidence) { e.CookieSamples = 0 },
		"empty list":   func(e *WAFEvidence) { e.Cookies = []WAFCookieSample{} },
		"samples only": func(e *WAFEvidence) { e.Cookies = nil },
	}
	for name, mutate := range cases {
		bad := clone(t, report)
		mutate(bad.WAFEvidence)
		if ValidateReport(bad) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestWAFAdaptRanks (waf-exclcap2): a site's active exclusions are ranked
// 1..n, each once, shadow ones unranked; the safety bound is 512 active.
func TestWAFAdaptRanks(t *testing.T) {
	cases := map[string]func(a *WAFAdapt){
		"active unranked":  func(a *WAFAdapt) { a.Exclusions[0].Rank = 0 },
		"shadow ranked":    func(a *WAFAdapt) { a.Exclusions[1].Rank = 3 },
		"rank twice":       func(a *WAFAdapt) { a.Exclusions[0].Rank, a.Exclusions[2].Rank = 1, 1 },
		"rank gap":         func(a *WAFAdapt) { a.Exclusions[0].Rank, a.Exclusions[2].Rank = 1, 3 },
		"rank negative":    func(a *WAFAdapt) { a.Exclusions[0].Rank = -1 },
		"rank beyond list": func(a *WAFAdapt) { a.Exclusions[0].Rank, a.Exclusions[2].Rank = 4, 1 },
	}
	valid := func(adapt *WAFAdapt) bool {
		snapshot := testSnapshot()
		snapshot.Canonical()
		snapshot.Sites[0].WAFAdapt = adapt
		return snapshot.Validate() == nil
	}
	for name, mutate := range cases {
		adapt := testWAFAdapt()
		adapt.canonical()
		mutate(adapt)
		if valid(adapt) {
			t.Errorf("%s: accepted", name)
		}
	}
	// any permutation is valid
	adapt := testWAFAdapt()
	adapt.canonical()
	adapt.Exclusions[0].Rank, adapt.Exclusions[2].Rank = adapt.Exclusions[2].Rank, adapt.Exclusions[0].Rank
	if !valid(adapt) {
		t.Error("swapped ranks refused")
	}
	if edgeconfig.DynamicWAFMaxTargets != 512 || !valid(&WAFAdapt{Exclusions: manyExclusions(512, WAFExclusionActive)}) {
		t.Errorf("512 active refused (bound %d)", edgeconfig.DynamicWAFMaxTargets)
	}
}

// TestWAFBudget (waf-exclcap2): the snapshot budget is part 1 only, within
// its bounds, and survives Split / Assemble.
func TestWAFBudget(t *testing.T) {
	for _, budget := range []WAFBudget{{99, 5}, {5001, 5}, {500, 0}, {500, 51}} {
		snapshot := testSnapshot()
		snapshot.Canonical()
		snapshot.WAFBudget = &budget
		if snapshot.Validate() == nil {
			t.Errorf("%+v accepted", budget)
		}
	}
	snapshot := testSnapshot()
	snapshot.Canonical()
	snapshot.WAFBudget = &WAFBudget{LatencyMicros: 100, MemoryPercent: 50}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	second := snapshot
	second.Part, second.Parts = 2, 2
	if second.Validate() == nil {
		t.Error("budget on part 2 accepted")
	}
	parts, err := Split(snapshot, "k1")
	if err != nil {
		t.Fatal(err)
	}
	whole, err := Assemble(parts)
	if err != nil || whole.WAFBudget == nil || *whole.WAFBudget != *snapshot.WAFBudget {
		t.Fatalf("assembled budget %+v: %v", whole.WAFBudget, err)
	}
	if DefaultWAFBudget() != (WAFBudget{LatencyMicros: 500, MemoryPercent: 5}) {
		t.Error("defaults")
	}
}

// TestWAFEvidenceLimit (waf-exclcap2): the node's applied / trimmed counts
// add up to the delivered ones; a report may carry only them.
func TestWAFEvidenceLimit(t *testing.T) {
	report := testWAFEvidenceReport()
	report.WAFEvidence.Limit = &WAFExclusionLimit{Delivered: 300, Applied: 120, LatencyTrimmed: 150, MemoryTrimmed: 30, CostNanos: 4100}
	encoded, err := EncodeReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeReport(encoded); err != nil || *decoded.WAFEvidence.Limit != *report.WAFEvidence.Limit {
		t.Fatalf("round trip: %v", err)
	}
	only := testWAFEvidenceReport()
	only.WAFEvidence.Items, only.WAFEvidence.Tighten, only.WAFEvidence.Exclusions = []WAFEvidenceItem{}, []WAFTightenState{}, []WAFExclusionResult{}
	only.WAFEvidence.Fragments, only.WAFEvidence.Cookies, only.WAFEvidence.CookieSamples, only.WAFEvidence.Headers = nil, nil, 0, nil
	if _, err := EncodeReport(only); err == nil {
		t.Fatal("empty evidence accepted")
	}
	only.WAFEvidence.Limit = &WAFExclusionLimit{Delivered: 2, Applied: 2}
	if _, err := EncodeReport(only); err != nil {
		t.Fatalf("limit only: %v", err)
	}
	for _, bad := range []WAFExclusionLimit{{Delivered: 0}, {Delivered: 3, Applied: 2}, {Delivered: 513, Applied: 513},
		{Delivered: 2, Applied: 3, LatencyTrimmed: -1}, {Delivered: 1, Applied: 1, CostNanos: MaxWAFExclusionCostNanos + 1}} {
		report := testWAFEvidenceReport()
		report.WAFEvidence.Limit = &bad
		if _, err := EncodeReport(report); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
