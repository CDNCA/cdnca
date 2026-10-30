package autodefense

import (
	"fmt"
	"strings"
	"testing"
)

func testFragments() []WAFFragment {
	return []WAFFragment{
		{Rule: 930100, Location: "path", Fragment: "../../etc/passwd", Encoding: "text", Signal: WAFFragmentStrong},
		{Rule: 942100, Location: "args", ParamKey: "q", Fragment: "' OR 1=1--", Encoding: "text", Signal: "sqli"},
		{Rule: 942100, Location: "args", ParamKey: "user.*.name", Fragment: "%00' OR 1", Encoding: "percent", Signal: "sqli"},
	}
}

func TestWAFEvidenceFragments(t *testing.T) {
	report := testWAFEvidenceReport()
	report.WAFEvidence.Fragments = testFragments()
	if err := ValidateReport(report); err != nil {
		t.Fatalf("fragments refused: %v", err)
	}
	encoded, err := EncodeReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeReport(encoded); err != nil || len(decoded.WAFEvidence.Fragments) != 3 {
		t.Fatalf("decode: %v", err)
	}
	// fragments only: still a report
	only := clone(t, report)
	only.WAFEvidence.Items, only.WAFEvidence.Tighten, only.WAFEvidence.Exclusions = []WAFEvidenceItem{}, []WAFTightenState{}, []WAFExclusionResult{}
	if err := ValidateReport(only); err != nil {
		t.Fatalf("fragments only: %v", err)
	}
	// without fragments the field is omitted (switch off: nothing on the wire)
	report.WAFEvidence.Fragments = nil
	if encoded, _ := EncodeReport(report); strings.Contains(string(encoded), "fragments") {
		t.Fatal("empty fragments encoded")
	}
}

func TestWAFEvidenceFragmentRejects(t *testing.T) {
	cases := map[string]func(*[]WAFFragment){
		"empty list":         func(f *[]WAFFragment) { *f = []WAFFragment{} },
		"rule":               func(f *[]WAFFragment) { (*f)[0].Rule = 1 },
		"location":           func(f *[]WAFFragment) { (*f)[0].Location = "query" },
		"path with key":      func(f *[]WAFFragment) { (*f)[0].ParamKey = "q" },
		"args without key":   func(f *[]WAFFragment) { (*f)[1].ParamKey = "" },
		"key not normalized": func(f *[]WAFFragment) { (*f)[1].ParamKey = "Q" },
		"key digits":         func(f *[]WAFFragment) { (*f)[1].ParamKey = "a.0" },
		"key charset":        func(f *[]WAFFragment) { (*f)[1].ParamKey = "a b" },
		"encoding":           func(f *[]WAFFragment) { (*f)[1].Encoding = "base64" },
		"empty fragment":     func(f *[]WAFFragment) { (*f)[1].Fragment = "" },
		"too long":           func(f *[]WAFFragment) { (*f)[1].Fragment = strings.Repeat("a", MaxWAFFragmentBytes+1) },
		"control in text":    func(f *[]WAFFragment) { (*f)[1].Fragment = "a\x00b" },
		"invalid utf8 text":  func(f *[]WAFFragment) { (*f)[1].Fragment = "a\xffb" },
		"raw byte percent":   func(f *[]WAFFragment) { (*f)[2].Fragment = "\x01" },
		"weak signal":        func(f *[]WAFFragment) { (*f)[1].Signal = "weak" },
		"order":              func(f *[]WAFFragment) { (*f)[0], (*f)[1] = (*f)[1], (*f)[0] },
		"duplicate":          func(f *[]WAFFragment) { (*f)[2] = (*f)[1] },
	}
	for name, mutate := range cases {
		report := testWAFEvidenceReport()
		fragments := testFragments()
		mutate(&fragments)
		report.WAFEvidence.Fragments = fragments
		if ValidateReport(report) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	report := testWAFEvidenceReport()
	for index := range MaxWAFFragments + 1 {
		report.WAFEvidence.Fragments = append(report.WAFEvidence.Fragments, WAFFragment{Rule: 942100, Location: "args",
			ParamKey: "q", Fragment: fmt.Sprintf("' OR %03d", index), Encoding: "text", Signal: "sqli"})
	}
	if ValidateReport(report) == nil {
		t.Error("33 fragments accepted")
	}
}

// 所有上限同时取满（128 项满长名 + 32 条最坏转义片段：'<' 在 JSON 里是 \u003c，6 倍）仍在单条上限内。
func TestWAFEvidenceFragmentsFitBound(t *testing.T) {
	report := fullWAFEvidenceReport()
	for index := range MaxWAFFragments {
		report.WAFEvidence.Fragments = append(report.WAFEvidence.Fragments, WAFFragment{Rule: 999999, Location: "header",
			ParamKey: fmt.Sprintf("%s%02d", strings.Repeat("h", 62), index), Fragment: strings.Repeat("<", MaxWAFFragmentBytes),
			Encoding: "text", Signal: "java_deser"})
	}
	encoded, err := EncodeReport(report)
	if err != nil || len(encoded) > MaxWAFEvidenceBytes {
		t.Fatalf("full evidence with fragments: %d bytes: %v", len(encoded), err)
	}
	t.Logf("full waf_evidence with fragments: %d bytes", len(encoded))
}

func TestWAFFragmentParamKey(t *testing.T) {
	for in, want := range map[string]string{"Content[]": "content", "a[0][b]": "a[*][b]", "json.items.3.Name": "json.items.*.name", "q": "q"} {
		if got := WAFFragmentParamKey(in); got != want {
			t.Errorf("WAFFragmentParamKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSnapshotAttackFragmentsSwitch(t *testing.T) {
	public, private := testKey(t)
	snapshot := testSnapshot()
	snapshot.AttackFragments = true
	encoded, err := Sign(snapshot, testKeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(encoded, testNode, trusted(public))
	if err != nil || !opened.AttackFragments {
		t.Fatalf("open: %v %v", opened.AttackFragments, err)
	}
	parts, err := Split(snapshot, testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	two := []Snapshot{parts[0], parts[0]}
	two[0].Parts, two[1].Parts, two[1].Part = 2, 2, 2
	two[1].PlatformAllow, two[1].PortGroups, two[1].Sites = nil, nil, nil
	if whole, err := Assemble(two); err != nil || !whole.AttackFragments {
		t.Fatalf("assemble: %v %v", whole.AttackFragments, err)
	}
	two[1].AttackFragments = false
	if _, err := Assemble(two); err == nil {
		t.Fatal("parts disagreeing on attack_fragments assembled")
	}
	// off by default: the field is not encoded
	snapshot.AttackFragments = false
	if encoded, _ := Sign(snapshot, testKeyID, private); strings.Contains(string(encoded), "attack_fragments") {
		t.Fatal("attack_fragments=false encoded")
	}
}
