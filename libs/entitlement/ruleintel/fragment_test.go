package ruleintel

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/cluster"
	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/redact"
)

var fragTarget = cluster.Target{Engine: FragmentEngine, PackID: "system/crs-pl2", RuleID: "942100"}

func fragment(text string) Fragment {
	return Fragment{Target: fragTarget, Location: "args", ParamKey: "q", Fragment: text, Encoding: redact.EncodingText,
		Signal: "sqli", Hits: 3, Sites: 2}
}

func TestReportAttackFragments(t *testing.T) {
	r := empty()
	r.AttackFragments = []Fragment{fragment("' OR 1=1--"), fragment("' OR email='<email>'--"),
		{Target: fragTarget, Location: "path", Fragment: "../../etc/passwd%00", Encoding: redact.EncodingText, Signal: "strong", Hits: 1, Sites: 1}}
	sortFragments(r.AttackFragments)
	if err := Validate(r); err != nil {
		t.Fatal(err)
	}
	if r.Counts()["attack_fragments"] != 3 {
		t.Fatal("counts")
	}
	// 未开启（省略）时报告与旧格式字节一致
	off := empty()
	if _, encoded, _ := Digest(off); strings.Contains(string(encoded), "attack_fragments") {
		t.Fatal("omitted section encoded")
	}
}

func TestReportAttackFragmentsRejects(t *testing.T) {
	notRedacted := map[string]Fragment{
		"邮箱":       fragment("' OR email='bob@corp.example'--"),
		"URL 编码邮箱": fragment("' OR u='bob%40corp.example'"),
		"手机号":      fragment("{{7*7}}13800138000"),
		"IP":       fragment("x' AND h='203.0.113.7"),
		"JWT":      fragment("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
		"超长":       fragment(strings.Repeat("'", redact.MaxFragmentBytes+1)),
		"编码未知":     func() Fragment { f := fragment("' OR 1"); f.Encoding = "base64"; return f }(),
		"编码不规范":    func() Fragment { f := fragment("%2E"); f.Encoding = redact.EncodingPercent; return f }(),
		"参数名是邮箱":   func() Fragment { f := fragment("' OR 1"); f.ParamKey = "a@b.co"; return f }(),
	}
	for name, f := range notRedacted {
		r := empty()
		r.AttackFragments = []Fragment{f}
		if err := Validate(r); !errors.Is(err, ErrNotRedacted) {
			t.Errorf("%s: %v, want ErrNotRedacted", name, err)
		}
	}
	invalid := map[string]func(*Fragment){
		"引擎":       func(f *Fragment) { f.Target.Engine = "cc" },
		"包":        func(f *Fragment) { f.Target.PackID = "system/cc" },
		"规则号":      func(f *Fragment) { f.Target.RuleID = "1" },
		"位置":       func(f *Fragment) { f.Location = "query" },
		"path 带参数": func(f *Fragment) { f.Location = "path" },
		"args 无参数": func(f *Fragment) { f.ParamKey = "" },
		"参数未规范化":   func(f *Fragment) { f.ParamKey = "Q" },
		"信号":       func(f *Fragment) { f.Signal = "Weak Signal" },
		"站点数 > 次数": func(f *Fragment) { f.Sites = 4 },
		"零次":       func(f *Fragment) { f.Hits, f.Sites = 0, 0 },
	}
	for name, mutate := range invalid {
		f := fragment("' OR 1=1")
		mutate(&f)
		r := empty()
		r.AttackFragments = []Fragment{f}
		if err := Validate(r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	r := empty()
	r.AttackFragments = []Fragment{}
	if Validate(r) == nil {
		t.Error("empty section accepted")
	}
	r.AttackFragments = []Fragment{fragment("b"), fragment("a")}
	if Validate(r) == nil {
		t.Error("unsorted accepted")
	}
	r.AttackFragments = []Fragment{fragment("a"), fragment("a")}
	if Validate(r) == nil {
		t.Error("duplicate accepted")
	}
}

func sighting(site string, hour int64, text string) FragmentSighting {
	return FragmentSighting{SiteID: site, Hour: hour, PackID: "system/crs-pl2", RuleID: 942100, Location: "args", ParamKey: "q",
		Fragment: text, Encoding: redact.EncodingText, Signal: "sqli"}
}

func TestAggregateFragments(t *testing.T) {
	if got, dropped := AggregateFragments(false, []FragmentSighting{sighting("s1", 0, "' OR 1=1")}); got != nil || dropped != 0 {
		t.Fatalf("disabled: %v %d", got, dropped)
	}
	in := []FragmentSighting{
		sighting("s1", 0, "' OR 1=1"), sighting("s1", 3600, "' OR 1=1"), sighting("s2", 0, "' OR 1=1"),
		// 节点漏打码：主控补打码后与已打码的同一片段合并
		sighting("s3", 0, "' OR e='bob@corp.example'"), sighting("s1", 0, "' OR e='<email>'"),
		// 形状不合法、无法解码
		{SiteID: "s1", PackID: "system/crs-pl2", RuleID: 1, Location: "args", ParamKey: "q", Fragment: "x", Encoding: "text", Signal: "sqli"},
		{SiteID: "s1", PackID: "system/crs-pl2", RuleID: 942100, Location: "args", ParamKey: "q", Fragment: "%zz", Encoding: "percent", Signal: "sqli"},
	}
	got, dropped := AggregateFragments(true, in)
	if dropped != 2 || len(got) != 2 {
		t.Fatalf("got %+v dropped %d", got, dropped)
	}
	want := map[string][2]int64{"' OR 1=1": {3, 2}, "' OR e='<email>'": {2, 2}}
	for _, f := range got {
		if w := want[f.Fragment]; f.Hits != w[0] || f.Sites != w[1] {
			t.Errorf("%q hits=%d sites=%d, want %v", f.Fragment, f.Hits, f.Sites, w)
		}
	}
	r := empty()
	r.AttackFragments = got
	if err := Validate(r); err != nil {
		t.Fatalf("aggregate output refused: %v", err)
	}
}

func TestAggregateFragmentsBounds(t *testing.T) {
	// 每站每小时 ≤ 32
	var in []FragmentSighting
	for i := range 40 {
		in = append(in, sighting("s1", 0, fmt.Sprintf("' OR %d", i)))
	}
	if got, dropped := AggregateFragments(true, in); len(got) != MaxSiteHourFragments || dropped != 8 {
		t.Fatalf("per site hour: %d kept, %d dropped", len(got), dropped)
	}
	// 报告上限：条数与字节预算，按次数取高的
	in = nil
	for i := range 700 {
		for range 1 + i%3 {
			in = append(in, sighting(fmt.Sprintf("s%d", i), 0, fmt.Sprintf("%s %04d", strings.Repeat("<", 200), i)))
		}
	}
	got, dropped := AggregateFragments(true, in)
	r := empty()
	r.AttackFragments = got
	_, encoded, _ := Digest(r)
	if len(got) > MaxReportFragments || len(encoded) > MaxReportBytes || dropped != 700-len(got) || Validate(r) != nil {
		t.Fatalf("report bound: %d kept, %d dropped, %d bytes, %v", len(got), dropped, len(encoded), Validate(r))
	}
	for _, f := range got {
		if f.Hits == 1 {
			t.Fatal("kept a 1-hit fragment while dropping more frequent ones")
		}
	}
	t.Logf("%d fragments, report %d bytes", len(got), len(encoded))
}

func TestFragmentRawNormalizes(t *testing.T) {
	a := fragment("' OR 1=1")
	b := a
	b.Hits, b.Sites, b.Signal = 9, 1, "strong" // 计数与信号不影响指纹
	ca, err := cluster.Normalizer{}.Normalize(a.Raw())
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := cluster.Normalizer{}.Normalize(b.Raw())
	c := a
	c.Fragment = "' OR 2=2"
	cc, _ := cluster.Normalizer{}.Normalize(c.Raw())
	if ca.Fingerprint != cb.Fingerprint || ca.Fingerprint == cc.Fingerprint || ca.Kind != cluster.KindAttackFragment {
		t.Fatal("fragment fingerprint")
	}
}
