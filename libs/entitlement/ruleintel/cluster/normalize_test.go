package cluster

import (
	"errors"
	"testing"
)

var tgt = Target{Engine: "modsecurity", PackID: "crs-pl2", RuleID: "942430"}

func richText(name string) string {
	switch name {
	case "content", "body", "html", "message":
		return "rich_text"
	}
	return ""
}

func TestNormalizeSameIntent(t *testing.T) {
	n := Normalizer{ParamClass: richText, PathClass: func(p string) string {
		if p == "/api/*/comments" {
			return "api_comments"
		}
		return ""
	}}
	cases := []struct {
		name string
		a, b []Cond
	}{
		{"参数名大小写与数组后缀", []Cond{{"param.name", "Content[]"}, {"value_type", "TEXT"}}, []Cond{{"param.name", "content"}, {"value_type", "text"}}},
		{"JSON 数字下标", []Cond{{"param.name", "items[0].msg"}}, []Cond{{"param.name", "items[3].msg"}}},
		{"点分数字段", []Cond{{"param.name", "a.12.b"}}, []Cond{{"param.name", "a.7.b"}}},
		{"条件顺序与重复", []Cond{{"value_type", "text"}, {"param.loc", "body"}, {"param.loc", "body"}}, []Cond{{"param.loc", "BODY"}, {"value_type", "text"}}},
		{"路径模板归字典类别", []Cond{{"path", "/API/12/comments"}}, []Cond{{"path.class", "api_comments"}}},
		{"正则简化", []Cond{{"uri.regex", "a{2,}"}}, []Cond{{"uri.regex", "aa+"}}},
		{"阈值对数分桶", []Cond{{"cc.threshold", "37"}}, []Cond{{"cc.threshold", "20"}}},
		{"空白与空值丢弃", []Cond{{" ua_family ", " curl "}, {"x", ""}}, []Cond{{"ua_family", "curl"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := n.Normalize(RawCandidate{Kind: KindWAFExclusion, Target: tgt, Conds: tc.a})
			if err != nil {
				t.Fatal(err)
			}
			b, err := n.Normalize(RawCandidate{Kind: KindWAFExclusion, Target: tgt, Conds: tc.b})
			if err != nil {
				t.Fatal(err)
			}
			if a.Fingerprint != b.Fingerprint {
				t.Fatalf("指纹不同：\n%s\n%s", a.Canonical, b.Canonical)
			}
		})
	}
}

func TestNormalizeDistinct(t *testing.T) {
	n := Normalizer{}
	base := RawCandidate{Kind: KindWAFExclusion, Target: tgt, Conds: []Cond{{"param.name", "q"}}}
	a, _ := n.Normalize(base)
	other := []RawCandidate{
		{Kind: KindWAFTypedParam, Target: tgt, Conds: base.Conds},
		{Kind: KindWAFExclusion, Target: Target{Engine: "modsecurity", PackID: "crs-pl2", RuleID: "942431"}, Conds: base.Conds},
		{Kind: KindWAFExclusion, Target: tgt, Conds: []Cond{{"param.name", "q2"}}},
	}
	for i, r := range other {
		b, err := n.Normalize(r)
		if err != nil || b.Fingerprint == a.Fingerprint {
			t.Fatalf("#%d 应得不同指纹，err=%v", i, err)
		}
	}
}

func TestNormalizeParamClassAndCompilable(t *testing.T) {
	n := Normalizer{ParamClass: richText, Compilable: func(_ Kind, dim string) bool { return dim != "header.x-trace" }}
	c, err := n.Normalize(RawCandidate{Kind: KindWAFExclusion, Target: tgt, Conds: []Cond{{"param.name", "Body"}, {"header.x-trace", "1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(c.Canonical); got != `{"conds":[["param.class","rich_text"],["param.name","body"]]}` {
		t.Fatalf("canonical = %s", got)
	}
	if _, err := n.Normalize(RawCandidate{Kind: KindWAFExclusion, Target: tgt, Conds: []Cond{{"header.x-trace", "1"}}}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("全被丢弃应 ErrEmpty，得 %v", err)
	}
}

func TestNormalizeErrors(t *testing.T) {
	n := Normalizer{}
	big := make([]Cond, 0, 400)
	for i := 0; i < 400; i++ {
		big = append(big, Cond{"param.name", string(rune('a'+i%26)) + string(rune('a'+i/26))})
	}
	cases := []struct {
		raw  RawCandidate
		want error
	}{
		{RawCandidate{Kind: "bogus", Conds: []Cond{{"a", "b"}}}, ErrInvalid},
		{RawCandidate{Kind: KindWAFExclusion, Conds: []Cond{{"uri.regex", "("}}}, ErrInvalid},
		{RawCandidate{Kind: KindCCRuleTune, Conds: []Cond{{"threshold", "NaN"}}}, ErrInvalid},
		{RawCandidate{Kind: KindWAFExclusion}, ErrEmpty},
		{RawCandidate{Kind: KindWAFExclusion, Conds: big}, ErrTooLarge},
	}
	for i, tc := range cases {
		if _, err := n.Normalize(tc.raw); !errors.Is(err, tc.want) {
			t.Fatalf("#%d err=%v want %v", i, err, tc.want)
		}
	}
}

func TestLogBucket(t *testing.T) {
	for in, want := range map[string]string{"0": "0", "-3": "0", "1": "1", "1.9": "1", "2": "2", "4.99": "2", "5": "5", "9.9": "5", "10": "10", "37": "20", "1000": "1000", "0.3": "0.2", "7000": "5000"} {
		got, err := LogBucket(in)
		if err != nil || got != want {
			t.Errorf("LogBucket(%s) = %s,%v want %s", in, got, err, want)
		}
	}
}

func TestParseCanonicalRoundTrip(t *testing.T) {
	c, _ := Normalizer{ParamClass: richText}.Normalize(RawCandidate{Kind: KindWAFExclusion, Target: tgt, Conds: []Cond{{"param.name", "html"}, {"value_type", "text"}}})
	back, err := ParseCanonical(c.Kind, c.Target, c.Canonical)
	if err != nil || back.Fingerprint != c.Fingerprint {
		t.Fatalf("回读指纹不一致 err=%v", err)
	}
}
