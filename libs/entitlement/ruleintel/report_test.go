package ruleintel

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/cluster"
)

func empty() Report {
	return Report{WAFExclusions: []Item{}, WAFRejections: []Item{}, WAFTighten: []Item{}, WAFRuleStats: []RuleStat{},
		AutodefenseSignatures: []Item{}, CCRuleStats: []RuleStat{}, CCRuleTunes: []Item{}, FalsePositives: []Item{},
		ScannerFingerprints: []Item{}}
}

var crs = cluster.Target{Engine: "modsecurity", PackID: "system/crs-pl2", RuleID: "942430"}

func exclusion(conds ...[2]string) Item {
	return Item{Kind: cluster.KindWAFExclusion, Target: crs, Conds: conds, Hits: 512, Sources: 30, Days: 7}
}

func TestValidateAcceptsRedactedReport(t *testing.T) {
	r := empty()
	pass := 0.97
	r.WAFExclusions = []Item{exclusion([2]string{"param.name", "q"}, [2]string{"param.loc", "query"}, [2]string{"value_type", "free_text"}),
		exclusion([2]string{"param.class", "other"}, [2]string{"param.hash", strings.Repeat("ab", 32)}, [2]string{"len_bucket", "5"})}
	r.WAFExclusions[0].PassRatio = &pass
	r.WAFRejections = []Item{{Kind: cluster.KindWAFExclusion, Target: crs, Conds: [][2]string{{"param.name", "q"}}, Reason: "attack"}}
	r.AutodefenseSignatures = []Item{{Kind: cluster.KindAutodefenseSignature, Target: cluster.Target{Engine: "cc_v2", PackID: "system/autodefense-intel", Set: "sig"},
		Conds: [][2]string{{"method", "POST"}, {"ja4", "t13d1516h2_8daaf6152771_02713d6af862"}, {"path.class", "/wp-admin/*"}, {"asn", "4134"}, {"country", "cn"}}}}
	r.CCRuleTunes = []Item{{Kind: cluster.KindCCRuleTune, Target: cluster.Target{Engine: "cc", PackID: "system/cc-base", RuleID: "login"},
		Conds: [][2]string{{"window", "60"}}, Params: map[string]float64{"threshold": 30}}}
	r.WAFRuleStats = []RuleStat{{Engine: "modsecurity", PackID: "system/crs-pl2", PackVersion: "1.3.0", RuleID: "942430", Hits: 9, GreyRatio: 0.1, PassRatio: 0.9}}
	if err := Validate(r); err != nil {
		t.Fatal(err)
	}
	d1, _, _ := Digest(r)
	d2, _, _ := Digest(r)
	if d1 != d2 {
		t.Fatal("digest not deterministic")
	}
}

func TestValidateRejectsLeaks(t *testing.T) {
	cases := map[string][2]string{
		"原始参数值":   {"value", "1' or 1=1"},
		"IP 维度":   {"ip", "203.0.113.7"},
		"cidr 维度": {"cidr", "203.0.113.0/24"},
		"IP 藏在值里":  {"asn", "203.0.113.7"},
		"IPv6 值":   {"country", "2001:db8::1"},
		"完整路径":     {"path", "/user/42/profile"},
		"路径进 path.class 但带查询": {"path.class", "/a?id=1"},
		"请求体":      {"body", "a=b"},
		"值带空白与引号":  {"ua_family", "Mozilla/5.0 (X11)"},
		"域名":       {"ua_family", "shop.example.com"},
		"站点 ID":    {"bucket.site", "0b6f2b0e-8d1c-4b3e-9e2a-1f2d3c4b5a69"},
		"参数名哈希非摘要": {"param.hash", "password"},
		"Cookie":   {"cookie", "sid"},
	}
	for name, c := range cases {
		r := empty()
		r.WAFExclusions = []Item{exclusion([2]string{"param.name", "q"}, c)}
		if err := Validate(r); !errors.Is(err, ErrNotRedacted) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	r := empty()
	r.WAFRuleStats = []RuleStat{{Engine: "modsecurity", PackID: "10.0.0.1", PackVersion: "1", RuleID: "1"}}
	if err := Validate(r); !errors.Is(err, ErrNotRedacted) {
		t.Errorf("rule stat ip: %v", err)
	}
}

func TestValidateLimitsAndStructure(t *testing.T) {
	r := empty()
	r.WAFTighten = make([]Item, SectionLimits["waf_tighten"]+1)
	if err := Validate(r); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("section limit: %v", err)
	}
	r = empty()
	big := make([]RuleStat, 1000)
	for i := range big {
		big[i] = RuleStat{Engine: "modsecurity", PackID: strings.Repeat("p", 120), PackVersion: strings.Repeat("v", 120), RuleID: strings.Repeat("r", 120)}
	}
	r.WAFRuleStats, r.CCRuleStats = big, big
	if err := Validate(r); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("byte limit: %v", err)
	}
	r = empty()
	r.WAFRuleStats = nil
	if err := Validate(r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing section: %v", err)
	}
	bad := []Item{
		{Kind: cluster.KindScannerFingerprint, Target: crs, Conds: [][2]string{{"ja4", "x"}}}, // 种类不属本段
		{Kind: cluster.KindWAFExclusion, Target: crs, Conds: [][2]string{{"param.name", "q"}}, Hits: -1},
		{Kind: cluster.KindWAFExclusion, Target: crs, Conds: [][2]string{{"param.name", "q"}}, Reason: "attack"}, // 非驳回段带原因
		{Kind: cluster.KindWAFExclusion, Target: crs, Conds: [][2]string{{"param.name", "q"}}, Params: map[string]float64{"threshold": 1}},
		{Kind: cluster.KindWAFExclusion, Target: cluster.Target{Engine: "modsecurity", PackID: "crs"}, Conds: [][2]string{{"param.name", "q"}}},
	}
	for i, item := range bad {
		r := empty()
		r.WAFExclusions = []Item{item}
		if err := Validate(r); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad[%d]: %v", i, err)
		}
	}
}

func TestProofMessageBindsFields(t *testing.T) {
	d, _, _ := Digest(empty())
	a := ProofMessage(Schema, "req-1", "inst", 1, 100, d)
	for _, b := range [][]byte{ProofMessage(Schema, "req-2", "inst", 1, 100, d), ProofMessage(Schema, "req-1", "inst", 2, 100, d),
		ProofMessage(Schema, "req-1", "inst", 1, 101, d)} {
		if string(a) == string(b) {
			t.Fatal("proof message does not bind all fields")
		}
	}
}
