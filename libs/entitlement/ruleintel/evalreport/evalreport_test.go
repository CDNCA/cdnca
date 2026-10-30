package evalreport

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func report(t *testing.T, outcomes ...string) []byte {
	t.Helper()
	tiers := []Tier{{PackID: "system/crs-pl1-log", Name: "仅记录"}, {PackID: StandardPackID, Name: "标准防护"},
		{PackID: "system/crs-pl2", Name: "严格防护"}}
	value := Report{Schema: Schema, CRSVersion: "4.30.0", Tiers: tiers, Corpus: strings.Repeat("a", 64)}
	for index, outcome := range outcomes {
		value.Results = append(value.Results, Result{ID: "s" + string(rune('0'+index)), Attack: index < 2, Outcome: outcome})
	}
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// 样本 s0、s1 是攻击，s2、s3 是正常请求；每个字符串依次是 仅记录/标准/严格 三档结果。
func TestDecide(t *testing.T) {
	base := report(t, "pbb", "ppb", "ppp", "ppb")
	cases := []struct {
		name      string
		candidate []byte
		reasons   []string
		changes   int
	}{
		{"same", base, []string{}, 0},
		// 严格档一条拦截改为挑战（挑战也算拦截）、少一条误报：通过，变化列出
		{"strict better", report(t, "pbc", "ppb", "ppp", "ppp"), []string{}, 2},
		// 严格档漏掉一条攻击：拦截率下降
		{"strict drops", report(t, "pbb", "ppp", "ppp", "ppb"), []string{ReasonBlockRateDrop}, 1},
		// 严格档新增误报
		{"strict false positive", report(t, "pbb", "ppb", "ppc", "ppb"), []string{ReasonFalsePosRise}, 1},
		// 标准档多拦一条攻击（拦截率升高）也拒绝：标准档逐条必须相同
		{"standard changed", report(t, "pbb", "pbb", "ppp", "ppb"), []string{ReasonStandardChanged}, 1},
		// 评测出错不算候选好坏，但不放行
		{"eval error", report(t, "pbb", "ppb", "ppe", "ppb"), []string{ReasonEvalErrors}, 1},
	}
	for _, c := range cases {
		verdict, err := Decide(base, c.candidate, StandardPackID)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !slices.Equal(verdict.Reasons, c.reasons) || verdict.Passed != (len(c.reasons) == 0) || len(verdict.Changes) != c.changes {
			t.Fatalf("%s: %+v", c.name, verdict)
		}
		if verdict.BaseSHA256 != Digest(base) || verdict.CandidateSHA256 != Digest(c.candidate) {
			t.Fatalf("%s: digests %+v", c.name, verdict)
		}
	}
	// 可复算：同样两份字节，结论逐字节相同
	first, _ := Decide(base, report(t, "pbc", "ppb", "ppp", "ppp"), StandardPackID)
	second, _ := Decide(base, report(t, "pbc", "ppb", "ppp", "ppp"), StandardPackID)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("verdict not reproducible")
	}
	if first.Tiers[2].Base.Blocked != 2 || first.Tiers[2].Candidate.Blocked != 2 || first.Tiers[2].Candidate.FalsePositives != 0 {
		t.Fatalf("strict counts %+v", first.Tiers[2])
	}
}

func TestDecideMismatch(t *testing.T) {
	base := report(t, "pbb", "ppb")
	var other Report
	_ = json.Unmarshal(base, &other)
	other.Corpus = strings.Repeat("b", 64)
	changed, _ := json.Marshal(other)
	verdict, err := Decide(base, changed, StandardPackID)
	if err != nil || verdict.Passed || !slices.Equal(verdict.Reasons, []string{ReasonMismatch}) {
		t.Fatalf("%+v %v", verdict, err)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, content := range []string{
		`{}`,
		`{"schema":"cdnca.waf-eval-report/v1","crs_version":"x","tiers":[{"pack_id":"a"}],"corpus_sha256":"` + strings.Repeat("a", 64) + `","results":[{"id":"1","attack":true,"outcome":"x"}]}`,
		`{"schema":"cdnca.waf-eval-report/v1","crs_version":"x","tiers":[{"pack_id":"a"}],"corpus_sha256":"` + strings.Repeat("a", 64) + `","results":[{"id":"1","attack":true,"outcome":"pp"}]}`,
		`{"schema":"cdnca.waf-eval-report/v1","crs_version":"x","tiers":[{"pack_id":"a"}],"corpus_sha256":"` + strings.Repeat("a", 64) + `","results":[{"id":"1","outcome":"p"},{"id":"1","outcome":"p"}]}`,
		`{"schema":"cdnca.waf-eval-report/v1","extra":1}`,
	} {
		if _, err := Decode([]byte(content)); err == nil {
			t.Fatalf("accepted %s", content)
		}
	}
}

func TestCorpusDigestOrderAndContent(t *testing.T) {
	a := []Request{{ID: "1", Attack: true, Value: "x"}, {ID: "2", Method: "GET", URI: "/", Headers: map[string]string{"B": "1", "A": "2"}}}
	b := []Request{a[1], a[0]}
	if CorpusDigest(a) == CorpusDigest(b) || CorpusDigest(a) != CorpusDigest(slices.Clone(a)) {
		t.Fatal("digest must follow order and be stable")
	}
}

// 通用数据集样本（std:）无应答记 x：新旧任一次为 x 的样本两边都不计；非 std 样本不得为 x；std 来源须一致。
func TestDecideStdExcluded(t *testing.T) {
	build := func(std *StdSource, results ...Result) []byte {
		value := Report{Schema: Schema, CRSVersion: "4.30.0", Corpus: strings.Repeat("a", 64), Std: std,
			Tiers: []Tier{{PackID: StandardPackID}, {PackID: "system/crs-pl2"}}, Results: results}
		content, _ := json.Marshal(value)
		return content
	}
	source := &StdSource{Mode: StdFast, Files: []StdFile{{Name: "wafcomp-legit", SHA256: strings.Repeat("b", 64), Requests: 2}}}
	base := build(source, Result{ID: "a", Attack: true, Outcome: "bb"}, Result{ID: "std:wafcomp-legit:1", Outcome: "pb"},
		Result{ID: "std:wafcomp-legit:2", Outcome: "pp"})
	// 样本 1 候选在严格档无应答（原为误报）、样本 2 两档无应答：不计，不算误报下降、也不算评测出错
	candidate := build(source, Result{ID: "a", Attack: true, Outcome: "bb"}, Result{ID: "std:wafcomp-legit:1", Outcome: "px"},
		Result{ID: "std:wafcomp-legit:2", Outcome: "xx"})
	verdict, err := Decide(base, candidate, StandardPackID)
	if err != nil || !verdict.Passed || len(verdict.Changes) != 0 || verdict.Std == nil || verdict.Std.Mode != StdFast {
		t.Fatalf("%+v %v", verdict, err)
	}
	if strict := verdict.Tiers[1]; strict.Base.Excluded != 2 || strict.Base.FalsePositives != 0 || strict.Candidate.Benign != 0 {
		t.Fatalf("strict %+v", strict)
	}
	if standard := verdict.Tiers[0]; standard.Base.Excluded != 1 || standard.Base.Benign != 1 {
		t.Fatalf("standard %+v", standard)
	}
	if _, err := Decode(build(nil, Result{ID: "a", Attack: true, Outcome: "bx"})); err == nil {
		t.Fatal("x accepted outside the public datasets")
	}
	other := &StdSource{Mode: StdFull, Files: source.Files}
	if verdict, _ := Decide(base, build(other, Result{ID: "a", Attack: true, Outcome: "bb"}, Result{ID: "std:wafcomp-legit:1", Outcome: "pb"},
		Result{ID: "std:wafcomp-legit:2", Outcome: "pp"}), StandardPackID); !slices.Equal(verdict.Reasons, []string{ReasonMismatch}) {
		t.Fatalf("std mode mismatch %+v", verdict.Reasons)
	}
}

// 情报只打标包回放（ModeMark）：一"档"即该包，b = 被打标；与档位包回放模式不同的两份报告不可比。
func TestDecideMarkMode(t *testing.T) {
	mark := func(mode string, outcomes ...string) []byte {
		value := Report{Schema: Schema, CRSVersion: "4.30.0", Mode: mode, Corpus: strings.Repeat("a", 64),
			Tiers: []Tier{{PackID: "system/scanner-signatures", Name: "扫描器特征"}}}
		for index, outcome := range outcomes {
			value.Results = append(value.Results, Result{ID: "m" + string(rune('0'+index)), Attack: index == 0, Outcome: outcome})
		}
		content, _ := json.Marshal(value)
		return content
	}
	base := mark(ModeMark, "b", "p")
	for _, c := range []struct {
		name      string
		candidate []byte
		reasons   []string
	}{
		{"same", mark(ModeMark, "b", "p"), []string{}},
		{"misses an attack", mark(ModeMark, "p", "p"), []string{ReasonBlockRateDrop}},
		{"marks normal traffic", mark(ModeMark, "b", "b"), []string{ReasonFalsePosRise}},
		{"tier mode report", mark("", "b", "p"), []string{ReasonMismatch}},
	} {
		verdict, err := Decide(base, c.candidate, StandardPackID)
		if err != nil || !slices.Equal(verdict.Reasons, c.reasons) {
			t.Fatalf("%s: %v %v", c.name, verdict.Reasons, err)
		}
	}
	if _, err := Decode(mark("other", "b", "p")); err == nil {
		t.Fatal("unknown mode accepted")
	}
}
