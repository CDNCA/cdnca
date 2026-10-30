package cluster

import (
	"fmt"
	"reflect"
	"testing"
)

const today = 20000

var norm = Normalizer{ParamClass: richText}

func mk(t testing.TB, kind Kind, state State, conds ...Cond) Candidate {
	t.Helper()
	c, err := norm.Normalize(RawCandidate{Kind: kind, Target: tgt, Conds: conds})
	if err != nil {
		t.Fatal(err)
	}
	return Candidate{Canon: c, State: state, FirstSeen: today - 1, PoolSince: today - 1}
}

// ev：n 个安装（每客户 perCust 个）各在 day 给 1 个权重。
func ev(fp string, day, n, perCust int, fp1 float64, prefix string) []Evidence {
	out := make([]Evidence, n)
	for i := range out {
		out[i] = Evidence{Fingerprint: fp, Day: day, Installation: fmt.Sprintf("%s-i%d", prefix, i), Customer: fmt.Sprintf("%s-c%d", prefix, i/perCust), Weight: 1, FP: fp1}
	}
	return out
}

func find(out Output, fp string) Candidate {
	for _, c := range out.Candidates {
		if c.Fingerprint == fp {
			return c
		}
	}
	return Candidate{}
}

func run(t testing.TB, cfg Config, in Input) Output {
	t.Helper()
	out, err := cfg.Run(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRunContainmentMerge(t *testing.T) {
	general := mk(t, KindWAFExclusion, StateNew, Cond{"param.name", "q"})
	specific := mk(t, KindWAFExclusion, StateNew, Cond{"param.name", "q"}, Cond{"value_type", "text"})
	cases := []struct {
		name        string
		genN, specN int
		genFP       float64
		wantMerged  bool
	}{
		{"通用候选证据多 → 具体并入通用", 12, 4, 0, true},
		{"通用候选安装少 → 保留具体，通用标通用化", 3, 12, 0, false},
		{"通用候选误判高 → 保留具体", 12, 4, 0.5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evs := append(ev(general.Fingerprint, today, tc.genN, 1, tc.genFP, "g"), ev(specific.Fingerprint, today, tc.specN, 1, 0, "s")...)
			out := run(t, DefaultConfig(), Input{Today: today, Candidates: []Candidate{general, specific}, Evidence: evs})
			s, g := find(out, specific.Fingerprint), find(out, general.Fingerprint)
			if tc.wantMerged {
				if s.MergedInto != general.Fingerprint || len(g.Variants) != 1 || g.Variants[0].Fingerprint != specific.Fingerprint {
					t.Fatalf("应合并：%+v / variants=%v", s.MergedInto, g.Variants)
				}
				if g.Installs30d != tc.genN+tc.specN {
					t.Fatalf("证据未累加：%d", g.Installs30d)
				}
				if len(out.Archive) != 1 || out.Archive[0].Source != ArchiveVariant || out.Archive[0].MergedInto != general.Fingerprint {
					t.Fatalf("变体未归档：%+v", out.Archive)
				}
				if len(out.Clusters) != 1 || len(out.Clusters[0].Members) != 2 || len(out.Clusters[0].MinHash) != 128 {
					t.Fatalf("簇：%+v", out.Clusters)
				}
			} else {
				if s.MergedInto != "" || g.MergedInto != "" {
					t.Fatal("不应合并")
				}
				if g.GeneralizationOf != specific.Fingerprint {
					t.Fatalf("应标通用化：%q", g.GeneralizationOf)
				}
				if len(out.Archive) != 0 {
					t.Fatal("不应归档")
				}
			}
		})
	}
}

func TestRunNearDuplicate(t *testing.T) {
	// 10 个共同条件 + 各自 1 个不同条件：Jaccard = 10/12 ≈ 0.83 ≥ 0.8。
	var common []Cond
	for i := 0; i < 10; i++ {
		common = append(common, Cond{"ua_family", fmt.Sprintf("u%02d", i)})
	}
	a := mk(t, KindScannerFingerprint, StateNew, append(append([]Cond{}, common...), Cond{"ja4", "aaa"})...)
	b := mk(t, KindScannerFingerprint, StateNew, append(append([]Cond{}, common...), Cond{"ja4", "bbb"})...)
	far := mk(t, KindScannerFingerprint, StateNew, Cond{"ja4", "zzz"})
	evs := append(ev(a.Fingerprint, today, 8, 1, 0, "a"), ev(b.Fingerprint, today, 3, 1, 0, "b")...)
	evs = append(evs, ev(far.Fingerprint, today, 3, 1, 0, "f")...)
	out := run(t, DefaultConfig(), Input{Today: today, Candidates: []Candidate{a, b, far}, Evidence: evs})
	if got := find(out, b.Fingerprint).MergedInto; got != a.Fingerprint {
		t.Fatalf("b 应并入证据更多的 a，得 %q", got)
	}
	if find(out, far.Fingerprint).MergedInto != "" {
		t.Fatal("far 不应合并")
	}
}

func TestRunCategoryExclusion(t *testing.T) {
	var cands []Candidate
	var evs []Evidence
	for _, name := range []string{"content", "body", "html", "message"} {
		c := mk(t, KindWAFExclusion, StateNew, Cond{"param.name", name}, Cond{"value_type", "text"})
		cands = append(cands, c)
		evs = append(evs, ev(c.Fingerprint, today, 3, 1, 0, name)...)
	}
	other := mk(t, KindWAFExclusion, StateNew, Cond{"param.name", "id"}, Cond{"value_type", "text"})
	cands = append(cands, other)
	out := run(t, DefaultConfig(), Input{Today: today, Candidates: cands, Evidence: evs})
	cls, _ := finish(KindWAFExclusion, tgt, []Cond{{"param.class", "rich_text"}, {"value_type", "text"}})
	syn := find(out, cls.Fingerprint)
	if !syn.Synthetic || len(syn.Variants) != 4 || syn.Installs30d != 12 {
		t.Fatalf("类别级候选：synthetic=%v variants=%d installs=%d", syn.Synthetic, len(syn.Variants), syn.Installs30d)
	}
	if syn.State != StateReady {
		t.Fatalf("12 安装 × 12 客户应 ready，得 %s", syn.State)
	}
	if find(out, other.Fingerprint).MergedInto != "" || len(out.Archive) != 4 {
		t.Fatalf("字典外参数不应合并；归档 %d", len(out.Archive))
	}
	// 只有一个富文本参数时不合成。
	out = run(t, DefaultConfig(), Input{Today: today, Candidates: cands[:1]})
	if len(out.Candidates) != 1 {
		t.Fatalf("单成员不应合成：%d", len(out.Candidates))
	}
}

func TestRunCCTuneMedian(t *testing.T) {
	a := mk(t, KindCCRuleTune, StateNew, Cond{"window", "60"}, Cond{"cc.threshold", "100"})
	b := mk(t, KindCCRuleTune, StateNew, Cond{"window", "10"}, Cond{"cc.threshold", "20"})
	var evs []Evidence
	for i, v := range []float64{80, 100, 120, 140, 900} {
		fp := a.Fingerprint
		if i == 4 {
			fp = b.Fingerprint
		}
		evs = append(evs, Evidence{Fingerprint: fp, Day: today, Installation: fmt.Sprint(i), Customer: fmt.Sprint(i), Weight: 1, Params: map[string]float64{"threshold": v}})
	}
	out := run(t, DefaultConfig(), Input{Today: today, Candidates: []Candidate{a, b}, Evidence: evs})
	rep := find(out, a.Fingerprint)
	if find(out, b.Fingerprint).MergedInto != a.Fingerprint {
		t.Fatal("同一官方 CC 规则应合成一个簇")
	}
	if ts := rep.Tune["threshold"]; ts.Median != 120 || ts.N != 5 || ts.Q1 != 100 || ts.Q3 != 140 {
		t.Fatalf("%+v", ts)
	}
}

func TestRunStates(t *testing.T) {
	cfg := DefaultConfig()
	cases := []struct {
		name  string
		cand  func() Candidate
		evs   func(fp string) []Evidence
		tombs func(fp string) []Tombstone
		want  State
		arch  ArchiveSource
	}{
		{"10 安装 2 客户 → ready", func() Candidate { return mk(t, KindWAFExclusion, StateNew, Cond{"param.name", "q"}) },
			func(fp string) []Evidence { return ev(fp, today, 10, 2, 0, "x") }, nil, StateReady, ""},
		{"单客户 20 安装刷 → 不 ready（有效安装 2）", func() Candidate { return mk(t, KindWAFExclusion, StateNew, Cond{"param.name", "q"}) },
			func(fp string) []Evidence { return ev(fp, today, 20, 20, 0, "x") }, nil, StateNew, ""},
		{"安装够但都是同 1 客户 ×2 → 不 ready（客户数 <2）", func() Candidate { return mk(t, KindAutodefenseSignature, StateNew, Cond{"uri", "/x"}) },
			func(fp string) []Evidence { return ev(fp, today, 2, 2, 0, "x") }, nil, StateNew, ""},
		{"非排除类 5 安装 → ready", func() Candidate { return mk(t, KindAutodefenseSignature, StateNew, Cond{"uri", "/x"}) },
			func(fp string) []Evidence { return ev(fp, today, 5, 1, 0, "x") }, nil, StateReady, ""},
		{"最近 14 天无证据 → ready 退回 new", func() Candidate { return mk(t, KindAutodefenseSignature, StateReady, Cond{"uri", "/x"}) },
			func(fp string) []Evidence { return ev(fp, today-20, 10, 1, 0, "x") }, nil, StateNew, ""},
		{"误判率 >5% → quarantined", func() Candidate { return mk(t, KindAutodefenseSignature, StateReady, Cond{"uri", "/x"}) },
			func(fp string) []Evidence { return ev(fp, today, 10, 1, 0.1, "x") }, nil, StateQuarantined, ""},
		{"30 天 weight<0.5 → expired 并归档", func() Candidate {
			c := mk(t, KindAutodefenseSignature, StateNew, Cond{"uri", "/x"})
			c.PoolSince = today - 40
			return c
		}, func(string) []Evidence { return nil }, nil, StateExpired, ArchiveExpired},
		{"已发布：零证据也不过期", func() Candidate {
			c := mk(t, KindAutodefenseSignature, StateReleased, Cond{"uri", "/x"})
			c.PoolSince = today - 400
			return c
		}, func(string) []Evidence { return nil }, nil, StateReleased, ""},
		{"已发布：误判高也不隔离", func() Candidate { return mk(t, KindAutodefenseSignature, StateReleased, Cond{"uri", "/x"}) },
			func(fp string) []Evidence { return ev(fp, today, 10, 1, 1, "x") }, nil, StateReleased, ""},
		{"墓碑中 → rejected", func() Candidate { return mk(t, KindAutodefenseSignature, StateReady, Cond{"uri", "/x"}) },
			func(fp string) []Evidence { return ev(fp, today, 10, 1, 0, "x") },
			func(fp string) []Tombstone { return []Tombstone{{Fingerprint: fp, Until: today + 1}} }, StateRejected, ""},
		{"墓碑到期且有新证据 → 恢复", func() Candidate {
			c := mk(t, KindAutodefenseSignature, StateRejected, Cond{"uri", "/x"})
			c.StateDay = today - 200
			return c
		}, func(fp string) []Evidence { return ev(fp, today, 10, 1, 0, "x") },
			func(fp string) []Tombstone { return []Tombstone{{Fingerprint: fp, Until: today - 1}} }, StateReady, ""},
		{"过期后同指纹再出现 → 恢复并继承证据", func() Candidate {
			c := mk(t, KindAutodefenseSignature, StateExpired, Cond{"uri", "/x"})
			c.StateDay = today - 10
			return c
		}, func(fp string) []Evidence {
			return append(ev(fp, today-15, 4, 1, 0, "old"), ev(fp, today, 1, 1, 0, "new")...)
		}, nil, StateReady, ""},
		{"永久墓碑：新证据也不恢复", func() Candidate {
			c := mk(t, KindAutodefenseSignature, StateRejected, Cond{"uri", "/x"})
			c.StateDay = today - 900
			return c
		}, func(fp string) []Evidence { return ev(fp, today, 10, 1, 0, "x") },
			func(fp string) []Tombstone { return []Tombstone{{Fingerprint: fp, Permanent: true}} }, StateRejected, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cand()
			var tombs []Tombstone
			if tc.tombs != nil {
				tombs = tc.tombs(c.Fingerprint)
			}
			out := run(t, cfg, Input{Today: today, Candidates: []Candidate{c}, Evidence: tc.evs(c.Fingerprint), Tombstones: tombs})
			got := find(out, c.Fingerprint)
			if got.State != tc.want {
				t.Fatalf("state=%s want %s (installs=%d cust=%d w=%.3f fp=%.3f)", got.State, tc.want, got.Installs30d, got.Customers30d, got.Weight, got.FPWeight)
			}
			if tc.arch != "" && (len(out.Archive) != 1 || out.Archive[0].Source != tc.arch) {
				t.Fatalf("归档：%+v", out.Archive)
			}
			if tc.arch == "" && len(out.Archive) != 0 {
				t.Fatalf("不应归档：%+v", out.Archive)
			}
		})
	}
}

func TestRunReleasedNeverMergedAway(t *testing.T) {
	rel := mk(t, KindWAFExclusion, StateReleased, Cond{"param.name", "q"}, Cond{"value_type", "text"})
	gen := mk(t, KindWAFExclusion, StateNew, Cond{"param.name", "q"})
	evs := ev(gen.Fingerprint, today, 30, 1, 0, "g")
	out := run(t, DefaultConfig(), Input{Today: today, Candidates: []Candidate{rel, gen}, Evidence: evs})
	if find(out, rel.Fingerprint).MergedInto != "" || find(out, rel.Fingerprint).State != StateReleased {
		t.Fatal("已发布候选不得被合并或改状态")
	}
	// 新的更具体变体并入已发布规则（证据累加到已发布代表上）。
	spec := mk(t, KindWAFExclusion, StateNew, Cond{"param.name", "q"}, Cond{"value_type", "text"}, Cond{"param.loc", "body"})
	out = run(t, DefaultConfig(), Input{Today: today, Candidates: []Candidate{rel, spec}, Evidence: ev(spec.Fingerprint, today, 1, 1, 0, "s")})
	if find(out, spec.Fingerprint).MergedInto != rel.Fingerprint || find(out, rel.Fingerprint).Installs30d != 1 {
		t.Fatal("具体变体应并入已发布规则")
	}
}

func TestRunCapacity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.KindCap, cfg.TotalCap = 3, 4
	var cands []Candidate
	var evs []Evidence
	for i := 0; i < 5; i++ {
		c := mk(t, KindAutodefenseSignature, StateNew, Cond{"uri", fmt.Sprintf("/a%d", i)})
		cands = append(cands, c)
		evs = append(evs, ev(c.Fingerprint, today, i+1, 1, 0, fmt.Sprint("a", i))...)
	}
	for i := 0; i < 2; i++ {
		c := mk(t, KindScannerFingerprint, StateNew, Cond{"ja4", fmt.Sprintf("j%d", i)})
		cands = append(cands, c)
		evs = append(evs, ev(c.Fingerprint, today, 10*(i+1), 1, 0, fmt.Sprint("j", i))...)
	}
	rel := mk(t, KindAutodefenseSignature, StateReleased, Cond{"uri", "/rel"})
	drafted := mk(t, KindAutodefenseSignature, StateDrafted, Cond{"uri", "/draft"}) // 零证据但在草稿
	cands = append(cands, rel, drafted)
	out := run(t, cfg, Input{Today: today, Candidates: cands, Evidence: evs})
	if out.Pool[KindAutodefenseSignature] != 2 || out.Pool[KindScannerFingerprint] != 2 || out.PoolTotal != 4 {
		t.Fatalf("pool=%v total=%d", out.Pool, out.PoolTotal)
	}
	// autodefense 池 6 个（a0–a4 + 草稿）：kind 上限淘汰 a0–a2；总量 5>4 再淘汰
	// 剩余非草稿里最低的 a3（草稿零分也最后淘汰）。
	for i, want := range []State{StateExpired, StateExpired, StateExpired, StateExpired, StateReady} {
		if got := find(out, cands[i].Fingerprint).State; got != want {
			t.Errorf("a%d state=%s want %s", i, got, want)
		}
	}
	if find(out, drafted.Fingerprint).State != StateDrafted || find(out, rel.Fingerprint).State != StateReleased {
		t.Fatal("草稿应最后淘汰、已发布不计入容量")
	}
	if len(out.Archive) != 4 {
		t.Fatalf("淘汰者应归档：%d", len(out.Archive))
	}
	for _, a := range out.Archive {
		if a.Source != ArchiveExpired || a.Reason != "capacity" {
			t.Fatalf("%+v", a)
		}
	}
}

func TestRunDeterministic(t *testing.T) {
	cands, evs := synth(t, 600, 7)
	out1 := run(t, DefaultConfig(), Input{Today: today, Candidates: cands, Evidence: evs})
	// 打乱输入顺序
	rc := append([]Candidate(nil), cands...)
	for i, j := 0, len(rc)-1; i < j; i, j = i+1, j-1 {
		rc[i], rc[j] = rc[j], rc[i]
	}
	re := append([]Evidence(nil), evs...)
	for i, j := 0, len(re)-1; i < j; i, j = i+1, j-1 {
		re[i], re[j] = re[j], re[i]
	}
	out2 := run(t, DefaultConfig(), Input{Today: today, Candidates: rc, Evidence: re})
	if !reflect.DeepEqual(out1, out2) {
		t.Fatal("同输入不同顺序结果不同")
	}
	if len(out1.Clusters) == 0 {
		t.Fatal("夹具应产生簇")
	}
	// 幂等：把输出再跑一次，簇与代表不变。
	out3 := run(t, DefaultConfig(), Input{Today: today, Candidates: out1.Candidates, Evidence: evs})
	if !reflect.DeepEqual(out1.Clusters, out3.Clusters) || len(out3.Archive) != 0 {
		t.Fatalf("二次运行簇变化或重复归档（%d）", len(out3.Archive))
	}
}

func TestRejectTombstone(t *testing.T) {
	cfg := DefaultConfig()
	if tb := cfg.Reject("f", 0, today); tb.Permanent || tb.Until != today+180 {
		t.Fatalf("%+v", tb)
	}
	if tb := cfg.Reject("f", 2, today); !tb.Permanent {
		t.Fatal("第 3 次驳回应永久")
	}
	if !Blocked([]Tombstone{{Fingerprint: "f", Until: today}}, "f", today) || Blocked([]Tombstone{{Fingerprint: "f", Until: today - 1}}, "f", today) {
		t.Fatal("Blocked")
	}
}

func TestRunConfigErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rows = 5
	if _, err := cfg.Run(Input{}); err == nil {
		t.Fatal("bands×rows≠hashes 应报错")
	}
	c := mk(t, KindWAFExclusion, StateNew, Cond{"param.name", "q"})
	if _, err := DefaultConfig().Run(Input{Candidates: []Candidate{c, c}}); err == nil {
		t.Fatal("重复指纹应报错")
	}
}
