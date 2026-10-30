package cluster

import (
	"fmt"
	"math/rand"
	"runtime"
	"testing"
	"time"
)

// synth 生成 n 个候选：每个“意图”10 个条件，派生超集变体（+1/+2 条件）与
// 换一个条件的近似变体（Jaccard 9/11），分布在 50 个规则号、三种 kind 上；
// 每个候选 1–15 个安装、最近 20 天内的证据。固定种子，可复现。
func synth(t testing.TB, n int, seed int64) ([]Candidate, []Evidence) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	kinds := []Kind{KindAutodefenseSignature, KindScannerFingerprint, KindWAFExclusion}
	seen := map[string]bool{}
	var cands []Candidate
	var evs []Evidence
	for intent := 0; len(cands) < n; intent++ {
		kind := kinds[intent%len(kinds)]
		target := Target{Engine: "modsecurity", PackID: "crs-pl2", RuleID: fmt.Sprint(942000 + r.Intn(50))}
		base := make([]Cond, 10)
		for i := range base {
			base[i] = Cond{fmt.Sprintf("d%d", i), fmt.Sprintf("v%d", r.Intn(1000))}
		}
		if kind == KindWAFExclusion {
			base[0] = Cond{"param.name", []string{"content", "body", "html", "message", "q", "id"}[r.Intn(6)]}
		}
		variants := [][]Cond{base}
		for v := 0; v < r.Intn(5); v++ {
			c := append([]Cond(nil), base...)
			switch r.Intn(3) {
			case 0:
				c = append(c, Cond{"x1", fmt.Sprint(r.Intn(100))})
			case 1:
				c = append(c, Cond{"x1", fmt.Sprint(r.Intn(100))}, Cond{"x2", fmt.Sprint(r.Intn(100))})
			default:
				c[1+r.Intn(9)] = Cond{"swap", fmt.Sprint(r.Intn(100000))}
			}
			variants = append(variants, c)
		}
		for _, conds := range variants {
			if len(cands) >= n {
				break
			}
			canon, err := norm.Normalize(RawCandidate{Kind: kind, Target: target, Conds: conds})
			if err != nil {
				t.Fatal(err)
			}
			if seen[canon.Fingerprint] {
				continue
			}
			seen[canon.Fingerprint] = true
			first := today - 1 - r.Intn(40)
			cands = append(cands, Candidate{Canon: canon, State: StateNew, FirstSeen: first, PoolSince: first})
			for i := 0; i < 1+r.Intn(15); i++ {
				evs = append(evs, Evidence{Fingerprint: canon.Fingerprint, Day: today - r.Intn(20), Installation: fmt.Sprintf("i%d", r.Intn(3000)), Customer: fmt.Sprintf("c%d", r.Intn(800)), Weight: 1, Hits: int64(r.Intn(100))})
			}
		}
	}
	return cands, evs
}

func benchRun(b *testing.B, n int) {
	cands, evs := synth(b, n, 1)
	in := Input{Today: today, Candidates: cands, Evidence: evs}
	cfg := DefaultConfig()
	b.ReportAllocs()
	b.ResetTimer()
	var out Output
	for i := 0; i < b.N; i++ {
		var err error
		if out, err = cfg.Run(in); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	merged := 0
	for _, c := range out.Candidates {
		if c.MergedInto != "" {
			merged++
		}
	}
	b.ReportMetric(float64(len(out.Clusters)), "clusters")
	b.ReportMetric(float64(merged), "merged")
}

func BenchmarkRun10k(b *testing.B) { benchRun(b, 10000) }
func BenchmarkRun20k(b *testing.B) { benchRun(b, 20000) }

// TestRun20kBudget：RI-10 验收“20000 候选聚类 ≤ 60 秒”，并报告峰值堆。
func TestRun20kBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	cands, evs := synth(t, 20000, 1)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	out := run(t, DefaultConfig(), Input{Today: today, Candidates: cands, Evidence: evs})
	elapsed := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("20000 候选 / %d 证据行：%v，分配 %.1f MiB，簇 %d，归档 %d", len(evs), elapsed, float64(after.TotalAlloc-before.TotalAlloc)/(1<<20), len(out.Clusters), len(out.Archive))
	if elapsed > 60*time.Second {
		t.Fatalf("超过 60 秒：%v", elapsed)
	}
}
