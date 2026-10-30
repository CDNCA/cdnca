package cluster

import (
	"math"
	"testing"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestCapDaily(t *testing.T) {
	cfg := DefaultConfig()
	cases := []struct {
		name   string
		rows   []Evidence
		wantW  map[string]float64 // install → 封顶后 weight（同一天）
		wantFP map[string]float64
	}{
		{"单安装多行合计封顶到 1", []Evidence{{Installation: "i1", Customer: "c1", Weight: 0.7}, {Installation: "i1", Customer: "c1", Weight: 0.8}},
			map[string]float64{"i1": 1}, nil},
		{"同客户 4 个安装合计封顶到 2", []Evidence{{Installation: "a", Customer: "c", Weight: 1}, {Installation: "b", Customer: "c", Weight: 1}, {Installation: "d", Customer: "c", Weight: 1}, {Installation: "e", Customer: "c", Weight: 1}},
			map[string]float64{"a": 0.5, "b": 0.5, "d": 0.5, "e": 0.5}, nil},
		{"不同客户互不影响", []Evidence{{Installation: "a", Customer: "c1", Weight: 1}, {Installation: "b", Customer: "c2", Weight: 1}, {Installation: "d", Customer: "c2", Weight: 0.5}},
			map[string]float64{"a": 1, "b": 1, "d": 0.5}, nil},
		{"误判同样封顶、负值与 Inf 视为 0", []Evidence{{Installation: "a", Customer: "c", FP: 5, Weight: -1}, {Installation: "b", Customer: "c", Weight: math.Inf(1), FP: 3}},
			map[string]float64{"a": 0, "b": 0}, map[string]float64{"a": 1, "b": 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := cfg.CapDaily(tc.rows)
			if len(out) != len(tc.wantW) {
				t.Fatalf("行数 %d", len(out))
			}
			for _, r := range out {
				if !near(r.Weight, tc.wantW[r.Installation]) {
					t.Errorf("%s weight=%v want %v", r.Installation, r.Weight, tc.wantW[r.Installation])
				}
				if tc.wantFP != nil && !near(r.FP, tc.wantFP[r.Installation]) {
					t.Errorf("%s fp=%v want %v", r.Installation, r.FP, tc.wantFP[r.Installation])
				}
			}
		})
	}
}

func TestAggregateDecayAndInstalls(t *testing.T) {
	cfg := DefaultConfig()
	today := 1000
	rows := []Evidence{
		{Day: today, Installation: "a", Customer: "c1", Weight: 1},
		{Day: today - 30, Installation: "b", Customer: "c2", Weight: 1, FP: 1},
		{Day: today - 90, Installation: "x", Customer: "c3", Weight: 1}, // 窗口外
		{Day: today + 1, Installation: "y", Customer: "c3", Weight: 1},  // 未来，忽略
	}
	for i := 0; i < 5; i++ { // 一个客户 5 个安装只计 2 个
		rows = append(rows, Evidence{Day: today - 3, Installation: string(rune('m' + i)), Customer: "big", Weight: 1})
	}
	s := cfg.aggregate(rows, today)
	wantW := 1 + 0.5 + 2*math.Pow(0.5, 3.0/30)
	if !near(s.weight, wantW) {
		t.Fatalf("weight=%v want %v", s.weight, wantW)
	}
	if !near(s.fp, math.Pow(0.5, 30.0/90)) {
		t.Fatalf("fp=%v", s.fp)
	}
	if s.installs30d != 1+2 || s.installs7d != 1+2 || s.cust != 2 {
		// b 在第 30 天前（today-30 不在 <30 内）
		t.Fatalf("installs30d=%d installs7d=%d cust=%d", s.installs30d, s.installs7d, s.cust)
	}
	if s.lastSeen != today || s.firstSeen != today-30 {
		t.Fatalf("seen %d..%d", s.firstSeen, s.lastSeen)
	}
}

func TestWilsonAndConfidence(t *testing.T) {
	cfg := DefaultConfig()
	if WilsonLower(0, 0, 1.96) != 0 || WilsonUpper(0, 0, 1.96) != 1 {
		t.Fatal("n=0 端点")
	}
	if l := WilsonLower(10, 10, 1.96); l < 0.69 || l > 0.73 {
		t.Fatalf("WilsonLower(10,10)=%v", l)
	}
	// 安装越多置信越高；误判越多置信越低。
	c5 := cfg.confidence(stats{installs30d: 5, weight: 5})
	c50 := cfg.confidence(stats{installs30d: 50, weight: 50})
	c50fp := cfg.confidence(stats{installs30d: 50, weight: 50, fp: 5})
	if !(c5 < c50 && c50fp < c50) {
		t.Fatalf("c5=%v c50=%v c50fp=%v", c5, c50, c50fp)
	}
	// CC 调参分散度降低置信。
	tight := cfg.confidence(stats{installs30d: 50, weight: 50, tune: map[string]TuneStat{"threshold": {Median: 100, Q1: 95, Q3: 105}}})
	wide := cfg.confidence(stats{installs30d: 50, weight: 50, tune: map[string]TuneStat{"threshold": {Median: 100, Q1: 20, Q3: 300}}})
	if !(wide < tight && tight < c50) {
		t.Fatalf("tight=%v wide=%v", tight, wide)
	}
}

func TestTuneStats(t *testing.T) {
	cfg := DefaultConfig()
	var rows []Evidence
	for i, v := range []float64{10, 20, 30, 40, 1000} {
		rows = append(rows, Evidence{Day: 5, Installation: string(rune('a' + i)), Customer: string(rune('a' + i)), Weight: 1, Params: map[string]float64{"threshold": v}})
	}
	// 安装 a 更早一天报的旧值不参与（每安装取最近一天）
	rows = append(rows, Evidence{Day: 4, Installation: "a", Customer: "a", Weight: 1, Params: map[string]float64{"threshold": 99999}})
	s := cfg.aggregate(rows, 5)
	ts := s.tune["threshold"]
	if ts.N != 5 || ts.Median != 30 || ts.Q1 != 20 || ts.Q3 != 40 {
		t.Fatalf("%+v", ts)
	}
}
