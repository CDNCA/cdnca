package quality

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

// rounds builds one round every 10 minutes going back from now; healthy(i)
// decides round i (0 = newest).
func rounds(n int, healthy func(int) bool, latency int) []Round {
	out := make([]Round, n)
	for i := range out {
		out[i] = Round{At: now.Add(-time.Duration(i) * 10 * time.Minute), Healthy: healthy(i), LatencyMs: latency}
	}
	return out
}

func TestScoreInsufficientDataIsNeutral(t *testing.T) {
	s := Compute(DefaultConfig(), Inputs{Rounds: rounds(5, func(int) bool { return true }, 30)}, now)
	if s.Score != NeutralScore || s.Tier != TierInsufficient {
		t.Fatalf("%+v", s)
	}
}

func TestScorePerfectNodeIsHighAndHasNoDeductions(t *testing.T) {
	s := Compute(DefaultConfig(), Inputs{Rounds: rounds(144, func(int) bool { return true }, 30), Grade: "s", Periods: 10}, now)
	if s.Score != MaxScore || s.Tier != TierHigh || len(s.Deductions) != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestForgettingFactorWeighsRecentRounds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Weights = Weights{Availability: 1}
	// Same 50% failure rate; failures recent vs. failures old.
	recentBad := Compute(cfg, Inputs{Rounds: rounds(100, func(i int) bool { return i >= 50 }, 30)}, now)
	oldBad := Compute(cfg, Inputs{Rounds: rounds(100, func(i int) bool { return i < 50 }, 30)}, now)
	if !(*recentBad.Availability < 0.5 && *oldBad.Availability > 0.5 && recentBad.Score < oldBad.Score) {
		t.Fatalf("recent=%v old=%v", *recentBad.Availability, *oldBad.Availability)
	}
	cfg.Lambda = 1 // no forgetting: both are exactly 50%
	if a := *Compute(cfg, Inputs{Rounds: rounds(100, func(i int) bool { return i >= 50 }, 30)}, now).Availability; a != 0.5 {
		t.Fatalf("lambda=1 availability %v", a)
	}
}

func TestDimensionsUseTheirOwnWindows(t *testing.T) {
	cfg := DefaultConfig()
	// Healthy for the last 24h; a burst of slow and flapping rounds 3 days ago
	// is outside the availability window but inside latency/stability (7d).
	in := rounds(144, func(int) bool { return true }, 30)
	for i := 0; i < 20; i++ {
		in = append(in, Round{At: now.Add(-72*time.Hour - time.Duration(i)*time.Minute), Healthy: i%2 == 0, LatencyMs: 900})
	}
	s := Compute(cfg, Inputs{Rounds: in}, now)
	if *s.Availability != 1 {
		t.Fatalf("availability should ignore rounds older than 24h: %v", *s.Availability)
	}
	rules := map[string]Deduction{}
	for _, d := range s.Deductions {
		rules[d.Rule] = d
	}
	if rules["stability"].Window != "7d" || rules["stability"].Value <= 0 {
		t.Fatalf("stability deduction missing: %+v", s.Deductions)
	}
	if _, ok := rules["availability"]; ok {
		t.Fatalf("unexpected availability deduction: %+v", s.Deductions)
	}
	disputed := Compute(cfg, Inputs{Rounds: rounds(144, func(int) bool { return true }, 30), Incidents: 3, Periods: 10}, now)
	if *disputed.DisputeRate != 0.3 || disputed.Score >= MaxScore {
		t.Fatalf("dispute dimension: %+v", disputed)
	}
}

func TestTiers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Weights = Weights{Availability: 1}
	cfg.Lambda = 1
	low := Compute(cfg, Inputs{Rounds: rounds(100, func(i int) bool { return i%3 == 0 }, 30)}, now)
	if low.Tier != TierLow {
		t.Fatalf("low: %+v", low)
	}
	std := Compute(cfg, Inputs{Rounds: rounds(99, func(i int) bool { return i%3 != 0 }, 30)}, now)
	if std.Tier != TierStandard {
		t.Fatalf("standard: %+v", std)
	}
}

func cand(key, _ string, price, score float64, probation bool) Candidate {
	return Candidate{Key: key, Price: price, Score: score, Probation: probation}
}

func TestSelectFiltersPriceAndQualityThenSamples(t *testing.T) {
	cfg := DefaultSelectConfig()
	cfg.Count, cfg.MaxPrice, cfg.MinScore = 10, 100, 1.0
	in := []Candidate{
		cand("a", "p1", 50, 2.5, false),
		cand("b", "p2", 150, 2.9, false), // over price cap
		cand("c", "p3", 80, 0.5, false),  // under quality floor
		cand("d", "p4", 0, 2.0, false),   // unknown price is not filtered
	}
	sel := Select(cfg, in, rand.New(rand.NewPCG(1, 2)))
	got := slices.Clone(sel.Keys)
	slices.Sort(got)
	if !slices.Equal(got, []string{"a", "d"}) || sel.FilteredPrice != 1 || sel.FilteredScore != 1 || sel.FiltersWaived {
		t.Fatalf("%+v", sel)
	}
	// Everything filtered: serve the unfiltered set instead of nothing.
	cfg.MaxPrice = 1
	cfg.MinScore = 2.95
	if sel := Select(cfg, in, rand.New(rand.NewPCG(1, 2))); !sel.FiltersWaived || len(sel.Keys) != 4 {
		t.Fatalf("waived: %+v", sel)
	}
	cfg.IgnoreFiltersIfEmpty = false
	if sel := Select(cfg, in, rand.New(rand.NewPCG(1, 2))); len(sel.Keys) != 0 {
		t.Fatalf("strict: %+v", sel)
	}
}

func TestSelectIsReproducibleWithAFixedSeed(t *testing.T) {
	cfg := DefaultSelectConfig()
	cfg.Count = 3
	var in []Candidate
	for i := 0; i < 20; i++ {
		in = append(in, cand(string(rune('a'+i)), string(rune('A'+i)), float64(10+i), 1+float64(i%5)*0.4, false))
	}
	shuffled := slices.Clone(in)
	rand.New(rand.NewPCG(9, 9)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	first := Select(cfg, in, rand.New(rand.NewPCG(42, 7))).Keys
	again := Select(cfg, shuffled, rand.New(rand.NewPCG(42, 7))).Keys
	if len(first) != 3 || !slices.Equal(first, again) {
		t.Fatalf("not reproducible: %v vs %v", first, again)
	}
	differs := false
	for seed := uint64(0); seed < 20 && !differs; seed++ {
		differs = !slices.Equal(first, Select(cfg, in, rand.New(rand.NewPCG(seed, 1))).Keys)
	}
	if !differs {
		t.Fatal("selection ignores the seed")
	}
}

func TestSelectWeightsFavourQualityAndPrice(t *testing.T) {
	cfg := DefaultSelectConfig()
	cfg.Count = 1
	in := []Candidate{cand("good-cheap", "p1", 10, 3, false), cand("bad-dear", "p2", 100, 0.3, false)}
	wins := 0
	for seed := uint64(0); seed < 2000; seed++ {
		if Select(cfg, in, rand.New(rand.NewPCG(seed, 3))).Keys[0] == "good-cheap" {
			wins++
		}
	}
	if wins < 1400 {
		t.Fatalf("good-cheap won only %d/2000", wins)
	}
}

func TestSelectCapsProbationShare(t *testing.T) {
	cfg := DefaultSelectConfig()
	cfg.Count, cfg.ProbationCap = 10, 0.1
	var in []Candidate
	for i := 0; i < 30; i++ {
		in = append(in, cand("adm"+string(rune('a'+i)), "a"+string(rune('a'+i)), 10, 2, false))
	}
	for i := 0; i < 30; i++ {
		// Probation nodes look better on paper but stay capped.
		in = append(in, cand("pro"+string(rune('a'+i)), "p"+string(rune('a'+i)), 1, 3, true))
	}
	probationPicks, total := 0, 0
	for seed := uint64(0); seed < 500; seed++ {
		sel := Select(cfg, in, rand.New(rand.NewPCG(seed, 5)))
		for _, k := range sel.Keys {
			total++
			if k[:3] == "pro" {
				probationPicks++
			}
		}
	}
	// Full answers: exactly one probation node in ten.
	if share := float64(probationPicks) / float64(total); share > 0.1+1e-9 || share < 0.1-1e-9 {
		t.Fatalf("probation share %.3f, want the cap", share)
	}
	// Short answers (3 admitted): long-run share ≈ cap.
	short := append(slices.Clone(in[:3]), in[30:]...)
	probationPicks, total = 0, 0
	for seed := uint64(0); seed < 4000; seed++ {
		for _, k := range Select(cfg, short, rand.New(rand.NewPCG(seed, 11))).Keys {
			total++
			if k[:3] == "pro" {
				probationPicks++
			}
		}
	}
	if share := float64(probationPicks) / float64(total); share > 0.12 || share < 0.07 {
		t.Fatalf("short-answer probation share %.3f", share)
	}
	// Few admitted nodes: probation fills only up to the cap of the answer…
	small := []Candidate{cand("adm", "a", 10, 2, false), cand("pro1", "p1", 10, 3, true), cand("pro2", "p2", 10, 3, true)}
	cfg.ProbationCap = 0
	if sel := Select(cfg, small, rand.New(rand.NewPCG(1, 1))); !slices.Equal(sel.Keys, []string{"adm"}) {
		t.Fatalf("cap 0: %+v", sel)
	}
	// …but a line with only probation nodes is still served.
	if sel := Select(cfg, small[1:], rand.New(rand.NewPCG(1, 1))); len(sel.Keys) != 2 {
		t.Fatalf("probation-only line: %+v", sel)
	}
}
