// Package quality turns probing, benchmarks and disputes into a node quality
// score, and selects supply DNS answers from scored candidates
// (docs/architecture/marketplace-buildout.md §3.12, §2.7).
//
// The score is multi-dimensional with a different time window per dimension
// (the idea of Mysterium's node quality, 0–3 with 1.5 when data is missing)
// and an exponential forgetting factor on availability (the idea of Storj's
// reputation lambda). No GPL/AGPL code is used; the formulas are written here.
package quality

import (
	"math"
	"slices"
	"strconv"
	"time"
)

// Round is one decided probe round of a node.
type Round struct {
	At        time.Time
	Healthy   bool
	LatencyMs int // median latency of the round; meaningful when Healthy
}

// Inputs are everything known about one node at one moment.
type Inputs struct {
	Rounds []Round // any order
	// Grade from the admission benchmark ("" when not graded).
	Grade string
	// Disputes over DisputeHours: lost or upheld incidents (SLA breaches,
	// disputed usage statements) and the subscription-periods they are out of.
	Incidents, Periods int
}

// Weights of the five dimensions; zero disables one.
type Weights struct {
	Availability float64 `json:"availability"`
	Latency      float64 `json:"latency"`
	Stability    float64 `json:"stability"`
	Disputes     float64 `json:"disputes"`
	Benchmark    float64 `json:"benchmark"`
}

// Config is the operator-tunable scoring policy.
type Config struct {
	Weights Weights `json:"weights"`
	// Windows per dimension, in hours.
	AvailabilityHours int `json:"availability_hours"`
	LatencyHours      int `json:"latency_hours"`
	StabilityHours    int `json:"stability_hours"`
	DisputeHours      int `json:"dispute_hours"`
	// Lambda is the forgetting factor per round for availability (newest
	// round weight 1, the one before λ, then λ², …).
	Lambda float64 `json:"lambda"`
	// Latency maps linearly from GoodLatencyMs (1.0) to BadLatencyMs (0.0) on
	// the p95 of healthy rounds' median latency.
	GoodLatencyMs int `json:"good_latency_ms"`
	BadLatencyMs  int `json:"bad_latency_ms"`
	// MaxFlipsPerDay healthy↔unhealthy changes per day give stability 0.
	MaxFlipsPerDay float64 `json:"max_flips_per_day"`
	// MinRounds in the availability window, otherwise the score is 1.5 and
	// the tier "insufficient".
	MinRounds int `json:"min_rounds"`
	// Tier floors.
	StandardFrom float64 `json:"standard_from"`
	HighFrom     float64 `json:"high_from"`
}

func DefaultConfig() Config {
	return Config{
		Weights:           Weights{Availability: 4, Latency: 2, Stability: 1, Disputes: 2, Benchmark: 1},
		AvailabilityHours: 24, LatencyHours: 7 * 24, StabilityHours: 7 * 24, DisputeHours: 30 * 24, Lambda: 0.99, GoodLatencyMs: 50, BadLatencyMs: 500, MaxFlipsPerDay: 6,
		MinRounds: 10, StandardFrom: 1.5, HighFrom: 2.4,
	}
}

func (c Config) Valid() bool {
	w := c.Weights
	sum := w.Availability + w.Latency + w.Stability + w.Disputes + w.Benchmark
	return w.Availability >= 0 && w.Latency >= 0 && w.Stability >= 0 && w.Disputes >= 0 && w.Benchmark >= 0 && sum > 0 &&
		c.AvailabilityHours > 0 && c.LatencyHours > 0 && c.StabilityHours > 0 && c.DisputeHours > 0 &&
		max(c.AvailabilityHours, c.LatencyHours, c.StabilityHours, c.DisputeHours) <= 90*24 &&
		c.Lambda > 0 && c.Lambda <= 1 && c.GoodLatencyMs >= 0 && c.BadLatencyMs > c.GoodLatencyMs && c.MaxFlipsPerDay > 0 &&
		c.MinRounds >= 0 && c.StandardFrom >= 0 && c.HighFrom >= c.StandardFrom && c.HighFrom <= MaxScore
}

const (
	MaxScore     = 3.0
	NeutralScore = 1.5
)

// Tiers.
const (
	TierInsufficient = "insufficient"
	TierLow          = "low"
	TierStandard     = "standard"
	TierHigh         = "high"
)

// Deduction is one reason the score is below the maximum, shown to the seller.
type Deduction struct {
	Rule   string  `json:"rule"`
	Window string  `json:"window"`
	Value  float64 `json:"value"` // points lost out of 3
	// Observed is the measured value the rule looked at.
	Observed float64 `json:"observed"`
}

// Score is the result for one node.
type Score struct {
	Availability *float64    `json:"availability"`
	LatencyP50Ms *int        `json:"latency_p50_ms"`
	LatencyP95Ms *int        `json:"latency_p95_ms"`
	Stability    *float64    `json:"stability"`
	DisputeRate  *float64    `json:"dispute_rate"`
	Score        float64     `json:"score"`
	Tier         string      `json:"tier"`
	Rounds       int         `json:"rounds"`
	Deductions   []Deduction `json:"deductions"`
}

// GradeValue maps a benchmark grade to 0..1.
func GradeValue(grade string) (float64, bool) {
	switch grade {
	case "s":
		return 1, true
	case "a":
		return 0.8, true
	case "b":
		return 0.6, true
	case "c":
		return 0.4, true
	}
	return 0, false
}

// Window names a duration of hours as "24h" or "7d".
func Window(hours int) string {
	if hours > 24 && hours%24 == 0 {
		return strconv.Itoa(hours/24) + "d"
	}
	return strconv.Itoa(hours) + "h"
}

func hours(h int) time.Duration { return time.Duration(h) * time.Hour }

// Compute scores one node at now:
//
//	score = 3 × Σ wᵢ·vᵢ / Σ wᵢ   over the dimensions that have data
//
// A: availability over AvailabilityHours with forgetting factor λ;
// L: p95 latency over LatencyHours, linear between good and bad;
// S: 1 − flips/day / MaxFlipsPerDay over StabilityHours;
// D: 1 − incidents/periods over DisputeHours (no periods → skipped);
// B: benchmark grade value (skipped when ungraded).
func Compute(cfg Config, in Inputs, now time.Time) Score {
	rounds := slices.Clone(in.Rounds)
	slices.SortFunc(rounds, func(a, b Round) int { return b.At.Compare(a.At) }) // newest first
	within := func(d time.Duration) []Round {
		var out []Round
		for _, r := range rounds {
			if !r.At.After(now) && now.Sub(r.At) <= d {
				out = append(out, r)
			}
		}
		return out
	}
	out := Score{Deductions: []Deduction{}}
	avail := within(hours(cfg.AvailabilityHours))
	out.Rounds = len(avail)
	if len(avail) < cfg.MinRounds || len(avail) == 0 {
		out.Score, out.Tier = NeutralScore, TierInsufficient
		return out
	}
	type dim struct {
		rule   string
		window int // hours, 0 = not windowed
		weight float64
		value  float64
		seen   float64
	}
	var dims []dim

	// A: decayed healthy share.
	var healthy, total, w float64 = 0, 0, 1
	for _, r := range avail {
		if r.Healthy {
			healthy += w
		}
		total += w
		w *= cfg.Lambda
	}
	a := healthy / total
	out.Availability = &a
	dims = append(dims, dim{"availability", cfg.AvailabilityHours, cfg.Weights.Availability, a, a})

	// L: p95 of healthy rounds.
	var lat []int
	for _, r := range within(hours(cfg.LatencyHours)) {
		if r.Healthy {
			lat = append(lat, r.LatencyMs)
		}
	}
	if len(lat) > 0 {
		slices.Sort(lat)
		p50, p95 := lat[(len(lat)-1)/2], lat[int(math.Ceil(0.95*float64(len(lat))))-1]
		out.LatencyP50Ms, out.LatencyP95Ms = &p50, &p95
		v := 1 - float64(p95-cfg.GoodLatencyMs)/float64(cfg.BadLatencyMs-cfg.GoodLatencyMs)
		dims = append(dims, dim{"latency_p95", cfg.LatencyHours, cfg.Weights.Latency, clamp01(v), float64(p95)})
	}

	// S: flips per day, oldest to newest.
	stab := within(hours(cfg.StabilityHours))
	if len(stab) >= 2 {
		flips := 0
		for i := 1; i < len(stab); i++ {
			if stab[i].Healthy != stab[i-1].Healthy {
				flips++
			}
		}
		span := stab[0].At.Sub(stab[len(stab)-1].At).Hours() / 24
		perDay := float64(flips) / math.Max(span, 1)
		s := clamp01(1 - perDay/cfg.MaxFlipsPerDay)
		out.Stability = &s
		dims = append(dims, dim{"stability", cfg.StabilityHours, cfg.Weights.Stability, s, perDay})
	}

	// D: incidents per subscription-period.
	if in.Periods > 0 {
		rate := clamp01(float64(in.Incidents) / float64(in.Periods))
		out.DisputeRate = &rate
		dims = append(dims, dim{"disputes", cfg.DisputeHours, cfg.Weights.Disputes, 1 - rate, rate})
	}

	// B: benchmark grade.
	if g, ok := GradeValue(in.Grade); ok {
		dims = append(dims, dim{"benchmark_grade", 0, cfg.Weights.Benchmark, g, g})
	}

	var sumW, sumV float64
	for _, d := range dims {
		sumW += d.weight
		sumV += d.weight * d.value
	}
	if sumW == 0 {
		out.Score, out.Tier = NeutralScore, TierInsufficient
		return out
	}
	out.Score = round3(MaxScore * sumV / sumW)
	for _, d := range dims {
		if lost := MaxScore * d.weight * (1 - d.value) / sumW; d.weight > 0 && lost >= 0.0005 {
			win := ""
			if d.window > 0 {
				win = Window(d.window)
			}
			out.Deductions = append(out.Deductions, Deduction{Rule: d.rule, Window: win, Value: round3(lost), Observed: round3(d.seen)})
		}
	}
	out.Tier = TierOf(cfg, out.Score)
	return out
}

// TierOf maps a score with enough data to low / standard / high.
func TierOf(cfg Config, score float64) string {
	switch {
	case score >= cfg.HighFrom:
		return TierHigh
	case score >= cfg.StandardFrom:
		return TierStandard
	}
	return TierLow
}

func clamp01(v float64) float64 { return math.Min(1, math.Max(0, v)) }

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }
