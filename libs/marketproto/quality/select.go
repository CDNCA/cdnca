package quality

import (
	"math"
	"math/rand/v2"
	"slices"
	"strings"
)

// Candidate is one node that could answer on a supply DNS line.
type Candidate struct {
	Key string // stable id; candidates are ordered by it so input order does not matter
	// Price is the normalised unit price behind this node for the buyer
	// (0 = unknown, never filtered by the price cap and price-neutral).
	Price     float64
	Score     float64 // 0..3
	Probation bool
	// GradeWeight multiplies the quality weight (benchmark grade); 0 → 1.
	GradeWeight float64
}

// SelectConfig follows the orchestrator selection of go-livepeer
// (server/selection_algorithm.go, MIT): filter by minimum performance, then by
// maximum price, then draw by a weighted mix of stake (here: quality), price
// and randomness. Probation nodes are drawn last, under a share cap.
type SelectConfig struct {
	// MaxPrice / MinScore are the buyer's limits, set per call.
	MaxPrice float64 `json:"-"` // 0 = no cap
	MinScore float64 `json:"-"` // 0 = no floor
	// Count answers to choose (≤ DNS records per line).
	Count int `json:"-"`
	// QualityWeight / PriceWeight / RandWeight mix the three probabilities.
	QualityWeight float64 `json:"quality_weight"`
	PriceWeight   float64 `json:"price_weight"`
	RandWeight    float64 `json:"rand_weight"`
	// PriceExpFactor: price score = exp(−f · price/median); higher f punishes
	// expensive nodes harder. 0 → 1.
	PriceExpFactor float64 `json:"price_exp_factor"`
	// ProbationCap is the largest share of Count probation nodes may take
	// while admitted nodes exist (from admission.ProbationConfig.WeightCap).
	ProbationCap float64 `json:"-"`
	// IgnoreFiltersIfEmpty keeps serving the unfiltered set when the price
	// cap and quality floor exclude everything (an empty DNS answer is worse
	// than an expensive or degraded one).
	IgnoreFiltersIfEmpty bool `json:"ignore_filters_if_empty"`
}

func DefaultSelectConfig() SelectConfig {
	return SelectConfig{Count: 10, QualityWeight: 0.6, PriceWeight: 0.2, RandWeight: 0.2, PriceExpFactor: 1,
		ProbationCap: 0.1, IgnoreFiltersIfEmpty: true}
}

// Selection is the result: chosen keys in draw order plus what the filters did.
type Selection struct {
	Keys          []string
	FilteredPrice int
	FilteredScore int
	FiltersWaived bool
}

// Select picks up to cfg.Count candidates. rng must be seeded by the caller;
// the same seed and input give the same answer.
func Select(cfg SelectConfig, candidates []Candidate, rng *rand.Rand) Selection {
	var sel Selection
	if cfg.Count <= 0 || len(candidates) == 0 || rng == nil {
		return sel
	}
	// Deterministic input order regardless of how the caller built the slice.
	all := slices.Clone(candidates)
	slices.SortFunc(all, func(a, b Candidate) int { return strings.Compare(a.Key, b.Key) })

	filtered := make([]Candidate, 0, len(all))
	for _, c := range all {
		switch {
		case cfg.MinScore > 0 && c.Score < cfg.MinScore:
			sel.FilteredScore++
		case cfg.MaxPrice > 0 && c.Price > 0 && c.Price > cfg.MaxPrice:
			sel.FilteredPrice++
		default:
			filtered = append(filtered, c)
		}
	}
	if len(filtered) == 0 && cfg.IgnoreFiltersIfEmpty {
		filtered, sel.FiltersWaived = all, true
	}

	var admitted, probation []Candidate
	for _, c := range filtered {
		if c.Probation {
			probation = append(probation, c)
		} else {
			admitted = append(admitted, c)
		}
	}

	// Probation share of the answer ≤ cap (the long-run share equals the cap:
	// the fractional slot is drawn). A full answer keeps cap × Count slots for
	// probation nodes; a short one allows p with p / (a + p) ≤ cap. A line
	// with no admitted node is served by probation nodes alone.
	a := min(len(admitted), cfg.Count)
	var exact float64
	switch {
	case a == 0:
		exact = float64(cfg.Count)
	case len(admitted) >= cfg.Count:
		exact = cfg.ProbationCap * float64(cfg.Count)
	case cfg.ProbationCap >= 1:
		exact = float64(cfg.Count - a)
	default:
		exact = cfg.ProbationCap * float64(a) / (1 - cfg.ProbationCap)
	}
	p := int(math.Floor(exact))
	if rng.Float64() < exact-math.Floor(exact) {
		p++
	}
	p = min(p, len(probation), cfg.Count)
	a = min(a, cfg.Count-p)
	sel.Keys = append(draw(cfg, admitted, a, rng), draw(cfg, probation, p, rng)...)
	return sel
}

// draw samples n candidates without replacement by the mixed probability,
// renormalising after every pick.
func draw(cfg SelectConfig, pool []Candidate, n int, rng *rand.Rand) []string {
	if n <= 0 {
		return nil
	}
	remaining := slices.Clone(pool)
	out := make([]string, 0, n)
	for len(out) < n && len(remaining) > 0 {
		probs := probabilities(cfg, remaining)
		r := rng.Float64()
		pick := len(remaining) - 1
		for i, p := range probs {
			if r < p {
				pick = i
				break
			}
			r -= p
		}
		out = append(out, remaining[pick].Key)
		remaining = slices.Delete(remaining, pick, pick+1)
	}
	return out
}

func probabilities(cfg SelectConfig, pool []Candidate) []float64 {
	n := float64(len(pool))
	quality := make([]float64, len(pool))
	price := make([]float64, len(pool))
	var sumQ, sumP float64
	var prices []float64
	for _, c := range pool {
		if c.Price > 0 {
			prices = append(prices, c.Price)
		}
	}
	median := 0.0
	if len(prices) > 0 {
		slices.Sort(prices)
		median = prices[(len(prices)-1)/2]
	}
	factor := cfg.PriceExpFactor
	if factor == 0 {
		factor = 1
	}
	for i, c := range pool {
		g := c.GradeWeight
		if g <= 0 {
			g = 1
		}
		quality[i] = math.Max(c.Score, 0.01) * g
		sumQ += quality[i]
		price[i] = 1
		if c.Price > 0 && median > 0 {
			price[i] = math.Exp(-factor * c.Price / median)
		}
		sumP += price[i]
	}
	total := cfg.QualityWeight + cfg.PriceWeight + cfg.RandWeight
	if total <= 0 {
		total, cfg.RandWeight = 1, 1
	}
	out := make([]float64, len(pool))
	for i := range pool {
		out[i] = (cfg.QualityWeight*quality[i]/sumQ + cfg.PriceWeight*price[i]/sumP + cfg.RandWeight/n) / total
	}
	return out
}

// Valid checks the operator-set parts of the config (Count and the buyer
// filters are set per call).
func (c SelectConfig) Valid() bool {
	return c.QualityWeight >= 0 && c.PriceWeight >= 0 && c.RandWeight >= 0 && c.QualityWeight+c.PriceWeight+c.RandWeight > 0 &&
		c.PriceExpFactor >= 0 && c.PriceExpFactor <= 20 && c.ProbationCap >= 0 && c.ProbationCap <= 1
}
