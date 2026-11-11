package edgeconfig

import (
	"math"
	"testing"
)

// The bucket boundaries cdnca_rum.bucket reproduces.
func TestRUMBucket(t *testing.T) {
	for value, want := range map[int64]int{-5: 0, 0: 0, 1: 1, 2: 10, 100: 60, 2500: 102, 120000: 152, 1 << 40: RUMMaxBucket} {
		if got := RUMBucket(value); got != want {
			t.Fatalf("RUMBucket(%d) = %d, want %d", value, got, want)
		}
	}
}

func TestRUMQuantileWithinBucket(t *testing.T) {
	histogram := RUMHistogram{}
	for value := int64(1); value <= 1000; value++ {
		histogram[uint16(RUMBucket(value))]++
	}
	got, ok := histogram.Quantile(0.75)
	if !ok || math.Abs(got-750)/750 > 0.04 {
		t.Fatalf("p75 = %v %v, want 750 within 4%%", got, ok)
	}
	if _, ok := (RUMHistogram{}).Quantile(0.75); ok {
		t.Fatal("empty histogram has a quantile")
	}
}

func TestRUMMinuteDataValid(t *testing.T) {
	data := RUMMinuteData{Series: []RUMSeries{
		{Dimension: "all", Views: 3, Histograms: map[string]RUMHistogram{"lcp": {102: 3}}},
		{Dimension: "page", Value: "/product/:id", Views: 3, Histograms: map[string]RUMHistogram{}},
		{Dimension: "country", Value: "--", Views: 3, Histograms: map[string]RUMHistogram{}},
	}, Errors: []RUMError{{Kind: "fetch", Target: "/api/cart", Status: 503, Count: 1}, {Kind: "resource", Element: "img", Target: "cdn.example.com", Count: 2}}}
	if !data.Valid() {
		t.Fatal("valid data refused")
	}
	for name, mutate := range map[string]func(*RUMMinuteData){
		"no all":         func(d *RUMMinuteData) { d.Series = d.Series[1:] },
		"query in page":  func(d *RUMMinuteData) { d.Series[1].Value = "/a b" },
		"unknown metric": func(d *RUMMinuteData) { d.Series[0].Histograms["fid"] = RUMHistogram{1: 1} },
		"status 302":     func(d *RUMMinuteData) { d.Errors[0].Status = 302 },
		"duplicate":      func(d *RUMMinuteData) { d.Errors[1] = d.Errors[0] },
	} {
		copied := RUMMinuteData{Series: append([]RUMSeries(nil), data.Series...), Errors: append([]RUMError(nil), data.Errors...)}
		copied.Series[0].Histograms = map[string]RUMHistogram{"lcp": {102: 3}}
		mutate(&copied)
		if copied.Valid() {
			t.Fatalf("%s accepted", name)
		}
	}
}
