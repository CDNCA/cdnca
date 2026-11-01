package smartsched

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/google/uuid"
)

func candidate(address, scope string, healthy bool, load *float64) Candidate {
	return Candidate{EndpointID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(address)), Address: address, Scope: scope,
		Healthy: healthy, LoadPercent: load}
}

func percent(value float64) *float64 { return &value }

func latencies(values map[string]int) map[uuid.UUID]Latency {
	out := map[uuid.UUID]Latency{}
	for address, p50 := range values {
		out[uuid.NewSHA1(uuid.NameSpaceOID, []byte(address))] = Latency{P50MS: p50, Samples: 5}
	}
	return out
}

func find(selections []Selection, scope string) (Selection, bool) {
	for _, selection := range selections {
		if selection.Scope == scope {
			return selection, true
		}
	}
	return Selection{}, false
}

func TestSelectTopNByLatencyHealthAndLoad(t *testing.T) {
	settings := DefaultSettings()
	settings.Enabled, settings.TopN, settings.MaxLoadPercent = true, 2, 85
	candidates := []Candidate{
		candidate("192.0.2.1", "telecom", true, percent(20)),
		candidate("192.0.2.2", "telecom", true, percent(90)), // overloaded
		candidate("192.0.2.3", "telecom", false, nil),        // unhealthy
		candidate("192.0.2.4", "", true, nil),                // BGP, unknown load
		candidate("192.0.2.5", "telecom", true, percent(10)),
		candidate("192.0.2.6", "unicom", true, nil), // another carrier, never on telecom
		candidate("198.51.100.1", "overseas", true, nil),
	}
	latency := map[LineKey]map[uuid.UUID]Latency{{Carrier: "telecom"}: latencies(map[string]int{
		"192.0.2.1": 30, "192.0.2.2": 5, "192.0.2.3": 1, "192.0.2.4": 20, "192.0.2.5": 40, "192.0.2.6": 2,
		"198.51.100.1": 1,
	})}
	got, _ := find(Select(Input{Settings: settings, Candidates: candidates, Latency: latency}), "telecom")
	if got.Source != SourceLatency || !slices.Equal(got.Addresses(), []string{"192.0.2.1", "192.0.2.4"}) {
		t.Fatalf("telecom = %+v", got)
	}
	if *got.Selected[0].LatencyMS != 20 || got.Selected[0].Address != "192.0.2.4" {
		t.Fatalf("selected must be fastest first: %+v", got.Selected)
	}
}

func TestSelectHysteresis(t *testing.T) {
	settings := DefaultSettings()
	settings.Enabled, settings.TopN = true, 1
	candidates := []Candidate{candidate("192.0.2.1", "mobile", true, nil), candidate("192.0.2.2", "mobile", true, nil)}
	previous := map[string][]string{"mobile": {"192.0.2.1"}}
	for _, tc := range []struct {
		name     string
		old, new int
		want     string
	}{
		{"newcomer 10% faster keeps the old", 100, 90, "192.0.2.1"},
		{"newcomer exactly 20% faster replaces", 100, 80, "192.0.2.2"},
		{"newcomer slower keeps the old", 50, 60, "192.0.2.1"},
	} {
		latency := map[LineKey]map[uuid.UUID]Latency{{Carrier: "mobile"}: latencies(map[string]int{
			"192.0.2.1": tc.old, "192.0.2.2": tc.new})}
		got, _ := find(Select(Input{Settings: settings, Candidates: candidates, Latency: latency, Previous: previous}), "mobile")
		if !slices.Equal(got.Addresses(), []string{tc.want}) {
			t.Fatalf("%s: %+v", tc.name, got.Addresses())
		}
	}
	// The kept endpoint turning unhealthy is replaced even when slower.
	candidates[0].Healthy = false
	latency := map[LineKey]map[uuid.UUID]Latency{{Carrier: "mobile"}: latencies(map[string]int{
		"192.0.2.1": 10, "192.0.2.2": 90})}
	got, _ := find(Select(Input{Settings: settings, Candidates: candidates, Latency: latency, Previous: previous}), "mobile")
	if !slices.Equal(got.Addresses(), []string{"192.0.2.2"}) {
		t.Fatalf("unhealthy previous kept: %+v", got.Addresses())
	}
	// Without a previous selection there is no hysteresis.
	got, _ = find(Select(Input{Settings: settings, Candidates: []Candidate{candidate("192.0.2.1", "mobile", true, nil),
		candidate("192.0.2.2", "mobile", true, nil)}, Latency: map[LineKey]map[uuid.UUID]Latency{{Carrier: "mobile"}: latencies(
		map[string]int{"192.0.2.1": 100, "192.0.2.2": 90})}}), "mobile")
	if !slices.Equal(got.Addresses(), []string{"192.0.2.2"}) {
		t.Fatalf("fresh selection = %+v", got.Addresses())
	}
}

func TestSelectFallback(t *testing.T) {
	settings := DefaultSettings()
	settings.Enabled, settings.Granularity, settings.TopN = true, GranularityProvinceCarrier, 3
	candidates := []Candidate{
		candidate("192.0.2.1", "telecom", true, nil),
		candidate("192.0.2.2", "telecom", false, nil),
		candidate("192.0.2.3", "unicom", false, nil),
		candidate("192.0.2.9", "mobile", true, nil),
	}
	latency := map[LineKey]map[uuid.UUID]Latency{
		{Carrier: "telecom"}:                  latencies(map[string]int{"192.0.2.1": 30, "192.0.2.2": 10}),
		{Province: "广东", Carrier: "telecom"}:  latencies(map[string]int{"192.0.2.1": 25}),
		{Province: "浙江", Carrier: "telecom"}:  latencies(map[string]int{"192.0.2.2": 8}), // only unhealthy
		{Carrier: "unicom"}:                   latencies(map[string]int{"192.0.2.3": 15}),
		{Province: "广东", Carrier: "unicom"}:   latencies(map[string]int{"192.0.2.3": 15}),
		{Province: "广东", Carrier: "overseas"}: latencies(map[string]int{"192.0.2.1": 1}), // ignored
		{Province: "四川", Carrier: "mobile"}:   latencies(map[string]int{"192.0.2.1": 1}), // telecom node: not in pool
		{Province: "", Carrier: "mobile"}:     nil,
	}
	selections := Select(Input{Settings: settings, Candidates: candidates, Latency: latency})
	want := map[string]struct {
		source, from string
		addresses    []string
	}{
		"telecom":    {SourceLatency, "", []string{"192.0.2.1"}},
		"unicom":     {SourceFallback, FallbackFromCarrier, []string{}},
		"mobile":     {SourceStatic, "", []string{"192.0.2.9"}}, // no samples: today's carrier set
		"广东:telecom": {SourceLatency, "", []string{"192.0.2.1"}},
		"浙江:telecom": {SourceFallback, FallbackFromProvince, []string{}},
		"广东:unicom":  {SourceFallback, FallbackFromProvince, []string{}},
	}
	if len(selections) != len(want) {
		t.Fatalf("selections = %+v", selections)
	}
	for scope, expected := range want {
		got, ok := find(selections, scope)
		if !ok || got.Source != expected.source || got.FallbackFrom != expected.from ||
			!slices.Equal(got.Addresses(), expected.addresses) {
			t.Fatalf("%s = %+v, want %+v", scope, got, expected)
		}
	}
	// Carrier granularity never emits province lines.
	settings.Granularity = GranularityCarrier
	if got := Select(Input{Settings: settings, Candidates: candidates, Latency: latency}); len(got) != 3 {
		t.Fatalf("carrier granularity = %+v", got)
	}
}

func TestSelectionDigestFollowsAddressesOnly(t *testing.T) {
	first, second := 10, 20
	a := Selection{Scope: "telecom", Source: SourceLatency, Selected: []Pick{{Address: "192.0.2.2", LatencyMS: &first},
		{Address: "192.0.2.1", LatencyMS: &second}}}
	b := Selection{Scope: "telecom", Source: SourceLatency, Selected: []Pick{{Address: "192.0.2.1", LatencyMS: &first},
		{Address: "192.0.2.2", LatencyMS: &first}}}
	if a.Digest() != b.Digest() {
		t.Fatal("latency or order must not change the digest")
	}
	b.Source = SourceStatic
	if a.Digest() == b.Digest() {
		t.Fatal("source must change the digest")
	}
}

func TestSettingsValidAndP50(t *testing.T) {
	if !DefaultSettings().Valid() {
		t.Fatal("default settings must be valid")
	}
	for _, mutate := range []func(*Settings){
		func(s *Settings) { s.TopN = 0 }, func(s *Settings) { s.TopN = 21 }, func(s *Settings) { s.Granularity = "x" },
		func(s *Settings) { s.LatencyWindowMinutes = 4 }, func(s *Settings) { s.MaxLoadPercent = 101 },
		func(s *Settings) { s.Fallback = "" },
	} {
		value := DefaultSettings()
		mutate(&value)
		if value.Valid() {
			t.Fatalf("invalid settings accepted: %+v", value)
		}
	}
	if P50([]int{5, 1, 9, 3}) != 3 || P50([]int{7}) != 7 || P50(nil) != 0 {
		t.Fatal("P50 is the lower median")
	}
	if province, carrier, ok := ParseScope("广东:mobile"); !ok || province != "广东" || carrier != "mobile" {
		t.Fatal("province scope")
	}
	if _, _, ok := ParseScope("telecom"); ok {
		t.Fatal("carrier scope is not a province scope")
	}
}

func TestProvinceNormalization(t *testing.T) {
	for raw, want := range map[string]string{"广东": "广东", "中国广东省": "广东", "广东电信": "广东", "黑龙江省": "黑龙江",
		"内蒙古自治区": "内蒙古", "中国香港": "", "日本": "", "": ""} {
		got, ok := marketprobe.Province(raw)
		if got != want || ok != (want != "") {
			t.Errorf("Province(%q) = %q,%v want %q", raw, got, ok, want)
		}
	}
}

// A static line without endpoints stores [] (migration 609 CHECK jsonb array).
func TestStaticSelectionWithoutEndpointsIsEmptyArray(t *testing.T) {
	selections := Select(Input{Settings: DefaultSettings()})
	for _, selection := range selections {
		if selection.Selected == nil {
			t.Fatalf("%s selected is nil", selection.Scope)
		}
	}
}
