// Package smartsched is line-group smart scheduling (migration
// 609): visitors on a carrier line (or province+carrier line) are answered
// with the top_n published endpoints of the line group that have the lowest
// windowed p50 latency from probes on that line, are healthy and are below
// max_load_percent. Latency comes from the dnspup checkpoints and the peer
// node probes already run for availability (nodednspupprobe / nodeprobe);
// nothing new is probed.
//
// Fallback per line: a province line with no eligible endpoint is not
// written (the DNS provider answers with the carrier line); a carrier line
// with samples but no eligible endpoint is not written (the default line
// answers); a carrier line without any latency sample keeps the static set
// of today (endpoints of that carrier). Smart scheduling off: nothing here
// runs and cnamelines writes exactly what it wrote before.
package smartsched

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const (
	GranularityCarrier         = "carrier"
	GranularityProvinceCarrier = "province_carrier"
	FallbackCarrierThenDefault = "carrier_then_default"

	SourceLatency  = "latency"
	SourceStatic   = "static"
	SourceFallback = "fallback"

	FallbackFromProvince = "province_carrier"
	FallbackFromCarrier  = "carrier"

	// Hysteresis: a selected endpoint is replaced only by one at least this
	// much faster (or when it stops being eligible).
	HysteresisPercent = 20
)

// Carriers are the carrier line scopes smart scheduling selects for.
var Carriers = []string{"telecom", "unicom", "mobile"}

// Settings is a line group's smart schedule configuration.
type Settings struct {
	Enabled              bool   `json:"enabled"`
	TopN                 int    `json:"top_n"`
	Granularity          string `json:"granularity"`
	LatencyWindowMinutes int    `json:"latency_window_minutes"`
	MaxLoadPercent       int    `json:"max_load_percent"`
	Fallback             string `json:"fallback"`
}

func DefaultSettings() Settings {
	return Settings{TopN: 3, Granularity: GranularityCarrier, LatencyWindowMinutes: 15, MaxLoadPercent: 85,
		Fallback: FallbackCarrierThenDefault}
}

// Valid reports whether settings are within the migration 609 bounds.
func (settings Settings) Valid() bool {
	return settings.TopN >= 1 && settings.TopN <= 20 &&
		(settings.Granularity == GranularityCarrier || settings.Granularity == GranularityProvinceCarrier) &&
		settings.LatencyWindowMinutes >= 5 && settings.LatencyWindowMinutes <= 60 &&
		settings.MaxLoadPercent >= 1 && settings.MaxLoadPercent <= 100 && settings.Fallback == FallbackCarrierThenDefault
}

// Candidate is one published endpoint of the line group.
type Candidate struct {
	EndpointID uuid.UUID
	Address    string
	// Scope is the endpoint's own line (cnamelines.EndpointScope): telecom /
	// unicom / mobile, overseas, or "" (BGP / unknown carrier).
	Scope   string
	Healthy bool
	// LoadPercent nil: unknown (no recent metric), treated as not loaded.
	LoadPercent *float64
}

// Latency is the windowed p50 of one endpoint on one line.
type Latency struct {
	P50MS   int
	Samples int
}

// Pick is one selected endpoint.
type Pick struct {
	Address     string    `json:"address"`
	EndpointID  uuid.UUID `json:"endpoint_id"`
	LatencyMS   *int      `json:"latency_ms"`
	Healthy     bool      `json:"healthy"`
	LoadPercent *float64  `json:"load_percent"`
}

// Selection is the result of one line.
type Selection struct {
	Scope        string `json:"scope"`
	Source       string `json:"source"`
	FallbackFrom string `json:"fallback_from,omitempty"`
	Selected     []Pick `json:"selected"`
}

// Digest identifies the selected address set (latency changes alone do not
// change it).
func (selection Selection) Digest() string {
	addresses := selection.Addresses()
	sum := sha256.Sum256([]byte("cdnca.smart-selection/v1 " + selection.Source + " " + selection.FallbackFrom + " " +
		strings.Join(addresses, ",")))
	return hex.EncodeToString(sum[:])
}

// Addresses are the selected addresses, sorted.
func (selection Selection) Addresses() []string {
	out := make([]string, 0, len(selection.Selected))
	for _, pick := range selection.Selected {
		out = append(out, pick.Address)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Eligible: healthy and below the load limit.
func (candidate Candidate) eligible(maxLoad int) bool {
	return candidate.Healthy && (candidate.LoadPercent == nil || *candidate.LoadPercent < float64(maxLoad))
}

// pool are the candidates a carrier line may use: endpoints of that carrier
// and mainland endpoints without a single carrier (BGP / multi-line); never
// overseas or another carrier's endpoints.
func pool(candidates []Candidate, carrier string) []Candidate {
	var out []Candidate
	for _, candidate := range candidates {
		if candidate.Scope == carrier || candidate.Scope == "" {
			out = append(out, candidate)
		}
	}
	return out
}

type ranked struct {
	candidate Candidate
	latency   Latency
}

// rank orders the eligible candidates that have samples by p50, then address.
func rank(candidates []Candidate, latency map[uuid.UUID]Latency, maxLoad int) []ranked {
	var out []ranked
	for _, candidate := range candidates {
		value, ok := latency[candidate.EndpointID]
		if !ok || value.Samples == 0 || !candidate.eligible(maxLoad) {
			continue
		}
		out = append(out, ranked{candidate, value})
	}
	sort.SliceStable(out, func(left, right int) bool {
		if out[left].latency.P50MS != out[right].latency.P50MS {
			return out[left].latency.P50MS < out[right].latency.P50MS
		}
		return out[left].candidate.Address < out[right].candidate.Address
	})
	return out
}

// choose applies top_n with hysteresis against the previous latency
// selection: a kept endpoint stays while it is eligible unless a newcomer is
// at least HysteresisPercent faster than the slowest kept one.
func choose(order []ranked, previous []string, topN int) []ranked {
	if len(previous) == 0 {
		return order[:min(topN, len(order))]
	}
	var kept, others []ranked
	for _, item := range order {
		if slices.Contains(previous, item.candidate.Address) {
			kept = append(kept, item)
		} else {
			others = append(others, item)
		}
	}
	if len(kept) > topN {
		kept = kept[:topN] // order is fastest first
	}
	for _, newcomer := range others {
		if len(kept) < topN {
			kept = append(kept, newcomer)
			continue
		}
		slowest := len(kept) - 1
		for index := range kept {
			if kept[index].latency.P50MS > kept[slowest].latency.P50MS {
				slowest = index
			}
		}
		if newcomer.latency.P50MS*100 <= kept[slowest].latency.P50MS*(100-HysteresisPercent) {
			kept[slowest] = newcomer
		}
	}
	sort.SliceStable(kept, func(left, right int) bool {
		if kept[left].latency.P50MS != kept[right].latency.P50MS {
			return kept[left].latency.P50MS < kept[right].latency.P50MS
		}
		return kept[left].candidate.Address < kept[right].candidate.Address
	})
	return kept
}

func picks(items []ranked) []Pick {
	out := make([]Pick, 0, len(items))
	for _, item := range items {
		value := item.latency.P50MS
		out = append(out, Pick{Address: item.candidate.Address, EndpointID: item.candidate.EndpointID, LatencyMS: &value,
			Healthy: item.candidate.Healthy, LoadPercent: item.candidate.LoadPercent})
	}
	return out
}

// LineKey identifies the latency of an endpoint on a line: province "" is
// the carrier-wide aggregate.
type LineKey struct {
	Province, Carrier string
}

// Input is what one line group's selection needs.
type Input struct {
	Settings   Settings
	Candidates []Candidate
	// Latency per line: the carrier-wide entry ({"", carrier}) aggregates
	// every province of that carrier.
	Latency map[LineKey]map[uuid.UUID]Latency
	// Previous is the address set of each line's last latency selection
	// (hysteresis); lines whose last selection was static/fallback are absent.
	Previous map[string][]string
}

// ProvinceScope is the line scope of a province+carrier line ("广东:mobile").
func ProvinceScope(province, carrier string) string { return province + ":" + carrier }

// ParseScope splits a province scope; ok=false for a carrier scope.
func ParseScope(scope string) (province, carrier string, ok bool) {
	province, carrier, ok = strings.Cut(scope, ":")
	return province, carrier, ok && province != "" && slices.Contains(Carriers, carrier)
}

// Select computes every line of a line group. Carrier lines are always
// present; province lines only for provinces with samples and only with
// granularity province_carrier.
func Select(input Input) []Selection {
	settings := input.Settings
	var out []Selection
	for _, carrier := range Carriers {
		candidates := pool(input.Candidates, carrier)
		latency := input.Latency[LineKey{Carrier: carrier}]
		if len(latency) == 0 || !anySampled(candidates, latency) {
			// No measurement on this carrier: today's static set.
			static := []Pick{}
			for _, candidate := range candidates {
				if candidate.Scope == carrier {
					static = append(static, Pick{Address: candidate.Address, EndpointID: candidate.EndpointID,
						Healthy: candidate.Healthy, LoadPercent: candidate.LoadPercent})
				}
			}
			sort.Slice(static, func(left, right int) bool { return static[left].Address < static[right].Address })
			out = append(out, Selection{Scope: carrier, Source: SourceStatic, Selected: static})
			continue
		}
		chosen := choose(rank(candidates, latency, settings.MaxLoadPercent), input.Previous[carrier], settings.TopN)
		if len(chosen) == 0 {
			out = append(out, Selection{Scope: carrier, Source: SourceFallback, FallbackFrom: FallbackFromCarrier,
				Selected: []Pick{}})
			continue
		}
		out = append(out, Selection{Scope: carrier, Source: SourceLatency, Selected: picks(chosen)})
	}
	if settings.Granularity != GranularityProvinceCarrier {
		return out
	}
	var keys []LineKey
	for key := range input.Latency {
		if key.Province != "" && slices.Contains(Carriers, key.Carrier) {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(left, right int) bool {
		return ProvinceScope(keys[left].Province, keys[left].Carrier) < ProvinceScope(keys[right].Province, keys[right].Carrier)
	})
	for _, key := range keys {
		scope := ProvinceScope(key.Province, key.Carrier)
		candidates := pool(input.Candidates, key.Carrier)
		if !anySampled(candidates, input.Latency[key]) {
			continue
		}
		chosen := choose(rank(candidates, input.Latency[key], settings.MaxLoadPercent), input.Previous[scope], settings.TopN)
		if len(chosen) == 0 {
			out = append(out, Selection{Scope: scope, Source: SourceFallback, FallbackFrom: FallbackFromProvince,
				Selected: []Pick{}})
			continue
		}
		out = append(out, Selection{Scope: scope, Source: SourceLatency, Selected: picks(chosen)})
	}
	return out
}

func anySampled(candidates []Candidate, latency map[uuid.UUID]Latency) bool {
	for _, candidate := range candidates {
		if value, ok := latency[candidate.EndpointID]; ok && value.Samples > 0 {
			return true
		}
	}
	return false
}

// P50 is the lower median of values (empty: 0).
func P50(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	return sorted[(len(sorted)-1)/2]
}
