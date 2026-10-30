package nodeserving

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"time"
)

const (
	ReasonBandwidthExceeded  = "bandwidth_exceeded"
	ReasonBandwidthRecovered = "bandwidth_recovered"
	ReasonTrafficExceeded    = "traffic_exceeded"
	ReasonPeriodReset        = "period_reset"
	ReasonDisabledPeriod     = "disabled_period"
	ReasonPeriodEnded        = "period_ended"
	ReasonSettingsChanged    = "settings_changed"

	// DefaultBandwidthOverLimit is used when the platform policy has no
	// "consecutive bandwidth over-limit" count.
	DefaultBandwidthOverLimit = 3
	// MinimumBandwidthHold keeps a bandwidth hold for at least one CNAME TTL
	// (300s), so traffic leaving the node cannot immediately re-enable it.
	MinimumBandwidthHold = 5 * time.Minute
	// bandwidthSampleFreshness: only live samples move the bandwidth streak;
	// catching up on history never holds a node for old peaks.
	bandwidthSampleFreshness = 2 * time.Minute
	gibibyte                 = 1 << 30
)

// AutoDisableSettings mirrors nodes.management_settings.auto_disable (239).
type AutoDisableSettings struct {
	BandwidthLimit     uint64   `json:"bandwidth_limit"`
	BandwidthUnit      string   `json:"bandwidth_unit"`
	TrafficEnabled     bool     `json:"traffic_enabled"`
	TrafficFromDay     int      `json:"traffic_from_day"`
	TrafficFromTime    string   `json:"traffic_from_time"`
	TrafficTotalGB     uint64   `json:"traffic_total_gb"`
	TrafficTypes       []string `json:"traffic_types"`
	ExcludedInterfaces string   `json:"excluded_interfaces"`
	DisabledPeriods    string   `json:"disabled_periods"`
}

// Active reports whether any auto-disable rule is configured.
func (settings AutoDisableSettings) Active() bool {
	return settings.BandwidthLimit > 0 || settings.TrafficEnabled && settings.TrafficTotalGB > 0 ||
		strings.TrimSpace(settings.DisabledPeriods) != ""
}

// BandwidthLimitBPS converts the Mbps/Gbps limit to bits per second (0: none).
func (settings AutoDisableSettings) BandwidthLimitBPS() uint64 {
	unit := uint64(1_000_000)
	if settings.BandwidthUnit == "Gbps" {
		unit = 1_000_000_000
	}
	if settings.BandwidthLimit > math.MaxUint64/unit {
		return math.MaxUint64
	}
	return settings.BandwidthLimit * unit
}

// TrafficLimitBytes is the period quota in bytes (GB as displayed: 1024^3).
func (settings AutoDisableSettings) TrafficLimitBytes() uint64 {
	if !settings.TrafficEnabled || settings.TrafficTotalGB == 0 {
		return 0
	}
	if settings.TrafficTotalGB > math.MaxInt64/gibibyte {
		return math.MaxInt64
	}
	return settings.TrafficTotalGB * gibibyte
}

func (settings AutoDisableSettings) direction(kind string) bool {
	for _, value := range settings.TrafficTypes {
		if value == kind {
			return true
		}
	}
	return false
}

// AccountingDigest binds accumulated usage to what it was measured with.
func (settings AutoDisableSettings) AccountingDigest() string {
	encoded, _ := json.Marshal([]any{settings.TrafficFromDay, settings.TrafficFromTime, settings.direction("inbound"),
		settings.direction("outbound"), strings.Fields(settings.ExcludedInterfaces)})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func parseClock(value string) (int, bool) {
	parsed, err := time.Parse("15:04:05", value)
	if err != nil {
		return 0, false
	}
	return parsed.Hour()*3600 + parsed.Minute()*60 + parsed.Second(), true
}

// Period is the accounting month containing now: from day N at HH:MM:SS
// local time until the same moment one month later.
func (settings AutoDisableSettings) Period(now time.Time, location *time.Location) (time.Time, time.Time) {
	seconds, ok := parseClock(settings.TrafficFromTime)
	if !ok {
		seconds = 0
	}
	day := min(max(settings.TrafficFromDay, 1), 28)
	local := now.In(location)
	anchor := func(year int, month time.Month) time.Time {
		return time.Date(year, month, day, seconds/3600, seconds/60%60, seconds%60, 0, location)
	}
	start := anchor(local.Year(), local.Month())
	if local.Before(start) {
		start = anchor(local.Year(), local.Month()-1)
	}
	end := anchor(start.Year(), start.Month()+1)
	return start.UTC(), end.UTC()
}

// InDisabledPeriod reports whether now falls in a daily "HH:MM:SS-HH:MM:SS"
// window; a window whose end is before its start crosses midnight.
func (settings AutoDisableSettings) InDisabledPeriod(now time.Time, location *time.Location) bool {
	local := now.In(location)
	current := local.Hour()*3600 + local.Minute()*60 + local.Second()
	for _, window := range strings.Fields(settings.DisabledPeriods) {
		from, to, found := strings.Cut(window, "-")
		start, startOK := parseClock(from)
		end, endOK := parseClock(to)
		if !found || !startOK || !endOK || start == end {
			continue
		}
		if start < end && current >= start && current < end || start > end && (current >= start || current < end) {
			return true
		}
	}
	return false
}

// NICCounter is the last cumulative counter seen for one interface.
type NICCounter struct {
	RX uint64 `json:"rx"`
	TX uint64 `json:"tx"`
}

// NetworkSample is one telemetry report's per-NIC counters and bandwidth.
type NetworkSample struct {
	Sequence   int64
	ObservedAt time.Time
	Interfaces []NetworkInterfaceSample
}

type NetworkInterfaceSample struct {
	Name           string `json:"name"`
	RXBytes        uint64 `json:"rx_bytes"`
	TXBytes        uint64 `json:"tx_bytes"`
	RXBandwidthBPS uint64 `json:"rx_bandwidth_bps"`
	TXBandwidthBPS uint64 `json:"tx_bandwidth_bps"`
}

// UsageState is the persisted accounting of one period.
type UsageState struct {
	PeriodStart, PeriodEnd time.Time
	Digest                 string
	LastSequence           int64
	Counters               map[string]NICCounter
	UsageBytes             uint64
	OverStreak             int
	UnderStreak            int
	LastBandwidthBPS       uint64
}

// Restart reports whether the stored state belongs to another period or was
// measured with other settings, and returns a fresh state for the current one.
func (state UsageState) Restart(settings AutoDisableSettings, start, end time.Time) (UsageState, bool, bool) {
	digest := settings.AccountingDigest()
	periodChanged := !state.PeriodStart.Equal(start) || !state.PeriodEnd.Equal(end)
	settingsChanged := state.Digest != digest
	if !periodChanged && !settingsChanged {
		return state, false, false
	}
	return UsageState{PeriodStart: start, PeriodEnd: end, Digest: digest, Counters: map[string]NICCounter{}}, periodChanged, settingsChanged
}

// Accumulate advances the state by samples ordered by sequence. Counters are
// cumulative per NIC: the first sighting is a baseline, a decrease is a counter
// reset (reboot, driver reload) and the new value is the traffic since it.
// Only fresh samples (observed within bandwidthSampleFreshness of now) move
// the bandwidth streaks.
func (state *UsageState) Accumulate(settings AutoDisableSettings, samples []NetworkSample, now time.Time) {
	excluded := map[string]bool{}
	for _, name := range strings.Fields(settings.ExcludedInterfaces) {
		excluded[name] = true
	}
	if state.Counters == nil {
		state.Counters = map[string]NICCounter{}
	}
	inbound, outbound := settings.direction("inbound"), settings.direction("outbound")
	limit := settings.BandwidthLimitBPS()
	for _, sample := range samples {
		if sample.Sequence <= state.LastSequence {
			continue
		}
		state.LastSequence = sample.Sequence
		var bandwidth uint64
		for _, network := range sample.Interfaces {
			if network.Name == "" || network.Name == "lo" || excluded[network.Name] {
				continue
			}
			previous, seen := state.Counters[network.Name]
			state.Counters[network.Name] = NICCounter{RX: network.RXBytes, TX: network.TXBytes}
			if inbound {
				bandwidth = saturatingAdd(bandwidth, network.RXBandwidthBPS)
			}
			if outbound {
				bandwidth = saturatingAdd(bandwidth, network.TXBandwidthBPS)
			}
			if !seen {
				continue
			}
			if inbound {
				state.UsageBytes = saturatingAdd(state.UsageBytes, counterDelta(previous.RX, network.RXBytes))
			}
			if outbound {
				state.UsageBytes = saturatingAdd(state.UsageBytes, counterDelta(previous.TX, network.TXBytes))
			}
		}
		if state.UsageBytes > math.MaxInt64 {
			state.UsageBytes = math.MaxInt64
		}
		if now.Sub(sample.ObservedAt) > bandwidthSampleFreshness {
			continue
		}
		state.LastBandwidthBPS = min(bandwidth, math.MaxInt64)
		switch {
		case limit == 0:
			state.OverStreak, state.UnderStreak = 0, 0
		case bandwidth > limit:
			state.OverStreak, state.UnderStreak = min(state.OverStreak+1, 1_000_000), 0
		default:
			state.UnderStreak, state.OverStreak = min(state.UnderStreak+1, 1_000_000), 0
		}
	}
}

func counterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}

// AutoDisableInput is everything one auto-disable decision depends on.
type AutoDisableInput struct {
	NodeActive bool
	Settings   AutoDisableSettings
	Usage      UsageState
	// Threshold is the platform's consecutive bandwidth over-limit count.
	Threshold         int
	InDisabledPeriod  bool
	Now               time.Time
	Held              bool
	Reason            string
	HeldSince         *time.Time
	PeriodRestarted   bool
	SettingsRestarted bool
	// CatchingUp: accounting has not yet replayed the period's samples, so a
	// low usage figure is not evidence for releasing a traffic hold.
	CatchingUp bool
}

// DecideAutoDisable holds a node while it is in a disabled time window, while
// the period traffic is at or over its quota, or after Threshold consecutive
// live bandwidth samples over the limit. A bandwidth hold lasts at least
// MinimumBandwidthHold and is released after Threshold samples back under the
// limit. A traffic hold is released by the next period.
func DecideAutoDisable(input AutoDisableInput) Decision {
	settings := input.Settings
	threshold := max(input.Threshold, 1)
	detail := map[string]any{
		"usage_bytes": input.Usage.UsageBytes, "traffic_limit_bytes": settings.TrafficLimitBytes(),
		"bandwidth_bps": input.Usage.LastBandwidthBPS, "bandwidth_limit_bps": settings.BandwidthLimitBPS(),
		"period_start": input.Usage.PeriodStart.UTC().Format(time.RFC3339), "period_end": input.Usage.PeriodEnd.UTC().Format(time.RFC3339),
	}
	if !input.NodeActive {
		return Decision{Reason: ReasonNodeInactive, Detail: detail}
	}
	if input.InDisabledPeriod {
		return Decision{Held: true, Reason: ReasonDisabledPeriod, Detail: detail}
	}
	if limit := settings.TrafficLimitBytes(); limit > 0 && input.Usage.UsageBytes >= limit {
		return Decision{Held: true, Reason: ReasonTrafficExceeded, Detail: detail}
	}
	if settings.BandwidthLimitBPS() > 0 {
		heldForBandwidth := input.Held && input.Reason == ReasonBandwidthExceeded
		if !heldForBandwidth && input.Usage.OverStreak >= threshold {
			return Decision{Held: true, Reason: ReasonBandwidthExceeded, Detail: detail}
		}
		if heldForBandwidth && (input.Usage.UnderStreak < threshold ||
			input.HeldSince != nil && input.Now.Sub(*input.HeldSince) < MinimumBandwidthHold) {
			return Decision{Held: true, Reason: ReasonBandwidthExceeded, Detail: detail}
		}
	}
	if !input.Held {
		return Decision{Reason: input.Reason, Detail: detail}
	}
	if input.CatchingUp && input.Reason == ReasonTrafficExceeded && settings.TrafficLimitBytes() > 0 && !input.PeriodRestarted {
		return Decision{Held: true, Reason: ReasonTrafficExceeded, Detail: detail}
	}
	switch {
	case input.Reason == ReasonDisabledPeriod && strings.TrimSpace(settings.DisabledPeriods) != "":
		return Decision{Reason: ReasonPeriodEnded, Detail: detail}
	case input.Reason == ReasonTrafficExceeded && input.PeriodRestarted && !input.SettingsRestarted:
		return Decision{Reason: ReasonPeriodReset, Detail: detail}
	case input.Reason == ReasonBandwidthExceeded && settings.BandwidthLimitBPS() > 0:
		return Decision{Reason: ReasonBandwidthRecovered, Detail: detail}
	default:
		return Decision{Reason: ReasonSettingsChanged, Detail: detail}
	}
}
