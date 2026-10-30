package nodeserving

import (
	"testing"
	"time"
)

var shanghai = time.FixedZone("CST", 8*3600)

func TestAutoDisablePeriodStartsOnConfiguredDayAndTime(t *testing.T) {
	settings := AutoDisableSettings{TrafficFromDay: 15, TrafficFromTime: "12:00:00"}
	for _, test := range []struct{ now, start, end string }{
		{"2026-10-20T00:00:00+08:00", "2026-10-15T12:00:00+08:00", "2026-11-15T12:00:00+08:00"},
		{"2026-10-15T11:59:59+08:00", "2026-09-15T12:00:00+08:00", "2026-10-15T12:00:00+08:00"},
		{"2026-10-15T12:00:00+08:00", "2026-10-15T12:00:00+08:00", "2026-11-15T12:00:00+08:00"},
		{"2027-01-02T00:00:00+08:00", "2026-12-15T12:00:00+08:00", "2027-01-15T12:00:00+08:00"},
	} {
		now, _ := time.Parse(time.RFC3339, test.now)
		start, end := settings.Period(now, shanghai)
		wantStart, _ := time.Parse(time.RFC3339, test.start)
		wantEnd, _ := time.Parse(time.RFC3339, test.end)
		if !start.Equal(wantStart) || !end.Equal(wantEnd) {
			t.Errorf("Period(%s) = %s..%s, want %s..%s", test.now, start, end, wantStart, wantEnd)
		}
	}
}

func TestAutoDisableWindowsIncludeCrossMidnight(t *testing.T) {
	settings := AutoDisableSettings{DisabledPeriods: "00:00:00-03:00:00 22:30:00-06:00:00"}
	for clock, want := range map[string]bool{
		"00:00:00": true, "02:59:59": true, "03:00:00": true, "06:00:00": false, "12:00:00": false,
		"22:29:59": false, "22:30:00": true, "23:59:59": true,
	} {
		now, _ := time.ParseInLocation("2006-01-02 15:04:05", "2026-10-13 "+clock, shanghai)
		if got := settings.InDisabledPeriod(now, shanghai); got != want {
			t.Errorf("InDisabledPeriod(%s) = %v, want %v", clock, got, want)
		}
	}
	if (AutoDisableSettings{}).InDisabledPeriod(time.Now(), shanghai) {
		t.Fatal("no windows must never disable")
	}
}

func TestAutoDisableAccountingHandlesBaselineResetsAndFilters(t *testing.T) {
	now := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	settings := AutoDisableSettings{TrafficTypes: []string{"outbound"}, ExcludedInterfaces: "docker0", BandwidthLimit: 100, BandwidthUnit: "Mbps"}
	nic := func(name string, rx, tx, rxBPS, txBPS uint64) NetworkInterfaceSample {
		return NetworkInterfaceSample{Name: name, RXBytes: rx, TXBytes: tx, RXBandwidthBPS: rxBPS, TXBandwidthBPS: txBPS}
	}
	state := UsageState{}
	state.Accumulate(settings, []NetworkSample{
		{Sequence: 1, ObservedAt: now.Add(-time.Hour), Interfaces: []NetworkInterfaceSample{nic("eth0", 10, 1000, 0, 0), nic("docker0", 0, 5000, 0, 0)}},
		{Sequence: 2, ObservedAt: now.Add(-50 * time.Minute), Interfaces: []NetworkInterfaceSample{nic("eth0", 999, 1500, 0, 900_000_000), nic("docker0", 0, 9000, 0, 0)}},
		// Reboot: counter restarts at 200, which is the traffic since the reset.
		{Sequence: 3, ObservedAt: now.Add(-40 * time.Minute), Interfaces: []NetworkInterfaceSample{nic("eth0", 0, 200, 0, 0)}},
		{Sequence: 3, ObservedAt: now.Add(-30 * time.Minute), Interfaces: []NetworkInterfaceSample{nic("eth0", 0, 1_000_000, 0, 0)}},
	}, now)
	if state.UsageBytes != 500+200 || state.LastSequence != 3 {
		t.Fatalf("usage = %d sequence = %d, want outbound eth0 only with reset handling and no replay", state.UsageBytes, state.LastSequence)
	}
	if state.OverStreak != 0 {
		t.Fatalf("historical bandwidth moved the streak: %+v", state)
	}
	for sequence := int64(4); sequence <= 6; sequence++ {
		state.Accumulate(settings, []NetworkSample{{Sequence: sequence, ObservedAt: now.Add(-10 * time.Second),
			Interfaces: []NetworkInterfaceSample{nic("eth0", 0, 300, 999_000_000, 150_000_000), nic("docker0", 0, 0, 0, 999_000_000)}}}, now)
	}
	if state.OverStreak != 3 || state.UnderStreak != 0 || state.LastBandwidthBPS != 150_000_000 {
		t.Fatalf("live outbound bandwidth streak = %+v", state)
	}
	both := settings
	both.TrafficTypes = []string{"outbound", "inbound"}
	if both.AccountingDigest() == settings.AccountingDigest() {
		t.Fatal("traffic types must change the accounting digest")
	}
	fresh, period, changed := state.Restart(both, state.PeriodStart, state.PeriodEnd)
	if !changed || period || fresh.UsageBytes != 0 || fresh.LastSequence != 0 {
		t.Fatalf("settings restart = %+v %v %v", fresh, period, changed)
	}
}

func TestDecideAutoDisableHoldsReleasesAndAvoidsFlapping(t *testing.T) {
	now := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	recent, old := now.Add(-time.Minute), now.Add(-10*time.Minute)
	quota := AutoDisableSettings{TrafficEnabled: true, TrafficTotalGB: 1}
	bandwidth := AutoDisableSettings{BandwidthLimit: 100, BandwidthUnit: "Mbps"}
	for index, test := range []struct {
		input  AutoDisableInput
		held   bool
		reason string
	}{
		{AutoDisableInput{NodeActive: true, Settings: quota, Usage: UsageState{UsageBytes: gibibyte - 1}}, false, ""},
		{AutoDisableInput{NodeActive: true, Settings: quota, Usage: UsageState{UsageBytes: gibibyte}}, true, ReasonTrafficExceeded},
		{AutoDisableInput{NodeActive: true, Settings: quota, Held: true, Reason: ReasonTrafficExceeded, PeriodRestarted: true}, false, ReasonPeriodReset},
		{AutoDisableInput{NodeActive: true, Settings: quota, Held: true, Reason: ReasonTrafficExceeded, CatchingUp: true}, true, ReasonTrafficExceeded},
		{AutoDisableInput{NodeActive: true, Settings: AutoDisableSettings{}, Held: true, Reason: ReasonTrafficExceeded, SettingsRestarted: true}, false, ReasonSettingsChanged},
		{AutoDisableInput{NodeActive: true, Settings: bandwidth, Threshold: 3, Usage: UsageState{OverStreak: 2}}, false, ""},
		{AutoDisableInput{NodeActive: true, Settings: bandwidth, Threshold: 3, Usage: UsageState{OverStreak: 3}}, true, ReasonBandwidthExceeded},
		{AutoDisableInput{NodeActive: true, Settings: bandwidth, Threshold: 3, Held: true, Reason: ReasonBandwidthExceeded, HeldSince: &old, Usage: UsageState{UnderStreak: 2}}, true, ReasonBandwidthExceeded},
		{AutoDisableInput{NodeActive: true, Settings: bandwidth, Threshold: 3, Held: true, Reason: ReasonBandwidthExceeded, HeldSince: &recent, Usage: UsageState{UnderStreak: 9}}, true, ReasonBandwidthExceeded},
		{AutoDisableInput{NodeActive: true, Settings: bandwidth, Threshold: 3, Held: true, Reason: ReasonBandwidthExceeded, HeldSince: &old, Usage: UsageState{UnderStreak: 3}}, false, ReasonBandwidthRecovered},
		{AutoDisableInput{NodeActive: true, Settings: AutoDisableSettings{DisabledPeriods: "00:00:00-01:00:00", TrafficEnabled: true, TrafficTotalGB: 1},
			InDisabledPeriod: true, Usage: UsageState{UsageBytes: gibibyte}}, true, ReasonDisabledPeriod},
		{AutoDisableInput{NodeActive: true, Settings: AutoDisableSettings{DisabledPeriods: "00:00:00-01:00:00"}, Held: true, Reason: ReasonDisabledPeriod}, false, ReasonPeriodEnded},
		{AutoDisableInput{NodeActive: false, Settings: quota, Held: true, Reason: ReasonTrafficExceeded, Usage: UsageState{UsageBytes: gibibyte}}, false, ReasonNodeInactive},
	} {
		test.input.Now = now
		decision := DecideAutoDisable(test.input)
		if decision.Held != test.held || test.reason != "" && decision.Reason != test.reason {
			t.Errorf("case %d: decision = %+v, want held=%v reason=%q", index, decision, test.held, test.reason)
		}
	}
}

func TestAutoDisableUnitsMatchDisplayedUnits(t *testing.T) {
	if got := (AutoDisableSettings{BandwidthLimit: 2, BandwidthUnit: "Gbps"}).BandwidthLimitBPS(); got != 2_000_000_000 {
		t.Fatalf("Gbps = %d", got)
	}
	if got := (AutoDisableSettings{TrafficEnabled: true, TrafficTotalGB: 500}).TrafficLimitBytes(); got != 500<<30 {
		t.Fatalf("GB = %d", got)
	}
	if (AutoDisableSettings{TrafficTotalGB: 500}).TrafficLimitBytes() != 0 || (AutoDisableSettings{TrafficTotalGB: 500}).Active() {
		t.Fatal("a switched-off traffic limit must not count")
	}
}
