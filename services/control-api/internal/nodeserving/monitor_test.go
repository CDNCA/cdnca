package nodeserving

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

func pausePolicy() systemconfig.NodeMonitoringConfiguration {
	return systemconfig.NodeMonitoringConfiguration{PortMode: "default", MonitorAction: "pause",
		ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000, FailureThreshold: 3, RecoveryThreshold: 3}
}

func TestDecideMonitorHoldsAndReleasesWithPolicyThresholds(t *testing.T) {
	now := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	base := MonitorInput{NodeActive: true, PolicyActive: true, Effective: pausePolicy(), Now: now}
	fresh := func(healthy, succeeded bool) *MonitorSample {
		return &MonitorSample{Healthy: healthy, ProbeSucceeded: succeeded, IngestedAt: now.Add(-time.Second)}
	}
	stale := &MonitorSample{Healthy: true, ProbeSucceeded: true, IngestedAt: now.Add(-44 * time.Second)}
	disabled := false
	for name, test := range map[string]struct {
		edit       func(*MonitorInput)
		held       bool
		reason     string
		transition bool
	}{
		"healthy stays serving":        {edit: func(in *MonitorInput) { in.Sample = fresh(true, false) }},
		"agent unhealthy holds":        {edit: func(in *MonitorInput) { in.Sample = fresh(false, false) }, held: true, reason: ReasonProbeUnhealthy, transition: true},
		"no report never holds":        {edit: func(in *MonitorInput) {}},
		"stale report holds":           {edit: func(in *MonitorInput) { in.Sample = stale }, held: true, reason: ReasonProbeStale, transition: true},
		"stale during warm-up keeps":   {edit: func(in *MonitorInput) { in.Sample = stale; in.WarmUntil = now.Add(time.Second) }},
		"stale ingestion outage keeps": {edit: func(in *MonitorInput) { in.Sample = stale; in.IngestionStale = true }},
		"action none never holds":      {edit: func(in *MonitorInput) { in.Sample = fresh(false, false); in.Effective.MonitorAction = "none" }, reason: ReasonActionNone},
		"monitor disabled releases":    {edit: func(in *MonitorInput) { in.Held = true; in.Effective.MonitorEnabled = &disabled }, reason: ReasonMonitorDisabled, transition: true},
		"inactive policy releases":     {edit: func(in *MonitorInput) { in.Held = true; in.PolicyActive = false }, reason: ReasonPolicyInactive, transition: true},
		"disabled node releases":       {edit: func(in *MonitorInput) { in.Held = true; in.NodeActive = false }, reason: ReasonNodeInactive, transition: true},
		"held needs recovery threshold": {edit: func(in *MonitorInput) {
			in.Held, in.Reason, in.Sample, in.RecentHealthy = true, ReasonProbeUnhealthy, fresh(true, true), 2
		}, held: true, reason: ReasonProbeUnhealthy},
		"held releases after threshold": {edit: func(in *MonitorInput) { in.Held, in.Sample, in.RecentHealthy = true, fresh(true, true), 3 }, reason: ReasonProbeRecovered, transition: true},
		"held keeps on failed probe":    {edit: func(in *MonitorInput) { in.Held, in.Sample, in.RecentHealthy = true, fresh(true, false), 3 }, held: true},
		"held keeps when stale":         {edit: func(in *MonitorInput) { in.Held, in.Sample, in.RecentHealthy = true, stale, 3 }, held: true},
		"held keeps without any report": {edit: func(in *MonitorInput) { in.Held = true }, held: true},
	} {
		input := base
		test.edit(&input)
		decision := DecideMonitor(input)
		if decision.Held != test.held || (test.reason != "" && decision.Reason != test.reason) {
			t.Errorf("%s: decision = %+v, want held=%v reason=%q", name, decision, test.held, test.reason)
		}
		if (decision.Held != input.Held) != test.transition {
			t.Errorf("%s: transition = %v, want %v", name, decision.Held != input.Held, test.transition)
		}
	}
}

// 本机探测与 dnspup 多数检测点都失败才停调度；只有一方失败不停；
// 没有新鲜的 dnspup 判定（关闭/额度用完/暂停）回落本机探测单独判定。
func TestDecideMonitorNeedsDNSPupAgreementWhenFresh(t *testing.T) {
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	base := MonitorInput{NodeActive: true, PolicyActive: true, Effective: pausePolicy(), Now: now}
	unhealthy := &MonitorSample{Healthy: false, IngestedAt: now.Add(-time.Second)}
	healthy := &MonitorSample{Healthy: true, ProbeSucceeded: true, IngestedAt: now.Add(-time.Second)}
	stale := &MonitorSample{Healthy: true, ProbeSucceeded: true, IngestedAt: now.Add(-44 * time.Second)}
	failing, reachable := &DNSPupVerdict{Failing: true}, &DNSPupVerdict{}
	for name, test := range map[string]struct {
		edit   func(*MonitorInput)
		held   bool
		reason string
	}{
		"both failed holds": {edit: func(in *MonitorInput) { in.Sample, in.DNSPup = unhealthy, failing },
			held: true, reason: ReasonProbeUnhealthy},
		"local failed, dnspup reachable keeps serving": {edit: func(in *MonitorInput) { in.Sample, in.DNSPup = unhealthy, reachable }},
		"stale local, dnspup reachable keeps serving":  {edit: func(in *MonitorInput) { in.Sample, in.DNSPup = stale, reachable }},
		"stale local, dnspup failed holds": {edit: func(in *MonitorInput) { in.Sample, in.DNSPup = stale, failing },
			held: true, reason: ReasonProbeStale},
		"dnspup failed alone keeps serving": {edit: func(in *MonitorInput) { in.Sample, in.DNSPup = healthy, failing }},
		"no dnspup verdict falls back to local": {edit: func(in *MonitorInput) { in.Sample = unhealthy },
			held: true, reason: ReasonProbeUnhealthy},
		"held releases when dnspup recovers": {edit: func(in *MonitorInput) {
			in.Held, in.Reason, in.Sample, in.DNSPup = true, ReasonProbeUnhealthy, unhealthy, reachable
		}, reason: ReasonDNSPupReachable},
		"held stays while both fail": {edit: func(in *MonitorInput) {
			in.Held, in.Reason, in.Sample, in.DNSPup = true, ReasonProbeUnhealthy, unhealthy, failing
		}, held: true, reason: ReasonProbeUnhealthy},
	} {
		input := base
		test.edit(&input)
		decision := DecideMonitor(input)
		if decision.Held != test.held || (test.reason != "" && decision.Reason != test.reason) {
			t.Errorf("%s: decision = %+v, want held=%v reason=%q", name, decision, test.held, test.reason)
		}
	}
}

func TestStaleAfterMatchesSnapshotClassification(t *testing.T) {
	if got := StaleAfter(pausePolicy()); got != 43*time.Second {
		t.Fatalf("StaleAfter = %v", got)
	}
	long := pausePolicy()
	long.ProbeIntervalMS, long.ProbeTimeoutMS = 300_000, 60_000
	if got := StaleAfter(long); got != 390*time.Second {
		t.Fatalf("StaleAfter cap = %v", got)
	}
}
