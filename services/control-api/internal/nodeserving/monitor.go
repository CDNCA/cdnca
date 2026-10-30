package nodeserving

import (
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

// MonitorSample is the newest Agent probe report of one node.
type MonitorSample struct {
	Healthy        bool
	ProbeSucceeded bool
	IngestedAt     time.Time
}

// MonitorInput is everything the availability decision depends on. Times are
// the database clock so decisions do not depend on control-api clock skew.
type MonitorInput struct {
	NodeActive bool
	// PolicyActive is false when the platform has no active monitoring policy.
	PolicyActive bool
	// Effective is the active platform policy overlaid by the node override.
	Effective systemconfig.NodeMonitoringConfiguration
	Sample    *MonitorSample
	// RecentHealthy is the number of newest consecutive reports ingested after
	// the hold started that are healthy with a successful probe.
	RecentHealthy int
	Now           time.Time
	// WarmUntil suppresses staleness holds until the worker has run for one
	// stale window, so a control-plane restart never reads as node failure.
	WarmUntil time.Time
	// IngestionStale is true when no node of the scope has a fresh report:
	// the reporting path, not the nodes, is down.
	IngestionStale bool
	Held           bool
	Reason         string
	// DNSPup is the node's fresh dnspup checkpoint verdict (nil: none, the
	// local probe decides alone; internal/nodednspupprobe).
	DNSPup *DNSPupVerdict
}

// DNSPupVerdict is a fresh dnspup verdict of the node:
// while one exists the node is removed from serving only when the local probe
// and the dnspup checkpoints both fail, and released as soon as dnspup
// reaches it again.
type DNSPupVerdict struct {
	Failing bool
}

// ReasonDNSPupReachable releases (or keeps serving) a node the local probe
// fails while dnspup checkpoints reach it.
const ReasonDNSPupReachable = "dnspup_reachable"

// StaleAfter mirrors the monitoring snapshot classification
// (nodemetrics.classifyMonitoringSample): interval+timeout+30s, capped at 390s.
func StaleAfter(value systemconfig.NodeMonitoringConfiguration) time.Duration {
	return time.Duration(min(value.ProbeIntervalMS+value.ProbeTimeoutMS+30_000, 390_000)) * time.Millisecond
}

// DecideMonitor applies the failure action "pause". The Agent already applies
// the failure/recovery thresholds and debounce before reporting healthy=false,
// so one fresh unhealthy report holds. A missing report stream (node or Agent
// down) holds once older than the stale window. Release always requires the
// policy's recovery_threshold consecutive healthy reports received after the
// hold started, so a restarting Agent's optimistic first report or a single
// recovered probe cannot flap the node back into DNS. With a fresh dnspup
// verdict (input.DNSPup) a local failure only holds when dnspup fails too,
// and a held node is released once dnspup reaches it again.
func DecideMonitor(input MonitorInput) Decision {
	keep := Decision{Held: input.Held, Reason: input.Reason}
	switch {
	case !input.NodeActive:
		return Decision{Reason: ReasonNodeInactive}
	case !input.PolicyActive:
		return Decision{Reason: ReasonPolicyInactive}
	case input.Effective.MonitorEnabled != nil && !*input.Effective.MonitorEnabled:
		return Decision{Reason: ReasonMonitorDisabled}
	case input.Effective.MonitorAction != "pause":
		return Decision{Reason: ReasonActionNone}
	}
	if input.Sample == nil {
		return keep
	}
	staleAfter := StaleAfter(input.Effective)
	fresh := !input.Sample.IngestedAt.Before(input.Now.Add(-staleAfter))
	detail := map[string]any{
		"ingested_at": input.Sample.IngestedAt.UTC().Format(time.RFC3339Nano), "healthy": input.Sample.Healthy,
		"probe_succeeded": input.Sample.ProbeSucceeded, "stale_after_ms": staleAfter.Milliseconds(),
	}
	if input.DNSPup != nil {
		detail["dnspup_failing"] = input.DNSPup.Failing
		if input.Held && !input.DNSPup.Failing {
			return Decision{Reason: ReasonDNSPupReachable, Detail: detail}
		}
		if !input.Held && !input.DNSPup.Failing {
			return keep
		}
	}
	if input.Held {
		need := max(input.Effective.RecoveryThreshold, 1)
		if fresh && input.Sample.Healthy && input.Sample.ProbeSucceeded && input.RecentHealthy >= need {
			detail["recovery_reports"] = input.RecentHealthy
			return Decision{Reason: ReasonProbeRecovered, Detail: detail}
		}
		return keep
	}
	if fresh {
		if !input.Sample.Healthy {
			return Decision{Held: true, Reason: ReasonProbeUnhealthy, Detail: detail}
		}
		return keep
	}
	if input.Now.Before(input.WarmUntil) || input.IngestionStale {
		return keep
	}
	return Decision{Held: true, Reason: ReasonProbeStale, Detail: detail}
}
