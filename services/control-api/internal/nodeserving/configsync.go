package nodeserving

import "time"

const (
	SourceConfigSync = "config_sync"
	// SourceExternalProbe: probes from outside the node (controller and peer
	// nodes, nodeprobe) found every published endpoint unreachable.
	SourceExternalProbe = "external_probe"

	ReasonSyncFailed     = "sync_failed"
	ReasonSyncRecovered  = "sync_recovered"
	ReasonSyncDisabled   = "sync_hold_disabled"
	ReasonSyncLimitGuard = "sync_hold_limit"

	// ConfigSyncRetryAfter is how long a node stays held before its failed
	// scopes are published to it again ("retry after half an hour").
	ConfigSyncRetryAfter = 30 * time.Minute
)

// ConfigSyncInput is everything one config-sync hold decision depends on.
type ConfigSyncInput struct {
	// Enabled is the platform switch disable_failed_sync_nodes.
	Enabled    bool
	NodeActive bool
	// Failing: the newest deployment of at least one scope on the node failed,
	// was reverted, or ran past its deadline.
	Failing bool
	// Running: a deployment is still in flight, so the outcome is not known.
	Running bool
	Held    bool
	Reason  string
	// OverLimit: holding this node would take more than half of the
	// admin-enabled nodes of one of its line groups out of DNS.
	OverLimit bool
}

// DecideConfigSync holds a node whose configuration sync failed and releases
// it once every scope's newest deployment is healthy again. A new hold is
// refused while it would hold more than half of a line group: a failure that
// wide is a publication problem, not a node problem.
func DecideConfigSync(input ConfigSyncInput) Decision {
	switch {
	case !input.Enabled:
		return Decision{Reason: ReasonSyncDisabled}
	case !input.NodeActive:
		return Decision{Reason: ReasonNodeInactive}
	case input.Held && (input.Failing || input.Running):
		return Decision{Held: true, Reason: input.Reason}
	case input.Held:
		return Decision{Reason: ReasonSyncRecovered}
	case input.Failing && input.OverLimit:
		return Decision{Reason: ReasonSyncLimitGuard}
	case input.Failing:
		return Decision{Held: true, Reason: ReasonSyncFailed}
	default:
		return Decision{Reason: input.Reason}
	}
}
