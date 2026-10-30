package nodemonitoringconfig

import "github.com/cdnca/cdnca/services/control-api/internal/systemconfig"

// MaxOverrideRevision bounds a node override revision (migration 279) so the
// effective revision stays a JavaScript-safe integer.
const MaxOverrideRevision = 1 << 20

// Override is one node's monitoring override. Nil/empty fields inherit the
// active platform policy. Revision is the override's own monotonic revision,
// zero when the node never had an override.
type Override struct {
	Revision       int64
	MonitorEnabled *bool
	Protocol       string
	ProbeTimeoutMS *int
	MonitorPort    *uint16
	MonitorAction  string
}

// EffectiveRevision is the config_revision delivered to one node. Platform and
// override revisions only advance and every change advances one of them, so
// the Agent observes a strictly increasing revision. Without an override it is
// exactly the platform revision, keeping existing outbox facts valid.
func EffectiveRevision(platformRevision, overrideRevision int64) int64 {
	return platformRevision + overrideRevision
}

func ValidOverride(override Override) bool {
	return override.Revision >= 0 && override.Revision <= MaxOverrideRevision &&
		(override.Protocol == "" || override.Protocol == "tcp" || override.Protocol == "http" || override.Protocol == "ping") &&
		(override.ProbeTimeoutMS == nil || *override.ProbeTimeoutMS >= 100 && *override.ProbeTimeoutMS <= 60_000) &&
		(override.MonitorPort == nil || *override.MonitorPort > 0) &&
		(override.MonitorAction == "" || override.MonitorAction == "none" || override.MonitorAction == "pause") &&
		(override.Revision > 0 || override == Override{})
}

// ApplyOverride overlays a node override on the platform policy. A timeout
// saved under a longer platform interval is clamped to the current interval,
// which the Agent requires (timeout <= interval).
func ApplyOverride(value systemconfig.NodeMonitoringConfiguration, override Override) systemconfig.NodeMonitoringConfiguration {
	if override.MonitorEnabled != nil {
		value.MonitorEnabled = cloneBool(override.MonitorEnabled)
	}
	if override.Protocol != "" {
		value.Protocol = override.Protocol
	}
	if override.ProbeTimeoutMS != nil {
		value.ProbeTimeoutMS = min(*override.ProbeTimeoutMS, value.ProbeIntervalMS)
	}
	if override.MonitorPort != nil {
		value.MonitorPort = clonePort(override.MonitorPort)
	}
	if override.MonitorAction != "" {
		value.MonitorAction = override.MonitorAction
	}
	return value
}

// CompileNodeDocument compiles the effective artifact for one node and returns
// its effective revision.
func CompileNodeDocument(document systemconfig.CategoryDocument, override Override) ([]byte, int64, error) {
	value, err := activePolicy(document)
	if err != nil || !ValidOverride(override) {
		return nil, 0, ErrInvalidDocument
	}
	effective := ApplyOverride(value, override)
	if !validPolicy(effective) {
		return nil, 0, ErrInvalidDocument
	}
	revision := EffectiveRevision(document.ActiveRevision, override.Revision)
	payload, err := compile(effective, uint64(revision))
	return payload, revision, err
}

// ApplyOverrideToPolicy is ApplyOverride on the read projection of an active
// policy (systemconfig.MonitoringPolicyFor).
func ApplyOverrideToPolicy(policy systemconfig.MonitoringPolicy, override Override) systemconfig.MonitoringPolicy {
	if override.MonitorEnabled != nil {
		policy.Enabled = *override.MonitorEnabled
	}
	if override.Protocol != "" {
		policy.RequestedProtocol = override.Protocol
	}
	if override.ProbeTimeoutMS != nil {
		policy.ProbeTimeoutMS = min(*override.ProbeTimeoutMS, policy.ProbeIntervalMS)
	}
	if override.MonitorPort != nil {
		policy.RequestedPort = clonePort(override.MonitorPort)
	}
	return policy
}
