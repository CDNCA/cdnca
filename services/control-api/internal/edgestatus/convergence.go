package edgestatus

import agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"

const (
	activeConfigProbeCheckName    = "edge_active_config_probe"
	activeConfigProbeCheckSummary = "active config runtime probe passed"
)

func requireTerminalConfigConvergence(deployment lockedDeployment, state string, status *agentv1.DeploymentStatus,
	identity *normalizedStatusActiveIdentity,
) error {
	if !completesRunningConfig(deployment.action, state) || status.ActiveConfigIdentityCapability == nil {
		return nil
	}
	if identity == nil {
		return ErrBindingConflict
	}
	for _, check := range status.Checks {
		if check != nil && check.Name == activeConfigProbeCheckName && check.Succeeded &&
			check.Summary == activeConfigProbeCheckSummary && check.LatencyDuration != nil &&
			check.LatencyDuration.CheckValid() == nil && check.LatencyDuration.AsDuration() >= 0 {
			return nil
		}
	}
	return ErrBindingConflict
}
