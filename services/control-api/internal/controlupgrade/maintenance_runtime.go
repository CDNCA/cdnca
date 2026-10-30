package controlupgrade

import "context"

// A status read only reports observations. It must not start a runner, create a
// publication, or register a replica as healthy.
func maintenanceControlRuntime(ctx context.Context, probe func(context.Context) MaintenanceRuntimeState) MaintenanceRuntimeState {
	if probe == nil {
		return MaintenanceRuntimeState{Reason: "control_upgrade_plan_writer_unconfigured"}
	}
	state := probe(ctx)
	if state.Ready && state.Reason == "ready" {
		return state
	}
	if !state.Ready {
		switch state.Reason {
		case "control_upgrade_plan_writer_unconfigured", "control_upgrade_runner_unconfirmed",
			"control_upgrade_state_unavailable", "control_upgrade_ha_unavailable", "control_upgrade_draining":
			return state
		}
	}
	return MaintenanceRuntimeState{Reason: "control_upgrade_execution_unavailable"}
}
