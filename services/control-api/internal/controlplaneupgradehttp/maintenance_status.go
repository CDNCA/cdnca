package controlplaneupgradehttp

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
)

func (handler *Handler) MaintenanceRuntimeStatus(ctx context.Context) controlupgrade.MaintenanceRuntimeState {
	state := controlupgrade.MaintenanceRuntimeState{Reason: "control_upgrade_plan_writer_unconfigured"}
	if handler == nil || handler.publisher == nil || handler.coordinator == nil {
		return state
	}
	snapshot, err := handler.coordinator.Snapshot(ctx)
	if err != nil {
		state.Reason = "control_upgrade_state_unavailable"
	} else if snapshot.Phase == controlplaneupgrade.ControlDraining {
		state.Reason = "control_upgrade_draining"
	} else if snapshot.ExpectedReplicas < 2 || snapshot.Quorum <= snapshot.ExpectedReplicas/2 ||
		snapshot.Quorum > snapshot.ExpectedReplicas || snapshot.HealthyReplicas < snapshot.Quorum {
		state.Reason = "control_upgrade_ha_unavailable"
	} else {
		// A reachable repository and healthy replicas do not prove that a separate
		// runner is alive, locked, and compatible with this installation's layout.
		state.Reason = "control_upgrade_runner_unconfirmed"
	}
	return state
}
