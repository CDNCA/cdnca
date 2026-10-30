package controlplaneupgradehttp

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
)

func TestMaintenanceRuntimeStatusNeverObservesOrStartsAnExecutor(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot controlplaneupgrade.ControlSnapshot
		reason   string
	}{
		{"standalone cannot claim HA", controlplaneupgrade.ControlSnapshot{Phase: controlplaneupgrade.ControlActive, ExpectedReplicas: 1, Quorum: 1, HealthyReplicas: 1}, "control_upgrade_ha_unavailable"},
		{"no quorum", controlplaneupgrade.ControlSnapshot{Phase: controlplaneupgrade.ControlActive, ExpectedReplicas: 3, Quorum: 2, HealthyReplicas: 1}, "control_upgrade_ha_unavailable"},
		{"draining", controlplaneupgrade.ControlSnapshot{Phase: controlplaneupgrade.ControlDraining, ExpectedReplicas: 3, Quorum: 2, HealthyReplicas: 3}, "control_upgrade_draining"},
		{"healthy replicas are not runner proof", controlplaneupgrade.ControlSnapshot{Phase: controlplaneupgrade.ControlActive, ExpectedReplicas: 3, Quorum: 2, HealthyReplicas: 3}, "control_upgrade_runner_unconfirmed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator := &coordinatorStub{snapshot: test.snapshot}
			handler := &Handler{publisher: &publisherStub{}, coordinator: coordinator}
			got := handler.MaintenanceRuntimeStatus(t.Context())
			if got.Ready || got.Reason != test.reason || coordinator.observeCalls != 0 {
				t.Fatalf("status=%+v observe calls=%d", got, coordinator.observeCalls)
			}
		})
	}
	var handler *Handler
	if state := handler.MaintenanceRuntimeStatus(t.Context()); state.Ready || state.Reason != "control_upgrade_plan_writer_unconfigured" {
		t.Fatalf("nil handler status=%+v", state)
	}
}
