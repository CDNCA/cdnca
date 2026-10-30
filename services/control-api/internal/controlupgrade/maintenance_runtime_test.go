package controlupgrade

import (
	"context"
	"testing"
)

func TestMaintenanceControlRuntimeUsesRealReadOnlyProbe(t *testing.T) {
	for _, test := range []struct {
		name  string
		probe func(context.Context) MaintenanceRuntimeState
		want  MaintenanceRuntimeState
	}{
		{"unconfigured", nil, MaintenanceRuntimeState{Reason: "control_upgrade_plan_writer_unconfigured"}},
		{"unconfirmed", func(context.Context) MaintenanceRuntimeState {
			return MaintenanceRuntimeState{Reason: "control_upgrade_runner_unconfirmed"}
		}, MaintenanceRuntimeState{Reason: "control_upgrade_runner_unconfirmed"}},
		{"ready", func(context.Context) MaintenanceRuntimeState {
			return MaintenanceRuntimeState{Ready: true, Reason: "ready"}
		}, MaintenanceRuntimeState{Ready: true, Reason: "ready"}},
		{"inconsistent", func(context.Context) MaintenanceRuntimeState {
			return MaintenanceRuntimeState{Ready: true, Reason: "control_upgrade_runner_unconfirmed"}
		}, MaintenanceRuntimeState{Reason: "control_upgrade_execution_unavailable"}},
		{"raw failure", func(context.Context) MaintenanceRuntimeState {
			return MaintenanceRuntimeState{Reason: "password=never-emit-test-value"}
		}, MaintenanceRuntimeState{Reason: "control_upgrade_execution_unavailable"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := maintenanceControlRuntime(t.Context(), test.probe)
			if got != test.want {
				t.Fatalf("got %+v want %+v", got, test.want)
			}
		})
	}
}
