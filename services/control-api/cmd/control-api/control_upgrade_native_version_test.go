package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestNativeControlUpgradeUsesRunningVersionAcrossUpgradeAndRollback(t *testing.T) {
	t.Setenv("CDNCA_NATIVE_UPGRADE_ENABLED", "true")
	t.Setenv("CDNCA_NATIVE_UPGRADE_STATUS_FILE", "/run/cdnca-upgrade/status.json")
	t.Setenv("CDNCA_NATIVE_UPGRADE_STATE_FILE", "/run/cdnca-upgrade/status.json.state.json")
	t.Setenv("CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE", "/run/cdnca-upgrade/maintenance.json")
	t.Setenv("CONTROL_UPGRADE_PLAN_WRITER_ENABLED", "false")
	t.Setenv(controlUpgradePlanEnabledEnv, "true")
	t.Setenv(controlUpgradePlanTokenFileEnv, "/etc/cdnca-upgrade/plan-source-token")
	t.Setenv("CONTROL_UPGRADE_PROTOCOL_VERSION", "2")
	t.Setenv("CONTROL_UPGRADE_EXPECTED_REPLICAS", "")
	t.Setenv("CONTROL_UPGRADE_QUORUM", "")
	originalVersion := controlVersion
	t.Cleanup(func() { controlVersion = originalVersion })
	configured := config.Config{ControlVersion: "1.0.0", ControlInstallationID: uuid.NewString()}
	for _, running := range []string{"1.1.0", "1.2.0", "1.0.0"} {
		controlVersion = running
		runtime, err := openControlPlaneUpgradeRuntimeWithDatabase(configured, &identity.Service{}, &entitlementguard.TrustStore{},
			&ops06PlanRuntimeDatabase{schemaReady: true})
		if err != nil || runtime == nil {
			t.Fatalf("native %s could not boot with preserved env %s: %v", running, configured.ControlVersion, err)
		}
		effective, err := controlPlaneUpgradeEffectiveConfig(configured)
		if err != nil || effective.ControlVersion != running || effective.ControlInstallationID != configured.ControlInstallationID || configured.ControlVersion != "1.0.0" {
			t.Fatalf("effective running=%s version=%s original=%s err=%v", running, effective.ControlVersion, configured.ControlVersion, err)
		}
	}
	for _, invalid := range []string{"", "development", "v1.1.0", "1.1", "01.1.0", "1.1.0+build", "1.1.0-rc.1", "1000000000.1.0"} {
		controlVersion = invalid
		if _, err := controlPlaneUpgradeEffectiveConfig(configured); err == nil {
			t.Fatalf("invalid native compiled version %q accepted", invalid)
		}
	}
	t.Setenv("CDNCA_NATIVE_UPGRADE_ENABLED", "false")
	controlVersion = "development"
	effective, err := controlPlaneUpgradeEffectiveConfig(configured)
	if err != nil || effective.ControlVersion != configured.ControlVersion {
		t.Fatalf("disabled native altered legacy version: effective=%s err=%v", effective.ControlVersion, err)
	}
}
