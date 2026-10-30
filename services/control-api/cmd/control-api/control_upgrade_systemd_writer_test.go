package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestControlUpgradeSystemdWriterUsesPlanSourceRepository(t *testing.T) {
	t.Setenv("CONTROL_UPGRADE_PLAN_WRITER_ENABLED", "true")
	t.Setenv(controlUpgradePlanEnabledEnv, "true")
	t.Setenv(controlUpgradePlanTokenFileEnv, ops06PlanTokenFile(t, 0o600))
	t.Setenv("CONTROL_UPGRADE_EXPECTED_REPLICAS", "3")
	t.Setenv("CONTROL_UPGRADE_QUORUM", "2")
	t.Setenv("CONTROL_UPGRADE_PROTOCOL_VERSION", "1")
	t.Setenv("CONTROL_UPGRADE_REPLICA_ID", "control-1")
	t.Setenv("CONTROL_ARTIFACT_SHA256", strings.Repeat("a", 64))
	oldVersion := controlVersion
	controlVersion = "2026.10.8"
	t.Cleanup(func() { controlVersion = oldVersion })
	installationID := uuid.NewString()
	database := &ops06PlanRuntimeDatabase{schemaReady: true}
	handler, err := openControlPlaneUpgradeHTTPRuntimeWithDatabase(config.Config{
		ControlVersion: controlVersion, ControlInstallationID: installationID,
	}, &identity.Service{}, &entitlementguard.TrustStore{}, database)
	if err != nil || handler == nil || !strings.Contains(database.schemaSQL, "control_upgrade_systemd_repository_154") {
		t.Fatalf("systemd writer incorrectly requires Kubernetes: handler=%v error=%v", handler != nil, err)
	}
	if state := handler.MaintenanceRuntimeStatus(t.Context()); state.Ready || state.Reason != "control_upgrade_ha_unavailable" {
		t.Fatalf("empty repository cannot claim healthy HA: %+v", state)
	}

	t.Setenv("CONTROL_UPGRADE_EXPECTED_REPLICAS", "1")
	t.Setenv("CONTROL_UPGRADE_QUORUM", "1")
	if _, err := openControlPlaneUpgradeHTTPRuntimeWithDatabase(config.Config{
		ControlVersion: controlVersion, ControlInstallationID: installationID,
	}, &identity.Service{}, &entitlementguard.TrustStore{}, database); !errors.Is(err, controlplaneupgrade.ErrInvalidConfig) {
		t.Fatalf("single replica silently enabled HA: %v", err)
	}
	for _, badDatabase := range []*ops06PlanRuntimeDatabase{nil, {schemaReady: false}} {
		t.Setenv("CONTROL_UPGRADE_EXPECTED_REPLICAS", "3")
		t.Setenv("CONTROL_UPGRADE_QUORUM", "2")
		if _, err := openControlPlaneUpgradeHTTPRuntimeWithDatabase(config.Config{
			ControlVersion: controlVersion, ControlInstallationID: installationID,
		}, &identity.Service{}, &entitlementguard.TrustStore{}, badDatabase); err == nil {
			t.Fatal("unavailable systemd repository accepted")
		}
	}
}
