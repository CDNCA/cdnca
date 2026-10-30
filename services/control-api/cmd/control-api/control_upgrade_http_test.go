package main

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

func TestControlPlaneUpgradeRuntimeRejectsConfiguredAndEmbeddedVersionDrift(t *testing.T) {
	t.Setenv("CONTROL_UPGRADE_PLAN_WRITER_ENABLED", "true")
	previous := controlVersion
	controlVersion = "1.5.0"
	t.Cleanup(func() { controlVersion = previous })
	_, err := openControlPlaneUpgradeHTTPRuntime(config.Config{ControlVersion: "1.4.0"},
		&identity.Service{}, &entitlementguard.TrustStore{})
	if !errors.Is(err, controlplaneupgrade.ErrInvalidConfig) {
		t.Fatalf("version drift error = %v", err)
	}
}
