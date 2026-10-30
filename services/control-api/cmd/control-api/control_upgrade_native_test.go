package main

import (
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestNativeControlUpgradeLicenseClientWiresIssueEndpoint(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "installation.key")
	controlUpgradeWritePrivateKey(t, keyFile, 0x37)
	installationID := uuid.NewString()
	cases := []struct {
		name    string
		cfg     config.Config
		client  bool
		wantErr bool
	}{
		{"no license service keeps manual upload", config.Config{ControlInstallationID: installationID, ControlInstallationKeyFile: keyFile}, false, false},
		{"configured installation", config.Config{LicenseServiceURL: "https://auth.example.test", ControlInstallationID: installationID,
			ControlInstallationKeyFile: keyFile}, true, false},
		{"unreadable key fails closed", config.Config{LicenseServiceURL: "https://auth.example.test", ControlInstallationID: installationID,
			ControlInstallationKeyFile: keyFile + ".missing"}, false, true},
		{"invalid installation id", config.Config{LicenseServiceURL: "https://auth.example.test", ControlInstallationID: "not-a-uuid",
			ControlInstallationKeyFile: keyFile}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := nativeControlUpgradeLicenseClient(tc.cfg)
			if (err != nil) != tc.wantErr || (client != nil) != tc.client {
				t.Fatalf("client=%v err=%v", client != nil, err)
			}
			if client != nil {
				client.Close()
			}
		})
	}
}

func TestNativeControlUpgradeConfigurationIsExplicitAndExclusive(t *testing.T) {
	valid := []string{
		"CDNCA_NATIVE_UPGRADE_ENABLED=true",
		"CDNCA_NATIVE_UPGRADE_STATUS_FILE=/run/cdnca-upgrade/status.json",
		"CDNCA_NATIVE_UPGRADE_STATE_FILE=/run/cdnca-upgrade/status.json.state.json",
		"CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE=/run/cdnca-upgrade/maintenance.json",
		"CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED=true",
	}
	config, err := loadNativeControlUpgradeConfigFromEnv(valid)
	if err != nil || !config.Enabled || config.StatusFile != "/run/cdnca-upgrade/status.json" ||
		config.StateFile != "/run/cdnca-upgrade/status.json.state.json" || config.MaintenanceFile != "/run/cdnca-upgrade/maintenance.json" {
		t.Fatalf("native config=%+v err=%v", config, err)
	}
	for _, test := range []struct {
		name, value string
	}{
		{"CONTROL_UPGRADE_PLAN_WRITER_ENABLED", "true"},
		{"CONTROL_UPGRADE_EXPECTED_REPLICAS", "1"},
		{"CONTROL_UPGRADE_QUORUM", "1"},
		{"CDNCA_NATIVE_UPGRADE_EXTRA", "unknown"},
		{"CDNCA_NATIVE_UPGRADE_ENABLED", "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := append(append([]string{}, valid...), test.name+"="+test.value)
			if _, err := loadNativeControlUpgradeConfigFromEnv(candidate); err == nil {
				t.Fatal("ambiguous native/HA configuration accepted")
			}
		})
	}
	for _, test := range []struct{ name, value string }{
		{"CDNCA_NATIVE_UPGRADE_ENABLED", "TRUE"},
		{"CDNCA_NATIVE_UPGRADE_STATUS_FILE", "relative/status.json"},
		{"CDNCA_NATIVE_UPGRADE_STATE_FILE", "/var/lib/../state.json"},
		{"CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE", ""},
		{"CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED", "false"},
	} {
		candidate := controlUpgradeReplaceEnvironment(valid, test.name, test.value)
		if _, err := loadNativeControlUpgradeConfigFromEnv(candidate); err == nil {
			t.Fatalf("invalid %s accepted", test.name)
		}
	}
	disabled, err := loadNativeControlUpgradeConfigFromEnv([]string{"CDNCA_NATIVE_UPGRADE_ENABLED=false",
		"CDNCA_NATIVE_UPGRADE_STATUS_FILE=/does/not/exist", "CONTROL_UPGRADE_PLAN_WRITER_ENABLED=true"})
	if err != nil || disabled.Enabled {
		t.Fatalf("disabled mode interfered with HA=%+v err=%v", disabled, err)
	}
}

func TestNativeControlUpgradeBootstrapUsesFormalSchemaAndMissingRunnerFailsClosed(t *testing.T) {
	originalVersion := controlVersion
	controlVersion = "1.1.0"
	t.Cleanup(func() { controlVersion = originalVersion })
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
	configuration := config.Config{ControlVersion: controlVersion, ControlInstallationID: uuid.NewString()}
	database := &ops06PlanRuntimeDatabase{schemaReady: true}
	runtime, err := openControlPlaneUpgradeRuntimeWithDatabase(configuration, &identity.Service{}, &entitlementguard.TrustStore{}, database)
	if err != nil || runtime == nil || database.schemaSQL == "" {
		t.Fatalf("native schema/bootstrap runtime=%v err=%v", runtime, err)
	}
	status := runtime.MaintenanceRuntimeStatus(t.Context())
	if status.Ready || status.Reason != "control_upgrade_runner_unconfirmed" {
		t.Fatalf("missing root runner claimed ready: %+v", status)
	}
	for _, unavailable := range []*ops06PlanRuntimeDatabase{nil, {schemaReady: false}} {
		if _, err := openControlPlaneUpgradeRuntimeWithDatabase(configuration, &identity.Service{}, &entitlementguard.TrustStore{}, unavailable); err == nil {
			t.Fatal("native boot accepted an unavailable formal repository")
		}
	}
	t.Setenv("CDNCA_NATIVE_UPGRADE_ENABLED", "false")
	runtime, err = openControlPlaneUpgradeRuntimeWithDatabase(configuration, nil, nil, nil)
	if err != nil || runtime != nil {
		t.Fatalf("disabled runtime retained a typed nil: runtime=%v err=%v", runtime, err)
	}
}
