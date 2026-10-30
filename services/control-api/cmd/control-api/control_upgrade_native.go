package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgradehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type controlPlaneUpgradeHTTPRuntime interface {
	Handler() http.Handler
	Gate(http.Handler) http.Handler
	MaintenanceRuntimeStatus(context.Context) controlupgrade.MaintenanceRuntimeState
}

type nativeControlUpgradeConfig struct {
	Enabled                                bool
	StatusFile, StateFile, MaintenanceFile string
}

var nativeCompiledVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// Preserve the original configured version for maintenance diagnostics. Native
// upgrades replace immutable binaries, not the operator-owned environment file.
func controlPlaneUpgradeEffectiveConfig(cfg config.Config) (config.Config, error) {
	native, err := loadNativeControlUpgradeConfigFromEnv(os.Environ())
	if err != nil {
		return config.Config{}, err
	}
	if native.Enabled {
		if !nativeCompiledVersionPattern.MatchString(controlVersion) {
			return config.Config{}, controlplaneupgrade.ErrInvalidConfig
		}
		cfg.ControlVersion = controlVersion
	}
	return cfg, nil
}

func loadNativeControlUpgradeConfigFromEnv(environment []string) (nativeControlUpgradeConfig, error) {
	values, err := runtimeEnvEntries(environment, "CDNCA_NATIVE_UPGRADE_", map[string]struct{}{
		"CDNCA_NATIVE_UPGRADE_ENABLED": {}, "CDNCA_NATIVE_UPGRADE_STATUS_FILE": {},
		"CDNCA_NATIVE_UPGRADE_STATE_FILE": {}, "CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE": {},
	})
	if err != nil {
		return nativeControlUpgradeConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, "CDNCA_NATIVE_UPGRADE_ENABLED")
	if err != nil || !enabled {
		return nativeControlUpgradeConfig{}, err
	}
	shared := make(map[string]string)
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		switch name {
		case "CONTROL_UPGRADE_PLAN_WRITER_ENABLED", "CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED",
			"CONTROL_UPGRADE_EXPECTED_REPLICAS", "CONTROL_UPGRADE_QUORUM":
			if _, duplicate := shared[name]; duplicate || !found {
				return nativeControlUpgradeConfig{}, controlplaneupgrade.ErrInvalidConfig
			}
			shared[name] = value
		}
	}
	if writer := shared["CONTROL_UPGRADE_PLAN_WRITER_ENABLED"]; writer != "" && writer != "false" {
		return nativeControlUpgradeConfig{}, controlplaneupgrade.ErrInvalidConfig
	}
	if shared["CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED"] != "true" ||
		shared["CONTROL_UPGRADE_EXPECTED_REPLICAS"] != "" || shared["CONTROL_UPGRADE_QUORUM"] != "" {
		return nativeControlUpgradeConfig{}, controlplaneupgrade.ErrInvalidConfig
	}
	result := nativeControlUpgradeConfig{Enabled: true,
		StatusFile: values["CDNCA_NATIVE_UPGRADE_STATUS_FILE"], StateFile: values["CDNCA_NATIVE_UPGRADE_STATE_FILE"],
		MaintenanceFile: values["CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE"]}
	for _, filename := range []string{result.StatusFile, result.StateFile, result.MaintenanceFile} {
		if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
			return nativeControlUpgradeConfig{}, controlplaneupgrade.ErrInvalidConfig
		}
	}
	if result.StateFile != result.StatusFile+".state.json" || result.StatusFile == result.MaintenanceFile || result.StateFile == result.MaintenanceFile {
		return nativeControlUpgradeConfig{}, controlplaneupgrade.ErrInvalidConfig
	}
	return result, nil
}

func openControlPlaneUpgradeRuntimeWithDatabase(cfg config.Config, identityService *identity.Service,
	trust *entitlementguard.TrustStore, database controlUpgradePlanRuntimeDatabase) (controlPlaneUpgradeHTTPRuntime, error) {
	native, err := loadNativeControlUpgradeConfigFromEnv(os.Environ())
	if err != nil {
		return nil, err
	}
	if !native.Enabled {
		handler, err := openControlPlaneUpgradeHTTPRuntimeWithDatabase(cfg, identityService, trust, database)
		if err != nil || handler == nil {
			return nil, err
		}
		return handler, nil
	}
	if identityService == nil || trust == nil {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	effective, err := controlPlaneUpgradeEffectiveConfig(cfg)
	if err != nil {
		return nil, err
	}
	protocol, err := positiveEnvironmentInt("CONTROL_UPGRADE_PROTOCOL_VERSION")
	if err != nil {
		return nil, err
	}
	planSource, err := loadControlUpgradePlanRuntimeConfig(cfg.ControlInstallationID)
	if err != nil || !planSource.Enabled {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlUpgradePlanReadyTimeout)
	defer cancel()
	if err := requireControlUpgradePlanSchema(ctx, database); err != nil {
		return nil, err
	}
	repository, err := controlplaneupgrade.NewPostgresSecretRepository(database, cfg.ControlInstallationID,
		controlplaneupgrade.SystemdControlUpgradeOperation)
	if err != nil {
		return nil, err
	}
	authenticate := func(request *http.Request) (identity.AuthenticatedSession, error) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}
		scheme, raw, found := strings.Cut(strings.TrimSpace(values[0]), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(raw) == "" {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}
		return identityService.AuthenticateSession(request.Context(), strings.TrimSpace(raw))
	}
	license, err := nativeControlUpgradeLicenseClient(cfg)
	if err != nil {
		return nil, err
	}
	return controlplaneupgradehttp.NewNative(controlplaneupgradehttp.NativeDependencies{
		AuthenticateSession: authenticate, Repository: repository, Trust: trust,
		InstallationID: cfg.ControlInstallationID, CurrentVersion: effective.ControlVersion, ProtocolVersion: protocol,
		StatusFile: native.StatusFile, StateFile: native.StateFile, MaintenanceFile: native.MaintenanceFile, Now: time.Now,
		License: license,
	})
}

// nativeControlUpgradeLicenseClient lets "升级主控" fetch its signed plan from
// the license service with this installation's key. Without a license service
// the /issue endpoint stays 503 and manual upload remains the only path.
func nativeControlUpgradeLicenseClient(cfg config.Config) (*controlupgrade.LicenseClient, error) {
	if cfg.LicenseServiceURL == "" || cfg.ControlInstallationKeyFile == "" {
		return nil, nil
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID.String() != cfg.ControlInstallationID {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	key, err := controlUpgradeLoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return controlupgrade.NewLicenseClient(cfg.LicenseServiceURL, &http.Client{Timeout: 30 * time.Second},
		installationID, key, time.Now)
}
