package config

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSITE14StatusRecoveryConfigurationDefaultsDisabledAndFailsClosed(t *testing.T) {
	setRequiredConfig(t)
	clearSITE14StatusRecoveryEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SiteStatusRecoveryEnabled || cfg.SiteStatusRecoveryTenantID != uuid.Nil ||
		cfg.SiteStatusRecoveryWorkerID != "" || cfg.SiteStatusRecoveryLeaseDuration != 0 {
		t.Fatalf("disabled config=%+v", cfg)
	}

	setRequiredConfig(t)
	clearSITE14StatusRecoveryEnvironment(t)
	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_WORKER_ID", "stale-worker")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "must be absent") {
		t.Fatalf("disabled stale configuration error=%v", err)
	}
}

func TestSITE14StatusRecoveryConfigurationRequiresIdentityAndBoundsDurations(t *testing.T) {
	setRequiredConfig(t)
	clearSITE14StatusRecoveryEnvironment(t)
	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_ENABLED", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TENANT_ID") {
		t.Fatalf("missing tenant error=%v", err)
	}

	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_TENANT_ID", "018f47a2-5b9c-7d31-8a60-104c9c0b7401")
	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_WORKER_ID", "site-status-recovery-main")
	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_LEASE_DURATION", "30s")
	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_POLL_INTERVAL", "1s")
	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_OPERATION_TIMEOUT", "5s")
	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_REPORT_TIMEOUT", "2s")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SiteStatusRecoveryEnabled || cfg.SiteStatusRecoveryBatchSize != 8 ||
		cfg.SiteStatusRecoveryLeaseDuration != 30*time.Second ||
		cfg.SiteStatusRecoveryPollInterval != time.Second ||
		cfg.SiteStatusRecoveryOperationTimeout != 5*time.Second ||
		cfg.SiteStatusRecoveryReportTimeout != 2*time.Second {
		t.Fatalf("loaded config=%+v", cfg)
	}

	t.Setenv("SITE_STATUS_RECOVERY_RUNTIME_REPORT_TIMEOUT", "6s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "limits or durations") {
		t.Fatalf("unsafe report timeout error=%v", err)
	}
}

func clearSITE14StatusRecoveryEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"SITE_STATUS_RECOVERY_RUNTIME_ENABLED",
		"SITE_STATUS_RECOVERY_RUNTIME_TENANT_ID",
		"SITE_STATUS_RECOVERY_RUNTIME_WORKER_ID",
		"SITE_STATUS_RECOVERY_RUNTIME_BATCH_SIZE",
		"SITE_STATUS_RECOVERY_RUNTIME_LEASE_DURATION",
		"SITE_STATUS_RECOVERY_RUNTIME_POLL_INTERVAL",
		"SITE_STATUS_RECOVERY_RUNTIME_OPERATION_TIMEOUT",
		"SITE_STATUS_RECOVERY_RUNTIME_REPORT_TIMEOUT",
	} {
		t.Setenv(name, "")
	}
}
