package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/sitestatusrecovery"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSITE14OpenStatusRecoveryRuntimeComposition(t *testing.T) {
	if runtime, err := openSiteStatusRecoveryRuntime(siteStatusRecoveryRuntimeConfig{}, siteStatusRecoveryRuntimeDependencies{}); err != nil || runtime != nil {
		t.Fatalf("disabled runtime=%v err=%v", runtime, err)
	}
	config := siteStatusRecoveryRuntimeConfig{Enabled: true, Runtime: sitestatusrecovery.RuntimeConfig{
		TenantID: uuid.New(), WorkerID: "site-status-recovery-composition", BatchSize: 4,
		LeaseDuration: time.Minute, PollInterval: time.Second,
		OperationTimeout: 2 * time.Second, ReportTimeout: time.Second,
	}}
	if _, err := openSiteStatusRecoveryRuntime(config, siteStatusRecoveryRuntimeDependencies{}); err == nil {
		t.Fatal("enabled runtime accepted missing pool")
	}
	pool, err := pgxpool.New(t.Context(), "postgres://cdnca:unused@127.0.0.1:1/cdnca?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	runtime, err := openSiteStatusRecoveryRuntime(config, siteStatusRecoveryRuntimeDependencies{Pool: pool, Clock: time.Now})
	if err != nil || runtime == nil || runtime.core == nil {
		t.Fatalf("runtime=%v err=%v", runtime, err)
	}
	closeCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := runtime.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
}

func TestSITE14StatusRecoveryRuntimeControlConfigMappingFailsClosed(t *testing.T) {
	if runtimeConfig, err := siteStatusRecoveryRuntimeConfigFromControlConfig(config.Config{}); err != nil || runtimeConfig.Enabled {
		t.Fatalf("disabled config=%+v err=%v", runtimeConfig, err)
	}
	if _, err := siteStatusRecoveryRuntimeConfigFromControlConfig(config.Config{
		SiteStatusRecoveryWorkerID: "stale",
	}); err == nil {
		t.Fatal("disabled non-empty configuration accepted")
	}
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7411")
	source := config.Config{
		SiteStatusRecoveryEnabled: true, SiteStatusRecoveryTenantID: tenantID,
		SiteStatusRecoveryWorkerID: "site-status-recovery-main", SiteStatusRecoveryBatchSize: 8,
		SiteStatusRecoveryLeaseDuration: time.Minute, SiteStatusRecoveryPollInterval: time.Second,
		SiteStatusRecoveryOperationTimeout: 5 * time.Second, SiteStatusRecoveryReportTimeout: 2 * time.Second,
		ShutdownPeriod: 10 * time.Second,
	}
	mapped, err := siteStatusRecoveryRuntimeConfigFromControlConfig(source)
	if err != nil || !mapped.Enabled || mapped.Runtime.TenantID != tenantID ||
		mapped.Runtime.WorkerID != source.SiteStatusRecoveryWorkerID || mapped.Runtime.BatchSize != 8 {
		t.Fatalf("mapped config=%+v err=%v", mapped, err)
	}
	source.ShutdownPeriod = time.Second
	if _, err := siteStatusRecoveryRuntimeConfigFromControlConfig(source); err == nil {
		t.Fatal("operation timeout beyond shutdown accepted")
	}
}

func TestSITE14StatusRecoveryRuntimeMainLifecycleComposition(t *testing.T) {
	content, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	fragments := []string{
		"siteStatusRecoveryRuntimeConfigFromControlConfig(cfg)",
		"openSiteStatusRecoveryRuntime(",
		"readinessProbes = append(readinessProbes, siteStatusRecoveryRuntime)",
		"err := siteStatusRecoveryRuntime.Run(ctx)",
		"runtimeStageError{stage: \"site status recovery runtime stopped\", err: err}",
		"siteStatusRecoveryRuntime.Close(shutdownCtx)",
		"siteStatusRecoveryRuntimeClosed = true",
	}
	for _, fragment := range fragments {
		if !strings.Contains(source, fragment) {
			t.Fatalf("main composition missing %q", fragment)
		}
	}
	backgroundDone := strings.Index(source, "case <-backgroundDone:")
	orderedClose := strings.Index(source, "siteStatusRecoveryRuntime.Close(shutdownCtx)")
	if backgroundDone < 0 || orderedClose < backgroundDone {
		t.Fatalf("status recovery close is not ordered after background completion: %d/%d", backgroundDone, orderedClose)
	}
}
