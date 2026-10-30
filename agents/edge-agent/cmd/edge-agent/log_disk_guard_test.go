package main

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/logdiskguard"
)

type fakeLogDiskGuardRunner struct {
	started chan struct{}
	stopped chan struct{}
	once    sync.Once
	metrics logdiskguard.Metrics
}

func (runner *fakeLogDiskGuardRunner) Run(ctx context.Context) error {
	runner.once.Do(func() { close(runner.started) })
	<-ctx.Done()
	close(runner.stopped)
	return ctx.Err()
}

func (runner *fakeLogDiskGuardRunner) Snapshot() logdiskguard.Metrics {
	return runner.metrics
}

func TestLogDiskGuardConfigUsesTelemetrySpoolAndBoundedDefaults(t *testing.T) {
	config := validFileConfig()
	config.DiskGuard.Enabled = true
	config.DiskGuard.MinimumFreeBytes = 256 << 20
	config.DiskGuard.MaxRoundDuration = "750ms"
	config.Telemetry.Enabled = true
	config.Telemetry.SpoolRoot = filepath.Join(secureConfigTempDir(t), "event-spool")

	guardConfig, err := config.logDiskGuardConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !guardConfig.Enabled || guardConfig.SpoolRoot != config.Telemetry.SpoolRoot ||
		guardConfig.MinimumFreeBytes != 256<<20 || guardConfig.MaxRoundDuration != 750*time.Millisecond ||
		guardConfig.DryRun != config.DiskGuard.DryRun {
		t.Fatalf("log disk guard config = %+v", guardConfig)
	}
	if guardConfig.StateRoot != filepath.Join(filepath.Dir(config.DiskGuard.LockPath), "log-disk-guard") {
		t.Fatalf("state root = %q", guardConfig.StateRoot)
	}

	config.Telemetry.Enabled = false
	disabled, err := config.logDiskGuardConfig()
	if err != nil || disabled.Enabled {
		t.Fatalf("disabled config = %+v, %v", disabled, err)
	}
}

func TestLogDiskGuardConfigRejectsUnsafeBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*diskGuardSettings)
	}{
		{name: "minimum free", mutate: func(value *diskGuardSettings) { value.MinimumFreeBytes = 0 }},
		{name: "round duration short", mutate: func(value *diskGuardSettings) { value.MaxRoundDuration = "0s" }},
		{name: "round duration long", mutate: func(value *diskGuardSettings) { value.MaxRoundDuration = "2m" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validFileConfig()
			config.DiskGuard.Enabled = true
			config.Telemetry.Enabled = true
			test.mutate(&config.DiskGuard)
			if _, err := config.logDiskGuardConfig(); err == nil {
				t.Fatal("logDiskGuardConfig() accepted unsafe bounds")
			}
		})
	}
}

func TestDaemonRunsAndStopsLogDiskGuardWithGateway(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	guard := &fakeLogDiskGuardRunner{
		started: make(chan struct{}), stopped: make(chan struct{}),
		metrics: logdiskguard.Metrics{ReasonCode: logdiskguard.ReasonHealthy},
	}
	daemon := &daemonClient{client: client, logDiskGuard: guard}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway start")
	waitChannel(t, guard.started, "log disk guard start")
	if snapshot := daemon.LogDiskGuardSnapshot(); !snapshot.Enabled || !snapshot.Running || snapshot.RunFailed || snapshot.Metrics.ReasonCode != logdiskguard.ReasonHealthy {
		t.Fatalf("running snapshot = %+v", snapshot)
	}
	cancel()
	waitChannel(t, guard.stopped, "log disk guard stop")
	if err := <-done; err != context.Canceled {
		t.Fatalf("daemon Run() error = %v", err)
	}
	if snapshot := daemon.LogDiskGuardSnapshot(); snapshot.Running || snapshot.RunFailed {
		t.Fatalf("stopped snapshot = %+v", snapshot)
	}
}
