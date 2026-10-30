package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRealtimeCoverageRuntimeConfig(t *testing.T) {
	if config, err := loadRealtimeCoverageRuntimeConfigFromEnv(nil); err != nil || config.Enabled {
		t.Fatalf("disabled config=%#v error=%v", config, err)
	}
	config, err := loadRealtimeCoverageRuntimeConfigFromEnv([]string{
		realtimeCoverageRuntimeEnabledEnv + "=true",
		realtimeCoverageRuntimePollIntervalEnv + "=15s",
		realtimeCoverageRuntimeGraceEnv + "=3m",
		realtimeCoverageRuntimeMaxWindowsEnv + "=125",
	})
	if err != nil || !config.Enabled || config.PollInterval != 15*time.Second ||
		config.FinalizationGrace != 3*time.Minute || config.MaximumWindows != 125 || config.RetryInterval != 5*time.Second {
		t.Fatalf("enabled config=%#v error=%v", config, err)
	}
	for _, test := range []struct {
		name        string
		environment []string
		want        string
	}{
		{name: "invalid bool", environment: []string{realtimeCoverageRuntimeEnabledEnv + "=1"}, want: realtimeCoverageRuntimeEnabledEnv},
		{name: "unknown", environment: []string{realtimeCoverageRuntimePrefix + "UNKNOWN=1"}, want: "UNKNOWN"},
		{name: "duplicate", environment: []string{realtimeCoverageRuntimeEnabledEnv + "=true", realtimeCoverageRuntimeEnabledEnv + "=true"}, want: "at most once"},
		{name: "short poll", environment: []string{realtimeCoverageRuntimeEnabledEnv + "=true", realtimeCoverageRuntimePollIntervalEnv + "=1ms"}, want: realtimeCoverageRuntimePollIntervalEnv},
		{name: "long grace", environment: []string{realtimeCoverageRuntimeEnabledEnv + "=true", realtimeCoverageRuntimeGraceEnv + "=2h"}, want: realtimeCoverageRuntimeGraceEnv},
		{name: "windows", environment: []string{realtimeCoverageRuntimeEnabledEnv + "=true", realtimeCoverageRuntimeMaxWindowsEnv + "=1001"}, want: realtimeCoverageRuntimeMaxWindowsEnv},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadRealtimeCoverageRuntimeConfigFromEnv(test.environment)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("config error=%v", err)
			}
		})
	}
}

func TestBuildRealtimeCoverageProductionRuntime(t *testing.T) {
	if runtime, err := buildRealtimeCoverageProductionRuntime(realtimeCoverageRuntimeConfig{}, nil, nil, nil); err != nil || runtime != nil {
		t.Fatalf("disabled runtime=(%v,%v)", runtime, err)
	}
	config := realtimeCoverageRuntimeConfig{
		Enabled: true, PollInterval: time.Second, FinalizationGrace: 2 * time.Minute, MaximumWindows: 10, RetryInterval: time.Second,
	}
	if runtime, err := buildRealtimeCoverageProductionRuntime(config, nil, nil, slog.Default()); err == nil || runtime != nil {
		t.Fatalf("missing dependency runtime=(%v,%v)", runtime, err)
	}
	poolConfig, err := pgxpool.ParseConfig("postgres://realtime-coverage-runtime.invalid/control")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	queryRuntime, err := openAnalyticsQueryStore(validAnalyticsQueryConfig(), inertAnalyticsHTTPClient{})
	if err != nil {
		t.Fatal(err)
	}
	defer queryRuntime.Close()
	runtime, err := buildRealtimeCoverageProductionRuntime(config, pool, queryRuntime, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || runtime == nil || runtime.core == nil {
		t.Fatalf("configured runtime=(%v,%v)", runtime, err)
	}
}

type retryingRealtimeCoverageCore struct {
	calls   atomic.Int32
	reached chan struct{}
	once    sync.Once
}

func (core *retryingRealtimeCoverageCore) Run(ctx context.Context) error {
	if core.calls.Add(1) < 3 {
		return analytics.ErrRealtimeCoverageUnavailable
	}
	core.once.Do(func() { close(core.reached) })
	<-ctx.Done()
	return ctx.Err()
}

func TestRealtimeCoverageProductionRuntimeRetriesWithoutBecomingTerminal(t *testing.T) {
	core := &retryingRealtimeCoverageCore{reached: make(chan struct{})}
	runtime, err := newRealtimeCoverageProductionRuntime(
		core, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-core.reached:
	case err := <-done:
		t.Fatalf("dependency failure became terminal: %v", err)
	case <-time.After(time.Second):
		t.Fatal("runtime did not retry dependency failures")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop after cancellation")
	}
	if core.calls.Load() < 3 {
		t.Fatalf("runtime calls=%d", core.calls.Load())
	}
	if runtime, err := newRealtimeCoverageProductionRuntime(nil, time.Second, slog.Default()); !errors.Is(err, errRealtimeCoverageRuntimeInvalid) || runtime != nil {
		t.Fatalf("invalid runtime=(%v,%v)", runtime, err)
	}
}
