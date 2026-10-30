package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
)

func TestEdgeAutomaticPublicationRuntimeConfigurationIsStrict(t *testing.T) {
	valid := edgeAutomaticPublicationRuntimeEnvironment()
	config, err := loadEdgeAutomaticPublicationRuntimeConfigFromEnv(valid)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.Worker.WorkerID != "automatic-publication-worker-a" ||
		config.Worker.LeaseDuration != time.Minute || config.Worker.RetryDelay != 5*time.Second ||
		config.Runtime.PollInterval != 250*time.Millisecond || config.Runtime.ErrorBackoff != time.Second ||
		config.Runtime.OperationTimeout != 30*time.Second {
		t.Fatalf("automatic publication config=%+v", config)
	}

	for _, test := range []struct {
		name        string
		environment []string
	}{
		{name: "absent is disabled"},
		{name: "explicit disabled", environment: []string{edgeAutomaticPublicationEnabledEnv + "=false"}},
		{name: "disabled with settings", environment: []string{edgeAutomaticPublicationEnabledEnv + "=false", edgeAutomaticPublicationPollIntervalEnv + "=1s"}},
		{name: "unknown", environment: append(append([]string(nil), valid...), "EDGE_AUTOMATIC_PUBLICATION_UNKNOWN=1")},
		{name: "duplicate", environment: append(append([]string(nil), valid...), edgeAutomaticPublicationEnabledEnv+"=true")},
		{name: "missing", environment: edgeAutomaticPublicationRuntimeWithout(edgeAutomaticPublicationLeaseDurationEnv)},
		{name: "worker whitespace", environment: edgeAutomaticPublicationRuntimeReplace(edgeAutomaticPublicationWorkerIDEnv, "worker a")},
		{name: "bad duration", environment: edgeAutomaticPublicationRuntimeReplace(edgeAutomaticPublicationPollIntervalEnv, "soon")},
		{name: "lease not beyond operation", environment: edgeAutomaticPublicationRuntimeReplace(edgeAutomaticPublicationLeaseDurationEnv, "30s")},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, loadErr := loadEdgeAutomaticPublicationRuntimeConfigFromEnv(test.environment)
			wantDisabled := test.name == "absent is disabled" || test.name == "explicit disabled"
			if wantDisabled {
				if loadErr != nil || got.Enabled {
					t.Fatalf("disabled config=%+v err=%v", got, loadErr)
				}
				return
			}
			if loadErr == nil || got.Enabled {
				t.Fatalf("invalid config=%+v err=%v", got, loadErr)
			}
		})
	}
}

func TestEdgeAutomaticPublicationRuntimeCompositionAndCloseAreFailClosed(t *testing.T) {
	disabled, err := openEdgeAutomaticPublicationProductionRuntime(
		edgeAutomaticPublicationRuntimeConfig{}, edgeAutomaticPublicationRuntimeDependencies{},
	)
	if err != nil || disabled != nil {
		t.Fatalf("disabled runtime=%v err=%v", disabled, err)
	}

	config, err := loadEdgeAutomaticPublicationRuntimeConfigFromEnv(edgeAutomaticPublicationRuntimeEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEdgeAutomaticPublicationShutdownPeriod(29*time.Second, config); err == nil {
		t.Fatal("shutdown shorter than operation timeout was accepted")
	}
	if err := validateEdgeAutomaticPublicationShutdownPeriod(30*time.Second, config); err != nil {
		t.Fatal(err)
	}
	if runtime, openErr := openEdgeAutomaticPublicationProductionRuntime(
		config, edgeAutomaticPublicationRuntimeDependencies{},
	); openErr == nil || runtime != nil || !strings.Contains(openErr.Error(), "production dependencies") {
		t.Fatalf("missing dependency runtime=%v err=%v", runtime, openErr)
	}

	dependencies := edgePublishRuntimeValidDependencies(t)
	runtime, err := openEdgeAutomaticPublicationProductionRuntime(config,
		edgeAutomaticPublicationRuntimeDependencies{
			Pool: dependencies.Pool, Signer: dependencies.Signer,
			Entitlement: dependencies.Entitlement, Resolver: dependencies.Resolver,
			Clock: time.Now,
		})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(runtime.Ready(), edgeautopublish.ErrRuntimeNotReady) {
		t.Fatalf("runtime readiness before start=%v", runtime.Ready())
	}
	if err := runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close()=%v", err)
	}
	if !errors.Is(runtime.Ready(), edgeautopublish.ErrRuntimeClosed) {
		t.Fatalf("runtime readiness after close=%v", runtime.Ready())
	}
}

func edgeAutomaticPublicationRuntimeEnvironment() []string {
	return []string{
		edgeAutomaticPublicationEnabledEnv + "=true",
		edgeAutomaticPublicationWorkerIDEnv + "=automatic-publication-worker-a",
		edgeAutomaticPublicationPollIntervalEnv + "=250ms",
		edgeAutomaticPublicationErrorBackoffEnv + "=1s",
		edgeAutomaticPublicationOperationTimeoutEnv + "=30s",
		edgeAutomaticPublicationLeaseDurationEnv + "=1m",
		edgeAutomaticPublicationRetryDelayEnv + "=5s",
	}
}

func edgeAutomaticPublicationRuntimeWithout(name string) []string {
	result := make([]string, 0, len(edgeAutomaticPublicationRuntimeEnvironment()))
	for _, entry := range edgeAutomaticPublicationRuntimeEnvironment() {
		if !strings.HasPrefix(entry, name+"=") {
			result = append(result, entry)
		}
	}
	return result
}

func edgeAutomaticPublicationRuntimeReplace(name, value string) []string {
	return append(edgeAutomaticPublicationRuntimeWithout(name), name+"="+value)
}
