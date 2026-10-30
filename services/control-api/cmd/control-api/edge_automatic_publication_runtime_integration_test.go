//go:build integration

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
)

func TestEdgeAutomaticPublicationProductionRuntimeReadinessAndShutdown(t *testing.T) {
	pool, _ := edgePublishProductionPGPool(t, &edgePublishProductionPGQueryTrace{})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config, err := loadEdgeAutomaticPublicationRuntimeConfigFromEnv([]string{
		edgeAutomaticPublicationEnabledEnv + "=true",
		edgeAutomaticPublicationWorkerIDEnv + "=automatic-publication-integration",
		edgeAutomaticPublicationPollIntervalEnv + "=10ms",
		edgeAutomaticPublicationErrorBackoffEnv + "=10ms",
		edgeAutomaticPublicationOperationTimeoutEnv + "=1s",
		edgeAutomaticPublicationLeaseDurationEnv + "=2s",
		edgeAutomaticPublicationRetryDelayEnv + "=10ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := openEdgeAutomaticPublicationProductionRuntime(config,
		edgeAutomaticPublicationRuntimeDependencies{
			Pool:        pool,
			Signer:      &edgePublishRuntimeTestSigner{public: publicKey, private: privateKey},
			Entitlement: &edgePublishRuntimeTestEntitlement{},
			Resolver:    edgepublish.NewSnapshotTargetResolver(),
			Clock:       time.Now,
		})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(t.Context()) }()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.Ready() != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("production runtime never became ready: %v", err)
	}
	closeContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run() after Close()=%v", err)
	}
	if err := runtime.Close(closeContext); err != nil {
		t.Fatalf("second Close()=%v", err)
	}
	if !errors.Is(runtime.Ready(), edgeautopublish.ErrRuntimeClosed) {
		t.Fatalf("closed runtime readiness=%v", runtime.Ready())
	}
}
