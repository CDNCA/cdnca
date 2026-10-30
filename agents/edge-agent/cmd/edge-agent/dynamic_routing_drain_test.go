package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
)

const (
	drainScope    = "0d13b000-0000-4000-8000-000000000001"
	drainScopeTwo = "0d13b000-0000-4000-8000-000000000002"
)

func drainTestManager(t *testing.T, remaining *int) (*dynamicRoutingManager, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	manager := &dynamicRoutingManager{root: t.TempDir(), now: func() time.Time { return now },
		remaining: func(old []string) int { return min(*remaining, len(old)) }}
	return manager, &now
}

func seedDrainScope(t *testing.T, manager *dynamicRoutingManager, scopeID, deploymentID string, oldWorkers []string) {
	t.Helper()
	at := manager.now()
	scope := dynamicRoutingScope{
		Previous: &dynamicRoutingRelease{ConfigVersionID: "v-old", RootSHA256: strings.Repeat("a", 64)},
		Current:  &dynamicRoutingRelease{ConfigVersionID: "v-new", RootSHA256: strings.Repeat("b", 64), OldWorkers: oldWorkers},
	}
	scope.record(deploymentID, gatewayclient.DynamicRoutingResult(deploymentID, 1, deployment.ActionApply, "v-new", at, at, nil))
	if err := manager.save(scopeID, scope); err != nil {
		t.Fatal(err)
	}
}

func drainRequest(deploymentID string, now time.Time) deployment.DrainRequest {
	return deployment.DrainRequest{DeploymentID: deploymentID, Revision: 1, Digest: strings.Repeat("c", 64),
		OldVersionID: "v-old", NewVersionID: "v-new", MaxDrain: time.Minute, CommandDeadline: now.Add(2 * time.Minute)}
}

func TestDynamicRoutingDrainWaitsForReplacedWorkers(t *testing.T) {
	remaining := 2
	manager, now := drainTestManager(t, &remaining)
	seedDrainScope(t, manager, drainScope, "d-reload", []string{"101", "102"})
	request := drainRequest("d-reload", *now)
	result, err := manager.ProcessDrain(context.Background(), request)
	if !errors.Is(err, deployment.ErrDrainInProgress) || result.Phase != deployment.DrainPhaseDrainingOld || result.RemainingOldWorkers != 2 {
		t.Fatalf("draining: %+v %v", result, err)
	}
	// the record survives a restart (new manager over the same journal)
	restarted := &dynamicRoutingManager{root: manager.root, now: manager.now, remaining: manager.remaining}
	remaining = 0
	result, err = restarted.ProcessDrain(context.Background(), request)
	if err != nil || result.Phase != deployment.DrainPhaseCompleted || len(result.Transitions) != 3 {
		t.Fatalf("completed: %+v %v", result, err)
	}
	again, err := restarted.ProcessDrain(context.Background(), request)
	if err != nil || again.Phase != deployment.DrainPhaseCompleted || len(again.Transitions) != 3 {
		t.Fatalf("redelivery: %+v %v", again, err)
	}
	changed := request
	changed.Revision = 2
	if _, err := restarted.ProcessDrain(context.Background(), changed); !errors.Is(err, deployment.ErrConflict) {
		t.Fatalf("changed plan: %v", err)
	}
}

func TestDynamicRoutingDrainWithoutReloadCompletesAndDeadlineFails(t *testing.T) {
	remaining := 0
	manager, now := drainTestManager(t, &remaining)
	seedDrainScope(t, manager, drainScope, "d-index", nil)
	result, err := manager.ProcessDrain(context.Background(), drainRequest("d-index", *now))
	if err != nil || result.Phase != deployment.DrainPhaseCompleted || result.RemainingOldWorkers != 0 {
		t.Fatalf("index-only activation: %+v %v", result, err)
	}
	remaining = 1
	seedDrainScope(t, manager, drainScopeTwo, "d-stuck", []string{"201"})
	request := drainRequest("d-stuck", *now)
	if _, err := manager.ProcessDrain(context.Background(), request); !errors.Is(err, deployment.ErrDrainInProgress) {
		t.Fatalf("stuck start: %v", err)
	}
	*now = now.Add(2 * time.Minute)
	result, err = manager.ProcessDrain(context.Background(), request)
	if !errors.Is(err, deployment.ErrDrainDeadline) || result.Phase != deployment.DrainPhaseFailed ||
		result.Transitions[len(result.Transitions)-1].ErrorCode != "DRAIN_DEADLINE_EXCEEDED" {
		t.Fatalf("deadline: %+v %v", result, err)
	}
	if _, err := manager.ProcessDrain(context.Background(), drainRequest("d-unknown", *now)); !errors.Is(err, deployment.ErrDrainNotReady) {
		t.Fatalf("unknown deployment: %v", err)
	}
	wrong := drainRequest("d-index", *now)
	wrong.OldVersionID = "v-other"
	if _, err := manager.ProcessDrain(context.Background(), wrong); !errors.Is(err, deployment.ErrDrainNotReady) {
		t.Fatalf("plan for other versions: %v", err)
	}
}

func TestDynamicRoutingNodePointersForUpgradeReceipt(t *testing.T) {
	remaining := 0
	manager, _ := drainTestManager(t, &remaining)
	if pointers, err := manager.NodePointers(); err != nil || pointers.CurrentDigest != "" {
		t.Fatalf("empty node: %+v %v", pointers, err)
	}
	seedDrainScope(t, manager, drainScope, "d1", nil)
	one, err := manager.NodePointers()
	if err != nil || one.CurrentDigest != strings.Repeat("b", 64) || one.PreviousDigest != strings.Repeat("a", 64) {
		t.Fatalf("one scope: %+v %v", one, err)
	}
	seedDrainScope(t, manager, drainScopeTwo, "d2", nil)
	two, err := manager.NodePointers()
	if err != nil || len(two.CurrentDigest) != 64 || len(two.PreviousDigest) != 64 || two.CurrentDigest == two.PreviousDigest ||
		two.CurrentDigest == one.CurrentDigest {
		t.Fatalf("two scopes: %+v %v", two, err)
	}
	probe := upgradeReceiptProbe{deployment: nodePointers{manager}}
	if pointers, err := probe.deployment.Pointers(); err != nil || pointers != two {
		t.Fatalf("receipt pointers: %+v %v", pointers, err)
	}
}
