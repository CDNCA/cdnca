package controlupgrade

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func planArtifactsFor(state PlanState, forward, rollback byte, platform, architecture string) planArtifacts {
	plan := planArtifacts{State: state, SHA256Digest: planDigest(forward), RollbackSHA256Digest: planDigest(rollback)}
	plan.ForwardProfile.Platform, plan.ForwardProfile.Architecture = platform, architecture
	return plan
}

func artifactName(fill byte) string { return hex.EncodeToString(bytes.Repeat([]byte{fill}, 32)) }

// Plans newest first: unfinished plans keep both artifacts; per cohort only the
// newest finished plan keeps its current (forward) and previous (rollback).
func TestRetainedArtifactNamesKeepsUnfinishedAndCurrentPlusPrevious(t *testing.T) {
	keep := retainedArtifactNames([]planArtifacts{
		planArtifactsFor(PlanRunning, 0x05, 0x04, "linux", "amd64"),
		planArtifactsFor(PlanCompleted, 0x04, 0x03, "linux", "amd64"),
		planArtifactsFor(PlanFailed, 0x03, 0x02, "linux", "amd64"),
		planArtifactsFor(PlanCompleted, 0x02, 0x01, "linux", "amd64"),
		planArtifactsFor(PlanCompleted, 0x12, 0x11, "linux", "arm64"),
		planArtifactsFor(PlanPaused, 0x21, 0x20, "linux", "arm64"),
	})
	for _, fill := range []byte{0x05, 0x04, 0x03, 0x12, 0x11, 0x21, 0x20} {
		if !keep[artifactName(fill)] {
			t.Errorf("artifact %#x not retained", fill)
		}
	}
	for _, fill := range []byte{0x02, 0x01} {
		if keep[artifactName(fill)] {
			t.Errorf("artifact %#x retained, want pruned", fill)
		}
	}
}

// The stored snapshot is json.Marshal(RolloutPlan); the narrow view must read it.
func TestPlanArtifactsDecodesRolloutPlanSnapshot(t *testing.T) {
	plan := mustRolloutPlan(t)
	snapshot, err := encodeRolloutValue(plan)
	if err != nil {
		t.Fatal(err)
	}
	var view planArtifacts
	if err := json.Unmarshal(snapshot, &view); err != nil {
		t.Fatal(err)
	}
	if view.State != plan.State || view.SHA256Digest != plan.SHA256Digest ||
		view.RollbackSHA256Digest != plan.RollbackSHA256Digest ||
		view.ForwardProfile.Platform != plan.ForwardProfile.Platform ||
		view.ForwardProfile.Architecture != plan.ForwardProfile.Architecture || view.ForwardProfile.Platform == "" {
		t.Fatalf("view = %+v, plan state=%s forward=%s rollback=%s profile=%+v",
			view, plan.State, plan.SHA256Digest, plan.RollbackSHA256Digest, plan.ForwardProfile)
	}
}

func TestArtifactCachePruneRemovesOnlyOldUnreferencedArtifacts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sha256")
	cache, err := NewArtifactCache(root, testArtifactBaseURL, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * artifactPruneMinAge)
	write := func(name string, modified time.Time) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	kept, stale, fresh := artifactName(0x01), artifactName(0x02), artifactName(0x03)
	write(kept, old)
	write(stale, old)
	write(fresh, time.Now())
	write(".partial-123", time.Now())
	write("README", old)

	removed, err := cache.Prune(map[string]bool{kept: true})
	if err != nil || removed != 2 {
		t.Fatalf("Prune() = (%d, %v), want 2 removed", removed, err)
	}
	for name, want := range map[string]bool{kept: true, stale: false, fresh: true, ".partial-123": false, "README": true} {
		if _, err := os.Stat(filepath.Join(root, name)); (err == nil) != want {
			t.Errorf("%s present=%v, want %v", name, err == nil, want)
		}
	}
}
