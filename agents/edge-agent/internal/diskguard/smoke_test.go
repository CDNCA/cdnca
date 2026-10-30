//go:build diskguard_smoke

package diskguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type smokeEvidence struct {
	NativeUsedBasisPoints      uint16 `json:"native_used_basis_points"`
	TriggeredDeletedFiles      int    `json:"triggered_deleted_files"`
	DryRunWouldDeleteFiles     int    `json:"dry_run_would_delete_files"`
	SparseLogicalBytes         int64  `json:"sparse_logical_bytes"`
	SparseAllocatedBytes       uint64 `json:"sparse_allocated_bytes"`
	ProtectedPreserved         bool   `json:"protected_preserved"`
	SymlinkHardlinkPreserved   bool   `json:"symlink_hardlink_preserved"`
	HysteresisStoppedAtLow     bool   `json:"hysteresis_stopped_at_low"`
	HysteresisHeldInMidBand    bool   `json:"hysteresis_held_in_mid_band"`
	ConcurrentInstanceRejected bool   `json:"concurrent_instance_rejected"`
	RecoveryDeletedRemaining   bool   `json:"recovery_deleted_remaining"`
}

func TestDiskGuardSmoke(t *testing.T) {
	root := filepath.Clean(os.Getenv("EDGE_DISKGUARD_SMOKE_ROOT"))
	if !strings.HasPrefix(root, "/smoke/") {
		t.Fatalf("EDGE_DISKGUARD_SMOKE_ROOT %q is outside the task-owned /smoke filesystem", root)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	logs := filepath.Join(root, "logs")
	cache := filepath.Join(root, "cache")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside-sentinel")
	writeOldFile(t, outside, "outside", 4*time.Hour)
	writeOldFile(t, filepath.Join(logs, "access.log.1.gz"), strings.Repeat("l", 32<<10), 4*time.Hour)
	writeOldFile(t, filepath.Join(logs, "agent.log"), "active", 4*time.Hour)
	writeOldFile(t, filepath.Join(logs, "audit.log.1.gz"), "audit", 4*time.Hour)
	sparsePath := filepath.Join(cache, "object.tmp")
	writeSparseSmokeFile(t, sparsePath, 8<<20, 4*time.Hour)
	if err := os.Symlink(outside, filepath.Join(cache, "linked.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(cache, "hard.tmp")); err != nil {
		t.Fatal(err)
	}
	quarantine := filepath.Join(cache, quarantinePrefix+"restart-leftover.tmp")
	writeOldFile(t, quarantine, "quarantine", 4*time.Hour)

	openedLogs, err := secureOpenDirectory(logs)
	if err != nil {
		t.Fatal(err)
	}
	nativeUsage, err := openedLogs.usage()
	openedLogs.close()
	if err != nil {
		t.Fatalf("native fstatfs: %v", err)
	}
	evidence := smokeEvidence{NativeUsedBasisPoints: usedBasisPoints(nativeUsage)}

	config := testConfig(root,
		ManagedDirectory{ID: "logs", Path: logs, Kind: DirectoryRotatedLogs, Patterns: []string{"*.log*"}, ActiveNames: []string{"agent.log"}},
		cacheDirectory("cache", cache),
	)
	config.MaxDeletedFiles = 1
	guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	report, err := guard.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("triggered evaluation: %v", err)
	}
	evidence.TriggeredDeletedFiles = report.Metrics.RoundDeletedFiles
	if report.Metrics.RoundDeletedFiles != 1 {
		t.Fatalf("triggered deleted files = %d", report.Metrics.RoundDeletedFiles)
	}
	if _, err := os.Stat(filepath.Join(logs, "access.log.1.gz")); !os.IsNotExist(err) {
		t.Fatal("compressed rotated log was not deleted first")
	}
	evidence.ProtectedPreserved = fileContentIs(filepath.Join(logs, "agent.log"), "active") &&
		fileContentIs(filepath.Join(logs, "audit.log.1.gz"), "audit") && fileContentIs(quarantine, "quarantine")
	symlinkInfo, symlinkErr := os.Lstat(filepath.Join(cache, "linked.tmp"))
	hardlinkInfo, hardlinkErr := os.Lstat(filepath.Join(cache, "hard.tmp"))
	outsideInfo, outsideErr := os.Lstat(outside)
	evidence.SymlinkHardlinkPreserved = fileContentIs(outside, "outside") &&
		symlinkErr == nil && symlinkInfo.Mode()&os.ModeSymlink != 0 &&
		hardlinkErr == nil && hardlinkInfo.Mode().IsRegular() && outsideErr == nil &&
		os.SameFile(hardlinkInfo, outsideInfo)
	if !evidence.ProtectedPreserved || !evidence.SymlinkHardlinkPreserved {
		t.Fatal("protected or external sentinel file changed")
	}

	sparseDirectory, err := secureOpenDirectory(cache)
	if err != nil {
		t.Fatal(err)
	}
	sparseMetadata, err := sparseDirectory.metadata("object.tmp")
	sparseDirectory.close()
	if err != nil {
		t.Fatal(err)
	}
	evidence.SparseLogicalBytes = sparseMetadata.size
	evidence.SparseAllocatedBytes = sparseMetadata.allocatedBytes
	if evidence.SparseLogicalBytes != 8<<20 || evidence.SparseAllocatedBytes >= uint64(evidence.SparseLogicalBytes) {
		t.Fatalf("sparse file was not sparse: logical=%d allocated=%d", evidence.SparseLogicalBytes, evidence.SparseAllocatedBytes)
	}

	writeOldFile(t, filepath.Join(cache, "dry-run.tmp"), "dry-run", 3*time.Hour)
	dryConfig := testConfig(root, cacheDirectory("cache", cache))
	dryConfig.DryRun = true
	dryConfig.MaxDeletedFiles = 2
	dryGuard := newTestGuard(t, dryConfig, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	dryReport, err := dryGuard.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("dry-run evaluation: %v", err)
	}
	evidence.DryRunWouldDeleteFiles = dryReport.Metrics.RoundWouldDeleteFiles
	if dryReport.Metrics.RoundWouldDeleteFiles != 2 || dryReport.Metrics.RoundDeletedFiles != 0 ||
		!fileContentIs(filepath.Join(cache, "dry-run.tmp"), "dry-run") {
		t.Fatalf("dry-run mutated data: %+v", dryReport.Metrics)
	}

	recovery := filepath.Join(root, "recovery")
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	firstRecovery := filepath.Join(recovery, "first.tmp")
	secondRecovery := filepath.Join(recovery, "second.tmp")
	writeOldFile(t, firstRecovery, "first", 4*time.Hour)
	writeOldFile(t, secondRecovery, "second", 3*time.Hour)
	recoveryGuard := newTestGuard(t, testConfig(root, cacheDirectory("recovery", recovery)), &sequenceUsage{values: []filesystemUsage{
		basisPoints(9500), basisPoints(8000), basisPoints(8500), basisPoints(9500), basisPoints(9500),
	}})
	firstReport, err := recoveryGuard.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	evidence.HysteresisStoppedAtLow = firstReport.Metrics.RoundDeletedFiles == 1 && fileContentIs(secondRecovery, "second")
	midReport, err := recoveryGuard.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	evidence.HysteresisHeldInMidBand = midReport.Metrics.RoundDeletedFiles == 0 && fileContentIs(secondRecovery, "second")
	highReport, err := recoveryGuard.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, remainingErr := os.Stat(secondRecovery)
	evidence.RecoveryDeletedRemaining = highReport.Metrics.RoundDeletedFiles == 1 && os.IsNotExist(remainingErr)
	if !evidence.HysteresisStoppedAtLow || !evidence.HysteresisHeldInMidBand || !evidence.RecoveryDeletedRemaining {
		t.Fatalf("hysteresis/recovery evidence failed: first=%+v mid=%+v high=%+v", firstReport.Metrics, midReport.Metrics, highReport.Metrics)
	}

	concurrentRoot := filepath.Join(root, "concurrent")
	if err := os.Mkdir(concurrentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeOldFile(t, filepath.Join(concurrentRoot, "candidate.tmp"), "concurrent", 3*time.Hour)
	concurrentConfig := testConfig(root, cacheDirectory("concurrent", concurrentRoot))
	firstGuard := newTestGuard(t, concurrentConfig, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	secondGuard := newTestGuard(t, concurrentConfig, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	entered := make(chan struct{})
	release := make(chan struct{})
	firstGuard.hooks.beforeQuarantine = func(_ *openDirectory, _ candidate) {
		close(entered)
		<-release
	}
	firstDone := make(chan error, 1)
	go func() {
		_, evaluateErr := firstGuard.Evaluate(context.Background())
		firstDone <- evaluateErr
	}()
	select {
	case <-entered:
	case evaluateErr := <-firstDone:
		t.Fatalf("first concurrent guard exited early: %v", evaluateErr)
	case <-time.After(5 * time.Second):
		t.Fatal("first concurrent guard did not enter deletion")
	}
	secondReport, secondErr := secondGuard.Evaluate(context.Background())
	evidence.ConcurrentInstanceRejected = errors.Is(secondErr, ErrAlreadyRunning) &&
		secondReport.Metrics.FailureReason == FailureLockHeld
	close(release)
	if firstErr := <-firstDone; firstErr != nil {
		t.Fatalf("first concurrent guard: %v", firstErr)
	}
	if !evidence.ConcurrentInstanceRejected {
		t.Fatalf("second concurrent guard was not rejected: report=%+v error=%v", secondReport, secondErr)
	}

	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("EDGE_DISKGUARD_SMOKE_EVIDENCE=%s\n", encoded)
}

func writeSparseSmokeFile(t *testing.T, path string, size int64, age time.Duration) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	modified := time.Now().Add(-age)
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
}

func fileContentIs(path, want string) bool {
	content, err := os.ReadFile(path)
	return err == nil && string(content) == want
}
