package diskguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type sequenceUsage struct {
	mu     sync.Mutex
	values []filesystemUsage
	errAt  int
	calls  int
}

func (usage *sequenceUsage) usage(_ *openDirectory) (filesystemUsage, error) {
	usage.mu.Lock()
	defer usage.mu.Unlock()
	usage.calls++
	if usage.errAt > 0 && usage.calls == usage.errAt {
		return filesystemUsage{}, os.ErrPermission
	}
	index := usage.calls - 1
	if index >= len(usage.values) {
		index = len(usage.values) - 1
	}
	return usage.values[index], nil
}

func basisPoints(value uint16) filesystemUsage {
	return filesystemUsage{totalBytes: 10000, availableBytes: uint64(10000 - value)}
}

func testConfig(root string, directories ...ManagedDirectory) Config {
	root = mustRealPathForTest(root)
	for index := range directories {
		directories[index].Path = mustRealPathForTest(directories[index].Path)
	}
	return Config{
		SchemaVersion: ConfigSchemaVersion, ConfigID: "test-disk-guard", Revision: 1,
		LockPath: filepath.Join(root, "guard.lock"), LowWatermark: 8000, HighWatermark: 9000,
		EvaluationPeriod: time.Second, MaxDeletedFiles: 100, MaxAllocatedBytes: 1 << 30,
		Directories: directories,
	}
}

func mustRealPathForTest(path string) string {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		panic(err)
	}
	return realPath
}

func cacheDirectory(id, root string) ManagedDirectory {
	return ManagedDirectory{ID: id, Path: root, Kind: DirectoryCacheTemp, Patterns: []string{"*.tmp"}}
}

func newTestGuard(t *testing.T, config Config, usage usageProvider) *Guard {
	t.Helper()
	guard, err := New(config, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	guard.usage = usage
	return guard
}

func writeOldFile(t *testing.T, path, content string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	modified := time.Now().Add(-age)
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func TestValidateConfigRejectsUnsafeBoundsAndPatterns(t *testing.T) {
	root := t.TempDir()
	valid := testConfig(root, cacheDirectory("cache", root))
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "schema", mutate: func(config *Config) { config.SchemaVersion = "v2" }},
		{name: "revision", mutate: func(config *Config) { config.Revision = 0 }},
		{name: "watermark ordering", mutate: func(config *Config) { config.LowWatermark = config.HighWatermark }},
		{name: "watermark range", mutate: func(config *Config) { config.HighWatermark = 10001 }},
		{name: "period", mutate: func(config *Config) { config.EvaluationPeriod = 0 }},
		{name: "root allowlist", mutate: func(config *Config) { config.Directories[0].Path = "/" }},
		{name: "relative path", mutate: func(config *Config) { config.Directories[0].Path = "cache" }},
		{name: "catch all", mutate: func(config *Config) { config.Directories[0].Patterns = []string{"*"} }},
		{name: "path pattern", mutate: func(config *Config) { config.Directories[0].Patterns = []string{"*/*.tmp"} }},
		{name: "unknown kind", mutate: func(config *Config) { config.Directories[0].Kind = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneConfig(valid)
			test.mutate(&candidate)
			if _, err := New(candidate, Options{}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewRejectsProtectedAndSharedWritableRoots(t *testing.T) {
	root := mustRealPathForTest(t.TempDir())
	config := testConfig(root, cacheDirectory("cache", root))
	config.ProtectedPaths = []string{root}
	if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(protected overlap) error = %v", err)
	}

	config.ProtectedPaths = nil
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0o700)
	if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(shared writable root) error = %v", err)
	}
	if err := os.Chmod(root, 0o300); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(unreadable root) error = %v", err)
	}
}

func TestWatermarkBoundariesAndHysteresis(t *testing.T) {
	root := t.TempDir()
	usage := &sequenceUsage{values: []filesystemUsage{
		basisPoints(9000), basisPoints(8500), basisPoints(8000), basisPoints(8500),
	}}
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), usage)

	wantPressure := []bool{true, true, false, false}
	for index, want := range wantPressure {
		report, err := guard.Evaluate(context.Background())
		if err != nil {
			t.Fatalf("Evaluate(%d) error = %v", index, err)
		}
		if got := report.Metrics.Directories[0].Pressure; got != want {
			t.Fatalf("Evaluate(%d) pressure = %t, want %t", index, got, want)
		}
	}
}

func TestMetricsSnapshotTracksFailureAndReturnsCopy(t *testing.T) {
	root := t.TempDir()
	usage := &sequenceUsage{values: []filesystemUsage{basisPoints(5000)}, errAt: 2}
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), usage)
	if _, err := guard.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := guard.Snapshot()
	if !snapshot.Healthy || snapshot.EvaluationsTotal != 1 || len(snapshot.Directories) != 1 {
		t.Fatalf("healthy snapshot = %+v", snapshot)
	}
	snapshot.Directories[0].DirectoryID = "mutated"
	if guard.Snapshot().Directories[0].DirectoryID != "cache" {
		t.Fatal("Snapshot() exposed internal directory metrics")
	}
	if _, err := guard.Evaluate(context.Background()); err == nil {
		t.Fatal("Evaluate() accepted usage failure")
	}
	failed := guard.Snapshot()
	if failed.Healthy || failed.FailureReason != FailureUsageUnavailable || failed.EvaluationsTotal != 2 {
		t.Fatalf("failed snapshot = %+v", failed)
	}
}

func TestDeletionPriorityRetentionAgeAndFileBudget(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	cache := filepath.Join(root, "cache")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	writeOldFile(t, filepath.Join(logs, "access.log.1.gz"), "old-compressed", 6*time.Hour)
	writeOldFile(t, filepath.Join(logs, "access.log.2.gz"), "newer-compressed", 5*time.Hour)
	writeOldFile(t, filepath.Join(logs, "access.log.3"), "retained-newest", 4*time.Hour)
	writeOldFile(t, filepath.Join(logs, "access.log.4.gz"), "too-young", time.Minute)
	writeOldFile(t, filepath.Join(cache, "oldest.tmp"), "cache", 24*time.Hour)

	config := testConfig(root,
		ManagedDirectory{ID: "logs", Path: logs, Kind: DirectoryRotatedLogs, Patterns: []string{"*.log.*"}, MinimumAge: time.Hour, MinimumRemain: 1},
		cacheDirectory("cache", cache),
	)
	config.MaxDeletedFiles = 2
	guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	report, err := guard.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if report.Metrics.RoundDeletedFiles != 2 || report.Metrics.RoundBudgetSkipped != 1 {
		t.Fatalf("round metrics = %+v", report.Metrics)
	}
	for _, name := range []string{"access.log.1.gz", "access.log.2.gz"} {
		if _, err := os.Stat(filepath.Join(logs, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was not deleted", name)
		}
	}
	for _, path := range []string{
		filepath.Join(logs, "access.log.3"), filepath.Join(logs, "access.log.4.gz"), filepath.Join(cache, "oldest.tmp"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("retained file %s: %v", path, err)
		}
	}
}

func TestAllocatedByteBudgetIsHardLimit(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.tmp")
	second := filepath.Join(root, "second.tmp")
	writeOldFile(t, first, string(make([]byte, 4096)), 2*time.Hour)
	writeOldFile(t, second, string(make([]byte, 8192)), time.Hour)
	directory, err := secureOpenDirectory(mustRealPathForTest(root))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := directory.metadata("first.tmp")
	directory.close()
	if err != nil || metadata.allocatedBytes == 0 {
		t.Fatalf("first allocation = %d, error = %v", metadata.allocatedBytes, err)
	}
	config := testConfig(root, cacheDirectory("cache", root))
	config.MaxAllocatedBytes = metadata.allocatedBytes
	guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	report, err := guard.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.RoundDeletedBytes > config.MaxAllocatedBytes || report.Metrics.RoundDeletedFiles != 1 || report.Metrics.RoundBudgetSkipped != 1 {
		t.Fatalf("budget was not enforced: %+v", report.Metrics)
	}
}

func TestDryRunProtectsSensitiveSymlinkHardlinkAndNonRegularFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	writeOldFile(t, outside, "outside", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "access.log.1.gz"), "candidate", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "agent.log"), "active", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "audit.log.1.gz"), "audit", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "identity.log.1.gz"), "identity", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "certificate.log.1.gz"), "certificate", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "config.log.1.gz"), "config", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "version.log.1.gz"), "version", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "upgrade.log.1.gz"), "upgrade", 2*time.Hour)
	writeOldFile(t, filepath.Join(root, "rollback.log.1.gz"), "rollback", 2*time.Hour)
	if err := os.Symlink(outside, filepath.Join(root, "linked.log.1.gz")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root, "hard.log.1.gz")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "pipe.log.1.gz"), 0o600); err != nil {
		t.Fatal(err)
	}

	config := testConfig(root, ManagedDirectory{
		ID: "logs", Path: root, Kind: DirectoryRotatedLogs, Patterns: []string{"*.log*"}, ActiveNames: []string{"agent.log"},
	})
	config.DryRun = true
	guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	report, err := guard.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.RoundWouldDeleteFiles != 1 || report.Metrics.RoundDeletedFiles != 0 ||
		report.Metrics.RoundProtectedFiles != 8 || report.Metrics.RoundUnsafeFiles != 3 {
		t.Fatalf("dry-run metrics = %+v", report.Metrics)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "outside" {
		t.Fatalf("outside target changed: content=%q err=%v", content, err)
	}
	if _, err := os.Stat(filepath.Join(root, "access.log.1.gz")); err != nil {
		t.Fatalf("dry-run deleted candidate: %v", err)
	}
}

func TestActiveLockFileIsNeverCandidate(t *testing.T) {
	root := t.TempDir()
	config := testConfig(root, ManagedDirectory{
		ID: "locks", Path: root, Kind: DirectoryCacheTemp, Patterns: []string{"*.lock"},
	})
	guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	report, err := guard.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.RoundCandidateFiles != 0 || report.Metrics.RoundDeletedFiles != 0 ||
		report.Metrics.RoundProtectedFiles != 1 {
		t.Fatalf("lock protection metrics = %+v", report.Metrics)
	}
	if info, err := os.Stat(config.LockPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("active lock was not preserved: info=%v error=%v", info, err)
	}
}

func TestPreflightPermissionFailureDeletesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denial cannot be asserted as root")
	}
	root := t.TempDir()
	readable := filepath.Join(root, "readable")
	denied := filepath.Join(root, "denied")
	if err := os.Mkdir(readable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(denied, 0o700); err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(readable, "candidate.tmp")
	writeOldFile(t, candidatePath, "keep", time.Hour)
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(denied, 0o700)
	config := testConfig(root, cacheDirectory("readable", readable), cacheDirectory("denied", denied))
	if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
	}
	if _, err := os.Stat(candidatePath); err != nil {
		t.Fatalf("preflight failure removed candidate: %v", err)
	}
}

func TestRuntimeManagedDirectoryPermissionChangeFailsClosed(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(logs, "candidate.tmp")
	writeOldFile(t, candidatePath, "keep", time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", logs)),
		&sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	if err := os.Chmod(logs, 0o770); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(logs, 0o700)
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureDirectoryUnsafe {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, candidatePath, "keep")
}

func TestRuntimeLockParentPermissionChangeFailsClosed(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	locks := filepath.Join(root, "locks")
	for _, path := range []string{logs, locks} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	candidatePath := filepath.Join(logs, "candidate.tmp")
	writeOldFile(t, candidatePath, "keep", time.Hour)
	config := testConfig(root, cacheDirectory("cache", logs))
	config.LockPath = filepath.Join(mustRealPathForTest(locks), "guard.lock")
	guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	if err := os.Chmod(locks, 0o770); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locks, 0o700)
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureLockUnsafe {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, candidatePath, "keep")
}

func TestRuntimeLockFilePermissionChangeFailsClosed(t *testing.T) {
	root := t.TempDir()
	candidatePath := filepath.Join(root, "candidate.tmp")
	writeOldFile(t, candidatePath, "keep", time.Hour)
	config := testConfig(root, cacheDirectory("cache", root))
	guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	if err := os.WriteFile(config.LockPath, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureLockUnsafe {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, candidatePath, "keep")
}

func TestCandidatePermissionFailureDeletesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denial cannot be asserted as root")
	}
	root := t.TempDir()
	oldest := filepath.Join(root, "oldest.tmp")
	denied := filepath.Join(root, "denied.tmp")
	writeOldFile(t, oldest, "keep-oldest", 2*time.Hour)
	writeOldFile(t, denied, "keep-denied", time.Hour)
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(denied, 0o600)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)),
		&sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureScanFailed {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, oldest, "keep-oldest")
	if err := os.Chmod(denied, 0o600); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, denied, "keep-denied")
}

func TestUsageFailureDeletesNothing(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(first, "candidate.tmp")
	writeOldFile(t, candidatePath, "keep", time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("first", first), cacheDirectory("second", second)),
		&sequenceUsage{values: []filesystemUsage{basisPoints(9500)}, errAt: 2})
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureUsageUnavailable {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	if _, err := os.Stat(candidatePath); err != nil {
		t.Fatalf("usage failure removed candidate: %v", err)
	}
}

func TestSymlinkLockFailsClosed(t *testing.T) {
	root := t.TempDir()
	candidatePath := filepath.Join(root, "candidate.tmp")
	outsideLock := filepath.Join(t.TempDir(), "outside.lock")
	writeOldFile(t, candidatePath, "keep", time.Hour)
	writeOldFile(t, outsideLock, "outside", time.Hour)
	config := testConfig(root, cacheDirectory("cache", root))
	if err := os.Symlink(outsideLock, config.LockPath); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
	}
	assertFileContent(t, candidatePath, "keep")
	assertFileContent(t, outsideLock, "outside")
}

func TestRenameSymlinkRaceFailsClosed(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	writeOldFile(t, outside, "outside", time.Hour)
	original := filepath.Join(root, "race.tmp")
	moved := filepath.Join(root, "moved")
	writeOldFile(t, original, "original", time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	guard.hooks.beforeQuarantine = func(_ *openDirectory, _ candidate) {
		if err := os.Rename(original, moved); err != nil {
			t.Errorf("rename race candidate: %v", err)
			return
		}
		if err := os.Symlink(outside, original); err != nil {
			t.Errorf("install race symlink: %v", err)
		}
	}
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureCandidateChanged {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, moved, "original")
	assertFileContent(t, outside, "outside")
}

func TestHardlinkRaceFailsClosed(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "race.tmp")
	hardlink := filepath.Join(root, "hardlink")
	writeOldFile(t, original, "original", time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	guard.hooks.beforeQuarantine = func(_ *openDirectory, _ candidate) {
		if err := os.Link(original, hardlink); err != nil {
			t.Errorf("create hardlink race: %v", err)
		}
	}
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureCandidateChanged {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, hardlink, "original")
	assertAllRegularContents(t, root, "original")
}

func TestDirectoryReplacementFailsClosed(t *testing.T) {
	rootParent := t.TempDir()
	root := filepath.Join(rootParent, "managed")
	moved := filepath.Join(rootParent, "managed-moved")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeOldFile(t, filepath.Join(root, "race.tmp"), "original", time.Hour)
	guard := newTestGuard(t, testConfig(rootParent, cacheDirectory("cache", root)), &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	guard.hooks.beforeQuarantine = func(_ *openDirectory, _ candidate) {
		if err := os.Rename(root, moved); err != nil {
			t.Errorf("replace managed directory: %v", err)
			return
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Errorf("create replacement directory: %v", err)
		}
	}
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureCandidateChanged {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, filepath.Join(moved, "race.tmp"), "original")
}

func TestCrossDeviceIdentityIsRejected(t *testing.T) {
	root := t.TempDir()
	writeOldFile(t, filepath.Join(root, "candidate.tmp"), "keep", time.Hour)
	directory, err := secureOpenDirectory(mustRealPathForTest(root))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	metadata, err := directory.metadata("candidate.tmp")
	if err != nil {
		t.Fatal(err)
	}
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	item := candidate{name: "candidate.tmp", identity: metadata.identity}
	item.identity.device++
	if err := guard.deleteCandidate(&directoryPlan{directory: directory}, item); err == nil {
		t.Fatal("deleteCandidate() accepted a cross-device identity")
	}
	assertFileContent(t, filepath.Join(root, "candidate.tmp"), "keep")
}

func TestSingleInstanceLockAndCancellation(t *testing.T) {
	root := t.TempDir()
	writeOldFile(t, filepath.Join(root, "candidate.tmp"), "keep", time.Hour)
	config := testConfig(root, cacheDirectory("cache", root))
	first := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	second := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	entered := make(chan struct{})
	release := make(chan struct{})
	first.hooks.beforeQuarantine = func(_ *openDirectory, _ candidate) {
		close(entered)
		<-release
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := first.Evaluate(context.Background())
		firstDone <- err
	}()
	select {
	case <-entered:
	case err := <-firstDone:
		t.Fatalf("first Evaluate() exited before hook: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first Evaluate() did not reach quarantine hook")
	}
	report, err := second.Evaluate(context.Background())
	if !errors.Is(err, ErrAlreadyRunning) || report.Metrics.FailureReason != FailureLockHeld {
		t.Fatalf("second Evaluate() report=%+v error=%v", report, err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Evaluate() error = %v", err)
	}

	runGuard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(5000)}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runGuard.Run(ctx); err != nil {
		t.Fatalf("Run(cancelled) error = %v", err)
	}
}

func TestRestartIgnoresQuarantineAndMidBandWithoutPriorPressure(t *testing.T) {
	root := t.TempDir()
	quarantine := filepath.Join(root, quarantinePrefix+"leftover.tmp")
	candidatePath := filepath.Join(root, "candidate.tmp")
	writeOldFile(t, quarantine, "quarantine", time.Hour)
	writeOldFile(t, candidatePath, "candidate", time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), &sequenceUsage{values: []filesystemUsage{basisPoints(8500)}})
	report, err := guard.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Metrics.RoundCandidateFiles != 0 || report.Metrics.RoundDeletedFiles != 0 {
		t.Fatalf("restart at mid-band reclaimed files: %+v", report.Metrics)
	}
	assertFileContent(t, quarantine, "quarantine")
	assertFileContent(t, candidatePath, "candidate")
}

func TestCancelledEvaluationDeletesNothing(t *testing.T) {
	root := t.TempDir()
	candidatePath := filepath.Join(root, "candidate.tmp")
	writeOldFile(t, candidatePath, "keep", time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)), &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := guard.Evaluate(ctx)
	if err == nil || report.Metrics.FailureReason != FailureCancelled {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, candidatePath, "keep")
}

type completionSink struct {
	mu        sync.Mutex
	completed int
	cancel    context.CancelFunc
}

func (sink *completionSink) RecordDiskGuardEvent(_ context.Context, event Event) {
	if event.Code != EventEvaluationCompleted {
		return
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.completed++
	if sink.completed == 2 {
		sink.cancel()
	}
}

func TestRunEvaluatesPeriodicallyUntilCancelled(t *testing.T) {
	root := t.TempDir()
	config := testConfig(root, cacheDirectory("cache", root))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sink := &completionSink{cancel: cancel}
	guard, err := New(config, Options{EventSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	guard.usage = &sequenceUsage{values: []filesystemUsage{basisPoints(5000)}}
	guard.config.EvaluationPeriod = time.Millisecond
	if err := guard.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	sink.mu.Lock()
	completed := sink.completed
	sink.mu.Unlock()
	if completed != 2 {
		t.Fatalf("completed evaluations = %d, want 2", completed)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil || string(content) != want {
		t.Fatalf("read %s = %q, %v; want %q", path, content, err, want)
	}
}

func assertAllRegularContents(t *testing.T, root string, want string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	contents := make([]string, 0)
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			content, err := os.ReadFile(filepath.Join(root, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			contents = append(contents, string(content))
		}
	}
	sort.Strings(contents)
	found := false
	for _, content := range contents {
		if content == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("regular contents %q do not contain %q", contents, want)
	}
}
