package diskguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCandidateMutationFailsClosedAcrossQuarantinePhases(t *testing.T) {
	mutations := []string{"append", "truncate", "touch"}
	phases := []string{"after_scan", "after_quarantine"}
	for _, phase := range phases {
		for _, mutation := range mutations {
			t.Run(phase+"_"+mutation, func(t *testing.T) {
				root := t.TempDir()
				candidatePath := filepath.Join(root, "candidate.tmp")
				writeOldFile(t, candidatePath, strings.Repeat("x", 8192), 2*time.Hour)
				directory, err := secureOpenDirectory(mustRealPathForTest(root))
				if err != nil {
					t.Fatal(err)
				}
				metadata, err := directory.metadata("candidate.tmp")
				directory.close()
				if err != nil || metadata.allocatedBytes == 0 {
					t.Fatalf("candidate metadata = %+v, error = %v", metadata, err)
				}

				config := testConfig(root, ManagedDirectory{
					ID: "cache", Path: root, Kind: DirectoryCacheTemp, Patterns: []string{"*.tmp"}, MinimumAge: time.Hour,
				})
				config.MaxAllocatedBytes = metadata.allocatedBytes
				guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
				var hookErr error
				mutate := func(path string) {
					if hookErr == nil {
						hookErr = mutateCandidateForTest(path, mutation)
					}
				}
				if phase == "after_scan" {
					guard.hooks.beforeQuarantine = func(directory *openDirectory, item candidate) {
						mutate(filepath.Join(directory.path, item.name))
					}
				} else {
					guard.hooks.afterQuarantine = func(directory *openDirectory, _ candidate, name string) {
						mutate(filepath.Join(directory.path, name))
					}
				}

				report, err := guard.Evaluate(context.Background())
				if hookErr != nil {
					t.Fatalf("mutate candidate: %v", hookErr)
				}
				if err == nil || report.Metrics.FailureReason != FailureCandidateChanged ||
					report.Metrics.RoundDeletedFiles != 0 || report.Metrics.RoundDeletedBytes != 0 {
					t.Fatalf("Evaluate() report=%+v error=%v", report, err)
				}
				if _, err := os.Lstat(candidatePath); err != nil {
					t.Fatalf("changed candidate was not preserved: %v", err)
				}
			})
		}
	}
}

func mutateCandidateForTest(path, mutation string) error {
	switch mutation {
	case "append":
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(make([]byte, 64<<10))
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	case "truncate":
		return os.Truncate(path, 1)
	case "touch":
		modified := time.Now().Add(time.Hour)
		return os.Chtimes(path, modified, modified)
	default:
		return errors.New("unknown test mutation")
	}
}

func TestAfterQuarantineUsesPrivateNamespaceAndPreservesReplacement(t *testing.T) {
	root := mustRealPathForTest(t.TempDir())
	original := filepath.Join(root, "race.tmp")
	writeOldFile(t, original, "old", 2*time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)),
		&sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	quarantinePath := ""
	var hookErr error
	guard.hooks.afterQuarantine = func(directory *openDirectory, item candidate, _ string) {
		quarantinePath = directory.path
		hookErr = os.WriteFile(filepath.Join(root, item.name), []byte("replacement"), 0o600)
	}
	report, err := guard.Evaluate(context.Background())
	if hookErr != nil {
		t.Fatalf("install replacement: %v", hookErr)
	}
	if err != nil || report.Metrics.RoundDeletedFiles != 1 {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	if filepath.Clean(quarantinePath) == root {
		t.Fatalf("afterQuarantine used writable managed root %q", quarantinePath)
	}
	assertFileContent(t, original, "replacement")
	quarantineEntries, err := os.ReadDir(filepath.Join(root, quarantineRootName))
	if err != nil {
		t.Fatalf("read private quarantine root: %v", err)
	}
	if len(quarantineEntries) != 0 {
		t.Fatalf("successful deletion left private quarantine entries: %v", quarantineEntries)
	}
}

func TestAfterQuarantineNamespaceSwapFailsClosed(t *testing.T) {
	root := mustRealPathForTest(t.TempDir())
	original := filepath.Join(root, "race.tmp")
	writeOldFile(t, original, "original", 2*time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)),
		&sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	movedPrivateRoot := filepath.Join(root, "moved-private-root")
	var hookErr error
	guard.hooks.afterQuarantine = func(directory *openDirectory, _ candidate, _ string) {
		privateRoot := filepath.Dir(directory.path)
		if filepath.Dir(privateRoot) != root {
			hookErr = errors.New("afterQuarantine did not receive a private namespace")
			return
		}
		if err := os.Rename(privateRoot, movedPrivateRoot); err != nil {
			hookErr = err
			return
		}
		hookErr = os.Mkdir(privateRoot, 0o700)
	}
	report, err := guard.Evaluate(context.Background())
	if hookErr != nil {
		t.Fatalf("swap private namespace: %v", hookErr)
	}
	if err == nil || report.Metrics.FailureReason != FailureCandidateChanged || report.Metrics.RoundDeletedFiles != 0 {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, original, "original")
}

func TestNewRejectsPhysicalProtectedPathAliases(t *testing.T) {
	t.Run("symlink alias", func(t *testing.T) {
		root := t.TempDir()
		managed := filepath.Join(root, "managed")
		if err := os.Mkdir(managed, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(root, "protected-alias")
		if err := os.Symlink(managed, alias); err != nil {
			t.Fatal(err)
		}
		config := testConfig(root, cacheDirectory("cache", managed))
		config.ProtectedPaths = []string{alias}
		if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New(physical alias) error = %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("nonexistent path below physical alias", func(t *testing.T) {
		root := t.TempDir()
		managed := filepath.Join(root, "managed")
		if err := os.Mkdir(managed, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(root, "future-alias")
		if err := os.Symlink(managed, alias); err != nil {
			t.Fatal(err)
		}
		config := testConfig(root, cacheDirectory("cache", managed))
		config.ProtectedPaths = []string{filepath.Join(alias, "future-protected")}
		if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New(nonexistent alias child) error = %v, want ErrInvalidConfig", err)
		}
	})

	if runtime.GOOS == "darwin" {
		t.Run("darwin tmp alias", func(t *testing.T) {
			managed, err := os.MkdirTemp("/private/tmp", "cdnca-diskguard-protected-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(managed) })
			config := testConfig(managed, cacheDirectory("cache", managed))
			config.ProtectedPaths = []string{strings.Replace(managed, "/private/tmp/", "/tmp/", 1)}
			if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New(/tmp alias) error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewAllowsMissingProtectedSibling(t *testing.T) {
	root := t.TempDir()
	application := filepath.Join(root, "app")
	managed := filepath.Join(application, "cache")
	for _, path := range []string{application, managed} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := testConfig(root, cacheDirectory("cache", managed))
	config.ProtectedPaths = []string{filepath.Join(application, "future-secret")}
	if _, err := New(config, Options{}); err != nil {
		t.Fatalf("New(missing protected sibling) error = %v, want nil", err)
	}
}

func TestNewRejectsDanglingProtectedSymlink(t *testing.T) {
	root := t.TempDir()
	application := filepath.Join(root, "app")
	managed := filepath.Join(application, "cache")
	for _, path := range []string{application, managed} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	protectedLink := filepath.Join(application, "protected-link")
	if err := os.Symlink(filepath.Join(managed, "future.tmp"), protectedLink); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(protectedLink); err != nil {
		t.Fatalf("dangling protected symlink does not exist: %v", err)
	}
	if _, err := os.Stat(protectedLink); !os.IsNotExist(err) {
		t.Fatalf("protected symlink target exists or returned unexpected error: %v", err)
	}
	config := testConfig(root, cacheDirectory("cache", managed))
	config.ProtectedPaths = []string{protectedLink}
	if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(dangling protected symlink) error = %v, want ErrInvalidConfig", err)
	}
}

func TestScanEntryCapFailsBeforeDeletion(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"first.tmp", "second.tmp", "third.tmp"} {
		writeOldFile(t, filepath.Join(root, name), name, time.Hour)
	}
	if _, err := New(testConfig(root, cacheDirectory("cache", root)), Options{MaxScanEntries: defaultMaxScanEntries + 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(oversized scan cap) error = %v, want ErrInvalidConfig", err)
	}
	options := Options{MaxScanEntries: 2}
	guard, err := New(testConfig(root, cacheDirectory("cache", root)), options)
	if err != nil {
		t.Fatal(err)
	}
	guard.usage = &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}}
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureScanFailed ||
		!strings.Contains(err.Error(), "scan entry limit exceeded") || report.Metrics.RoundDeletedFiles != 0 {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	for _, name := range []string{"first.tmp", "second.tmp", "third.tmp"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
			t.Fatalf("scan cap removed %s: %v", name, err)
		}
	}
}

func TestMinimumAgePreservesNanosecondBoundary(t *testing.T) {
	root := t.TempDir()
	fixedNow := time.Unix(1_800_000_000, 800_000_000)
	minimumAge := time.Second
	exactPath := filepath.Join(root, "exact.tmp")
	youngPath := filepath.Join(root, "young.tmp")
	for path, modified := range map[string]time.Time{
		exactPath: fixedNow.Add(-minimumAge),
		youngPath: fixedNow.Add(-minimumAge + time.Nanosecond),
	} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.ModTime().UnixNano() != modified.UnixNano() {
			t.Fatalf("filesystem did not preserve mtime nanoseconds for %s: got=%v want=%v err=%v", path, info.ModTime(), modified, err)
		}
	}
	config := testConfig(root, ManagedDirectory{
		ID: "cache", Path: root, Kind: DirectoryCacheTemp, Patterns: []string{"*.tmp"}, MinimumAge: minimumAge,
	})
	guard := newTestGuard(t, config, &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	guard.now = func() time.Time { return fixedNow }
	report, err := guard.Evaluate(context.Background())
	if err != nil || report.Metrics.RoundCandidateFiles != 1 || report.Metrics.RoundDeletedFiles != 1 {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	if _, err := os.Lstat(exactPath); !os.IsNotExist(err) {
		t.Fatalf("exact MinimumAge boundary was not deleted: %v", err)
	}
	if _, err := os.Lstat(youngPath); err != nil {
		t.Fatalf("one-nanosecond-young candidate was deleted: %v", err)
	}
}

func TestScanEntryCapIsGlobalAcrossManagedRoots(t *testing.T) {
	root := t.TempDir()
	firstRoot := filepath.Join(root, "first")
	secondRoot := filepath.Join(root, "second")
	for _, directory := range []string{firstRoot, secondRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"one.tmp", "two.tmp"} {
			writeOldFile(t, filepath.Join(directory, name), filepath.Base(directory)+"-"+name, time.Hour)
		}
	}
	config := testConfig(root, cacheDirectory("first", firstRoot), cacheDirectory("second", secondRoot))
	guard, err := New(config, Options{MaxScanEntries: 3})
	if err != nil {
		t.Fatal(err)
	}
	guard.usage = &sequenceUsage{values: []filesystemUsage{basisPoints(9500)}}
	report, err := guard.Evaluate(context.Background())
	if err == nil || report.Metrics.FailureReason != FailureScanFailed ||
		!strings.Contains(err.Error(), "scan entry limit exceeded") || report.Metrics.RoundDeletedFiles != 0 {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	for _, directory := range []string{firstRoot, secondRoot} {
		for _, name := range []string{"one.tmp", "two.tmp"} {
			assertFileContent(t, filepath.Join(directory, name), filepath.Base(directory)+"-"+name)
		}
	}
}

func TestRestoreCollisionPreservesReplacementAndQuarantinedEvidence(t *testing.T) {
	root := mustRealPathForTest(t.TempDir())
	originalPath := filepath.Join(root, "collision.tmp")
	writeOldFile(t, originalPath, "original", 2*time.Hour)
	guard := newTestGuard(t, testConfig(root, cacheDirectory("cache", root)),
		&sequenceUsage{values: []filesystemUsage{basisPoints(9500)}})
	evidencePath := ""
	var hookErr error
	guard.hooks.afterQuarantine = func(directory *openDirectory, item candidate, name string) {
		evidencePath = filepath.Join(directory.path, name)
		if err := os.WriteFile(filepath.Join(root, item.name), []byte("replacement"), 0o600); err != nil {
			hookErr = err
			return
		}
		file, err := os.OpenFile(evidencePath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			hookErr = err
			return
		}
		_, writeErr := file.WriteString("-mutated")
		closeErr := file.Close()
		if writeErr != nil {
			hookErr = writeErr
		} else {
			hookErr = closeErr
		}
	}
	report, err := guard.Evaluate(context.Background())
	if hookErr != nil {
		t.Fatalf("install restore collision: %v", hookErr)
	}
	if err == nil || report.Metrics.FailureReason != FailureCandidateChanged || report.Metrics.RoundDeletedFiles != 0 {
		t.Fatalf("Evaluate() report=%+v error=%v", report, err)
	}
	assertFileContent(t, originalPath, "replacement")
	assertFileContent(t, evidencePath, "original-mutated")
}

func assertFutureMtimeFailsClosed(t *testing.T, metadata fileMetadata, future time.Time) {
	t.Helper()
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	if metadata.modified.seconds != future.Unix() || metadata.modified.nanoseconds != int64(future.Nanosecond()) {
		t.Fatalf("future mtime was not preserved: got=%+v want=%v", metadata.modified, future)
	}
	if candidateOldEnough(metadata.modified, now, 0) {
		t.Fatalf("future mtime entered deletion range: modified=%+v now=%v", metadata.modified, now)
	}
}

func TestPhysicalPathOverlapIsSymmetric(t *testing.T) {
	filesystemRoot := fileIdentity{device: 1, inode: 1}
	managed := fileIdentity{device: 1, inode: 10}
	protected := fileIdentity{device: 1, inode: 20}
	managedChild := fileIdentity{device: 1, inode: 11}
	protectedChild := fileIdentity{device: 1, inode: 21}
	tests := []struct {
		name  string
		left  []fileIdentity
		right []fileIdentity
		want  bool
	}{
		{name: "same root", left: []fileIdentity{managed, filesystemRoot}, right: []fileIdentity{managed, filesystemRoot}, want: true},
		{name: "managed below protected", left: []fileIdentity{managedChild, protected, filesystemRoot}, right: []fileIdentity{protected, filesystemRoot}, want: true},
		{name: "protected below managed", left: []fileIdentity{managed, filesystemRoot}, right: []fileIdentity{protectedChild, managed, filesystemRoot}, want: true},
		{name: "siblings only share filesystem root", left: []fileIdentity{managed, filesystemRoot}, right: []fileIdentity{protected, filesystemRoot}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := physicalPathsOverlap(test.left, test.right); got != test.want {
				t.Fatalf("physicalPathsOverlap(left, right) = %t, want %t", got, test.want)
			}
			if got := physicalPathsOverlap(test.right, test.left); got != test.want {
				t.Fatalf("physicalPathsOverlap(right, left) = %t, want %t", got, test.want)
			}
		})
	}
}
