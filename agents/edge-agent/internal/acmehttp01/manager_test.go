package acmehttp01

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

type filesystemProbe struct {
	root      string
	mu        sync.Mutex
	calls     int
	notFound  int
	failValue string
}

func (probe *filesystemProbe) Check(_ context.Context, host, token string, expected *string) error {
	probe.mu.Lock()
	probe.calls++
	if expected == nil {
		probe.notFound++
	}
	probe.mu.Unlock()
	content, err := os.ReadFile(filepath.Join(probe.root, "acme-http01", "current", host, token))
	if expected == nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return ErrHealthFailed
	}
	if err != nil || string(content) != *expected || *expected == probe.failValue {
		return ErrHealthFailed
	}
	return nil
}

func (probe *filesystemProbe) counts() (int, int) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return probe.calls, probe.notFound
}

func TestManagerReplacesCompleteSetIdempotentlyAndCleansOneToken(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, probe, now)
	first := snapshot(now, 1,
		entry("a.example.test", token("a"), now),
		entry("b.example.test", token("b"), now),
	)
	firstCommand := overlayCommand(first, nil)
	result, err := manager.Apply(context.Background(), firstCommand)
	if err != nil || result.State != StateHealthy || result.Active.VersionID != first.OverlayVersionID {
		t.Fatalf("Apply(first) = (%+v, %v)", result, err)
	}
	beforeCalls, _ := probe.counts()
	replayed, err := manager.Apply(context.Background(), firstCommand)
	afterCalls, _ := probe.counts()
	if err != nil || replayed.State != StateHealthy || afterCalls != beforeCalls {
		t.Fatalf("idempotent replay = (%+v, %v), probes %d -> %d", replayed, err, beforeCalls, afterCalls)
	}

	second := snapshot(now, 2, entry("b.example.test", token("b"), now))
	secondCommand := overlayCommand(second, &Pointer{VersionID: first.OverlayVersionID, Revision: first.OverlayRevision})
	result, err = manager.Apply(context.Background(), secondCommand)
	if err != nil || result.State != StateHealthy || result.Active.VersionID != second.OverlayVersionID {
		t.Fatalf("Apply(cleanup) = (%+v, %v)", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, "acme-http01", "current", "a.example.test", token("a"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed token remains readable: %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(root, "acme-http01", "current", "b.example.test", token("b"))); err != nil || string(content) != value(token("b")) {
		t.Fatalf("remaining token = %q, %v", content, err)
	}
	_, notFound := probe.counts()
	if notFound == 0 {
		t.Fatal("cleanup activation did not verify removed token as 404")
	}
}

func TestManagerHealthFailureRestoresPreviousCompleteSet(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, probe, now)
	first := snapshot(now, 1, entry("a.example.test", token("a"), now))
	if _, err := manager.Apply(context.Background(), overlayCommand(first, nil)); err != nil {
		t.Fatal(err)
	}
	second := snapshot(now, 2, entry("b.example.test", token("b"), now))
	probe.failValue = value(token("b"))
	command := overlayCommand(second, &Pointer{VersionID: first.OverlayVersionID, Revision: first.OverlayRevision})
	command.Health.ActivationTimeout = 40 * time.Millisecond
	result, err := manager.Apply(context.Background(), command)
	if !errors.Is(err, ErrHealthFailed) || result.State != StateReverted || result.Active.VersionID != first.OverlayVersionID {
		t.Fatalf("Apply(failing) = (%+v, %v)", result, err)
	}
	if content, readErr := os.ReadFile(filepath.Join(root, "acme-http01", "current", "a.example.test", token("a"))); readErr != nil || string(content) != value(token("a")) {
		t.Fatalf("rollback token = %q, %v", content, readErr)
	}
}

func TestManagerCatchesUpAcrossMissedRevisions(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, probe, now)
	first := snapshot(now, 1, entry("a.example.test", token("a"), now))
	if _, err := manager.Apply(context.Background(), overlayCommand(first, nil)); err != nil {
		t.Fatal(err)
	}

	latest := snapshot(now, 4, entry("b.example.test", token("b"), now))
	missedPrevious := Pointer{VersionID: uuid.NewString(), Revision: 3}
	result, err := manager.Apply(context.Background(), overlayCommand(latest, &missedPrevious))
	if err != nil || result.State != StateHealthy || result.Active.VersionID != latest.OverlayVersionID {
		t.Fatalf("Apply(catch-up) = (%+v, %v)", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, "acme-http01", "current", "a.example.test", token("a"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missed-revision catch-up retained old token: %v", err)
	}
}

func TestManagerAcceptsLatestEmptySnapshotAfterExpiredCommand(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, probe, now)
	expired := snapshot(now, 1, entry("a.example.test", token("a"), now))
	expired.Entries[0].ExpiresAt = now
	if _, err := manager.Apply(context.Background(), overlayCommand(expired, nil)); !errors.Is(err, ErrExpired) {
		t.Fatalf("Apply(expired) error = %v, want %v", err, ErrExpired)
	}

	cleanup := snapshot(now, 3)
	missedPrevious := Pointer{VersionID: uuid.NewString(), Revision: 2}
	result, err := manager.Apply(context.Background(), overlayCommand(cleanup, &missedPrevious))
	if err != nil || result.State != StateHealthy || result.Active.VersionID != cleanup.OverlayVersionID {
		t.Fatalf("Apply(latest cleanup) = (%+v, %v)", result, err)
	}
}

func TestManagerRejectsSameRevisionConflictAndReverseRevision(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, probe, now)
	current := snapshot(now, 3, entry("a.example.test", token("a"), now))
	if _, err := manager.Apply(context.Background(), overlayCommand(current, nil)); err != nil {
		t.Fatal(err)
	}

	conflict := snapshot(now, 3, entry("b.example.test", token("b"), now))
	if _, err := manager.Apply(context.Background(), overlayCommand(conflict, nil)); !errors.Is(err, ErrConflict) {
		t.Fatalf("Apply(same revision conflict) error = %v, want %v", err, ErrConflict)
	}
	stale := snapshot(now, 2)
	if _, err := manager.Apply(context.Background(), overlayCommand(stale, nil)); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("Apply(reverse revision) error = %v, want %v", err, ErrStaleAttempt)
	}
}

func TestManagerResumesMissedRevisionCatchUpAfterActivationCrash(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, probe, now)
	first := snapshot(now, 1, entry("a.example.test", token("a"), now))
	if _, err := manager.Apply(context.Background(), overlayCommand(first, nil)); err != nil {
		t.Fatal(err)
	}

	latest := snapshot(now, 4, entry("b.example.test", token("b"), now))
	missedPrevious := Pointer{VersionID: uuid.NewString(), Revision: 3}
	command := overlayCommand(latest, &missedPrevious)
	manager.afterPhase = func(phase executionPhase) error {
		if phase == phaseHealth {
			return errors.New("simulated process crash")
		}
		return nil
	}
	if _, err := manager.Apply(context.Background(), command); err == nil {
		t.Fatal("activation crash injection did not interrupt Apply")
	}

	restarted := overlayTestManager(t, root, probe, now)
	result, err := restarted.Apply(context.Background(), command)
	if err != nil || result.State != StateHealthy || result.Active.VersionID != latest.OverlayVersionID {
		t.Fatalf("Apply(restarted catch-up) = (%+v, %v)", result, err)
	}
}

func TestManagerResumesAfterPrecheckAndActivationCrashes(t *testing.T) {
	for _, crashPhase := range []executionPhase{phasePrecheck, phaseHealth} {
		t.Run(string(crashPhase), func(t *testing.T) {
			root := overlayTestRoot(t)
			probe := &filesystemProbe{root: root}
			now := time.Now().UTC().Truncate(time.Second)
			manager := overlayTestManager(t, root, probe, now)
			manager.afterPhase = func(phase executionPhase) error {
				if phase == crashPhase {
					return errors.New("simulated process crash")
				}
				return nil
			}
			document := snapshot(now, 1, entry("a.example.test", token("a"), now))
			command := overlayCommand(document, nil)
			if _, err := manager.Apply(context.Background(), command); err == nil {
				t.Fatal("crash injection did not interrupt Apply")
			}
			pointerBefore, _ := os.Readlink(filepath.Join(root, "acme-http01", "current"))
			restarted := overlayTestManager(t, root, probe, now)
			result, err := restarted.Apply(context.Background(), command)
			if err != nil || result.State != StateHealthy {
				t.Fatalf("restart Apply = (%+v, %v)", result, err)
			}
			if crashPhase == phaseHealth {
				pointerAfter, _ := os.Readlink(filepath.Join(root, "acme-http01", "current"))
				if pointerBefore == "" || pointerAfter != pointerBefore {
					t.Fatalf("activated pointer changed across recovery: %q -> %q", pointerBefore, pointerAfter)
				}
			}
		})
	}
}

func TestManagerRecoversActivatedCleanupAfterCommandDeadline(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	clock := time.Now().UTC().Truncate(time.Second)
	newManager := func() *Manager {
		manager, err := NewManagerWithConfig(root, Config{
			Probe: probe, ProbeAddress: "127.0.0.1:80", RequestTimeout: time.Second,
			Now: func() time.Time { return clock },
		})
		if err != nil {
			t.Fatal(err)
		}
		return manager
	}
	manager := newManager()
	first := snapshot(clock, 1, entry("a.example.test", token("a"), clock))
	firstResult, err := manager.Apply(context.Background(), overlayCommand(first, nil))
	if err != nil {
		t.Fatal(err)
	}
	cleanup := snapshot(clock, 2)
	command := overlayCommand(cleanup, &firstResult.Active)
	manager.afterPhase = func(phase executionPhase) error {
		if phase == phaseHealth {
			return errors.New("simulated process crash after activation")
		}
		return nil
	}
	if _, err := manager.Apply(context.Background(), command); err == nil {
		t.Fatal("activation crash injection did not interrupt Apply")
	}
	pointer, err := manager.Current()
	if err != nil || pointer.VersionID != cleanup.OverlayVersionID {
		t.Fatalf("cleanup was not active at crash: (%+v, %v)", pointer, err)
	}
	clock = command.Deadline.Add(time.Second)
	result, err := newManager().Apply(context.Background(), command)
	if err != nil || result.State != StateHealthy || result.Active.VersionID != cleanup.OverlayVersionID {
		t.Fatalf("expired cleanup recovery = (%+v, %v)", result, err)
	}
}

func TestManagerRejectsNewCommandAfterDeadline(t *testing.T) {
	root := overlayTestRoot(t)
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, &filesystemProbe{root: root}, now)
	document := snapshot(now, 1, entry("a.example.test", token("a"), now))
	command := overlayCommand(document, nil)
	command.Deadline = now
	if _, err := manager.Apply(context.Background(), command); !errors.Is(err, ErrExpired) {
		t.Fatalf("Apply() error = %v, want ErrExpired", err)
	}
	if pointer, err := manager.Current(); err != nil || pointer.VersionID != "" {
		t.Fatalf("expired new command changed current: (%+v, %v)", pointer, err)
	}
}

func TestManagerSharesDeploymentActivationFlock(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, probe, now)
	lock, err := os.OpenFile(filepath.Join(root, "state", "activation.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, applyErr := manager.Apply(context.Background(), overlayCommand(snapshot(now, 1, entry("a.example.test", token("a"), now)), nil))
		done <- applyErr
	}()
	select {
	case err := <-done:
		t.Fatalf("Apply bypassed shared activation lock: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	if calls, _ := probe.counts(); calls != 0 {
		t.Fatalf("probe ran while deployment lock was held: %d", calls)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Apply did not resume after deployment lock release")
	}
}

func TestDecodeSnapshotRejectsMalformedTamperedAndExpiredEntries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := snapshot(now, 1, entry("a.example.test", token("a"), now))
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		want   error
	}{
		{"host", func(value *Snapshot) { value.Entries[0].Host = "A.example.test" }, ErrInvalidSnapshot},
		{"token", func(value *Snapshot) { value.Entries[0].Token = "../token" }, ErrInvalidSnapshot},
		{"value", func(value *Snapshot) { value.Entries[0].Value = "wrong" }, ErrInvalidSnapshot},
		{"expired", func(value *Snapshot) { value.Entries[0].ExpiresAt = now }, ErrExpired},
		{"unordered", func(value *Snapshot) {
			value.Entries = []Entry{entry("b.example.test", token("b"), now), entry("a.example.test", token("a"), now)}
		}, ErrInvalidSnapshot},
		{"duplicate", func(value *Snapshot) { value.Entries = append(value.Entries, value.Entries[0]) }, ErrInvalidSnapshot},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Entries = append([]Entry(nil), valid.Entries...)
			test.mutate(&candidate)
			if err := ValidateSnapshot(candidate, now); !errors.Is(err, test.want) {
				t.Fatalf("ValidateSnapshot() error = %v, want %v", err, test.want)
			}
		})
	}
	encoded, err := CanonicalSnapshot(valid)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)
	if _, err := DecodeSnapshot(encoded, now); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestManagerRejectsTamperedOrNonClosedCurrentRelease(t *testing.T) {
	tests := map[string]func(*testing.T, string, Snapshot){
		"manifest snapshot digest": func(t *testing.T, release string, _ Snapshot) {
			path := filepath.Join(release, releaseManifestFile)
			var manifest releaseManifest
			content, err := os.ReadFile(path)
			if err != nil || json.Unmarshal(content, &manifest) != nil {
				t.Fatal("read manifest")
			}
			manifest.SnapshotSHA256 = strings.Repeat("0", sha256.Size*2)
			rewriteReleaseFile(t, path, manifest)
		},
		"snapshot bytes": func(t *testing.T, release string, document Snapshot) {
			document.GeneratedAt = document.GeneratedAt.Add(time.Second)
			rewriteReleaseFile(t, filepath.Join(release, releaseSnapshotFile), document)
		},
		"challenge value": func(t *testing.T, release string, document Snapshot) {
			path := filepath.Join(release, document.Entries[0].Host, document.Entries[0].Token)
			rewriteReleaseBytes(t, path, []byte("tampered"))
		},
		"extra token": func(t *testing.T, release string, document Snapshot) {
			host := filepath.Join(release, document.Entries[0].Host)
			if err := os.Chmod(host, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(host, token("x")), []byte(value(token("x"))), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(host, 0o500); err != nil {
				t.Fatal(err)
			}
		},
		"extra host": func(t *testing.T, release string, _ Snapshot) {
			if err := os.Chmod(release, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(release, "extra.example.test"), 0o500); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(release, 0o500); err != nil {
				t.Fatal(err)
			}
		},
		"declared token symlink": func(t *testing.T, release string, document Snapshot) {
			host := filepath.Join(release, document.Entries[0].Host)
			path := filepath.Join(host, document.Entries[0].Token)
			if err := os.Chmod(host, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(releaseSnapshotFile, path); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(host, 0o500); err != nil {
				t.Fatal(err)
			}
		},
		"declared token hardlink": func(t *testing.T, release string, document Snapshot) {
			host := filepath.Join(release, document.Entries[0].Host)
			path := filepath.Join(host, document.Entries[0].Token)
			external := filepath.Join(filepath.Dir(release), "hardlink-source")
			if err := os.WriteFile(external, []byte(document.Entries[0].Value), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(host, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(external, path); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			if err := os.Chmod(host, 0o500); err != nil {
				t.Fatal(err)
			}
		},
		"declared token permission": func(t *testing.T, release string, document Snapshot) {
			if err := os.Chmod(filepath.Join(release, document.Entries[0].Host, document.Entries[0].Token), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"declared token type": func(t *testing.T, release string, document Snapshot) {
			host := filepath.Join(release, document.Entries[0].Host)
			path := filepath.Join(host, document.Entries[0].Token)
			if err := os.Chmod(host, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o500); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(host, 0o500); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root := overlayTestRoot(t)
			now := time.Now().UTC().Truncate(time.Second)
			manager := overlayTestManager(t, root, &filesystemProbe{root: root}, now)
			document := snapshot(now, 1, entry("a.example.test", token("a"), now))
			if _, err := manager.Apply(context.Background(), overlayCommand(document, nil)); err != nil {
				t.Fatal(err)
			}
			release := filepath.Join(root, "acme-http01", "releases", document.OverlayVersionID)
			mutate(t, release, document)
			if _, err := manager.Current(); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("Current() error = %v, want ErrCorruptState", err)
			}
			if manager.Ready() {
				t.Fatal("tampered current release remained ready")
			}
		})
	}
}

func rewriteReleaseFile(t *testing.T, path string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	rewriteReleaseBytes(t, path, content)
}

func rewriteReleaseBytes(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
}

func overlayTestRoot(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(base, func(path string, _ os.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	root := filepath.Join(base, "deployment")
	for _, path := range []string{root, filepath.Join(root, "state"), filepath.Join(root, "releases"), filepath.Join(root, "releases", "cfg-v1")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The site runtime renders the fixed route into every HTTP server; this
	// is the release's nginx.conf as far as the overlay store reads it.
	nginx := "http {\n  server {\n    listen 18081;\n" + edgeconfig.RenderACMEHTTP01Location(root) + "  }\n}\n"
	if err := os.WriteFile(filepath.Join(root, "releases", "cfg-v1", "nginx.conf"), []byte(nginx), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", "cfg-v1"), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	return root
}

func overlayTestManager(t *testing.T, root string, probe Probe, now time.Time) *Manager {
	t.Helper()
	manager, err := NewManagerWithConfig(root, Config{Probe: probe, ProbeAddress: "127.0.0.1:80", RequestTimeout: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.Ready() {
		t.Fatal("manager did not recognize the generated fixed route")
	}
	return manager
}

func snapshot(now time.Time, revision uint64, entries ...Entry) Snapshot {
	return Snapshot{
		SchemaVersion: ArtifactSchemaVersion, OverlayVersionID: uuid.NewString(), OverlayRevision: revision,
		GeneratedAt: now, Entries: entries,
	}
}

func entry(host, token string, now time.Time) Entry {
	return Entry{Host: host, Token: token, Value: value(token), ExpiresAt: now.Add(time.Hour)}
}

func token(seed string) string {
	return seed + "234567890123456789012345678901234567890123"
}

func value(token string) string {
	return token + ".abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
}

func overlayCommand(document Snapshot, previous *Pointer) Command {
	artifact, _ := CanonicalSnapshot(document)
	artifactDigest := sha256.Sum256(artifact)
	purpose := PurposeApply
	if document.Purpose == PurposeCleanupOnly {
		purpose = PurposeCleanupOnly
	}
	command := Command{
		DeploymentID: uuid.NewString(), Attempt: 1, OverlayVersionID: document.OverlayVersionID,
		OverlayRevision: document.OverlayRevision, ArtifactSHA256: artifactDigest, Purpose: purpose,
		CommandSHA256: sha256.Sum256([]byte(document.OverlayVersionID)), Snapshot: document,
		Health:   HealthPolicy{ActivationTimeout: time.Second, RequiredConsecutiveSuccesses: 1},
		Deadline: document.GeneratedAt.Add(time.Hour),
	}
	if previous != nil {
		command.PreviousVersionID = &previous.VersionID
		command.PreviousRevision = &previous.Revision
	}
	return command
}

// FX05①: OpenResty workers do not run as the agent's user: they may only
// traverse the overlay tree and read token files; listing, the manifest and
// the snapshot stay private.
func TestManagerReleaseIsReadableByWorkersOnlyWhereServed(t *testing.T) {
	root := overlayTestRoot(t)
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, &filesystemProbe{root: root}, now)
	document := snapshot(now, 1, entry("a.example.test", token("a"), now))
	if _, err := manager.Apply(context.Background(), overlayCommand(document, nil)); err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(root, "acme-http01", "releases", document.OverlayVersionID)
	for path, want := range map[string]os.FileMode{
		filepath.Join(root, "acme-http01"):             0o711,
		filepath.Join(root, "acme-http01", "releases"): 0o711,
		release:                                  0o511,
		filepath.Join(release, "a.example.test"): 0o511,
		filepath.Join(release, "a.example.test", document.Entries[0].Token): 0o444,
		filepath.Join(release, releaseManifestFile):                         0o400,
		filepath.Join(release, releaseSnapshotFile):                         0o400,
		filepath.Join(root, "acme-http01", "state"):                         0o700,
	} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v (%v)", path, info.Mode().Perm(), want, err)
		}
	}
	if !manager.Ready() {
		t.Fatal("manager not ready after reopening modes")
	}
}

// ADR-0003 CLEANUP_ONLY: the signed snapshot names the purpose and carries no
// token; applying it removes every token the node still serves. A purpose
// that disagrees with the artifact, or a cleanup_only snapshot with tokens,
// is rejected before anything is staged.
func TestManagerCleanupOnlyRemovesEveryTokenAndBindsPurpose(t *testing.T) {
	root := overlayTestRoot(t)
	probe := &filesystemProbe{root: root}
	now := time.Now().UTC().Truncate(time.Second)
	manager := overlayTestManager(t, root, probe, now)
	first := snapshot(now, 1, entry("a.example.test", token("a"), now))
	if _, err := manager.Apply(context.Background(), overlayCommand(first, nil)); err != nil {
		t.Fatal(err)
	}
	previous := &Pointer{VersionID: first.OverlayVersionID, Revision: first.OverlayRevision}

	withToken := snapshot(now, 2, entry("b.example.test", token("b"), now))
	withToken.Purpose = PurposeCleanupOnly
	if _, err := manager.Apply(context.Background(), overlayCommand(withToken, previous)); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("cleanup_only snapshot with a token: %v", err)
	}
	cleanup := snapshot(now, 3)
	cleanup.Purpose = PurposeCleanupOnly
	relabeled := overlayCommand(cleanup, previous)
	relabeled.Purpose = PurposeApply
	if _, err := manager.Apply(context.Background(), relabeled); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("apply command over a cleanup_only artifact: %v", err)
	}
	applyArtifact := overlayCommand(snapshot(now, 4), previous)
	applyArtifact.Purpose = PurposeCleanupOnly
	if _, err := manager.Apply(context.Background(), applyArtifact); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("cleanup_only command over an apply artifact: %v", err)
	}
	missing := overlayCommand(snapshot(now, 5), previous)
	missing.Purpose = ""
	if _, err := manager.Apply(context.Background(), missing); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("command without a purpose: %v", err)
	}
	if current, err := manager.Current(); err != nil || current.VersionID != first.OverlayVersionID {
		t.Fatalf("rejected commands moved the pointer: %+v %v", current, err)
	}

	result, err := manager.Apply(context.Background(), overlayCommand(cleanup, previous))
	if err != nil || result.State != StateHealthy || result.Active.VersionID != cleanup.OverlayVersionID {
		t.Fatalf("Apply(cleanup_only) = (%+v, %v)", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, "acme-http01", "current", "a.example.test", token("a"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup_only left a token readable: %v", err)
	}
	if _, notFound := probe.counts(); notFound == 0 {
		t.Fatal("cleanup_only activation did not verify the removed token as 404")
	}
	// The stored release keeps its signed purpose across a restart.
	reopened := overlayTestManager(t, root, probe, now)
	if current, err := reopened.Current(); err != nil || current.VersionID != cleanup.OverlayVersionID {
		t.Fatalf("reopened pointer %+v %v", current, err)
	}
}

func TestDecodeSnapshotRejectsUnknownPurpose(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, purpose := range []string{"apply", "CLEANUP_ONLY", "serve"} {
		document := snapshot(now, 1)
		document.Purpose = purpose
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeSnapshot(encoded, now); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("purpose %q accepted: %v", purpose, err)
		}
	}
}
