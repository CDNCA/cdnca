package cachefreshness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPublisherPrecheckFailureLeavesCurrentAndLKG(t *testing.T) {
	fixture := newPublisherFixture(t)
	fixture.apply(t, 1)
	first := fixture.readCurrent(t)
	currentBefore := fixture.pointer(t, "current")
	lkgBefore := fixture.pointer(t, "lkg")
	fixture.runtime.precheckError = errors.New("bad candidate")

	policy := validPolicy()
	policy.PolicyVersion = 2
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrPrecheck) {
		t.Fatalf("ApplyJSON error = %v, want ErrPrecheck", err)
	}
	if fixture.pointer(t, "current") != currentBefore || fixture.pointer(t, "lkg") != lkgBefore {
		t.Fatal("precheck failure changed current or LKG")
	}
	if got := fixture.readCurrent(t); string(got) != string(first) {
		t.Fatal("precheck failure partially overwrote current config")
	}
}

func TestPublisherActivationFailureRollsBackAtomically(t *testing.T) {
	fixture := newPublisherFixture(t)
	fixture.apply(t, 1)
	first := fixture.readCurrent(t)
	fixture.runtime.activateErrorAt = 2

	policy := validPolicy()
	policy.PolicyVersion = 2
	raw, _ := json.Marshal(policy)
	if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrActivate) {
		t.Fatalf("ApplyJSON error = %v, want ErrActivate", err)
	}
	if got := fixture.readCurrent(t); string(got) != string(first) {
		t.Fatal("activation failure did not restore the previous complete config")
	}
	if fixture.pointer(t, "current") != fixture.pointer(t, "lkg") {
		t.Fatal("activation failure left current and LKG divergent")
	}
	if fixture.runtime.lastActivatedVersion() != 1 {
		t.Fatalf("rollback activated version %d, want 1", fixture.runtime.lastActivatedVersion())
	}
}

func TestPublisherHealthFailureRollsBackAndSameVersionIsIdempotent(t *testing.T) {
	fixture := newPublisherFixture(t)
	first := fixture.apply(t, 1)
	replayed := fixture.apply(t, 1)
	if replayed.Changed || replayed.Digest != first.Digest {
		t.Fatalf("idempotent replay = %#v", replayed)
	}

	fixture.runtime.healthErrorAt = 2
	policy := validPolicy()
	policy.PolicyVersion = 2
	raw, _ := json.Marshal(policy)
	if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrHealth) {
		t.Fatalf("ApplyJSON error = %v, want ErrHealth", err)
	}
	if fixture.runtime.lastActivatedVersion() != 1 {
		t.Fatal("health failure did not reactivate LKG")
	}
}

func TestPublisherCancellationAndInvalidPolicyDoNotTouchRuntime(t *testing.T) {
	fixture := newPublisherFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	raw, _ := json.Marshal(validPolicy())
	if _, err := fixture.publisher.ApplyJSON(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ApplyJSON error = %v", err)
	}
	if fixture.runtime.callCount() != 0 {
		t.Fatal("canceled publication called runtime")
	}

	policy := validPolicy()
	policy.TenantID = "bad|tenant"
	raw, _ = json.Marshal(policy)
	if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid ApplyJSON error = %v", err)
	}
	if fixture.runtime.callCount() != 0 {
		t.Fatal("invalid publication called runtime")
	}
}

func TestPublisherReplayRejectsTamperedRelease(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*testing.T, *publisherFixture, string)
	}{
		{
			name: "symlinked config",
			tamper: func(t *testing.T, fixture *publisherFixture, release string) {
				content, err := os.ReadFile(filepath.Join(release, configFilename))
				if err != nil {
					t.Fatal(err)
				}
				external := filepath.Join(t.TempDir(), configFilename)
				if err := os.WriteFile(external, content, 0o400); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(release, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(release, configFilename)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, filepath.Join(release, configFilename)); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(release, 0o500); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "extra file",
			tamper: func(t *testing.T, _ *publisherFixture, release string) {
				if err := os.Chmod(release, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(release, "unexpected"), []byte("tampered\n"), 0o400); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(release, 0o500); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "writable release",
			tamper: func(t *testing.T, _ *publisherFixture, release string) {
				if err := os.Chmod(release, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlinked policy",
			tamper: func(t *testing.T, _ *publisherFixture, release string) {
				external := filepath.Join(t.TempDir(), policyFilename)
				if err := os.Link(filepath.Join(release, policyFilename), external); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublisherFixture(t)
			fixture.apply(t, 1)
			release := filepath.Join(fixture.root, fixture.pointer(t, "current"))
			test.tamper(t, fixture, release)
			policy := validPolicy()
			policy.PolicyVersion = 1
			raw, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("ApplyJSON tampered replay error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestPublisherHistoricalHeadSurvivesRollbackAndMissingLatestRelease(t *testing.T) {
	fixture := newPublisherFixture(t)
	fixture.apply(t, 1)
	fixture.runtime.activateErrorAt = 2
	policy := validPolicy()
	policy.PolicyVersion = 2
	raw, _ := json.Marshal(policy)
	if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrActivate) {
		t.Fatalf("ApplyJSON version 2 error = %v, want ErrActivate", err)
	}
	versionTwo := filepath.Join(fixture.root, "versions", versionDirectory(2))
	if err := os.Chmod(versionTwo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(versionTwo); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.activateErrorAt = 0
	policy.PolicyVersion = 1
	raw, _ = json.Marshal(policy)
	if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("reinsert below historical head error = %v, want ErrInvalidPolicy", err)
	}
	head, err := os.ReadFile(filepath.Join(fixture.root, "historical-head"))
	if err != nil {
		t.Fatalf("read historical head: %v", err)
	}
	if string(head) != "00000000000000000002\n" {
		t.Fatalf("historical head = %q", head)
	}
}

func TestPublisherRollbackRejectsTamperedPreviousBeforePointerOrActivate(t *testing.T) {
	fixture := newPublisherFixture(t)
	fixture.apply(t, 1)
	previous := filepath.Join(fixture.root, fixture.pointer(t, "current"))
	if err := os.Chmod(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(previous, "unexpected"), []byte("tampered\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(previous, 0o500); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.activateErrorAt = 2
	policy := validPolicy()
	policy.PolicyVersion = 2
	raw, _ := json.Marshal(policy)
	if _, err := fixture.publisher.ApplyJSON(context.Background(), raw); !errors.Is(err, ErrRollback) {
		t.Fatalf("ApplyJSON with tampered previous error = %v, want ErrRollback", err)
	}
	if fixture.pointer(t, "current") != filepath.Join("versions", versionDirectory(2)) {
		t.Fatal("rollback changed current before validating the previous release")
	}
	if fixture.runtime.lastActivatedVersion() != 1 {
		t.Fatal("rollback activated the tampered previous release")
	}
}

func TestPublisherRecoversValidPostRenameReleaseAndCleansStaging(t *testing.T) {
	fixture := newPublisherFixture(t)
	fixture.apply(t, 1)
	residue := filepath.Join(fixture.root, "staging", ".cache-freshness-residue")
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(residue, "partial"), []byte("partial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := validPolicy()
	policy.PolicyVersion = 2
	artifact, err := Compile(policy, fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(fixture.root, "versions", versionDirectory(2))
	if err := fixture.publisher.stageRelease(context.Background(), release, artifact); err != nil {
		t.Fatalf("stage simulated post-rename release: %v", err)
	}
	raw, _ := json.Marshal(policy)
	publication, err := fixture.publisher.ApplyJSON(context.Background(), raw)
	if err != nil {
		t.Fatalf("recover post-rename release: %v", err)
	}
	if !publication.Changed || publication.PolicyVersion != 2 {
		t.Fatalf("recovered publication = %#v", publication)
	}
	entries, err := os.ReadDir(filepath.Join(fixture.root, "staging"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging residue remains: %v", entries)
	}
}

func TestPublisherRecoversValidatedPostRenameReleaseBeforeDirectorySeal(t *testing.T) {
	fixture := newPublisherFixture(t)
	fixture.apply(t, 1)
	policy := validPolicy()
	policy.PolicyVersion = 2
	artifact, err := Compile(policy, fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(fixture.root, "versions", versionDirectory(2))
	if err := os.Mkdir(release, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		policyFilename: artifact.CanonicalPolicy,
		configFilename: artifact.Nginx,
		digestFilename: []byte(fmt.Sprintf("%x\n", artifact.Digest)),
	} {
		if err := writeExclusive(filepath.Join(release, name), content); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(policy)
	publication, err := fixture.publisher.ApplyJSON(context.Background(), raw)
	if err != nil {
		t.Fatalf("recover unsealed post-rename release: %v", err)
	}
	if !publication.Changed || fixture.pointer(t, "current") != filepath.Join("versions", versionDirectory(2)) {
		t.Fatalf("recovered publication = %#v", publication)
	}
	info, err := os.Stat(release)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o500 {
		t.Fatalf("recovered release mode = %04o, want 0500", info.Mode().Perm())
	}
}

func TestPublisherRecoversCurrentPointerAheadOfRuntime(t *testing.T) {
	for _, test := range []struct {
		name          string
		activateFails bool
		wantErr       error
		wantVersion   uint64
		wantChanged   bool
		wantTarget    string
	}{
		{
			name:        "activate interrupted target",
			wantVersion: 2,
			wantChanged: true,
			wantTarget:  filepath.Join("versions", versionDirectory(2)),
		},
		{
			name:          "rollback when interrupted target cannot activate",
			activateFails: true,
			wantErr:       ErrActivate,
			wantVersion:   1,
			wantTarget:    filepath.Join("versions", versionDirectory(1)),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublisherFixture(t)
			fixture.apply(t, 1)
			policy := validPolicy()
			policy.PolicyVersion = 2
			artifact, err := Compile(policy, fixture.paths)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join("versions", versionDirectory(2))
			if err := fixture.publisher.stageRelease(context.Background(), filepath.Join(fixture.root, target), artifact); err != nil {
				t.Fatalf("stage interrupted target: %v", err)
			}
			if err := fixture.publisher.setPointer("current", target); err != nil {
				t.Fatalf("simulate current pointer switch: %v", err)
			}
			if test.activateFails {
				fixture.runtime.activateErrorAt = 2
			}
			raw, _ := json.Marshal(policy)
			publication, err := fixture.publisher.ApplyJSON(context.Background(), raw)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ApplyJSON error = %v, want %v", err, test.wantErr)
			}
			if publication.Changed != test.wantChanged {
				t.Fatalf("publication changed = %t, want %t", publication.Changed, test.wantChanged)
			}
			if got := fixture.runtime.lastActivatedVersion(); got != test.wantVersion {
				t.Fatalf("runtime version = %d, want %d", got, test.wantVersion)
			}
			if current, lkg := fixture.pointer(t, "current"), fixture.pointer(t, "lkg"); current != test.wantTarget || lkg != test.wantTarget {
				t.Fatalf("current/lkg = %q/%q, want %q", current, lkg, test.wantTarget)
			}
		})
	}
}

type publisherFixture struct {
	t         *testing.T
	root      string
	paths     RuntimePaths
	runtime   *fakeRuntime
	publisher *Publisher
}

func newPublisherFixture(t *testing.T) *publisherFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "releases")
	paths := RuntimePaths{StateRoot: filepath.Join(t.TempDir(), "state"), LuaRoot: "/opt/cdnca-cache-freshness"}
	runtime := &fakeRuntime{}
	publisher, err := NewPublisher(root, paths, runtime)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, _ error) error {
			if entry != nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	return &publisherFixture{t: t, root: root, paths: paths, runtime: runtime, publisher: publisher}
}

func (fixture *publisherFixture) apply(t *testing.T, version uint64) Publication {
	t.Helper()
	policy := validPolicy()
	policy.PolicyVersion = version
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := fixture.publisher.ApplyJSON(context.Background(), raw)
	if err != nil {
		t.Fatalf("ApplyJSON version %d: %v", version, err)
	}
	return publication
}

func (fixture *publisherFixture) pointer(t *testing.T, name string) string {
	t.Helper()
	target, err := os.Readlink(filepath.Join(fixture.root, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return target
}

func (fixture *publisherFixture) readCurrent(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(fixture.root, "current", configFilename))
	if err != nil {
		t.Fatalf("read current config: %v", err)
	}
	return content
}

type fakeRuntime struct {
	mu              sync.Mutex
	precheckError   error
	activateErrorAt uint64
	healthErrorAt   uint64
	calls           []string
	activated       []uint64
}

func (runtime *fakeRuntime) Precheck(_ context.Context, _ string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.calls = append(runtime.calls, "precheck")
	return runtime.precheckError
}

func (runtime *fakeRuntime) Activate(_ context.Context, _ string, version uint64) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.calls = append(runtime.calls, "activate")
	if version == runtime.activateErrorAt {
		return errors.New("activate")
	}
	runtime.activated = append(runtime.activated, version)
	return nil
}

func (runtime *fakeRuntime) Healthy(_ context.Context, version uint64) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.calls = append(runtime.calls, "healthy")
	if version == runtime.healthErrorAt {
		return errors.New("unhealthy")
	}
	return nil
}

func (runtime *fakeRuntime) Stop(context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.calls = append(runtime.calls, "stop")
	return nil
}

func (runtime *fakeRuntime) callCount() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return len(runtime.calls)
}

func (runtime *fakeRuntime) lastActivatedVersion() uint64 {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.activated) == 0 {
		return 0
	}
	return runtime.activated[len(runtime.activated)-1]
}
