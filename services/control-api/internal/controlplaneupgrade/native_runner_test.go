//go:build !windows

package controlplaneupgrade

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

func TestNativeStandaloneAppliesCompleteReleaseAndReplaysWithoutRestart(t *testing.T) {
	fixture := newNativeFixture(t)
	status, err := fixture.runner.Probe(t.Context())
	if err != nil || !status.Ready || status.CurrentArtifactSHA256 != fixture.old.Digest {
		t.Fatalf("probe: %+v %v", status, err)
	}
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if err != nil || receipt.Result != ResultApplied || receipt.Target != TargetNativeStandalone {
		t.Fatalf("apply: %+v %v", receipt, err)
	}
	fixture.assertLinks(t, fixture.next.Digest, fixture.old.Digest)
	state, err := readNativeMaintenance(fixture.runner.executor.config.MaintenanceFile, fixture.installationID(), uint32(os.Getuid()))
	if err != nil || state.Phase != "active" || fixture.commands.restarts != 1 {
		t.Fatalf("maintenance=%+v err=%v restarts=%d", state, err, fixture.commands.restarts)
	}
	if second, err := fixture.runner.Run(t.Context(), fixture.bundle); err != nil || !second.Replayed || second.ID != receipt.ID || fixture.commands.restarts != 1 {
		t.Fatalf("replay: %+v %v", second, err)
	}
	status, err = fixture.runner.Probe(t.Context())
	if err != nil || !status.Ready || status.CurrentVersion != "1.5.0" || status.CurrentArtifactSHA256 == nativeFile(fixture.manifests[fixture.next.Digest], "bin/control-api").SHA256 {
		t.Fatalf("post apply probe: %+v %v", status, err)
	}
}

func TestNativeStandaloneRejectsInvalidSignatureLayoutAncestryAndMigrationsBeforeDrain(t *testing.T) {
	for _, reason := range []string{"signature", "mixed layout", "source ancestry", "source non ancestor", "migration changed", "migration added", "missing legacy asset"} {
		t.Run(reason, func(t *testing.T) {
			fixture := newNativeFixture(t)
			switch reason {
			case "signature":
				fixture.bundle[len(fixture.bundle)-2] ^= 1
			case "mixed layout":
				fixture.commands.mixed = true
			default:
				candidate := fixture.manifests[fixture.next.Digest]
				files := fixture.contents[fixture.next.Digest]
				switch reason {
				case "source ancestry":
					candidate.Source.Commit = strings.Repeat("f", 40)
				case "source non ancestor":
					command := exec.Command("git", "--git-dir="+fixture.runner.executor.config.SourceGitDirectory,
						"-c", "user.name=Native Test", "-c", "user.email=native@example.invalid", "commit-tree", candidate.Source.Tree, "-m", "unrelated root")
					output, err := command.CombinedOutput()
					if err != nil {
						t.Fatalf("create isolated unrelated commit: %v %s", err, output)
					}
					candidate.Source.Commit = strings.TrimSpace(string(output))
				case "migration changed":
					files["migrations/001.up.sql"] = []byte("ALTER TABLE real_data DROP COLUMN required;")
				case "migration added":
					files["migrations/002.up.sql"] = []byte("SELECT 2;")
				case "missing legacy asset":
					delete(files, "static/web/assets/old-hash.js")
				}
				fixture.replaceCandidate(t, candidate, files)
			}
			if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err == nil {
				t.Fatal("unsafe candidate accepted")
			}
			current, _, err := fixture.runner.executor.current()
			state, stateErr := readNativeMaintenance(fixture.runner.executor.config.MaintenanceFile, fixture.installationID(), uint32(os.Getuid()))
			if err != nil || current.Digest != fixture.old.Digest || stateErr != nil || state.Phase != "active" || fixture.commands.restarts != 0 {
				t.Fatalf("preflight mutated live deployment: current=%+v state=%+v err=%v/%v", current, state, err, stateErr)
			}
		})
	}
}

func TestNativeStandaloneHealthFailureRollsBackWholeRelease(t *testing.T) {
	fixture := newNativeFixture(t)
	fixture.commands.failHealth = fixture.next.Digest
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if !errors.Is(err, ErrRolledBack) || receipt.Result != ResultRolledBack || receipt.ErrorCode != "target_health_failed" {
		t.Fatalf("rollback: %+v %v", receipt, err)
	}
	fixture.assertLinks(t, fixture.old.Digest, fixture.old.Digest)
	if fixture.commands.restarts != 2 {
		t.Fatalf("both services must restart on activate and rollback: %d", fixture.commands.restarts)
	}
	if _, err := os.Stat(fixture.runner.executor.release(fixture.next)); err != nil {
		t.Fatal("failed immutable release must remain for audit")
	}
	status, err := fixture.runner.Probe(t.Context())
	if err != nil || !status.Ready {
		t.Fatalf("rollback not healthy: %+v %v", status, err)
	}
}

func TestNativeStandaloneResumesActivationAndResumeCrashBoundaries(t *testing.T) {
	for _, phase := range []Phase{PhaseDrained, PhaseContracted} {
		t.Run(string(phase), func(t *testing.T) {
			fixture := newNativeFixture(t)
			plan, err := fixture.runner.runner.verifyBundle(fixture.bundle)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range []func(context.Context, Plan) error{fixture.runner.executor.Expand, fixture.runner.executor.Preflight, fixture.runner.executor.Drain, fixture.runner.executor.Activate} {
				if err := step(t.Context(), plan); err != nil {
					t.Fatal(err)
				}
			}
			if phase == PhaseContracted {
				if err := fixture.runner.executor.Resume(t.Context(), plan); err != nil {
					t.Fatal(err)
				}
			}
			if err := fixture.runner.runner.store.Save(State{Schema: StateSchema, PlanID: plan.ID, BundleSHA256: plan.BundleSHA256,
				Sequence: plan.Sequence, Phase: phase, PreviousDigest: fixture.old.Digest, TargetDigest: fixture.next.Digest}); err != nil {
				t.Fatal(err)
			}
			receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
			if err != nil || receipt.Result != ResultApplied {
				t.Fatalf("recovery after %s side effect: %+v %v", phase, receipt, err)
			}
		})
	}
}

func TestNativeStandaloneLocksAndBusyStatus(t *testing.T) {
	fixture := newNativeFixture(t)
	if _, err := newNativeStandaloneRunner(fixture.runner.executor.config, fixture.runner.runner.trust, fixture.runner.runner.store,
		fixture.runner.runner.now, uint32(os.Getuid()), fixture.commands, fixture.commands.inspect); !errors.Is(err, ErrPlanInProgress) {
		t.Fatalf("second runner accepted: %v", err)
	}
	lock, err := openNativeLock(fixture.runner.executor.config.LockPath, uint32(os.Getuid()), true)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runner.Run(t.Context(), fixture.bundle); !errors.Is(err, ErrPlanInProgress) {
		t.Fatalf("release lock ignored: %v", err)
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	fixture.runner.busy.Store(true)
	status, err := fixture.runner.Probe(t.Context())
	fixture.runner.busy.Store(false)
	if err != nil || status.Ready || !status.Busy || status.Reason != "control_upgrade_draining" {
		t.Fatalf("busy probe: %+v %v", status, err)
	}
}

func TestNativeStandaloneRequiresPlanSourceReadConfirmation(t *testing.T) {
	fixture := newNativeFixture(t)
	for _, probe := range []func() bool{nil, func() bool { return false }} {
		fixture.runner.executor.config.PlanSourceReady = probe
		status, err := fixture.runner.Probe(t.Context())
		if err != nil || status.Ready || status.Reason != "control_upgrade_runner_unconfirmed" {
			t.Fatalf("unconfirmed plan source claimed ready: %+v %v", status, err)
		}
	}
}

func TestNativePreflightRejectsFalseReadinessAndUnownedChanges(t *testing.T) {
	for index, body := range []string{"", "<html>OK</html>", `{"status":"not_ready"}`, `{"status":"ready","unexpected":true}`, `{"status":"ready","status":"not_ready"}`} {
		t.Run(fmt.Sprintf("readiness%d", index), func(t *testing.T) {
			fixture := newNativeFixture(t)
			fixture.commands.healthBody = &body
			if status, err := fixture.runner.Probe(t.Context()); err == nil || status.Ready {
				t.Fatalf("false readiness accepted: %+v %v", status, err)
			}
		})
	}
	for _, reason := range []string{"existing unowned changed", "new unowned path"} {
		t.Run(reason, func(t *testing.T) {
			fixture := newNativeFixture(t)
			candidate := fixture.manifests[fixture.next.Digest]
			files := fixture.contents[fixture.next.Digest]
			if reason == "existing unowned changed" {
				files["bin/license-worker"] = []byte("replaced without ownership")
			} else {
				files["config/override.env"] = []byte("UNSAFE_OVERRIDE=1")
			}
			fixture.replaceCandidate(t, candidate, files)
			if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err == nil || fixture.commands.restarts != 0 {
				t.Fatalf("unowned path accepted: %v", err)
			}
		})
	}
}

func TestNativeDirectoryManifestMustMatchSignedTarAndMode(t *testing.T) {
	for _, change := range []string{"source", "mode"} {
		t.Run(change, func(t *testing.T) {
			fixture := newNativeFixture(t)
			path := filepath.Join(fixture.runner.executor.release(fixture.old), NativeManifestFilename)
			if change == "mode" {
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				manifest := fixture.manifests[fixture.old.Digest]
				manifest.Source.Commit = strings.Repeat("e", 40)
				encoded, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encoded, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if status, err := fixture.runner.Probe(t.Context()); err == nil || status.Ready {
				t.Fatalf("tampered physical manifest accepted: %+v %v", status, err)
			}
		})
	}
}

func TestNativeStageFsyncFailureCannotActivate(t *testing.T) {
	fixture := newNativeFixture(t)
	var synced []string
	fixture.runner.executor.syncDir = func(path string) error {
		synced = append(synced, path)
		return errors.New("injected stage directory sync failure")
	}
	if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err == nil || len(synced) == 0 || fixture.commands.restarts != 0 {
		t.Fatalf("unsynced stage activated: synced=%v err=%v", synced, err)
	}
	current, err := os.Readlink(filepath.Join(fixture.runner.executor.config.ReleaseRoot, "current"))
	if err != nil || filepath.Base(current) != fixture.old.Digest {
		t.Fatalf("current changed: %s %v", current, err)
	}
	if _, err := os.Stat(fixture.runner.executor.release(fixture.next)); !os.IsNotExist(err) {
		t.Fatal("failed stage published immutable target")
	}
	var ordered []string
	if err := syncNativeDirectories(fixture.runner.executor.release(fixture.old), func(path string) error { ordered = append(ordered, path); return nil }); err != nil {
		t.Fatal(err)
	}
	for index := 1; index < len(ordered); index++ {
		if strings.Count(ordered[index], string(filepath.Separator)) > strings.Count(ordered[index-1], string(filepath.Separator)) {
			t.Fatalf("directories not synced child-first: %v", ordered)
		}
	}
}

func TestNativeArtifactDownloadVerifiesTarBeforePublishing(t *testing.T) {
	for _, outcome := range []string{"valid", "tampered", "short body", "not found", "http rejected"} {
		t.Run(outcome, func(t *testing.T) {
			fixture := newNativeFixture(t)
			filename := filepath.Join(fixture.runner.executor.config.ReleaseRoot, "artifacts", fixture.next.Digest+".tar")
			encoded, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filename); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if outcome == "not found" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				body := append([]byte(nil), encoded...)
				if outcome == "tampered" {
					body[0] ^= 1
				}
				if outcome == "short body" {
					body = body[:len(body)-1024]
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			fixture.runner.executor.client = server.Client()
			artifact := fixture.next
			artifact.URL = server.URL + "/full.tar"
			if outcome == "http rejected" {
				artifact.URL = strings.Replace(artifact.URL, "https:", "http:", 1)
			}
			_, err = fixture.runner.executor.ensureArchive(t.Context(), artifact)
			if outcome == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filename); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unverified download accepted")
			} else if _, err := os.Stat(filename); !os.IsNotExist(err) {
				t.Fatal("failed download published as an artifact")
			}
		})
	}
}

func TestNativeArtifactNetworkErrorDoesNotExposeSignedURL(t *testing.T) {
	fixture := newNativeFixture(t)
	filename := filepath.Join(fixture.runner.executor.config.ReleaseRoot, "artifacts", fixture.next.Digest+".tar")
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	fixture.runner.executor.client = &http.Client{Transport: nativeFailTransport{}}
	artifact := fixture.next
	artifact.URL = "https://release.example.invalid/full.tar?token=never-emit-test-credential"
	_, err := fixture.runner.executor.ensureArchive(t.Context(), artifact)
	if err == nil || strings.Contains(err.Error(), "never-emit") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("download URL leaked: %v", err)
	}
	if !errors.Is(err, ErrArtifactUnavailable) || errors.Is(err, ErrCandidateRejected) {
		t.Fatalf("network failure must stay retryable: %v", err)
	}
}

func TestNativeDefaultClientHasNoWholeRequestTimeout(t *testing.T) {
	// A 100MB release at ~1.4MB/s takes over a minute; the step context bounds it.
	fixture := newNativeFixture(t)
	if fixture.runner.executor.config.HTTPClient != nil || fixture.runner.executor.client.Timeout != 0 {
		t.Fatalf("default client timeout = %s", fixture.runner.executor.client.Timeout)
	}
}

func TestNativeRejectedLineageFailsTerminallyAndLeavesRunnerReady(t *testing.T) {
	fixture := newNativeFixture(t)
	candidate := fixture.manifests[fixture.next.Digest]
	// Same shape as a fresh-install package: its predecessor is not current.
	candidate.Source.PreviousCommit = strings.Repeat("8", 40)
	fixture.replaceCandidate(t, candidate, fixture.contents[fixture.next.Digest])
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if !errors.Is(err, ErrTargetMismatch) || receipt.Result != ResultFailed || receipt.ErrorCode != "expand_failed" {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	if current, _, err := fixture.runner.executor.current(); err != nil || current.Digest != fixture.old.Digest {
		t.Fatalf("rejected candidate changed current: %+v %v", current, err)
	}
	status, err := fixture.runner.Probe(t.Context())
	if err != nil || !status.Ready || status.Busy {
		t.Fatalf("probe after terminal rejection: %+v %v", status, err)
	}
}

func TestNativeProbeReadyWhileFailedCheckpointAwaitsSupersede(t *testing.T) {
	fixture := newNativeFixture(t)
	if err := fixture.runner.runner.store.Save(State{Schema: StateSchema, PlanID: "00000000-0000-4000-8000-000000000099",
		BundleSHA256: digestBytes([]byte("stuck")), Sequence: 41, Phase: PhaseVerified, ErrorCode: "expand_failed",
		PreviousDigest: fixture.old.Digest}); err != nil {
		t.Fatal(err)
	}
	status, err := fixture.runner.Probe(t.Context())
	if err != nil || !status.Ready || status.Busy {
		t.Fatalf("probe with failed checkpoint: %+v %v", status, err)
	}
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if err != nil || receipt.Result != ResultApplied {
		t.Fatalf("superseding plan: %+v %v", receipt, err)
	}
}

type nativeFailTransport struct{}

func (nativeFailTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

type nativeFixture struct {
	runner    *NativeStandaloneRunner
	commands  *nativeCommands
	old, next Artifact
	manifests map[string]NativeManifest
	contents  map[string]map[string][]byte
	bundle    []byte
}

func (fixture nativeFixture) installationID() string {
	return fixture.runner.executor.config.InstallationID
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	return newNativeFixtureWith(t, nil)
}

// newNativeFixtureWith lets a test change each release's files (index 0 is
// current, 1 the candidate) before the archives are built.
func newNativeFixtureWith(t *testing.T, mutate func(index int, files map[string][]byte)) *nativeFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "native")
	for _, directory := range []string{root, filepath.Join(root, "releases"), filepath.Join(root, "artifacts")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gitDirectory := filepath.Join(base, "source")
	if err := os.Mkdir(gitDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(arguments ...string) string {
		command := exec.Command("git", append([]string{"-C", gitDirectory}, arguments...)...)
		command.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture git: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "--quiet")
	git("-c", "user.name=Native Test", "-c", "user.email=native@example.invalid", "commit", "--allow-empty", "--quiet", "-m", "baseline")
	oldCommit, oldTree := git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
	git("-c", "user.name=Native Test", "-c", "user.email=native@example.invalid", "commit", "--allow-empty", "--quiet", "-m", "candidate")
	nextCommit, nextTree := git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
	fixture := &nativeFixture{manifests: map[string]NativeManifest{}, contents: map[string]map[string][]byte{}}
	for index, version := range []string{"1.4.0", "1.5.0"} {
		manifest, files := nativeManifestFixture()
		manifest.Version, manifest.Platform.Arch = version, runtime.GOARCH
		manifest.Source = NativeSource{Commit: oldCommit, Tree: oldTree, PreviousCommit: strings.Repeat("c", 40)}
		if index == 1 {
			manifest.Source = NativeSource{Commit: nextCommit, Tree: nextTree, PreviousCommit: oldCommit}
		}
		files["bin/control-api"], files["bin/agent-gateway"] = nativeELF(version+"control"), nativeELF(version+"gateway")
		files["static/web/index.html"] = []byte("<html>" + version + "</html>")
		files["static/web/assets/old-hash.js"] = []byte("window.legacy = true;")
		files["bin/license-worker"] = []byte("unchanged non-owned worker")
		if mutate != nil {
			mutate(index, files)
		}
		manifest.Files = nativeFilesForTest(files)
		filename, artifact := nativeArchiveFixture(t, manifest, files, nil)
		artifact.Version, artifact.Sequence = version, uint64(41+index)
		encoded, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "artifacts", artifact.Digest+".tar"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.manifests[artifact.Digest], fixture.contents[artifact.Digest] = manifest, files
		if index == 0 {
			fixture.old = artifact
			release := filepath.Join(root, "releases", artifact.Digest)
			reader := tar.NewReader(bytes.NewReader(encoded))
			for {
				header, err := reader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				content, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := nativeStageFile(release, header.Name, content, uint32(header.Mode)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(release, filepath.Join(root, "current")); err != nil {
				t.Fatal(err)
			}
		} else {
			fixture.next = artifact
		}
	}
	fixture.commands = &nativeCommands{root: root, active: fixture.old.Digest, manifests: fixture.manifests}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.commands.mu.Lock()
		defer fixture.commands.mu.Unlock()
		if fixture.commands.failHealth == fixture.commands.active {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/index.html" {
			served := fixture.commands.active
			if fixture.commands.staleIndex != "" {
				served = fixture.commands.staleIndex
			}
			_, _ = w.Write(fixture.contents[served]["static/web/index.html"])
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if fixture.commands.healthBody != nil {
			_, _ = io.WriteString(w, *fixture.commands.healthBody)
			return
		}
		_, _ = io.WriteString(w, `{"status":"ready"}`)
	}))
	t.Cleanup(server.Close)
	baseRunner := newRunnerFixture(t)
	maintenance := filepath.Join(root, "maintenance.json")
	if err := writeNativeMaintenance(maintenance, baseRunner.runner.config.InstallationID, "active", "", baseRunner.runner.now()); err != nil {
		t.Fatal(err)
	}
	config := NativeStandaloneConfig{InstallationID: baseRunner.runner.config.InstallationID, ProtocolVersion: 2, ReleaseRoot: root,
		LockPath: filepath.Join(root, "release.lock"), SourceGitDirectory: filepath.Join(gitDirectory, ".git"),
		ControlUnit: "cdnca-control-api.service", GatewayUnit: "cdnca-agent-gateway.service",
		ControlHealthURL: server.URL + "/control", GatewayHealthURL: server.URL + "/gateway", WebIndexURL: server.URL + "/index.html",
		MaintenanceFile: maintenance, PollInterval: time.Millisecond, StepTimeout: time.Second, HealthTimeout: 40 * time.Millisecond}
	config.PlanSourceReady = func() bool { return true }
	store, err := NewFileStore(filepath.Join(root, "runner-state"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.runner, err = newNativeStandaloneRunner(config, baseRunner.runner.trust, store, baseRunner.runner.now, uint32(os.Getuid()), fixture.commands, fixture.commands.inspect)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.runner.Close() })
	fixture.bundle = nativeSignedBundle(t, baseRunner.encoded, fixture.old, fixture.next)
	return fixture
}

func (fixture *nativeFixture) replaceCandidate(t *testing.T, manifest NativeManifest, files map[string][]byte) {
	manifest.Files = nativeFilesForTest(files)
	filename, artifact := nativeArchiveFixture(t, manifest, files, nil)
	artifact.Version, artifact.Sequence = manifest.Version, 42
	encoded, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.runner.executor.config.ReleaseRoot, "artifacts", artifact.Digest+".tar"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.next = artifact
	fixture.manifests[artifact.Digest], fixture.contents[artifact.Digest] = manifest, files
	fixture.bundle = nativeSignedBundle(t, fixture.bundle, fixture.old, artifact)
}

func (fixture *nativeFixture) assertLinks(t *testing.T, current, previous string) {
	t.Helper()
	for name, want := range map[string]string{"current": current, "previous": previous} {
		actual, err := os.Readlink(filepath.Join(fixture.runner.executor.config.ReleaseRoot, name))
		if err != nil || filepath.Base(actual) != want {
			t.Fatalf("%s=%s err=%v", name, actual, err)
		}
	}
}

func nativeFilesForTest(files map[string][]byte) []NativeFile {
	items := make([]NativeFile, 0, len(files))
	for name, content := range files {
		mode := uint32(0o644)
		if strings.HasPrefix(name, "bin/") {
			mode = 0o755
		}
		items = append(items, NativeFile{Path: name, SHA256: digestBytes(content), Bytes: int64(len(content)), Mode: mode})
	}
	// A canonical path order is part of the manifest contract.
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func nativeELF(marker string) []byte {
	value := make([]byte, 64)
	copy(value, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(value[16:], 2)
	machine := uint16(62)
	if runtime.GOARCH == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(value[18:], machine)
	binary.LittleEndian.PutUint32(value[20:], 1)
	binary.LittleEndian.PutUint16(value[52:], 64)
	return append(value, []byte(marker)...)
}

type nativeCommands struct {
	mu                       sync.Mutex
	root, active, failHealth string
	manifests                map[string]NativeManifest
	restarts                 int
	stops                    int
	stopped                  map[string]bool
	mixed                    bool
	healthBody               *string
	// staleIndex, when set, is the release whose index.html the web keeps serving.
	staleIndex string
	// journal maps a unit to the lines journalctl prints; others fail.
	journal      map[string][]string
	journalCalls []string
	// clickhouse records each configure-clickhouse.py call with the release
	// current pointed at; clickhouseOutput answers by "check"/"apply".
	clickhouse       []nativeClickHouseCall
	clickhouseOutput map[string]string
}

type nativeClickHouseCall struct {
	args    []string
	current string
}

func (commands *nativeCommands) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "git" {
		return (execCommands{}).Run(ctx, name, args...)
	}
	commands.mu.Lock()
	defer commands.mu.Unlock()
	if name == "systemctl" && args[0] == "restart" {
		link, err := os.Readlink(filepath.Join(commands.root, "current"))
		commands.active = filepath.Base(link)
		commands.restarts++
		commands.stopped = nil
		return nil, err
	}
	if name == "systemctl" && args[0] == "stop" {
		if commands.stopped == nil {
			commands.stopped = map[string]bool{}
		}
		commands.stopped[args[len(args)-1]] = true
		commands.stops++
		return nil, nil
	}
	if name == "systemctl" && args[0] == "show" && args[2] == "--property=ActiveState,MainPID" {
		if commands.stopped[args[len(args)-1]] {
			return []byte("ActiveState=inactive\nMainPID=0\n"), nil
		}
		return []byte("ActiveState=active\nMainPID=601\n"), nil
	}
	if name == "systemctl" && args[0] == "show" {
		if commands.stopped[args[len(args)-1]] {
			return []byte("ExecStart=\nMainPID=0\nActiveState=inactive\nSubState=dead\n"), nil
		}
		binary, pid := "bin/control-api", 601
		if strings.Contains(args[len(args)-1], "gateway") {
			binary, pid = "bin/agent-gateway", 602
		}
		path := filepath.Join(commands.root, "current", binary)
		if commands.mixed {
			path = "/usr/local/bin/control-api"
		}
		return []byte(fmt.Sprintf("ExecStart={ path=%s ; argv[]=%s serve ; }\nMainPID=%d\nActiveState=active\nSubState=running\n", path, path, pid)), nil
	}
	if name == "journalctl" {
		commands.journalCalls = append(commands.journalCalls, strings.Join(args, " "))
		unit, found := strings.CutPrefix(args[len(args)-1], "--unit=")
		if lines, ok := commands.journal[unit]; found && ok {
			return []byte(strings.Join(lines, "\n") + "\n"), nil
		}
		return []byte("No journal files were found.\n"), errors.New("journal unavailable")
	}
	if len(args) == 1 && args[0] == "--version" {
		return []byte("1.5.0\n"), nil
	}
	if name == "python3" {
		link, _ := os.Readlink(filepath.Join(commands.root, "current"))
		commands.clickhouse = append(commands.clickhouse, nativeClickHouseCall{args: append([]string(nil), args...), current: filepath.Base(link)})
		mode, output := "apply", `{"status": "migrations_applied", "pending": [], "applied": []}`
		if args[len(args)-1] == "--check" {
			mode, output = "check", `{"status": "migrations_checked", "pending": [], "applied": []}`
		}
		if configured, ok := commands.clickhouseOutput[mode]; ok {
			output = configured
		}
		if strings.Contains(output, `"migration_failed"`) {
			return []byte(output + "\n"), errors.New("exit status 1")
		}
		return []byte(output + "\n"), nil
	}
	return nil, fmt.Errorf("unexpected native command %s", name)
}

func (commands *nativeCommands) inspect(pid int) (nativeProcess, error) {
	commands.mu.Lock()
	defer commands.mu.Unlock()
	if pid == os.Getpid() {
		return nativeProcess{startID: "boot:123", digest: strings.Repeat("d", 64)}, nil
	}
	name := "bin/control-api"
	if pid == 602 {
		name = "bin/agent-gateway"
	}
	return nativeProcess{startID: fmt.Sprintf("boot:%d", pid), digest: nativeFile(commands.manifests[commands.active], name).SHA256}, nil
}

func nativeSignedBundle(t *testing.T, original []byte, old, next Artifact) []byte {
	t.Helper()
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(original)
	if err != nil {
		t.Fatal(err)
	}
	signer := runnerTestSigner{privateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))}
	set := func(destination *entitlement.UpgradePlanArtifact, artifact Artifact) {
		digest, err := hex.DecodeString(artifact.Digest)
		if err != nil {
			t.Fatal(err)
		}
		destination.Manifest.Version = artifact.Version
		destination.Manifest.SHA256Digest = base64.RawURLEncoding.EncodeToString(digest)
		destination.Manifest.ArtifactSizeBytes = artifact.Size
		signature, err := entitlement.SignArtifactManifestV3(t.Context(), destination.Manifest, signer)
		if err != nil {
			t.Fatal(err)
		}
		destination.ManifestSignature = base64.RawURLEncoding.EncodeToString(signature)
	}
	set(&signed.Bundle.Forward, next)
	set(&signed.Bundle.Rollback, old)
	resigned, err := entitlement.SignUpgradePlanArtifactBundle(t.Context(), signed.Bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := resigned.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// 10-22 73: an operator certificate that does not chain to the system roots
// (a temporary self-signed one while Let's Encrypt is rate limited) left the
// console index check failing forever, so the runner never became ready.
func TestNativeWebCAFileTrustsOperatorCertificateForConsoleIndexOnly(t *testing.T) {
	fixture := newNativeFixture(t)
	index := fixture.contents[fixture.old.Digest]["static/web/index.html"]
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(index) }))
	t.Cleanup(server.Close)
	config, store, trust := fixture.runner.executor.config, fixture.runner.runner.store, fixture.runner.runner.trust
	if err := fixture.runner.Close(); err != nil {
		t.Fatal(err)
	}
	config.WebIndexURL = server.URL + "/dashboard/"
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(directory, "web-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o444); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Getuid())
	open := func(caFile string) (*NativeStandaloneRunner, error) {
		config := config
		config.WebCAFile = caFile
		return newNativeStandaloneRunner(config, trust, store, fixture.runner.runner.now, owner, fixture.commands, fixture.commands.inspect)
	}

	// Unset keeps the system roots: the self-signed console is not trusted.
	runner, err := open("")
	if err != nil {
		t.Fatal(err)
	}
	if status, err := runner.Probe(t.Context()); err == nil || status.Ready {
		t.Fatalf("system roots must reject the operator certificate: %+v %v", status, err)
	}
	_ = runner.Close()

	runner, err = open(caFile)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	if status, err := runner.Probe(t.Context()); err != nil || !status.Ready || status.Reason != "ready" {
		t.Fatalf("operator CA must make the runner ready: %+v %v", status, err)
	}
	// Only the console index uses the operator CA; artifact and health requests keep the default client.
	if runner.executor.client.Transport != nil || runner.executor.webClient == runner.executor.client ||
		runner.executor.webClient.CheckRedirect == nil {
		t.Fatalf("web CA leaked into the shared client")
	}
}

func TestNativeWebCAFileRejectsUnsafeOrInvalidFiles(t *testing.T) {
	fixture := newNativeFixture(t)
	config, store, trust := fixture.runner.executor.config, fixture.runner.runner.store, fixture.runner.runner.trust
	if err := fixture.runner.Close(); err != nil {
		t.Fatal(err)
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	server.Close()
	valid := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for name, prepare := range map[string]func(string) string{
		"relative": func(string) string { return "web-ca.pem" },
		"missing":  func(path string) string { return path },
		"writable": func(path string) string { mustWriteMode(t, path, valid, 0o666); return path },
		"not pem":  func(path string) string { mustWriteMode(t, path, []byte("not a certificate\n"), 0o444); return path },
		"key block": func(path string) string {
			mustWriteMode(t, path, append(append([]byte{}, valid...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})...), 0o444)
			return path
		},
		"symlink": func(path string) string {
			target := path + ".target"
			mustWriteMode(t, target, valid, 0o444)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			return path
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := config
			config.WebCAFile = prepare(filepath.Join(directory, strings.ReplaceAll(name, " ", "-")+".pem"))
			runner, err := newNativeStandaloneRunner(config, trust, store, fixture.runner.runner.now, uint32(os.Getuid()), fixture.commands, fixture.commands.inspect)
			if !errors.Is(err, ErrInvalidConfig) {
				if runner != nil {
					_ = runner.Close()
				}
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func mustWriteMode(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
