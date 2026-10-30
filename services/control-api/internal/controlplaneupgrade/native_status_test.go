//go:build !windows

package controlplaneupgrade

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeStatusRequiresProcessIdentityOwnershipAndFreshness(t *testing.T) {
	fixture := newNativeFixture(t)
	filename := filepath.Join(fixture.runner.executor.config.ReleaseRoot, "runner-status.json")
	if err := fixture.runner.PublishStatus(t.Context(), filename); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Getuid())
	status, err := readNativeStandaloneStatus(filename, fixture.installationID(), fixture.runner.runner.now(), owner, fixture.commands.inspect)
	if err != nil || !status.Ready {
		t.Fatalf("valid status: %+v %v", status, err)
	}
	for _, reason := range []string{"expired", "future", "pid reused", "wrong binary", "wrong installation", "wrong owner", "world readable", "symlink", "busy ready"} {
		t.Run(reason, func(t *testing.T) {
			copy := status
			currentTime := fixture.runner.runner.now()
			expectedOwner := owner
			path := filepath.Join(filepath.Dir(filename), "case-"+strings.ReplaceAll(reason, " ", "-")+".json")
			mode := os.FileMode(0o640)
			switch reason {
			case "expired":
				currentTime = currentTime.Add(31 * time.Second)
			case "future":
				currentTime = currentTime.Add(-2 * time.Second)
			case "pid reused":
				copy.StartID = "boot:reused"
			case "wrong binary":
				copy.RunnerExeSHA256 = strings.Repeat("a", 64)
			case "wrong installation":
				copy.InstallationID = "different"
			case "wrong owner":
				expectedOwner++
			case "world readable":
				mode = 0o644
			case "busy ready":
				copy.Busy = true
			}
			encoded, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			if reason == "symlink" {
				if err := os.Symlink(filename, path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, encoded, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := readNativeStandaloneStatus(path, fixture.installationID(), currentTime, expectedOwner, fixture.commands.inspect); err == nil {
				t.Fatal("untrusted runner status accepted")
			}
		})
	}
	if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runner.PublishStatus(t.Context(), filename); err != nil {
		t.Fatal(err)
	}
	state, err := readNativeStandaloneState(filename+".state.json", owner)
	if err != nil || state.Receipt == nil || state.Receipt.Result != ResultApplied || state.Receipt.Target != TargetNativeStandalone {
		t.Fatalf("read-only receipt snapshot: %+v %v", state, err)
	}
	info, err := os.Stat(filepath.Join(fixture.runner.runner.store.root, stateFilename))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("publishing status weakened private state permissions")
	}
}

func TestNativeMaintenanceGateFailsClosedAndDrainsExistingWrites(t *testing.T) {
	fixture := newNativeFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	gate, err := newNativeMaintenanceGate(NativeMaintenanceGateConfig{Enabled: true, File: fixture.runner.executor.config.MaintenanceFile,
		InstallationID: fixture.installationID()}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/write" {
			close(entered)
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	}), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	requestDone := make(chan struct{})
	go func() {
		gate.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/write", nil))
		close(requestDone)
	}()
	<-entered
	plan, err := fixture.runner.runner.verifyBundle(fixture.bundle)
	if err != nil {
		t.Fatal(err)
	}
	drainDone := make(chan error, 1)
	go func() { drainDone <- fixture.runner.executor.Drain(t.Context(), plan) }()
	select {
	case err := <-drainDone:
		t.Fatalf("drain ignored in-flight write: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	<-requestDone
	if err := <-drainDone; err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusNoContent {
		t.Fatalf("existing write=%d", response.Code)
	}
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/v1/admin/status", http.StatusNoContent},
		{http.MethodHead, "/health/ready", http.StatusNoContent},
		{http.MethodPost, "/v1/admin/sites", http.StatusServiceUnavailable},
		{http.MethodPost, "/v1/internal/not-a-recovery-endpoint", http.StatusServiceUnavailable},
		{http.MethodDelete, "/v1/admin/sites/one", http.StatusServiceUnavailable},
	} {
		response := httptest.NewRecorder()
		gate.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != test.status {
			t.Fatalf("%s %s = %d", test.method, test.path, response.Code)
		}
	}
	if err := os.WriteFile(fixture.runner.executor.config.MaintenanceFile, []byte(`{"phase":"active"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	gate.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/admin/sites", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("corrupt maintenance state did not fail closed")
	}
}

func TestNativeProductionProcessEvidenceReadsOnlyOwnLinuxProcess(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires a Linux root process for actual /proc evidence")
	}
	process, err := inspectNativeProcess(os.Getpid())
	if err != nil || !digestPattern.MatchString(process.digest) || !strings.Contains(process.startID, ":") {
		t.Fatalf("real root process evidence: %+v %v", process, err)
	}
	if _, err := inspectNativeProcess(-1); err == nil {
		t.Fatal("missing process accepted")
	}
}

func TestNativeStatusPublicationKeepsUnreadyEvidenceWithoutStoppingRecovery(t *testing.T) {
	fixture := newNativeFixture(t)
	fixture.commands.mixed = true
	filename := filepath.Join(fixture.runner.executor.config.ReleaseRoot, "runner-status.json")
	if err := fixture.runner.PublishStatus(t.Context(), filename); err != nil {
		t.Fatal(err)
	}
	status, err := readNativeStandaloneStatus(filename, fixture.installationID(), fixture.runner.runner.now(), uint32(os.Getuid()), fixture.commands.inspect)
	if err != nil || status.Ready {
		t.Fatalf("unready evidence: %+v %v", status, err)
	}
	if _, err := ReadNativeStandaloneState(filepath.Join(fixture.runner.executor.config.ReleaseRoot, "missing-state")); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("missing state not safely rejected: %v", err)
	}
}
