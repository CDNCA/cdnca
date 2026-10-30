//go:build !windows

package controlplaneupgrade

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSystemdExecutorStagesAtomicBinaryAndRollsBack(t *testing.T) {
	oldBinary := []byte("old-control-api")
	newBinary := []byte("new-control-api")
	oldDigest := fmt.Sprintf("%x", sha256.Sum256(oldBinary))
	newDigest := fmt.Sprintf("%x", sha256.Sum256(newBinary))
	artifactServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write(newBinary)
	}))
	defer artifactServer.Close()
	var drainCalls []string
	healthVersion, healthDigest := "1.5.0", newDigest
	const internalToken = "internal-token-32-bytes-long-value"
	drainServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+internalToken {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		drainCalls = append(drainCalls, request.URL.Path)
		if request.Method == http.MethodGet {
			_, _ = fmt.Fprintf(writer, `{"phase":"draining","plan_id":"00000000-0000-4000-8000-000000000002","quorum":1,"replicas":[{"replica_id":"control-0","version":%q,"digest":%q,"observed_at":1800000000}]}`, healthVersion, healthDigest)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer drainServer.Close()

	root := t.TempDir()
	oldRelease := filepath.Join(root, "releases", oldDigest)
	if err := os.MkdirAll(oldRelease, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldRelease, "control-api"), oldBinary, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(oldRelease, filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	commands := &recordingCommands{outputs: map[string][]byte{"--version": []byte("1.5.0\n")}}
	executor, err := newSystemdExecutor(SystemdConfig{ReleaseRoot: root, CurrentLink: filepath.Join(root, "current"),
		UnitName: "cdnca-control-api.service", DrainURL: drainServer.URL + "/internal/upgrade/drain",
		ResumeURL: drainServer.URL + "/internal/upgrade/resume", HealthURL: drainServer.URL + "/ready",
		InstallationID: "00000000-0000-4000-8000-000000000005", CurrentVersion: "1.4.0", ProtocolVersion: 2,
		InternalToken: internalToken, HTTPClient: artifactServer.Client(), PollInterval: time.Millisecond,
		HealthTimeout: 50 * time.Millisecond}, commands)
	if err != nil {
		t.Fatal(err)
	}
	plan := adapterTestPlan(oldDigest, newDigest)
	plan.Target.URL = artifactServer.URL + "/control-api"
	plan.Target.Size = int64(len(newBinary))
	plan.Rollback.Size = int64(len(oldBinary))
	if err := executor.Expand(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := executor.Preflight(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := executor.Drain(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := executor.Activate(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := executor.Health(t.Context(), plan, plan.Target); err != nil {
		t.Fatal(err)
	}
	current, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || current != filepath.Join(root, "releases", newDigest) {
		t.Fatalf("current after activate = (%q, %v)", current, err)
	}
	if err := executor.Contract(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	oldBinaryPath := filepath.Join(oldRelease, "control-api")
	if err := os.Chmod(oldBinaryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldBinaryPath, []byte("tampered-old-control-api"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(oldBinaryPath, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := executor.Rollback(t.Context(), plan); !errors.Is(err, ErrPlanConflict) {
		t.Fatalf("tampered rollback error = %v", err)
	}
	current, err = os.Readlink(filepath.Join(root, "current"))
	if err != nil || current != filepath.Join(root, "releases", newDigest) {
		t.Fatalf("current after rejected rollback = (%q, %v)", current, err)
	}
	if err := os.Chmod(oldBinaryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldBinaryPath, oldBinary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(oldBinaryPath, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := executor.Rollback(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	current, err = os.Readlink(filepath.Join(root, "current"))
	if err != nil || current != oldRelease {
		t.Fatalf("current after rollback = (%q, %v)", current, err)
	}
	if err := executor.Resume(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if strings.Join(drainCalls, ",") != "/internal/upgrade/drain,/ready,/internal/upgrade/resume" {
		t.Fatalf("drain calls = %v", drainCalls)
	}
	joined := strings.Join(commands.calls, "\n")
	for _, required := range []string{"migrate up", "--version", "systemctl restart cdnca-control-api.service"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("commands omit %q: %s", required, joined)
		}
	}
}

type recordingCommands struct {
	calls   []string
	outputs map[string][]byte
}

func (commands *recordingCommands) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	commands.calls = append(commands.calls, strings.Join(append([]string{name}, args...), " "))
	for suffix, output := range commands.outputs {
		if len(args) > 0 && args[len(args)-1] == suffix {
			return output, nil
		}
	}
	return nil, nil
}
