package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/nativeruntime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

// node-runtime-upgrade: on a native node the upgrade health probe fails with
// the runtime switch's code until the runtime of this release is active.
func TestNativeRuntimeHealthReportsSwitchStatus(t *testing.T) {
	config := fileConfig{JournalDir: filepath.Join(t.TempDir(), "gateway-journal")}
	config.SecurityRuntime.Mode = securityRuntimeModeNative
	if code := nativeruntime.Code(nativeRuntimeHealth(config)); code != nativeruntime.CodeStatusAbsent {
		t.Fatalf("no status: code %q", code)
	}
	write := func(status nativeruntime.Status) {
		path := nativeRuntimeStatusPath(config)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		status.Schema = nativeruntime.StatusSchema
		raw := []byte(`{"schema":"` + status.Schema + `","state":"` + status.State + `","agent_version":"` + status.AgentVersion +
			`","error_code":"` + status.ErrorCode + `","at":"2026-10-24T00:00:00Z"}`)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(nativeruntime.Status{State: nativeruntime.StateFailed, AgentVersion: agentVersion, ErrorCode: nativeruntime.CodePrecheck})
	if code := nativeruntime.Code(nativeRuntimeHealth(config)); code != nativeruntime.CodePrecheck {
		t.Fatalf("failed switch: code %q", code)
	}
	write(nativeruntime.Status{State: nativeruntime.StateSwitched, AgentVersion: agentVersion})
	if err := nativeRuntimeHealth(config); err != nil {
		t.Fatalf("switched runtime: %v", err)
	}
	// Container nodes have no native runtime to check.
	if err := nativeRuntimeHealth(fileConfig{JournalDir: config.JournalDir}); err != nil {
		t.Fatalf("container node: %v", err)
	}
}

func TestUpgradeProbeFailsWithRuntimeCode(t *testing.T) {
	installer := &fakeCurrentInstaller{}
	probe := upgradeReceiptProbe{installer: installer, runVersion: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("the version must not run after a runtime failure")
		return nil, nil
	}, nativeRuntime: func() error {
		return nativeruntime.HealthError(nativeruntime.Status{State: nativeruntime.StateFailed, AgentVersion: agentVersion,
			ErrorCode: nativeruntime.CodeReload}, agentVersion)
	}}
	err := probe.Check(context.Background(), installer.receipt, []string{"{artifact}", "--version"})
	if nativeruntime.Code(err) != nativeruntime.CodeReload {
		t.Fatalf("probe error %v", err)
	}
}

type fakeCurrentInstaller struct {
	updater.Installer
	receipt updater.ActivationReceipt
}

func (f *fakeCurrentInstaller) Current(context.Context) (updater.ActivationReceipt, error) {
	return f.receipt, nil
}

// node-runtime-upgrade: the heartbeat's EdgeRuntimeStatus.native_runtime.
func TestNativeRuntimeReportMapsSwitchStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native-runtime", "status.json")
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	write := func(status nativeruntime.Status) {
		status.Schema = nativeruntime.StatusSchema
		raw, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if report := nativeRuntimeReport(path); report != nil {
		t.Fatalf("no status: %v", report)
	}
	for _, test := range []struct {
		name   string
		status nativeruntime.Status
		want   *agentv1.NativeRuntimeStatus
	}{
		{"switched", nativeruntime.Status{State: nativeruntime.StateSwitched, AgentVersion: agentVersion, Release: b, PreviousRelease: a},
			&agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_SWITCHED, Release: b, PreviousRelease: a}},
		{"unchanged", nativeruntime.Status{State: nativeruntime.StateUnchanged, AgentVersion: agentVersion, Release: a},
			&agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNCHANGED, Release: a}},
		{"failed", nativeruntime.Status{State: nativeruntime.StateFailed, AgentVersion: agentVersion, Release: b, PreviousRelease: a,
			ErrorCode: nativeruntime.CodePrecheck},
			&agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK, Release: b, PreviousRelease: a,
				ErrorCode: nativeruntime.CodePrecheck}},
		{"agent rolled back", nativeruntime.Status{State: nativeruntime.StateUnchanged, AgentVersion: agentVersion, Release: a,
			RolledBack: &nativeruntime.Rollback{AgentVersion: "9.9.9", Release: b, ErrorCode: nativeruntime.CodeReload}},
			&agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK, Release: b, PreviousRelease: a,
				ErrorCode: nativeruntime.CodeReload}},
		{"values outside the wire format are left out", nativeruntime.Status{State: nativeruntime.StateFailed, AgentVersion: agentVersion,
			Release: "releases/x", ErrorCode: "bad code"},
			&agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK}},
		{"another Agent", nativeruntime.Status{State: nativeruntime.StateSwitched, AgentVersion: "9.9.9", Release: b}, nil},
	} {
		write(test.status)
		if got := nativeRuntimeReport(path); !proto.Equal(got, test.want) || (got == nil) != (test.want == nil) {
			t.Errorf("%s: got %v, want %v", test.name, got, test.want)
		}
	}
}
