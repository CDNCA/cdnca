package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/http3runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

type http3RuntimeTestDelegate struct {
	prechecks int
	reloads   int
	healthy   int
}

func (delegate *http3RuntimeTestDelegate) Precheck(context.Context, string, string) error {
	delegate.prechecks++
	return nil
}

func (delegate *http3RuntimeTestDelegate) Reload(context.Context, string, string) error {
	delegate.reloads++
	return nil
}

func (delegate *http3RuntimeTestDelegate) Healthy(context.Context, string) error {
	delegate.healthy++
	return nil
}

type http3RuntimeTestManager struct {
	applied       []http3runtime.Policy
	status        http3runtime.Status
	substituteFor string
}

func (manager *http3RuntimeTestManager) Apply(_ context.Context, policy http3runtime.Policy) (http3runtime.Result, error) {
	manager.applied = append(manager.applied, policy)
	compiled, err := http3runtime.Compile(policy)
	if err != nil {
		return http3runtime.Result{}, err
	}
	manager.status = http3runtime.Status{Active: true, VersionID: policy.VersionID, Digest: compiled.Digest}
	if policy.VersionID == manager.substituteFor {
		manager.status.VersionID = "substitute-version"
	}
	return http3runtime.Result{
		VersionID: policy.VersionID, Digest: compiled.Digest, State: http3runtime.StateApplied,
		ActiveVersionID: policy.VersionID, ActiveDigest: compiled.Digest,
	}, nil
}

func (manager *http3RuntimeTestManager) Status() (http3runtime.Status, error) {
	return manager.status, nil
}

func TestHTTP3DeploymentBridgeUsesGenericLifecycleAndExactActiveIdentity(t *testing.T) {
	basePolicy := http3runtime.Policy{
		SchemaVersion: http3runtime.SchemaVersionV1,
		VersionID:     "config-v7",
		Protocols:     []string{"http1", "http2", "http3"},
		Runtime: http3runtime.RuntimeRef{
			Family: http3runtime.RuntimeFamilyOpenResty, Version: http3runtime.RuntimeVersionOpenResty,
		},
		Listener: http3runtime.Listener{
			Address: "0.0.0.0", Port: 8443, ServerName: "edge.example.test", AltSvcMaxAgeSeconds: 300,
		},
		TLS: http3runtime.TLSConfig{
			MinimumVersion: "TLSv1.3", CertificateFile: "/var/lib/cdnca/cert.pem",
			CertificateSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PrivateKeyFile:    "/var/lib/cdnca/key.pem",
			PrivateKeySHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		Limits: http3runtime.Limits{
			IdleTimeoutMS: 30_000, WorkerConnections: 128, ConnectionsPerClient: 8,
			ConcurrentStreams: 16, RequestHeaderBytes: 4_096, ActiveConnectionIDs: 4,
		},
	}
	delegate := &http3RuntimeTestDelegate{}
	http3Manager := &http3RuntimeTestManager{}
	bridge, err := newHTTP3DeploymentBridge(delegate, http3Manager)
	if err != nil {
		t.Fatal(err)
	}
	deploymentRoot := filepath.Join(t.TempDir(), "deployments")
	t.Cleanup(func() {
		_ = filepath.Walk(deploymentRoot, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	managerConfig := deployment.DefaultConfig()
	managerConfig.HealthTimeout = 20 * time.Millisecond
	managerConfig.HealthInterval = time.Millisecond
	manager, err := deployment.NewManagerWithConfig(deploymentRoot, bridge, bridge, managerConfig)
	if err != nil {
		t.Fatal(err)
	}
	bundleFiles := func(files map[string][]byte) edgeconfig.Bundle {
		t.Helper()
		manifest := edgeconfig.Manifest{Files: make([]edgeconfig.FileManifest, 0, len(files))}
		for path, raw := range files {
			fileDigest := sha256.Sum256(raw)
			manifest.Files = append(manifest.Files, edgeconfig.FileManifest{
				Path: path, Size: int64(len(raw)), SHA256: hex.EncodeToString(fileDigest[:]),
			})
		}
		manifestDigest, err := edgeconfig.ManifestDigest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		return edgeconfig.Bundle{
			Manifest: manifest, ManifestSHA256: manifestDigest, Files: files,
		}
	}
	bundle := func(policy http3runtime.Policy) edgeconfig.Bundle {
		t.Helper()
		raw, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		return bundleFiles(map[string][]byte{http3PolicyArtifactPath: raw})
	}
	deploymentID := uuid.NewString()
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: deploymentID, Attempt: 1, Action: deployment.ActionApply,
		ConfigVersionID: basePolicy.VersionID, Bundle: bundle(basePolicy),
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.State != deployment.StateHealthy || result.DeploymentID != deploymentID ||
		result.ConfigVersionID != basePolicy.VersionID || result.Attempt != 1 {
		t.Fatalf("generic deployment identity was not preserved: %+v", result)
	}
	if delegate.prechecks != 1 || delegate.reloads != 1 || delegate.healthy != 1 || len(http3Manager.applied) != 1 {
		t.Fatalf("HTTP/3 lifecycle bypassed manager: delegate=%+v applies=%d", delegate, len(http3Manager.applied))
	}
	restartedBridge, err := newHTTP3DeploymentBridge(delegate, http3Manager)
	if err != nil {
		t.Fatalf("newHTTP3DeploymentBridge(restart) error = %v", err)
	}
	if err := restartedBridge.Healthy(context.Background(), basePolicy.VersionID); err != nil {
		t.Fatalf("restart did not recover active HTTP/3 identity: %v", err)
	}
	restartedManager, err := deployment.NewManagerWithConfig(deploymentRoot, restartedBridge, restartedBridge, managerConfig)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := restartedManager.Process(context.Background(), deployment.Command{
		DeploymentID: uuid.NewString(), Attempt: 1, Action: deployment.ActionApply,
		ConfigVersionID: "config-without-http3", PreviousVersionID: basePolicy.VersionID,
		Bundle: bundleFiles(map[string][]byte{"nginx.conf": []byte("events {}\n")}),
	})
	if err != nil {
		t.Fatalf("Process(missing policy) error = %v", err)
	}
	if missing.State != deployment.StateFailed || !missing.RunningConfigUnchanged || len(http3Manager.applied) != 1 ||
		delegate.prechecks != 1 || delegate.reloads != 1 {
		t.Fatalf("missing policy changed active HTTP/3 state: result=%+v delegate=%+v applies=%d", missing, delegate, len(http3Manager.applied))
	}

	nextPolicy := basePolicy
	nextPolicy.VersionID = "config-v8"
	http3Manager.substituteFor = nextPolicy.VersionID
	reverted, err := restartedManager.Process(context.Background(), deployment.Command{
		DeploymentID: uuid.NewString(), Attempt: 1, Action: deployment.ActionApply,
		ConfigVersionID: nextPolicy.VersionID, PreviousVersionID: basePolicy.VersionID, Bundle: bundle(nextPolicy),
	})
	if err != nil {
		t.Fatalf("Process(failed health) error = %v", err)
	}
	pointers, pointerErr := restartedManager.Pointers()
	if reverted.State != deployment.StateReverted || pointerErr != nil || pointers.Current != basePolicy.VersionID ||
		http3Manager.status.VersionID != basePolicy.VersionID {
		t.Fatalf("generic deployment did not restore the previous bundle: %+v", reverted)
	}
	if delegate.prechecks != 2 || delegate.reloads != 3 || delegate.healthy != 3 || len(http3Manager.applied) != 3 ||
		http3Manager.applied[2].VersionID != basePolicy.VersionID {
		t.Fatalf("rollback bypassed composed lifecycle: delegate=%+v applied=%+v", delegate, http3Manager.applied)
	}
}

const fakeH3ProbeVersion = `{"schema":"cdnca.h3probe/v1","go":"go1.24.5","quic_go":"v0.54.0"}`

// writeFakeH3Probe writes an executable that answers `version` like the
// packaged h3probe (edge/openresty/http3/client) and nothing else.
func writeFakeH3Probe(t *testing.T, directory, output string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, "h3probe")
	script := "#!/bin/sh\n[ \"$1\" = version ] && [ $# -eq 1 ] || exit 2\nprintf '%s\\n' '" + output + "'\n"
	if err := os.WriteFile(path, []byte(script), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func http3RuntimeTestConfig(root, probe string) fileConfig {
	return fileConfig{
		JournalDir: filepath.Join(root, "gateway", "journal"),
		OpenResty: openRestySettings{Binary: "/usr/local/openresty/bin/openresty",
			Version: http3runtime.RuntimeVersionOpenResty, HTTP3Probe: probe},
	}
}

func writeHTTP3ActiveState(t *testing.T, root string) {
	t.Helper()
	directory := filepath.Join(root, "gateway", "http3-runtime", "state")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "active.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

var http3RuntimeTestTimeouts = parsedTimeouts{Reload: time.Second, HealthRequest: time.Second}

// An h3probe on PATH is never picked up: production nodes have no such PATH
// entry, so the probe is the configured absolute path or HTTP/3 is not
// declared, with the reason, instead of silently falling back.
func TestHTTP3RuntimeIgnoresPATHAndRequiresConfiguredProbe(t *testing.T) {
	onPath := t.TempDir()
	writeFakeH3Probe(t, onPath, fakeH3ProbeVersion, 0o755)
	t.Setenv("PATH", onPath)
	root := t.TempDir()
	delegate := &http3RuntimeTestDelegate{}
	runtime, readiness, err := assembleHTTP3DeploymentRuntime(http3RuntimeTestConfig(root, ""), http3RuntimeTestTimeouts, delegate)
	if err != nil || readiness.Ready || runtime != delegate || !strings.Contains(readiness.Reason, "openresty.http3_probe is not configured") {
		t.Fatalf("unconfigured probe = (%T,%+v,%v)", runtime, readiness, err)
	}
	writeHTTP3ActiveState(t, root)
	runtime, readiness, err = assembleHTTP3DeploymentRuntime(http3RuntimeTestConfig(root, ""), http3RuntimeTestTimeouts, delegate)
	if err == nil || readiness.Ready || runtime != nil || !strings.Contains(err.Error(), "openresty.http3_probe is not configured") {
		t.Fatalf("durable active state without probe = (%T,%+v,%v), want startup error", runtime, readiness, err)
	}
}

func TestHTTP3RuntimeProbeFailuresAreExplicit(t *testing.T) {
	for _, item := range []struct {
		name, output, reason string
		mode                 os.FileMode
		missing              bool
	}{
		{name: "missing", missing: true, reason: "not found"},
		{name: "not executable", output: fakeH3ProbeVersion, mode: 0o644, reason: "not executable"},
		{name: "wrong schema", output: `{"schema":"other","go":"go1.24.5","quic_go":"v0.54.0"}`, mode: 0o755, reason: "self-test"},
		{name: "no quic-go", output: `{"schema":"cdnca.h3probe/v1","go":"go1.24.5","quic_go":""}`, mode: 0o755, reason: "self-test"},
		{name: "garbage", output: `nope`, mode: 0o755, reason: "self-test"},
	} {
		t.Run(item.name, func(t *testing.T) {
			directory, root := t.TempDir(), t.TempDir()
			probe := filepath.Join(directory, "h3probe")
			if !item.missing {
				probe = writeFakeH3Probe(t, directory, item.output, item.mode)
			}
			delegate := &http3RuntimeTestDelegate{}
			runtime, readiness, err := assembleHTTP3DeploymentRuntime(http3RuntimeTestConfig(root, probe), http3RuntimeTestTimeouts, delegate)
			if err != nil || readiness.Ready || runtime != delegate || !strings.Contains(readiness.Reason, probe) ||
				!strings.Contains(readiness.Reason, item.reason) {
				t.Fatalf("probe %s = (%T,%+v,%v)", item.name, runtime, readiness, err)
			}
			writeHTTP3ActiveState(t, root)
			if runtime, _, err = assembleHTTP3DeploymentRuntime(http3RuntimeTestConfig(root, probe), http3RuntimeTestTimeouts, delegate); err == nil ||
				runtime != nil || !strings.Contains(err.Error(), item.reason) {
				t.Fatalf("durable active state with probe %s = (%T,%v), want startup error", item.name, runtime, err)
			}
		})
	}
}

func TestHTTP3RuntimeVersionMismatchIsExplicit(t *testing.T) {
	config := http3RuntimeTestConfig(t.TempDir(), writeFakeH3Probe(t, t.TempDir(), fakeH3ProbeVersion, 0o755))
	config.OpenResty.Version = "1.27.1.2"
	delegate := &http3RuntimeTestDelegate{}
	runtime, readiness, err := assembleHTTP3DeploymentRuntime(config, http3RuntimeTestTimeouts, delegate)
	if err != nil || readiness.Ready || runtime != delegate || !strings.Contains(readiness.Reason, "1.27.1.2") ||
		!strings.Contains(readiness.Reason, http3runtime.RuntimeVersionOpenResty) {
		t.Fatalf("version mismatch = (%T,%+v,%v)", runtime, readiness, err)
	}
}

func TestHTTP3RuntimeReadyWithConfiguredProbe(t *testing.T) {
	probe := writeFakeH3Probe(t, t.TempDir(), fakeH3ProbeVersion, 0o555)
	runtime, readiness, err := assembleHTTP3DeploymentRuntime(http3RuntimeTestConfig(t.TempDir(), probe), http3RuntimeTestTimeouts, &http3RuntimeTestDelegate{})
	if err != nil || !readiness.Ready || readiness.Probe != probe || readiness.Reason != "" {
		t.Fatalf("configured probe = (%T,%+v,%v)", runtime, readiness, err)
	}
	if bridge, ok := runtime.(*http3DeploymentBridge); !ok || bridge == nil {
		t.Fatalf("runtime = %T, want HTTP/3 bridge", runtime)
	}
}

// The reason travels with every terminal deployment status (node status on
// the control plane), and the same text is the local log line.
func TestHTTP3RuntimeCheckAndLogCarryTheReason(t *testing.T) {
	reason := "h3probe /opt/x/h3probe not found"
	checks := http3RuntimeChecks(http3RuntimeReadiness{Reason: reason})()
	if len(checks) != 1 || checks[0].Name != "edge_http3_runtime" || checks[0].Succeeded ||
		!strings.Contains(checks[0].Summary, "HTTP_3 not declared") || !strings.Contains(checks[0].Summary, reason) ||
		checks[0].LatencyDuration == nil {
		t.Fatalf("unavailable check = %+v", checks)
	}
	ready := http3RuntimeChecks(http3RuntimeReadiness{Ready: true, Probe: "/opt/x/h3probe"})()
	if len(ready) != 1 || !ready[0].Succeeded || !strings.Contains(ready[0].Summary, "/opt/x/h3probe") {
		t.Fatalf("ready check = %+v", ready)
	}
	var log strings.Builder
	logHTTP3Readiness(&log, http3RuntimeReadiness{Reason: reason})
	if !strings.Contains(log.String(), "HTTP/3 unavailable, HTTP_3 not declared: "+reason) {
		t.Fatalf("log = %q", log.String())
	}
	combined := combineDeploymentChecks(
		func() []*agentv1.CheckResult { return []*agentv1.CheckResult{{Name: "edge_waf_crs_engine"}} },
		http3RuntimeChecks(http3RuntimeReadiness{Reason: reason}),
	)()
	if len(combined) != 2 || combined[0].Name != "edge_waf_crs_engine" || combined[1].Name != "edge_http3_runtime" {
		t.Fatalf("combined checks = %+v", combined)
	}
}

func TestHTTP3ProbeConfigMustBeAbsoluteClean(t *testing.T) {
	for _, value := range []string{"h3probe", "/opt/cdnca-node/current/runtime/bin/../bin/h3probe", "/opt/x/h3probe\n"} {
		config := validFileConfig()
		config.OpenResty.HTTP3Probe = value
		if _, err := config.validate(); err == nil || !strings.Contains(err.Error(), "openresty.http3_probe") {
			t.Fatalf("http3_probe %q accepted: %v", value, err)
		}
	}
	config := validFileConfig()
	config.OpenResty.HTTP3Probe = "/opt/cdnca-node/current/runtime/bin/h3probe"
	if _, err := config.validate(); err != nil {
		t.Fatalf("installer probe path rejected: %v", err)
	}
	var settings openRestySettings
	if err := json.Unmarshal([]byte(`{"http3_probe":"/opt/cdnca-node/current/runtime/bin/h3probe"}`), &settings); err != nil ||
		settings.HTTP3Probe != "/opt/cdnca-node/current/runtime/bin/h3probe" {
		t.Fatalf("decode http3_probe = %+v, %v", settings, err)
	}
}

func TestDaemonHTTP3HealthProbeUsesBoundedFreshConnections(t *testing.T) {
	policy := http3runtime.Policy{
		VersionID: "http3-v2",
		Listener:  http3runtime.Listener{Address: "0.0.0.0", Port: 18443, ServerName: "h3.test"},
	}
	valid := []byte(`{"protocol":"HTTP/3.0","status":200,"version_header":"http3-v2","tls_version":"TLSv1.3"}`)

	t.Run("transient reset recovers", func(t *testing.T) {
		attempts := 0
		probe := daemonHTTP3HealthProbe{
			clientBinary: "/usr/local/bin/h3probe",
			timeout:      time.Second,
			run: func(context.Context, string, ...string) ([]byte, error) {
				attempts++
				if attempts < http3HealthProbeAttempts {
					return nil, errors.New("received a stateless reset")
				}
				return valid, nil
			},
		}
		if err := probe.HTTP3(context.Background(), policy); err != nil {
			t.Fatalf("HTTP3() error = %v", err)
		}
		if attempts != http3HealthProbeAttempts {
			t.Fatalf("fresh connection attempts = %d, want %d", attempts, http3HealthProbeAttempts)
		}
	})

	t.Run("persistent failure stays fail closed", func(t *testing.T) {
		attempts := 0
		probe := daemonHTTP3HealthProbe{
			clientBinary: "/usr/local/bin/h3probe",
			timeout:      time.Second,
			run: func(context.Context, string, ...string) ([]byte, error) {
				attempts++
				return nil, errors.New("received a stateless reset")
			},
		}
		if err := probe.HTTP3(context.Background(), policy); err == nil {
			t.Fatal("HTTP3() accepted persistent connection failure")
		}
		if attempts != http3HealthProbeAttempts {
			t.Fatalf("fresh connection attempts = %d, want %d", attempts, http3HealthProbeAttempts)
		}
	})
}
