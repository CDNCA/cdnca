package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/acmehttp01"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/diskguard"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type blockingClient struct {
	started chan struct{}
	once    sync.Once
}

func (c *blockingClient) Run(ctx context.Context) error {
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	return ctx.Err()
}

type errorClient struct{ err error }

func (c errorClient) Run(context.Context) error { return c.err }

type upgradeProbeInstaller struct {
	current updater.ActivationReceipt
	err     error
}

func (installer upgradeProbeInstaller) Current(context.Context) (updater.ActivationReceipt, error) {
	return installer.current, installer.err
}

func (upgradeProbeInstaller) Install(context.Context, updater.InstallRequest) (updater.ActivationReceipt, error) {
	return updater.ActivationReceipt{}, updater.ErrInstaller
}

func (upgradeProbeInstaller) Query(context.Context, string) (updater.ActivationReceipt, error) {
	return updater.ActivationReceipt{}, updater.ErrInstaller
}

func (upgradeProbeInstaller) Rollback(context.Context, updater.RollbackRequest) (updater.ActivationReceipt, error) {
	return updater.ActivationReceipt{}, updater.ErrInstaller
}

type fakeDiskGuardRunner struct {
	started   chan struct{}
	cancelled chan struct{}
	stopped   chan struct{}
	release   <-chan struct{}
	err       error
	once      sync.Once
	metrics   diskguard.Metrics
}

type cleanExitDiskGuardRunner struct {
	stopped chan struct{}
	metrics diskguard.Metrics
}

type fakeTelemetryRunner struct {
	started   chan struct{}
	cancelled chan struct{}
	stopped   chan struct{}
	release   <-chan struct{}
	err       error
	cleanExit bool
	once      sync.Once
	snapshot  telemetryclient.WorkerSnapshot
}

type fakeChallengeVerifierRunner struct {
	started chan struct{}
	err     error
}

func (runner *fakeChallengeVerifierRunner) Run(ctx context.Context) error {
	close(runner.started)
	if runner.err != nil {
		return runner.err
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestDaemonRunsExternalChallengeVerifierAndFailsClosedWhenItStops(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	verifier := &fakeChallengeVerifierRunner{started: make(chan struct{}), err: errors.New("bind failed")}
	daemon := &daemonClient{client: client, challengeVerifier: verifier}
	err := daemon.Run(context.Background())
	if !strings.Contains(fmt.Sprint(err), "external challenge verifier stopped: bind failed") {
		t.Fatalf("daemon Run() error=%v", err)
	}
	waitChannel(t, verifier.started, "external challenge verifier start")
}

func (runner *fakeTelemetryRunner) Run(ctx context.Context) error {
	runner.once.Do(func() { close(runner.started) })
	defer close(runner.stopped)
	if runner.err != nil {
		return runner.err
	}
	if runner.cleanExit {
		return nil
	}
	<-ctx.Done()
	close(runner.cancelled)
	if runner.release != nil {
		<-runner.release
	}
	return ctx.Err()
}

func (runner *fakeTelemetryRunner) Snapshot() telemetryclient.WorkerSnapshot {
	return runner.snapshot
}

func (runner *cleanExitDiskGuardRunner) Run(context.Context) error {
	close(runner.stopped)
	return nil
}

func (runner *cleanExitDiskGuardRunner) Snapshot() diskguard.Metrics {
	return runner.metrics
}

func (runner *fakeDiskGuardRunner) Run(ctx context.Context) error {
	runner.once.Do(func() { close(runner.started) })
	defer close(runner.stopped)
	if runner.err != nil {
		return runner.err
	}
	<-ctx.Done()
	close(runner.cancelled)
	if runner.release != nil {
		<-runner.release
	}
	return nil
}

func (runner *fakeDiskGuardRunner) Snapshot() diskguard.Metrics {
	return runner.metrics
}

func TestExecuteCancelsGracefullyAndGeneratesBootID(t *testing.T) {
	config := validFileConfig()
	client := &blockingClient{started: make(chan struct{})}
	var observedBootID string
	deps := dependencies{
		load: func(string) (fileConfig, parsedTimeouts, error) {
			return config, parsedTimeouts{}, nil
		},
		build: func(_ fileConfig, _ parsedTimeouts, bootID string) (clientRunner, error) {
			observedBootID = bootID
			return client, nil
		},
		bootID: uuid.NewString,
	}
	ctx, cancel := context.WithCancel(context.Background())
	var output bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- execute(ctx, nil, nil, &output, deps) }()
	select {
	case <-client.started:
	case <-time.After(time.Second):
		t.Fatal("client did not start")
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("execute() code = %d, output = %s", code, output.String())
		}
	case <-time.After(time.Second):
		t.Fatal("execute() did not honor cancellation")
	}
	if parsed, err := uuid.Parse(observedBootID); err != nil || parsed.String() != observedBootID {
		t.Fatalf("boot ID = %q", observedBootID)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"event":"agent_started"`)) || !bytes.Contains(output.Bytes(), []byte(`"event":"agent_stopped"`)) {
		t.Fatalf("structured lifecycle log = %s", output.String())
	}
}

func TestExecuteReturnsNonzeroForStartupAndRuntimeErrors(t *testing.T) {
	config := validFileConfig()
	tests := []struct {
		name string
		deps dependencies
	}{
		{
			name: "load",
			deps: dependencies{
				load: func(string) (fileConfig, parsedTimeouts, error) {
					return fileConfig{}, parsedTimeouts{}, errors.New("invalid")
				},
				build: assembleClient, bootID: uuid.NewString,
			},
		},
		{
			name: "build",
			deps: dependencies{
				load:   func(string) (fileConfig, parsedTimeouts, error) { return config, parsedTimeouts{}, nil },
				build:  func(fileConfig, parsedTimeouts, string) (clientRunner, error) { return nil, errors.New("failed") },
				bootID: uuid.NewString,
			},
		},
		{
			name: "runtime",
			deps: dependencies{
				load: func(string) (fileConfig, parsedTimeouts, error) { return config, parsedTimeouts{}, nil },
				build: func(fileConfig, parsedTimeouts, string) (clientRunner, error) {
					return errorClient{err: errors.New("protocol failure")}, nil
				},
				bootID: uuid.NewString,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if code := execute(context.Background(), nil, nil, &output, test.deps); code == 0 {
				t.Fatalf("execute() code = 0, output = %s", output.String())
			}
			if !bytes.Contains(output.Bytes(), []byte(`"level":"ERROR"`)) {
				t.Fatalf("error log = %s", output.String())
			}
		})
	}
}

func TestDaemonDiskGuardLifecycleWaitsAndRejectsConcurrentRun(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	release := make(chan struct{})
	guard := &fakeDiskGuardRunner{
		started: make(chan struct{}), cancelled: make(chan struct{}), stopped: make(chan struct{}), release: release,
		metrics: diskguard.Metrics{SchemaVersion: diskguard.SchemaVersion, ConfigID: "test"},
	}
	daemon := &daemonClient{client: client, diskGuard: guard}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway client start")
	waitChannel(t, guard.started, "disk guard start")
	if snapshot := daemon.DiskGuardSnapshot(); !snapshot.Enabled || !snapshot.Running || snapshot.RunFailed {
		t.Fatalf("running snapshot = %+v", snapshot)
	}
	if err := daemon.Run(ctx); !errors.Is(err, errDaemonAlreadyRunning) {
		t.Fatalf("concurrent Run() error = %v", err)
	}
	cancel()
	waitChannel(t, guard.cancelled, "disk guard cancellation")
	select {
	case err := <-done:
		t.Fatalf("daemon stopped before disk guard completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := waitError(t, done, "daemon stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}
	if snapshot := daemon.DiskGuardSnapshot(); snapshot.Running || snapshot.RunFailed {
		t.Fatalf("stopped snapshot = %+v", snapshot)
	}
}

func TestDaemonDiskGuardRunErrorDoesNotStopGatewayClient(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	guard := &fakeDiskGuardRunner{
		started: make(chan struct{}), cancelled: make(chan struct{}), stopped: make(chan struct{}),
		err: errors.New("background failed"),
		metrics: diskguard.Metrics{
			SchemaVersion: diskguard.SchemaVersion, ConfigID: "test", Healthy: false,
			FailureReason: diskguard.FailureLockUnsafe,
		},
	}
	daemon := &daemonClient{client: client, diskGuard: guard}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway client start")
	waitChannel(t, guard.stopped, "disk guard failure")
	waitCondition(t, "disk guard failure snapshot", func() bool {
		snapshot := daemon.DiskGuardSnapshot()
		return snapshot.RunFailed && !snapshot.Running
	})
	select {
	case err := <-done:
		t.Fatalf("disk guard failure stopped gateway client: %v", err)
	default:
	}
	cancel()
	if err := waitError(t, done, "gateway cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}
}

func TestDaemonDiskGuardUnexpectedCleanExitIsUnhealthy(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	guard := &cleanExitDiskGuardRunner{
		stopped: make(chan struct{}),
		metrics: diskguard.Metrics{SchemaVersion: diskguard.SchemaVersion, ConfigID: "test"},
	}
	daemon := &daemonClient{client: client, diskGuard: guard}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway client start")
	waitChannel(t, guard.stopped, "disk guard clean exit")
	waitCondition(t, "disk guard clean exit snapshot", func() bool {
		snapshot := daemon.DiskGuardSnapshot()
		return snapshot.RunFailed && !snapshot.Running
	})
	select {
	case err := <-done:
		t.Fatalf("disk guard clean exit stopped gateway client: %v", err)
	default:
	}
	cancel()
	if err := waitError(t, done, "gateway cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}
}

func TestDaemonTelemetryFailureDoesNotStopGatewayClient(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	telemetry := &fakeTelemetryRunner{
		started: make(chan struct{}), cancelled: make(chan struct{}), stopped: make(chan struct{}),
		err: errors.New("telemetry failed"),
	}
	daemon := &daemonClient{client: client, telemetry: telemetry}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway client start")
	waitChannel(t, telemetry.stopped, "telemetry failure")
	waitCondition(t, "telemetry degraded snapshot", func() bool {
		snapshot := daemon.TelemetrySnapshot()
		return snapshot.Enabled && !snapshot.Running && snapshot.Degraded && snapshot.LastErrorCode == "TELEMETRY_WORKER_EXITED"
	})
	select {
	case err := <-done:
		t.Fatalf("telemetry failure stopped gateway client: %v", err)
	default:
	}
	cancel()
	if err := waitError(t, done, "gateway cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}
}

func TestDaemonTelemetryUnexpectedCleanExitIsDegraded(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	telemetry := &fakeTelemetryRunner{
		started: make(chan struct{}), cancelled: make(chan struct{}), stopped: make(chan struct{}),
		cleanExit: true,
	}
	daemon := &daemonClient{client: client, telemetry: telemetry}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway client start")
	waitChannel(t, telemetry.stopped, "telemetry clean exit")
	waitCondition(t, "telemetry clean exit snapshot", func() bool {
		snapshot := daemon.TelemetrySnapshot()
		return snapshot.Enabled && !snapshot.Running && snapshot.Degraded && snapshot.LastErrorCode == "TELEMETRY_WORKER_EXITED"
	})
	select {
	case err := <-done:
		t.Fatalf("telemetry clean exit stopped gateway client: %v", err)
	default:
	}
	cancel()
	if err := waitError(t, done, "gateway cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}
}

func TestDaemonCancellationWaitsForTelemetryWorker(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	release := make(chan struct{})
	telemetry := &fakeTelemetryRunner{
		started: make(chan struct{}), cancelled: make(chan struct{}), stopped: make(chan struct{}), release: release,
	}
	daemon := &daemonClient{client: client, telemetry: telemetry}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway client start")
	waitChannel(t, telemetry.started, "telemetry start")
	cancel()
	waitChannel(t, telemetry.cancelled, "telemetry cancellation")
	select {
	case err := <-done:
		t.Fatalf("daemon stopped before telemetry worker completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := waitError(t, done, "daemon stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}
}

func TestDaemonRealDiskGuardErrorIsolationAndRestartRecovery(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	logRoot := filepath.Join(root, "logs")
	movedRoot := filepath.Join(root, "logs-moved")
	if err := os.Mkdir(logRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	config := validFileConfig()
	config.DiskGuard.Enabled = true
	config.DiskGuard.LogRoot = logRoot
	config.DiskGuard.LockPath = filepath.Join(root, "diskguard.lock")
	guard, err := assembleDiskGuard(config)
	if err != nil {
		t.Fatalf("assembleDiskGuard() error = %v", err)
	}
	if err := os.Rename(logRoot, movedRoot); err != nil {
		t.Fatal(err)
	}

	client := &blockingClient{started: make(chan struct{})}
	daemon := &daemonClient{client: client, diskGuard: guard}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway client start")
	waitCondition(t, "unhealthy disk guard snapshot", func() bool {
		snapshot := daemon.DiskGuardSnapshot()
		return snapshot.Running && !snapshot.RunFailed && snapshot.Metrics.EvaluationsTotal > 0 &&
			!snapshot.Metrics.Healthy && snapshot.Metrics.FailureReason == diskguard.FailureDirectoryUnsafe
	})
	select {
	case err := <-done:
		t.Fatalf("evaluation failure stopped gateway client: %v", err)
	default:
	}
	cancel()
	if err := waitError(t, done, "unhealthy daemon stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}

	if err := os.Rename(movedRoot, logRoot); err != nil {
		t.Fatal(err)
	}
	restartedGuard, err := assembleDiskGuard(config)
	if err != nil {
		t.Fatalf("restart assembleDiskGuard() error = %v", err)
	}
	restartedClient := &blockingClient{started: make(chan struct{})}
	restarted := &daemonClient{client: restartedClient, diskGuard: restartedGuard}
	restartContext, cancelRestart := context.WithCancel(context.Background())
	restartDone := make(chan error, 1)
	go func() { restartDone <- restarted.Run(restartContext) }()
	waitChannel(t, restartedClient.started, "restarted gateway client")
	waitCondition(t, "recovered disk guard snapshot", func() bool {
		snapshot := restarted.DiskGuardSnapshot()
		return snapshot.Running && snapshot.Metrics.EvaluationsTotal > 0 && snapshot.Metrics.Healthy
	})
	cancelRestart()
	if err := waitError(t, restartDone, "restarted daemon stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("restarted daemon Run() error = %v", err)
	}
}

func TestAssembleDiskGuardFailsStartupPreflight(t *testing.T) {
	config := validFileConfig()
	config.DiskGuard.Enabled = true
	config.DiskGuard.LogRoot = filepath.Join(t.TempDir(), "missing")
	config.DiskGuard.LockPath = filepath.Join(t.TempDir(), "diskguard.lock")
	if _, err := assembleDiskGuard(config); err == nil {
		t.Fatal("assembleDiskGuard() accepted a missing log root")
	}
	config.DiskGuard.Enabled = false
	guard, err := assembleDiskGuard(config)
	if err != nil || guard != nil {
		t.Fatalf("disabled assembleDiskGuard() = %v, %v", guard, err)
	}
}

func TestExecuteSupportsOfflineConfigCheckAndVersion(t *testing.T) {
	config := validFileConfig()
	loadCalls := 0
	buildCalls := 0
	deps := dependencies{
		load: func(string) (fileConfig, parsedTimeouts, error) {
			loadCalls++
			return config, parsedTimeouts{}, nil
		},
		build: func(fileConfig, parsedTimeouts, string) (clientRunner, error) {
			buildCalls++
			return errorClient{}, nil
		},
		bootID: uuid.NewString,
	}
	var output bytes.Buffer
	if code := execute(context.Background(), []string{"-check-config"}, nil, &output, deps); code != 0 {
		t.Fatalf("check-config code = %d, output = %s", code, output.String())
	}
	if loadCalls != 1 || buildCalls != 0 || !bytes.Contains(output.Bytes(), []byte(`"event":"configuration_valid"`)) {
		t.Fatalf("check-config calls = load:%d build:%d, output = %s", loadCalls, buildCalls, output.String())
	}

	output.Reset()
	if code := execute(context.Background(), []string{"-version"}, func(string) (string, bool) {
		return "relative-path", true
	}, &output, dependencies{}); code != 0 {
		t.Fatalf("version code = %d, output = %s", code, output.String())
	}
	if loadCalls != 1 || buildCalls != 0 || !bytes.Contains(output.Bytes(), []byte(`"event":"version"`)) {
		t.Fatalf("version unexpectedly initialized the daemon, output = %s", output.String())
	}
}

func TestHealthProbeRequiresExactActiveVersion(t *testing.T) {
	version := "cfg-v2"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-CDNCA-Config-Version", version)
		_, _ = fmt.Fprintf(writer, "ok:%s\n", version)
	}))
	defer server.Close()
	probe := newHealthProbe(server.URL+"/healthz", time.Second)
	if err := probe(context.Background(), version); err != nil {
		t.Fatalf("health probe error = %v", err)
	}
	if err := probe(context.Background(), "cfg-v3"); err == nil {
		t.Fatal("health probe accepted a different active version")
	}
}

func TestUpgradeReceiptProbeExecutesFixedCurrentArtifactVersion(t *testing.T) {
	expected := updater.ActivationReceipt{CurrentVersion: "2.0.0"}
	var path string
	var arguments []string
	probe := upgradeReceiptProbe{
		installer: upgradeProbeInstaller{current: expected},
		runVersion: func(_ context.Context, executable string, args ...string) ([]byte, error) {
			path = executable
			arguments = append([]string(nil), args...)
			return []byte("{\"event\":\"version\",\"agent_version\":\"2.0.0\"}\n"), nil
		},
	}
	if err := probe.Check(context.Background(), expected, []string{"{artifact}", "--version"}); err != nil {
		t.Fatalf("upgrade version probe error = %v", err)
	}
	if path != currentUpgradeArtifactPath() || len(arguments) != 1 || arguments[0] != "--version" {
		t.Fatalf("upgrade version command = %q %#v", path, arguments)
	}
}

func TestUpgradeReceiptProbeRejectsUnfrozenOrInvalidVersionEvidence(t *testing.T) {
	expected := updater.ActivationReceipt{CurrentVersion: "2.0.0"}
	base := upgradeReceiptProbe{
		installer: upgradeProbeInstaller{current: expected},
	}
	for _, test := range []struct {
		name    string
		command []string
		output  string
	}{
		{name: "alternate argument", command: []string{"{artifact}", "health"}, output: "{\"event\":\"version\",\"agent_version\":\"2.0.0\"}\n"},
		{name: "wrong version", command: []string{"{artifact}", "--version"}, output: "{\"event\":\"version\",\"agent_version\":\"2.0.1\"}\n"},
		{name: "wrong event", command: []string{"{artifact}", "--version"}, output: "{\"event\":\"startup\",\"agent_version\":\"2.0.0\"}\n"},
		{name: "multiple lines", command: []string{"{artifact}", "--version"}, output: "{\"event\":\"version\",\"agent_version\":\"2.0.0\"}\n{}\n"},
		{name: "malformed", command: []string{"{artifact}", "--version"}, output: "not-json\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := base
			probe.runVersion = func(context.Context, string, ...string) ([]byte, error) {
				return []byte(test.output), nil
			}
			if err := probe.Check(context.Background(), expected, test.command); !errors.Is(err, updater.ErrHealth) {
				t.Fatalf("upgrade version probe error = %v", err)
			}
		})
	}
}

func TestHealthProbeRejectsRedirects(t *testing.T) {
	version := "cfg-v2"
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-CDNCA-Config-Version", version)
		_, _ = fmt.Fprintf(writer, "ok:%s\n", version)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirect.Close()

	if err := newHealthProbe(redirect.URL, time.Second)(context.Background(), version); err == nil {
		t.Fatal("health probe followed a redirect")
	}
}

func TestDeploymentPrecheckerCreatesTelemetrySourcesWhenCollectorDisabled(t *testing.T) {
	root := telemetrySecureRoot(t)
	bundle := telemetryBundle(t, root, "cfg-v1")
	release := filepath.Join(root, "releases", bundle.ManifestSHA256)
	writeTelemetryRelease(t, release, bundle)

	config := defaultFileConfig()
	config.DeploymentRoot = root
	config.Telemetry.Enabled = false
	called := false
	prechecker, err := assembleDeploymentPrechecker(config, precheckFunc(func(context.Context, string, string) error {
		called = true
		manifest, parseErr := edgeconfig.ParseTelemetryIdentityManifest(bundle.Files[edgeconfig.TelemetryIdentityManifestPath])
		if parseErr != nil {
			return parseErr
		}
		for _, site := range manifest.Sites {
			for _, path := range []string{site.AccessLogPath, site.SecurityLogPath} {
				if _, statErr := os.Stat(path); statErr != nil {
					return statErr
				}
			}
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "cfg-v1", release); err != nil {
		t.Fatalf("Precheck() error = %v", err)
	}
	if !called {
		t.Fatal("OpenResty precheck was not called")
	}
}

// A JS challenge release loads <DeploymentRoot>/challenge/policies/...; until
// the challenge rollout installed it the assembled precheck refuses the
// release before OpenResty (nginx -t would accept it, master start would not).
func TestDeploymentPrecheckerRefusesMissingChallengePolicy(t *testing.T) {
	root := telemetrySecureRoot(t)
	release := filepath.Join(root, "releases", "challenge")
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(root, "challenge", "policies", "01990000-0000-7000-8000-000000000005", "versions",
		"00000000000000000007.json")
	if err := os.WriteFile(filepath.Join(release, "nginx.conf"),
		[]byte(fmt.Sprintf("init_by_lua_block { m.init({ policy_path = %q }) }\n", policy)), 0o600); err != nil {
		t.Fatal(err)
	}
	config := defaultFileConfig()
	config.DeploymentRoot = root
	config.Telemetry.Enabled = false
	called := false
	prechecker, err := assembleDeploymentPrechecker(config, precheckFunc(func(context.Context, string, string) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "cfg-v1", release); !errors.Is(err, challenge.ErrPolicyNotInstalled) || called {
		t.Fatalf("Precheck() error = %v, OpenResty precheck called = %v", err, called)
	}
}

func daemonStage2StreamMetadata(sequence uint64) *commonv1.StreamMetadata {
	return &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: sequence}
}

func TestCapabilitiesExcludeUnsupportedRuntimeFeatures(t *testing.T) {
	capabilities := agentCapabilities("1.27.1")
	seen := make(map[agentv1.CapabilityName]bool)
	for _, capability := range capabilities.Features {
		seen[capability.Name] = true
	}
	for _, unsupported := range []agentv1.CapabilityName{
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_3,
		agentv1.CapabilityName_CAPABILITY_NAME_NFTABLES,
		agentv1.CapabilityName_CAPABILITY_NAME_IPSET,
		agentv1.CapabilityName_CAPABILITY_NAME_JA4,
	} {
		if seen[unsupported] {
			t.Fatalf("unsupported capability %s was advertised", unsupported)
		}
	}
	if !seen[agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE] || !seen[agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK] {
		t.Fatal("required deployment capabilities were not advertised")
	}
}

type daemonFirewallRuntime struct {
	probeErr error
	probes   int
	mu       sync.Mutex
	expires  [][2]string
	expired  chan struct{}
}

func (runtime *daemonFirewallRuntime) Probe(context.Context) error {
	runtime.probes++
	return runtime.probeErr
}

func (*daemonFirewallRuntime) Apply(context.Context, firewall.FirewallVersion) (firewall.Result, error) {
	return firewall.Result{}, nil
}

func (runtime *daemonFirewallRuntime) Expire(_ context.Context, taskID, versionID string) (firewall.Result, error) {
	runtime.mu.Lock()
	runtime.expires = append(runtime.expires, [2]string{taskID, versionID})
	expired := runtime.expired
	runtime.mu.Unlock()
	if expired != nil {
		select {
		case expired <- struct{}{}:
		default:
		}
	}
	return firewall.Result{}, firewall.ErrNoExpiredEntry
}

type fakeFirewallExpiryRunner struct {
	started   chan struct{}
	cancelled chan struct{}
}

func (runner *fakeFirewallExpiryRunner) Run(ctx context.Context) error {
	close(runner.started)
	<-ctx.Done()
	close(runner.cancelled)
	return ctx.Err()
}

func TestDaemonRunsFirewallExpiryWhenOtherBackgroundWorkersAreDisabled(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	expiry := &fakeFirewallExpiryRunner{started: make(chan struct{}), cancelled: make(chan struct{})}
	daemon := &daemonClient{client: client, firewallExpiry: expiry}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, client.started, "gateway client start")
	waitChannel(t, expiry.started, "firewall expiry start")
	cancel()
	waitChannel(t, expiry.cancelled, "firewall expiry cancellation")
	if err := waitError(t, done, "daemon stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error=%v", err)
	}
}

func TestFirewallExpirySchedulerUsesStableBoundedBuckets(t *testing.T) {
	runtime := &daemonFirewallRuntime{expired: make(chan struct{}, 2)}
	now := time.Date(2026, time.January, 2, 3, 4, 59, 0, time.UTC)
	waitStarted := make(chan time.Duration, 2)
	release := make(chan struct{}, 1)
	scheduler := newFirewallExpiryScheduler(runtime, func() time.Time { return now }, func(ctx context.Context, interval time.Duration) error {
		waitStarted <- interval
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if scheduler == nil {
		t.Fatal("newFirewallExpiryScheduler() returned nil for ready runtime")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitChannel(t, runtime.expired, "first expiry evaluation")
	if interval := <-waitStarted; interval != time.Minute {
		t.Fatalf("expiry interval=%s, want 1m", interval)
	}
	runtime.mu.Lock()
	first := runtime.expires[0]
	runtime.mu.Unlock()
	if first != [2]string{"ttl-expire-1767323040", "ttl-runtime-1767323040"} {
		t.Fatalf("first expiry identity=%q", first)
	}
	select {
	case <-runtime.expired:
		t.Fatal("scheduler retried without bounded wait")
	case <-time.After(20 * time.Millisecond):
	}
	release <- struct{}{}
	waitChannel(t, runtime.expired, "second expiry evaluation")
	runtime.mu.Lock()
	second := runtime.expires[1]
	runtime.mu.Unlock()
	if second != first {
		t.Fatalf("same time bucket changed identity: first=%q second=%q", first, second)
	}
	cancel()
	if err := waitError(t, done, "expiry scheduler stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("scheduler Run() error=%v", err)
	}
	var disabled firewallExpiryRunner = newFirewallExpiryScheduler(nil, time.Now, nil)
	if disabled != nil {
		t.Fatalf("unready runtime started scheduler=%T", disabled)
	}
}

func TestFirewallCapabilitiesRequireManagerAndKernelProbe(t *testing.T) {
	runtime := &daemonFirewallRuntime{}
	builtRoot, builtBinary := "", ""
	selected, ready := selectFirewallRuntime(
		context.Background(), "/var/lib/cdnca-edge-agent/firewall",
		func(string) (string, error) { return "/usr/sbin/nft", nil },
		func(root, binary string) (firewallRuntime, error) {
			builtRoot, builtBinary = root, binary
			return runtime, nil
		},
	)
	if !ready || selected != runtime || runtime.probes != 1 || builtRoot != "/var/lib/cdnca-edge-agent/firewall" || builtBinary != "/usr/sbin/nft" {
		t.Fatalf("firewall selection ready=%t runtime=%T probes=%d root=%q binary=%q", ready, selected, runtime.probes, builtRoot, builtBinary)
	}
	capabilities := agentCapabilitiesWithFirewall("1.27.1", ready)
	seen := make(map[agentv1.CapabilityName]uint32)
	for _, capability := range capabilities.Features {
		seen[capability.Name] = capability.ApiVersion
	}
	for _, name := range []agentv1.CapabilityName{
		agentv1.CapabilityName_CAPABILITY_NAME_NFTABLES,
		agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL,
	} {
		if seen[name] != 1 {
			t.Fatalf("ready firewall capability %s version=%d, want 1", name, seen[name])
		}
	}

	runtime.probeErr = firewall.ErrUnsupported
	if selected, ready := selectFirewallRuntime(
		context.Background(), "/var/lib/cdnca-edge-agent/firewall",
		func(string) (string, error) { return "/usr/sbin/nft", nil },
		func(string, string) (firewallRuntime, error) { return runtime, nil },
	); ready || selected != nil {
		t.Fatalf("failed kernel probe selected runtime=%T ready=%t", selected, ready)
	}
	if capabilities := agentCapabilitiesWithFirewall("1.27.1", false); hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL) || hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_NFTABLES) {
		t.Fatalf("unready firewall capabilities=%+v", capabilities.Features)
	}
	if selected, ready := selectFirewallRuntime(
		context.Background(), "/var/lib/cdnca-edge-agent/firewall",
		func(string) (string, error) { return "", errors.New("not found") },
		func(string, string) (firewallRuntime, error) {
			t.Fatal("builder called without nft binary")
			return nil, nil
		},
	); ready || selected != nil {
		t.Fatalf("missing nft selected runtime=%T ready=%t", selected, ready)
	}
}

func hasCapability(capabilities *agentv1.AgentCapabilities, name agentv1.CapabilityName) bool {
	for _, capability := range capabilities.Features {
		if capability.Name == name {
			return true
		}
	}
	return false
}

func TestACMEHTTP01CapabilityReadinessRequiresGeneratedFixedRoute(t *testing.T) {
	root := filepath.Join(secureConfigTempDir(t), "deployments")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := acmehttp01.NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	if manager.Ready() {
		t.Fatal("overlay manager was ready without an active fixed route")
	}

	release := filepath.Join(root, "releases", "cfg-v1")
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	// The fixed route as the site runtime renders it into an HTTP server.
	nginx := "http {\n  server {\n    listen 18081;\n" + edgeconfig.RenderACMEHTTP01Location(root) + "  }\n}\n"
	if err := os.WriteFile(filepath.Join(release, "nginx.conf"), []byte(nginx), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", "cfg-v1"), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if !manager.Ready() {
		t.Fatal("overlay manager did not recognize the generated fixed route")
	}
}

func TestAssembleClientUsesSecureFilesAndRealRuntimeAdapter(t *testing.T) {
	root := secureConfigTempDir(t)
	securityDir := filepath.Join(root, "security")
	if err := os.Mkdir(securityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM, publicKeyPEM := testSecurityMaterial(t)
	rootCAFile := writeTestFile(t, securityDir, "ca.pem", certificatePEM, 0o600)
	clientCertificateFile := writeTestFile(t, securityDir, "client.pem", certificatePEM, 0o600)
	clientPrivateKeyFile := writeTestFile(t, securityDir, "client-key.pem", privateKeyPEM, 0o600)
	trustContent, err := json.Marshal(map[string]any{
		"version": 1,
		"keys":    []map[string]string{{"key_id": "artifact-key", "public_key_pem": string(publicKeyPEM)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	trustFile := writeTestFile(t, securityDir, "trust.json", trustContent, 0o400)

	config := validFileConfig()
	config.ArtifactTrustFile = trustFile
	config.DeploymentRoot = filepath.Join(root, "deployments")
	config.JournalDir = filepath.Join(root, "gateway-journal")
	config.CertificateRuntime.StateRoot = filepath.Join(root, "certificates")
	config.Gateway.RootCAFile = rootCAFile
	config.Gateway.ClientCertificate = clientCertificateFile
	config.Gateway.ClientPrivateKeyFile = clientPrivateKeyFile
	config.OpenResty.Binary = trueBinary(t)
	timeouts, err := config.validate()
	if err != nil {
		t.Fatal(err)
	}
	client, err := assembleClient(config, timeouts, uuid.NewString())
	if err != nil {
		t.Fatalf("assembleClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("assembleClient() returned a nil client")
	}
	disabled, ok := client.(*daemonClient)
	if !ok || disabled.telemetry != nil || disabled.TelemetrySnapshot().Enabled || disabled.cacheTasks == nil {
		t.Fatalf("disabled telemetry assembly = %#v", client)
	}
	// Dynamic routing is the only node runtime: cache tasks go to it.
	if _, ok := disabled.cacheTasks.(dynroute.CacheTasks); !ok {
		t.Fatalf("cache task runtime = %T, want dynroute.CacheTasks", disabled.cacheTasks)
	}
	if err := disabled.Close(); err != nil {
		t.Fatalf("Close(first client) error = %v", err)
	}

	config.Telemetry.Enabled = true
	config.Telemetry.SpoolRoot = filepath.Join(root, "event-spool")
	timeouts, err = config.validate()
	if err != nil {
		t.Fatal(err)
	}
	client, err = assembleClient(config, timeouts, uuid.NewString())
	if err != nil {
		t.Fatalf("assembleClient(telemetry) error = %v", err)
	}
	enabled, ok := client.(*daemonClient)
	if !ok || enabled.telemetry == nil || !enabled.TelemetrySnapshot().Enabled {
		t.Fatalf("enabled telemetry assembly = %#v", client)
	}
	for _, directory := range []string{config.Telemetry.SpoolRoot, filepath.Join(config.Telemetry.SpoolRoot, "segments"), filepath.Join(config.Telemetry.SpoolRoot, "state")} {
		info, statErr := os.Stat(directory)
		if statErr != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("telemetry spool directory %q is unsafe: %v, %v", directory, info, statErr)
		}
	}
}

func TestRunClientRejectsUnexpectedCleanExit(t *testing.T) {
	if err := runClient(context.Background(), errorClient{}); err == nil {
		t.Fatal("runClient() accepted an unexpected clean exit")
	}
}

func waitChannel(t *testing.T, channel <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitError(t *testing.T, channel <-chan error, description string) error {
	t.Helper()
	select {
	case err := <-channel:
		return err
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
		return nil
	}
}

func waitCondition(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func testSecurityMaterial(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge-agent-test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})
}

// trueBinary 是 /bin/true 的替身：Ubuntu merged-usr 下 /bin 是指向 usr/bin 的符号链接，
// 而 errorpage 预检逐级拒绝符号链接路径（publisher.go cleanAbsolutePath），macOS 的 /bin 是实目录。
// 放在独立私有目录：配置校验要求运行时根与 openresty.binary 互不包含。
func trueBinary(t *testing.T) string {
	t.Helper()
	return writeTestFile(t, secureConfigTempDir(t), "openresty-true", []byte("#!/bin/sh\nexit 0\n"), 0o700)
}

func writeTestFile(t *testing.T, directory, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDynamicRoutingDeclaresSiteRuntimeNine(t *testing.T) {
	capabilities := agentCapabilities("1.27.1")
	declareSiteRuntimeVersion(capabilities, edgeconfig.DynamicRoutingSiteRuntimeVersion)
	declareSiteRuntimeVersion(capabilities, edgeconfig.DynamicRoutingSiteRuntimeVersion)
	count := 0
	for _, capability := range capabilities.Features {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			count++
			if capability.ApiVersion != 9 {
				t.Fatalf("site runtime API version = %d, want 9", capability.ApiVersion)
			}
		}
	}
	if count != 1 || edgeconfig.MaxSiteRuntimeVersion != edgeconfig.DynamicRoutingSiteRuntimeVersion {
		t.Fatalf("%d SITE_RUNTIME entries; MaxSiteRuntimeVersion must be 9", count)
	}
}
