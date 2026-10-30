package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/drainruntime"
)

type daemonDrainRuntime struct {
	mu              sync.Mutex
	calls           []string
	healthy         bool
	healthErr       error
	remaining       []int
	closeErr        error
	recoverStarted  chan struct{}
	runnerStarted   chan struct{}
	runnerCancelled chan struct{}
}

func (runtime *daemonDrainRuntime) record(value string) {
	runtime.mu.Lock()
	runtime.calls = append(runtime.calls, value)
	runtime.mu.Unlock()
}

func (runtime *daemonDrainRuntime) Precheck(context.Context, drainruntime.Plan, drainruntime.Artifacts) error {
	runtime.record("precheck")
	return nil
}

func (runtime *daemonDrainRuntime) ActivateNew(context.Context, drainruntime.Plan, drainruntime.Artifacts) error {
	runtime.record("activate")
	return nil
}

func (runtime *daemonDrainRuntime) NewHealthy(context.Context, drainruntime.Plan, drainruntime.Artifacts) (bool, error) {
	runtime.record("health")
	return runtime.healthy, runtime.healthErr
}

func (runtime *daemonDrainRuntime) BeginDrain(context.Context, drainruntime.Plan, drainruntime.Artifacts) error {
	runtime.record("drain")
	return nil
}

func (runtime *daemonDrainRuntime) RemainingOldWorkers(context.Context, drainruntime.Plan, drainruntime.Artifacts) (int, error) {
	runtime.record("remaining")
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.remaining) == 0 {
		return 0, nil
	}
	value := runtime.remaining[0]
	runtime.remaining = runtime.remaining[1:]
	return value, nil
}

func (runtime *daemonDrainRuntime) Complete(context.Context, drainruntime.Plan, drainruntime.Artifacts) error {
	runtime.record("complete")
	return nil
}

func (runtime *daemonDrainRuntime) Rollback(context.Context, drainruntime.Plan, drainruntime.Artifacts) error {
	runtime.record("rollback")
	return nil
}

func (runtime *daemonDrainRuntime) ForceTerminate(context.Context, drainruntime.Plan, drainruntime.Artifacts) error {
	runtime.record("force")
	return nil
}

func (runtime *daemonDrainRuntime) count(want string) int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	count := 0
	for _, value := range runtime.calls {
		if value == want {
			count++
		}
	}
	return count
}

func TestDrainRuntimeConfigurationIsExplicitAndFailClosed(t *testing.T) {
	config := validFileConfig()
	config.DrainRuntime.Prefix = "/private/var/lib/cdnca-edge-agent/drain-prefix"
	if _, err := config.validate(); err == nil {
		t.Fatal("disabled drain runtime accepted configured paths")
	}

	config = validFileConfig()
	config.DrainRuntime.Enabled = true
	if _, err := config.validate(); err == nil {
		t.Fatal("enabled drain runtime accepted missing paths and timeouts")
	}

	config.DrainRuntime = validDrainRuntimeSettings()
	timeouts, err := config.validate()
	if err != nil {
		t.Fatal(err)
	}
	if timeouts.DrainCommandLimit != 5*time.Second || timeouts.DrainResumeInterval != 20*time.Millisecond {
		t.Fatalf("parsed drain timeouts = (%s, %s)", timeouts.DrainCommandLimit, timeouts.DrainResumeInterval)
	}

	config.DrainRuntime.StateRoot = config.DeploymentRoot
	if _, err := config.validate(); err == nil {
		t.Fatal("drain state root overlapping deployment root was accepted")
	}
}

func TestDrainPlanHandlerPersistsAndRecoversPendingTransition(t *testing.T) {
	root := secureConfigTempDir(t)
	stateRoot := filepath.Join(root, "drain-state")
	cleanupDrainState(t, stateRoot)
	firstRuntime := &daemonDrainRuntime{healthy: true, remaining: []int{1}}
	firstManager, err := drainruntime.NewManager(stateRoot, firstRuntime)
	if err != nil {
		t.Fatal(err)
	}
	first, err := newDrainPlanHandler(stateRoot, firstManager, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	plan := daemonDrainPlan(1)
	result, err := first.HandleDrainPlan(t.Context(), plan)
	if !errors.Is(err, drainruntime.ErrDrainInProgress) || result.Phase != drainruntime.PhaseDrainingOld {
		t.Fatalf("first HandleDrainPlan() = (%+v, %v)", result, err)
	}
	if snapshot := first.Snapshot(); !snapshot.Enabled || !snapshot.Ready || !snapshot.Pending || snapshot.Phase != drainruntime.PhaseDrainingOld {
		t.Fatalf("first snapshot = %+v", snapshot)
	}
	if info, err := os.Stat(filepath.Join(stateRoot, drainActivePlanFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("active plan info = (%v, %v)", info, err)
	}

	secondRuntime := &daemonDrainRuntime{healthy: true, remaining: []int{0}}
	secondManager, err := drainruntime.NewManager(stateRoot, secondRuntime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newDrainPlanHandler(stateRoot, secondManager, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if snapshot := second.Snapshot(); !snapshot.Ready || snapshot.Pending || snapshot.Degraded || snapshot.Phase != drainruntime.PhaseCompleted {
		t.Fatalf("recovered snapshot = %+v", snapshot)
	}
	if secondRuntime.count("activate") != 0 || secondRuntime.count("complete") != 1 {
		t.Fatalf("recovery calls = %+v", secondRuntime.calls)
	}
}

func TestDrainPlanHandlerRollsBackAndRejectsInvalidPlan(t *testing.T) {
	root := secureConfigTempDir(t)
	stateRoot := filepath.Join(root, "drain-state")
	cleanupDrainState(t, stateRoot)
	runtime := &daemonDrainRuntime{healthErr: errors.New("health failed")}
	manager, err := drainruntime.NewManager(stateRoot, runtime)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newDrainPlanHandler(stateRoot, manager, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	result, processErr := handler.HandleDrainPlan(t.Context(), daemonDrainPlan(1))
	if processErr == nil || result.Phase != drainruntime.PhaseRolledBack || runtime.count("rollback") != 1 {
		t.Fatalf("rollback result = (%+v, %v), calls=%v", result, processErr, runtime.calls)
	}
	if snapshot := handler.Snapshot(); !snapshot.Ready || !snapshot.Degraded || snapshot.LastErrorCode != "DRAIN_PLAN_ROLLED_BACK" {
		t.Fatalf("rollback snapshot = %+v", snapshot)
	}
	if _, err := handler.HandleDrainPlan(t.Context(), drainruntime.Plan{}); !errors.Is(err, drainruntime.ErrInvalidPlan) {
		t.Fatalf("invalid plan error = %v", err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.HandleDrainPlan(t.Context(), daemonDrainPlan(2)); !errors.Is(err, errDrainRuntimeClosed) {
		t.Fatalf("closed handler error = %v", err)
	}
}

type fakeDrainController struct {
	recovered chan struct{}
	started   chan struct{}
	stopped   chan struct{}
	closeErr  error
	closeOnce sync.Once
}

func (controller *fakeDrainController) Recover(context.Context) error {
	close(controller.recovered)
	return nil
}

func (controller *fakeDrainController) Run(ctx context.Context) error {
	select {
	case <-controller.recovered:
	default:
		return errors.New("run started before recovery")
	}
	close(controller.started)
	<-ctx.Done()
	close(controller.stopped)
	return ctx.Err()
}

func (*fakeDrainController) HandleDrainPlan(context.Context, drainruntime.Plan) (drainruntime.Result, error) {
	return drainruntime.Result{}, nil
}

func (*fakeDrainController) Snapshot() drainRuntimeSnapshot {
	return drainRuntimeSnapshot{Enabled: true, Ready: true}
}

func (controller *fakeDrainController) Close() error {
	controller.closeOnce.Do(func() {})
	return controller.closeErr
}

type closingClient struct {
	started  chan struct{}
	closeErr error
}

func (client *closingClient) Run(ctx context.Context) error {
	close(client.started)
	<-ctx.Done()
	return ctx.Err()
}

func (client *closingClient) Close() error { return client.closeErr }

func TestDaemonRecoversDrainBeforeServingAndReportsCloseFailures(t *testing.T) {
	drainCloseErr := errors.New("drain close failed")
	clientCloseErr := errors.New("client close failed")
	controller := &fakeDrainController{
		recovered: make(chan struct{}), started: make(chan struct{}), stopped: make(chan struct{}), closeErr: drainCloseErr,
	}
	client := &closingClient{started: make(chan struct{}), closeErr: clientCloseErr}
	daemon := &daemonClient{client: client, drain: controller}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	waitChannel(t, controller.recovered, "drain recovery")
	waitChannel(t, controller.started, "drain runner")
	waitChannel(t, client.started, "gateway client")
	if snapshot := daemon.DrainRuntimeSnapshot(); !snapshot.Enabled || !snapshot.Ready || !snapshot.Running || snapshot.RunFailed {
		t.Fatalf("running drain snapshot = %+v", snapshot)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon Run() error = %v", err)
	}
	waitChannel(t, controller.stopped, "drain runner stop")
	closeErr := daemon.Close()
	if !errors.Is(closeErr, drainCloseErr) || !errors.Is(closeErr, clientCloseErr) {
		t.Fatalf("daemon Close() error = %v", closeErr)
	}
}

func validDrainRuntimeSettings() drainRuntimeSettings {
	return drainRuntimeSettings{
		Enabled: true, Prefix: "/private/var/lib/cdnca-edge-agent/drain-prefix",
		StateRoot:    "/private/var/lib/cdnca-edge-agent/drain-state",
		CommandLimit: "5s", ResumeInterval: "20ms",
	}
}

func daemonDrainPlan(revision uint64) drainruntime.Plan {
	return drainruntime.Plan{
		SchemaVersion: drainruntime.SchemaVersionV1,
		PlanID:        "daemon-drain",
		Revision:      revision,
		Old: drainruntime.Version{VersionID: "old-v1", Listeners: []drainruntime.Listener{{
			ID: "http", Protocol: drainruntime.ProtocolHTTP, Address: "127.0.0.1", Port: 18080,
			UpstreamAddress: "127.0.0.1", UpstreamPort: 19080,
		}}},
		New: drainruntime.Version{VersionID: "new-v1", Listeners: []drainruntime.Listener{{
			ID: "http", Protocol: drainruntime.ProtocolHTTP, Address: "127.0.0.1", Port: 18080,
			UpstreamAddress: "127.0.0.1", UpstreamPort: 19081,
		}}},
		HealthTimeoutSeconds: 10,
		HealthChecks: []drainruntime.HealthCheck{{
			ListenerID: "http", Path: "/health", ExpectedStatus: 200, ExpectedBodyPrefix: "ok",
		}},
		Drain: drainruntime.DrainPolicy{MaxDrainSeconds: 60, Force: drainruntime.ForceNever},
	}
}

func cleanupDrainState(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			} else {
				_ = os.Chmod(path, 0o600)
			}
			return nil
		})
	})
}
