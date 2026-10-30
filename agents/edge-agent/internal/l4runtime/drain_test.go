package l4runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var errInjectedDrain = errors.New("injected drain failure")

type drainTestRuntime struct {
	mu           sync.Mutex
	active       string
	events       []string
	drainCalls   []time.Duration
	drainStarted chan struct{}
	releaseDrain chan struct{}
	startOnce    sync.Once
	drainErr     error
	blockDrain   bool
}

func (r *drainTestRuntime) Precheck(_ context.Context, _ string) error { return nil }

func (r *drainTestRuntime) Activate(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	version := currentTarget(path)
	r.active = version
	r.events = append(r.events, "activate:"+version)
	return nil
}

func (r *drainTestRuntime) Healthy(context.Context, Config) error { return nil }

func (r *drainTestRuntime) Stop(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "stop:"+currentTarget(path))
	return nil
}

func (r *drainTestRuntime) Drain(ctx context.Context, timeout time.Duration) error {
	r.mu.Lock()
	r.drainCalls = append(r.drainCalls, timeout)
	r.events = append(r.events, fmt.Sprintf("drain:%s", timeout))
	started := r.drainStarted
	release := r.releaseDrain
	block := r.blockDrain
	drainErr := r.drainErr
	r.mu.Unlock()
	if started != nil {
		r.startOnce.Do(func() { close(started) })
	}
	if !block {
		return drainErr
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	select {
	case <-release:
		return drainErr
	case <-ctx.Done():
		return ctx.Err()
	case <-deadline.C:
		return context.DeadlineExceeded
	}
}

func (r *drainTestRuntime) snapshot() (string, []string, []time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active, append([]string(nil), r.events...), append([]time.Duration(nil), r.drainCalls...)
}

type drainTestConnection struct{ generation string }

func (r *drainTestRuntime) openLongConnection() drainTestConnection {
	r.mu.Lock()
	defer r.mu.Unlock()
	return drainTestConnection{generation: r.active}
}

func (r *drainTestRuntime) openConnection() drainTestConnection {
	return r.openLongConnection()
}

func (r *drainTestRuntime) exchange(connection drainTestConnection) string {
	return connection.generation
}

func drainConfig(versionID string, timeoutMS int) Config {
	config := validConfig(versionID)
	config.DrainTimeoutMS = timeoutMS
	return config
}

func TestManagerDrainKeepsLongTCPAndRoutesNewConnectionsToCandidate(t *testing.T) {
	runtime := &drainTestRuntime{drainStarted: make(chan struct{}), releaseDrain: make(chan struct{}), blockDrain: true}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), drainConfig("l4-v1", 0))
	if err != nil {
		t.Fatal(err)
	}
	long := runtime.openLongConnection()

	resultCh := make(chan struct {
		result Result
		err    error
	}, 1)
	go func() {
		result, applyErr := manager.Apply(context.Background(), drainConfig("l4-v2", 250))
		resultCh <- struct {
			result Result
			err    error
		}{result: result, err: applyErr}
	}()
	select {
	case <-runtime.drainStarted:
	case <-time.After(time.Second):
		t.Fatal("candidate activation did not enter the drain phase")
	}

	if got := runtime.exchange(long); got != "l4-v1-"+first.Digest {
		t.Fatalf("long TCP connection generation = %q, want LKG %q", got, "l4-v1-"+first.Digest)
	}
	newConnection := runtime.openConnection()
	if got := runtime.exchange(newConnection); !strings.HasPrefix(got, "l4-v2-") {
		t.Fatalf("new TCP connection generation = %q, want candidate", got)
	}
	close(runtime.releaseDrain)

	select {
	case outcome := <-resultCh:
		if outcome.err != nil || outcome.result.State != StateApplied || outcome.result.ActiveVersionID != "l4-v2" {
			t.Fatalf("candidate Apply() = %+v, %v", outcome.result, outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("candidate activation did not complete after drain release")
	}

	active, events, calls := runtime.snapshot()
	if !strings.HasPrefix(active, "l4-v2-") || !reflect.DeepEqual(calls, []time.Duration{250 * time.Millisecond}) {
		t.Fatalf("active=%q drain calls=%v", active, calls)
	}
	if !reflect.DeepEqual(events, []string{"activate:l4-v1-" + first.Digest, "activate:l4-v2-" + resultDigest(t, "l4-v2", 250), "drain:250ms"}) {
		t.Fatalf("runtime audit events = %v", events)
	}
	if got := currentTarget(filepath.Join(root, "current")); !strings.HasPrefix(got, "l4-v2-") {
		t.Fatalf("current target = %q, want candidate", got)
	}
}

func TestManagerDrainTimeoutRollsBackToLKGAndKeepsCurrentStable(t *testing.T) {
	runtime := &drainTestRuntime{blockDrain: true}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), drainConfig("l4-v1", 0))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	failed, err := manager.Apply(context.Background(), drainConfig("l4-v2", 100))
	elapsed := time.Since(started)
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "DRAIN_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != first.VersionID || failed.ActiveDigest != first.Digest {
		t.Fatalf("drain timeout Apply() = %+v, %v", failed, err)
	}
	if elapsed < 90*time.Millisecond || elapsed > time.Second {
		t.Fatalf("drain timeout elapsed=%s, want bounded around 100ms", elapsed)
	}
	if got := currentTarget(filepath.Join(root, "current")); got != first.VersionID+"-"+first.Digest {
		t.Fatalf("current target after timeout = %q, want LKG", got)
	}
	active, events, calls := runtime.snapshot()
	if active != first.VersionID+"-"+first.Digest || !reflect.DeepEqual(calls, []time.Duration{100 * time.Millisecond}) {
		t.Fatalf("active=%q drain calls=%v", active, calls)
	}
	wantSuffix := []string{"activate:l4-v2-" + resultDigest(t, "l4-v2", 100), "drain:100ms", "activate:l4-v1-" + first.Digest}
	if len(events) < len(wantSuffix) || !reflect.DeepEqual(events[len(events)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("rollback audit events = %v, want suffix %v", events, wantSuffix)
	}
	status, statusErr := manager.Status()
	if statusErr != nil || !status.Active || status.VersionID != first.VersionID || status.Digest != first.Digest {
		t.Fatalf("status after timeout = %+v, %v", status, statusErr)
	}
}

func TestManagerDrainFailureRestoresInitialStateAndStopsCandidate(t *testing.T) {
	runtime := &drainTestRuntime{drainErr: errInjectedDrain}
	manager, root := testManager(t, runtime)
	failed, err := manager.Apply(context.Background(), drainConfig("l4-v1", 100))
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "DRAIN_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "" {
		t.Fatalf("initial drain failure = %+v, %v", failed, err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "current")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("initial drain failure left current symlink: %v", statErr)
	}
	_, events, calls := runtime.snapshot()
	if !reflect.DeepEqual(calls, []time.Duration{100 * time.Millisecond}) || len(events) != 3 || !strings.HasPrefix(events[1], "drain:") || !strings.HasPrefix(events[0], "activate:") || !strings.HasPrefix(events[2], "stop:") {
		t.Fatalf("initial drain events=%v calls=%v", events, calls)
	}
}

func TestDrainTimeoutBoundsAndZeroPreservesLegacyNginxBytes(t *testing.T) {
	for _, timeoutMS := range []int{1, 99, 60_001} {
		if _, err := Compile(drainConfig("invalid-drain", timeoutMS)); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Compile(timeout=%d) error=%v, want ErrInvalidConfig", timeoutMS, err)
		}
	}

	base := drainConfig("udp-baseline", 0)
	base.Listeners[0].TrafficHealth = &TrafficHealthPolicy{Request: []byte("PING"), ExpectedResponse: []byte("PONG"), TimeoutMS: 100, Attempts: 1}
	without, err := Compile(base)
	if err != nil {
		t.Fatal(err)
	}
	withConfig := base
	withConfig.DrainTimeoutMS = 60000
	with, err := Compile(withConfig)
	if err != nil {
		t.Fatal(err)
	}
	withoutBody := strings.Join(strings.Split(string(without.NginxConfig), "\n")[2:], "\n")
	withBody := strings.Join(strings.Split(string(with.NginxConfig), "\n")[2:], "\n")
	if withoutBody != withBody {
		t.Fatalf("drain timeout changed legacy nginx bytes:\nwithout=%s\nwith=%s", withoutBody, withBody)
	}
	udpWithout := listenerForProtocol(t, without.Config, ProtocolUDP)
	udpWith := listenerForProtocol(t, with.Config, ProtocolUDP)
	if !reflect.DeepEqual(udpWithout, udpWith) || !strings.Contains(withBody, "listen 0.0.0.0:5353 udp") || !strings.Contains(withBody, "proxy_responses 1;") {
		t.Fatalf("UDP semantics changed: without=%+v with=%+v", udpWithout, udpWith)
	}
}

func TestOpenRestyDrainKeepsLongConnectionGenerationUntilItExits(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, record)
	master := &fakeProcessHandle{alive: reloadAliveSamples()}
	controller := testOpenResty(t, pidFile)
	controller.retired = []*retiredGeneration{{workers: workerGeneration{{PID: 101, StartTicks: 1001}: {}}, master: record}}
	controller.inspect = func(pid int) (processIdentity, error) {
		if pid != record.PID {
			return processIdentity{}, fmt.Errorf("unexpected inspect pid %d", pid)
		}
		return record, nil
	}
	controller.openProcess = func(pid int) (processHandle, error) {
		if pid != record.PID {
			return nil, fmt.Errorf("unexpected open pid %d", pid)
		}
		return master, nil
	}
	snapshots := 0
	controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
		snapshots++
		if snapshots == 1 {
			return workerGeneration{{PID: 101, StartTicks: 1001}: {}}, nil
		}
		return workerGeneration{}, nil
	}
	if err := controller.Drain(context.Background(), 100*time.Millisecond); err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if signals, closes := master.snapshot(); len(signals) != 0 || closes != 1 {
		t.Fatalf("master signals=%v closes=%d, want no signal and one close", signals, closes)
	}
	if len(controller.retired) != 0 {
		t.Fatalf("drain generation remained after natural exit: %+v", controller.retired)
	}
}

// Old workers exit independently: at the deadline one may already be gone
// while a sibling still holds a long connection. Only the survivor is signaled.
func TestOpenRestyDrainTimeoutSkipsOldWorkerThatAlreadyExited(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, record)
	master := &fakeProcessHandle{alive: reloadAliveSamples()}
	survivor := &fakeProcessHandle{}
	controller := testOpenResty(t, pidFile)
	controller.timeout = 40 * time.Millisecond
	exited := workerIdentity{PID: 101, StartTicks: 1001}
	lingering := workerIdentity{PID: 102, StartTicks: 1002}
	controller.retired = []*retiredGeneration{{workers: workerGeneration{exited: {}, lingering: {}}, master: record}}
	controller.inspect = func(pid int) (processIdentity, error) {
		switch pid {
		case record.PID:
			return record, nil
		case exited.PID:
			return processIdentity{}, errProcessNotRunning
		case lingering.PID:
			return processIdentity{PID: lingering.PID, StartTicks: lingering.StartTicks}, nil
		default:
			return processIdentity{}, fmt.Errorf("unexpected inspect pid %d", pid)
		}
	}
	controller.openProcess = func(pid int) (processHandle, error) {
		switch pid {
		case record.PID:
			return master, nil
		case lingering.PID:
			return survivor, nil
		default:
			return nil, fmt.Errorf("unexpected open pid %d", pid)
		}
	}
	controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
		if signals, _ := survivor.snapshot(); len(signals) > 0 {
			return workerGeneration{}, nil
		}
		return workerGeneration{lingering: {}}, nil
	}
	if err := controller.Drain(context.Background(), 10*time.Millisecond); err != nil {
		t.Fatalf("Drain() with one old worker already exited: %v", err)
	}
	if signals, closes := survivor.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM}) || closes != 1 {
		t.Fatalf("lingering worker signals=%v closes=%d, want one SIGTERM and close", signals, closes)
	}
	if len(controller.retired) != 0 {
		t.Fatalf("drain generation remained: %+v", controller.retired)
	}
}

func TestOpenRestyDrainTimeoutSignalsOnlyVerifiedOldWorkers(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, record)
	master := &fakeProcessHandle{alive: reloadAliveSamples()}
	oldWorker := &fakeProcessHandle{}
	controller := testOpenResty(t, pidFile)
	controller.timeout = 40 * time.Millisecond
	old := workerIdentity{PID: 101, StartTicks: 1001}
	newWorker := workerIdentity{PID: 201, StartTicks: 2001}
	controller.retired = []*retiredGeneration{{workers: workerGeneration{old: {}}, master: record}}
	controller.inspect = func(pid int) (processIdentity, error) {
		switch pid {
		case record.PID:
			return record, nil
		case old.PID:
			return processIdentity{PID: old.PID, StartTicks: old.StartTicks}, nil
		case newWorker.PID:
			return processIdentity{PID: newWorker.PID, StartTicks: newWorker.StartTicks}, nil
		default:
			return processIdentity{}, fmt.Errorf("unexpected inspect pid %d", pid)
		}
	}
	controller.openProcess = func(pid int) (processHandle, error) {
		switch pid {
		case record.PID:
			return master, nil
		case old.PID:
			return oldWorker, nil
		case newWorker.PID:
			return nil, fmt.Errorf("new worker %d was signaled", pid)
		default:
			return nil, fmt.Errorf("unexpected open pid %d", pid)
		}
	}
	controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
		signals, _ := oldWorker.snapshot()
		if len(signals) > 0 {
			return workerGeneration{}, nil
		}
		return workerGeneration{old: {}, newWorker: {}}, nil
	}
	started := time.Now()
	if err := controller.Drain(context.Background(), 10*time.Millisecond); err != nil {
		t.Fatalf("Drain() forced termination error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("forced drain took %s, want bounded completion", elapsed)
	}
	if signals, closes := oldWorker.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGTERM}) || closes != 1 {
		t.Fatalf("old worker signals=%v closes=%d, want one SIGTERM and close", signals, closes)
	}
	if signals, _ := master.snapshot(); len(signals) != 0 {
		t.Fatalf("master received worker drain signal(s): %v", signals)
	}
}

func resultDigest(t *testing.T, versionID string, timeoutMS int) string {
	t.Helper()
	compiled, err := Compile(drainConfig(versionID, timeoutMS))
	if err != nil {
		t.Fatal(err)
	}
	return compiled.Digest
}
