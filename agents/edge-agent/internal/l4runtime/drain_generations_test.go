package l4runtime

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeNginx models an nginx master: SIGHUP starts a new worker generation and
// gracefully quits the serving one. Quitting workers that hold sessions stay
// ("shutting down") until they are terminated; idle ones exit at once.
type fakeNginx struct {
	mu            sync.Mutex
	master        processIdentity
	handle        *fakeProcessHandle
	perGeneration int
	holdSessions  bool
	nextPID       int
	workers       map[workerIdentity]bool // value: shutting down
	terminated    []workerIdentity
}

func newFakeNginx(t *testing.T, perGeneration int, holdSessions bool) (*fakeNginx, *OpenResty, string) {
	t.Helper()
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, record)
	nginx := &fakeNginx{master: record, perGeneration: perGeneration, holdSessions: holdSessions,
		nextPID: 100, workers: map[workerIdentity]bool{}}
	nginx.spawn()
	nginx.handle = &fakeProcessHandle{onSignal: func(signal syscall.Signal) error {
		if signal == syscall.SIGHUP {
			nginx.reload()
		}
		return nil
	}}
	controller := testOpenResty(t, pidFile)
	controller.timeout = 2 * time.Second
	controller.inspect = func(pid int) (processIdentity, error) {
		if pid == record.PID {
			return record, nil
		}
		nginx.mu.Lock()
		defer nginx.mu.Unlock()
		for worker := range nginx.workers {
			if worker.PID == pid {
				return processIdentity{PID: worker.PID, StartTicks: worker.StartTicks}, nil
			}
		}
		return processIdentity{}, errProcessNotRunning
	}
	controller.openProcess = func(pid int) (processHandle, error) {
		if pid == record.PID {
			return &aliveHandle{fakeProcessHandle: nginx.handle}, nil
		}
		return &fakeProcessHandle{onSignal: func(signal syscall.Signal) error {
			if signal == syscall.SIGTERM {
				nginx.terminate(pid)
			}
			return nil
		}}, nil
	}
	controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
		nginx.mu.Lock()
		defer nginx.mu.Unlock()
		generation := make(workerGeneration, len(nginx.workers))
		for worker := range nginx.workers {
			generation[worker] = struct{}{}
		}
		return generation, nil
	}
	controller.shuttingDown = func(worker workerIdentity) bool {
		nginx.mu.Lock()
		defer nginx.mu.Unlock()
		return nginx.workers[worker]
	}
	return nginx, controller, root
}

// aliveHandle reports the master alive for as long as a test needs.
type aliveHandle struct{ *fakeProcessHandle }

func (aliveHandle) Alive() (bool, error) { return true, nil }
func (aliveHandle) Close() error         { return nil }

func (nginx *fakeNginx) spawn() {
	for range nginx.perGeneration {
		nginx.nextPID++
		nginx.workers[workerIdentity{PID: nginx.nextPID, StartTicks: uint64(nginx.nextPID) * 10}] = false
	}
}

func (nginx *fakeNginx) reload() {
	nginx.mu.Lock()
	defer nginx.mu.Unlock()
	for worker, shutting := range nginx.workers {
		if shutting {
			continue
		}
		if nginx.holdSessions {
			nginx.workers[worker] = true
		} else {
			delete(nginx.workers, worker)
		}
	}
	nginx.spawn()
}

func (nginx *fakeNginx) terminate(pid int) {
	nginx.mu.Lock()
	defer nginx.mu.Unlock()
	for worker := range nginx.workers {
		if worker.PID == pid {
			delete(nginx.workers, worker)
			nginx.terminated = append(nginx.terminated, worker)
		}
	}
}

func (nginx *fakeNginx) state() (alive int, terminated []workerIdentity) {
	nginx.mu.Lock()
	defer nginx.mu.Unlock()
	return len(nginx.workers), append([]workerIdentity(nil), nginx.terminated...)
}

func (nginx *fakeNginx) alive(worker workerIdentity) bool {
	nginx.mu.Lock()
	defer nginx.mu.Unlock()
	_, ok := nginx.workers[worker]
	return ok
}

// Each reload must confirm against the serving generation only, even while
// earlier generations still drain sessions; none of them is terminated.
func TestOpenRestyReloadConfirmsWhileEarlierGenerationsDrain(t *testing.T) {
	nginx, controller, root := newFakeNginx(t, 2, true)
	for reload := 1; reload <= 3; reload++ {
		if err := controller.Activate(context.Background(), root); err != nil {
			t.Fatalf("reload %d with %d draining generations: %v", reload, reload-1, err)
		}
		if err := controller.Drain(context.Background(), 100*time.Millisecond); err != nil {
			t.Fatalf("drain after reload %d: %v", reload, err)
		}
	}
	alive, terminated := nginx.state()
	if alive != 8 || len(terminated) != 0 {
		t.Fatalf("alive workers=%d terminated=%v, want 3 draining generations + 1 serving and none terminated", alive, terminated)
	}
	if status := controller.DrainStatus(); status.Generations != 3 || status.Workers != 6 || status.OldestRetiredAt.IsZero() {
		t.Fatalf("DrainStatus() = %+v", status)
	}
}

// Draining sessions are not a deployment failure: Drain returns at once and
// never signals workers that already stopped accepting.
func TestOpenRestyDrainLeavesShuttingDownWorkersServing(t *testing.T) {
	nginx, controller, root := newFakeNginx(t, 2, true)
	if err := controller.Activate(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := controller.Drain(context.Background(), 30*time.Second); err != nil {
		t.Fatalf("Drain() = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Drain() waited %s for sessions to end", elapsed)
	}
	if alive, terminated := nginx.state(); alive != 4 || len(terminated) != 0 {
		t.Fatalf("alive=%d terminated=%v, want retired workers still serving", alive, terminated)
	}
}

func TestOpenRestyEndsOldestDrainingGenerationBeyondLimit(t *testing.T) {
	nginx, controller, root := newFakeNginx(t, 2, true)
	first := make([]workerIdentity, 0, 2)
	for worker := range nginx.workers {
		first = append(first, worker)
	}
	for reload := 1; reload <= maxRetiredGenerations+2; reload++ {
		if err := controller.Activate(context.Background(), root); err != nil {
			t.Fatalf("reload %d: %v", reload, err)
		}
	}
	alive, terminated := nginx.state()
	if len(terminated) != 4 || alive != 2*(maxRetiredGenerations+1) {
		t.Fatalf("alive=%d terminated=%d, want the two oldest generations ended", alive, len(terminated))
	}
	for _, worker := range first {
		if nginx.alive(worker) {
			t.Fatalf("oldest generation worker %d still runs", worker.PID)
		}
	}
	if status := controller.DrainStatus(); status.Generations != maxRetiredGenerations {
		t.Fatalf("DrainStatus() = %+v, want %d generations", status, maxRetiredGenerations)
	}
}

func TestOpenRestyDrainLimitEndsRetiredGeneration(t *testing.T) {
	nginx, controller, root := newFakeNginx(t, 2, true)
	if err := controller.SetDrainLimit(150 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := controller.Activate(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if alive, _ := nginx.state(); alive != 4 {
		t.Fatalf("retired generation ended before its limit: alive=%d", alive)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if alive, terminated := nginx.state(); alive == 2 && len(terminated) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retired generation outlived its drain limit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status := controller.DrainStatus(); status.Generations != 0 {
		t.Fatalf("DrainStatus() = %+v after the limit", status)
	}

	// 0 is unlimited: the next retired generation keeps draining.
	if err := controller.SetDrainLimit(0); err != nil {
		t.Fatal(err)
	}
	if err := controller.Activate(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if alive, terminated := nginx.state(); alive != 4 || len(terminated) != 2 {
		t.Fatalf("unlimited drain ended sessions: alive=%d terminated=%d", alive, len(terminated))
	}
}

func TestOpenRestyStopForgetsDrainingGenerations(t *testing.T) {
	nginx, controller, root := newFakeNginx(t, 1, true)
	if err := controller.SetDrainLimit(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := controller.Activate(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	nginx.handle.onSignal = func(syscall.Signal) error { return nil }
	stopCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = controller.Stop(stopCtx, root) // the fake master never exits
	time.Sleep(250 * time.Millisecond)
	if _, terminated := nginx.state(); len(terminated) != 0 || len(controller.retired) != 0 {
		t.Fatalf("stopped runtime kept a drain timer: terminated=%v retired=%d", terminated, len(controller.retired))
	}
}

func TestOpenRestySetDrainLimitBounds(t *testing.T) {
	controller := testOpenResty(t, filepath.Join(t.TempDir(), "nginx.pid"))
	if controller.drainLimit != 24*time.Hour {
		t.Fatalf("default drain limit = %s, want 24h", controller.drainLimit)
	}
	for _, limit := range []time.Duration{-time.Millisecond, 7*24*time.Hour + time.Millisecond} {
		if err := controller.SetDrainLimit(limit); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("SetDrainLimit(%s) = %v", limit, err)
		}
	}
	for _, limit := range []time.Duration{0, time.Second, 7 * 24 * time.Hour} {
		if err := controller.SetDrainLimit(limit); err != nil {
			t.Fatalf("SetDrainLimit(%s) = %v", limit, err)
		}
	}
}
