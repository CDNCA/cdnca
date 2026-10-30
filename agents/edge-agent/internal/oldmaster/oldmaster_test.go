package oldmaster

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	oldPID    = 100
	freshPID  = 200
	workerPID = 101
	cachePID  = 102
)

// fakeMasters: old (100) with workers 101/102 and the new master 200 as
// children; exitOn is the signal old exits on (0: survives everything).
type fakeMasters struct {
	mu      sync.Mutex
	exitOn  syscall.Signal
	exited  map[int]bool
	signals []string
}

func newFakeMasters(exitOn syscall.Signal) *fakeMasters {
	return &fakeMasters{exitOn: exitOn, exited: map[int]bool{}}
}

func (f *fakeMasters) system() system {
	return system{
		stat: func(pid int) (process, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.exited[pid] {
				return process{}, os.ErrNotExist
			}
			switch pid {
			case oldPID:
				return process{parent: 1, start: 7}, nil
			case freshPID:
				if f.exited[oldPID] {
					return process{parent: 1, start: 9}, nil
				}
				return process{parent: oldPID, start: 9}, nil
			case workerPID, cachePID:
				return process{parent: oldPID, start: 8}, nil
			}
			return process{}, os.ErrNotExist
		},
		children: func(int) []int { return []int{workerPID, freshPID, cachePID} },
		signal: func(pid int, signal syscall.Signal) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.signals = append(f.signals, strconv.Itoa(pid)+":"+signal.String())
			if pid == oldPID && (signal == f.exitOn || signal == syscall.SIGKILL && f.exitOn != 0) {
				f.exited[oldPID] = true
			}
			return nil
		},
		poll: time.Millisecond,
	}
}

func (f *fakeMasters) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.signals...)
}

func TestRetireQuitEnoughSendsNothingElse(t *testing.T) {
	f := newFakeMasters(syscall.SIGQUIT)
	if err := f.system().retire(context.Background(), oldPID, freshPID, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := f.sent(); !reflect.DeepEqual(got, []string{"100:quit"}) {
		t.Fatalf("signals = %v", got)
	}
}

func TestRetireTermAfterQuitGrace(t *testing.T) {
	f := newFakeMasters(syscall.SIGTERM)
	started := time.Now()
	if err := f.system().retire(context.Background(), oldPID, freshPID, 30*time.Millisecond, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := f.sent(); !reflect.DeepEqual(got, []string{"100:quit", "100:terminated"}) {
		t.Fatalf("signals = %v", got)
	}
	if elapsed := time.Since(started); elapsed < 30*time.Millisecond {
		t.Fatalf("TERM after %v, before the QUIT grace", elapsed)
	}
}

// Sessions held past both graces: old and its workers get KILL, never the
// new master.
func TestRetireKillsMasterAndWorkersButNotNewMaster(t *testing.T) {
	f := newFakeMasters(syscall.SIGKILL)
	if err := f.system().retire(context.Background(), oldPID, freshPID, 10*time.Millisecond, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	want := []string{"100:quit", "100:terminated", "100:killed", "101:killed", "102:killed"}
	if got := f.sent(); !reflect.DeepEqual(got, want) {
		t.Fatalf("signals = %v, want %v", got, want)
	}
}

func TestRetireCancelledSkipsToKill(t *testing.T) {
	f := newFakeMasters(syscall.SIGKILL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.system().retire(ctx, oldPID, freshPID, time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := f.sent(); !reflect.DeepEqual(got, []string{"100:killed", "101:killed", "102:killed"}) {
		t.Fatalf("signals = %v", got)
	}
}

func TestRetireSurvivingKillIsAnError(t *testing.T) {
	f := newFakeMasters(0)
	if err := f.system().retire(context.Background(), oldPID, freshPID, time.Millisecond, 10*time.Millisecond); err == nil {
		t.Fatal("want an error for a master that survived KILL")
	}
}

// old is not the new master's parent (it exited, its pid may be reused):
// nothing is signalled.
func TestRetireNotParentSignalsNothing(t *testing.T) {
	f := newFakeMasters(syscall.SIGQUIT)
	if err := f.system().retire(context.Background(), workerPID, freshPID, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	f.exited[oldPID] = true
	if err := f.system().retire(context.Background(), oldPID, freshPID, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := f.sent(); len(got) != 0 {
		t.Fatalf("signals = %v, want none", got)
	}
}

// A pid file .oldbin that is not the parent of the master (stale, or this
// test process standing for an unrelated pid) retires nothing.
func TestRetirePreviousIgnoresStaleOldbin(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "nginx.pid")
	if err := RetirePrevious(context.Background(), pidFile, os.Getpid()); err != nil {
		t.Fatalf("missing .oldbin: %v", err)
	}
	if err := os.WriteFile(pidFile+".oldbin", []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RetirePrevious(context.Background(), pidFile, os.Getpid()); err != nil {
		t.Fatalf("self .oldbin: %v", err)
	}
	if err := RetirePrevious(context.Background(), pidFile, 1); err != nil {
		t.Fatalf("unrelated .oldbin: %v", err)
	}
}
