package dynroute

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/oldmaster"
)

// Native runtime switch (node-runtime-upgrade): the OpenResty binary and Lua
// of the running master change on disk; nginx's binary upgrade moves the
// master to them without closing a connection.

// UpgradeBinary replaces the running master by one started from the current
// binary (nginx binary upgrade): USR2 starts the new master, which inherits
// the listening sockets and writes nginx.pid (the old one moves to
// nginx.pid.oldbin). Each master has its own shared dictionaries: the new
// workers rebuild the site index from the current index file (cold start).
// Once a control socket answer comes from a new worker at the current
// generation, WINCH stops the old workers accepting and the old master is
// retired (oldmaster.Retire: QUIT, TERM after 10 seconds, KILL 5 seconds
// later; connections it still holds are cut). A new master that does not come up is rolled
// back as nginx documents: HUP the old master (it starts workers again) and
// QUIT the new one. No master: nothing to do (the next start uses the new
// binary).
func (runtime *Runtime) UpgradeBinary(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if _, alive := runtime.masterPID(); !alive {
		return nil
	}
	err := UpgradeMaster(ctx, filepath.Join(runtime.config.SharedRoot, "nginx.pid"), func(ctx context.Context, fresh int) error {
		index, found, err := runtime.activator.Files.Current()
		if err != nil {
			return err
		}
		var generation uint64
		if found {
			generation = index.Generation
		}
		waitCtx, cancel := context.WithTimeout(ctx, runtime.config.HealthTimeout)
		defer cancel()
		if err := runtime.waitMasterServes(waitCtx, fresh, generation); err != nil {
			return fmt.Errorf("new master %d at site index generation %d: %w", fresh, generation, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The new master's cache dictionary is empty: push the purge
	// generations and a new prewarm token.
	return runtime.startCache(ctx, true)
}

// UpgradeMaster is the nginx binary upgrade of the master whose pid file is
// pidFile (Runtime.UpgradeBinary; the native runtime acceptance drives it
// against a real OpenResty): USR2, wait for the new master, serves confirms
// it answers, then WINCH and retire the old master (oldmaster.Retire). A
// master an earlier upgrade replaced and left running is retired first:
// nginx ignores USR2 while it runs. A new master that does not come up or
// serve is rolled back (HUP old, QUIT new) and the old master keeps serving.
// No live master: nothing to do.
func UpgradeMaster(ctx context.Context, pidFile string, serves func(ctx context.Context, fresh int) error) error {
	old, err := readPID(pidFile)
	if err != nil || syscall.Kill(old, 0) != nil {
		return nil
	}
	if err := oldmaster.RetirePrevious(ctx, pidFile, old); err != nil {
		return fmt.Errorf("openresty binary upgrade: %w", err)
	}
	oldbin := pidFile + ".oldbin"
	if err := syscall.Kill(old, syscall.SIGUSR2); err != nil {
		return fmt.Errorf("openresty binary upgrade: signal master %d: %w", old, err)
	}
	fresh, err := waitNewMaster(ctx, pidFile, oldbin, old, 30*time.Second)
	if err != nil {
		return fmt.Errorf("openresty binary upgrade: %w", err)
	}
	if err := serves(ctx, fresh); err != nil {
		hupErr := syscall.Kill(old, syscall.SIGHUP)
		_ = syscall.Kill(fresh, syscall.SIGQUIT)
		waitExit(fresh, 15*time.Second)
		// The old master renames nginx.pid.oldbin back when the new one exits.
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if pid, err := readPID(pidFile); err == nil && pid == old {
				break
			}
		}
		if pid, err := readPID(pidFile); err != nil || pid != old {
			hupErr = errors.Join(hupErr, os.WriteFile(pidFile, []byte(strconv.Itoa(old)+"\n"), 0o644))
		}
		return errors.Join(fmt.Errorf("openresty binary upgrade: %w", err), hupErr)
	}
	_ = syscall.Kill(old, syscall.SIGWINCH)
	if err := oldmaster.Retire(ctx, old, fresh); err != nil {
		// The new master serves; only a master that survived KILL is left.
		slog.Warn("old OpenResty master left running", "event", "openresty_old_master_left", "error", err)
	}
	return nil
}

// waitMasterServes waits for a control socket answer from a worker of
// master at the generation (both masters' workers accept on the socket until
// the old ones are retired; a worker's status lists its own master's
// workers). Without /proc any answer at the generation counts.
func (runtime *Runtime) waitMasterServes(ctx context.Context, master int, generation uint64) error {
	for {
		status, err := runtime.activator.Control.Status(ctx)
		if err == nil && status.Generation == generation {
			children := workerPIDs(master)
			if children == nil {
				return nil
			}
			for pid := range status.Workers {
				if slices.Contains(children, pid) {
					return nil
				}
			}
		}
		if status.Rebuild != nil && status.Rebuild.Error != "" {
			return fmt.Errorf("site index rebuild: %s", status.Rebuild.Error)
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// waitNewMaster waits until the old master renamed its pid file and the new
// master wrote its own (a different, live pid).
func waitNewMaster(ctx context.Context, pidFile, oldbin string, old int, limit time.Duration) (int, error) {
	deadline := time.Now().Add(limit)
	for {
		if renamed, err := readPID(oldbin); err == nil && renamed == old {
			if fresh, err := readPID(pidFile); err == nil && fresh != old && syscall.Kill(fresh, 0) == nil {
				return fresh, nil
			}
		}
		if syscall.Kill(old, 0) != nil {
			return 0, fmt.Errorf("master %d exited during the binary upgrade", old)
		}
		if time.Now().After(deadline) {
			return 0, errors.New("the new master did not start")
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func readPID(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 2 {
		return 0, errors.New("invalid pid file")
	}
	return pid, nil
}

func waitExit(pid int, limit time.Duration) {
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if syscall.Kill(pid, 0) != nil {
			return
		}
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
