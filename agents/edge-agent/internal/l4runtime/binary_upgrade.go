package l4runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Native runtime switch (node-runtime-upgrade): the OpenResty binary the
// configured path resolves to changed on disk; nginx's binary upgrade moves
// the L4 master to it without closing a session.

// UpgradeBinary replaces the owned master by one started from the binary
// the OpenResty path resolves to now: USR2 makes the master start the new
// binary, which inherits the listening sockets and writes the pid file (the
// old one moves to <pid>.oldbin). Once the new master (a child of the old
// one, running the new binary) has a stable worker generation, the identity
// record names it and the old master is retired like the HTTP one
// (oldmaster.Retire: QUIT, TERM after 10 seconds, KILL with its workers 5
// seconds later; sessions it still holds are cut). A master an earlier
// upgrade replaced and left running is retired the same way before USR2
// (nginx ignores USR2 while it runs). A new master that does not come up
// gets QUIT and the old master keeps serving untouched (no HUP: a reload
// would retire the workers holding sessions). No owned master, or it
// already runs that binary: nothing to do.
func (r *OpenResty) UpgradeBinary(ctx context.Context) (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	handle, record, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if !running {
		return nil
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	device, inode, err := executableFileIdentity(r.binary)
	if err != nil {
		return err
	}
	if record.ExecutableDevice == device && record.ExecutableInode == inode {
		return nil
	}
	if previous, ok := r.previousMaster(record.PID); ok {
		if err := r.retireMaster(ctx, previous, record.PID); err != nil {
			return fmt.Errorf("L4 OpenResty binary upgrade: %w", err)
		}
	}
	retireCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if err := handle.Signal(syscall.SIGUSR2); err != nil {
		return fmt.Errorf("L4 OpenResty binary upgrade: signal master %d: %w", record.PID, err)
	}
	freshHandle, fresh, err := r.openUpgradedMaster(ctx, handle, record)
	if err == nil && (fresh.ExecutableDevice != device || fresh.ExecutableInode != inode ||
		fresh.OwnerUID != record.OwnerUID || fresh.BootID != record.BootID) {
		err = fmt.Errorf("new master %d does not run the switched binary", fresh.PID)
	}
	if err == nil {
		err = waitForInitialWorkerGeneration(ctx, freshHandle, fresh, r.inspect, r.workerGeneration)
	}
	if err == nil {
		err = r.writeIdentity(r.pidFile+".identity", []byte(formatProcessRecord(fresh)))
	}
	if err != nil {
		return errors.Join(fmt.Errorf("L4 OpenResty binary upgrade: %w", err), r.abandonUpgrade(record, freshHandle))
	}
	defer func() { result = errors.Join(result, freshHandle.Close()) }()
	if err := r.retireMaster(retireCtx, record.PID, fresh.PID); err != nil {
		// The new master serves; only a master that survived KILL is left.
		slog.Warn("old L4 OpenResty master left running", "event", "l4_old_master_left", "error", err)
	}
	return nil
}

// previousMaster is the master <pid>.oldbin names when it still runs as the
// parent of master: an earlier binary upgrade's old master left running.
func (r *OpenResty) previousMaster(master int) (int, bool) {
	previous, exists, err := readProcessPID(r.pidFile + ".oldbin")
	if err != nil || !exists || previous == master {
		return 0, false
	}
	if parent, err := r.parentPID(master); err != nil || parent != previous {
		return 0, false
	}
	return previous, true
}

// openUpgradedMaster waits for the master the old one started: the old pid
// moved to <pid>.oldbin and the pid file names a live child of the old one.
func (r *OpenResty) openUpgradedMaster(ctx context.Context, old processHandle, record processIdentity) (processHandle, processIdentity, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if renamed, exists, err := readProcessPID(r.pidFile + ".oldbin"); err == nil && exists && renamed == record.PID {
			if pid, exists, err := readProcessPID(r.pidFile); err == nil && exists && pid != record.PID {
				if parent, err := r.parentPID(pid); err == nil && parent == record.PID {
					identity, inspectErr := r.inspect(pid)
					if inspectErr == nil {
						handle, openErr := r.openProcess(pid)
						if openErr == nil {
							confirmed, confirmErr := r.inspect(pid)
							if confirmErr == nil && confirmed == identity {
								return handle, identity, nil
							}
							_ = handle.Close()
						}
					}
				}
			}
		}
		if alive, err := old.Alive(); err != nil || !alive {
			return nil, processIdentity{}, errors.Join(fmt.Errorf("master %d exited during the binary upgrade", record.PID), err)
		}
		select {
		case <-ctx.Done():
			return nil, processIdentity{}, errors.Join(errors.New("the new master did not start"), ctx.Err())
		case <-ticker.C:
		}
	}
}

// abandonUpgrade stops the new master (fresh, or the old master's child the
// pid file names) gracefully, never killing it: sessions it accepted end on
// their own. The pid file names the old master again (nginx renames
// <pid>.oldbin back once the new master exits; until then it is rewritten).
func (r *OpenResty) abandonUpgrade(record processIdentity, fresh processHandle) error {
	if fresh == nil {
		if pid, exists, err := readProcessPID(r.pidFile); err == nil && exists && pid != record.PID {
			if parent, err := r.parentPID(pid); err == nil && parent == record.PID {
				fresh, _ = r.openProcess(pid)
			}
		}
	}
	var result error
	if fresh != nil {
		if err := fresh.Signal(syscall.SIGQUIT); err != nil && !errors.Is(err, syscall.ESRCH) {
			result = err
		}
		_, _ = waitProcessHandleExit(fresh, r.timeout)
		result = errors.Join(result, fresh.Close())
	}
	if pid, exists, err := readProcessPID(r.pidFile); err != nil || !exists || pid != record.PID {
		result = errors.Join(result, r.writeIdentity(r.pidFile, []byte(strconv.Itoa(record.PID)+"\n")))
	}
	return result
}

func executableFileIdentity(path string) (uint64, uint64, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0, 0, errors.New("OpenResty binary identity is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, 0, errors.New("OpenResty binary identity is invalid")
	}
	return uint64(stat.Dev), uint64(stat.Ino), nil
}

func kernelParentPID(pid int) (int, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	separator := bytes.LastIndex(raw, []byte(") "))
	if separator < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(raw[separator+2:]))
	if len(fields) < 2 {
		return 0, errors.New("invalid process stat")
	}
	return strconv.Atoi(fields[1])
}
