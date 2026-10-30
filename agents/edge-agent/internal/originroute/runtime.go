package originroute

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type HealthProbe func(context.Context, string) error

type OpenRestyRuntime struct {
	binary    string
	stateRoot string
	pidFile   string
	probe     HealthProbe
}

var errTransientPID = errors.New("origin route master PID is not complete")

func NewOpenRestyRuntime(binary, stateRoot string, probe HealthProbe) (*OpenRestyRuntime, error) {
	if !safeAbsolutePath(binary) || !safeAbsolutePath(stateRoot) || probe == nil {
		return nil, invalid("OpenResty binary, state root, and health probe are required")
	}
	return &OpenRestyRuntime{
		binary: binary, stateRoot: stateRoot,
		pidFile: filepath.Join(stateRoot, "shared", "originroute.pid"), probe: probe,
	}, nil
}

func (runtime *OpenRestyRuntime) Precheck(ctx context.Context, release string) error {
	if err := runtime.validateRelease(release); err != nil {
		return err
	}
	return runtime.command(ctx, "-t", "-p", withTrailingSeparator(release), "-c", "nginx.conf")
}

func (runtime *OpenRestyRuntime) Reload(ctx context.Context, release string) error {
	if err := runtime.validateRelease(release); err != nil {
		return err
	}
	masterPID, running, err := runningProcessID(runtime.pidFile)
	if err != nil && !errors.Is(err, errTransientPID) {
		return err
	}
	var previousWorkers map[int]struct{}
	if running {
		previousWorkers, err = openRestyWorkerProcessIDs(masterPID)
		if err != nil {
			return err
		}
		if len(previousWorkers) == 0 {
			return errors.New("origin route master has no ready worker generation")
		}
	}
	if !running {
		if err := os.Remove(runtime.pidFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	args := []string{"-p", withTrailingSeparator(filepath.Join(runtime.stateRoot, "current")), "-c", "nginx.conf"}
	if running {
		args = append(args, "-s", "reload")
	}
	if err := runtime.command(ctx, args...); err != nil {
		return err
	}
	return runtime.waitWorkerGeneration(ctx, masterPID, previousWorkers)
}

func (runtime *OpenRestyRuntime) Healthy(ctx context.Context, versionID string) error {
	return runtime.probe(ctx, versionID)
}

func (runtime *OpenRestyRuntime) Stop(ctx context.Context) error {
	var pid int
	for {
		var running bool
		var err error
		pid, running, err = runningProcessID(runtime.pidFile)
		if err == nil {
			if !running {
				return removePIDFile(runtime.pidFile)
			}
			break
		}
		if !errors.Is(err, errTransientPID) {
			return err
		}
		if removeErr := os.Remove(runtime.pidFile); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
		return nil
	}
	if err := runtime.command(ctx,
		"-p", withTrailingSeparator(filepath.Join(runtime.stateRoot, "current")),
		"-c", "nginx.conf", "-s", "quit",
	); err != nil {
		return err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		running, err := processRunning(pid)
		if err != nil {
			return err
		}
		if !running {
			return removePIDFile(runtime.pidFile)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (runtime *OpenRestyRuntime) validateRelease(release string) error {
	if !safeAbsolutePath(release) || filepath.Dir(release) != filepath.Join(runtime.stateRoot, "versions") ||
		!digestPattern.MatchString(filepath.Base(release)) {
		return invalid("release path is outside the immutable origin route store")
	}
	info, err := os.Lstat(release)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return invalid("release path is not a regular directory")
	}
	return nil
}

func (runtime *OpenRestyRuntime) waitRunning(ctx context.Context) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, running, err := runningProcessID(runtime.pidFile)
		if err != nil && !errors.Is(err, errTransientPID) {
			return err
		}
		if err == nil && running {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (runtime *OpenRestyRuntime) waitWorkerGeneration(
	ctx context.Context, previousMasterPID int, previousWorkers map[int]struct{},
) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		masterPID, running, err := runningProcessID(runtime.pidFile)
		if err != nil && !errors.Is(err, errTransientPID) {
			return err
		}
		if err == nil && running {
			if previousMasterPID > 0 && masterPID != previousMasterPID {
				return errors.New("origin route master changed during reload")
			}
			workers, workerErr := openRestyWorkerProcessIDs(masterPID)
			if workerErr != nil {
				return workerErr
			}
			if workerGenerationReady(workers, previousWorkers) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func workerGenerationReady(current, previous map[int]struct{}) bool {
	if len(current) == 0 {
		return false
	}
	if len(previous) == 0 {
		return true
	}
	newWorker := false
	for pid := range current {
		if _, existed := previous[pid]; !existed {
			newWorker = true
		}
	}
	if !newWorker {
		return false
	}
	for pid := range previous {
		running, err := processRunning(pid)
		if err != nil || running {
			return false
		}
	}
	return true
}

func openRestyWorkerProcessIDs(masterPID int) (map[int]struct{}, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", masterPID, masterPID))
	if err != nil {
		return nil, fmt.Errorf("read origin route worker generation: %w", err)
	}
	workers := make(map[int]struct{})
	for _, field := range strings.Fields(string(raw)) {
		pid, parseErr := strconv.Atoi(field)
		if parseErr != nil || pid <= 1 {
			return nil, fmt.Errorf("read origin route worker generation: invalid child PID %q", field)
		}
		commandLine, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, syscall.ESRCH) {
			continue
		}
		if readErr != nil {
			return nil, fmt.Errorf("read origin route worker command: %w", readErr)
		}
		if strings.Contains(strings.ReplaceAll(string(commandLine), "\x00", " "), "nginx: worker process") {
			workers[pid] = struct{}{}
		}
	}
	return workers, nil
}

func (runtime *OpenRestyRuntime) command(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, runtime.binary, arguments...)
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return nil
}

func runningProcessID(pidFile string) (int, bool, error) {
	raw, err := os.ReadFile(pidFile)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		value := strings.TrimSpace(string(raw))
		if len(value) > 64 {
			value = value[:64]
		}
		return 0, false, fmt.Errorf("%w: %q", errTransientPID, value)
	}
	running, err := processRunning(pid)
	return pid, running, err
}

func processRunning(pid int) (bool, error) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}
	err = process.Signal(syscall.Signal(0))
	if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stat, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if readErr == nil {
		separator := strings.LastIndex(string(stat), ") ")
		if separator >= 0 && len(stat) > separator+2 && stat[separator+2] == 'Z' {
			return false, nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return false, readErr
	}
	return true, nil
}

func removePIDFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func withTrailingSeparator(path string) string {
	return path + string(filepath.Separator)
}
