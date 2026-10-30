package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxTrackedOpenRestyWorkers = 256

func (o *OpenResty) CaptureGeneration(ctx context.Context) (RuntimeGeneration, error) {
	if o == nil {
		return RuntimeGeneration{}, ErrCorruptState
	}
	return o.captureGenerationFromPIDFile(ctx)
}

func (o *OpenResty) RemainingGeneration(ctx context.Context, generation RuntimeGeneration) (int, error) {
	if o == nil || !validRuntimeGeneration(generation) {
		return 0, ErrCorruptState
	}
	master, err := inspectProcess(generation.Master.PID)
	if err != nil || master != generation.Master {
		return 0, fmt.Errorf("%w: OpenResty master identity changed", ErrCorruptState)
	}
	remaining := 0
	for _, expected := range generation.Workers {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		current, err := inspectProcess(expected.PID)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if current == expected {
			remaining++
		}
	}
	masterAfter, err := inspectProcess(generation.Master.PID)
	if err != nil || masterAfter != generation.Master {
		return 0, fmt.Errorf("%w: OpenResty master changed while observing workers", ErrCorruptState)
	}
	return remaining, nil
}

func (o *OpenResty) captureGenerationFromPIDFile(ctx context.Context) (RuntimeGeneration, error) {
	pidFile, err := o.pidFile()
	if err != nil {
		return RuntimeGeneration{}, err
	}
	masterPID, err := readOpenRestyPID(pidFile)
	if err != nil {
		return RuntimeGeneration{}, err
	}
	master, err := inspectProcess(masterPID)
	if err != nil {
		return RuntimeGeneration{}, err
	}
	if master.Role != "master" {
		return RuntimeGeneration{}, fmt.Errorf("%w: OpenResty PID does not identify the master process", ErrCorruptState)
	}
	if err := verifyOpenRestyExecutable(o.binary, master); err != nil {
		return RuntimeGeneration{}, err
	}
	children, err := readProcessChildren(masterPID)
	if err != nil {
		return RuntimeGeneration{}, err
	}
	if len(children) == 0 || len(children) > maxTrackedOpenRestyWorkers {
		return RuntimeGeneration{}, fmt.Errorf("%w: OpenResty worker set is empty or oversized", ErrCorruptState)
	}
	sort.Ints(children)
	workers := make([]ProcessIdentity, 0, len(children))
	var workerUID uint32
	for _, pid := range children {
		if err := ctx.Err(); err != nil {
			return RuntimeGeneration{}, err
		}
		worker, err := inspectProcess(pid)
		if err != nil {
			return RuntimeGeneration{}, err
		}
		if worker.Role != "worker" {
			continue
		}
		if worker.ParentPID != masterPID || (master.OwnerUID != 0 && worker.OwnerUID != master.OwnerUID) ||
			(len(workers) > 0 && worker.OwnerUID != workerUID) || worker.BootID != master.BootID ||
			worker.ExecutableDevice != master.ExecutableDevice || worker.ExecutableInode != master.ExecutableInode {
			return RuntimeGeneration{}, fmt.Errorf("%w: OpenResty worker identity is not owned by the master", ErrCorruptState)
		}
		workerUID = worker.OwnerUID
		workers = append(workers, worker)
	}
	masterAfter, err := inspectProcess(masterPID)
	if err != nil || masterAfter != master {
		return RuntimeGeneration{}, fmt.Errorf("%w: OpenResty master changed during generation capture", ErrCorruptState)
	}
	generation := RuntimeGeneration{Master: master, Workers: workers}
	if !validRuntimeGeneration(generation) {
		return RuntimeGeneration{}, ErrCorruptState
	}
	return generation, nil
}

func (o *OpenResty) waitForNewWorker(ctx context.Context, masterPID int, previousWorkers []int) error {
	previous := make(map[int]struct{}, len(previousWorkers))
	for _, worker := range previousWorkers {
		previous[worker] = struct{}{}
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var stable []int
	stableObservations := 0
	for {
		currentMaster, err := readOpenRestyPID(o.pidPath)
		var currentWorkers []int
		if err == nil && currentMaster == masterPID {
			currentWorkers, err = readProcessChildren(masterPID)
		}
		if err == nil && currentMaster == masterPID {
			fresh := make([]int, 0, len(currentWorkers))
			for _, worker := range currentWorkers {
				role, roleErr := readProcessRole(worker)
				if roleErr != nil {
					err = roleErr
					break
				}
				if role != "worker" {
					continue
				}
				if _, existed := previous[worker]; !existed {
					fresh = append(fresh, worker)
				}
			}
			if err == nil {
				if len(fresh) > 0 && sameProcessIDs(stable, fresh) {
					stableObservations++
				} else if len(fresh) > 0 {
					stable = append(stable[:0], fresh...)
					stableObservations = 1
				} else {
					stable = stable[:0]
					stableObservations = 0
				}
				if stableObservations >= 2 {
					return nil
				}
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ESRCH) {
			return err
		} else if err == nil && currentMaster != masterPID {
			return fmt.Errorf("%w: OpenResty master changed during reload", ErrCorruptState)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func readProcessRole(pid int) (string, error) {
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if errors.Is(err, os.ErrNotExist) {
		return "", syscall.ESRCH
	}
	if err != nil {
		return "", err
	}
	return processRole(strings.ReplaceAll(string(content), "\x00", " ")), nil
}

func sameProcessIDs(first, second []int) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func (o *OpenResty) pidFile() (string, error) {
	if o == nil || o.pidPath == "" {
		return "", ErrInvalidPath
	}
	return o.pidPath, nil
}

func readOpenRestyPID(path string) (int, error) {
	content, err := readRegularFile(path)
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(content))
	pid, err := strconv.Atoi(text)
	if err != nil || pid <= 1 || text != strconv.Itoa(pid) {
		return 0, fmt.Errorf("%w: OpenResty PID file is invalid", ErrCorruptState)
	}
	return pid, nil
}

func inspectProcess(pid int) (ProcessIdentity, error) {
	statContent, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	statText := string(statContent)
	opening := strings.IndexByte(statText, '(')
	closing := strings.LastIndexByte(statText, ')')
	if opening < 0 || closing <= opening || closing+2 >= len(statContent) {
		return ProcessIdentity{}, ErrCorruptState
	}
	commandLine, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	role := processRole(strings.ReplaceAll(string(commandLine), "\x00", " "))
	fields := strings.Fields(statText[closing+2:])
	if len(fields) < 20 {
		return ProcessIdentity{}, ErrCorruptState
	}
	parentPID, err := strconv.Atoi(fields[1])
	if err != nil || parentPID < 0 {
		return ProcessIdentity{}, ErrCorruptState
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return ProcessIdentity{}, ErrCorruptState
	}
	executable, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	processDir, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return ProcessIdentity{}, err
	}
	executableStat, executableOK := executable.Sys().(*syscall.Stat_t)
	processStat, processOK := processDir.Sys().(*syscall.Stat_t)
	if !executableOK || !processOK || executableStat.Ino == 0 {
		return ProcessIdentity{}, ErrCorruptState
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(bootID)) == "" {
		return ProcessIdentity{}, ErrCorruptState
	}
	return ProcessIdentity{
		PID: pid, ParentPID: parentPID, Role: role, StartTicks: startTicks,
		ExecutableDevice: uint64(executableStat.Dev), ExecutableInode: executableStat.Ino,
		OwnerUID: processStat.Uid, BootID: strings.TrimSpace(string(bootID)),
	}, nil
}

func processRole(name string) string {
	switch {
	case strings.Contains(name, "master process"):
		return "master"
	case strings.Contains(name, "worker process"):
		return "worker"
	default:
		return "other"
	}
}

func verifyOpenRestyExecutable(binary string, process ProcessIdentity) error {
	info, err := os.Stat(binary)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != process.ExecutableDevice || stat.Ino != process.ExecutableInode ||
		(process.OwnerUID != 0 && process.OwnerUID != uint32(os.Geteuid())) {
		return fmt.Errorf("%w: OpenResty process does not match the configured binary", ErrCorruptState)
	}
	return nil
}

func readProcessChildren(pid int) ([]int, error) {
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(pid), "children"))
	if err != nil {
		return nil, err
	}
	values := strings.Fields(string(content))
	children := make([]int, 0, len(values))
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		child, err := strconv.Atoi(value)
		if err != nil || child <= 1 {
			return nil, ErrCorruptState
		}
		if _, exists := seen[child]; exists {
			return nil, ErrCorruptState
		}
		seen[child] = struct{}{}
		children = append(children, child)
	}
	return children, nil
}
