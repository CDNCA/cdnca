//go:build !windows

package controlplaneupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const NativeStatusSchema = "cdnca.native-management.runner-status/v1"
const nativeMaintenanceSchema = "cdnca.native-management.maintenance/v1"

type NativeStandaloneStatus struct {
	Schema                string    `json:"schema"`
	Ready                 bool      `json:"ready"`
	Reason                string    `json:"reason"`
	InstallationID        string    `json:"installation_id"`
	ProtocolVersion       int       `json:"protocol_version"`
	ArtifactFormat        string    `json:"artifact_format"`
	CurrentVersion        string    `json:"current_version"`
	CurrentArtifactSHA256 string    `json:"current_artifact_sha256"`
	SourceCommit          string    `json:"source_commit"`
	SourceTree            string    `json:"source_tree"`
	RunnerPID             int       `json:"runner_pid"`
	StartID               string    `json:"start_id"`
	RunnerExeSHA256       string    `json:"runner_exe_sha256"`
	ObservedAt            time.Time `json:"observed_at"`
	Busy                  bool      `json:"busy"`
	Phase                 string    `json:"phase"`
}

type nativeProcess struct {
	startID string
	digest  string
}

type nativeProcessInspector func(int) (nativeProcess, error)

// ReadNativeStandaloneStatus is intentionally local/root-owned evidence, not a
// timestamp-only health claim. API callers must project out process details.
func ReadNativeStandaloneStatus(filename, installationID string, now time.Time) (NativeStandaloneStatus, error) {
	return readNativeStandaloneStatus(filename, installationID, now, 0, inspectNativeProcess)
}

// ReadNativeStandaloneState never creates or chmods a directory. It is safe for
// the unprivileged API projection of a root-owned runner receipt.
func ReadNativeStandaloneState(filename string) (State, error) {
	return readNativeStandaloneState(filename, 0)
}

func readNativeStandaloneState(filename string, owner uint32) (State, error) {
	encoded, err := readNativeOwnedFile(filename, owner, 64*1024)
	var state State
	if err != nil || decodeNativeJSON(encoded, &state) != nil || !validState(state) {
		return State{}, ErrCorruptState
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return State{}, ErrCorruptState
	}
	return state, nil
}

// ReadNativeStandaloneHistory reads the root-owned upgrade journal published
// beside the runner state. Like the state, it never creates directories.
func ReadNativeStandaloneHistory(filename string) (History, error) {
	return readNativeStandaloneHistory(filename, 0)
}

func readNativeStandaloneHistory(filename string, owner uint32) (History, error) {
	encoded, err := readNativeOwnedFile(filename, owner, 64*1024)
	if err != nil {
		return History{}, ErrCorruptState
	}
	return decodeHistory(encoded)
}

// ReadNativeStandaloneRunLog reads the root-owned run log published beside the
// runner state. Journal lines are redacted again before they leave the API.
func ReadNativeStandaloneRunLog(filename string) (RunLog, error) {
	return readNativeStandaloneRunLog(filename, 0)
}

func readNativeStandaloneRunLog(filename string, owner uint32) (RunLog, error) {
	encoded, err := readNativeOwnedFile(filename, owner, maxRunLogBytes)
	if err != nil {
		return RunLog{}, ErrCorruptState
	}
	log, err := DecodeRunLog(encoded)
	if err != nil {
		return RunLog{}, err
	}
	for index := range log.Programs {
		log.Programs[index].Lines = sanitizeRunLogLines(log.Programs[index].Lines)
	}
	return log, nil
}

func readNativeStandaloneStatus(filename, installationID string, now time.Time, owner uint32, inspect nativeProcessInspector) (NativeStandaloneStatus, error) {
	var status NativeStandaloneStatus
	encoded, err := readNativeOwnedFile(filename, owner, 16*1024)
	if err != nil || decodeNativeJSON(encoded, &status) != nil || status.Schema != NativeStatusSchema ||
		status.InstallationID != installationID || status.ProtocolVersion < 1 ||
		(status.ArtifactFormat != NativeManifestSchema && status.ArtifactFormat != NativeManifestSignedSchema) ||
		status.RunnerPID < 1 || status.StartID == "" || !digestPattern.MatchString(status.RunnerExeSHA256) ||
		status.ObservedAt.After(now.Add(time.Second)) || now.Sub(status.ObservedAt) > 30*time.Second ||
		!nativeVersion(status.CurrentVersion) || !digestPattern.MatchString(status.CurrentArtifactSHA256) ||
		!nativeGitObject.MatchString(status.SourceCommit) || !nativeGitObject.MatchString(status.SourceTree) ||
		(status.Ready && (status.Busy || status.Phase != "idle" || status.Reason != "ready")) {
		return NativeStandaloneStatus{}, ErrTargetMismatch
	}
	process, err := inspect(status.RunnerPID)
	if err != nil || process.startID != status.StartID || process.digest != status.RunnerExeSHA256 {
		return NativeStandaloneStatus{}, ErrTargetMismatch
	}
	return status, nil
}

func inspectNativeProcess(pid int) (nativeProcess, error) {
	root := filepath.Join("/proc", strconv.Itoa(pid))
	info, err := os.Stat(root)
	stat, ok := infoSysStat(info)
	if err != nil || !ok || stat.Uid != 0 {
		return nativeProcess{}, ErrTargetMismatch
	}
	return inspectNativeServiceProcess(pid)
}

func inspectNativeServiceProcess(pid int) (nativeProcess, error) {
	root := filepath.Join("/proc", strconv.Itoa(pid))
	encoded, err := os.ReadFile(filepath.Join(root, "stat"))
	end := strings.LastIndex(string(encoded), ") ")
	if err != nil || end < 0 {
		return nativeProcess{}, ErrTargetMismatch
	}
	fields := strings.Fields(string(encoded[end+2:]))
	if len(fields) < 20 || fields[0] == "Z" {
		return nativeProcess{}, ErrTargetMismatch
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return nativeProcess{}, ErrTargetMismatch
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(strings.TrimSpace(string(boot))) != 36 {
		return nativeProcess{}, ErrTargetMismatch
	}
	file, err := os.Open(filepath.Join(root, "exe"))
	if err != nil {
		return nativeProcess{}, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, nativeArchiveLimit+1))
	if err != nil || size < 1 || size > nativeArchiveLimit {
		return nativeProcess{}, ErrTargetMismatch
	}
	return nativeProcess{startID: strings.TrimSpace(string(boot)) + ":" + fields[19], digest: fmt.Sprintf("%x", hash.Sum(nil))}, nil
}

type nativeMaintenanceState struct {
	Schema         string    `json:"schema"`
	InstallationID string    `json:"installation_id"`
	Phase          string    `json:"phase"`
	PlanID         string    `json:"plan_id"`
	ObservedAt     time.Time `json:"observed_at"`
}

type NativeMaintenanceGateConfig struct {
	Enabled        bool
	File           string
	InstallationID string
}

func NewNativeMaintenanceGate(config NativeMaintenanceGateConfig, next http.Handler) (http.Handler, error) {
	return newNativeMaintenanceGate(config, next, 0)
}

func newNativeMaintenanceGate(config NativeMaintenanceGateConfig, next http.Handler, owner uint32) (http.Handler, error) {
	if next == nil || (config.Enabled && (!filepath.IsAbs(config.File) || config.InstallationID == "")) {
		return nil, ErrInvalidConfig
	}
	if !config.Enabled {
		return next, nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		// An in-flight management write holds this shared lock through response.
		// Drain takes it exclusively before atomically publishing draining state.
		lock, err := openNativeLock(config.File+".lock", owner, false)
		if err == nil {
			defer lock.Close()
			err = syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		}
		if err == nil {
			defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			state, readErr := readNativeMaintenance(config.File, config.InstallationID, owner)
			if readErr == nil && state.Phase == "active" {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":{"code":"control_upgrade_draining"}}`)
	}), nil
}

func readNativeMaintenance(filename, installationID string, owner uint32) (nativeMaintenanceState, error) {
	var state nativeMaintenanceState
	encoded, err := readNativeOwnedFile(filename, owner, 4096)
	if err != nil || decodeNativeJSON(encoded, &state) != nil || state.Schema != nativeMaintenanceSchema ||
		state.InstallationID != installationID || (state.Phase != "active" && state.Phase != "draining") ||
		(state.Phase == "draining" && state.PlanID == "") || state.ObservedAt.IsZero() {
		return nativeMaintenanceState{}, ErrTargetMismatch
	}
	return state, nil
}

func readNativeOwnedFile(filename string, owner uint32, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename || nativeOwnedDirectory(filepath.Dir(filename), owner) != nil {
		return nil, ErrInvalidConfig
	}
	file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || stat.Uid != owner || stat.Nlink != 1 || !info.Mode().IsRegular() ||
		(info.Mode().Perm() != 0o600 && info.Mode().Perm() != 0o640) || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrTargetMismatch
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(encoded)) != info.Size() {
		return nil, ErrTargetMismatch
	}
	return encoded, nil
}

func nativeOwnedDirectory(directory string, owner uint32) error {
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return ErrInvalidConfig
	}
	info, err := os.Lstat(directory)
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.IsDir() || stat.Uid != owner ||
		(info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
		return ErrInvalidConfig
	}
	// A root-owned file in a replaceable parent is not a trust boundary.
	if owner == 0 && directory != "/" {
		return nativeOwnedDirectory(filepath.Dir(directory), owner)
	}
	return nil
}

func openNativeLock(filename string, owner uint32, create bool) (*os.File, error) {
	if nativeOwnedDirectory(filepath.Dir(filename), owner) != nil {
		return nil, ErrInvalidConfig
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	if create {
		flags = os.O_CREATE | os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	}
	file, err := os.OpenFile(filename, flags, 0o640)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || stat.Uid != owner || stat.Nlink != 1 || !info.Mode().IsRegular() ||
		(info.Mode().Perm() != 0o600 && info.Mode().Perm() != 0o640) {
		_ = file.Close()
		return nil, ErrInvalidConfig
	}
	return file, nil
}

func nativeWaitLock(ctx context.Context, file *os.File) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return nil
		} else if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func writeNativeMaintenance(filename, installationID, phase, planID string, now time.Time) error {
	state := nativeMaintenanceState{Schema: nativeMaintenanceSchema, InstallationID: installationID,
		Phase: phase, PlanID: planID, ObservedAt: now.UTC()}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeAtomicFile(filepath.Dir(filename), filepath.Base(filename), encoded, 0o640)
}
