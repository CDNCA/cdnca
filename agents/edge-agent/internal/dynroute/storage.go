package dynroute

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// Node storage (NODE_STORAGE v1, fix-nodesettings): the control plane's
// cache directory and limit apply on the next render (reload); its log
// directory is recorded and applies when New runs again (Agent restart).
// Settings the node cannot use never block a publication: the previous
// ones keep running and StorageStatus says why.

// Storage states (NodeStorageV1.state).
const (
	StorageApplied        = "applied"
	StorageDefault        = "default"
	StorageFailed         = "failed"
	StorageRestartPending = "restart_pending"
)

// StorageStatus is what the node runs and the last outcome.
type StorageStatus struct {
	CacheDirectory        string
	CacheMaxBytes         int64
	LogDirectory          string
	State                 string
	Reason                string
	RequestedLogDirectory string
}

// effectiveStorage is the cache part a render uses ("" / 0 = defaults).
type effectiveStorage struct {
	CacheDirectory string `json:"cache_directory,omitempty"`
	CacheMaxBytes  int64  `json:"cache_max_bytes,omitempty"`
}

// fileSystemSize is the size of the file system holding dir (a variable:
// tests fake it).
var fileSystemSize = func(dir string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Blocks) * int64(stat.Bsize), nil
}

// prepareStorage checks and creates the requested cache directory; the
// returned settings are the ones to render. An error leaves the caller on
// its previous settings.
func (runtime *Runtime) prepareStorage(requested *siteobject.NodeStorage) (effectiveStorage, error) {
	if requested == nil {
		return effectiveStorage{}, nil
	}
	if !requested.Validate() {
		return effectiveStorage{}, fmt.Errorf("%w: node storage settings", ErrInvalid)
	}
	storage := effectiveStorage{CacheDirectory: requested.CacheDirectory, CacheMaxBytes: requested.CacheMaxBytes}
	if storage.CacheDirectory == "" {
		return storage, nil
	}
	if err := runtime.prepareWorkerDirectory(storage.CacheDirectory); err != nil {
		return effectiveStorage{}, fmt.Errorf("cache directory %s: %w", storage.CacheDirectory, err)
	}
	return storage, nil
}

// prepareWorkerDirectory creates dir (worker group, 0750) and checks the
// workers can reach it: every existing ancestor is searchable by them.
func (runtime *Runtime) prepareWorkerDirectory(dir string) error {
	if overlapsRuntimeRoot(dir, runtime.config) {
		return errors.New("overlaps the node runtime directories")
	}
	if err := mkdirWorker(dir, runtime.config.WorkerGID); err != nil {
		return err
	}
	if runtime.config.WorkerGID < 0 {
		return nil // no worker group (tests): mkdirWorker sets none either
	}
	for parent := filepath.Dir(dir); ; parent = filepath.Dir(parent) {
		info, err := os.Stat(parent)
		if err != nil {
			return err
		}
		if !workerSearchable(info, runtime.config.WorkerGID) {
			return fmt.Errorf("%s is not searchable by the OpenResty workers", parent)
		}
		if parent == "/" {
			return nil
		}
	}
}

func workerSearchable(info os.FileInfo, gid int) bool {
	mode := info.Mode().Perm()
	if mode&0o001 != 0 {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && gid >= 0 && int(stat.Gid) == gid && mode&0o010 != 0
}

// overlapsRuntimeRoot: a storage directory must not be, contain or lie in
// the state or Lua roots (the shared root's own cache/ is fine: the default).
func overlapsRuntimeRoot(dir string, config Config) bool {
	for _, root := range []string{config.StateRoot, config.LuaRoot, config.SharedRoot} {
		if root == config.SharedRoot && siteobject.NodeStorageDirectoriesOverlap(dir, filepath.Join(root, "cache")) &&
			dir != root {
			continue
		}
		if siteobject.NodeStorageDirectoriesOverlap(dir, root) {
			return true
		}
	}
	return false
}

// refuseStorage records why the control plane's settings are not in effect;
// the same settings are not tried again until they change (Apply).
func (runtime *Runtime) refuseStorage(requested *siteobject.NodeStorage, err error) {
	runtime.storageError = err.Error()
	if len(runtime.storageError) > 512 {
		runtime.storageError = runtime.storageError[:512]
	}
	if requested != nil {
		copied := *requested
		runtime.refusedStorage = &copied
	}
	log.Printf("dynamic routing: node storage settings refused, previous ones keep running: %v", err)
}

// cacheBudget is the node's own budget before the system configuration's
// cap: the control plane's limit (at most the size of the file system
// holding the cache directory) or the Agent's configured one.
func (runtime *Runtime) cacheBudget() int64 {
	limit := runtime.storage.CacheMaxBytes
	if limit <= 0 {
		return runtime.config.CacheMaxBytes
	}
	if size, err := fileSystemSize(runtime.cacheRoot()); err == nil && size > 0 && limit > size {
		limit = max(size>>20<<20, siteobject.NodeStorageMinCacheBytes)
	}
	return limit
}

// cacheRoot is the cache zone root (edgeskeleton.Paths.Cache).
func (runtime *Runtime) cacheRoot() string {
	if runtime.storage.CacheDirectory != "" {
		return runtime.storage.CacheDirectory
	}
	return filepath.Join(runtime.config.SharedRoot, "cache")
}

// logRootFor is the log directory New runs with: the recorded request when
// it is usable, else the shared root.
func (runtime *Runtime) logRootFor(requested string) (string, error) {
	if requested == "" {
		return runtime.config.SharedRoot, nil
	}
	if !siteobject.ValidNodeStorageDirectory(requested) {
		return runtime.config.SharedRoot, fmt.Errorf("%w: log directory %q", ErrInvalid, requested)
	}
	if overlapsRuntimeRoot(requested, runtime.config) {
		return runtime.config.SharedRoot, fmt.Errorf("log directory %s overlaps the node runtime directories", requested)
	}
	if err := mkdirWorker(requested, runtime.config.WorkerGID); err != nil {
		return runtime.config.SharedRoot, fmt.Errorf("log directory %s: %w", requested, err)
	}
	return requested, nil
}

// LogRoot is the directory of error.log and the node-level telemetry logs
// for this process.
func (runtime *Runtime) LogRoot() string { return runtime.logRoot }

// StorageStatus is the node storage in effect (NodeStorageV1).
func (runtime *Runtime) StorageStatus() StorageStatus {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	status := StorageStatus{CacheDirectory: runtime.cacheRoot(), CacheMaxBytes: runtime.cacheBudget(),
		LogDirectory: runtime.logRoot, State: StorageDefault}
	requested := runtime.state.RequestedStorage
	if requested != nil {
		status.State = StorageApplied
		if requested.LogDirectory != "" && requested.LogDirectory != runtime.logRoot {
			status.State, status.RequestedLogDirectory = StorageRestartPending, requested.LogDirectory
		}
	}
	if runtime.storageError != "" {
		status.State, status.Reason, status.RequestedLogDirectory = StorageFailed, runtime.storageError, ""
	}
	return status
}
