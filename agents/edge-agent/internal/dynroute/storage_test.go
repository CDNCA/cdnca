package dynroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

func storageRuntime(t *testing.T) (*Runtime, string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "nst") // short: the control socket path has a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: filepath.Join(root, "lua"), OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1,
		CacheMaxBytes: 10 << 30, Telemetry: true})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, root
}

// NODE_STORAGE: the cache directory and limit the control plane sets are
// what the skeleton renders; without settings the node's defaults stay.
func TestNodeStorageCacheRendered(t *testing.T) {
	runtime, root := storageRuntime(t)
	sites := []edgesite.Site{testSite(testScopeA, testSiteA, 80)}
	conf, err := runtime.render(sites, dynwaf.Result{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), filepath.Join(root, "shared", "cache", "cdnca-0")) {
		t.Fatal("default cache root not rendered")
	}
	defaultStatus := runtime.StorageStatus()
	if defaultStatus.State != StorageDefault || defaultStatus.CacheMaxBytes != 10<<30 || defaultStatus.LogDirectory != filepath.Join(root, "shared") {
		t.Fatalf("default status = %+v", defaultStatus)
	}

	cache := filepath.Join(root, "disk", "cache")
	if err := runtime.prepareWorkerDirectory(cache); err != nil {
		t.Fatal(err)
	}
	original := fileSystemSize
	fileSystemSize = func(string) (int64, error) { return 4 << 30, nil }
	t.Cleanup(func() { fileSystemSize = original })
	runtime.storage = effectiveStorage{CacheDirectory: cache, CacheMaxBytes: 2 << 30}
	conf, err = runtime.render(sites, dynwaf.Result{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(conf)
	if !strings.Contains(text, `proxy_cache_path "`+cache+`/cdnca-0" `) || strings.Contains(text, "shared/cache") {
		t.Fatalf("cache directory not rendered:\n%s", text)
	}
	if runtime.zones.Root != cache {
		t.Fatalf("purge zones root %q", runtime.zones.Root)
	}
	// The limit is capped by the file system holding the directory.
	runtime.storage.CacheMaxBytes = 100 << 30
	if got := runtime.cacheBudget(); got != 4<<30 {
		t.Fatalf("budget over the disk = %d", got)
	}
}

// Settings that are invalid or overlap the runtime are refused and the
// previous ones keep running; the refusal is reported.
func TestNodeStorageRefused(t *testing.T) {
	runtime, root := storageRuntime(t)
	if _, err := runtime.prepareStorage(&siteobject.NodeStorage{CacheDirectory: "/etc/cdnca"}); err == nil {
		t.Fatal("cache directory outside the allowed roots accepted")
	}
	for _, dir := range []string{filepath.Join(root, "node", "c"), filepath.Join(root, "lua"), root} {
		if err := runtime.prepareWorkerDirectory(dir); err == nil {
			t.Fatalf("%s overlapping the runtime accepted", dir)
		}
	}
	if err := runtime.prepareWorkerDirectory(filepath.Join(root, "shared", "cache", "x")); err != nil {
		t.Fatalf("below the default cache root: %v", err)
	}
	runtime.storage = effectiveStorage{CacheMaxBytes: 1 << 30}
	runtime.refuseStorage(&siteobject.NodeStorage{CacheDirectory: "/data/x"}, os.ErrPermission)
	status := runtime.StorageStatus()
	if status.State != StorageFailed || status.Reason == "" || runtime.refusedStorage == nil {
		t.Fatalf("refused status = %+v", status)
	}
}

// The log directory is fixed for the process: a new one recorded in
// state.json applies on the next start (restart_pending until then).
func TestNodeStorageLogDirectoryOnRestart(t *testing.T) {
	runtime, root := storageRuntime(t)
	logs := "/var/lib/cdnca-test-never-created/logs"
	runtime.state.RequestedStorage = &siteobject.NodeStorage{LogDirectory: logs}
	status := runtime.StorageStatus()
	if status.State != StorageRestartPending || status.RequestedLogDirectory != logs || status.LogDirectory != filepath.Join(root, "shared") {
		t.Fatalf("pending status = %+v", status)
	}
	// A recorded directory that is invalid falls back to the shared root.
	runtime.state.RequestedStorage = &siteobject.NodeStorage{LogDirectory: "/etc/logs"}
	if err := runtime.saveState(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(runtime.config)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.LogRoot() != filepath.Join(root, "shared") || restarted.StorageStatus().State != StorageFailed {
		t.Fatalf("invalid recorded log directory: root %q status %+v", restarted.LogRoot(), restarted.StorageStatus())
	}
	access, _ := restarted.TelemetryLogs()
	if !strings.HasPrefix(access, filepath.Join(root, "shared")) {
		t.Fatalf("telemetry log %s", access)
	}
}
