package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// Node storage (NODE_STORAGE v1, fix-finalgaps2 第 2 项; tests/node-storage/run.sh,
// -suite node-storage) on a real OpenResty:
//   - a new cache directory takes the next render: the reload serves
//     MISS then HIT from the new directory;
//   - a cache directory nginx -t refuses (the path is a file, so the zone
//     directory cannot be created) keeps the previous directory running,
//     the state says failed and the same settings are not tried again;
//   - a new log directory is restart_pending until the agent restarts;
//     after the restart (New, Recover, Apply as the daemon does) error.log
//     and the node-level telemetry logs are in the new directory.
func runNodeStorage(ctx context.Context) {
	// as main does: the state root 0755 (the workers reach the node and
	// shared roots below it), the node root 0750
	_ = os.RemoveAll(*state)
	if err := os.MkdirAll(*state, 0o755); err != nil {
		fmt.Println("FAIL state", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Join(*state, "node"), 0o750); err != nil {
		fmt.Println("FAIL state", err)
		os.Exit(1)
	}
	root := "/var/cache/cdnca-node-storage-check"
	logs := "/var/log/cdnca-node-storage-check/logs"
	_ = os.RemoveAll(root)
	_ = os.RemoveAll(filepath.Dir(logs))
	objectsRoot := filepath.Join(*state, "node", "objects")
	var err error
	if siteObjects, err = objectstore.OpenShared(objectsRoot, max(workerGID(), 0)); err != nil {
		fmt.Println("FAIL object store", err)
		os.Exit(1)
	}
	config := dynroute.Config{StateRoot: filepath.Join(*state, "node"), SharedRoot: filepath.Join(*state, "shared"), ObjectsRoot: objectsRoot,
		LuaRoot: *luaRoot, OpenResty: *binary, WorkerGID: workerGID(), CacheMaxBytes: 512 << 20, Workers: *workers,
		HealthTimeout: 20 * time.Second, Telemetry: true}
	runtime, err := dynroute.New(config)
	if err != nil {
		fmt.Println("FAIL runtime", err)
		os.Exit(1)
	}
	h := &harness{ctx: ctx, config: config, runtime: runtime,
		input: dynroute.Input{ScopeVersions: map[string]string{scope: "0d130000-0000-4000-8000-0000000000a1"}}}
	shop := withCache(makeSite(1, "shop.d13.test", 1, portPlain), 64<<20)
	conf := func() string {
		raw, _ := os.ReadFile(filepath.Join(config.SharedRoot, "nginx.conf"))
		return string(raw)
	}
	missHit := func(name, path, dir string) {
		a := get(portPlain, "shop.d13.test", path)
		b := get(portPlain, "shop.d13.test", path)
		check(name, a.cache == "MISS" && b.cache == "HIT" && cacheFiles(dir) > 0, "%s/%s files under %s: %d %s",
			a.cache, b.cache, dir, cacheFiles(dir), a.err)
	}

	// default storage
	h.apply("storage-default-apply", shop)
	defaultCache := filepath.Join(config.SharedRoot, "cache")
	missHit("storage-default-hit", "/default.css", defaultCache)
	status := runtime.StorageStatus()
	check("storage-default-state", status.State == dynroute.StorageDefault && status.CacheDirectory == defaultCache, "%+v", status)

	// a new cache directory: reload, MISS then HIT there
	first := filepath.Join(root, "first")
	pid := masterPID()
	h.input.NodeStorage = &siteobject.NodeStorage{CacheDirectory: first, CacheMaxBytes: 256 << 20}
	moved := h.apply("storage-cache-dir-apply", shop)
	status = runtime.StorageStatus()
	check("storage-cache-dir-reloaded", moved.Reloaded && !moved.Started && masterPID() == pid &&
		strings.Contains(conf(), `"`+first+`/cdnca-0"`) && status.State == dynroute.StorageApplied && status.CacheDirectory == first,
		"reloaded %v started %v master %s/%s %+v", moved.Reloaded, moved.Started, pid, masterPID(), status)
	missHit("storage-cache-dir-hit", "/first.css", first)

	// nginx -t refuses the next directory (a file where the zone directory
	// must be created): the previous directory keeps serving
	broken := filepath.Join(root, "broken")
	if err := os.WriteFile(broken, []byte("not a directory\n"), 0o644); err != nil {
		check("storage-refused-fixture", false, "%v", err)
	}
	h.input.NodeStorage = &siteobject.NodeStorage{CacheDirectory: broken, CacheMaxBytes: 256 << 20}
	refused := h.apply("storage-refused-apply", shop)
	status = runtime.StorageStatus()
	a := get(portPlain, "shop.d13.test", "/first.css")
	check("storage-refused-keeps-previous", !strings.Contains(conf(), broken) && strings.Contains(conf(), `"`+first+`/cdnca-0"`) &&
		status.State == dynroute.StorageFailed && status.CacheDirectory == first && status.Reason != "" && a.cache == "HIT",
		"reloaded %v %+v first.css %s", refused.Reloaded, status, a.cache)
	again := h.apply("storage-refused-again-apply", shop)
	check("storage-refused-not-retried", !again.Reloaded && runtime.StorageStatus().State == dynroute.StorageFailed,
		"reloaded %v %+v", again.Reloaded, runtime.StorageStatus())

	// a new log directory waits for the agent restart
	h.input.NodeStorage = &siteobject.NodeStorage{CacheDirectory: first, CacheMaxBytes: 256 << 20, LogDirectory: logs}
	h.apply("storage-log-dir-apply", shop)
	status = runtime.StorageStatus()
	check("storage-log-dir-pending", status.State == dynroute.StorageRestartPending && status.RequestedLogDirectory == logs &&
		runtime.LogRoot() == config.SharedRoot && !strings.Contains(conf(), logs), "%+v root %s", status, runtime.LogRoot())
	pid = masterPID()
	restarted, err := dynroute.New(config)
	if err == nil {
		err = restarted.Recover(ctx)
	}
	check("storage-agent-restart", err == nil && restarted.LogRoot() == logs && masterPID() == pid, "root %s master %s/%s %v",
		restarted.LogRoot(), pid, masterPID(), err)
	h.runtime = restarted
	after := h.apply("storage-after-restart-apply", shop)
	access, security := restarted.TelemetryLogs()
	_, errorLog := os.Stat(filepath.Join(logs, "error.log"))
	status = restarted.StorageStatus()
	check("storage-log-dir-applied", after.Reloaded && errorLog == nil && strings.Contains(conf(), `"`+filepath.Join(logs, "error.log")+`"`) &&
		strings.HasPrefix(access, logs+"/") && strings.HasPrefix(security, logs+"/") && status.State == dynroute.StorageApplied &&
		status.LogDirectory == logs, "reloaded %v error.log %v access %s %+v", after.Reloaded, errorLog, access, status)
	appendLog(filepath.Join(logs, "error.log"), "[crit] 1#1: *1 node storage synthetic critical line")
	stats, err := restarted.ReadErrorLog()
	check("storage-error-log-read", err == nil && len(stats.Recent) > 0 &&
		strings.Contains(stats.Recent[len(stats.Recent)-1], "node storage synthetic critical line"), "%d recent %v", len(stats.Recent), err)
	missHit("storage-after-restart-hit", "/after.css", first)

	if failures != 0 {
		if stats, err := restarted.ReadErrorLog(); err == nil {
			for _, line := range stats.Recent {
				fmt.Println("LOG", line)
			}
		}
	}
	_ = restarted.Stop(ctx)
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}
