package dynroute

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Recover brings the runtime back after an agent restart: a running
// OpenResty is kept as is (the index lives in its shared dictionary); a
// stopped one (node reboot) is started from the installed skeleton and
// rebuilds the index from the current index file (contract §5.3). The
// active sites are read back from the index file and the object directory,
// and the cache purge generations are pushed again.
func (runtime *Runtime) Recover(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if _, err := os.Stat(runtime.confPath()); os.IsNotExist(err) {
		return nil // never applied
	}
	index, found, err := runtime.activator.Files.Current()
	if err != nil {
		return fmt.Errorf("site index file: %w", err)
	}
	fresh := false
	if !runtime.running() {
		if err := runtime.openresty(ctx, runtime.confPath()); err != nil {
			return err
		}
		if err := runtime.waitControl(ctx); err != nil {
			return err
		}
		fresh = true
	}
	if !found {
		return nil
	}
	sites, err := runtime.readSites(index)
	if err != nil {
		return err
	}
	runtime.sites = sites
	pool, err := runtime.cachePool(sites, runtime.state.System)
	if err != nil {
		return err
	}
	runtime.zones.Root, runtime.zones.Count = runtime.cacheRoot(), pool.Zones
	waitCtx, cancel := context.WithTimeout(ctx, runtime.config.HealthTimeout)
	defer cancel()
	if err := runtime.activator.WaitGeneration(waitCtx, index.Generation); err != nil {
		return fmt.Errorf("site index generation %d after restart: %w", index.Generation, err)
	}
	return runtime.startCache(ctx, fresh)
}

// Applied reports whether an Apply ever wrote the runtime configuration. Before
// the node's first publication OpenResty is not started by design (Recover
// returns "never applied"), so its loopback endpoints do not exist yet.
func (runtime *Runtime) Applied() bool {
	if runtime == nil {
		return false
	}
	_, err := os.Stat(runtime.confPath())
	return err == nil
}

func (runtime *Runtime) readSites(index siteindex.Index) ([]edgesite.Site, error) {
	var sites []edgesite.Site
	for _, digest := range index.Digests() {
		raw, err := os.ReadFile(runtime.activator.Objects.Path(digest))
		if err != nil {
			return nil, fmt.Errorf("site object %s: %w", digest, err)
		}
		object, err := siteindex.DecodeObject(digest, raw)
		if err != nil {
			return nil, err
		}
		sites = append(sites, object.Site)
	}
	return sites, nil
}

// Stop stops OpenResty (tests, uninstall); the state stays on disk.
func (runtime *Runtime) Stop(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	pid, alive := runtime.masterPID()
	if !alive {
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGQUIT)
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if syscall.Kill(pid, 0) != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}
