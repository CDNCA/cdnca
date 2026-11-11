package dynroute

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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
		// Cold start only (a running master already loaded its files): a
		// configuration naming a file that is gone (uninstall --purge removed
		// the WAF extension, D-e) cannot start; it is set aside and the node
		// waits for its next publication like one never applied.
		if missing := missingConfigurationReference(runtime.confPath()); missing != "" {
			return runtime.discardStale(missing)
		}
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

// discardStale moves nginx.conf to nginx.conf.stale (kept for diagnosis,
// replaced by the next discard) and resets the runtime state to that of a
// node never applied: the skeleton, WAF, L4 release and scopes it names were
// installed by the previous runtime. The generation keeps counting (index
// files on disk) and the control plane's storage request stays.
func (runtime *Runtime) discardStale(missing string) error {
	if err := os.Rename(runtime.confPath(), runtime.confPath()+".stale"); err != nil {
		return fmt.Errorf("set aside stale runtime configuration: %w", err)
	}
	runtime.state = persisted{Generation: runtime.state.Generation, RequestedStorage: runtime.state.RequestedStorage}
	runtime.storage, runtime.region = effectiveStorage{}, ""
	if err := runtime.saveState(); err != nil {
		return err
	}
	log.Printf("dynamic routing: previous runtime configuration names %s, which no longer exists; "+
		"set aside as %s.stale, waiting for the next publication", missing, runtime.confPath())
	return nil
}

// fileDirectives are the nginx directives the skeleton renders with a file
// path that must exist when OpenResty starts.
var fileDirectives = map[string]bool{"load_module": true, "include": true, "ssl_certificate": true,
	"ssl_certificate_key": true, "ssl_client_certificate": true, "proxy_ssl_trusted_certificate": true}

// missingConfigurationReference returns the first absolute file the
// configuration at path names that does not exist ("" when all do): the
// directives above, ModSecurity's modsecurity_rules_file and
// SecUnicodeMapFile, and the Include lines of every rules file (followed
// through nested rules files once each). Values with a variable, a glob or a
// relative path are not checked. Only a file reported as not existing
// counts: a file that cannot be read or checked is left to OpenResty, as
// before this check.
func missingConfigurationReference(path string) string {
	seen := map[string]bool{}
	rules, missing := scanReferences(path, func(fields []string) (string, bool) {
		switch {
		case len(fields) >= 2 && fileDirectives[fields[0]]:
			return fields[1], false
		case len(fields) >= 2 && fields[0] == "modsecurity_rules_file":
			return fields[1], true
		case len(fields) >= 3 && fields[0] == "modsecurity_rules" && strings.Trim(fields[1], `'"`) == "SecUnicodeMapFile":
			return fields[2], false
		}
		return "", false
	}, seen)
	include := func(fields []string) (string, bool) {
		if len(fields) >= 2 && strings.EqualFold(fields[0], "Include") {
			return fields[1], true
		}
		return "", false
	}
	for len(rules) > 0 && missing == "" {
		var nested []string
		nested, missing = scanReferences(rules[0], include, seen)
		rules = append(rules[1:], nested...)
	}
	return missing
}

// scanReferences checks the files path's lines name (match: the value and
// whether it is a rules file to follow); it returns those rules files and the
// first missing file.
func scanReferences(path string, match func([]string) (string, bool), seen map[string]bool) ([]string, string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ""
	}
	var rules []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		value, nested := match(strings.Fields(strings.TrimSuffix(line, ";")))
		value = strings.Trim(strings.TrimSuffix(value, ";"), `'"`)
		if !filepath.IsAbs(value) || strings.ContainsAny(value, "$*?[") || seen[value] {
			continue
		}
		seen[value] = true
		if _, err := os.Stat(value); errors.Is(err, os.ErrNotExist) {
			return nil, value
		} else if err == nil && nested {
			rules = append(rules, value)
		}
	}
	return rules, ""
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
