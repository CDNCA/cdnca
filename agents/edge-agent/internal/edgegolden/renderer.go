package edgegolden

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
)

// Renderer turns a scenario's site facts into a running edge runtime. The
// corpus was recorded by the deleted per-site server{} (v7) renderer; the
// dynamic routing renderer (goldendyn, cdnca-dynroute) runs it.
type Renderer interface {
	Name() string
	Start(ctx context.Context, env Env, scenario *Scenario) (Instance, error)
}

// Instance is one running runtime.
type Instance interface {
	// Logs returns the access and security log records written since the
	// last call, access first, each in file order.
	Logs(ctx context.Context) ([]LogRecord, error)
	// CacheEntries lists the cache keys of a site's objects on disk.
	CacheEntries(ctx context.Context, siteID string) ([]string, error)
	// Task runs a cache task to completion.
	Task(ctx context.Context, task TaskSpec) (*TaskResult, error)
	// Publish activates a new publication of the scenario's scope in place.
	Publish(ctx context.Context, publication Publication) error
	Stop(ctx context.Context) error
}

// Env is the environment of a run (inside the node runtime image).
type Env struct {
	WorkDir   string
	OpenResty string
	// LuaRoot is the node Lua tree (/usr/local/share/cdnca in the image).
	LuaRoot string
	// ModSecurity is the OWASP CRS engine extension directory; "" when the
	// run has none (scenarios that require managed_waf are skipped).
	ModSecurity string
	// HTTP3 is the HTTP/3 client binary (tests/dynroute-filters/probe);
	// "" when the run has none (scenarios that require http3 are skipped).
	HTTP3 string
	PKI   *PKI
}

// Provides reports whether the environment has the optional piece name.
func (env Env) Provides(name string) bool {
	switch name {
	case "managed_waf":
		return env.ModSecurity != ""
	case "http3":
		return env.HTTP3 != ""
	case "l4":
		// the node's L4 runtime runs as root (tests/edge-golden/run.sh
		// runs these scenarios in a root container)
		return os.Geteuid() == 0
	default:
		return false
	}
}

var (
	renderersMu sync.Mutex
	renderers   = map[string]Renderer{}
)

// Register makes a renderer selectable by name.
func Register(renderer Renderer) {
	renderersMu.Lock()
	defer renderersMu.Unlock()
	if _, exists := renderers[renderer.Name()]; exists {
		panic("edgegolden: renderer " + renderer.Name() + " registered twice")
	}
	renderers[renderer.Name()] = renderer
}

func Lookup(name string) (Renderer, error) {
	renderersMu.Lock()
	defer renderersMu.Unlock()
	renderer, ok := renderers[name]
	if !ok {
		return nil, fmt.Errorf("unknown renderer %q (have %v)", name, rendererNames())
	}
	return renderer, nil
}

func rendererNames() []string {
	names := make([]string, 0, len(renderers))
	for name := range renderers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
