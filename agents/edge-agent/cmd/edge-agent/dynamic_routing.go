package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/wafengine"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// dynamicRoutingSettings configures the node runtime, dynamic routing
// (ADR 0009, site_runtime 9): one shared server per port, sites activated
// through the node index instead of compiled into nginx.conf. It is the only
// node runtime (1.0.35): enabled defaults to true and false is refused.
type dynamicRoutingSettings struct {
	Enabled bool `json:"enabled"`
	// StateRoot holds the worker readable state (site objects, index, TLS
	// pool, secrets) and SharedRoot the OpenResty prefix; both default under
	// the deployment root's parent ("dynroute/state", "dynroute/shared").
	StateRoot  string `json:"state_root,omitempty"`
	SharedRoot string `json:"shared_root,omitempty"`
	// WorkerGroup is the OpenResty worker group (default nobody, the
	// compiled-in worker user's group; the native profile's cdnca-runtime).
	WorkerGroup string `json:"worker_group,omitempty"`
	// CacheMaxBytes is the node cache budget: unset = the default for the
	// shared root's file system (dynamicRoutingCacheMaxBytes), 0 = no cache
	// zones (N16: the installer writes none, so unset must cache).
	CacheMaxBytes *int64 `json:"cache_max_bytes,omitempty"`
}

const (
	// defaultCacheMinBytes / defaultCacheMaxBytes bound the default budget:
	// edgecache.PlanPool's 64 MiB floor, and the top of its 4 zone tier (a
	// default never moves sites between zones as disks grow; below the
	// platform's proxy_cache_max_bytes default of 100 GiB).
	defaultCacheMinBytes = int64(64) << 20
	defaultCacheMaxBytes = int64(64) << 30
	// defaultCacheDiskDivisor: the default takes a quarter of the file
	// system, leaving the rest to logs, temp files and the system.
	defaultCacheDiskDivisor = 4
)

// dynamicRoutingCacheMaxBytes is the node cache budget: the configured value,
// or by default a quarter of the size (not the free space, which moves with
// every restart) of the file system holding the shared root, at most 64 GiB;
// 0 when that is under 64 MiB.
func dynamicRoutingCacheMaxBytes(settings dynamicRoutingSettings, shared string) (int64, error) {
	if settings.CacheMaxBytes != nil {
		return *settings.CacheMaxBytes, nil
	}
	size, err := fileSystemBytes(shared)
	if err != nil {
		return 0, fmt.Errorf("dynamic routing default cache size: %w", err)
	}
	return defaultCacheBytes(size), nil
}

func defaultCacheBytes(fileSystem int64) int64 {
	value := min(fileSystem/defaultCacheDiskDivisor, defaultCacheMaxBytes) >> 20 << 20
	if value < defaultCacheMinBytes {
		return 0
	}
	return value
}

// fileSystemBytes is the size of the file system holding dir, or of its
// closest existing parent (the shared root is created by dynroute.New).
func fileSystemBytes(dir string) (int64, error) {
	for {
		var stat syscall.Statfs_t
		err := syscall.Statfs(dir, &stat)
		if err == nil {
			return int64(stat.Blocks) * int64(stat.Bsize), nil
		}
		parent := filepath.Dir(dir)
		if !errors.Is(err, syscall.ENOENT) || parent == dir {
			return 0, err
		}
		dir = parent
	}
}

func (c fileConfig) validateDynamicRouting() error {
	settings := c.DynamicRouting
	if !settings.Enabled {
		return errors.New("dynamic_routing.enabled cannot be false: dynamic routing is the only node runtime")
	}
	for _, path := range []string{settings.StateRoot, settings.SharedRoot} {
		if path != "" && !absoluteCleanPath(path) {
			return errors.New("dynamic_routing roots must be absolute clean paths")
		}
	}
	if value := settings.CacheMaxBytes; value != nil && *value != 0 && (*value < 64<<20 || *value > 1<<50) {
		return errors.New("dynamic_routing.cache_max_bytes must be 0 or between 64 MiB and 1 PiB")
	}
	return nil
}

// dynamicRoutingACMERoot is the ACME HTTP-01 overlay root of a dynamic
// routing node, beside its state and shared roots: the skeleton's workers
// read the tokens, and the deployment root stays private.
func dynamicRoutingACMERoot(config fileConfig) string {
	return filepath.Join(filepath.Dir(config.DeploymentRoot), "dynroute", "acme")
}

func dynamicRoutingRoots(config fileConfig) (state, shared string) {
	base := filepath.Join(filepath.Dir(config.DeploymentRoot), "dynroute")
	state, shared = config.DynamicRouting.StateRoot, config.DynamicRouting.SharedRoot
	if state == "" {
		state = filepath.Join(base, "state")
	}
	if shared == "" {
		shared = filepath.Join(base, "shared")
	}
	return state, shared
}

// dynamicRoutingObjectsRoot is the agent's object store on a dynamic routing
// node: inside the state root, opened shared with the worker group, so the
// workers read the site objects the gateway client stored (no copy, F13).
func dynamicRoutingObjectsRoot(config fileConfig) string {
	state, _ := dynamicRoutingRoots(config)
	return filepath.Join(state, objectStoreDir)
}

// openObjectStore opens the agent's one object store (site objects and the
// node artifact set): worker readable under the dynamic routing state root
// on a dynamic routing node, private under the deployment root otherwise.
func openObjectStore(config fileConfig) (*objectstore.Store, error) {
	if !config.DynamicRouting.Enabled {
		return objectstore.Open(filepath.Join(config.DeploymentRoot, objectStoreDir))
	}
	gid, err := lookupWorkerGID(config.DynamicRouting.WorkerGroup)
	if err != nil {
		return nil, err
	}
	// The daemon opens the store before assembleDynamicRouting: the state
	// root and every parent created on the way get the worker group
	// (dynroute.New leaves existing parents alone; a 0750 root:root
	// dynroute parent kept the workers out of site-index, D13d-2).
	state, _ := dynamicRoutingRoots(config)
	if err := dynroute.MkdirWorker(state, gid); err != nil {
		return nil, err
	}
	return objectstore.OpenShared(dynamicRoutingObjectsRoot(config), gid)
}

func lookupWorkerGID(name string) (int, error) {
	if name == "" {
		name = "nobody"
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return -1, fmt.Errorf("dynamic routing worker group %q: %w", name, err)
	}
	return strconv.Atoi(group.Gid)
}

// assembleDynamicRouting builds the node's dynamic routing runtime.
func assembleDynamicRouting(config fileConfig, nodeID string, certificates *certstore.Manager, engine *wafengine.Manager,
	healthTimeout time.Duration, ddosManager *ddos.Manager, rulePlans dynroute.RulePlans, l4 dynroute.L4Runtime) (*dynroute.Runtime, error) {
	gid, err := lookupWorkerGID(config.DynamicRouting.WorkerGroup)
	if err != nil {
		return nil, err
	}
	state, shared := dynamicRoutingRoots(config)
	cacheMaxBytes, err := dynamicRoutingCacheMaxBytes(config.DynamicRouting, shared)
	if err != nil {
		return nil, err
	}
	// The loopback health server (/healthz, the CC auto switch status and
	// kernel ban queue the runtime status poller drains) on the configured
	// health URL's port, as the v8 runtime serves it.
	healthPort, err := healthURLPort(config.OpenResty.HealthURL)
	if err != nil {
		return nil, err
	}
	registry, err := dyntelemetry.OpenRegistry(filepath.Join(state, "dyntelemetry-registry.json"))
	if err != nil {
		return nil, fmt.Errorf("dynamic routing telemetry registry: %w", err)
	}
	var ddosTable dynroute.DDoSApplier
	if ddosManager != nil {
		ddosTable = ddosManager
	}
	runtime, err := dynroute.New(dynroute.Config{
		StateRoot: state, SharedRoot: shared, ObjectsRoot: dynamicRoutingObjectsRoot(config), LuaRoot: dynamicRoutingLuaRoot, OpenResty: config.OpenResty.Binary,
		Globals:   dynamicRoutingGlobals(config),
		WorkerGID: gid, CacheMaxBytes: cacheMaxBytes, Telemetry: config.Telemetry.Enabled,
		Node: edgeskeleton.Node{ID: strings.ToLower(nodeID),
			IngressSourceIPv4: config.IngressSourceIPv4, IngressSourceIPv6: config.IngressSourceIPv6},
		NodeID:       strings.ToLower(nodeID),
		Certificates: certificates, OCSP: dyntls.HTTPFetcher{Client: &http.Client{Timeout: 10 * time.Second}},
		WAFEngine: func() (*dynwaf.Engine, error) {
			if engine == nil {
				return nil, nil
			}
			module, unicodeMap, err := engine.VerifiedPaths()
			if err != nil {
				return nil, err
			}
			return &dynwaf.Engine{ModulePath: module, UnicodeMapPath: unicodeMap}, nil
		},
		Registry: registry, HealthTimeout: healthTimeout, HealthPort: healthPort, DDoS: ddosTable, RulePlans: rulePlans,
		L4: l4, ACMEOverlayRoot: dynamicRoutingACMERoot(config),
		MarketProbe: config.MarketProbe.Enabled, MarketBenchmark: config.MarketProbe.JoinMarket,
		// The gate the local auto defense runtime writes (AD-05; assembleAutoDefense).
		AutoDefense: false, // cdncaCE: the auto defense module is not part of the community edition
	})
	if err != nil {
		return nil, fmt.Errorf("configure dynamic routing runtime: %w", err)
	}
	return runtime, nil
}

// dynamicRoutingGlobals: on the installed native profile the workers run as
// the native worker account (cdnca-runtime, the worker group of every worker
// readable file), not the compiled-in nobody.
func dynamicRoutingGlobals(config fileConfig) string {
	if config.OpenResty.SystemdService == "" {
		return ""
	}
	return "user cdnca-runtime cdnca-runtime;"
}

// healthURLPort is openresty.health_url's port (validated loopback URL).
func healthURLPort(value string) (int, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return 0, fmt.Errorf("openresty.health_url: %w", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("openresty.health_url has no valid port")
	}
	return port, nil
}

// dynamicRoutingRunner recovers the runtime at daemon start and runs its
// maintenance.
type dynamicRoutingRunner interface {
	Recover(context.Context) error
	Run(context.Context, dynroute.Intervals) error
}

// dynamicRoutingL4 runs the scopes' L4 forwards in the node's L4 runtime
// (the one l4DeploymentBridge drives on a v8 node): a release is opened,
// applied and, after the HTTP side is healthy, finished. No streams applies
// the empty v1 configuration, as the bridge does for a release without L4.
type dynamicRoutingL4 struct {
	manager *l4runtime.Manager
	dns     *l4runtime.DNSCoordinator
	// deploymentRoot holds the L4 telemetry logs the compiled config writes
	// (<root>/shared/telemetry/...): prepared before the release, as the
	// telemetry prechecker does for a v8 release.
	deploymentRoot string
	// stop closes the sessions of forwards withdrawn for package traffic
	// (L4_TRAFFIC_STOP); nil or without a closing executor they drain.
	stop *l4TrafficStop
}

// l4TrafficStopAPIVersion is CAPABILITY_NAME_L4_TRAFFIC_STOP's version.
const l4TrafficStopAPIVersion = 1

// l4TrafficStop holds what closing withdrawn forwards' sessions needs: the
// live connection executor (set once the daemon built it) and the
// configuration the open release replaces (its sessions are found there).
type l4TrafficStop struct {
	mu       sync.Mutex
	executor interface {
		CloseStreams(ctx context.Context, previous, current *l4runtime.ConfigV2, streamIDs []string) (int, error)
	}
	previous *l4runtime.ConfigV2
}

func (l4 dynamicRoutingL4) Begin(ctx context.Context, versionID string) error {
	if l4.stop != nil {
		previous, err := l4.manager.ActiveConfigV2(ctx)
		l4.stop.mu.Lock()
		l4.stop.previous = nil
		if err == nil {
			l4.stop.previous = previous
		}
		l4.stop.mu.Unlock()
	}
	return l4.manager.BeginRelease(ctx, versionID)
}

// CloseTrafficStopped closes the open sessions of streamIDs the finished
// release withdrew (dynroute.L4TrafficStopper).
func (l4 dynamicRoutingL4) CloseTrafficStopped(ctx context.Context, streamIDs []string) error {
	if l4.stop == nil {
		return nil
	}
	l4.stop.mu.Lock()
	executor, previous := l4.stop.executor, l4.stop.previous
	l4.stop.previous = nil
	l4.stop.mu.Unlock()
	if executor == nil || previous == nil {
		return nil
	}
	current, err := l4.manager.ActiveConfigV2(ctx)
	if err != nil {
		return err
	}
	closed, err := executor.CloseStreams(ctx, previous, current, streamIDs)
	if closed > 0 {
		log.Printf("dynamic routing: closed %d L4 sessions of %d forwards over package traffic", closed, len(streamIDs))
	}
	return err
}

func (l4 dynamicRoutingL4) Apply(ctx context.Context, versionID string, config *l4runtime.ConfigV2) error {
	if config != nil {
		if err := l4.prepareTelemetry(*config); err != nil {
			return err
		}
		_, err := l4.manager.ApplyV2(ctx, *config, l4.dns)
		return err
	}
	_, err := l4.manager.Apply(ctx, l4runtime.Config{SchemaVersion: l4runtime.SchemaVersionV1, VersionID: versionID,
		Listeners: []l4runtime.Listener{}, UpstreamPools: []l4runtime.UpstreamPool{}, DrainTimeoutMS: 30000})
	return err
}

func (l4 dynamicRoutingL4) Finish(ctx context.Context, versionID string, succeeded bool) error {
	return l4.manager.FinishRelease(ctx, versionID, succeeded)
}

func (l4 dynamicRoutingL4) prepareTelemetry(config l4runtime.ConfigV2) error {
	realRoot, err := filepath.EvalSymlinks(l4.deploymentRoot)
	if err != nil || realRoot == string(filepath.Separator) {
		return errors.New("L4 telemetry deployment root is unsafe")
	}
	for _, listener := range config.Listeners {
		versionID := listener.ConfigVersionID
		if versionID == "" {
			versionID = config.VersionID
		}
		sockets := []struct {
			id       string
			protocol l4runtime.Protocol
			address  string
			port     int
		}{{listener.ID, listener.Protocol, listener.Address, listener.Port}}
		for _, socket := range listener.AdditionalListeners {
			sockets = append(sockets, struct {
				id       string
				protocol l4runtime.Protocol
				address  string
				port     int
			}{socket.ID, socket.Protocol, socket.Address, socket.Port})
		}
		for _, socket := range sockets {
			path, err := l4runtime.L4TelemetryLogPathForIdentity(realRoot, versionID, listener.SiteID, listener.StreamID,
				socket.id, socket.protocol, socket.address, socket.port)
			if err != nil {
				return err
			}
			if err := ensurePrivateTelemetrySource(realRoot, path, os.Geteuid(), os.Getegid()); err != nil {
				return fmt.Errorf("prepare L4 telemetry log source: %w", err)
			}
		}
	}
	return nil
}

// dynamicRoutingTelemetrySource is the node-level shared log source of a
// dynamic routing node (D12): every line is bound to its site by the
// generation registry and the site object it names. nil without dynamic
// routing.
func dynamicRoutingTelemetrySource(runtime *dynroute.Runtime, nodeID string) *dynamicRoutingTelemetry {
	if runtime == nil || runtime.TelemetryRegistry() == nil {
		return nil
	}
	access, security := runtime.TelemetryLogs()
	resolver := &dyntelemetry.Resolver{Registry: runtime.TelemetryRegistry(),
		Sites: &dyntelemetry.ObjectSites{Root: runtime.ObjectsRoot()}, NodeID: strings.ToLower(nodeID)}
	return &dynamicRoutingTelemetry{AccessLogPath: access, SecurityLogPath: security, Resolve: resolver.Resolve,
		Sites: runtime.MetricSites, Connections: runtime.SiteConnections,
		SubscriptionMinutes: &dyntelemetry.SubscriptionMinutes{NodeID: strings.ToLower(nodeID), Take: runtime.SubscriptionMinutes,
			Sites: runtime.SubscriptionMinuteSites}}
}

// dynamicRoutingLuaRoot is where both node runtimes install the Lua modules.
const dynamicRoutingLuaRoot = "/usr/local/share/cdnca"
