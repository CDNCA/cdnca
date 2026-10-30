package dynroute

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// Apply makes input the node's running state. On an error nothing the node
// serves has changed unless the error says the activation itself failed
// after the skeleton was reloaded (the previous index generation is still
// active then: the skeleton is a superset-compatible frame, see Rollback).
func (runtime *Runtime) Apply(ctx context.Context, input Input) (Result, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	started := runtime.config.Now()
	sites := make([]edgesite.Site, len(input.Objects))
	for index, object := range input.Objects {
		sites[index] = object.Site
	}
	var result Result
	// 1. certificates: copied from the certificate store into the pool
	// before any site naming them is routable.
	synced, err := runtime.syncCertificates(ctx, sites)
	if err != nil {
		return result, err
	}
	result.Certificates = synced
	// 2. rule pack mounts: refused unless the node reproduces every
	// mounting site's resolved_sha256 (the plans exist before any site
	// naming them is routable); the mounted CRS tuning pack goes to 2b.
	tuning, err := runtime.prepareRulePlans(sites, input)
	if err != nil {
		return result, err
	}
	// 2b. managed WAF tiers (D11): refused, not degraded, when unavailable.
	waf, err := runtime.prepareWAF(input, sites, tuning)
	if err != nil {
		return result, err
	}
	result.WAFDigest, result.WAFProbe = waf.Digest, waf.Probe
	// 3. skeleton: rendered from every site and the system configuration;
	// reload only when it changed.
	system, err := runtime.selectSystem(input.Systems)
	if err != nil {
		return result, err
	}
	// 3a. L4 forwards (D13-c0): planned with the sites (one port table);
	// a port moving between the skeleton and the L4 dispatcher is handed
	// over with both sides listening (installL4).
	streams := input.Streams
	if runtime.maintenance != nil {
		streams = nil // stopped: layer 4 refused (the L4 runtime releases every port)
	}
	l4, err := runtime.planStreams(sites, streams)
	if err != nil {
		return result, err
	}
	if input.NodeRegion != "" && !siteobject.NodeRegionPattern.MatchString(input.NodeRegion) {
		return result, fmt.Errorf("%w: node region %q", ErrInvalid, input.NodeRegion)
	}
	runtime.region = input.NodeRegion
	pages, err := runtime.writeNodePages(input.NodePages)
	if err != nil {
		return result, fmt.Errorf("node pages: %w", err)
	}
	// 3b. node storage (NODE_STORAGE): the requested cache directory and
	// limit take this render; settings the node refused before (or cannot
	// prepare now) keep the previous ones.
	previousStorage, requested := runtime.storage, runtime.state.RequestedStorage
	if runtime.refusedStorage == nil || input.NodeStorage == nil || *runtime.refusedStorage != *input.NodeStorage {
		storage, err := runtime.prepareStorage(input.NodeStorage)
		if err != nil {
			runtime.refuseStorage(input.NodeStorage, err)
		} else {
			runtime.storage, requested, runtime.refusedStorage, runtime.storageError = storage, input.NodeStorage, nil, ""
		}
	}
	conf, err := runtime.render(sites, waf, system, l4.dispatched, l4.tcp, pages)
	if err != nil {
		runtime.storage = previousStorage
		return result, err
	}
	if l4.versionID != "" && l4.versionID != runtime.state.L4 {
		if err := runtime.installL4(ctx, &result, sites, waf, system, l4, pages); err != nil {
			return result, err
		}
	}
	skeleton := skeletonDigest(conf)
	running := runtime.running()
	reloadedSkeleton := false // this Apply installed a new skeleton (a revert re-renders the old sites)
	if skeleton != runtime.state.Skeleton || !running {
		reloaded, startedNow, old, err := runtime.install(ctx, conf)
		if err != nil {
			if runtime.storage == previousStorage {
				runtime.abortL4(l4)
				return result, err
			}
			// The running configuration is unchanged (the candidate was
			// refused). Try the release on the previous storage: when that
			// installs, the new storage was the cause and is refused (until
			// the control plane changes it) instead of failing every
			// publication.
			storageErr := err
			runtime.storage, requested = previousStorage, runtime.state.RequestedStorage
			if conf, err = runtime.render(sites, waf, system, l4.dispatched, l4.tcp, pages); err == nil {
				skeleton = skeletonDigest(conf)
				reloaded, startedNow, old, err = runtime.install(ctx, conf)
			}
			if err != nil {
				runtime.abortL4(l4)
				return result, err
			}
			runtime.refuseStorage(input.NodeStorage, storageErr)
		}
		reloadedSkeleton = true
		result.Reloaded, result.Started = result.Reloaded || reloaded, startedNow
		result.OldWorkers = append(result.OldWorkers, old...)
		if err := runtime.startCache(ctx, startedNow || !running); err != nil {
			runtime.abortL4(l4)
			return result, err
		}
	}
	// 4. index generation (objects, referenced objects, change sets).
	runtime.activator.Prepare = runtime.prepareGenerations(input.ScopeVersions)
	activation, err := runtime.activator.Activate(ctx, input.Objects)
	if err != nil {
		runtime.abortL4(l4)
		return result, fmt.Errorf("activate site index: %w", err)
	}
	result.Activation = activation
	// From here the new generation is active: a failure is compensated by
	// returning to the previous one (RevertedError), and when that fails too
	// the error says the node's state is not the previous one
	// (RollbackFailedError), never "running configuration unchanged".
	installed := runtime.state.Skeleton
	if reloadedSkeleton {
		installed = skeleton
	}
	health, err := runtime.activator.WaitHealthy(ctx, activation.Generation, activation.Probes, runtime.config.HealthTimeout)
	if err == nil && !health.Healthy {
		err = fmt.Errorf("site index generation %d unhealthy: %s", activation.Generation, strings.Join(health.Reasons, "; "))
	}
	if err != nil {
		runtime.abortL4(l4)
		return result, runtime.revertActivation(ctx, activation.Generation, installed, previousStorage, err)
	}
	if l4.versionID != "" && l4.versionID != runtime.state.L4 {
		if err := runtime.config.L4.Finish(ctx, l4.versionID, true); err != nil {
			runtime.abortL4(l4)
			return result, runtime.revertActivation(ctx, activation.Generation, installed, previousStorage, fmt.Errorf("L4 runtime: %w", err))
		}
		// Over-traffic forwards: their sessions end now, not after the
		// drain. A failure leaves them draining (the release stands).
		if stopper, ok := runtime.config.L4.(L4TrafficStopper); ok && len(input.TrafficStop) != 0 {
			if err := stopper.CloseTrafficStopped(ctx, input.TrafficStop); err != nil {
				log.Printf("dynamic routing: L4 traffic stop: %v", err)
			}
		}
	}
	// 5. retention: the active and the previous generation's certificates
	// and WAF tiers stay; the rest goes.
	previous := runtime.state
	runtime.state = persisted{Generation: activation.Generation, Versions: synced.Versions, PrevVersions: previous.Versions,
		WAF: waf.Digest, PrevWAF: previous.WAF, Skeleton: skeleton, System: system,
		L4: previous.L4, L4Ports: sortedPorts(l4.dispatched), L4TCP: l4.tcp, NodePages: pages,
		NodeRegion: input.NodeRegion, Scopes: scopeIdentities(input), Storage: runtime.storage, RequestedStorage: requested}
	if l4.versionID != "" {
		runtime.state.L4 = l4.versionID
	}
	if previous.WAF == waf.Digest {
		runtime.state.PrevWAF = previous.PrevWAF
	}
	previousSites := runtime.sites
	runtime.sites = sites
	runtime.setUnavailable(synced)
	runtime.lastInput = Input{CRSText: input.CRSText, Profiles: input.Profiles, Apps: input.Apps}
	if err := runtime.maintainActivated(ctx, activation.Generation, system, sites, previousSites, l4.tcp); err != nil {
		return result, err
	}
	result.Duration = runtime.config.Now().Sub(started)
	return result, nil
}

// revertActivation compensates generation, activated by this Apply and then
// failed (cause): the index returns to the previous generation and the
// skeleton is rendered again for its sites (installed is the skeleton
// digest running now; runtime.state still describes the previous release).
// Called with runtime.mu held.
func (runtime *Runtime) revertActivation(ctx context.Context, generation uint64, installed string,
	previousStorage effectiveStorage, cause error) error {
	ctx = context.WithoutCancel(ctx) // the compensation runs even when the delivery is cancelled
	failed := func(err error) error {
		log.Printf("dynamic routing: ALERT generation %d active and failed (%v); rollback failed: %v", generation, cause, err)
		return &RollbackFailedError{Generation: generation, Err: cause, RollbackErr: err}
	}
	// generations made by the rollback serve the previous release's scopes
	versions := map[string]string{}
	for scope, identity := range runtime.state.Scopes {
		versions[scope] = identity.ConfigVersionID
	}
	runtime.activator.Prepare = runtime.prepareGenerations(versions)
	reverted, err := runtime.rollbackIndex(ctx)
	if err != nil {
		return failed(fmt.Errorf("site index: %w", err))
	}
	runtime.storage, runtime.region = previousStorage, runtime.state.NodeRegion
	current, _, err := runtime.activator.Files.Current()
	if err != nil {
		return failed(err)
	}
	sites, err := runtime.readSites(current)
	if err != nil {
		return failed(err)
	}
	tuning, err := runtime.prepareRulePlans(sites, runtime.lastInput)
	if err != nil {
		return failed(err)
	}
	waf, err := runtime.prepareWAF(runtime.lastInput, sites, tuning)
	if err != nil {
		return failed(err)
	}
	conf, err := runtime.render(sites, waf, runtime.state.System, portSet(runtime.state.L4Ports), runtime.state.L4TCP, runtime.state.NodePages)
	if err != nil {
		return failed(err)
	}
	if digest := skeletonDigest(conf); digest != installed {
		if _, _, _, err := runtime.install(ctx, conf); err != nil {
			return failed(fmt.Errorf("skeleton: %w", err))
		}
		installed = digest
	}
	runtime.state.Skeleton, runtime.state.Generation = installed, reverted
	if err := runtime.saveState(); err != nil {
		// the previous generation runs; only state.json is stale
		log.Printf("dynamic routing: state after reverting generation %d: %v", generation, err)
	}
	return &RevertedError{Generation: generation, RevertedTo: reverted, Err: cause}
}

// rollbackIndex returns the index to the previous generation: one step when
// the active generation came from one change set, else by activating the
// previous index file as a new generation (contract §4.3).
func (runtime *Runtime) rollbackIndex(ctx context.Context) (uint64, error) {
	index, found, err := runtime.activator.Files.Current()
	if err != nil || !found {
		return 0, fmt.Errorf("%w: no active index file", ErrInvalid)
	}
	generation, err := runtime.activator.Rollback(ctx)
	if err == nil {
		return generation, nil
	}
	previous, ok := runtime.activator.Files.Previous(index.Generation)
	if !ok {
		return 0, err
	}
	activation, toErr := runtime.activator.RollbackTo(ctx, previous)
	if toErr != nil {
		return 0, errors.Join(err, toErr)
	}
	return activation.Generation, nil
}

// RevertedError is an Apply failure after the new generation was activated
// (health check or L4 hand-over) that was compensated: the node runs the
// previous generation again (RevertedTo).
type RevertedError struct {
	Generation, RevertedTo uint64
	Err                    error
}

func (e *RevertedError) Error() string {
	return fmt.Sprintf("generation %d activated and failed: %v; reverted to generation %d", e.Generation, e.Err, e.RevertedTo)
}

func (e *RevertedError) Unwrap() error { return e.Err }

// RevertedAfterActivation marks the error for the deployment journal
// (gatewayclient.DynamicRoutingReverted).
func (e *RevertedError) RevertedAfterActivation() bool { return true }

// RollbackFailedError is an Apply failure after activation whose
// compensation failed too: the node's running state is not the previous
// release (the new generation may be active), it needs reconciliation.
type RollbackFailedError struct {
	Generation       uint64
	Err, RollbackErr error
}

func (e *RollbackFailedError) Error() string {
	return fmt.Sprintf("generation %d activated and failed: %v; rollback to the previous generation failed: %v",
		e.Generation, e.Err, e.RollbackErr)
}

func (e *RollbackFailedError) Unwrap() []error { return []error{e.Err, e.RollbackErr} }

// RollbackFailedAfterActivation marks the error for the deployment journal
// (gatewayclient.DynamicRoutingRollbackFailed).
func (e *RollbackFailedError) RollbackFailedAfterActivation() bool { return true }

// maintainActivated is what follows an activated, healthy generation: the
// state save, the DDoS table and retention. The generation is active: a
// failure here is a MaintenanceError (activated, maintenance failed), never
// "running configuration unchanged" (PJ-E02).
func (runtime *Runtime) maintainActivated(ctx context.Context, generation uint64, system *edgeconfig.SiteRuntimeSystem,
	sites, previousSites []edgesite.Site, streams []ddos.PortRange) error {
	if err := runtime.saveState(); err != nil {
		// No retention without the persisted state: the state on disk still
		// names the versions the retention would delete.
		runtime.applyDDoS(ctx, system, sites, streams)
		return &MaintenanceError{Generation: generation, Step: "save_state", Err: err}
	}
	runtime.applyDDoS(ctx, system, sites, streams)
	if err := runtime.retain(ctx); err != nil {
		return &MaintenanceError{Generation: generation, Step: "retain", Err: err}
	}
	if runtime.config.RulePlans != nil {
		// The previous generation's plans stay (rollback).
		keep := mountedResolved(sites)
		for resolved := range mountedResolved(previousSites) {
			keep[resolved] = true
		}
		if err := runtime.config.RulePlans.Retain(keep); err != nil {
			return &MaintenanceError{Generation: generation, Step: "retain_rule_plans", Err: err}
		}
	}
	return nil
}

// MaintenanceError is an Apply failure after the new generation was
// activated and healthy: the node serves the new configuration, only the
// bookkeeping after it (state.json, retention) failed.
type MaintenanceError struct {
	Generation uint64
	Step       string // save_state, retain or retain_rule_plans
	Err        error
}

func (e *MaintenanceError) Error() string {
	return fmt.Sprintf("generation %d active, post-activation %s failed: %v", e.Generation, e.Step, e.Err)
}

func (e *MaintenanceError) Unwrap() error { return e.Err }

// ActivatedMaintenanceFailure marks the error as "activated, maintenance
// failed" for the deployment journal (gatewayclient.DynamicRoutingActivated).
func (e *MaintenanceError) ActivatedMaintenanceFailure() bool { return true }

func (runtime *Runtime) prepareRulePlans(sites []edgesite.Site, input Input) ([]edgeconfig.CRSTuningEntry, error) {
	if len(mountedResolved(sites)) == 0 {
		return nil, nil
	}
	if runtime.config.RulePlans == nil {
		return nil, fmt.Errorf("%w: sites mount rule packs and the node has no rule pack runtime", ErrInvalid)
	}
	referenced := map[string][]byte{}
	for _, object := range input.Objects {
		for digest, content := range object.Referenced {
			referenced[digest] = content
		}
	}
	tuning, err := runtime.config.RulePlans.Prepare(sites, referenced, input.CRSText, input.Profiles)
	if err != nil {
		return nil, fmt.Errorf("rule pack mounts: %w", err)
	}
	return tuning, nil
}

// mountedResolved is the resolved_sha256 of every site with mounts.
func mountedResolved(sites []edgesite.Site) map[string]bool {
	resolved := map[string]bool{}
	for _, site := range sites {
		if len(site.Security.Mounts) > 0 {
			resolved[site.Security.ResolvedSHA256] = true
		}
	}
	return resolved
}

func skeletonDigest(conf []byte) string {
	digest := sha256.Sum256(conf)
	return hex.EncodeToString(digest[:])
}

func (runtime *Runtime) syncCertificates(ctx context.Context, sites []edgesite.Site) (dyntls.SyncResult, error) {
	tls := false
	for _, site := range sites {
		for _, listener := range site.Listeners {
			tls = tls || listener.TLS != nil
		}
	}
	if !tls {
		return dyntls.SyncResult{}, nil
	}
	if runtime.config.Certificates == nil {
		return dyntls.SyncResult{}, fmt.Errorf("%w: TLS sites without a certificate store", ErrInvalid)
	}
	return runtime.pool.Sync(ctx, runtime.config.Certificates, sites)
}

// UnavailableCertificates are the certificate versions of the running
// sites the last sync could not give (missing, or outside their validity
// window): those sites serve no HTTPS; the rest of the node is unaffected.
func (runtime *Runtime) UnavailableCertificates() []dyntls.Unavailable {
	if current := runtime.unavailable.Load(); current != nil {
		return append([]dyntls.Unavailable(nil), (*current)...)
	}
	return nil
}

func (runtime *Runtime) setUnavailable(result dyntls.SyncResult) {
	value := append([]dyntls.Unavailable(nil), result.Unavailable...)
	runtime.unavailable.Store(&value)
}

func (runtime *Runtime) prepareWAF(input Input, sites []edgesite.Site, tuning []edgeconfig.CRSTuningEntry) (dynwaf.Result, error) {
	managed := false
	for _, site := range sites {
		managed = managed || site.Security.ManagedWAF != nil
	}
	if !managed {
		return dynwaf.Result{}, nil
	}
	var engine *dynwaf.Engine
	if runtime.config.WAFEngine != nil {
		var err error
		if engine, err = runtime.config.WAFEngine(); err != nil {
			return dynwaf.Result{}, fmt.Errorf("%w: %v", dynwaf.ErrUnavailable, err)
		}
	}
	return dynwaf.Prepare(dynwaf.Input{Sites: sites, CRSText: input.CRSText, Profiles: input.Profiles, Apps: input.Apps, Engine: engine,
		Root: filepath.Join(runtime.config.StateRoot, "managed-waf"), AuditLog: AuditLogPath(runtime.config.SharedRoot),
		Targets: input.WAFTargets, Tuning: tuning})
}

// AuditLogPath is the managed WAF's ModSecurity audit log under the shared
// root (the adaptive WAF reads and truncates it, agent internal/wafadapt).
func AuditLogPath(sharedRoot string) string {
	return filepath.Join(sharedRoot, "modsecurity-audit.log")
}

// render: l4TCP are the TCP ports the L4 runtime listens on (the probe
// server stays off port 80 when a stream owns it).
func (runtime *Runtime) render(sites []edgesite.Site, waf dynwaf.Result, system *edgeconfig.SiteRuntimeSystem, dispatched map[int]bool,
	l4TCP []ddos.PortRange, pages []nodePageRecord) ([]byte, error) {
	unknown, noHost, slotPages, err := runtime.skeletonPages(pages)
	if err != nil {
		return nil, err
	}
	ports, keys, err := edgeskeleton.FromSites(sites)
	if err != nil {
		return nil, err
	}
	pool, err := runtime.cachePool(sites, system)
	if err != nil {
		return nil, err
	}
	runtime.zones = dyncache.Zones{Root: runtime.cacheRoot(), Count: pool.Zones}
	placeholder := placeholderPath(runtime.config, ".crt")
	rulePlanRoot := ""
	if runtime.config.RulePlans != nil {
		rulePlanRoot = runtime.config.RulePlans.Root()
	}
	node := runtime.config.Node
	node.ID = strings.ToLower(runtime.config.NodeID) // error page variants (errpage-ovr)
	node.Region = runtime.region                     // the control plane's (fz-x12)
	conf, err := edgeskeleton.Render(edgeskeleton.Input{Ports: ports, IndexKeys: keys, System: system,
		Node: node, Cache: pool, Telemetry: runtime.config.Telemetry, HealthPort: runtime.config.HealthPort,
		Challenges: edgeskeleton.ChallengesFromSites(sites), ManagedWAF: waf.Skeleton, AutoDefense: runtime.config.AutoDefense,
		SiteGzip: edgeskeleton.SiteGzipFromSites(sites), SiteBrotli: edgeskeleton.SiteBrotliFromSites(sites),
		SiteWebP: edgeskeleton.SiteWebPFromSites(sites), UnknownSite: unknown, NoHost: noHost, SlotPages: slotPages,
		Paths: edgeskeleton.Paths{SharedRoot: runtime.config.SharedRoot, CacheRoot: runtime.cacheRoot(), LogRoot: runtime.logRoot, LuaRoot: runtime.config.LuaRoot, StateRoot: runtime.config.StateRoot,
			ObjectsRoot: runtime.config.ObjectsRoot, PlaceholderCertificate: placeholder, PlaceholderKey: placeholderPath(runtime.config, ".key"), OriginTrustPlaceholder: placeholder,
			RulePlanRoot: rulePlanRoot, MuxRoot: runtime.muxRoot()}, DispatchedPorts: dispatched,
		ACMEOverlayRoot: runtime.config.ACMEOverlayRoot, MarketProbe: runtime.config.MarketProbe,
		MarketBenchmark: runtime.config.MarketBenchmark, ProbePortTaken: portIn(l4TCP, edgeskeleton.MarketProbePort),
		Maintenance: runtime.maintenance, NodeNetworks: nodeNetworks(system)})
	if err != nil {
		return nil, err
	}
	if runtime.config.Workers > 0 {
		conf = []byte(strings.Replace(string(conf), "worker_processes auto;\n", "worker_processes "+strconv.Itoa(runtime.config.Workers)+";\n", 1))
	}
	return conf, nil
}

// cachePool is the zone pool for the node budget, its inactive time covering
// the longest cache rule TTL of the sites (none without a budget). The
// system configuration's proxy_cache_max_size caps the node's own budget
// (never above it: the local budget is what the disk allows) and its
// min_free is rendered on every zone.
func (runtime *Runtime) cachePool(sites []edgesite.Site, system *edgeconfig.SiteRuntimeSystem) (edgecache.Pool, error) {
	budget, minFree := runtime.cacheBudget(), int64(0)
	if budget <= 0 {
		return edgecache.Pool{}, nil
	}
	if system != nil {
		if limit := system.Nginx.ProxyCacheMaxBytes; limit > 0 && limit < budget {
			budget = max(limit, 64<<20) // edgecache.PlanPool's floor
		}
		minFree = system.Nginx.ProxyCacheMinFreeBytes
	}
	maxTTL := time.Duration(0)
	for _, site := range sites {
		if plan, err := edgecache.Build(site); err == nil && plan != nil {
			maxTTL = max(maxTTL, plan.MaxTTL())
		}
	}
	return edgecache.PlanPool(edgecache.PoolInput{MaxBytes: budget, MinFreeBytes: minFree, MaxRuleTTL: maxTTL})
}

func (runtime *Runtime) openresty(ctx context.Context, conf string, args ...string) error {
	command := []string{"-p", runtime.config.SharedRoot + "/", "-c", conf}
	if runtime.config.Globals != "" {
		command = append(command, "-g", runtime.config.Globals)
	}
	output, err := exec.CommandContext(ctx, runtime.config.OpenResty, append(command, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// install checks conf with nginx -t (as a candidate file), then swaps it in
// and reloads (or starts) OpenResty. A failed check leaves the running
// configuration untouched. old are the workers a reload replaced (they
// finish their connections: drain, RemainingWorkers).
func (runtime *Runtime) install(ctx context.Context, conf []byte) (reloaded, started bool, old []string, err error) {
	candidate := runtime.confPath() + ".candidate"
	if err := os.WriteFile(candidate, conf, 0o640); err != nil {
		return false, false, nil, err
	}
	defer os.Remove(candidate)
	if err := runtime.openresty(ctx, candidate, "-t", "-q"); err != nil {
		return false, false, nil, err
	}
	previous, _ := os.ReadFile(runtime.confPath())
	if err := os.Rename(candidate, runtime.confPath()); err != nil {
		return false, false, nil, err
	}
	pid, alive := runtime.masterPID()
	if !alive {
		if err := runtime.openresty(ctx, runtime.confPath()); err != nil {
			return false, false, nil, err
		}
		return true, true, nil, runtime.waitControl(ctx)
	}
	before := workerPIDs(pid)
	if err := runtime.openresty(ctx, runtime.confPath(), "-s", "reload"); err != nil {
		if previous != nil {
			_ = os.WriteFile(runtime.confPath(), previous, 0o640)
		}
		return false, false, nil, err
	}
	return true, false, httpWorkers(before), waitNewWorkers(ctx, pid, before)
}

// httpWorkers keeps the worker processes of pids (not the cache manager or
// loader, which a reload replaces without connections to finish).
func httpWorkers(pids []string) []string {
	var workers []string
	for _, pid := range pids {
		if raw, err := os.ReadFile("/proc/" + pid + "/cmdline"); err == nil && strings.Contains(string(raw), "worker process") {
			workers = append(workers, pid)
		}
	}
	return workers
}

// RemainingWorkers counts the workers of old (Result.OldWorkers) still
// running under the active master: shutting down, they serve the
// connections they held at the reload. A changed master (restart) leaves
// none of them.
func (runtime *Runtime) RemainingWorkers(old []string) int {
	master, alive := runtime.masterPID()
	if !alive || len(old) == 0 {
		return 0
	}
	remaining := 0
	for _, pid := range workerPIDs(master) {
		if slices.Contains(old, pid) {
			remaining++
		}
	}
	return remaining
}

func (runtime *Runtime) masterPID() (int, bool) {
	raw, err := os.ReadFile(filepath.Join(runtime.config.SharedRoot, "nginx.pid"))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 2 {
		return 0, false
	}
	return pid, syscall.Kill(pid, 0) == nil
}

// liveWorker: a heartbeat pid is live while it is a child of the running
// master (Linux /proc); without /proc every heartbeat counts.
func (runtime *Runtime) liveWorker(pid string) bool {
	master, alive := runtime.masterPID()
	if !alive {
		return true
	}
	children := workerPIDs(master)
	if children == nil {
		return true
	}
	// A worker a reload replaced keeps serving the connections it held
	// (drain) but no longer accepts: its generation does not matter, or a
	// long request would hold the health check until it ends.
	return slices.Contains(children, pid) && !shuttingDown(pid)
}

func (runtime *Runtime) running() bool {
	_, alive := runtime.masterPID()
	return alive
}

func (runtime *Runtime) waitControl(ctx context.Context) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := runtime.activator.Control.Status(ctx); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return fmt.Errorf("control socket: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// workerPIDs lists master's children (Linux /proc; elsewhere none, so the
// reload wait only checks the control socket).
func workerPIDs(master int) []string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", master, master))
	if err != nil {
		return nil
	}
	return strings.Fields(string(raw))
}

// waitNewWorkers waits until the reload's new workers run and every worker
// of before has left (exited, or "worker process is shutting down": it no
// longer accepts), so the next connection is served by the new
// configuration.
func waitNewWorkers(ctx context.Context, master int, before []string) error {
	if before == nil {
		return nil
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		current := workerPIDs(master)
		fresh, old := false, false
		for _, pid := range current {
			if !slices.Contains(before, pid) {
				fresh = true
			} else if !shuttingDown(pid) {
				old = true
			}
		}
		if fresh && !old {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("openresty reload: workers did not switch")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func shuttingDown(pid string) bool {
	raw, err := os.ReadFile("/proc/" + pid + "/cmdline")
	return err != nil || strings.Contains(string(raw), "shutting down")
}

// startCache pushes the purge generations (until then the node caches
// nothing) and a prewarm token after OpenResty (re)started with an empty
// cache dictionary. A reload keeps the dictionary; pushing again is
// harmless.
func (runtime *Runtime) startCache(ctx context.Context, fresh bool) error {
	if runtime.zones.Count == 0 {
		return nil
	}
	if err := runtime.generations.Sync(ctx); err != nil {
		return fmt.Errorf("cache generations: %w", err)
	}
	if runtime.prewarm.Token == "" || fresh {
		token := make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			return err
		}
		runtime.prewarm = dyncache.Prewarmer{Token: hex.EncodeToString(token), Address: "127.0.0.1", Timeout: 30 * time.Second, MaxBytes: 64 << 20}
	}
	return dyncache.SetPrewarmToken(ctx, runtime.control, runtime.prewarm.Token)
}

// prepareGenerations registers the scope versions of the generations an
// activation is about to make servable (telemetry attribution, D12).
func (runtime *Runtime) prepareGenerations(versions map[string]string) func(first, last uint64) error {
	if runtime.config.Registry == nil || len(versions) == 0 {
		return nil
	}
	return func(first, last uint64) error { return runtime.config.Registry.Register(first, last, versions) }
}

// retain drops certificate versions and WAF tiers that neither the active
// nor the previous generation uses, and tells the certificate store which
// versions are still in use.
func (runtime *Runtime) retain(ctx context.Context) error {
	references := dyntls.Keep(runtime.state.Versions, runtime.state.PrevVersions)
	keep := append(slices.Clone(references.Current), references.Previous...)
	sort.Strings(keep)
	if _, err := runtime.pool.Retain(keep); err != nil {
		return err
	}
	if runtime.config.Certificates != nil {
		if err := runtime.config.Certificates.SetCertificateVersionReferences(ctx, references); err != nil {
			return err
		}
	}
	var wafKeep []string
	for _, digest := range []string{runtime.state.WAF, runtime.state.PrevWAF} {
		if digest != "" {
			wafKeep = append(wafKeep, digest)
		}
	}
	if err := runtime.retainNodePages(); err != nil {
		return err
	}
	return dynwaf.Retain(filepath.Join(runtime.config.StateRoot, "managed-waf"), wafKeep...)
}
