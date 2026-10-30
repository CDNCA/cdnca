// Package dynroute is the edge agent side of dynamic routing (ADR 0009,
// site_runtime 9): it turns the node's site objects into a running node —
// the skeleton (edgeskeleton.Render, nginx -t and reload only when it
// changes), the certificate pool (dyntls), the managed WAF tiers (dynwaf),
// the cache zone pool and purge generations (dyncache) and the site index
// generation (siteindex.Activator) — and keeps them consistent across
// restarts, rollbacks and certificate rotation.
//
// Order of one Apply (contract §5.5, D11 interface): certificates into the
// pool and referenced objects into the worker readable directory, managed
// WAF tiers, skeleton reload (only if changed), index activation, health,
// then retention of the previous generation's certificates, WAF tiers and
// objects. A site never becomes routable before what it reads.
package dynroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyncache"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

var ErrInvalid = errors.New("dynamic routing runtime: invalid")

// CertificateStore is the certificate store (certstore.Manager): version
// files for the pool and the references that keep versions alive.
type CertificateStore interface {
	dyntls.Resolver
	SetCertificateVersionReferences(context.Context, certstore.CertificateVersionReferences) error
}

// Config is node-local and fixed for the process.
type Config struct {
	// StateRoot holds run/, site-objects/, site-index/, tls-pool/,
	// challenge/, origin-auth-secrets/, managed-waf/ (worker readable) and
	// the agent's own state.json and cache-generations.json.
	StateRoot string
	// SharedRoot is the OpenResty prefix: nginx.conf, pid, error.log,
	// temp and cache directories.
	SharedRoot string
	// ObjectsRoot, when set, is the agent's object store opened shared
	// (objectstore.OpenShared): the workers read site objects there and the
	// store owns their writes and collection (F13). "" = StateRoot/site-objects,
	// written by the activator.
	ObjectsRoot string
	LuaRoot     string
	OpenResty   string // absolute binary path
	// Globals are passed with -g on every OpenResty invocation (native
	// service: "user ..."); "" = none.
	Globals string
	// WorkerGID is the worker group of the worker readable files; < 0 keeps
	// the process group.
	WorkerGID int
	Node      edgeskeleton.Node
	// NodeID is this node's ID: the system configuration's per-node nginx
	// base (region/node overrides) is picked by it ("" = the base only).
	NodeID string
	// System is the system configuration when no scope carries one (tests;
	// nil = built-in defaults); a scope's Input.Systems takes precedence.
	System *edgeconfig.SiteRuntimeSystem
	// DDoS, when set, applies the node DDoS protection table of the running
	// system configuration after every activation (nil: no table).
	DDoS DDoSApplier
	// L4 is the node's L4 runtime the scopes' L4 forwards run in (nil: an
	// input with L4 forwards is refused).
	L4 L4Runtime
	// MuxRoot holds the internal sockets of ports an L4 forward shares with
	// websites; "" = SharedRoot/mux.
	MuxRoot string
	// ACMEOverlayRoot is the root the ACME HTTP-01 overlay (acmehttp01)
	// keeps its tokens under; "" renders no ACME location. The workers read
	// the tokens, so it is made worker traversable: never the deployment
	// root, which telemetry requires to be private.
	ACMEOverlayRoot string
	// MarketProbe / MarketBenchmark: the node market probe path and the
	// benchmark object (market_probe.enabled / join_market).
	MarketProbe     bool
	MarketBenchmark bool
	// CacheMaxBytes is the node cache budget (0 = no cache zones).
	CacheMaxBytes int64
	HealthPort    int
	Telemetry     bool
	Workers       int // > 0 pins worker_processes (tests)
	// AutoDefense renders the auto defense gate dictionaries and control
	// location (edgeskeleton.Input.AutoDefense): on when the node runs the
	// local auto defense runtime (AD-05), which writes the gate.
	AutoDefense bool
	// Certificates is required when any site has a TLS listener.
	Certificates CertificateStore
	OCSP         dyntls.Fetcher
	// WAFEngine returns the installed engine (nil, nil = none installed).
	WAFEngine func() (*dynwaf.Engine, error)
	// Registry, when set, registers every activated generation's scope
	// versions for telemetry attribution (D12).
	Registry *dyntelemetry.Registry
	// RulePlans prechecks rule pack mounts and writes their plans (nil: a
	// site with mounts is refused).
	RulePlans RulePlans
	// HealthTimeout bounds the wait for an activated generation's health.
	HealthTimeout time.Duration
	// ErrorLogRecent is how many recent severe error.log lines the snapshot
	// keeps (0 = 16).
	ErrorLogRecent int
	Now            func() time.Time
}

// RulePlans is the node side of rule pack mounts (ADR 0009 §8.4).
// Prepare reproduces each mounting site's resolved_sha256 from the packs in
// the object store and writes its plan under Root() (an error refuses the
// whole input: nothing changes); Retain drops plans no kept site names.
type RulePlans interface {
	Root() string
	// Prepare also checks a site's modsecurity pack against its managed WAF
	// with the input's CRS rule text and profile packs. referenced holds the
	// objects the sites reference by digest (the site's CC policies: their
	// trusted crawlers also exempt from the CC pack rules).
	// It returns the official CRS tuning entries of the mounted
	// system/crs-tuning pack (ADR 0011 RI-13; nil: none), which the managed
	// WAF's node rules render.
	Prepare(sites []edgesite.Site, referenced map[string][]byte, crsText *edgeconfig.CRSRuleText,
		profiles map[string]edgeconfig.CRSProfile) ([]edgeconfig.CRSTuningEntry, error)
	Retain(resolved map[string]bool) error
}

// Input is one node state: every site object of every scope the node
// serves, and what the managed WAF tiers are built from.
type Input struct {
	Objects []siteindex.Object
	// ScopeVersions is each scope's config version (telemetry attribution).
	ScopeVersions map[string]string
	// Installations is each scope's telemetry installation (independent
	// connections metrics; a scope without one reports none).
	Installations map[string]string
	CRSText       *edgeconfig.CRSRuleText
	Profiles      map[string]edgeconfig.CRSProfile
	// Apps are the application exclusion packs the scopes carry, by digest.
	Apps map[string]edgeconfig.CRSApp
	// WAFTargets are the automatic exclusions in force by site (ADR 0011
	// RI-04: the adaptive WAF's NodeTargets of the auto defense snapshot);
	// nil: none. A listed site gets its own location, so a change reloads.
	WAFTargets map[string][]edgeconfig.DynamicWAFTarget
	// Systems are the scopes' platform system configurations (nginx base,
	// DDoS protection); the node runs the highest revision.
	Systems []*edgeconfig.SiteRuntimeSystem
	// Streams are the scopes' L4 forwards, merged into the L4 runtime.
	Streams []ScopeStreams
	// TrafficStop are L4 forwards withdrawn because their package went over
	// its monthly traffic (L4_TRAFFIC_STOP): once the release is in place
	// their open sessions are closed instead of draining. nil: none.
	TrafficStop []string
	// NodePages are the scopes' node pages (no_host, unknown_site, error
	// page slots); per category this node's page wins (selectNodePages),
	// then the first.
	NodePages []NodePage
	// NodeRegion is the node's region code as the control plane sent it
	// (key document, NODE_REGION; fz-x12): region node pages, error page
	// variants and origin routes match on it. "" = none (nothing by region).
	NodeRegion string
	// NodeStorage is the node's storage settings as the control plane sent
	// them (key document, NODE_STORAGE); nil = the node's defaults.
	NodeStorage *siteobject.NodeStorage
}

// Result is what Apply did.
type Result struct {
	Activation siteindex.Activation
	Reloaded   bool // the skeleton changed (nginx -t + reload or start)
	Started    bool // OpenResty was not running and was started
	// OldWorkers are the worker PIDs a reload replaced (none without one).
	OldWorkers   []string
	Certificates dyntls.SyncResult
	WAFDigest    string
	// WAFProbe is the managed WAF's exclusion cost self test input
	// (dynwaf.Result.Probe, waf-exclcap2); nil without a managed WAF.
	WAFProbe *dynwaf.Probe
	Duration time.Duration
}

// persisted is state.json: what the previous generation kept alive.
type persisted struct {
	Generation   uint64           `json:"generation"`
	Versions     []dyntls.Version `json:"versions"`
	PrevVersions []dyntls.Version `json:"previous_versions"`
	WAF          string           `json:"waf"`
	PrevWAF      string           `json:"previous_waf"`
	Skeleton     string           `json:"skeleton"`
	// System is the system configuration the skeleton was rendered with
	// (Rollback and Recover keep it).
	System *edgeconfig.SiteRuntimeSystem `json:"system,omitempty"`
	// L4 is the L4 runtime's active version ("" = none applied), L4Ports
	// the ports its dispatcher hands to the skeleton, L4TCP the streams'
	// TCP ports (DDoS table, CC exclusive ports).
	L4      string           `json:"l4,omitempty"`
	L4Ports []int            `json:"l4_ports,omitempty"`
	L4TCP   []ddos.PortRange `json:"l4_tcp,omitempty"`
	// NodePages are the skeleton's node pages (D13-b2).
	NodePages []nodePageRecord `json:"node_pages,omitempty"`
	// NodeRegion is the region the skeleton was rendered with (Input.NodeRegion).
	NodeRegion string `json:"node_region,omitempty"`
	// Storage is the cache directory and limit the skeleton was rendered
	// with; RequestedStorage the control plane's last accepted settings
	// (its log directory is what the next New runs with).
	Storage          effectiveStorage        `json:"storage,omitempty"`
	RequestedStorage *siteobject.NodeStorage `json:"requested_storage,omitempty"`
	// Scopes: each active scope's config version and telemetry installation
	// (MetricSites).
	Scopes map[string]scopeIdentity `json:"scopes,omitempty"`
}

type scopeIdentity struct {
	ConfigVersionID string `json:"config_version_id"`
	InstallationID  string `json:"installation_id,omitempty"`
}

// Runtime owns the node's dynamic routing runtime. Methods are safe for
// concurrent use; Apply, Rollback and cache operations are serialized.
type Runtime struct {
	config    Config
	activator *siteindex.Activator
	pool      dyntls.Pool
	control   dyncache.UnixControl

	mu          sync.Mutex
	state       persisted
	lastInput   Input // CRS text and profiles of the last Apply (Rollback)
	sites       []edgesite.Site
	generations *dyncache.Generations
	prewarm     dyncache.Prewarmer
	zones       dyncache.Zones

	logMu    sync.Mutex
	errorLog dyntelemetry.ErrorLog
	logStats ErrorLogStats

	// maintenance: the node is stopped (ADR 0014 LIC-BAN-05): every site
	// server answers 503 and no L4 forward runs; nil = serving.
	maintenance *edgeskeleton.Maintenance

	// region: the node's region code of the last Apply (Input.NodeRegion,
	// kept in state.json for Rollback and the maintenance re-render).
	region string

	// storage: the cache directory and limit of the last render; logRoot the
	// log directory of this process (fixed at New); storageError why the
	// control plane's last settings were refused ("" = none).
	storage      effectiveStorage
	logRoot      string
	storageError string
	// refusedStorage: the settings storageError is about (not retried).
	refusedStorage *siteobject.NodeStorage

	// unavailable: the certificate versions the last sync could not give
	// (their sites' handshakes are refused), read without the apply lock.
	unavailable atomic.Pointer[[]dyntls.Unavailable]

	// ddosStatus: the last DDoS table application (DDoSStatus), read without
	// the apply lock.
	ddosStatus atomic.Pointer[DDoSStatus]
}

// New prepares the directories and the placeholder certificate; it does not
// start OpenResty (Recover or Apply does).
func New(config Config) (*Runtime, error) {
	for _, path := range []string{config.StateRoot, config.SharedRoot, config.LuaRoot, config.OpenResty} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("%w: path %q must be absolute and clean", ErrInvalid, path)
		}
	}
	if root := config.ObjectsRoot; root != "" && (!filepath.IsAbs(root) || filepath.Clean(root) != root) {
		return nil, fmt.Errorf("%w: path %q must be absolute and clean", ErrInvalid, root)
	}
	if config.HealthTimeout <= 0 {
		config.HealthTimeout = 30 * time.Second
	}
	if config.ErrorLogRecent <= 0 {
		config.ErrorLogRecent = 16
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	access := siteindex.Access{GID: config.WorkerGID}
	// both roots are traversed by the workers (group worker, no other)
	roots := []string{config.StateRoot, config.SharedRoot}
	if config.ACMEOverlayRoot != "" {
		roots = append(roots, config.ACMEOverlayRoot)
	}
	for _, dir := range roots {
		if err := mkdirWorker(dir, config.WorkerGID); err != nil {
			return nil, err
		}
	}
	names := []string{"run", edgeskeleton.IndexDirectory, edgeskeleton.TLSPoolDirectory,
		edgeskeleton.ChallengeDirectory, edgeskeleton.OriginAuthDirectory, "managed-waf"}
	if config.ObjectsRoot == "" {
		names = append(names, edgeskeleton.ObjectDirectory)
	}
	for _, name := range names {
		if err := mkdirWorker(filepath.Join(config.StateRoot, name), config.WorkerGID); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"cache", "logs", "client_body-temp", "proxy-temp", "fastcgi-temp", "uwsgi-temp", "scgi-temp"} {
		if err := mkdirWorker(filepath.Join(config.SharedRoot, name), config.WorkerGID); err != nil {
			return nil, err
		}
	}
	if err := dyntls.WritePlaceholder(placeholderPath(config, ".crt"), placeholderPath(config, ".key"), config.WorkerGID); err != nil {
		return nil, err
	}
	// The log directory (NODE_STORAGE) is fixed for the process: the one the
	// last accepted control plane settings name, else the shared root.
	var saved persisted
	if raw, err := os.ReadFile(filepath.Join(config.StateRoot, "state.json")); err == nil {
		if err := json.Unmarshal(raw, &saved); err != nil {
			return nil, fmt.Errorf("%w: state.json: %v", ErrInvalid, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	probe := &Runtime{config: config}
	requestedLogs := ""
	if saved.RequestedStorage != nil {
		requestedLogs = saved.RequestedStorage.LogDirectory
	}
	logRoot, logErr := probe.logRootFor(requestedLogs)
	if logErr != nil {
		log.Printf("dynamic routing: node log directory: %v; logging under %s", logErr, logRoot)
	}
	if config.Telemetry {
		// The node-level logs exist before nginx opens them (the master
		// keeps an existing file's mode): private to the agent, whose
		// tailers refuse anything else.
		access, security := edgeconfig.DynamicRoutingTelemetryPaths(logRoot)
		if err := os.MkdirAll(filepath.Dir(access), 0o750); err != nil {
			return nil, err
		}
		for _, path := range []string{access, security} {
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return nil, err
			}
			_ = file.Close()
		}
		// The aggregated security lines' flush socket (sec-log-agg): nginx
		// makes a unix listener 0666, so the directory is the access control
		// - group worker may enter (connect), not list or create.
		flush := filepath.Join(config.StateRoot, edgeskeleton.SecurityFlushDirectory)
		if err := os.Mkdir(flush, 0o710); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err := os.Chmod(flush, 0o710); err != nil {
			return nil, err
		}
		if config.WorkerGID >= 0 {
			if err := os.Lchown(flush, -1, config.WorkerGID); err != nil {
				return nil, err
			}
		}
	}
	socket := filepath.Join(config.StateRoot, edgeskeleton.ControlSocket)
	runtime := &Runtime{
		config: config,
		activator: &siteindex.Activator{Control: siteindex.NewControl(socket),
			Files:   siteindex.Files{Root: filepath.Join(config.StateRoot, edgeskeleton.IndexDirectory), Access: access},
			Objects: objectDir(config, access)},
		pool:     dyntls.Pool{Root: filepath.Join(config.StateRoot, edgeskeleton.TLSPoolDirectory), GID: config.WorkerGID},
		control:  dyncache.UnixControl{Socket: socket},
		errorLog: dyntelemetry.ErrorLog{Path: filepath.Join(logRoot, "error.log")},
		logRoot:  logRoot,
	}
	if logErr != nil {
		runtime.storageError = logErr.Error()
	}
	runtime.activator.LiveWorker = runtime.liveWorker
	runtime.generations = &dyncache.Generations{Path: filepath.Join(config.StateRoot, "cache-generations.json"), Control: runtime.control}
	if raw, err := os.ReadFile(runtime.statePath()); err == nil {
		if err := json.Unmarshal(raw, &runtime.state); err != nil {
			return nil, fmt.Errorf("%w: state.json: %v", ErrInvalid, err)
		}
		runtime.region = runtime.state.NodeRegion
		runtime.storage = runtime.state.Storage
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return runtime, nil
}

func objectDir(config Config, access siteindex.Access) siteindex.ObjectDir {
	if config.ObjectsRoot != "" {
		return siteindex.ObjectDir{Root: config.ObjectsRoot, Access: access, External: true}
	}
	return siteindex.ObjectDir{Root: filepath.Join(config.StateRoot, edgeskeleton.ObjectDirectory), Access: access}
}

// mkdirWorker makes dir 0750 group worker. Every missing parent it creates on
// the way gets the same mode and group: the workers open files below dir by
// path, so a parent left 0750 root:root (MkdirAll under the root unit) makes
// the whole tree unreachable. Parents that already exist are left alone.
func mkdirWorker(dir string, gid int) error {
	if parent := filepath.Dir(dir); parent != dir {
		if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
			if err := mkdirWorker(parent, gid); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	if gid >= 0 {
		return os.Lchown(dir, -1, gid)
	}
	return nil
}

// MkdirWorker is mkdirWorker for callers that create a directory below the
// dynamic routing roots before New runs (the daemon's object store, D13d-2).
func MkdirWorker(dir string, gid int) error { return mkdirWorker(dir, gid) }

func placeholderPath(config Config, suffix string) string {
	return filepath.Join(config.StateRoot, "placeholder"+suffix)
}

func (runtime *Runtime) statePath() string {
	return filepath.Join(runtime.config.StateRoot, "state.json")
}
func (runtime *Runtime) confPath() string {
	return filepath.Join(runtime.config.SharedRoot, "nginx.conf")
}

func (runtime *Runtime) saveState() error {
	raw, err := json.Marshal(runtime.state)
	if err != nil {
		return err
	}
	temporary := runtime.statePath() + ".tmp"
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, runtime.statePath())
}

// TelemetryLogs are the node-level access and security logs the skeleton
// writes when Config.Telemetry is set.
func (runtime *Runtime) TelemetryLogs() (access, security string) {
	return edgeconfig.DynamicRoutingTelemetryPaths(runtime.logRoot)
}

// TelemetryRegistry is the generation -> scope version table the shared
// log resolver attributes lines with (nil without one).
func (runtime *Runtime) TelemetryRegistry() *dyntelemetry.Registry { return runtime.config.Registry }

// ObjectsRoot is the worker readable site object directory.
func (runtime *Runtime) ObjectsRoot() string {
	return objectDir(runtime.config, siteindex.Access{}).Root
}

// Object reads one verified object of the site object directory (a site's
// referenced policy, FX45 firewall action).
func (runtime *Runtime) Object(digest string) ([]byte, error) {
	if _, err := siteindex.ParseDigest(digest); err != nil {
		return nil, err
	}
	content, err := os.ReadFile(objectDir(runtime.config, siteindex.Access{}).Path(digest))
	if err != nil {
		return nil, err
	}
	if edgesite.Digest(content) != digest {
		return nil, fmt.Errorf("object %s does not match its digest", digest)
	}
	return content, nil
}

// Sites is the active generation's sites (after Apply or Recover).
func (runtime *Runtime) Sites() []edgesite.Site {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return slices.Clone(runtime.sites)
}

// SetMaintenance stops (non-nil) or resumes (nil) serving from the next
// Apply on; the caller applies again (dynamicRoutingManager.Reapply). The
// site objects, certificates and caches stay, so resuming is one reload.
func (runtime *Runtime) SetMaintenance(maintenance *edgeskeleton.Maintenance) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if maintenance != nil {
		copied := *maintenance
		maintenance = &copied
	}
	runtime.maintenance = maintenance
}

// Generation is the active index generation.
func (runtime *Runtime) Generation() uint64 {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.state.Generation
}

// ScopeVersion is the config version the active generation serves for
// scope ("" = none), from the persisted state: the dynamic routing manager
// settles an activation whose scope journal could not be saved with it.
func (runtime *Runtime) ScopeVersion(scopeID string) string {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.state.Scopes[scopeID].ConfigVersionID
}
