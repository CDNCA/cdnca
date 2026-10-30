package nodemonitoring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Probe interface {
	Probe(context.Context, uint16, time.Duration) error
}

// ProtocolProbe is implemented by probes that can execute the protocol
// requested by the active configuration. Probe remains the compatibility
// boundary for older callers; those probes continue to perform a TCP check.
type ProtocolProbe interface {
	ProbeProtocol(context.Context, string, uint16, time.Duration) error
}

type RecoveryNotifier interface {
	NotifyRecovery(context.Context, RecoveryEvent) error
}

type Options struct {
	StateDir      string
	NodeID        string
	DefaultPort   uint16
	Probe         Probe
	Notifier      RecoveryNotifier
	Now           func() time.Time
	LoadCollector LoadCollector
}

type Runtime struct {
	mu            sync.Mutex
	stateDir      string
	nodeID        string
	defaultPort   uint16
	probe         Probe
	notifier      RecoveryNotifier
	now           func() time.Time
	loadCollector LoadCollector
	// ddosDrops holds a func(context.Context) []DDoSDropMetrics; its own
	// atomic, collectLoad runs under mu.
	ddosDrops atomic.Value
	// xdp holds a func(context.Context) *XDPStatusMetrics (SetXDP).
	xdp atomic.Value
	// siteDrop holds a func(context.Context) *SiteDropMetrics (SetSiteDrop).
	siteDrop atomic.Value
	// ddosProtection holds a func(context.Context) *DDoSProtectionMetrics
	// (SetDDoSProtection).
	ddosProtection atomic.Value
	// portGroupOverrides holds a func(context.Context) []PortGroupOverrideMetrics
	// (SetPortGroupOverrides).
	portGroupOverrides atomic.Value
	// storage holds a func() *StorageMetrics (SetStorage).
	storage         atomic.Value
	wait            func(context.Context, time.Duration) error
	changed         chan struct{}
	active          *Config
	lkg             *Config
	healthy         bool
	failures        uint8
	successes       uint8
	failureAt       time.Time
	recoveryAt      time.Time
	pendingRecovery *RecoveryEvent
	probes          uint64
	probeErrors     uint64
}

// SetDDoSDrops names the node DDoS table's drop counters (ddos.Manager,
// which the Agent builds after the runtime); every load sample with node
// telemetry carries them.
func (runtime *Runtime) SetDDoSDrops(source func(context.Context) []DDoSDropMetrics) {
	if source != nil {
		runtime.ddosDrops.Store(source)
	}
}

// SetXDP names the node XDP filter's status (xdp.Manager); every load
// sample with node telemetry carries it.
func (runtime *Runtime) SetXDP(source func(context.Context) *XDPStatusMetrics) {
	if source != nil {
		runtime.xdp.Store(source)
	}
}

// SetSiteDrop names the level D site drops since the previous call; every
// load sample with node telemetry carries them (none: no site drop).
func (runtime *Runtime) SetSiteDrop(source func(context.Context) *SiteDropMetrics) {
	if source != nil {
		runtime.siteDrop.Store(source)
	}
}

// SetDDoSProtection names the node DDoS protection state; every load sample
// with node telemetry carries it.
func (runtime *Runtime) SetDDoSProtection(source func(context.Context) *DDoSProtectionMetrics) {
	if source != nil {
		runtime.ddosProtection.Store(source)
	}
}

// SetPortGroupOverrides names the layer 4 auto defense port group overrides
// (l4.Engine); every load sample with node telemetry carries them.
func (runtime *Runtime) SetPortGroupOverrides(source func(context.Context) []PortGroupOverrideMetrics) {
	if source != nil {
		runtime.portGroupOverrides.Store(source)
	}
}

// SetStorage names the node storage in effect (dynroute StorageStatus);
// every load sample with node telemetry carries it.
func (runtime *Runtime) SetStorage(source func() *StorageMetrics) {
	if source != nil {
		runtime.storage.Store(source)
	}
}

// collectLoad is a valid load sample at now, nil when there is none.
func (runtime *Runtime) collectLoad(ctx context.Context, now time.Time) *LoadMetrics {
	load, err := runtime.loadCollector.Collect(ctx, now)
	if err != nil || !validLoadMetrics(load, now) {
		return nil
	}
	source, _ := runtime.ddosDrops.Load().(func(context.Context) []DDoSDropMetrics)
	if source != nil && load.Telemetry != nil {
		if drops := source(ctx); validDDoSDrops(drops) {
			telemetry := *load.Telemetry
			telemetry.DDoSDrops = drops
			load.Telemetry = &telemetry
		}
	}
	xdpSource, _ := runtime.xdp.Load().(func(context.Context) *XDPStatusMetrics)
	if xdpSource != nil && load.Telemetry != nil {
		if status := xdpSource(ctx); status != nil && validXDPStatus(status) {
			telemetry := *load.Telemetry
			telemetry.XDP = status
			load.Telemetry = &telemetry
		}
	}
	siteDropSource, _ := runtime.siteDrop.Load().(func(context.Context) *SiteDropMetrics)
	if siteDropSource != nil && load.Telemetry != nil {
		if drop := siteDropSource(ctx); drop != nil && validSiteDrop(drop) {
			telemetry := *load.Telemetry
			telemetry.SiteDrop = drop
			load.Telemetry = &telemetry
		}
	}
	protectionSource, _ := runtime.ddosProtection.Load().(func(context.Context) *DDoSProtectionMetrics)
	if protectionSource != nil && load.Telemetry != nil {
		if status := protectionSource(ctx); status != nil && validDDoSProtection(status) {
			telemetry := *load.Telemetry
			telemetry.DDoSProtection = status
			load.Telemetry = &telemetry
		}
	}
	overrideSource, _ := runtime.portGroupOverrides.Load().(func(context.Context) []PortGroupOverrideMetrics)
	if overrideSource != nil && load.Telemetry != nil {
		if overrides := overrideSource(ctx); len(overrides) > 0 && validPortGroupOverrides(overrides) {
			telemetry := *load.Telemetry
			telemetry.PortGroupOverrides = overrides
			load.Telemetry = &telemetry
		}
	}
	if storageSource, _ := runtime.storage.Load().(func() *StorageMetrics); storageSource != nil && load.Telemetry != nil {
		if storage := storageSource(); storage != nil {
			telemetry := *load.Telemetry
			telemetry.Storage = storage
			load.Telemetry = &telemetry
		}
	}
	return load
}

func NewRuntime(options Options) (*Runtime, error) {
	if !validNodeID(options.NodeID) || options.DefaultPort == 0 || options.Probe == nil {
		return nil, ErrInvalidOptions
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.LoadCollector == nil {
		options.LoadCollector = NewLinuxLoadCollector()
	}
	if err := prepareStateDir(options.StateDir); err != nil {
		return nil, err
	}
	active, err := loadStoredConfig(filepath.Join(options.StateDir, activeFileName))
	if err != nil {
		return nil, err
	}
	lkg, err := loadStoredConfig(filepath.Join(options.StateDir, lkgFileName))
	if err != nil {
		return nil, err
	}
	if active != nil && lkg != nil && lkg.ConfigRevision > active.ConfigRevision {
		return nil, ErrCorruptState
	}
	runtime := &Runtime{
		stateDir: options.StateDir, nodeID: options.NodeID, defaultPort: options.DefaultPort,
		probe: options.Probe, notifier: options.Notifier, now: options.Now, loadCollector: options.LoadCollector,
		active: active, lkg: lkg, healthy: active != nil, changed: make(chan struct{}, 1),
	}
	runtime.wait = func(ctx context.Context, duration time.Duration) error {
		return waitDuration(ctx, duration, runtime.changed)
	}
	return runtime, nil
}

func (runtime *Runtime) Apply(ctx context.Context, payload []byte) (ApplyResult, error) {
	config, err := decodeConfig(payload)
	if err != nil {
		return ApplyResult{}, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.active != nil {
		if config.ConfigRevision < runtime.active.ConfigRevision {
			return ApplyResult{}, ErrConflict
		}
		if config.ConfigRevision == runtime.active.ConfigRevision {
			current, _ := canonicalConfig(*runtime.active)
			candidate, _ := canonicalConfig(config)
			if !bytes.Equal(current, candidate) {
				return ApplyResult{}, ErrConflict
			}
			return ApplyResult{ConfigRevision: config.ConfigRevision, Replayed: true}, nil
		}
	}
	if config.MonitorEnabled == nil || *config.MonitorEnabled {
		if err := runtime.probeForConfig(ctx, config); err != nil {
			return ApplyResult{}, fmt.Errorf("%w: %v", ErrPreflight, err)
		}
	}
	var previous uint64
	if runtime.active != nil {
		previous = runtime.active.ConfigRevision
		if err := storeConfig(runtime.stateDir, lkgFileName, *runtime.active); err != nil {
			return ApplyResult{}, err
		}
	}
	if err := storeConfig(runtime.stateDir, activeFileName, config); err != nil {
		return ApplyResult{}, err
	}
	if runtime.active == nil {
		runtime.lkg = nil
	} else {
		lkg := cloneConfig(*runtime.active)
		runtime.lkg = &lkg
	}
	active := cloneConfig(config)
	runtime.active = &active
	runtime.healthy = true
	runtime.resetDebounce()
	select {
	case runtime.changed <- struct{}{}:
	default:
	}
	return ApplyResult{ConfigRevision: config.ConfigRevision, PreviousRevision: previous}, nil
}

func (runtime *Runtime) RunOnce(ctx context.Context) (MetricReport, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.active == nil {
		return MetricReport{}, ErrNoActiveConfig
	}
	// Apply may disable monitoring after Run selects this iteration.
	if runtime.active.MonitorEnabled != nil && !*runtime.active.MonitorEnabled {
		return MetricReport{}, nil
	}
	config := cloneConfig(*runtime.active)
	port := runtime.port(config)
	probeErr := runtime.probeForConfig(ctx, config)
	now := runtime.now().UTC()
	runtime.probes++
	report := runtime.metric(config.ConfigRevision, port, now)
	if load := runtime.collectLoad(ctx, now); load != nil {
		report.LoadMetrics = load
	}
	if probeErr != nil {
		runtime.probeErrors++
		runtime.recordFailure(now, config)
		if !runtime.healthy && runtime.lkg != nil && runtime.lkg.ConfigRevision < config.ConfigRevision {
			if err := storeConfig(runtime.stateDir, activeFileName, *runtime.lkg); err != nil {
				report = runtime.metric(config.ConfigRevision, port, now)
				return report, fmt.Errorf("%w: %v", ErrRollback, err)
			}
			active := cloneConfig(*runtime.lkg)
			runtime.active = &active
			runtime.healthy = true
			runtime.resetDebounce()
			report.RolledBack = true
		}
		report = runtime.finishMetric(report, config.ConfigRevision, port, now, false)
		return report, probeErr
	}

	recovered := runtime.recordSuccess(now, config)
	notified := false
	if recovered && config.RecoveryNotificationEnabled && runtime.notifier != nil {
		event := RecoveryEvent{NodeID: runtime.nodeID, ConfigRevision: config.ConfigRevision, RecoveredAt: now}
		runtime.pendingRecovery = &event
	}
	if runtime.pendingRecovery != nil && runtime.notifier != nil {
		if err := runtime.notifier.NotifyRecovery(ctx, *runtime.pendingRecovery); err != nil {
			report = runtime.finishMetric(report, config.ConfigRevision, port, now, true)
			report.Recovered = recovered
			return report, err
		}
		runtime.pendingRecovery = nil
		notified = true
	}
	report = runtime.finishMetric(report, config.ConfigRevision, port, now, true)
	report.Recovered = recovered
	report.RecoveryNotified = notified
	return report, nil
}

func (runtime *Runtime) Run(ctx context.Context, sink MetricSink) error {
	if sink == nil {
		return ErrInvalidOptions
	}
	for {
		runtime.mu.Lock()
		select {
		case <-runtime.changed:
		default:
		}
		enabled := runtime.active != nil && (runtime.active.MonitorEnabled == nil || *runtime.active.MonitorEnabled)
		runtime.mu.Unlock()
		var report MetricReport
		if enabled {
			report, _ = runtime.RunOnce(ctx)
		} else {
			now := runtime.now().UTC()
			if load := runtime.collectLoad(ctx, now); load != nil {
				report = MetricReport{SchemaVersion: 1, NodeID: runtime.nodeID, ObservedAt: now,
					AppliedConfigRevision: runtime.Status().ConfigRevision, LoadMetrics: load}
			}
		}
		if report.NodeID != "" {
			if err := sink.ReportNodeMonitoring(ctx, report); err != nil && !errors.Is(err, ErrMetricBackpressure) {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		runtime.mu.Lock()
		interval := 10 * time.Second
		if runtime.active != nil && enabled {
			interval = time.Duration(runtime.active.ProbeIntervalMS) * time.Millisecond
		}
		runtime.mu.Unlock()
		if err := runtime.wait(ctx, interval); err != nil {
			return err
		}
	}
}

func (runtime *Runtime) Status() Status {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.active == nil {
		return Status{}
	}
	return Status{ConfigRevision: runtime.active.ConfigRevision, Healthy: runtime.healthy}
}

func (runtime *Runtime) recordFailure(now time.Time, config Config) {
	runtime.successes = 0
	runtime.recoveryAt = time.Time{}
	if runtime.failures < config.FailureThreshold {
		runtime.failures++
	}
	if runtime.failures < config.FailureThreshold {
		return
	}
	if runtime.failureAt.IsZero() {
		runtime.failureAt = now
	}
	if now.Sub(runtime.failureAt) >= time.Duration(config.FailureDebounceMS)*time.Millisecond {
		runtime.healthy = false
	}
}

func (runtime *Runtime) recordSuccess(now time.Time, config Config) bool {
	runtime.failures = 0
	runtime.failureAt = time.Time{}
	if runtime.healthy {
		runtime.successes = 0
		runtime.recoveryAt = time.Time{}
		return false
	}
	if runtime.successes < config.RecoveryThreshold {
		runtime.successes++
	}
	if runtime.successes < config.RecoveryThreshold {
		return false
	}
	if runtime.recoveryAt.IsZero() {
		runtime.recoveryAt = now
	}
	if now.Sub(runtime.recoveryAt) < time.Duration(config.RecoveryDebounceMS)*time.Millisecond {
		return false
	}
	runtime.healthy = true
	runtime.successes = 0
	runtime.recoveryAt = time.Time{}
	return true
}

func (runtime *Runtime) metric(revision uint64, port uint16, now time.Time) MetricReport {
	return MetricReport{SchemaVersion: 1, ObservedAt: now, NodeID: runtime.nodeID,
		ConfigRevision: revision, ProbeProtocol: "tcp", ProbePort: port}
}

func (runtime *Runtime) finishMetric(report MetricReport, revision uint64, port uint16, now time.Time, success bool) MetricReport {
	report.ObservedAt = now
	report.ConfigRevision = revision
	report.ProbePort = port
	report.ProbeSucceeded = success
	report.Healthy = runtime.healthy
	report.ConsecutiveFailures = runtime.failures
	report.ConsecutiveSuccesses = runtime.successes
	report.ProbesTotal = runtime.probes
	report.ProbeFailuresTotal = runtime.probeErrors
	if runtime.active != nil {
		report.ActiveConfigRevision = runtime.active.ConfigRevision
		report.ProbeProtocol = runtime.active.Protocol
		if report.ProbeProtocol == "" {
			report.ProbeProtocol = "tcp"
		}
	}
	return report
}

func (runtime *Runtime) port(config Config) uint16 {
	if config.MonitorPort != nil {
		return *config.MonitorPort
	}
	if config.PortMode == "custom" {
		return *config.CustomPort
	}
	return runtime.defaultPort
}

func (runtime *Runtime) probeForConfig(ctx context.Context, config Config) error {
	protocol := config.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	timeout := time.Duration(config.ProbeTimeoutMS) * time.Millisecond
	if probe, ok := runtime.probe.(ProtocolProbe); ok {
		return probe.ProbeProtocol(ctx, protocol, runtime.port(config), timeout)
	}
	return runtime.probe.Probe(ctx, runtime.port(config), timeout)
}

func (runtime *Runtime) resetDebounce() {
	runtime.failures = 0
	runtime.successes = 0
	runtime.failureAt = time.Time{}
	runtime.recoveryAt = time.Time{}
	runtime.pendingRecovery = nil
}

func validNodeID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func waitDuration(ctx context.Context, duration time.Duration, changed <-chan struct{}) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	case <-changed:
		return nil
	}
}
