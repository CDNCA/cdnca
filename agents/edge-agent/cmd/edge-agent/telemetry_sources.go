package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4usage"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

const (
	telemetrySourceRegistryName = "telemetry-sources-v1.json"
	telemetrySourceRegistryMax  = 1 << 20
	telemetrySourceLimit        = 4000
)

// l4TelemetryListenerCountBySite counts listeners per telemetry partition;
// since tcp/udp v12 a stream is its own partition (no website).
func l4TelemetryListenerCountBySite(streams []l4runtime.StreamRuntimeSpecV2) map[string]int {
	counts := make(map[string]int)
	for _, stream := range streams {
		counts[stream.StreamID] += 1 + len(stream.AdditionalListeners)
	}
	return counts
}

func l4TelemetrySourcePath(deploymentRoot, configVersionID string, stream l4runtime.StreamRuntimeSpecV2, listenerCountBySite map[string]int) (string, error) {
	path, err := l4runtime.L4TelemetryLogPathForRuntimeStream(deploymentRoot, configVersionID, stream)
	if err != nil {
		return "", err
	}
	if listenerCountBySite[stream.StreamID] != 1 {
		return path, nil
	}
	legacy := l4runtime.L4TelemetryLogPath(deploymentRoot, configVersionID, stream.StreamID, stream.Listener.Port)
	if _, legacyErr := os.Lstat(legacy); legacyErr == nil {
		if _, pathErr := os.Lstat(path); errors.Is(pathErr, os.ErrNotExist) {
			return legacy, nil
		}
	} else if !errors.Is(legacyErr, os.ErrNotExist) {
		return "", legacyErr
	}
	return path, nil
}

func l4TelemetryRegistrations(deploymentRoot, nodeID string, document l4StreamSetV2Document) ([]telemetrySourceRegistration, error) {
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2(document.VersionID, document.Revision, document.Streams, document.SiteSockets...)
	if err != nil {
		return nil, err
	}
	counts := l4TelemetryListenerCountBySite(document.Streams)
	var sources []telemetrySourceRegistration
	for _, stream := range config.Listeners {
		// A composed runtime's streams carry their own scope's release.
		versionID, revision := document.VersionID, document.Revision
		if stream.ConfigVersionID != "" {
			versionID, revision = stream.ConfigVersionID, stream.ConfigRevision
		}
		primary := l4runtime.StreamRuntimeSpecV2{StreamID: stream.StreamID,
			Listener: l4runtime.ListenerSocketV2{Protocol: stream.Protocol, Address: stream.Address, Port: stream.Port}}
		path, err := l4TelemetrySourcePath(deploymentRoot, versionID, primary, counts)
		if err != nil {
			return nil, err
		}
		identity := eventspool.TrustedIdentity{EnrollmentNodeID: nodeID, TenantID: stream.TenantID, SiteID: stream.SiteID,
			ConfigVersionID: versionID, ConfigRevision: uint64(revision), StreamID: stream.StreamID, ListenerID: stream.StreamID,
			PackageSubscriptionID: stream.PackageSubscriptionID}
		sources = append(sources, telemetrySourceRegistration{SourcePath: path, Identity: identity, EventType: eventspool.EventL4Session})
		for _, socket := range stream.AdditionalListeners {
			path, err := l4runtime.L4TelemetryLogPathForIdentity(deploymentRoot, versionID, stream.SiteID, stream.StreamID,
				socket.ID, socket.Protocol, socket.Address, socket.Port)
			if err != nil {
				return nil, err
			}
			identity.ListenerID = socket.ID
			sources = append(sources, telemetrySourceRegistration{SourcePath: path, Identity: identity, EventType: eventspool.EventL4Session})
		}
	}
	return sources, nil
}

type telemetryPrechecker struct {
	deploymentRoot string
	delegate       deployment.Prechecker
	ownerUID       int
	ownerGID       int
}

func newTelemetryPrechecker(deploymentRoot string, delegate deployment.Prechecker) (*telemetryPrechecker, error) {
	if delegate == nil || !absoluteCleanPath(deploymentRoot) {
		return nil, errors.New("telemetry prechecker requires a deployment root and delegate")
	}
	if deploymentRoot == string(filepath.Separator) || rejectSymlinkAncestors(deploymentRoot) != nil {
		return nil, errors.New("telemetry deployment root is unsafe")
	}
	return &telemetryPrechecker{
		deploymentRoot: deploymentRoot, delegate: delegate,
		ownerUID: os.Geteuid(), ownerGID: os.Getegid(),
	}, nil
}

func (p *telemetryPrechecker) Precheck(ctx context.Context, versionID, releasePath string) error {
	realRoot, err := filepath.EvalSymlinks(p.deploymentRoot)
	if err != nil || realRoot == string(filepath.Separator) {
		return errors.New("telemetry deployment root is unsafe")
	}
	manifest, present, err := readTelemetryManifest(releasePath)
	if err != nil {
		return err
	}
	if present {
		if manifest.SourceCapabilities.TaskBinding || manifest.SourceCapabilities.JA4 {
			return errors.New("signed telemetry identity requires unavailable runtime authority")
		}
		cache, cachePresent, cacheErr := readCachePolicyManifest(releasePath)
		if cacheErr != nil {
			return cacheErr
		}
		// The derived release carries a cache identity when a site caches;
		// one it carries must name the same listeners.
		cacheIdentityValid := !cachePresent || edgeconfig.ValidateTelemetryCacheReleaseIdentity(manifest, cache) == nil
		if manifest.ConfigVersionID != versionID || !cacheIdentityValid ||
			edgeconfig.ValidateTelemetryIdentityPaths(manifest, realRoot) != nil {
			return errors.New("signed telemetry identity does not match the staged release")
		}
		for _, site := range manifest.Sites {
			for _, sourcePath := range []string{site.AccessLogPath, site.SecurityLogPath} {
				if err := ensurePrivateTelemetrySource(realRoot, sourcePath, p.ownerUID, p.ownerGID); err != nil {
					return fmt.Errorf("prepare telemetry log source: %w", err)
				}
			}
		}
	}
	// A composed release (multi-tenant node) logs each scope under that
	// scope's own config version, as its signed identity names.
	composed, err := readComposedTelemetryManifests(releasePath)
	if err != nil {
		return err
	}
	for _, scope := range composed {
		if edgeconfig.ValidateTelemetryIdentityPaths(scope, realRoot) != nil {
			return errors.New("composed telemetry identity paths are invalid")
		}
		for _, site := range scope.Sites {
			for _, sourcePath := range []string{site.AccessLogPath, site.SecurityLogPath} {
				if err := ensurePrivateTelemetrySource(realRoot, sourcePath, p.ownerUID, p.ownerGID); err != nil {
					return fmt.Errorf("prepare composed telemetry log source: %w", err)
				}
			}
		}
	}
	l4, l4Present, l4Err := readL4RuntimeDocument(releasePath)
	if l4Err != nil {
		return l4Err
	}
	if l4Present {
		if l4.VersionID != versionID {
			return errors.New("L4 telemetry identity does not match the staged release")
		}
		sources, err := l4TelemetryRegistrations(realRoot, "", l4)
		if err != nil {
			return fmt.Errorf("resolve L4 telemetry log source: %w", err)
		}
		for _, source := range sources {
			if err := ensurePrivateTelemetrySource(realRoot, source.SourcePath, p.ownerUID, p.ownerGID); err != nil {
				return fmt.Errorf("prepare L4 telemetry log source: %w", err)
			}
		}
	}
	return p.delegate.Precheck(ctx, versionID, releasePath)
}

type telemetrySourceConfig struct {
	IndependentMetricsEnabled bool
	DeploymentRoot            string
	SpoolRoot                 string
	FirewallRoot              string
	EnrollmentNodeID          string
	PollInterval              time.Duration
	MaxLineBytes              int
	MaxBatchEvents            int
	MaxQuarantineBytes        int64

	// ComposedCurrent is the composed runtime's current link on a
	// multi-tenant node; its L4 runtime replaces deployment_root/current's.
	ComposedCurrent string

	// DynamicRouting: the node-level access and security logs of the
	// dynamic routing skeleton (D12), each line bound to its site by
	// Resolve (dyntelemetry.Resolver). nil on other nodes.
	DynamicRouting *dynamicRoutingTelemetry
}

type dynamicRoutingTelemetry struct {
	AccessLogPath, SecurityLogPath string
	Resolve                        func([]byte) (eventspool.ResolvedLine, error)
	// Sites and Connections feed the independent connections metrics:
	// the active site listeners and their requests in flight (D13-b2).
	Sites       func() []dynroute.MetricSite
	Connections func(context.Context) ([]dynroute.SiteConnection, [32]byte, error)
	// SubscriptionMinutes moves cdnca_limits' per subscription minutes into
	// the spool (ADR 0012 §6.2); nil disables them.
	SubscriptionMinutes *dyntelemetry.SubscriptionMinutes
}

type telemetrySourceRegistration struct {
	SourcePath    string                     `json:"source_path"`
	Identity      eventspool.TrustedIdentity `json:"identity"`
	CapturePolicy eventspool.CapturePolicy   `json:"capture_policy,omitempty"`
	EventType     eventspool.EventType       `json:"event_type,omitempty"`
}

type telemetrySourceRegistry struct {
	SchemaVersion uint16                        `json:"schema_version"`
	Sources       []telemetrySourceRegistration `json:"sources"`
}

type firewallHitSource interface {
	ReadBatch(context.Context, int) ([]eventspool.Envelope, error)
	Close() error
}

type telemetrySourceRunner struct {
	metrics         *independentMetricsSource
	config          telemetrySourceConfig
	sink            eventspool.BatchSink
	registryPath    string
	stateDir        string
	sources         map[string]telemetrySourceRegistration
	tailers         map[string]*eventspool.Tailer
	shared          []*eventspool.Tailer // dynamic routing node-level logs
	mu              sync.RWMutex
	lastError       string
	firewallHits    firewallHitSource
	firewallPending []eventspool.Envelope
	// tailState: each source's last reported outcome (reportTail); used by
	// the Run goroutine only.
	tailState map[string]string
}

func newTelemetrySourceRunner(config telemetrySourceConfig, sink eventspool.BatchSink) (*telemetrySourceRunner, error) {
	if sink == nil || !absoluteCleanPath(config.DeploymentRoot) || !absoluteCleanPath(config.SpoolRoot) ||
		config.DeploymentRoot == string(filepath.Separator) || config.SpoolRoot == string(filepath.Separator) ||
		config.PollInterval <= 0 || config.MaxLineBytes < 256 || config.MaxLineBytes > 1<<20 ||
		config.MaxBatchEvents < 1 || config.MaxBatchEvents > 10000 ||
		config.MaxQuarantineBytes < 64<<10 || config.MaxQuarantineBytes > 1<<30 {
		return nil, errors.New("invalid telemetry source configuration")
	}
	nodeID, err := uuid.Parse(config.EnrollmentNodeID)
	if err != nil {
		return nil, errors.New("invalid telemetry enrollment node identity")
	}
	config.EnrollmentNodeID = strings.ToLower(nodeID.String())
	config.DeploymentRoot, err = filepath.EvalSymlinks(config.DeploymentRoot)
	if err != nil {
		return nil, errors.New("resolve telemetry deployment root")
	}
	config.SpoolRoot, err = filepath.EvalSymlinks(config.SpoolRoot)
	if err != nil {
		return nil, errors.New("resolve telemetry spool root")
	}
	stateDir := filepath.Join(config.SpoolRoot, "tail-state")
	if err := ensurePrivateDirectory(config.SpoolRoot, stateDir); err != nil {
		return nil, fmt.Errorf("prepare telemetry tail state: %w", err)
	}
	runner := &telemetrySourceRunner{
		config: config, sink: sink, registryPath: filepath.Join(config.SpoolRoot, "state", telemetrySourceRegistryName),
		stateDir: stateDir, sources: make(map[string]telemetrySourceRegistration), tailers: make(map[string]*eventspool.Tailer),
		tailState: make(map[string]string),
	}
	if err := runner.loadRegistry(); err != nil {
		return nil, err
	}
	if shared := config.DynamicRouting; shared != nil {
		for _, path := range []string{shared.AccessLogPath, shared.SecurityLogPath} {
			tailer, err := eventspool.NewTailer(eventspool.TailConfig{
				SourcePath: path, StateDir: stateDir, Identity: eventspool.TrustedIdentity{EnrollmentNodeID: config.EnrollmentNodeID},
				MaxLineBytes: config.MaxLineBytes, MaxBatchEvents: config.MaxBatchEvents,
				MaxQuarantineBytes: config.MaxQuarantineBytes, Resolve: shared.Resolve,
			})
			if err != nil {
				return nil, fmt.Errorf("dynamic routing telemetry source %s: %w", filepath.Base(path), err)
			}
			runner.shared = append(runner.shared, tailer)
		}
	}
	if config.IndependentMetricsEnabled {
		metrics, err := newIndependentMetricsSource(config, sink)
		if err != nil {
			return nil, err
		}
		runner.metrics = metrics
	}
	return runner, nil
}

func (r *telemetrySourceRunner) Run(ctx context.Context) error {
	defer func() {
		if r.firewallHits != nil {
			_ = r.firewallHits.Close()
		}
	}()
	for {
		err := r.syncOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.setError(err)
		timer := time.NewTimer(r.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (r *telemetrySourceRunner) syncOnce(ctx context.Context) error {
	if err := r.observeActive(); err != nil {
		if r.metrics != nil {
			r.metrics.invalidate()
		}
		return err
	}
	paths := make([]string, 0, len(r.sources))
	for path := range r.sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var firstError error
	accessHealthy := true
	expired := 0
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		tailer, err := r.tailer(r.sources[path])
		if err == nil {
			var result eventspool.TailResult
			result, err = tailer.TailOnce(ctx, r.sink)
			r.reportTail(tailer, result, err)
			expired += result.ExpiredEvents
			if result.QuarantinedLines > 0 || result.SampledEvents > 0 || result.ExpiredEvents > 0 || len(result.Issues) > 0 {
				accessHealthy = false
			}
		} else {
			r.reportSource(path, err)
		}
		if err != nil {
			accessHealthy = false
		}
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	for _, tailer := range r.shared {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := tailer.TailOnce(ctx, r.sink)
		if !errors.Is(err, os.ErrNotExist) {
			r.reportTail(tailer, result, err)
		}
		expired += result.ExpiredEvents
		if err != nil || result.QuarantinedLines > 0 || result.SampledEvents > 0 || result.ExpiredEvents > 0 || len(result.Issues) > 0 {
			accessHealthy = false
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstError == nil {
			firstError = err
		}
	}
	if r.metrics != nil {
		var err error
		if r.config.DynamicRouting != nil && len(r.shared) > 0 {
			err = r.metrics.collectDynamicRouting(ctx, r.shared[0], accessHealthy)
		} else {
			err = r.metrics.collect(ctx, r.tailers, accessHealthy)
		}
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	if err := r.syncFirewallHits(ctx); err != nil && firstError == nil {
		firstError = err
	}
	if shared := r.config.DynamicRouting; shared != nil && shared.SubscriptionMinutes != nil {
		if err := shared.SubscriptionMinutes.Sync(ctx, r.sink, r.config.MaxBatchEvents); err != nil && firstError == nil {
			firstError = err
		}
	}
	if firstError == nil && expired > 0 {
		// The tail moved past them; report the loss for this round.
		firstError = errTelemetryEventsExpired
	}
	return firstError
}

// errTelemetryEventsExpired: log lines older than the spool hard age limit
// (a node offline longer than that) were skipped and counted
// (eventspool Stats.ExpiredEvents) instead of stopping the tail.
var errTelemetryEventsExpired = errors.New("telemetry source skipped events past the spool hard age limit")

func (r *telemetrySourceRunner) syncFirewallHits(ctx context.Context) error {
	if r.firewallHits == nil {
		if runtime.GOOS != "linux" || r.config.FirewallRoot == "" {
			return nil
		}
		source, err := firewall.NewKernelHitSource(r.config.FirewallRoot, "/dev/kmsg", r.config.EnrollmentNodeID, time.Now)
		if err != nil {
			return err
		}
		r.firewallHits = source
	}
	if len(r.firewallPending) == 0 {
		events, err := r.firewallHits.ReadBatch(ctx, r.config.MaxBatchEvents)
		if len(events) > 0 {
			r.firewallPending = r.bindFirewallHits(events)
		}
		if err != nil || len(r.firewallPending) == 0 {
			return err
		}
	}
	if _, err := r.sink.AppendBatch(ctx, r.firewallPending); err != nil {
		return err
	}
	r.firewallPending = nil
	return nil
}

// bindFirewallHits gives each kernel hit its site's telemetry identity. The
// firewall command names the configuration scope (access_scopes.id) and its
// own runtime version; the gateway accepts a security event only under the
// tenant (tenants.id) and a published config version of its site, and
// rejects the whole batch otherwise, which would hold every later event in
// the spool. A hit whose site has no active telemetry identity is dropped.
func (r *telemetrySourceRunner) bindFirewallHits(events []eventspool.Envelope) []eventspool.Envelope {
	identities := r.firewallHitIdentities()
	bound := make([]eventspool.Envelope, 0, len(events))
	for _, event := range events {
		identity, ok := identities[event.SiteID]
		if !ok {
			continue
		}
		event.TenantID, event.ConfigVersionID = identity.TenantID, identity.ConfigVersionID
		bound = append(bound, event)
	}
	if dropped := len(events) - len(bound); dropped > 0 {
		slog.Warn("global firewall hits dropped: site has no active telemetry identity", "dropped", dropped)
	}
	return bound
}

// firewallHitIdentities: site ID -> the tenant and config version of its
// active telemetry sources (signed manifests and L4 runtime) or, on a
// dynamic routing node, of its site object. Sources are visited in path
// order so a site published under two versions maps deterministically.
func (r *telemetrySourceRunner) firewallHitIdentities() map[string]eventspool.TrustedIdentity {
	identities := make(map[string]eventspool.TrustedIdentity)
	paths := make([]string, 0, len(r.sources))
	for path := range r.sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		identity := r.sources[path].Identity
		if _, ok := identities[identity.SiteID]; !ok {
			identities[identity.SiteID] = eventspool.TrustedIdentity{TenantID: identity.TenantID, SiteID: identity.SiteID,
				ConfigVersionID: identity.ConfigVersionID}
		}
	}
	if shared := r.config.DynamicRouting; shared != nil && shared.Sites != nil {
		for _, site := range shared.Sites() {
			if _, ok := identities[site.SiteID]; !ok {
				identities[site.SiteID] = eventspool.TrustedIdentity{TenantID: site.TenantID, SiteID: site.SiteID,
					ConfigVersionID: site.ConfigVersionID}
			}
		}
	}
	return identities
}

func (r *telemetrySourceRunner) ErrorCode() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastError
}

// reportTail logs a source's outcome when it changes (N11: a tail that
// stopped used to leave no trace): a failure, the first issue of a round
// (quarantined, not ready, rotation) with its offset, and the recovery.
func (r *telemetrySourceRunner) reportTail(tailer *eventspool.Tailer, result eventspool.TailResult, err error) {
	path := tailer.SourcePath()
	state := ""
	switch {
	case err != nil:
		state = "error:" + err.Error()
	case len(result.Issues) > 0:
		state = fmt.Sprintf("%s@%d", result.Issues[0].Code, result.Issues[0].Offset)
	}
	previous := r.tailState[path]
	if state == previous {
		return
	}
	r.tailState[path] = state
	generation, offset := tailer.Position()
	switch {
	case err != nil:
		slog.Error("telemetry source stalled", "source", path, "generation", generation, "offset", offset,
			"appended", result.AppendedEvents, "error", err)
	case state != "":
		issue := result.Issues[0]
		slog.Warn("telemetry source issue", "source", path, "generation", generation, "offset", offset,
			"issue", issue.Code, "issue_offset", issue.Offset, "issues", len(result.Issues),
			"quarantined", result.QuarantinedLines, "appended", result.AppendedEvents)
	default:
		slog.Info("telemetry source recovered", "source", path, "generation", generation, "offset", offset,
			"appended", result.AppendedEvents, "previous", previous)
	}
}

// reportSource logs a registered source whose tailer cannot be built.
func (r *telemetrySourceRunner) reportSource(path string, err error) {
	state := "error:" + err.Error()
	if r.tailState[path] == state {
		return
	}
	r.tailState[path] = state
	slog.Error("telemetry source unavailable", "source", path, "error", err)
}

func (r *telemetrySourceRunner) setError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := r.lastError
	defer func() {
		switch {
		case r.lastError == previous:
		case r.lastError == "":
			slog.Info("telemetry sources recovered", "previous_code", previous)
		default:
			slog.Warn("telemetry sources degraded", "code", r.lastError, "error", err)
		}
	}()
	if err == nil {
		r.lastError = ""
		return
	}
	switch {
	case errors.Is(err, eventspool.ErrBackpressure), errors.Is(err, eventspool.ErrHardLimit), errors.Is(err, eventspool.ErrTenantLimit):
		r.lastError = "TELEMETRY_SOURCE_BACKPRESSURE"
	case errors.Is(err, errTelemetryEventsExpired):
		r.lastError = "TELEMETRY_SOURCE_EVENTS_EXPIRED"
	case errors.Is(err, eventspool.ErrQuarantineLimit):
		r.lastError = "TELEMETRY_SOURCE_QUARANTINE_FULL"
	default:
		r.lastError = "TELEMETRY_SOURCE_UNAVAILABLE"
	}
}

func (r *telemetrySourceRunner) observeActive() error {
	manifest, present, err := readActiveTelemetryManifest(r.config.DeploymentRoot)
	if err != nil {
		return err
	}
	manifests := []edgeconfig.TelemetryIdentityManifest{}
	if present {
		manifests = append(manifests, manifest)
	}
	// A multi-tenant node serves its websites from the composed release; each
	// scope's sources are named by that scope's signed identity.
	if r.config.ComposedCurrent != "" {
		composed, err := readActiveComposedTelemetryManifests(r.config.ComposedCurrent)
		if err != nil {
			return err
		}
		manifests = composed
	}
	desired := make(map[string]telemetrySourceRegistration)
	for _, manifest := range manifests {
		if edgeconfig.ValidateTelemetryIdentityPaths(manifest, r.config.DeploymentRoot) != nil {
			return errors.New("active telemetry identity paths are invalid")
		}
		for index, site := range manifest.Sites {
			capturePolicy, err := eventspoolCapturePolicy(manifest.CapturePolicy.Sites[index])
			if err != nil {
				return err
			}
			identity := eventspool.TrustedIdentity{
				ListenPort:       site.ListenPort,
				EnrollmentNodeID: r.config.EnrollmentNodeID, TenantID: manifest.TenantID,
				SiteID: site.SiteID, ConfigVersionID: manifest.ConfigVersionID,
				CapturePolicyRevision: manifest.CapturePolicy.Sites[index].Revision,
				CapturePolicyDigest:   manifest.CapturePolicy.Sites[index].EvidenceDigest,
			}
			for _, registration := range []telemetrySourceRegistration{
				{SourcePath: site.AccessLogPath, Identity: identity, CapturePolicy: capturePolicy},
				{SourcePath: site.SecurityLogPath, Identity: identity, CapturePolicy: capturePolicy},
			} {
				if existing, ok := desired[registration.SourcePath]; ok && !sameTelemetryRegistration(existing, registration) {
					return errors.New("active telemetry source paths conflict")
				}
				desired[registration.SourcePath] = registration
			}
		}
	}
	l4, l4Present, l4Err := readActiveL4RuntimeDocument(r.config.DeploymentRoot)
	if r.config.ComposedCurrent != "" {
		l4, l4Present, l4Err = readComposedL4RuntimeDocument(r.config.ComposedCurrent)
	}
	if l4Err != nil {
		return l4Err
	}
	if l4Present {
		sources, err := l4TelemetryRegistrations(r.config.DeploymentRoot, r.config.EnrollmentNodeID, l4)
		if err != nil {
			return err
		}
		for _, registration := range sources {
			if existing, ok := desired[registration.SourcePath]; ok && !sameTelemetryRegistration(existing, registration) {
				return errors.New("active telemetry source paths conflict")
			}
			desired[registration.SourcePath] = registration
		}
	}
	if len(desired) > telemetrySourceLimit {
		return errors.New("telemetry source registration limit reached")
	}
	upgradedLegacy := false
	for path, existing := range r.sources {
		if registration, ok := desired[path]; ok && !sameTelemetryRegistration(existing, registration) {
			legacy := registration
			legacy.Identity.ListenPort = 0
			if existing.Identity.ListenPort == 0 && registration.Identity.ListenPort > 0 && sameTelemetryRegistration(existing, legacy) {
				r.sources[path] = registration
				delete(r.tailers, path)
				upgradedLegacy = true
				continue
			}
			return errors.New("active telemetry source identity conflicts with persisted registration")
		}
	}
	changed := upgradedLegacy || len(r.sources) != len(desired)
	for path := range r.sources {
		if _, ok := desired[path]; !ok {
			delete(r.sources, path)
			delete(r.tailers, path)
		}
	}
	for path, registration := range desired {
		if _, ok := r.sources[path]; ok {
			continue
		}
		if _, err := r.tailer(registration); err != nil {
			return err
		}
		r.sources[path] = registration
		changed = true
	}
	if changed {
		return r.saveRegistry()
	}
	return nil
}

func (r *telemetrySourceRunner) tailer(registration telemetrySourceRegistration) (*eventspool.Tailer, error) {
	if tailer := r.tailers[registration.SourcePath]; tailer != nil {
		return tailer, nil
	}
	if err := validateTelemetryRegistration(r.config, registration); err != nil {
		return nil, err
	}
	tailer, err := eventspool.NewTailer(eventspool.TailConfig{
		SourcePath: registration.SourcePath, StateDir: r.stateDir, Identity: registration.Identity,
		MaxLineBytes: r.config.MaxLineBytes, MaxBatchEvents: r.config.MaxBatchEvents,
		MaxQuarantineBytes: r.config.MaxQuarantineBytes, CapturePolicy: registration.CapturePolicy,
		EventType: registration.EventType,
	})
	if err != nil {
		return nil, err
	}
	r.tailers[registration.SourcePath] = tailer
	return tailer, nil
}

func (r *telemetrySourceRunner) loadRegistry() error {
	content, present, err := readPrivateFile(r.registryPath, telemetrySourceRegistryMax)
	if err != nil || !present {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var registry telemetrySourceRegistry
	if err := decoder.Decode(&registry); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		registry.SchemaVersion != 1 || len(registry.Sources) > telemetrySourceLimit {
		return errors.New("telemetry source registry is corrupt")
	}
	for index, registration := range registry.Sources {
		if index > 0 && registry.Sources[index-1].SourcePath >= registration.SourcePath ||
			validateTelemetryRegistration(r.config, registration) != nil {
			return errors.New("telemetry source registry is corrupt")
		}
		if _, err := r.tailer(registration); err != nil {
			return fmt.Errorf("restore telemetry source: %w", err)
		}
		r.sources[registration.SourcePath] = registration
	}
	return nil
}

func (r *telemetrySourceRunner) saveRegistry() error {
	sources := make([]telemetrySourceRegistration, 0, len(r.sources))
	for _, registration := range r.sources {
		sources = append(sources, registration)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].SourcePath < sources[j].SourcePath })
	content, err := json.Marshal(telemetrySourceRegistry{SchemaVersion: 1, Sources: sources})
	if err != nil || len(content) > telemetrySourceRegistryMax {
		return errors.New("encode telemetry source registry")
	}
	content = append(content, '\n')
	return writePrivateFileAtomic(r.registryPath, content)
}

type telemetryPipeline struct {
	worker      telemetryRunner
	sources     *telemetrySourceRunner
	connections *telemetryclient.Worker
	// spool: its Stats (pending events) for the cross-process telemetry e2e.
	spool *eventspool.Spool
	// l4Usage writes in-progress L4 session checkpoints into l4UsageSink
	// every minute (L4-USAGE-01); nil off Linux.
	l4Usage     *l4usage.Ledger
	l4UsageSink eventspool.BatchSink
}

func (p *telemetryPipeline) Run(ctx context.Context) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	count := 2
	if p.connections != nil {
		count++
	}
	if p.l4Usage != nil {
		count++
	}
	completed := make(chan error, count)
	go func() { completed <- p.worker.Run(child) }()
	go func() { completed <- p.sources.Run(child) }()
	if p.connections != nil {
		go func() { completed <- p.connections.RunConnections(child) }()
	}
	if p.l4Usage != nil {
		go func() {
			completed <- p.l4Usage.Run(child, p.l4UsageSink, func(err error) {
				if err != nil {
					// the next round retries (pending checkpoints first)
					slog.Warn("L4 usage checkpoint failed", "error", err)
				}
			})
		}()
	}
	first := <-completed
	if ctx.Err() == nil {
		// One component ending stops the others (the tail included): say so.
		slog.Error("telemetry pipeline component exited; stopping telemetry", "error", first)
	}
	cancel()
	for i := 1; i < count; i++ {
		if err := <-completed; first == nil && err != nil && !errors.Is(err, context.Canceled) {
			first = err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first != nil {
		return first
	}
	return errors.New("telemetry pipeline exited unexpectedly")
}

func (p *telemetryPipeline) Snapshot() telemetryclient.WorkerSnapshot {
	snapshot := p.worker.Snapshot()
	if p.connections != nil {
		connections := p.connections.Snapshot()
		snapshot.Running = snapshot.Running && connections.Running
		if connections.Degraded {
			snapshot.Degraded = true
			snapshot.LastErrorCode = connections.LastErrorCode
		}
	}
	if code := p.sources.ErrorCode(); code != "" {
		snapshot.Degraded = true
		snapshot.LastErrorCode = code
	}
	return snapshot
}

func readActiveTelemetryManifest(deploymentRoot string) (edgeconfig.TelemetryIdentityManifest, bool, error) {
	current := filepath.Join(deploymentRoot, "current")
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		return edgeconfig.TelemetryIdentityManifest{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return edgeconfig.TelemetryIdentityManifest{}, false, errors.New("active release pointer is invalid")
	}
	target, err := os.Readlink(current)
	if err != nil || filepath.Dir(target) != "releases" || !validTelemetryReleaseDigest(filepath.Base(target)) {
		return edgeconfig.TelemetryIdentityManifest{}, false, errors.New("active release pointer target is invalid")
	}
	return readTelemetryManifest(filepath.Join(deploymentRoot, target))
}

// readActiveComposedTelemetryManifests reads the scope identities of the
// composed release a multi-tenant node runs (the removed v7 composed runtime's composed-current).
func readActiveComposedTelemetryManifests(current string) ([]edgeconfig.TelemetryIdentityManifest, error) {
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return nil, errors.New("composed release pointer is invalid")
	}
	target, err := os.Readlink(current)
	if err != nil || filepath.Dir(target) != "composed-releases" || !validTelemetryReleaseDigest(filepath.Base(target)) {
		return nil, errors.New("composed release pointer target is invalid")
	}
	return readComposedTelemetryManifests(filepath.Join(filepath.Dir(current), target))
}

// composedTelemetryIdentityDir holds a composed release's scope telemetry
// identities, one <scope>.json each.
const composedTelemetryIdentityDir = "telemetry/scopes"

// readComposedTelemetryManifests reads a composed release's scope telemetry
// identities (composedTelemetryIdentityDir), ordered by scope; none for a
// single-scope release.
func readComposedTelemetryManifests(releasePath string) ([]edgeconfig.TelemetryIdentityManifest, error) {
	directory := filepath.Join(releasePath, filepath.FromSlash(composedTelemetryIdentityDir))
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("composed telemetry identities are unreadable")
	}
	if len(entries) > telemetrySourceLimit {
		return nil, errors.New("composed telemetry identity limit reached")
	}
	manifests := make([]edgeconfig.TelemetryIdentityManifest, 0, len(entries))
	for _, entry := range entries {
		scopeID, found := strings.CutSuffix(entry.Name(), ".json")
		if !found || uuid.Validate(scopeID) != nil || uuid.MustParse(scopeID).String() != scopeID || !entry.Type().IsRegular() {
			return nil, errors.New("composed telemetry identity name is invalid")
		}
		content, present, err := readPrivateFile(filepath.Join(directory, entry.Name()), 1<<20)
		if err != nil || !present {
			return nil, errors.New("composed telemetry identity is unreadable")
		}
		manifest, err := edgeconfig.ParseTelemetryIdentityManifest(content)
		if err != nil {
			return nil, errors.New("composed telemetry identity is invalid")
		}
		manifests = append(manifests, manifest)
	}
	return manifests, nil
}

func readTelemetryManifest(releasePath string) (edgeconfig.TelemetryIdentityManifest, bool, error) {
	content, present, err := readPrivateFile(filepath.Join(releasePath, filepath.FromSlash(edgeconfig.TelemetryIdentityManifestPath)), 1<<20)
	if err != nil || !present {
		return edgeconfig.TelemetryIdentityManifest{}, present, err
	}
	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(content)
	if err != nil {
		return edgeconfig.TelemetryIdentityManifest{}, true, errors.New("signed telemetry identity is invalid")
	}
	return manifest, true, nil
}

func readCachePolicyManifest(releasePath string) (edgeconfig.CachePolicyManifest, bool, error) {
	content, present, err := readPrivateFile(filepath.Join(releasePath, filepath.FromSlash(edgeconfig.CachePolicyManifestPath)), 1<<20)
	if err != nil || !present {
		return edgeconfig.CachePolicyManifest{}, present, err
	}
	manifest, err := edgeconfig.ParseCachePolicyManifest(content)
	if err != nil {
		return edgeconfig.CachePolicyManifest{}, true, errors.New("signed cache identity is invalid")
	}
	return manifest, true, nil
}

func ensurePrivateTelemetrySource(deploymentRoot, sourcePath string, ownerUID, ownerGID int) error {
	expectedRoot := filepath.Join(deploymentRoot, "shared", "telemetry")
	if !absoluteCleanPath(sourcePath) || !pathWithin(expectedRoot, sourcePath) {
		return errors.New("telemetry source leaves the deployment telemetry root")
	}
	if err := ensurePrivateDirectoryForOwner(deploymentRoot, filepath.Dir(sourcePath), ownerUID, ownerGID); err != nil {
		return err
	}
	file, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	validationErr := validatePrivateTelemetrySourceFile(file, ownerUID, ownerGID)
	closeErr := file.Close()
	if validationErr != nil {
		return validationErr
	}
	if closeErr != nil {
		return errors.New("inspect telemetry source")
	}
	return nil
}

func validatePrivateTelemetrySourceFile(file *os.File, ownerUID, ownerGID int) error {
	if file == nil {
		return errors.New("inspect telemetry source")
	}
	info, err := file.Stat()
	if err != nil {
		return errors.New("inspect telemetry source")
	}
	return validatePrivateTelemetrySourceInfo(info, ownerUID, ownerGID)
}

func validatePrivateTelemetrySourceInfo(info os.FileInfo, ownerUID, ownerGID int) error {
	stat, ok := infoSyscall(info)
	if !ok || ownerUID < 0 || ownerGID < 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 ||
		stat.Uid != uint32(ownerUID) || stat.Gid != uint32(ownerGID) {
		return errors.New("telemetry source must be a private single-link regular file")
	}
	return nil
}

func ensurePrivateDirectory(root, target string) error {
	return ensurePrivateDirectoryForOwner(root, target, os.Geteuid(), os.Getegid())
}

func ensurePrivateDirectoryForOwner(root, target string, ownerUID, ownerGID int) error {
	if !absoluteCleanPath(root) || !absoluteCleanPath(target) || !pathWithin(root, target) {
		return errors.New("private directory leaves its root")
	}
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	current := root
	info, err := os.Lstat(current)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 ||
		requirePrivateDirectoryOwner(info, ownerUID, ownerGID) != nil {
		return errors.New("telemetry root must be a private real directory")
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 ||
			requirePrivateDirectoryOwner(info, ownerUID, ownerGID) != nil {
			return errors.New("telemetry directory must be a private real directory")
		}
	}
	return nil
}

func requirePrivateDirectoryOwner(info os.FileInfo, ownerUID, ownerGID int) error {
	stat, ok := infoSyscall(info)
	if !ok || ownerUID < 0 || ownerGID < 0 || stat.Uid != uint32(ownerUID) || stat.Gid != uint32(ownerGID) {
		return errors.New("telemetry directory owner is invalid")
	}
	return nil
}

func validateTelemetryRegistration(config telemetrySourceConfig, registration telemetrySourceRegistration) error {
	identity := registration.Identity
	if identity.EnrollmentNodeID != config.EnrollmentNodeID || uuid.Validate(identity.TenantID) != nil || uuid.Validate(identity.SiteID) != nil ||
		!l4runtime.IsSafeTelemetryPathComponent(identity.ConfigVersionID) ||
		!validTelemetryCaptureIdentity(identity.CapturePolicyRevision, identity.CapturePolicyDigest) {
		return errors.New("telemetry source identity is invalid")
	}
	directory := filepath.Join(config.DeploymentRoot, "shared", "telemetry", identity.ConfigVersionID, identity.SiteID)
	relative, err := filepath.Rel(directory, registration.SourcePath)
	parts := strings.Split(filepath.ToSlash(relative), "/")
	port := uint64(0)
	if len(parts) == 2 {
		port, err = strconv.ParseUint(parts[0], 10, 16)
	}
	if err != nil || len(parts) != 2 || port == 0 || strconv.FormatUint(port, 10) != parts[0] ||
		(parts[1] != "access.jsonl" && parts[1] != "security.jsonl" && parts[1] != "l4.jsonl" &&
			!l4runtime.IsL4TelemetryLogNameForIdentity(parts[1], identity.StreamID, identity.ListenerID)) ||
		!validTelemetrySourceCapturePolicy(registration.CapturePolicy) {
		return errors.New("telemetry source path is not bound to its identity")
	}
	if parts[1] == "l4.jsonl" || l4runtime.IsL4TelemetryLogNameForIdentity(parts[1], identity.StreamID, identity.ListenerID) {
		if registration.EventType != eventspool.EventL4Session || uuid.Validate(identity.StreamID) != nil {
			return errors.New("L4 telemetry source identity is invalid")
		}
	}
	return nil
}

func readL4RuntimeDocument(releasePath string) (l4StreamSetV2Document, bool, error) {
	content, present, err := readPrivateFile(filepath.Join(releasePath, filepath.FromSlash(edgeconfig.L4RuntimeV2ArtifactPath)), 1<<20)
	if err != nil || !present {
		return l4StreamSetV2Document{}, present, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document l4StreamSetV2Document
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF || document.SchemaVersion != l4StreamSetV2Schema || document.VersionID == "" || document.Revision < 1 || len(document.Streams) == 0 {
		return l4StreamSetV2Document{}, true, errors.New("L4 runtime telemetry document is invalid")
	}
	if _, err := l4runtime.AggregateStreamRuntimeSpecsV2(document.VersionID, document.Revision, document.Streams, document.SiteSockets...); err != nil {
		return l4StreamSetV2Document{}, true, errors.New("L4 runtime telemetry document is invalid")
	}
	return document, true, nil
}

func readActiveL4RuntimeDocument(deploymentRoot string) (l4StreamSetV2Document, bool, error) {
	current := filepath.Join(deploymentRoot, "current")
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		return l4StreamSetV2Document{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return l4StreamSetV2Document{}, false, errors.New("active release pointer is invalid")
	}
	target, err := os.Readlink(current)
	if err != nil || filepath.Dir(target) != "releases" || !validTelemetryReleaseDigest(filepath.Base(target)) {
		return l4StreamSetV2Document{}, false, errors.New("active release pointer target is invalid")
	}
	return readL4RuntimeDocument(filepath.Join(deploymentRoot, target))
}

// readComposedL4RuntimeDocument reads the L4 runtime of the composed release
// a multi-tenant node runs (the removed v7 composed runtime's composed-current).
func readComposedL4RuntimeDocument(current string) (l4StreamSetV2Document, bool, error) {
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		return l4StreamSetV2Document{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return l4StreamSetV2Document{}, false, errors.New("composed release pointer is invalid")
	}
	target, err := os.Readlink(current)
	if err != nil || filepath.Dir(target) != "composed-releases" || !validTelemetryReleaseDigest(filepath.Base(target)) {
		return l4StreamSetV2Document{}, false, errors.New("composed release pointer target is invalid")
	}
	return readL4RuntimeDocument(filepath.Join(filepath.Dir(current), target))
}

func validTelemetryCaptureIdentity(revision uint64, digest string) bool {
	if revision == 0 || digest == "" {
		return revision == 0 && digest == ""
	}
	if revision > 1<<53-1 || len(digest) != 64 {
		return false
	}
	for _, character := range digest {
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func eventspoolCapturePolicy(policy edgeconfig.TelemetrySiteCapturePolicy) (eventspool.CapturePolicy, error) {
	if !policy.Enabled {
		return eventspool.CapturePolicy{}, nil
	}
	result := eventspool.CapturePolicy{
		Enabled:             true,
		Methods:             cloneTelemetryCaptureValues(policy.Methods),
		URIPrefixes:         cloneTelemetryCaptureValues(policy.URIPrefixes),
		RequestHeaders:      cloneTelemetryCaptureValues(policy.RequestHeaderAllowlist),
		ResponseHeaders:     cloneTelemetryCaptureValues(policy.ResponseHeaderAllowlist),
		RequestBodyFields:   cloneTelemetryCaptureValues(policy.RequestBodyFieldAllowlist),
		ResponseBodyFields:  cloneTelemetryCaptureValues(policy.ResponseBodyFieldAllowlist),
		MaxHeaderValueBytes: policy.MaxValueBytes, MaxBodyBytes: policy.MaxBodyBytes, MaxEventBytes: policy.MaxEventBytes,
	}
	if !validTelemetrySourceCapturePolicy(result) {
		return eventspool.CapturePolicy{}, errors.New("signed telemetry capture policy is invalid")
	}
	return result, nil
}

func cloneTelemetryCaptureValues(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func validTelemetrySourceCapturePolicy(policy eventspool.CapturePolicy) bool {
	if !policy.Enabled {
		return len(policy.Methods) == 0 && len(policy.URIPrefixes) == 0 && len(policy.RequestHeaders) == 0 && len(policy.ResponseHeaders) == 0 &&
			len(policy.RequestBodyFields) == 0 && len(policy.ResponseBodyFields) == 0 &&
			policy.MaxHeaderValueBytes == 0 && policy.MaxBodyBytes == 0 && policy.MaxEventBytes == 0
	}
	return policy.MaxHeaderValueBytes >= 1 && policy.MaxHeaderValueBytes <= 16<<10 &&
		policy.MaxBodyBytes >= 1 && policy.MaxBodyBytes <= 1<<20 && policy.MaxEventBytes >= 256 && policy.MaxEventBytes <= 1<<20 &&
		len(policy.Methods) <= 128 && len(policy.URIPrefixes) <= 128 && len(policy.RequestHeaders) <= 128 && len(policy.ResponseHeaders) <= 128 &&
		len(policy.RequestBodyFields) <= 128 && len(policy.ResponseBodyFields) <= 128
}

func sameTelemetryRegistration(left, right telemetrySourceRegistration) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

var readPrivateOpen = func(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func readPrivateFile(path string, maximum int64) ([]byte, bool, error) {
	file, err := readPrivateOpen(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSyscall(info)
	if err != nil || !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || info.Size() > maximum {
		return nil, false, errors.New("private telemetry file is unsafe")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, false, errors.New("read private telemetry file")
	}
	return content, true, nil
}

func writePrivateFileAtomic(path string, content []byte) error {
	directory := filepath.Dir(path)
	directoryInfo, err := os.Lstat(directory)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 {
		return errors.New("telemetry registry directory is unsafe")
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("telemetry registry target is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".telemetry-sources-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func validTelemetryReleaseDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func pathWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func infoSyscall(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
