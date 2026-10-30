package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// dynamicRoutingManager is the deployment manager of a dynamic routing node:
// each scope's last release (site objects, referenced objects, CRS files) is
// kept by digest under <state>/scopes, and every apply or rollback merges all
// scopes into one dynroute.Runtime.Apply. It answers the gateway client's
// deployment manager questions (scope pointers, results by deployment) from
// its own journal; there is no bundle and no deployment.Manager.
type dynamicRoutingManager struct {
	runtime *dynroute.Runtime
	objects *objectstore.Store
	root    string
	now     func() time.Time
	// remaining counts the still running workers of a reload's replaced
	// set (dynroute.Runtime.RemainingWorkers; tests override it).
	remaining func([]string) int

	mu sync.Mutex
	// indexRoots/siteScopes: ScopeForSite's index and the current roots it
	// was built from.
	indexRoots map[string]string
	siteScopes map[string]string

	// adaptive is the adaptive WAF (ADR 0011 RI-04; nil without the local
	// auto defense runtime): its node exclusion hooks go into the input, the
	// applied managed WAF sites go to it.
	adaptive dynamicRoutingAdaptive

	// apply and activeVersion are the runtime's Apply and ScopeVersion
	// (tests replace them).
	apply         func(context.Context, dynroute.Input) (dynroute.Result, error)
	activeVersion func(scopeID string) string
}

// dynamicRoutingAdaptive is wafadaptAssembly's side the manager uses.
type dynamicRoutingAdaptive interface {
	NodeTargets() map[string][]edgeconfig.DynamicWAFTarget
	Applied(input dynroute.Input, probe *dynwaf.Probe)
}

// dynamicRoutingScope is one scope's journal (<root>/<scope>.json).
type dynamicRoutingScope struct {
	Current  *dynamicRoutingRelease `json:"current,omitempty"`
	Previous *dynamicRoutingRelease `json:"previous,omitempty"`
	// Results: the last results by deployment ID (bounded).
	Results []dynamicRoutingResult `json:"results"`
	// Accepted is the newest release an apply activated: its source revision
	// is the scope's high-water mark (DYNROUTE-LATE-APPLY-REVISION-01). An
	// explicit rollback runs older content but keeps the mark; an apply below
	// it, or at it with another root, is refused before activation.
	Accepted *dynamicRoutingAccepted `json:"accepted,omitempty"`
	// RolledBack: the root an explicit rollback left. A late apply of that
	// root (same revision as the mark) must not undo the rollback; only a
	// newer revision supersedes it.
	RolledBack string `json:"rolled_back_root,omitempty"`
	// Pending is an apply's release saved before activation
	// (DYNROUTE-SCOPE-SAVE-LOSS-01): when the journal after activation cannot
	// be written, the next load settles it against what the runtime serves.
	Pending *dynamicRoutingPending `json:"pending,omitempty"`
}

type dynamicRoutingAccepted struct {
	SourceRevision int64  `json:"source_revision"`
	RootSHA256     string `json:"root_sha256"`
}

type dynamicRoutingPending struct {
	DeploymentID string                 `json:"deployment_id"`
	Release      *dynamicRoutingRelease `json:"release"`
	// Result is the deployment's result as if activated; recorded when the
	// runtime turns out to serve Release.
	Result deployment.Result `json:"result"`
}

// Stable codes of an apply refused before activation (running config unchanged).
const (
	dynamicRoutingStaleRevision    = "STALE_CONFIGURATION_REVISION"
	dynamicRoutingRevisionConflict = "CONFIGURATION_REVISION_CONFLICT"
	dynamicRoutingRolledBack       = "CONFIGURATION_ROLLED_BACK"
)

type dynamicRoutingRelease struct {
	ConfigVersionID string            `json:"config_version_id"`
	RootSHA256      string            `json:"root_sha256"`
	Sites           []string          `json:"sites"`
	Referenced      []string          `json:"referenced"`
	ScopeFiles      map[string]string `json:"scope_files"`
	// System is the release's platform system configuration (nginx base,
	// DDoS protection); the node runs the highest revision of all scopes.
	System *edgeconfig.SiteRuntimeSystem `json:"system,omitempty"`
	// SourceRevision and Streams: the release's L4 forwards, merged into
	// the node's L4 runtime.
	SourceRevision int64                     `json:"source_revision,omitempty"`
	Streams        *edgeconfig.StreamRuntime `json:"streams,omitempty"`
	// NodePages: the release's node pages (bodies among Referenced).
	NodePages []siteobject.NodePageV2 `json:"node_pages,omitempty"`
	// InstallationID: the scope's telemetry installation.
	InstallationID string `json:"installation_id,omitempty"`
	// NodeRegion: this node's region code as the release's key document
	// gave it (NODE_REGION; "" = none).
	NodeRegion string `json:"node_region,omitempty"`
	// NodeStorage: this node's storage settings as the release's key
	// document gave them (NODE_STORAGE; nil = none).
	NodeStorage *siteobject.NodeStorage `json:"node_storage,omitempty"`
	// OldWorkers are the workers the activation's reload replaced (none
	// without a reload): a drain plan waits for them.
	OldWorkers []string             `json:"old_workers,omitempty"`
	Drain      *dynamicRoutingDrain `json:"drain,omitempty"`
}

// dynamicRoutingDrain is a drain plan's record on the release it drains to.
type dynamicRoutingDrain struct {
	Revision        uint64                       `json:"revision"`
	Digest          string                       `json:"digest"`
	OldVersionID    string                       `json:"old_version_id"`
	Phase           deployment.DrainPhase        `json:"phase"`
	StartedAt       time.Time                    `json:"started_at"`
	Deadline        time.Time                    `json:"deadline"`
	CommandDeadline time.Time                    `json:"command_deadline"`
	Remaining       int                          `json:"remaining"`
	Transitions     []deployment.DrainTransition `json:"transitions"`
}

type dynamicRoutingResult struct {
	DeploymentID string            `json:"deployment_id"`
	Result       deployment.Result `json:"result"`
}

const dynamicRoutingKeptResults = 32

var scopeIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func newDynamicRoutingManager(runtime *dynroute.Runtime, objects *objectstore.Store, root string) (*dynamicRoutingManager, error) {
	if runtime == nil || objects == nil || !filepath.IsAbs(root) {
		return nil, errors.New("dynamic routing manager: runtime, object store and absolute root are required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("dynamic routing manager root: %w", err)
	}
	return &dynamicRoutingManager{runtime: runtime, objects: objects, root: root, now: time.Now,
		remaining: runtime.RemainingWorkers, apply: runtime.Apply, activeVersion: runtime.ScopeVersion}, nil
}

func (m *dynamicRoutingManager) scopePath(scopeID string) string {
	return filepath.Join(m.root, scopeID+".json")
}

func (m *dynamicRoutingManager) load(scopeID string) (dynamicRoutingScope, error) {
	var scope dynamicRoutingScope
	content, err := os.ReadFile(m.scopePath(scopeID))
	if errors.Is(err, os.ErrNotExist) {
		return scope, nil
	}
	if err != nil {
		return scope, fmt.Errorf("read dynamic routing scope %s: %w", scopeID, err)
	}
	if err := json.Unmarshal(content, &scope); err != nil {
		return scope, fmt.Errorf("decode dynamic routing scope %s: %w", scopeID, err)
	}
	if scope.Accepted == nil && scope.Current != nil {
		// journal from before the high-water mark: its current release
		scope.Accepted = &dynamicRoutingAccepted{SourceRevision: scope.Current.SourceRevision, RootSHA256: scope.Current.RootSHA256}
	}
	m.settle(scopeID, &scope, false)
	return scope, nil
}

// settle resolves a pending activation: when the runtime serves its release
// it becomes current with its result (pointers and lookups see what runs;
// nothing runs again). With drop (an apply or rollback holding m.mu, nothing
// in flight) an intent the runtime does not serve never activated and goes,
// and the settled journal is written back; reads only settle in memory.
func (m *dynamicRoutingManager) settle(scopeID string, scope *dynamicRoutingScope, drop bool) {
	pending := scope.Pending
	if pending == nil || m.activeVersion == nil {
		return
	}
	serves := m.activeVersion(scopeID) == pending.Release.ConfigVersionID
	if !serves && !drop {
		return
	}
	scope.Pending = nil
	if serves {
		m.accept(scope, pending.Release)
		if _, found := scope.result(pending.DeploymentID, pending.Result.Attempt); !found {
			scope.record(pending.DeploymentID, pending.Result)
		}
	}
	if drop {
		_ = m.save(scopeID, *scope)
	}
}

// loadForWrite is load for an apply or rollback (m.mu held).
func (m *dynamicRoutingManager) loadForWrite(scopeID string) (dynamicRoutingScope, error) {
	scope, err := m.load(scopeID)
	if err == nil {
		m.settle(scopeID, &scope, true)
	}
	return scope, err
}

// accept makes release (activated by an apply) current and raises the mark.
func (m *dynamicRoutingManager) accept(scope *dynamicRoutingScope, release *dynamicRoutingRelease) {
	if scope.Current == nil || scope.Current.ConfigVersionID != release.ConfigVersionID {
		scope.Previous, scope.Current = scope.Current, release
	}
	if scope.Accepted == nil || release.SourceRevision > scope.Accepted.SourceRevision {
		scope.RolledBack = ""
	}
	scope.Accepted = &dynamicRoutingAccepted{SourceRevision: release.SourceRevision, RootSHA256: release.RootSHA256}
}

// refusal is why an apply of release must not activate, or "".
func (scope dynamicRoutingScope) refusal(release gatewayclient.DynamicRoutingRelease) (code, summary string) {
	mark := scope.Accepted
	switch {
	case mark == nil:
		return "", ""
	case release.SourceRevision < mark.SourceRevision:
		return dynamicRoutingStaleRevision, fmt.Sprintf("source revision %d is older than the accepted %d; the running configuration is kept",
			release.SourceRevision, mark.SourceRevision)
	case release.SourceRevision == mark.SourceRevision && release.RootSHA256 != mark.RootSHA256:
		return dynamicRoutingRevisionConflict, fmt.Sprintf("source revision %d was accepted with another root", release.SourceRevision)
	case release.SourceRevision == mark.SourceRevision && scope.RolledBack == release.RootSHA256:
		return dynamicRoutingRolledBack, "this release was rolled back; a newer revision replaces it"
	}
	return "", ""
}

// refusedResult is the terminal result of an apply refused before
// activation: failed, running configuration unchanged.
func refusedResult(deploymentID string, attempt uint32, configVersionID string, at time.Time, code, summary string) deployment.Result {
	result := gatewayclient.DynamicRoutingResult(deploymentID, attempt, deployment.ActionApply, configVersionID, at, at, errors.New(summary))
	last := &result.Transitions[len(result.Transitions)-1]
	last.ErrorCode = code
	result.ErrorCode = code
	return result
}

func (m *dynamicRoutingManager) save(scopeID string, scope dynamicRoutingScope) error {
	content, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(m.root, ".scope-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), m.scopePath(scopeID))
}

func (m *dynamicRoutingManager) scopeIDs() ([]string, error) {
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return nil, err
	}
	var scopes []string
	for _, entry := range entries {
		if name, ok := strings.CutSuffix(entry.Name(), ".json"); ok && scopeIDPattern.MatchString(name) {
			scopes = append(scopes, name)
		}
	}
	sort.Strings(scopes)
	return scopes, nil
}

// ApplyDynamicRouting makes release scope's current release and applies every
// scope's current release. On failure the scope keeps its release.
func (m *dynamicRoutingManager) ApplyDynamicRouting(ctx context.Context, deploymentID string, attempt uint32,
	release gatewayclient.DynamicRoutingRelease) (deployment.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	started := m.now()
	scopeID := release.ConfigurationScopeID
	if !scopeIDPattern.MatchString(scopeID) {
		return deployment.Result{}, fmt.Errorf("dynamic routing scope %q", scopeID)
	}
	scope, err := m.loadForWrite(scopeID)
	if err != nil {
		return deployment.Result{}, err
	}
	if found, ok := scope.result(deploymentID, attempt); ok {
		return found, nil // redelivery of a finished deployment
	}
	if code, summary := scope.refusal(release); code != "" {
		result := refusedResult(deploymentID, attempt, release.ConfigVersionID, started, code, summary)
		scope.record(deploymentID, result)
		if err := m.save(scopeID, scope); err != nil {
			return deployment.Result{}, err
		}
		return result, nil
	}
	next := &dynamicRoutingRelease{ConfigVersionID: release.ConfigVersionID, RootSHA256: release.RootSHA256,
		ScopeFiles: map[string]string{}, System: release.System, SourceRevision: release.SourceRevision, Streams: release.Streams,
		NodePages: release.NodePages, InstallationID: release.InstallationID, NodeRegion: release.NodeRegion, NodeStorage: release.NodeStorage}
	for digest := range release.Sites {
		next.Sites = append(next.Sites, digest)
	}
	for digest := range release.Referenced {
		next.Referenced = append(next.Referenced, digest)
	}
	for path, content := range release.ScopeFiles {
		next.ScopeFiles[path] = siteobject.Digest(content)
	}
	sort.Strings(next.Sites)
	sort.Strings(next.Referenced)
	// The intent is on disk before anything switches: a journal that cannot
	// be written stops here with the running configuration unchanged.
	pending := scope
	pending.Pending = &dynamicRoutingPending{DeploymentID: deploymentID, Release: next,
		Result: gatewayclient.DynamicRoutingResult(deploymentID, attempt, deployment.ActionApply, release.ConfigVersionID, started, started,
			&scopeJournalError{errors.New("scope journal not saved after activation; settled from the runtime state")})}
	if err := m.save(scopeID, pending); err != nil {
		return deployment.Result{}, err
	}
	applied, applyErr := m.applyAll(ctx, map[string]*dynamicRoutingRelease{scopeID: next}, release)
	next.OldWorkers = applied.OldWorkers
	// Activated but its bookkeeping failed (PJ-E02): the release runs, so it
	// is the scope's current one.
	activated := applyErr == nil || gatewayclient.DynamicRoutingActivated(applyErr)
	if activated {
		m.accept(&scope, next)
	}
	result := gatewayclient.DynamicRoutingResult(deploymentID, attempt, deployment.ActionApply, release.ConfigVersionID,
		started, m.now(), applyErr)
	scope.record(deploymentID, result)
	if err := m.save(scopeID, scope); err != nil {
		if !activated {
			// Not activated: the pending intent is dropped on the next load
			// (the runtime does not serve it); the result stays unchanged.
			return result, nil
		}
		// Activated, journal not saved (DYNROUTE-SCOPE-SAVE-LOSS-01): the
		// node serves the release, so the result says so (healthy with a
		// failed maintenance check, never "unchanged"); the pending intent
		// on disk makes it current on the next load.
		return gatewayclient.DynamicRoutingResult(deploymentID, attempt, deployment.ActionApply, release.ConfigVersionID,
			started, m.now(), &scopeJournalError{err}), nil
	}
	return result, nil
}

// scopeJournalError: the release was activated, its scope journal not
// saved (reported as an activated maintenance failure).
type scopeJournalError struct{ err error }

func (e *scopeJournalError) Error() string                     { return "save scope journal: " + e.err.Error() }
func (e *scopeJournalError) Unwrap() error                     { return e.err }
func (e *scopeJournalError) ActivatedMaintenanceFailure() bool { return true }

// applyAll applies every scope's current release with override replacing
// its scope's; supplied carries the plaintexts of the release being applied
// (the rest come from the object store).
func (m *dynamicRoutingManager) applyAll(ctx context.Context, override map[string]*dynamicRoutingRelease,
	supplied gatewayclient.DynamicRoutingRelease) (dynroute.Result, error) {
	input, err := m.input(override, supplied)
	if err != nil {
		return dynroute.Result{}, err
	}
	// Only the release being applied names forwards to stop (a reapply
	// withdraws nothing).
	input.TrafficStop = supplied.TrafficStop
	if m.adaptive != nil {
		input.WAFTargets = m.adaptive.NodeTargets()
	}
	result, err := m.apply(ctx, input)
	if (err == nil || gatewayclient.DynamicRoutingActivated(err)) && m.adaptive != nil {
		m.adaptive.Applied(input, result.WAFProbe)
	}
	return result, err
}

// Reapply applies every scope's current release again: what the node adds
// beside the releases changed (a new CRS engine module, the node pages,
// the rule packs of the node artifact set: a site whose mounts were waiting
// on a pack now passes its precheck).
// Nothing applied yet: nothing to do.
func (m *dynamicRoutingManager) Reapply(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Scopes()) == 0 {
		return nil
	}
	_, err := m.applyAll(ctx, nil, gatewayclient.DynamicRoutingRelease{})
	return err
}

func (m *dynamicRoutingManager) input(override map[string]*dynamicRoutingRelease,
	supplied gatewayclient.DynamicRoutingRelease) (dynroute.Input, error) {
	scopes, err := m.scopeIDs()
	if err != nil {
		return dynroute.Input{}, err
	}
	releases := map[string]*dynamicRoutingRelease{}
	for _, scopeID := range scopes {
		scope, err := m.load(scopeID)
		if err != nil {
			return dynroute.Input{}, err
		}
		if scope.Current != nil {
			releases[scopeID] = scope.Current
		}
	}
	for scopeID, release := range override {
		if release == nil {
			delete(releases, scopeID)
		} else {
			releases[scopeID] = release
		}
	}
	get := func(digest string, local map[string][]byte) ([]byte, error) {
		if content, ok := local[digest]; ok {
			return content, nil
		}
		return m.objects.Get(digest)
	}
	input := dynroute.Input{ScopeVersions: map[string]string{}, Installations: map[string]string{},
		Profiles: map[string]edgeconfig.CRSProfile{}, Apps: map[string]edgeconfig.CRSApp{}}
	crsFiles := map[string][]byte{}
	ids := make([]string, 0, len(releases))
	for scopeID := range releases {
		ids = append(ids, scopeID)
	}
	sort.Strings(ids)
	// The node's region (fz-x12): a control plane fact every key document
	// carries. The release being applied has the latest; a reapply or
	// rollback takes the first scope's that names one (a region change
	// republishes every scope).
	regionSet := supplied.ConfigurationScopeID != ""
	input.NodeRegion = supplied.NodeRegion
	// The node's storage settings (NODE_STORAGE) are the same kind of fact:
	// a change republishes every scope.
	input.NodeStorage = supplied.NodeStorage
	for _, scopeID := range ids {
		release := releases[scopeID]
		if !regionSet && release.NodeRegion != "" {
			input.NodeRegion, regionSet = release.NodeRegion, true
		}
		if supplied.ConfigurationScopeID == "" && input.NodeStorage == nil && release.NodeStorage != nil {
			input.NodeStorage = release.NodeStorage
		}
		input.ScopeVersions[scopeID] = release.ConfigVersionID
		if release.InstallationID != "" {
			input.Installations[scopeID] = release.InstallationID
		}
		if release.System != nil {
			input.Systems = append(input.Systems, release.System)
		}
		if release.Streams != nil {
			input.Streams = append(input.Streams, dynroute.ScopeStreams{ScopeID: scopeID, ConfigVersionID: release.ConfigVersionID,
				Revision: release.SourceRevision, Runtime: *release.Streams})
		}
		var local gatewayclient.DynamicRoutingRelease
		if supplied.ConfigurationScopeID == scopeID && supplied.ConfigVersionID == release.ConfigVersionID {
			local = supplied
		}
		referenced := map[string][]byte{}
		for _, digest := range release.Referenced {
			content, err := get(digest, local.Referenced)
			if err != nil {
				return dynroute.Input{}, fmt.Errorf("scope %s referenced object %s: %w", scopeID, digest, err)
			}
			referenced[digest] = content
		}
		for _, page := range release.NodePages {
			body, ok := referenced[page.SHA256]
			if !ok {
				return dynroute.Input{}, fmt.Errorf("scope %s node page %s: body %s not referenced", scopeID, page.Category, page.SHA256)
			}
			input.NodePages = append(input.NodePages, dynroute.NodePage{Category: page.Category, Status: page.Status,
				MIMEType: page.MIMEType, StyleHash: page.StyleHash, Body: body, Region: page.Region, NodeID: page.NodeID})
		}
		for _, digest := range release.Sites {
			raw, err := get(digest, local.Sites)
			if err != nil {
				return dynroute.Input{}, fmt.Errorf("scope %s site object %s: %w", scopeID, digest, err)
			}
			object, err := siteindex.DecodeObject(digest, raw)
			if err != nil {
				return dynroute.Input{}, fmt.Errorf("scope %s: %w", scopeID, err)
			}
			object.Referenced = map[string][]byte{}
			for _, ref := range object.Site.ReferencedDigests() {
				if content, ok := referenced[ref]; ok {
					object.Referenced[ref] = content
				}
			}
			input.Objects = append(input.Objects, object)
		}
		for path, digest := range release.ScopeFiles {
			content, ok := local.ScopeFiles[path]
			if !ok {
				if content, err = m.objects.Get(digest); err != nil {
					return dynroute.Input{}, fmt.Errorf("scope %s file %s: %w", scopeID, path, err)
				}
			}
			if profileDigest, isProfile := edgeconfig.ListenerCRSProfileDigest(path); isProfile {
				_, profile, err := rulepack.LoadCRSProfile(content, profileDigest)
				if err != nil {
					return dynroute.Input{}, fmt.Errorf("scope %s CRS profile %s: %w", scopeID, profileDigest, err)
				}
				input.Profiles[profileDigest] = profile
				continue
			}
			if appDigest, isApp := edgeconfig.ListenerCRSAppDigest(path); isApp {
				_, app, err := rulepack.LoadCRSApp(content, appDigest)
				if err != nil {
					return dynroute.Input{}, fmt.Errorf("scope %s CRS application pack %s: %w", scopeID, appDigest, err)
				}
				input.Apps[appDigest] = app
				continue
			}
			if name, isRule := strings.CutPrefix(path, edgeconfig.ListenerCRSReleasePath("")); isRule {
				crsFiles[name] = content
			}
		}
	}
	if len(crsFiles) > 0 {
		input.CRSText = &edgeconfig.CRSRuleText{Files: crsFiles}
	}
	// CRS profile packs come with the node artifact set (crs_profile/*
	// items, object store by digest); a pack not stored yet is left out and
	// the managed WAF check refuses the site until the set brings it.
	for _, object := range input.Objects {
		if object.Site.Security.ManagedWAF == nil {
			continue
		}
		digest := object.Site.Security.ManagedWAF.CRSProfile.SHA256
		if _, ok := input.Profiles[digest]; ok {
			continue
		}
		content, err := m.objects.Get(digest)
		if errors.Is(err, objectstore.ErrNotFound) {
			continue
		}
		if err != nil {
			return dynroute.Input{}, fmt.Errorf("CRS profile %s: %w", digest, err)
		}
		_, profile, err := rulepack.LoadCRSProfile(content, digest)
		if err != nil {
			return dynroute.Input{}, fmt.Errorf("CRS profile %s: %w", digest, err)
		}
		input.Profiles[digest] = profile
	}
	return input, nil
}

// Process handles the deployment commands the gateway client routes to the
// manager: only explicit rollbacks reach a dynamic routing node (applies go
// through ApplyDynamicRouting).
func (m *dynamicRoutingManager) Process(ctx context.Context, command deployment.Command) (deployment.Result, error) {
	if command.Action != deployment.ActionRollback {
		return deployment.Result{}, fmt.Errorf("%w: a dynamic routing node takes site object releases only", deployment.ErrInvalidCommand)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	started := m.now()
	if !scopeIDPattern.MatchString(command.ScopeID) {
		return deployment.Result{}, fmt.Errorf("%w: rollback requires a scope", deployment.ErrInvalidCommand)
	}
	scope, err := m.loadForWrite(command.ScopeID)
	if err != nil {
		return deployment.Result{}, err
	}
	if found, ok := scope.result(command.DeploymentID, command.Attempt); ok {
		return found, nil
	}
	var rollbackErr error
	switch {
	case scope.Current == nil || scope.Previous == nil:
		rollbackErr = errors.New("no previous release to roll back to")
	case scope.Previous.ConfigVersionID != command.ConfigVersionID:
		rollbackErr = fmt.Errorf("previous release is %s, not %s", scope.Previous.ConfigVersionID, command.ConfigVersionID)
	default:
		_, rollbackErr = m.applyAll(ctx, map[string]*dynamicRoutingRelease{command.ScopeID: scope.Previous},
			gatewayclient.DynamicRoutingRelease{})
	}
	result := gatewayclient.DynamicRoutingResult(command.DeploymentID, command.Attempt, deployment.ActionRollback,
		command.ConfigVersionID, started, m.now(), rollbackErr)
	if rollbackErr == nil || gatewayclient.DynamicRoutingActivated(rollbackErr) {
		scope.Current, scope.Previous = scope.Previous, scope.Current
		// The mark stays; a late apply of the release rolled away from is
		// refused until a newer revision arrives.
		scope.RolledBack = scope.Previous.RootSHA256
		// The object store keeps an owner's current and previous generation:
		// make the restored release current so the next apply keeps it.
		_ = m.objects.Commit("site-"+command.ScopeID, scope.Current.digests())
	}
	scope.record(command.DeploymentID, result)
	if err := m.save(command.ScopeID, scope); err != nil {
		return deployment.Result{}, err
	}
	return result, nil
}

// Pointers is the node-wide pair when exactly one scope holds a release.
func (m *dynamicRoutingManager) Pointers() (deployment.Pointers, error) {
	scopes := m.Scopes()
	if len(scopes) != 1 {
		return deployment.Pointers{}, nil
	}
	return m.ScopePointers(scopes[0])
}

// NodePointers is the node's active and last known good configuration for
// the upgrade receipt: one scope's root digests, or for several scopes the
// SHA-256 of their sorted "scope root" lines (current roots; previous roots,
// a scope without one counting its current), since every scope's release is
// active at once.
func (m *dynamicRoutingManager) NodePointers() (deployment.Pointers, error) {
	scopes := m.Scopes()
	if len(scopes) <= 1 {
		return m.Pointers()
	}
	current, previous := sha256.New(), sha256.New()
	for _, scopeID := range scopes {
		scope, err := m.load(scopeID)
		if err != nil {
			return deployment.Pointers{}, err
		}
		fmt.Fprintf(current, "%s %s\n", scopeID, scope.Current.RootSHA256)
		last := scope.Current
		if scope.Previous != nil {
			last = scope.Previous
		}
		fmt.Fprintf(previous, "%s %s\n", scopeID, last.RootSHA256)
	}
	return deployment.Pointers{CurrentDigest: hex.EncodeToString(current.Sum(nil)), PreviousDigest: hex.EncodeToString(previous.Sum(nil))}, nil
}

func (m *dynamicRoutingManager) ScopePointers(scopeID string) (deployment.Pointers, error) {
	scope, err := m.load(scopeID)
	if err != nil {
		return deployment.Pointers{}, err
	}
	var pointers deployment.Pointers
	if scope.Current != nil {
		pointers.Current, pointers.CurrentDigest = scope.Current.ConfigVersionID, scope.Current.RootSHA256
	}
	if scope.Previous != nil {
		pointers.Previous, pointers.PreviousDigest = scope.Previous.ConfigVersionID, scope.Previous.RootSHA256
	}
	return pointers, nil
}

// Scopes lists the scopes holding a current release.
func (m *dynamicRoutingManager) Scopes() []string {
	ids, err := m.scopeIDs()
	if err != nil {
		return nil
	}
	var scopes []string
	for _, scopeID := range ids {
		if scope, err := m.load(scopeID); err == nil && scope.Current != nil {
			scopes = append(scopes, scopeID)
		}
	}
	return scopes
}

func (m *dynamicRoutingManager) Lookup(deploymentID string) (deployment.Result, bool, error) {
	ids, err := m.scopeIDs()
	if err != nil {
		return deployment.Result{}, false, err
	}
	for _, scopeID := range ids {
		scope, err := m.load(scopeID)
		if err != nil {
			return deployment.Result{}, false, err
		}
		for index := len(scope.Results) - 1; index >= 0; index-- {
			if scope.Results[index].DeploymentID == deploymentID {
				return scope.Results[index].Result, true, nil
			}
		}
	}
	return deployment.Result{}, false, nil
}

// Recover restarts the runtime from its own state (dynroute.Runtime.Recover
// is run by the daemon); nothing to do here.
func (m *dynamicRoutingManager) Recover(context.Context) error { return nil }

func (m *dynamicRoutingManager) RecoverCertificateVersionReferences(context.Context) error {
	return nil
}

// ConfigureCertificateVersionStore: dynroute holds the certificate store
// references itself (dynroute.Config.Certificates).
func (m *dynamicRoutingManager) ConfigureCertificateVersionStore(deployment.CertificateVersionStore, string) error {
	return nil
}

func (release *dynamicRoutingRelease) digests() []string {
	digests := append(append([]string(nil), release.Sites...), release.Referenced...)
	for _, digest := range release.ScopeFiles {
		digests = append(digests, digest)
	}
	return digests
}

func (scope dynamicRoutingScope) result(deploymentID string, attempt uint32) (deployment.Result, bool) {
	for _, entry := range scope.Results {
		if entry.DeploymentID == deploymentID && entry.Result.Attempt == attempt {
			return entry.Result, true
		}
	}
	return deployment.Result{}, false
}

func (scope *dynamicRoutingScope) record(deploymentID string, result deployment.Result) {
	scope.Results = append(scope.Results, dynamicRoutingResult{DeploymentID: deploymentID, Result: result})
	if len(scope.Results) > dynamicRoutingKeptResults {
		scope.Results = scope.Results[len(scope.Results)-dynamicRoutingKeptResults:]
	}
}

// ScopeForSite maps a site to the scope whose current release carries it
// (telemetry scoped_records on a MULTI_TENANT_RUNTIME session). The index
// is rebuilt from the scope journals and the object store when the set of
// current roots changes.
func (m *dynamicRoutingManager) ScopeForSite(siteID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids, err := m.scopeIDs()
	if err != nil {
		return "", false
	}
	roots := map[string]string{}
	current := map[string]*dynamicRoutingRelease{}
	for _, scopeID := range ids {
		scope, err := m.load(scopeID)
		if err != nil {
			return "", false
		}
		if scope.Current != nil {
			roots[scopeID], current[scopeID] = scope.Current.RootSHA256, scope.Current
		}
	}
	if !maps.Equal(roots, m.indexRoots) {
		sites := map[string]string{}
		for scopeID, release := range current {
			for _, digest := range release.Sites {
				raw, err := m.objects.Get(digest)
				if err != nil {
					return "", false
				}
				object, err := siteindex.DecodeObject(digest, raw)
				if err != nil {
					return "", false
				}
				sites[object.Site.SiteID] = scopeID
			}
		}
		m.indexRoots, m.siteScopes = roots, sites
	}
	scopeID, ok := m.siteScopes[siteID]
	return scopeID, ok
}
