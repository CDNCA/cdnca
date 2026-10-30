package l4runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"
)

type Runtime interface {
	Precheck(context.Context, string) error
	Activate(context.Context, string) error
	Healthy(context.Context, Config) error
	Stop(context.Context, string) error
}

type drainRuntime interface {
	Drain(context.Context, time.Duration) error
}

// resumeRuntime takes over the runtime a previous agent process left running.
type resumeRuntime interface {
	Resume(context.Context, string) error
}

// drainLimitRuntime takes how long the generation the next activation
// retires may keep draining its sessions.
type drainLimitRuntime interface {
	SetDrainLimit(time.Duration) error
}

type Manager struct {
	mu      sync.Mutex
	store   *diskStore
	runtime Runtime
	now     func() time.Time
}

func NewManager(stateRoot string, runtime Runtime) (*Manager, error) {
	return newManager(stateRoot, runtime, time.Now)
}

func newManager(stateRoot string, runtime Runtime, now func() time.Time) (*Manager, error) {
	if runtime == nil || now == nil {
		return nil, ErrInvalidConfig
	}
	store, err := newDiskStore(stateRoot)
	if err != nil {
		return nil, err
	}
	manager := &Manager{store: store, runtime: runtime, now: now}
	unlock, err := store.lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := manager.recoverActivation(context.Background()); err != nil {
		return nil, err
	}
	if err := manager.recoverRelease(context.Background()); err != nil {
		return nil, err
	}
	// Not fatal: the agent must stay manageable when the active listeners
	// cannot be restored (for example a port taken while it was down); the
	// next release activates the runtime again.
	resumeContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := manager.resumeActive(resumeContext); err != nil {
		slog.Warn("resume active L4 runtime after agent start failed", "error", err)
	}
	return manager, nil
}

// resumeActive keeps the active version serving across an agent restart:
// it adopts the master the previous agent left running, or starts the active
// version when that master is gone (killed, crashed, or the host rebooted).
func (m *Manager) resumeActive(ctx context.Context) error {
	runtime, ok := m.runtime.(resumeRuntime)
	if !ok {
		return nil
	}
	active, err := m.store.loadActive()
	if err != nil || active == nil {
		return err
	}
	current, err := m.store.currentVersionDir()
	if err != nil {
		return err
	}
	if current != active.VersionDir {
		return ErrCorruptState
	}
	compiled, versionDir, err := m.store.loadVersion(active.VersionID, active.Digest)
	if err != nil || versionDir != active.VersionDir {
		return errors.Join(ErrCorruptState, err)
	}
	if limiter, ok := m.runtime.(drainLimitRuntime); ok {
		if err := limiter.SetDrainLimit(drainLimit(compiled.Config.DrainMaxMS)); err != nil {
			return err
		}
	}
	return runtime.Resume(ctx, m.store.currentPath)
}

func (m *Manager) Apply(ctx context.Context, config Config) (Result, error) {
	compiled, err := Compile(config)
	if err != nil {
		return Result{}, err
	}
	return m.applyCompiled(ctx, compiled, nil)
}

// ApplyV2 resolves every scoped hostname before compiling and atomically
// activates the resulting address sets through the existing LKG journal.
func (m *Manager) ApplyV2(ctx context.Context, config ConfigV2, coordinator *DNSCoordinator) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := m.recoverActivation(ctx); err != nil {
		return Result{}, err
	}
	compiledV2, err := m.prepareV2(ctx, config, coordinator)
	if err != nil {
		return Result{}, err
	}
	return m.applyCompiledLocked(ctx, compatibleCompiledV2(*compiledV2), compiledV2)
}

func (m *Manager) applyCompiled(ctx context.Context, compiled CompiledConfig, compiledV2 *CompiledConfigV2) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := m.recoverActivation(ctx); err != nil {
		return Result{}, err
	}

	return m.applyCompiledLocked(ctx, compiled, compiledV2)
}

func (m *Manager) applyCompiledLocked(ctx context.Context, compiled CompiledConfig, compiledV2 *CompiledConfigV2) (Result, error) {
	previous, err := m.store.loadActive()
	if err != nil {
		return Result{}, err
	}
	if previous != nil && previous.VersionID == compiled.Config.VersionID {
		if previous.Digest != compiled.Digest {
			return Result{}, ErrConflict
		}
		return appliedResult(previous, nil), nil
	}
	previousConfig, err := m.loadActiveConfig(previous)
	if err != nil {
		return Result{}, err
	}
	listenerResults := listenerLifecycle(previousConfig, compiled.Config)
	var stagePath string
	if compiledV2 == nil {
		stagePath, err = m.store.stage(compiled)
	} else {
		stagePath, err = m.store.stageV2(*compiledV2)
	}
	if err != nil {
		return Result{}, err
	}
	stageRemoved := false
	defer func() {
		if !stageRemoved {
			_ = os.RemoveAll(stagePath)
		}
	}()
	if err := m.runtime.Precheck(ctx, stagePath); err != nil {
		return failedResult(compiled, previous, "PRECHECK_FAILED", true, listenerResults, err), fmt.Errorf("%w: %v", ErrPrecheck, err)
	}
	var versionDir string
	if compiledV2 == nil {
		versionDir, err = m.store.commitStage(stagePath, compiled)
	} else {
		versionDir, err = m.store.commitStageV2(stagePath, *compiledV2)
	}
	if err != nil {
		return Result{}, err
	}
	if err := os.RemoveAll(stagePath); err != nil && !os.IsNotExist(err) {
		return Result{}, fmt.Errorf("remove committed L4 staging directory: %w", err)
	}
	stageRemoved = true
	active := activeRecord{
		SchemaVersion: stateSchemaVersion, VersionID: compiled.Config.VersionID, Digest: compiled.Digest,
		VersionDir: versionDir, AppliedAt: m.now().UTC(),
	}
	if err := m.store.saveActivationJournal(activationJournal{
		SchemaVersion: activationJournalSchemaVersion, Operation: activationOperationApply,
		Candidate: active, Previous: previous, CreatedAt: m.now().UTC(),
	}); err != nil {
		return Result{}, err
	}
	if err := m.store.switchCurrent(versionDir); err != nil {
		return Result{}, err
	}
	if err := m.activate(ctx, compiled.Config); err != nil {
		unchanged, rollbackErr := m.restoreWithTimeout(previous)
		if rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: activate: %v; restore LKG: %v", ErrActivation, err, rollbackErr)
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: activate: %v; clear recovery journal: %v", ErrActivation, err, clearErr)
		}
		return failedResult(compiled, previous, "ACTIVATION_FAILED", unchanged, listenerResults, err), fmt.Errorf("%w: %v", ErrActivation, err)
	}
	if err := m.healthy(ctx, compiled); err != nil {
		unchanged, rollbackErr := m.restoreWithTimeout(previous)
		if rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: traffic health: %v; restore LKG: %v", ErrActivation, err, rollbackErr)
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: traffic health: %v; clear recovery journal: %v", ErrActivation, err, clearErr)
		}
		return failedResult(compiled, previous, "TRAFFIC_HEALTH_FAILED", unchanged, listenerResults, err), fmt.Errorf("%w: traffic health: %v", ErrActivation, err)
	}
	if err := m.drain(ctx, transitionDrainTimeoutMS(previousConfig, compiled.Config)); err != nil {
		unchanged, rollbackErr := m.restoreWithTimeout(previous)
		if rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: drain: %v; restore LKG: %v", ErrActivation, err, rollbackErr)
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: drain: %v; clear recovery journal: %v", ErrActivation, err, clearErr)
		}
		return failedResult(compiled, previous, "DRAIN_FAILED", unchanged, listenerResults, err), fmt.Errorf("%w: %v", ErrActivation, err)
	}
	if err := m.store.saveActive(active); err != nil {
		if _, rollbackErr := m.restoreWithTimeout(previous); rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("persist L4 active state: %w", err)
		}
		if restoreErr := m.store.restoreActive(previous); restoreErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, restoreErr), fmt.Errorf("restore L4 active state: %w", restoreErr)
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, clearErr), fmt.Errorf("clear L4 recovery journal: %w", clearErr)
		}
		return Result{}, err
	}
	if err := m.store.clearActivationJournal(); err != nil {
		return Result{}, err
	}
	return appliedResult(&active, listenerResults), nil
}

func compatibleCompiledV2(compiled CompiledConfigV2) CompiledConfig {
	config := Config{SchemaVersion: SchemaVersionV2, VersionID: compiled.Config.VersionID}
	for _, listener := range compiled.Config.Listeners {
		poolID := "v2_" + listener.StreamID
		pool := UpstreamPool{ID: poolID}
		for _, address := range compiled.ResolvedAddressSets[listener.StreamID] {
			pool.Endpoints = append(pool.Endpoints, Endpoint{Address: address.String(), Port: listener.Endpoint.Port,
				Weight: 1, MaxFails: 1, FailTimeoutMS: 1000})
		}
		config.UpstreamPools = append(config.UpstreamPools, pool)
		for _, socket := range listenerSocketsV2(listener) {
			config.Listeners = append(config.Listeners, Listener{ID: socket.ID, Protocol: socket.Protocol,
				Address: socket.Address, Port: socket.Port, PortEnd: socket.PortEnd, UpstreamPoolID: poolID,
				ConnectTimeoutMS: listener.ConnectTimeoutMS, IdleTimeoutMS: listener.ResponseTimeoutMS,
				ProxyProtocolInbound: listener.ProxyProtocolInbound, ProxyProtocolOutbound: listener.ProxyProtocolOutbound,
				MaxConnectionsPerClient: listener.MaxConnectionsPerClient, TrustedProxyCIDRs: listener.Geo.TrustedProxyCIDRs})
		}
		if listener.DrainTimeoutMS > config.DrainTimeoutMS {
			config.DrainTimeoutMS = listener.DrainTimeoutMS
		}
		config.DrainMaxMS = mergeDrainMaxMS(config.DrainMaxMS, listener.DrainMaxMS)
	}
	return CompiledConfig{Config: config, Digest: compiled.Digest, CanonicalJSON: compiled.GeoJSON, NginxConfig: compiled.NginxConfig, v2: &compiled.Config}
}

func (m *Manager) Rollback(ctx context.Context, versionID, digest string) (Result, error) {
	if !identifierPattern.MatchString(versionID) || !validDigest(digest) {
		return Result{}, ErrInvalidConfig
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := m.recoverActivation(ctx); err != nil {
		return Result{}, err
	}

	previous, err := m.store.loadActive()
	if err != nil {
		return Result{}, err
	}
	if previous != nil && previous.VersionID == versionID && previous.Digest == digest {
		return appliedResult(previous, nil), nil
	}
	compiled, versionDir, err := m.store.loadVersion(versionID, digest)
	if err != nil {
		return Result{}, err
	}
	previousConfig, err := m.loadActiveConfig(previous)
	if err != nil {
		return Result{}, err
	}
	listenerResults := listenerLifecycle(previousConfig, compiled.Config)
	versionPath := filepath.Join(m.store.versionsDir, versionDir)
	if err := m.runtime.Precheck(ctx, versionPath); err != nil {
		return failedResult(compiled, previous, "PRECHECK_FAILED", true, listenerResults, err), fmt.Errorf("%w: %v", ErrPrecheck, err)
	}
	active := activeRecord{
		SchemaVersion: stateSchemaVersion, VersionID: versionID, Digest: digest,
		VersionDir: versionDir, AppliedAt: m.now().UTC(),
	}
	if err := m.store.saveActivationJournal(activationJournal{
		SchemaVersion: activationJournalSchemaVersion, Operation: activationOperationRollback,
		Candidate: active, Previous: previous, CreatedAt: m.now().UTC(),
	}); err != nil {
		return Result{}, err
	}
	if err := m.store.switchCurrent(versionDir); err != nil {
		return Result{}, err
	}
	if err := m.activate(ctx, compiled.Config); err != nil {
		unchanged, rollbackErr := m.restoreWithTimeout(previous)
		if rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: activate rollback target: %v; restore LKG: %v", ErrActivation, err, rollbackErr)
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: activate rollback target: %v; clear recovery journal: %v", ErrActivation, err, clearErr)
		}
		return failedResult(compiled, previous, "ACTIVATION_FAILED", unchanged, listenerResults, err), fmt.Errorf("%w: %v", ErrActivation, err)
	}
	if err := m.healthy(ctx, compiled); err != nil {
		unchanged, rollbackErr := m.restoreWithTimeout(previous)
		if rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: rollback target traffic health: %v; restore LKG: %v", ErrActivation, err, rollbackErr)
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: rollback target traffic health: %v; clear recovery journal: %v", ErrActivation, err, clearErr)
		}
		return failedResult(compiled, previous, "TRAFFIC_HEALTH_FAILED", unchanged, listenerResults, err), fmt.Errorf("%w: rollback target traffic health: %v", ErrActivation, err)
	}
	if err := m.drain(ctx, transitionDrainTimeoutMS(previousConfig, compiled.Config)); err != nil {
		unchanged, rollbackErr := m.restoreWithTimeout(previous)
		if rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: drain rollback target: %v; restore LKG: %v", ErrActivation, err, rollbackErr)
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("%w: drain rollback target: %v; clear recovery journal: %v", ErrActivation, err, clearErr)
		}
		return failedResult(compiled, previous, "DRAIN_FAILED", unchanged, listenerResults, err), fmt.Errorf("%w: %v", ErrActivation, err)
	}
	if err := m.store.saveActive(active); err != nil {
		if _, rollbackErr := m.restoreWithTimeout(previous); rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, err), fmt.Errorf("persist L4 rollback state: %w; restore LKG: %v", err, rollbackErr)
		}
		if restoreErr := m.store.restoreActive(previous); restoreErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, restoreErr), fmt.Errorf("restore L4 active state: %w", restoreErr)
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false, listenerResults, clearErr), fmt.Errorf("clear L4 recovery journal: %w", clearErr)
		}
		return Result{}, err
	}
	if err := m.store.clearActivationJournal(); err != nil {
		return Result{}, err
	}
	return appliedResult(&active, listenerResults), nil
}

func (m *Manager) recoverActivation(ctx context.Context) error {
	journal, err := m.store.loadActivationJournal()
	if err != nil || journal == nil {
		return err
	}
	active, err := m.store.loadActive()
	if err != nil {
		return err
	}
	current, err := m.store.currentVersionDir()
	if err != nil {
		return err
	}
	if sameActiveRecord(active, &journal.Candidate) {
		if current != journal.Candidate.VersionDir {
			if err := m.store.switchCurrent(journal.Candidate.VersionDir); err != nil {
				return err
			}
		}
		return m.store.clearActivationJournal()
	}
	if !sameActiveRecord(active, journal.Previous) ||
		(current != "" && current != journal.Candidate.VersionDir &&
			(journal.Previous == nil || current != journal.Previous.VersionDir)) {
		return ErrCorruptState
	}
	if journal.Previous == nil {
		if current == journal.Candidate.VersionDir {
			if err := m.runtime.Stop(ctx, m.store.currentPath); err != nil {
				return fmt.Errorf("recover unconfirmed initial L4 activation: %w", err)
			}
		}
		if err := m.store.clearCurrent(); err != nil {
			return err
		}
	} else {
		if _, err := m.restore(ctx, journal.Previous); err != nil {
			return fmt.Errorf("recover L4 last known good: %w", err)
		}
	}
	return m.store.clearActivationJournal()
}

func (m *Manager) restoreWithTimeout(previous *activeRecord) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return m.restore(ctx, previous)
}

func (m *Manager) Status() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active, err := m.store.loadActive()
	if err != nil {
		return Status{}, err
	}
	if active == nil {
		return Status{}, nil
	}
	return Status{Active: true, VersionID: active.VersionID, Digest: active.Digest, AppliedAt: active.AppliedAt}, nil
}

func (m *Manager) restore(ctx context.Context, previous *activeRecord) (bool, error) {
	if previous == nil {
		if err := m.runtime.Stop(ctx, m.store.currentPath); err != nil {
			return false, err
		}
		if err := m.store.clearCurrent(); err != nil {
			return false, err
		}
		return true, nil
	}
	compiled, versionDir, err := m.store.loadVersion(previous.VersionID, previous.Digest)
	if err != nil || versionDir != previous.VersionDir {
		return false, errors.Join(ErrCorruptState, err)
	}
	if err := m.store.switchCurrent(previous.VersionDir); err != nil {
		return false, err
	}
	if err := m.activate(ctx, compiled.Config); err != nil {
		return false, err
	}
	if err := m.healthy(ctx, compiled); err != nil {
		return false, err
	}
	return true, nil
}

func transitionDrainTimeoutMS(previous *Config, candidate Config) int {
	if len(candidate.Listeners) == 0 && candidate.DrainTimeoutMS == 0 && previous != nil {
		return previous.DrainTimeoutMS
	}
	return candidate.DrainTimeoutMS
}

// activate reloads the runtime onto the current version. The generation it
// retires drains under config's limit.
func (m *Manager) activate(ctx context.Context, config Config) error {
	if runtime, ok := m.runtime.(drainLimitRuntime); ok {
		if err := runtime.SetDrainLimit(drainLimit(config.DrainMaxMS)); err != nil {
			return err
		}
	}
	return m.runtime.Activate(ctx, m.store.currentPath)
}

func (m *Manager) drain(ctx context.Context, timeoutMS int) error {
	if timeoutMS == 0 {
		return nil
	}
	runtime, ok := m.runtime.(drainRuntime)
	if !ok {
		return errors.New("L4 runtime does not support graceful drain")
	}
	return runtime.Drain(ctx, time.Duration(timeoutMS)*time.Millisecond)
}

func (m *Manager) loadActiveConfig(active *activeRecord) (*Config, error) {
	if active == nil {
		return nil, nil
	}
	compiled, versionDir, err := m.store.loadVersion(active.VersionID, active.Digest)
	if err != nil || versionDir != active.VersionDir {
		return nil, errors.Join(ErrCorruptState, err)
	}
	return &compiled.Config, nil
}

func listenerLifecycle(previous *Config, candidate Config) []ListenerResult {
	previousListeners := make(map[string]Listener)
	previousPools := make(map[string]UpstreamPool)
	if previous != nil {
		previousListeners = make(map[string]Listener, len(previous.Listeners))
		previousPools = make(map[string]UpstreamPool, len(previous.UpstreamPools))
		for _, listener := range previous.Listeners {
			previousListeners[listener.ID] = listener
		}
		for _, pool := range previous.UpstreamPools {
			previousPools[pool.ID] = pool
		}
	}
	candidateListeners := make(map[string]Listener, len(candidate.Listeners))
	candidatePools := make(map[string]UpstreamPool, len(candidate.UpstreamPools))
	ids := make(map[string]struct{}, len(previousListeners)+len(candidate.Listeners))
	for id := range previousListeners {
		ids[id] = struct{}{}
	}
	for _, listener := range candidate.Listeners {
		candidateListeners[listener.ID] = listener
		ids[listener.ID] = struct{}{}
	}
	for _, pool := range candidate.UpstreamPools {
		candidatePools[pool.ID] = pool
	}
	orderedIDs := make([]string, 0, len(ids))
	for id := range ids {
		orderedIDs = append(orderedIDs, id)
	}
	sort.Strings(orderedIDs)

	results := make([]ListenerResult, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		before, existed := previousListeners[id]
		after, exists := candidateListeners[id]
		switch {
		case !existed:
			results = append(results, ListenerResult{ID: id, Operation: ListenerOperationCreate, ReasonCode: ListenerReasonCreated})
		case !exists:
			results = append(results, ListenerResult{ID: id, Operation: ListenerOperationDelete, ReasonCode: ListenerReasonDeleted})
		case before.Disabled != after.Disabled:
			if after.Disabled {
				results = append(results, ListenerResult{ID: id, Operation: ListenerOperationDisable, ReasonCode: ListenerReasonDisabled})
			} else {
				results = append(results, ListenerResult{ID: id, Operation: ListenerOperationEnable, ReasonCode: ListenerReasonEnabled})
			}
		case !reflect.DeepEqual(before, after) ||
			!reflect.DeepEqual(previousPools[before.UpstreamPoolID], candidatePools[after.UpstreamPoolID]):
			results = append(results, ListenerResult{ID: id, Operation: ListenerOperationEdit, ReasonCode: ListenerReasonEdited})
		}
	}
	return results
}

func appliedResult(active *activeRecord, listenerResults []ListenerResult) Result {
	return Result{
		VersionID: active.VersionID, Digest: active.Digest, State: StateApplied,
		ActiveVersionID: active.VersionID, ActiveDigest: active.Digest,
		RunningVersionUnchanged: false, ListenerResults: listenerResults, AppliedAt: active.AppliedAt,
	}
}

func failedResult(compiled CompiledConfig, active *activeRecord, code string, unchanged bool, listenerResults []ListenerResult, cause error) Result {
	result := Result{
		VersionID: compiled.Config.VersionID, Digest: compiled.Digest, State: StateFailed,
		ErrorCode: code, RunningVersionUnchanged: unchanged,
		ListenerResults: failedListenerResults(listenerResults, cause),
	}
	if active != nil {
		result.ActiveVersionID = active.VersionID
		result.ActiveDigest = active.Digest
	}
	return result
}

func failedListenerResults(listenerResults []ListenerResult, cause error) []ListenerResult {
	if len(listenerResults) == 0 {
		return nil
	}
	failed := make([]ListenerResult, len(listenerResults))
	copy(failed, listenerResults)
	for index := range failed {
		failed[index].ReasonCode = ListenerReasonApplyAborted
	}
	var listenerCause interface {
		ListenerID() string
		ReasonCode() string
	}
	if !errors.As(cause, &listenerCause) || listenerCause.ListenerID() == "" || listenerCause.ReasonCode() == "" {
		return failed
	}
	for index := range failed {
		if failed[index].ID == listenerCause.ListenerID() {
			failed[index].ReasonCode = listenerCause.ReasonCode()
			break
		}
	}
	return failed
}
