package acmehttp01

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

type Probe interface {
	Check(context.Context, string, string, *string) error
}

type Config struct {
	ProbeAddress   string
	RequestTimeout time.Duration
	Probe          Probe
	Now            func() time.Time
	// RuntimeConfigPaths are the rendered nginx.conf files consulted, in
	// order, when deployment_root/current carries none: a site runtime v2
	// release is rendered into the site runtime's own current release.
	RuntimeConfigPaths []string
}

func DefaultConfig() Config {
	return Config{ProbeAddress: "127.0.0.1:80", RequestTimeout: 2 * time.Second, Now: time.Now}
}

type Manager struct {
	mu         sync.Mutex
	store      *diskStore
	probe      Probe
	now        func() time.Time
	afterPhase func(executionPhase) error
}

func NewManager(deploymentRoot string) (*Manager, error) {
	return NewManagerWithConfig(deploymentRoot, DefaultConfig())
}

func NewManagerWithConfig(deploymentRoot string, config Config) (*Manager, error) {
	if config.Now == nil || config.RequestTimeout <= 0 {
		return nil, ErrInvalidStateRoot
	}
	probe := config.Probe
	if probe == nil {
		var err error
		probe, err = newHTTPProbe(config.ProbeAddress, config.RequestTimeout)
		if err != nil {
			return nil, err
		}
	}
	for _, path := range config.RuntimeConfigPaths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrInvalidStateRoot
		}
	}
	store, err := newDiskStore(deploymentRoot)
	if err != nil {
		return nil, err
	}
	store.runtimeConfigs = append([]string(nil), config.RuntimeConfigPaths...)
	return &Manager{store: store, probe: probe, now: config.Now}, nil
}

func (m *Manager) Ready() bool {
	if m == nil || m.store == nil || !m.store.ready() {
		return false
	}
	_, _, err := m.store.current()
	return err == nil
}

func (m *Manager) Current() (Pointer, error) {
	if m == nil || m.store == nil {
		return Pointer{}, ErrCorruptState
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pointer, _, err := m.store.current()
	return pointer, err
}

func (m *Manager) Apply(ctx context.Context, command Command) (Result, error) {
	if m == nil || m.store == nil || m.probe == nil || m.now == nil {
		return Result{}, ErrCorruptState
	}
	now := m.now().UTC()
	if err := validateCommandStructure(command); err != nil {
		return Result{}, err
	}
	if !m.Ready() {
		return Result{}, ErrRouteUnavailable
	}
	operationBase := ctx
	cancelDeadline := func() {}
	if command.Deadline.After(now) {
		operationBase, cancelDeadline = context.WithDeadline(ctx, command.Deadline.UTC())
	}
	defer cancelDeadline()
	operationCtx, cancelTimeout := context.WithTimeout(operationBase, command.Health.ActivationTimeout)
	defer cancelTimeout()

	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(operationCtx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()

	value, err := m.store.loadJournal(command.DeploymentID)
	if err != nil {
		return Result{}, err
	}
	attemptCount := len(value.Attempts)
	record, err := prepareAttempt(&value, command)
	if err != nil {
		return Result{}, err
	}
	if len(value.Attempts) != attemptCount {
		if err := validateCommand(command, now); err != nil {
			return Result{}, err
		}
	}
	if record.Phase == phaseDone {
		return resultFromRecord(command.DeploymentID, *record, m.store)
	}
	if err := m.store.saveJournal(value); err != nil {
		return Result{}, err
	}

	for {
		switch record.Phase {
		case phaseStage:
			if !command.Deadline.After(m.now().UTC()) {
				return m.failBeforeActivation(&value, record, command, "EXPIRED", "overlay command expired before staging", ErrExpired)
			}
			if err := ValidateSnapshot(command.Snapshot, m.now().UTC()); err != nil {
				return m.failBeforeActivation(&value, record, command, "INVALID_ARTIFACT", "overlay snapshot validation failed", err)
			}
			if err := m.store.stage(command.Snapshot, command.ArtifactSHA256); err != nil {
				return m.failBeforeActivation(&value, record, command, "INVALID_ARTIFACT", "overlay artifact staging failed", err)
			}
			appendTransition(record, StateStaged, m.now(), "OK", "overlay artifact staged", true)
			record.Phase = phasePrecheck
			if err := m.persistPhase(&value, record.Phase); err != nil {
				return Result{}, err
			}
		case phasePrecheck:
			if !command.Deadline.After(m.now().UTC()) {
				return m.failBeforeActivation(&value, record, command, "EXPIRED", "overlay command expired before precheck", ErrExpired)
			}
			if err := ValidateSnapshot(command.Snapshot, m.now().UTC()); err != nil {
				return m.failBeforeActivation(&value, record, command, "INVALID_ARTIFACT", "overlay snapshot validation failed", err)
			}
			if !m.store.ready() {
				return m.failBeforeActivation(&value, record, command, "PRECHECK_FAILED", "managed challenge route is unavailable", ErrRouteUnavailable)
			}
			if err := m.store.verifyRelease(m.store.releasePath(command.OverlayVersionID), command.Snapshot, command.ArtifactSHA256); err != nil {
				return m.failBeforeActivation(&value, record, command, "PRECHECK_FAILED", "overlay release precheck failed", err)
			}
			appendTransition(record, StatePrechecked, m.now(), "OK", "overlay release precheck passed", true)
			record.Phase = phaseActivate
			if err := m.persistPhase(&value, record.Phase); err != nil {
				return Result{}, err
			}
		case phaseActivate:
			if !command.Deadline.After(m.now().UTC()) {
				current, _, currentErr := m.store.current()
				target := Pointer{VersionID: command.OverlayVersionID, Revision: command.OverlayRevision, SHA256: hex.EncodeToString(command.ArtifactSHA256[:])}
				if currentErr != nil {
					return Result{}, currentErr
				}
				if current != target {
					return m.failBeforeActivation(&value, record, command, "EXPIRED", "overlay command expired before activation", ErrExpired)
				}
			}
			if err := m.activate(&value, record, command); err != nil {
				return m.failBeforeActivation(&value, record, command, "ACTIVATION_FAILED", "overlay activation failed", err)
			}
			appendTransition(record, StateActivated, m.now(), "OK", "overlay version activated", false)
			record.Phase = phaseHealth
			if err := m.persistPhase(&value, record.Phase); err != nil {
				return Result{}, err
			}
		case phaseHealth:
			priorSnapshot, err := m.snapshotFor(record.PriorPointer)
			if err != nil {
				return Result{}, err
			}
			if err := m.observe(operationCtx, command.Snapshot, priorSnapshot, command.Health); err == nil {
				appendTransition(record, StateHealthy, m.now(), "OK", "overlay activation is healthy", false)
				record.Phase = phaseDone
				if err := m.persistPhase(&value, record.Phase); err != nil {
					return Result{}, err
				}
				return resultFromRecord(command.DeploymentID, *record, m.store)
			}
			appendTransition(record, StateReverting, m.now(), "HEALTH_FAILED", "overlay health check failed; reverting", false)
			record.Phase = phaseRollback
			if err := m.persistPhase(&value, record.Phase); err != nil {
				return Result{}, err
			}
		case phaseRollback:
			return m.rollback(&value, record, command)
		default:
			return Result{}, ErrCorruptState
		}
	}
}

func prepareAttempt(value *journal, command Command) (*attemptRecord, error) {
	commandDigest := hex.EncodeToString(command.CommandSHA256[:])
	artifactDigest := hex.EncodeToString(command.ArtifactSHA256[:])
	var highest uint32
	for index := range value.Attempts {
		record := &value.Attempts[index]
		if record.Attempt > highest {
			highest = record.Attempt
		}
		if record.Attempt != command.Attempt {
			continue
		}
		if record.CommandSHA256 != commandDigest || record.ArtifactSHA256 != artifactDigest ||
			record.OverlayVersionID != command.OverlayVersionID || record.OverlayRevision != command.OverlayRevision ||
			record.PreviousVersionID != optionalString(command.PreviousVersionID) || record.PreviousRevision != optionalUint64(command.PreviousRevision) {
			return nil, ErrConflict
		}
		return record, nil
	}
	if command.Attempt <= highest {
		return nil, ErrStaleAttempt
	}
	value.Attempts = append(value.Attempts, attemptRecord{
		Attempt: command.Attempt, CommandSHA256: commandDigest, ArtifactSHA256: artifactDigest,
		OverlayVersionID: command.OverlayVersionID, OverlayRevision: command.OverlayRevision,
		PreviousVersionID: optionalString(command.PreviousVersionID), PreviousRevision: optionalUint64(command.PreviousRevision),
		Phase: phaseStage,
	})
	return &value.Attempts[len(value.Attempts)-1], nil
}

func (m *Manager) activate(value *journal, record *attemptRecord, command Command) error {
	current, _, err := m.store.current()
	if err != nil {
		return err
	}
	target := Pointer{VersionID: command.OverlayVersionID, Revision: command.OverlayRevision, SHA256: hex.EncodeToString(command.ArtifactSHA256[:])}
	if target.Revision < current.Revision {
		return ErrStaleAttempt
	}
	if target.Revision == current.Revision {
		if current != target {
			return ErrConflict
		}
		if !record.PriorPointerSet {
			record.PriorPointerSet = true
			record.PriorPointer = current
			return m.store.saveJournal(*value)
		}
		return nil
	}
	if !record.PriorPointerSet {
		if err := validateBaseline(current, command); err != nil {
			return err
		}
		record.PriorPointerSet = true
		record.PriorPointer = current
		if err := m.store.saveJournal(*value); err != nil {
			return err
		}
	} else if current != record.PriorPointer {
		return ErrConflict
	}
	return m.store.switchCurrent(target)
}

func validateBaseline(current Pointer, command Command) error {
	if command.PreviousVersionID != nil && current.Revision == *command.PreviousRevision && current.VersionID != *command.PreviousVersionID {
		return ErrConflict
	}
	return nil
}

func (m *Manager) observe(ctx context.Context, current, prior Snapshot, policy HealthPolicy) error {
	removed := removedEntries(prior.Entries, current.Entries)
	consecutive := uint32(0)
	started := m.now()
	interval := 10 * time.Millisecond
	if policy.ObservationWindow > 0 {
		interval = policy.ObservationWindow / time.Duration(policy.RequiredConsecutiveSuccesses)
		if interval < 10*time.Millisecond {
			interval = 10 * time.Millisecond
		}
	}
	for {
		if err := ValidateSnapshot(current, m.now().UTC()); err != nil && len(current.Entries) > 0 {
			return err
		}
		err := m.checkEntries(ctx, current.Entries, removed)
		if err == nil {
			consecutive++
			if consecutive >= policy.RequiredConsecutiveSuccesses && m.now().Sub(started) >= policy.ObservationWindow {
				return nil
			}
		} else {
			consecutive = 0
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrHealthFailed
		case <-timer.C:
		}
	}
}

func (m *Manager) checkEntries(ctx context.Context, current, removed []Entry) error {
	for _, entry := range current {
		expected := entry.Value
		if err := m.probe.Check(ctx, entry.Host, entry.Token, &expected); err != nil {
			return ErrHealthFailed
		}
	}
	for _, entry := range removed {
		if err := m.probe.Check(ctx, entry.Host, entry.Token, nil); err != nil {
			return ErrHealthFailed
		}
	}
	return nil
}

func (m *Manager) rollback(value *journal, record *attemptRecord, command Command) (Result, error) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 10*time.Second)
	defer cancel()
	if err := m.store.switchCurrent(record.PriorPointer); err != nil {
		appendTransition(record, StateRollbackFailed, m.now(), "ROLLBACK_FAILED", "overlay rollback failed", false)
		record.Phase = phaseDone
		_ = m.store.saveJournal(*value)
		result, _ := resultFromRecord(command.DeploymentID, *record, m.store)
		return result, errors.Join(ErrRollbackFailed, err)
	}
	priorSnapshot, err := m.snapshotFor(record.PriorPointer)
	if err == nil {
		err = m.observe(rollbackCtx, priorSnapshot, command.Snapshot, HealthPolicy{ActivationTimeout: 10 * time.Second, RequiredConsecutiveSuccesses: 1})
	}
	if err != nil {
		appendTransition(record, StateRollbackFailed, m.now(), "ROLLBACK_FAILED", "overlay rollback verification failed", false)
		record.Phase = phaseDone
		_ = m.store.saveJournal(*value)
		result, _ := resultFromRecord(command.DeploymentID, *record, m.store)
		return result, errors.Join(ErrRollbackFailed, err)
	}
	appendTransition(record, StateReverted, m.now(), "ROLLED_BACK", "previous overlay restored", false)
	record.Phase = phaseDone
	if err := m.persistPhase(value, record.Phase); err != nil {
		return Result{}, err
	}
	result, _ := resultFromRecord(command.DeploymentID, *record, m.store)
	return result, ErrHealthFailed
}

func (m *Manager) failBeforeActivation(value *journal, record *attemptRecord, command Command, code, summary string, cause error) (Result, error) {
	appendTransition(record, StateFailed, m.now(), code, summary, true)
	record.Phase = phaseDone
	if err := m.persistPhase(value, record.Phase); err != nil {
		return Result{}, err
	}
	result, _ := resultFromRecord(command.DeploymentID, *record, m.store)
	return result, cause
}

func (m *Manager) persistPhase(value *journal, phase executionPhase) error {
	if err := m.store.saveJournal(*value); err != nil {
		return err
	}
	if m.afterPhase != nil {
		return m.afterPhase(phase)
	}
	return nil
}

func (m *Manager) snapshotFor(pointer Pointer) (Snapshot, error) {
	if pointer.VersionID == "" {
		return Snapshot{SchemaVersion: ArtifactSchemaVersion, GeneratedAt: m.now()}, nil
	}
	_, snapshot, err := m.store.loadRelease(pointer.VersionID)
	return snapshot, err
}

func resultFromRecord(deploymentID string, record attemptRecord, store *diskStore) (Result, error) {
	active, _, err := store.current()
	if err != nil {
		return Result{}, err
	}
	result := Result{
		DeploymentID: deploymentID, Attempt: record.Attempt, VersionID: record.OverlayVersionID,
		Revision: record.OverlayRevision, Active: active,
	}
	result.Transitions = make([]Transition, len(record.Transitions))
	for index, transition := range record.Transitions {
		result.Transitions[index] = Transition{
			Sequence: transition.Sequence, State: transition.State, At: transition.At,
			ResultCode: transition.ResultCode, Summary: transition.Summary, ActiveUnchanged: transition.ActiveUnchanged,
		}
	}
	if len(result.Transitions) > 0 {
		result.State = result.Transitions[len(result.Transitions)-1].State
	}
	switch result.State {
	case StateHealthy:
		return result, nil
	case StateReverted:
		return result, ErrHealthFailed
	case StateRollbackFailed:
		return result, ErrRollbackFailed
	case StateFailed:
		return result, errorForCode(result.Transitions[len(result.Transitions)-1].ResultCode)
	default:
		return result, ErrCorruptState
	}
}

func appendTransition(record *attemptRecord, state State, at time.Time, code, summary string, unchanged bool) {
	record.Transitions = append(record.Transitions, persistedTransition{
		Sequence: uint64(len(record.Transitions) + 2), State: state, At: at.UTC(),
		ResultCode: code, Summary: summary, ActiveUnchanged: unchanged,
	})
}

func removedEntries(prior, current []Entry) []Entry {
	present := make(map[string]struct{}, len(current))
	for _, entry := range current {
		present[entry.Host+"\x00"+entry.Token] = struct{}{}
	}
	removed := make([]Entry, 0)
	for _, entry := range prior {
		if _, exists := present[entry.Host+"\x00"+entry.Token]; !exists {
			removed = append(removed, entry)
		}
	}
	return removed
}

func errorForCode(code string) error {
	switch code {
	case "INVALID_ARTIFACT":
		return ErrInvalidSnapshot
	case "EXPIRED":
		return ErrExpired
	case "PRECHECK_FAILED":
		return ErrPrecheckFailed
	case "ACTIVATION_FAILED":
		return ErrActivationFailed
	default:
		return ErrConflict
	}
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func optionalUint64(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func digestCommand(parts ...string) [sha256.Size]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%q", parts)))
}
