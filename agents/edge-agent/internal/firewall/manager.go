package firewall

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

type Manager struct {
	mu               sync.Mutex
	store            *diskStore
	runner           Runner
	now              func() time.Time
	saveActive       func(activeRecord) error
	afterJournalSync func() error
	afterKernelApply func() error
	// ownerScopeID owns the node (SetOwnerScope); "" until learned: no
	// tenant owns it, so tenant host rules are refused (owner.go).
	ownerScopeID string
	// admitAllTenants lifts the owner gate (package tests of the manager's
	// CAS and recovery mechanics, which use several tenants on one node).
	admitAllTenants bool
}

func NewManager(stateRoot, nftBinary string) (*Manager, error) {
	runner, err := newSystemRunner(nftBinary)
	if err != nil {
		return nil, err
	}
	return NewManagerWithDependencies(stateRoot, runner, time.Now)
}

func NewManagerWithDependencies(stateRoot string, runner Runner, now func() time.Time) (*Manager, error) {
	if runner == nil || now == nil {
		return nil, ErrInvalidVersion
	}
	store, err := newDiskStore(stateRoot)
	if err != nil {
		return nil, err
	}
	manager := &Manager{store: store, runner: runner, now: now, saveActive: store.saveActive}
	if err := manager.Recover(context.Background()); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *Manager) Apply(ctx context.Context, version FirewallVersion) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if version.TenantID != "" || version.SiteID != "" {
		return m.applyScopedLocked(ctx, version)
	}
	return m.applyLocked(ctx, version)
}

func (m *Manager) Probe(ctx context.Context) error {
	if _, err := m.runner.Run(ctx, "--json", "list", "ruleset"); err != nil {
		return ErrUnsupported
	}
	return nil
}

func (m *Manager) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	inflight, err := m.store.loadInflight()
	if err != nil || inflight == nil {
		return err
	}
	if inflight.Command.TenantID == "" && inflight.Command.SiteID == "" && !inflight.Command.Aggregate {
		return m.recoverLegacyLocked(ctx, inflight)
	}
	return m.recoverScopedLocked(ctx, inflight)
}

func (m *Manager) ScopeStatus(ctx context.Context, tenantID, siteID string) (ScopeStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return ScopeStatus{}, err
	}
	defer unlock()
	active, err := m.store.loadActive()
	if err != nil || active == nil {
		return ScopeStatus{}, err
	}
	for _, scope := range active.Scopes {
		if scope.TenantID == tenantID && scope.SiteID == siteID {
			return ScopeStatus{
				TenantID: scope.TenantID, SiteID: scope.SiteID, PolicyKind: scope.PolicyKind, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion,
				TaskRevision: scope.TaskRevision, EntryCount: len(scope.Entries),
			}, nil
		}
	}
	return ScopeStatus{}, nil
}

// ScopeEntries returns the policy version and entries of one applied scope
// (zero and none when it was never applied).
func (m *Manager) ScopeEntries(ctx context.Context, tenantID, siteID, policyKind, policyID string) (uint64, []Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer unlock()
	active, err := m.store.loadActive()
	if err != nil || active == nil {
		return 0, nil, err
	}
	for _, scope := range active.Scopes {
		if sameScopeIdentity(scope, tenantID, siteID, policyKind, policyID) {
			return scope.PolicyVersion, append([]Entry(nil), scope.Entries...), nil
		}
	}
	return 0, nil, nil
}

func (m *Manager) applyScopedLocked(ctx context.Context, version FirewallVersion) (Result, error) {
	if !firewallIDPattern.MatchString(version.TaskID) {
		return Result{}, ErrInvalidVersion
	}
	existingTask, err := m.store.loadTask(version.TaskID)
	if err != nil {
		return Result{}, err
	}
	if existingTask != nil {
		_, digest, normalizeErr := normalize(version)
		if normalizeErr != nil || existingTask.Digest != digest {
			return Result{}, ErrConflict
		}
		return existingTask.Result, nil
	}
	previous, err := m.store.loadActive()
	if err != nil {
		return Result{}, err
	}
	currentPolicy := scopePolicyVersion(previous, version.TenantID, version.SiteID, version.PolicyKind, version.PolicyID)
	if version.PolicyVersion <= currentPolicy {
		return Result{}, ErrPolicyVersionRegression
	}
	if version.ExpectedActivePolicyVersion != currentPolicy {
		return Result{}, ErrActiveVersionConflict
	}
	normalized, digest, err := normalize(version)
	if err != nil {
		return Result{}, err
	}
	if existing, err := m.store.loadTaskByIdempotency(normalized.IdempotencyKey); err != nil {
		return Result{}, err
	} else if existing != nil {
		return Result{}, ErrConflict
	}
	now := m.now().UTC()
	for _, entry := range normalized.Entries {
		if entry.ExpiresAt != nil && !entry.ExpiresAt.After(now) {
			return Result{}, ErrExpiredEntry
		}
	}
	if !m.admitsScope(normalized.TenantID, normalized.PolicyKind, normalized.Entries) {
		return m.finishScoped(normalized, digest, previous, StateFailed, ErrorCodeSharedNodeHostRule, true, currentPolicy, time.Time{})
	}
	candidate, compiled, err := scopedCandidate(previous, normalized, now)
	if err != nil {
		return Result{}, err
	}
	if err := m.store.saveVersion(compiled); err != nil {
		return Result{}, err
	}
	path, err := m.store.writeBatch(normalized.TaskID, compiled.Batch)
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(path)
	if _, err := m.runner.Run(ctx, "--check", "--file", path); err != nil {
		return m.finishScoped(normalized, digest, previous, StateFailed, "CHECK_FAILED", true, currentPolicy, time.Time{})
	}
	inflight := inflightRecord{
		SchemaVersion: stateSchemaVersion, Digest: digest, Command: normalized,
		Candidate: candidate, Previous: previous, StartedAt: now,
	}
	if err := m.store.saveInflight(inflight); err != nil {
		return Result{}, err
	}
	if m.afterJournalSync != nil {
		if err := m.afterJournalSync(); err != nil {
			return Result{}, err
		}
	}
	if _, err := m.runner.Run(ctx, "--file", path); err != nil {
		if rollbackErr := m.rollback(ctx, normalized.TaskID, previous); rollbackErr != nil {
			return m.finishScoped(normalized, digest, previous, StateRollbackFailed, "ROLLBACK_FAILED", false, 0, time.Time{})
		}
		return m.finishScoped(normalized, digest, previous, StateRolledBack, "APPLY_FAILED", true, currentPolicy, time.Time{})
	}
	if m.afterKernelApply != nil {
		if err := m.afterKernelApply(); err != nil {
			return Result{}, err
		}
	}
	if err := m.confirm(ctx, candidate.Version.VersionID, candidate.Digest); err != nil {
		if rollbackErr := m.rollback(ctx, normalized.TaskID, previous); rollbackErr != nil {
			return m.finishScoped(normalized, digest, previous, StateRollbackFailed, "ROLLBACK_FAILED", false, 0, time.Time{})
		}
		return m.finishScoped(normalized, digest, previous, StateRolledBack, "HEALTH_FAILED", true, currentPolicy, time.Time{})
	}
	if err := m.saveActive(candidate); err != nil {
		if rollbackErr := m.rollback(ctx, normalized.TaskID, previous); rollbackErr != nil {
			return m.finishScoped(normalized, digest, previous, StateRollbackFailed, "ROLLBACK_FAILED", false, 0, time.Time{})
		}
		return m.finishScoped(normalized, digest, previous, StateRolledBack, "STATE_COMMIT_FAILED", true, currentPolicy, time.Time{})
	}
	return m.finishScoped(normalized, digest, &candidate, StateApplied, "", false, normalized.PolicyVersion, now)
}

func scopedCandidate(previous *activeRecord, command FirewallVersion, now time.Time) (activeRecord, CompiledVersion, error) {
	scopes := make([]scopeRecord, 0, 1)
	if previous != nil {
		scopes = append(scopes, previous.Scopes...)
	}
	next := scopeRecord{
		TenantID: command.TenantID, SiteID: command.SiteID, PolicyKind: command.PolicyKind, PolicyID: command.PolicyID, PolicyVersion: command.PolicyVersion,
		TaskRevision: command.TaskRevision, IdempotencyKey: command.IdempotencyKey,
		CommandDigest: command.CommandDigest, Entries: append([]Entry(nil), command.Entries...), AppliedAt: now,
	}
	replaced := false
	for index := range scopes {
		if sameScopeIdentity(scopes[index], command.TenantID, command.SiteID, command.PolicyKind, command.PolicyID) {
			scopes[index] = next
			replaced = true
			break
		}
	}
	if !replaced {
		scopes = append(scopes, next)
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].TenantID != scopes[j].TenantID {
			return scopes[i].TenantID < scopes[j].TenantID
		}
		if scopes[i].SiteID != scopes[j].SiteID {
			return scopes[i].SiteID < scopes[j].SiteID
		}
		if scopes[i].PolicyKind != scopes[j].PolicyKind {
			return scopes[i].PolicyKind < scopes[j].PolicyKind
		}
		return scopes[i].PolicyID < scopes[j].PolicyID
	})
	entries := make([]Entry, 0)
	for _, scope := range scopes {
		for _, entry := range scope.Entries {
			entries = append(entries, entry)
		}
	}
	runtime := FirewallVersion{
		TaskID: command.TaskID, VersionID: "runtime-" + command.IdempotencyKey,
		Entries: entries, Aggregate: true,
	}
	compiled, err := Compile(runtime)
	if err != nil {
		return activeRecord{}, CompiledVersion{}, err
	}
	return activeRecord{
		SchemaVersion: stateSchemaVersion, Digest: compiled.Digest, AppliedAt: now,
		Version: compiled.Version, Scopes: scopes,
	}, compiled, nil
}

func scopePolicyVersion(active *activeRecord, tenantID, siteID, policyKind, policyID string) uint64 {
	if active == nil {
		return 0
	}
	for _, scope := range active.Scopes {
		if sameScopeIdentity(scope, tenantID, siteID, policyKind, policyID) {
			return scope.PolicyVersion
		}
	}
	return 0
}

func sameScopeIdentity(scope scopeRecord, tenantID, siteID, policyKind, policyID string) bool {
	return scope.TenantID == tenantID && scope.SiteID == siteID && scope.PolicyKind == policyKind && scope.PolicyID == policyID
}

func (m *Manager) finishScoped(command FirewallVersion, digest string, active *activeRecord, state ApplyState, code string, unchanged bool, activePolicy uint64, appliedAt time.Time) (Result, error) {
	result := Result{
		TaskID: command.TaskID, TaskRevision: command.TaskRevision, IdempotencyKey: command.IdempotencyKey,
		TenantID: command.TenantID, SiteID: command.SiteID, PolicyVersion: command.PolicyVersion,
		ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion,
		VersionID:                   command.VersionID, Digest: digest, State: state, ActivePolicyVersion: activePolicy,
		ErrorCode: code, RunningVersionUnchanged: unchanged, AppliedAt: appliedAt,
	}
	if active != nil {
		result.ActiveVersionID = active.Version.VersionID
	}
	if err := m.store.saveTask(command.TaskID, digest, result); err != nil {
		return Result{}, err
	}
	if state == StateRollbackFailed {
		return result, nil
	}
	if err := m.store.clearInflight(); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (m *Manager) recoverScopedLocked(ctx context.Context, inflight *inflightRecord) error {
	if task, err := m.store.loadTask(inflight.Command.TaskID); err != nil {
		return err
	} else if task != nil {
		if task.Digest != inflight.Digest {
			return ErrConflict
		}
		if task.Result.State != StateRollbackFailed {
			return m.store.clearInflight()
		}
	}
	if matches, err := m.matches(ctx, inflight.Candidate.Version.VersionID, inflight.Candidate.Digest); err == nil && matches {
		if err := m.saveActive(inflight.Candidate); err != nil {
			return err
		}
		_, err = m.finishScoped(
			inflight.Command, inflight.Digest, &inflight.Candidate, StateApplied, "", false,
			inflight.Command.PolicyVersion, inflight.StartedAt,
		)
		return err
	}
	if inflight.Previous != nil {
		if matches, err := m.matches(ctx, inflight.Previous.Version.VersionID, inflight.Previous.Digest); err == nil && matches {
			if err := m.saveActive(*inflight.Previous); err != nil {
				return err
			}
			_, err = m.finishScoped(
				inflight.Command, inflight.Digest, inflight.Previous, StateFailed, "RECOVERY_NOT_APPLIED", true,
				scopePolicyVersion(inflight.Previous, inflight.Command.TenantID, inflight.Command.SiteID, inflight.Command.PolicyKind, inflight.Command.PolicyID), time.Time{},
			)
			return err
		}
	}
	if err := m.rollback(ctx, inflight.Command.TaskID, inflight.Previous); err != nil {
		_, finishErr := m.finishScoped(inflight.Command, inflight.Digest, nil, StateRollbackFailed, "ROLLBACK_FAILED", false, 0, time.Time{})
		return finishErr
	}
	if inflight.Previous != nil {
		if err := m.saveActive(*inflight.Previous); err != nil {
			return err
		}
	}
	_, err := m.finishScoped(
		inflight.Command, inflight.Digest, inflight.Previous, StateRolledBack, "RECOVERY_ROLLED_BACK", true,
		scopePolicyVersion(inflight.Previous, inflight.Command.TenantID, inflight.Command.SiteID, inflight.Command.PolicyKind, inflight.Command.PolicyID), time.Time{},
	)
	return err
}

func (m *Manager) matches(ctx context.Context, versionID, digest string) (bool, error) {
	output, err := m.runner.Run(ctx, "--json", "list", "table", TableFamily, TableName)
	if err != nil {
		return false, err
	}
	comment, err := tableComment(output)
	if err != nil {
		return false, err
	}
	return comment == tableVersionComment(versionID, digest), nil
}

func tableComment(output []byte) (string, error) {
	var listing struct {
		Objects []struct {
			Table *struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &listing); err != nil {
		return "", ErrUnhealthy
	}
	for _, object := range listing.Objects {
		if object.Table != nil && object.Table.Family == TableFamily && object.Table.Name == TableName {
			return object.Table.Comment, nil
		}
	}
	return "", ErrUnhealthy
}

func (m *Manager) Expire(ctx context.Context, taskID, versionID string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	active, err := m.store.loadActive()
	if err != nil {
		return Result{}, err
	}
	if active == nil {
		return Result{}, ErrNoActiveVersion
	}
	if !firewallIDPattern.MatchString(taskID) || !firewallIDPattern.MatchString(versionID) {
		return Result{}, ErrInvalidVersion
	}
	if existing, err := m.store.loadTask(taskID); err != nil {
		return Result{}, err
	} else if existing != nil {
		if existing.Result.VersionID != versionID {
			return Result{}, ErrConflict
		}
		return existing.Result, nil
	}
	now := m.now().UTC()
	candidate, compiled, expired, err := expiryCandidate(active, taskID, versionID, now)
	if err != nil {
		return Result{}, err
	}
	if !expired {
		return Result{}, ErrNoExpiredEntry
	}
	return m.replaceActiveLocked(ctx, taskID, active, candidate, compiled, now)
}

func expiryCandidate(previous *activeRecord, taskID, versionID string, now time.Time) (activeRecord, CompiledVersion, bool, error) {
	expired := false
	scopes := make([]scopeRecord, len(previous.Scopes))
	entries := make([]Entry, 0, len(previous.Version.Entries))
	for index, scope := range previous.Scopes {
		scopes[index] = scope
		scopes[index].Entries = make([]Entry, 0, len(scope.Entries))
		for _, entry := range scope.Entries {
			if entry.ExpiresAt != nil && !entry.ExpiresAt.After(now) {
				expired = true
				continue
			}
			scopes[index].Entries = append(scopes[index].Entries, entry)
			entries = append(entries, entry)
		}
	}
	if len(previous.Scopes) == 0 {
		for _, entry := range previous.Version.Entries {
			if entry.ExpiresAt != nil && !entry.ExpiresAt.After(now) {
				expired = true
				continue
			}
			entries = append(entries, entry)
		}
	}
	if !expired {
		return activeRecord{}, CompiledVersion{}, false, nil
	}
	compiled, err := Compile(FirewallVersion{
		TaskID: taskID, VersionID: versionID, Entries: entries, Aggregate: len(previous.Scopes) > 0,
	})
	if err != nil {
		return activeRecord{}, CompiledVersion{}, false, err
	}
	return activeRecord{
		SchemaVersion: stateSchemaVersion, Digest: compiled.Digest, AppliedAt: now,
		Version: compiled.Version, Scopes: scopes,
	}, compiled, true, nil
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	active, err := m.store.loadActive()
	if err != nil {
		return Status{}, err
	}
	if active == nil {
		return Status{}, nil
	}
	status := statusFromActive(active)
	if err := m.confirm(ctx, active.Version.VersionID, active.Digest); err != nil {
		return status, err
	}
	status.Healthy = true
	return status, nil
}

func (m *Manager) applyLocked(ctx context.Context, version FirewallVersion) (Result, error) {
	normalized, digest, err := normalize(version)
	if err != nil {
		return Result{}, err
	}
	existingTask, err := m.store.loadTask(normalized.TaskID)
	if err != nil {
		return Result{}, err
	}
	if existingTask != nil {
		if existingTask.Digest != digest || existingTask.Result.VersionID != normalized.VersionID {
			return Result{}, ErrConflict
		}
		return existingTask.Result, nil
	}
	now := m.now().UTC()
	for _, entry := range normalized.Entries {
		if entry.ExpiresAt != nil && !entry.ExpiresAt.After(now) {
			return Result{}, ErrExpiredEntry
		}
	}
	compiled := compileNormalized(normalized, digest)
	if err := m.store.saveVersion(compiled); err != nil {
		return Result{}, err
	}
	previous, err := m.store.loadActive()
	if err != nil {
		return Result{}, err
	}
	path, err := m.store.writeBatch(normalized.TaskID, compiled.Batch)
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(path)
	if _, err := m.runner.Run(ctx, "--check", "--file", path); err != nil {
		return m.recordFailure(normalized, digest, previous, "CHECK_FAILED", true)
	}
	inflight := inflightRecord{
		SchemaVersion: stateSchemaVersion, Digest: digest, Command: normalized,
		Candidate: activeRecord{
			SchemaVersion: stateSchemaVersion, Digest: digest, AppliedAt: now, Version: normalized,
		},
		Previous: previous, StartedAt: now,
	}
	if err := m.store.saveInflight(inflight); err != nil {
		return Result{}, err
	}
	if m.afterJournalSync != nil {
		if err := m.afterJournalSync(); err != nil {
			return Result{}, err
		}
	}
	if _, err := m.runner.Run(ctx, "--file", path); err != nil {
		if rollbackErr := m.rollback(ctx, normalized.TaskID, previous); rollbackErr != nil {
			return m.recordFailure(normalized, digest, previous, "ROLLBACK_FAILED", false)
		}
		return m.recordFailure(normalized, digest, previous, "APPLY_FAILED", true)
	}
	if m.afterKernelApply != nil {
		if err := m.afterKernelApply(); err != nil {
			return Result{}, err
		}
	}
	if err := m.confirm(ctx, normalized.VersionID, digest); err != nil {
		if rollbackErr := m.rollback(ctx, normalized.TaskID, previous); rollbackErr != nil {
			return m.recordFailure(normalized, digest, previous, "ROLLBACK_FAILED", false)
		}
		return m.recordFailure(normalized, digest, previous, "HEALTH_FAILED", true)
	}
	active := activeRecord{SchemaVersion: stateSchemaVersion, Digest: digest, AppliedAt: now, Version: normalized}
	if err := m.saveActive(active); err != nil {
		if rollbackErr := m.rollback(ctx, normalized.TaskID, previous); rollbackErr != nil {
			return m.recordFailure(normalized, digest, previous, "ROLLBACK_FAILED", false)
		}
		return Result{}, err
	}
	result := Result{
		TaskID: normalized.TaskID, VersionID: normalized.VersionID, Digest: digest, State: StateApplied,
		ActiveVersionID: normalized.VersionID, AppliedAt: now,
	}
	if err := m.store.saveTask(normalized.TaskID, digest, result); err != nil {
		return Result{}, err
	}
	if err := m.store.clearInflight(); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (m *Manager) recordFailure(version FirewallVersion, digest string, previous *activeRecord, code string, unchanged bool) (Result, error) {
	state := StateFailed
	if code == "ROLLBACK_FAILED" {
		state = StateRollbackFailed
	}
	return m.finishLegacy(version, digest, previous, state, code, unchanged, time.Time{})
}

func (m *Manager) finishLegacy(command FirewallVersion, digest string, active *activeRecord, state ApplyState, code string, unchanged bool, appliedAt time.Time) (Result, error) {
	result := Result{
		TaskID: command.TaskID, TaskRevision: command.TaskRevision, IdempotencyKey: command.IdempotencyKey,
		TenantID: command.TenantID, SiteID: command.SiteID, PolicyVersion: command.PolicyVersion,
		ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion,
		VersionID:                   command.VersionID, Digest: digest, State: state, ErrorCode: code,
		RunningVersionUnchanged: unchanged, AppliedAt: appliedAt,
	}
	if active != nil {
		result.ActiveVersionID = active.Version.VersionID
	}
	if err := m.store.saveTask(command.TaskID, digest, result); err != nil {
		return Result{}, err
	}
	if state == StateRollbackFailed {
		return result, nil
	}
	if err := m.store.clearInflight(); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (m *Manager) recoverLegacyLocked(ctx context.Context, inflight *inflightRecord) error {
	if task, err := m.store.loadTask(inflight.Command.TaskID); err != nil {
		return err
	} else if task != nil {
		if task.Digest != inflight.Digest {
			return ErrConflict
		}
		if task.Result.State != StateRollbackFailed {
			return m.store.clearInflight()
		}
	}
	if matches, err := m.matches(ctx, inflight.Candidate.Version.VersionID, inflight.Candidate.Digest); err == nil && matches {
		if err := m.saveActive(inflight.Candidate); err != nil {
			return err
		}
		_, err = m.finishLegacy(
			inflight.Command, inflight.Digest, &inflight.Candidate, StateApplied, "", false, inflight.Candidate.AppliedAt,
		)
		return err
	}
	if inflight.Previous != nil {
		if matches, err := m.matches(ctx, inflight.Previous.Version.VersionID, inflight.Previous.Digest); err == nil && matches {
			if err := m.saveActive(*inflight.Previous); err != nil {
				return err
			}
			_, err = m.finishLegacy(
				inflight.Command, inflight.Digest, inflight.Previous, StateFailed, "RECOVERY_NOT_APPLIED", true, time.Time{},
			)
			return err
		}
	}
	if err := m.rollback(ctx, inflight.Command.TaskID, inflight.Previous); err != nil {
		_, finishErr := m.finishLegacy(inflight.Command, inflight.Digest, nil, StateRollbackFailed, "ROLLBACK_FAILED", false, time.Time{})
		return finishErr
	}
	if inflight.Previous != nil {
		if err := m.saveActive(*inflight.Previous); err != nil {
			return err
		}
	}
	_, err := m.finishLegacy(
		inflight.Command, inflight.Digest, inflight.Previous, StateRolledBack, "RECOVERY_ROLLED_BACK", true, time.Time{},
	)
	return err
}

func (m *Manager) rollback(ctx context.Context, taskID string, previous *activeRecord) error {
	batch := deleteBatch()
	expectedVersion, expectedDigest := "", ""
	if previous != nil {
		batch = compileNormalized(previous.Version, previous.Digest).Batch
		expectedVersion, expectedDigest = previous.Version.VersionID, previous.Digest
	}
	path, err := m.store.writeBatch(taskID+"-rollback", batch)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	if _, err := m.runner.Run(ctx, "--check", "--file", path); err != nil {
		return ErrUnhealthy
	}
	if _, err := m.runner.Run(ctx, "--file", path); err != nil {
		return ErrUnhealthy
	}
	if previous != nil {
		return m.confirm(ctx, expectedVersion, expectedDigest)
	}
	return nil
}

func (m *Manager) confirm(ctx context.Context, versionID, digest string) error {
	output, err := m.runner.Run(ctx, "--json", "list", "table", TableFamily, TableName)
	if err != nil {
		return ErrUnhealthy
	}
	var listing struct {
		Objects []struct {
			Table *struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &listing); err != nil {
		return ErrUnhealthy
	}
	expected := tableVersionComment(versionID, digest)
	for _, object := range listing.Objects {
		if object.Table != nil && object.Table.Family == TableFamily && object.Table.Name == TableName && object.Table.Comment == expected {
			return nil
		}
	}
	return ErrUnhealthy
}

func statusFromActive(active *activeRecord) Status {
	return Status{
		Active: true, VersionID: active.Version.VersionID, TaskID: active.Version.TaskID, Digest: active.Digest,
		AppliedAt: active.AppliedAt, EntryCount: len(active.Version.Entries),
	}
}
