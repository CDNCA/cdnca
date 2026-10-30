package firewall

import (
	"context"
	"os"
	"time"

	"github.com/google/uuid"
)

// Host rules of one scope are a single nftables input chain with no tenant,
// site or destination address in the match (compiler.go), so on a node
// another scope owns they would filter every tenant on the host (A08). The
// manager therefore takes a tenant-scoped entry only when that tenant owns
// the node, or when the entry is port-isolated: a kernel ban on the TCP/UDP
// ports of the tenant's own exclusive listeners (CC/WAF/security_ban under
// exclusive_ports, L4 guard on exclusive streams). Empty versions (recovery,
// withdrawal, expiry) always pass so a rule can always be removed.

// ErrorCodeSharedNodeHostRule is the status code of a rejected tenant host
// rule on a node the tenant does not own.
const ErrorCodeSharedNodeHostRule = "SHARED_NODE_HOST_RULE_REJECTED"

// portIsolatedKinds are the scopes whose entries stay on a shared node when
// every entry names a destination port range.
var portIsolatedKinds = map[string]bool{
	PolicyKindCCBan: true, PolicyKindWAFBan: true, PolicyKindSecurityBan: true, PolicyKindL4Guard: true,
}

// SetOwnerScope records the scope that owns the node (GatewayHello
// node_owner_scope_id; "" or invalid: no tenant owns it) and removes every
// active tenant scope the owner no longer admits.
func (m *Manager) SetOwnerScope(ctx context.Context, ownerScopeID string) error {
	if !canonicalUUID(ownerScopeID) {
		ownerScopeID = ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ownerScopeID = ownerScopeID
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return m.purgeForeignScopesLocked(ctx)
}

// OwnedBy reports whether tenantScopeID owns the node.
func (m *Manager) OwnedBy(tenantScopeID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return tenantScopeID != "" && tenantScopeID == m.ownerScopeID
}

// OwnerScope is the scope that owns the node ("" when no tenant owns it).
func (m *Manager) OwnerScope() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ownerScopeID
}

// admitsScope: may scope tenantID / kind with entries be applied on this node.
func (m *Manager) admitsScope(tenantID, kind string, entries []Entry) bool {
	if len(entries) == 0 || tenantID == "" || tenantID == m.ownerScopeID || m.admitAllTenants {
		return true
	}
	if !portIsolatedKinds[kind] {
		return false
	}
	for _, entry := range entries {
		if (entry.Protocol != ProtocolTCP && entry.Protocol != ProtocolUDP) || entry.PortStart == 0 {
			return false
		}
	}
	return true
}

// purgeForeignScopesLocked rebuilds the active version without the scopes
// admitsScope refuses (stored before the gate or before the owner changed).
func (m *Manager) purgeForeignScopesLocked(ctx context.Context) error {
	active, err := m.store.loadActive()
	if err != nil || active == nil {
		return err
	}
	scopes := make([]scopeRecord, 0, len(active.Scopes))
	entries := make([]Entry, 0, len(active.Version.Entries))
	for _, scope := range active.Scopes {
		if !m.admitsScope(scope.TenantID, scope.PolicyKind, scope.Entries) {
			continue
		}
		scopes = append(scopes, scope)
		entries = append(entries, scope.Entries...)
	}
	if len(scopes) == len(active.Scopes) {
		return nil
	}
	now := m.now().UTC()
	id := "owner-purge-" + uuid.NewString()
	compiled, err := Compile(FirewallVersion{TaskID: id, VersionID: id, Entries: entries, Aggregate: true})
	if err != nil {
		return err
	}
	candidate := activeRecord{SchemaVersion: stateSchemaVersion, Digest: compiled.Digest, AppliedAt: now,
		Version: compiled.Version, Scopes: scopes}
	result, err := m.replaceActiveLocked(ctx, id, active, candidate, compiled, now)
	if err != nil {
		return err
	}
	if result.State != StateApplied {
		return ErrOwnerPurgeFailed
	}
	return nil
}

// replaceActiveLocked journals, checks, applies and confirms candidate in
// place of active (the expiry and owner purge transaction).
func (m *Manager) replaceActiveLocked(ctx context.Context, taskID string, active *activeRecord, candidate activeRecord, compiled CompiledVersion, now time.Time) (Result, error) {
	if err := m.store.saveVersion(compiled); err != nil {
		return Result{}, err
	}
	path, err := m.store.writeBatch(taskID, compiled.Batch)
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(path)
	if _, err := m.runner.Run(ctx, "--check", "--file", path); err != nil {
		return m.finishScoped(compiled.Version, compiled.Digest, active, StateFailed, "CHECK_FAILED", true, 0, time.Time{})
	}
	inflight := inflightRecord{
		SchemaVersion: stateSchemaVersion, Digest: compiled.Digest, Command: compiled.Version,
		Candidate: candidate, Previous: active, StartedAt: now,
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
		if rollbackErr := m.rollback(ctx, taskID, active); rollbackErr != nil {
			return m.finishScoped(compiled.Version, compiled.Digest, active, StateRollbackFailed, "ROLLBACK_FAILED", false, 0, time.Time{})
		}
		return m.finishScoped(compiled.Version, compiled.Digest, active, StateRolledBack, "APPLY_FAILED", true, 0, time.Time{})
	}
	if m.afterKernelApply != nil {
		if err := m.afterKernelApply(); err != nil {
			return Result{}, err
		}
	}
	if err := m.confirm(ctx, candidate.Version.VersionID, candidate.Digest); err != nil {
		if rollbackErr := m.rollback(ctx, taskID, active); rollbackErr != nil {
			return m.finishScoped(compiled.Version, compiled.Digest, active, StateRollbackFailed, "ROLLBACK_FAILED", false, 0, time.Time{})
		}
		return m.finishScoped(compiled.Version, compiled.Digest, active, StateRolledBack, "HEALTH_FAILED", true, 0, time.Time{})
	}
	if err := m.saveActive(candidate); err != nil {
		if rollbackErr := m.rollback(ctx, taskID, active); rollbackErr != nil {
			return m.finishScoped(compiled.Version, compiled.Digest, active, StateRollbackFailed, "ROLLBACK_FAILED", false, 0, time.Time{})
		}
		return m.finishScoped(compiled.Version, compiled.Digest, active, StateRolledBack, "STATE_COMMIT_FAILED", true, 0, time.Time{})
	}
	return m.finishScoped(compiled.Version, compiled.Digest, &candidate, StateApplied, "", false, 0, now)
}
