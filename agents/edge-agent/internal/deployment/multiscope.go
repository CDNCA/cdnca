package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/google/uuid"
)

// ScopeRelease is one scope's verified, content-addressed release directory.
type ScopeRelease struct {
	ConfigVersionID string
	Path            string
}

// ScopeRuntime composes every scope's release into one runtime. The map passed
// to each call is the complete composition: the scope being changed with its
// candidate (or without it, when its release was removed) and every other
// scope with its current release. Implementations must not mutate the active
// runtime in PrecheckComposition.
type ScopeRuntime interface {
	PrecheckComposition(ctx context.Context, scopeID string, releases map[string]ScopeRelease) error
	ReloadComposition(ctx context.Context, releases map[string]ScopeRelease) error
	HealthyScope(ctx context.Context, scopeID, versionID string) error
}

// MultiScopeManager runs one deployment state machine per configuration scope
// under <root>/scopes/<scope>. Each scope keeps its own current/previous
// pointers, journals and releases, so a failed attempt rolls back only that
// scope. One node-level lock serializes every activation and reload.
type MultiScopeManager struct {
	apply     sync.Mutex
	scopesMu  sync.RWMutex
	root      string
	scopesDir string
	lockPath  string
	runtime   ScopeRuntime
	config    Config
	managers  map[string]*Manager

	certificates         *scopedCertificateReferences
	certificateStateRoot string
}

func NewMultiScopeManager(stateRoot string, runtime ScopeRuntime, config Config) (*MultiScopeManager, error) {
	if runtime == nil {
		return nil, fmt.Errorf("%w: scope runtime is required", ErrInvalidCommand)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if stateRoot == "" || !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return nil, fmt.Errorf("%w: state root must be a clean absolute path", ErrInvalidPath)
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create state root: %w", err)
	}
	if err := ensureDirectory(stateRoot); err != nil {
		return nil, err
	}
	realRoot, err := filepath.EvalSymlinks(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve state root: %w", err)
	}
	manager := &MultiScopeManager{
		root: realRoot, scopesDir: filepath.Join(realRoot, "scopes"),
		lockPath: filepath.Join(realRoot, "node-activation.lock"),
		runtime:  runtime, config: config, managers: make(map[string]*Manager),
	}
	if err := ensureOrCreateDirectory(manager.scopesDir); err != nil {
		return nil, fmt.Errorf("create scopes directory: %w", err)
	}
	// Create the node lock now: readers (cache prewarm) take it shared and must
	// not depend on an apply having happened first.
	unlock, err := lockFile(context.Background(), manager.lockPath)
	if err != nil {
		return nil, err
	}
	unlock()
	entries, err := os.ReadDir(manager.scopesDir)
	if err != nil {
		return nil, fmt.Errorf("read scopes directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || validateScopeID(entry.Name()) != nil {
			return nil, fmt.Errorf("%w: scopes directory contains an unsafe entry", ErrInvalidPath)
		}
		if _, err := manager.openScope(entry.Name()); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func validateScopeID(scopeID string) error {
	parsed, err := uuid.Parse(scopeID)
	if err != nil || parsed.String() != scopeID || parsed == uuid.Nil {
		return fmt.Errorf("%w: configuration scope must be a canonical non-nil UUID", ErrInvalidCommand)
	}
	return nil
}

// openScope returns the scope's manager, creating its state directory once.
func (m *MultiScopeManager) openScope(scopeID string) (*Manager, error) {
	if err := validateScopeID(scopeID); err != nil {
		return nil, err
	}
	m.scopesMu.Lock()
	defer m.scopesMu.Unlock()
	if existing := m.managers[scopeID]; existing != nil {
		return existing, nil
	}
	adapter := &scopeRuntimeAdapter{owner: m, scopeID: scopeID}
	scoped, err := newManagerWithConfig(filepath.Join(m.scopesDir, scopeID), adapter, adapter, m.config)
	if err != nil {
		return nil, err
	}
	scoped.reloadCleared = adapter.reloadCleared
	adapter.manager = scoped
	if m.certificates != nil {
		if err := scoped.ConfigureCertificateVersionStore(m.certificates.view(scopeID), m.certificateStateRoot); err != nil {
			return nil, err
		}
	}
	m.managers[scopeID] = scoped
	return scoped, nil
}

func (m *MultiScopeManager) scope(scopeID string) (*Manager, error) {
	if err := validateScopeID(scopeID); err != nil {
		return nil, err
	}
	m.scopesMu.RLock()
	defer m.scopesMu.RUnlock()
	return m.managers[scopeID], nil
}

// Process applies or rolls back one scope's command under the node lock.
func (m *MultiScopeManager) Process(ctx context.Context, scopeID string, command Command) (Result, error) {
	if err := validateScopeID(scopeID); err != nil {
		return Result{}, err
	}
	m.apply.Lock()
	defer m.apply.Unlock()
	unlock, err := lockFile(ctx, m.lockPath)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	scoped, err := m.openScope(scopeID)
	if err != nil {
		return Result{}, err
	}
	return scoped.Process(ctx, command)
}

// Pointers returns one scope's pointers; an unknown scope has none.
func (m *MultiScopeManager) Pointers(scopeID string) (Pointers, error) {
	scoped, err := m.scope(scopeID)
	if err != nil || scoped == nil {
		return Pointers{}, err
	}
	return scoped.Pointers()
}

// Lookup returns a scope's recorded attempt for deploymentID.
func (m *MultiScopeManager) Lookup(scopeID, deploymentID string) (Result, bool, error) {
	scoped, err := m.scope(scopeID)
	if err != nil || scoped == nil {
		return Result{}, false, err
	}
	return scoped.Lookup(deploymentID)
}

// Scopes lists every scope with local state, sorted.
func (m *MultiScopeManager) Scopes() []string {
	m.scopesMu.RLock()
	defer m.scopesMu.RUnlock()
	scopes := make([]string, 0, len(m.managers))
	for scopeID := range m.managers {
		scopes = append(scopes, scopeID)
	}
	sort.Strings(scopes)
	return scopes
}

// Recover settles every scope's interrupted activation before commands run.
func (m *MultiScopeManager) Recover(ctx context.Context) error {
	m.apply.Lock()
	defer m.apply.Unlock()
	unlock, err := lockFile(ctx, m.lockPath)
	if err != nil {
		return err
	}
	defer unlock()
	for _, scopeID := range m.Scopes() {
		scoped, err := m.scope(scopeID)
		if err != nil {
			return err
		}
		if err := scoped.Recover(ctx); err != nil {
			return fmt.Errorf("recover scope %s: %w", scopeID, err)
		}
	}
	return nil
}

func (m *MultiScopeManager) StateRoot() string { return m.root }

// otherReleases returns the current release of every scope except scopeID.
// It runs inside Process, so no other scope is mid-activation.
func (m *MultiScopeManager) otherReleases(scopeID string) (map[string]ScopeRelease, error) {
	m.scopesMu.RLock()
	defer m.scopesMu.RUnlock()
	releases := make(map[string]ScopeRelease, len(m.managers))
	for otherID, scoped := range m.managers {
		if otherID == scopeID {
			continue
		}
		release, present, err := scoped.currentRelease()
		if err != nil {
			return nil, fmt.Errorf("read scope %s current release: %w", otherID, err)
		}
		if present {
			releases[otherID] = release
		}
	}
	return releases, nil
}

// currentRelease reads this manager's healthy current release.
func (m *Manager) currentRelease() (ScopeRelease, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pointers, err := m.store.loadPointers()
	if err != nil || pointers.Current == "" {
		return ScopeRelease{}, false, err
	}
	path, err := m.store.releasePath(pointers.CurrentDigest)
	if err != nil {
		return ScopeRelease{}, false, err
	}
	return ScopeRelease{ConfigVersionID: pointers.Current, Path: path}, true, nil
}

// scopeRuntimeAdapter presents the composed runtime to one scope's Manager as
// that scope's Prechecker and Runtime.
type scopeRuntimeAdapter struct {
	owner   *MultiScopeManager
	scopeID string
	manager *Manager
}

func (a *scopeRuntimeAdapter) Precheck(ctx context.Context, versionID, releasePath string) error {
	releases, err := a.owner.otherReleases(a.scopeID)
	if err != nil {
		return err
	}
	releases[a.scopeID] = ScopeRelease{ConfigVersionID: versionID, Path: releasePath}
	return a.owner.runtime.PrecheckComposition(ctx, a.scopeID, releases)
}

func (a *scopeRuntimeAdapter) Reload(ctx context.Context, versionID, currentLink string) error {
	releases, err := a.owner.otherReleases(a.scopeID)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(currentLink)
	if err != nil {
		return fmt.Errorf("resolve scope current release: %w", err)
	}
	releases[a.scopeID] = ScopeRelease{ConfigVersionID: versionID, Path: resolved}
	return a.owner.runtime.ReloadComposition(ctx, releases)
}

func (a *scopeRuntimeAdapter) Healthy(ctx context.Context, versionID string) error {
	return a.owner.runtime.HealthyScope(ctx, a.scopeID, versionID)
}

func (a *scopeRuntimeAdapter) reloadCleared(ctx context.Context) error {
	releases, err := a.owner.otherReleases(a.scopeID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(a.manager.store.currentLink); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: cleared scope still has a current release", ErrCorruptState)
	}
	return a.owner.runtime.ReloadComposition(ctx, releases)
}

// ScopedManager presents a MultiScopeManager through the single-manager
// interface the gateway client uses: Process routes by Command.ScopeID and
// Lookup searches every scope's journal (deployment IDs are unique).
type ScopedManager struct {
	owner *MultiScopeManager
}

func (m *MultiScopeManager) ScopedManager() *ScopedManager { return &ScopedManager{owner: m} }

func (s *ScopedManager) Process(ctx context.Context, command Command) (Result, error) {
	if command.ScopeID == "" {
		return Result{}, fmt.Errorf("%w: a multi-scope node requires a scoped command", ErrInvalidCommand)
	}
	return s.owner.Process(ctx, command.ScopeID, command)
}

// Pointers is the node-wide pointer pair only when exactly one scope holds
// state; several scopes have no single current version.
func (s *ScopedManager) Pointers() (Pointers, error) {
	scopes := s.owner.Scopes()
	if len(scopes) != 1 {
		return Pointers{}, nil
	}
	return s.owner.Pointers(scopes[0])
}

func (s *ScopedManager) ScopePointers(scopeID string) (Pointers, error) {
	return s.owner.Pointers(scopeID)
}

func (s *ScopedManager) Scopes() []string { return s.owner.Scopes() }

func (s *ScopedManager) Lookup(deploymentID string) (Result, bool, error) {
	for _, scopeID := range s.owner.Scopes() {
		result, found, err := s.owner.Lookup(scopeID, deploymentID)
		if err != nil || found {
			return result, found, err
		}
	}
	return Result{}, false, nil
}

func (s *ScopedManager) StateRoot() string { return s.owner.StateRoot() }
