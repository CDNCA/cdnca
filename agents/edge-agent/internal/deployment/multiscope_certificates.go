package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
)

const scopedCertificateReferencesFile = "certificate-references.json"

// scopedCertificateReferences shares one node-wide CertificateVersionStore
// between scopes. The store protects exactly the versions it was last given,
// so each scope's Manager writes through a view: the view records that scope's
// references and the node store receives the union of every scope.
type scopedCertificateReferences struct {
	mu     sync.Mutex
	dir    string
	store  CertificateVersionStore
	scopes map[string]certstore.CertificateVersionReferences
}

func newScopedCertificateReferences(dir string, store CertificateVersionStore) (*scopedCertificateReferences, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: certificate version store is required", ErrInvalidCommand)
	}
	references := &scopedCertificateReferences{dir: dir, store: store, scopes: map[string]certstore.CertificateVersionReferences{}}
	content, err := readRegularFile(filepath.Join(dir, scopedCertificateReferencesFile))
	if errors.Is(err, os.ErrNotExist) {
		return references, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(content, &references.scopes); err != nil {
		return nil, fmt.Errorf("%w: scoped certificate references cannot be decoded", ErrCorruptState)
	}
	for scopeID := range references.scopes {
		if validateScopeID(scopeID) != nil {
			return nil, fmt.Errorf("%w: scoped certificate references name an invalid scope", ErrCorruptState)
		}
	}
	return references, nil
}

func (r *scopedCertificateReferences) view(scopeID string) *scopedCertificateView {
	return &scopedCertificateView{owner: r, scopeID: scopeID}
}

func (r *scopedCertificateReferences) set(ctx context.Context, scopeID string, references certstore.CertificateVersionReferences) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]certstore.CertificateVersionReferences, len(r.scopes)+1)
	for id, value := range r.scopes {
		next[id] = value
	}
	if len(references.Current) == 0 && len(references.Previous) == 0 {
		delete(next, scopeID)
	} else {
		next[scopeID] = certstore.CertificateVersionReferences{
			Current: append([]string(nil), references.Current...), Previous: append([]string(nil), references.Previous...),
		}
	}
	// Protect the new union in the node store first. If recording the scope
	// split then fails, the node still protects at least what every scope uses.
	if err := r.store.SetCertificateVersionReferences(ctx, unionCertificateReferences(next)); err != nil {
		return err
	}
	if err := writeJSONAtomic(r.dir, scopedCertificateReferencesFile, next); err != nil {
		return err
	}
	r.scopes = next
	return nil
}

func (r *scopedCertificateReferences) get(scopeID string) certstore.CertificateVersionReferences {
	r.mu.Lock()
	defer r.mu.Unlock()
	value := r.scopes[scopeID]
	return certstore.CertificateVersionReferences{
		Current: append([]string(nil), value.Current...), Previous: append([]string(nil), value.Previous...),
	}
}

// unionCertificateReferences protects a version as current when any scope
// uses it as current, and as previous only when no scope uses it as current.
func unionCertificateReferences(scopes map[string]certstore.CertificateVersionReferences) certstore.CertificateVersionReferences {
	current, previous := map[string]struct{}{}, map[string]struct{}{}
	for _, value := range scopes {
		for _, id := range value.Current {
			current[id] = struct{}{}
		}
	}
	for _, value := range scopes {
		for _, id := range value.Previous {
			if _, exists := current[id]; !exists {
				previous[id] = struct{}{}
			}
		}
	}
	return certstore.CertificateVersionReferences{Current: sortedKeys(current), Previous: sortedKeys(previous)}
}

func sortedKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// scopedCertificateView is the CertificateVersionStore one scope's Manager sees.
type scopedCertificateView struct {
	owner   *scopedCertificateReferences
	scopeID string
}

func (v *scopedCertificateView) CertificateVersionReferences(context.Context) (certstore.CertificateVersionReferences, error) {
	return v.owner.get(v.scopeID), nil
}

func (v *scopedCertificateView) SetCertificateVersionReferences(ctx context.Context, references certstore.CertificateVersionReferences) error {
	return v.owner.set(ctx, v.scopeID, references)
}

func (v *scopedCertificateView) ResolveCertificateVersion(ctx context.Context, request certstore.CertificateResolveRequest) (certstore.ResolvedCertificateVersion, error) {
	return v.owner.store.ResolveCertificateVersion(ctx, request)
}

// ConfigureCertificateVersionStore gives every scope, present and future, a
// scoped view of the node certificate store.
func (m *MultiScopeManager) ConfigureCertificateVersionStore(store CertificateVersionStore, certificateStateRoot string) error {
	m.apply.Lock()
	defer m.apply.Unlock()
	m.scopesMu.Lock()
	defer m.scopesMu.Unlock()
	if m.certificates != nil {
		return fmt.Errorf("%w: certificate version store is already configured", ErrInvalidCommand)
	}
	references, err := newScopedCertificateReferences(m.root, store)
	if err != nil {
		return err
	}
	for scopeID, scoped := range m.managers {
		if err := scoped.ConfigureCertificateVersionStore(references.view(scopeID), certificateStateRoot); err != nil {
			return err
		}
	}
	m.certificates = references
	m.certificateStateRoot = certificateStateRoot
	return nil
}

// RecoverCertificateVersionReferences re-protects every scope's references
// before commands run.
func (m *MultiScopeManager) RecoverCertificateVersionReferences(ctx context.Context) error {
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
		if err := scoped.RecoverCertificateVersionReferences(ctx); err != nil {
			return fmt.Errorf("recover scope %s certificate references: %w", scopeID, err)
		}
	}
	return nil
}
