package deployment

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
)

type recordingCertificateStore struct {
	mu         sync.Mutex
	references certstore.CertificateVersionReferences
	failNext   bool
}

func (s *recordingCertificateStore) CertificateVersionReferences(context.Context) (certstore.CertificateVersionReferences, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.references, nil
}

func (s *recordingCertificateStore) SetCertificateVersionReferences(_ context.Context, references certstore.CertificateVersionReferences) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return errors.New("store unavailable")
	}
	s.references = references
	return nil
}

func (s *recordingCertificateStore) ResolveCertificateVersion(context.Context, certstore.CertificateResolveRequest) (certstore.ResolvedCertificateVersion, error) {
	return certstore.ResolvedCertificateVersion{}, nil
}

const (
	certA1 = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1"
	certA2 = "a2a2a2a2-a2a2-4a2a-8a2a-a2a2a2a2a2a2"
	certB1 = "b1b1b1b1-b1b1-4b1b-8b1b-b1b1b1b1b1b1"
)

func TestScopedCertificateReferencesWriteTheUnionOfAllScopes(t *testing.T) {
	root := t.TempDir()
	store := &recordingCertificateStore{}
	references, err := newScopedCertificateReferences(root, store)
	if err != nil {
		t.Fatal(err)
	}
	viewA, viewB := references.view(testScopeA), references.view(testScopeB)
	ctx := context.Background()
	if err := viewA.SetCertificateVersionReferences(ctx, certstore.CertificateVersionReferences{Current: []string{certA2}, Previous: []string{certA1}}); err != nil {
		t.Fatal(err)
	}
	if err := viewB.SetCertificateVersionReferences(ctx, certstore.CertificateVersionReferences{Current: []string{certB1}}); err != nil {
		t.Fatal(err)
	}
	want := certstore.CertificateVersionReferences{Current: []string{certA2, certB1}, Previous: []string{certA1}}
	if !reflect.DeepEqual(store.references, want) {
		t.Fatalf("node references = %+v, want union %+v", store.references, want)
	}
	if own, _ := viewA.CertificateVersionReferences(ctx); !reflect.DeepEqual(own, certstore.CertificateVersionReferences{Current: []string{certA2}, Previous: []string{certA1}}) {
		t.Fatalf("scope A view = %+v, want only its own references", own)
	}

	// Scope A dropping its releases must not unprotect scope B's certificate.
	if err := viewA.SetCertificateVersionReferences(ctx, certstore.CertificateVersionReferences{}); err != nil {
		t.Fatal(err)
	}
	if want := (certstore.CertificateVersionReferences{Current: []string{certB1}}); !reflect.DeepEqual(store.references, want) {
		t.Fatalf("node references after A cleared = %+v, want %+v", store.references, want)
	}

	// A failed node write leaves both the node and the scope view unchanged.
	store.failNext = true
	if err := viewB.SetCertificateVersionReferences(ctx, certstore.CertificateVersionReferences{Current: []string{certA1}}); err == nil {
		t.Fatal("failed node write was reported as success")
	}
	if own, _ := viewB.CertificateVersionReferences(ctx); !reflect.DeepEqual(own, certstore.CertificateVersionReferences{Current: []string{certB1}}) {
		t.Fatalf("scope B view after failed write = %+v", own)
	}

	reopened, err := newScopedCertificateReferences(root, store)
	if err != nil {
		t.Fatal(err)
	}
	if own, _ := reopened.view(testScopeB).CertificateVersionReferences(ctx); !reflect.DeepEqual(own, certstore.CertificateVersionReferences{Current: []string{certB1}}) {
		t.Fatalf("reopened scope B view = %+v", own)
	}
}

func TestMultiScopeManagerConfiguresScopedCertificateViews(t *testing.T) {
	manager := newTestMultiScopeManager(t, newFakeScopeRuntime(), "")
	store := &recordingCertificateStore{}
	if err := manager.ConfigureCertificateVersionStore(store, t.TempDir()); err != nil {
		t.Fatalf("ConfigureCertificateVersionStore() error = %v", err)
	}
	scoped, err := manager.openScope(testScopeA)
	if err != nil {
		t.Fatal(err)
	}
	view, ok := scoped.certificateVersions.(*scopedCertificateView)
	if !ok || view.scopeID != testScopeA {
		t.Fatalf("scope manager certificate store = %T, want its scoped view", scoped.certificateVersions)
	}
	if err := manager.ConfigureCertificateVersionStore(store, t.TempDir()); err == nil {
		t.Fatal("certificate store was configured twice")
	}
}
