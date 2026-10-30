package acmehttp01

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
)

type recordingFetchStore struct {
	calls int
	err   error
}

func (s *recordingFetchStore) FetchChunk(context.Context, *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
	s.calls++
	return edgeartifact.FetchResult{}, s.err
}

// A cleanup_only fetch (a session without deployments) never reaches the
// ordinary configuration artifacts: only the overlay store may answer it.
func TestCompositeStoreCleanupOnlySkipsOrdinaryArtifacts(t *testing.T) {
	ordinary := &recordingFetchStore{err: errors.New("must not be called")}
	overlay := &recordingFetchStore{}
	composite, err := NewCompositeStore(ordinary, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := composite.FetchChunk(t.Context(), &controlv1.FetchArtifactRequest{CleanupOnly: true}); err != nil {
		t.Fatal(err)
	}
	if ordinary.calls != 0 || overlay.calls != 1 {
		t.Fatalf("ordinary=%d overlay=%d", ordinary.calls, overlay.calls)
	}
}

// The site-scoped 063 artifacts have no cleanup_only purpose.
func TestLegacyArtifactStoreRefusesCleanupOnly(t *testing.T) {
	store := &ArtifactStore{}
	_, err := store.FetchChunk(t.Context(), &controlv1.FetchArtifactRequest{CleanupOnly: true})
	if !errors.Is(err, edgeartifact.ErrDeploymentIneligible) {
		t.Fatalf("legacy store cleanup_only fetch: %v", err)
	}
}

// The purpose is part of the signed snapshot bytes; an apply snapshot keeps
// the exact bytes it had before purposes existed.
func TestSnapshotPurposeIsSigned(t *testing.T) {
	apply, err := json.Marshal(snapshot{SchemaVersion: ArtifactSchemaVersion, Entries: []snapshotEntry{}})
	if err != nil || strings.Contains(string(apply), "purpose") {
		t.Fatalf("apply snapshot %s %v", apply, err)
	}
	cleanup, err := json.Marshal(snapshot{SchemaVersion: ArtifactSchemaVersion, Purpose: snapshotPurposeCleanupOnly,
		Entries: []snapshotEntry{}})
	if err != nil || !strings.Contains(string(cleanup), `"purpose":"cleanup_only"`) {
		t.Fatalf("cleanup_only snapshot %s %v", cleanup, err)
	}
}
