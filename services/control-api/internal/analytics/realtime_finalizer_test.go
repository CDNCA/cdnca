package analytics

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

type realtimeCoverageStoreStub struct {
	candidates []RealtimeCoverageCandidateV1
	snapshot   RealtimeCoverageSnapshotV1
	pendingErr error
	loadErr    error
	commitErr  error
	committed  *RealtimeCoverageFactV1
	inserted   bool
}

func (store *realtimeCoverageStoreStub) PendingRealtimeCoverage(
	context.Context, time.Time, int,
) ([]RealtimeCoverageCandidateV1, error) {
	return append([]RealtimeCoverageCandidateV1(nil), store.candidates...), store.pendingErr
}

func (store *realtimeCoverageStoreStub) LoadRealtimeCoverage(
	context.Context, RealtimeCoverageCandidateV1,
) (RealtimeCoverageSnapshotV1, error) {
	return store.snapshot, store.loadErr
}

func (store *realtimeCoverageStoreStub) CommitRealtimeCoverage(
	_ context.Context,
	_ RealtimeCoverageSnapshotV1,
	fact RealtimeCoverageFactV1,
) (bool, error) {
	store.committed = &fact
	return store.inserted, store.commitErr
}

type realtimeConnectionEvidenceStub struct {
	evidence []RealtimeConnectionEvidenceV1
	err      error
}

func (reader *realtimeConnectionEvidenceStub) RealtimeConnectionEvidence(
	context.Context, RealtimeCoverageCandidateV1,
) ([]RealtimeConnectionEvidenceV1, error) {
	return append([]RealtimeConnectionEvidenceV1(nil), reader.evidence...), reader.err
}

func TestRealtimeCoverageFinalizerCommitsOnlyCompleteIndependentEvidence(t *testing.T) {
	candidate, snapshot, connections, now := realtimeCoverageFixture(t)
	store := &realtimeCoverageStoreStub{
		candidates: []RealtimeCoverageCandidateV1{candidate}, snapshot: snapshot, inserted: true,
	}
	finalizer, err := newRealtimeCoverageFinalizer(
		store, &realtimeConnectionEvidenceStub{evidence: connections},
		RealtimeCoverageFinalizerConfig{Now: func() time.Time { return now }, MaximumWindows: 10},
	)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := finalizer.FinalizeOnce(t.Context())
	if err != nil || committed != 1 || store.committed == nil {
		t.Fatalf("FinalizeOnce() = %d, %+v, error=%v", committed, store.committed, err)
	}
	fact := *store.committed
	if fact.Candidate != candidate || fact.AccessSourcesExpected != 2 || fact.AccessSourcesFinalized != 2 ||
		fact.ConnectionSourcesExpected != 2 || fact.ConnectionSourcesFinalized != 2 ||
		!fact.AccessFinalizedThrough.Equal(candidate.WindowEnd) ||
		!fact.ConnectionFinalizedThrough.Equal(candidate.WindowEnd) ||
		fact.EvidenceSHA256 == ([sha256.Size]byte{}) || !fact.RecordedAt.Equal(connections[1].RecordedAt) {
		t.Fatalf("committed fact = %+v", fact)
	}
	if !fact.AccessSourceWatermark.Equal(snapshot.Sources[0].AccessRecordedAt) ||
		!fact.ConnectionSourceWatermark.Equal(connections[0].RecordedAt) {
		t.Fatalf("source watermarks = %s / %s", fact.AccessSourceWatermark, fact.ConnectionSourceWatermark)
	}

	store.committed = nil
	store.snapshot.Sources[1] = RealtimeCoverageSourceV1{
		NodeID:          snapshot.Sources[1].NodeID,
		ConfigVersionID: snapshot.Sources[1].ConfigVersionID,
	}
	committed, err = finalizer.FinalizeOnce(t.Context())
	if err != nil || committed != 0 || store.committed != nil {
		t.Fatalf("incomplete access committed = %d, %+v, error=%v", committed, store.committed, err)
	}
	store.snapshot = snapshot
	finalizer.connections = &realtimeConnectionEvidenceStub{evidence: connections[:1]}
	committed, err = finalizer.FinalizeOnce(t.Context())
	if err != nil || committed != 0 || store.committed != nil {
		t.Fatalf("incomplete connections committed = %d, %+v, error=%v", committed, store.committed, err)
	}
}

func TestRealtimeCoverageFinalizerRejectsConflictAndMapsDependencies(t *testing.T) {
	candidate, snapshot, connections, now := realtimeCoverageFixture(t)
	store := &realtimeCoverageStoreStub{candidates: []RealtimeCoverageCandidateV1{candidate}, snapshot: snapshot, inserted: true}
	reader := &realtimeConnectionEvidenceStub{evidence: append(connections, connections[0])}
	finalizer, err := newRealtimeCoverageFinalizer(store, reader,
		RealtimeCoverageFinalizerConfig{Now: func() time.Time { return now }, MaximumWindows: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finalizer.FinalizeOnce(t.Context()); !errors.Is(err, ErrRealtimeCoverageConflict) || store.committed != nil {
		t.Fatalf("duplicate connection evidence error=%v committed=%+v", err, store.committed)
	}

	dependency := errors.New("database endpoint must not escape")
	reader.evidence, reader.err = nil, dependency
	if _, err := finalizer.FinalizeOnce(t.Context()); !errors.Is(err, ErrRealtimeCoverageUnavailable) || errors.Is(err, dependency) {
		t.Fatalf("connection dependency error = %v", err)
	}
	reader.err = nil
	store.loadErr = dependency
	if _, err := finalizer.FinalizeOnce(t.Context()); !errors.Is(err, ErrRealtimeCoverageUnavailable) || errors.Is(err, dependency) {
		t.Fatalf("topology dependency error = %v", err)
	}
	store.loadErr = nil
	store.commitErr = ErrRealtimeCoverageConflict
	reader.evidence = connections
	if _, err := finalizer.FinalizeOnce(t.Context()); !errors.Is(err, ErrRealtimeCoverageConflict) {
		t.Fatalf("commit conflict error = %v", err)
	}
}

func TestRealtimeCoverageFinalizerReplayIsIdempotentAndDigestIsDeterministic(t *testing.T) {
	candidate, snapshot, connections, now := realtimeCoverageFixture(t)
	store := &realtimeCoverageStoreStub{candidates: []RealtimeCoverageCandidateV1{candidate}, snapshot: snapshot}
	reader := &realtimeConnectionEvidenceStub{evidence: connections}
	finalizer, err := newRealtimeCoverageFinalizer(store, reader,
		RealtimeCoverageFinalizerConfig{Now: func() time.Time { return now }, MaximumWindows: 10})
	if err != nil {
		t.Fatal(err)
	}
	if committed, err := finalizer.FinalizeOnce(t.Context()); err != nil || committed != 0 || store.committed == nil {
		t.Fatalf("idempotent replay = %d, %+v, error=%v", committed, store.committed, err)
	}
	first := store.committed.EvidenceSHA256
	store.committed = nil
	snapshot.Sources[0], snapshot.Sources[1] = snapshot.Sources[1], snapshot.Sources[0]
	connections[0], connections[1] = connections[1], connections[0]
	store.snapshot = snapshot
	reader.evidence = connections
	if _, err := finalizer.FinalizeOnce(t.Context()); err != nil || store.committed == nil || store.committed.EvidenceSHA256 != first {
		t.Fatalf("reordered digest = %x, want %x, error=%v", store.committed.EvidenceSHA256, first, err)
	}
}

func realtimeCoverageFixture(t *testing.T) (
	RealtimeCoverageCandidateV1,
	RealtimeCoverageSnapshotV1,
	[]RealtimeConnectionEvidenceV1,
	time.Time,
) {
	t.Helper()
	start := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	candidate := RealtimeCoverageCandidateV1{
		ScopeID: "018f0000-0000-7000-8000-000000000001", TenantID: "018f0000-0000-7000-8000-000000000002",
		SiteID: "018f0000-0000-7000-8000-000000000003", Host: "coverage.example.test", ListenPort: 443,
		WindowStart: start, WindowEnd: start.Add(time.Hour),
	}
	nodes := []string{
		"018f0000-0000-7000-8000-000000000004",
		"018f0000-0000-7000-8000-000000000005",
	}
	sources := make([]RealtimeCoverageSourceV1, len(nodes))
	connections := make([]RealtimeConnectionEvidenceV1, len(nodes))
	for index, node := range nodes {
		sources[index] = RealtimeCoverageSourceV1{
			NodeID: node, ConfigVersionID: "018f0000-0000-7000-8000-000000000006",
			AccessPresent: true, AccessSourceWatermark: uint64(index + 7),
			AccessFinalizedThrough: candidate.WindowEnd,
			AccessEvidenceSHA256:   sha256.Sum256([]byte("access-" + node)),
			AccessRecordedAt:       candidate.WindowEnd.Add(time.Duration(index+1) * time.Minute),
		}
		connections[index] = RealtimeConnectionEvidenceV1{
			NodeID: node, SourceWatermark: uint64(index + 11), FinalizedThrough: candidate.WindowEnd,
			EvidenceSHA256: sha256.Sum256([]byte("connections-" + node)),
			RecordedAt:     candidate.WindowEnd.Add(time.Duration(index+2) * time.Minute),
		}
	}
	return candidate, RealtimeCoverageSnapshotV1{Candidate: candidate, Sources: sources}, connections,
		candidate.WindowEnd.Add(5 * time.Minute)
}
