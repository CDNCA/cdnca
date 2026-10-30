package signerrevocation

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRuntimeReplaceRejectsRollbackAndSameRevisionConflict(t *testing.T) {
	lower, higher := runtimeHardeningSnapshots(t)
	runtime, err := NewRuntime(higher)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Replace(lower); !errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("3 -> 2 replacement error = %v", err)
	}
	if err := runtime.Replace(higher); err != nil {
		t.Fatalf("exact revision replay: %v", err)
	}
	divergent := cloneSnapshot(higher)
	divergent.AcceptedAt = divergent.AcceptedAt.Add(time.Microsecond)
	if err := runtime.Replace(divergent); !errors.Is(err, ErrSnapshotConflict) {
		t.Fatalf("same revision divergent replacement error = %v", err)
	}
	loaded, ok := runtime.Snapshot()
	if !ok || loaded.Revision != higher.Revision || !loaded.AcceptedAt.Equal(higher.AcceptedAt) {
		t.Fatalf("runtime changed after rejected replacements = %#v", loaded)
	}
	decision := runtime.DecideLease(SignerIdentity{KeyID: "root", Generation: 1}, fixedNow)
	if decision.Allowed || decision.Reason != ReasonSignerRevoked {
		t.Fatalf("rollback re-allowed revoked signer = %#v", decision)
	}
}

func TestRuntimeReplaceConcurrentOutOfOrderKeepsHighestRevision(t *testing.T) {
	lower, higher := runtimeHardeningSnapshots(t)
	for iteration := 0; iteration < 64; iteration++ {
		runtime, err := NewRuntime(lower)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		go func() {
			<-start
			results <- runtime.Replace(higher)
		}()
		go func() {
			<-start
			results <- runtime.Replace(lower)
		}()
		close(start)
		for range 2 {
			if err := <-results; err != nil && !errors.Is(err, ErrSnapshotRollback) {
				t.Fatalf("concurrent replacement error = %v", err)
			}
		}
		loaded, ok := runtime.Snapshot()
		if !ok || loaded.Revision != higher.Revision {
			t.Fatalf("iteration %d final snapshot = %#v", iteration, loaded)
		}
	}
}

func TestRuntimeConcurrentReadersSeeWholeMonotonicSnapshots(t *testing.T) {
	_, initial := runtimeHardeningSnapshots(t)
	runtime, err := NewRuntime(initial)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsFound := make(chan error, 9)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			last := initial.Revision
			for range 512 {
				snapshot, ok := runtime.Snapshot()
				if !ok || snapshot.Revision < last || len(snapshot.Revocations) != 1 {
					errorsFound <- fmt.Errorf("non-monotonic or partial snapshot: revision=%d last=%d revocations=%d",
						snapshot.Revision, last, len(snapshot.Revocations))
					return
				}
				last = snapshot.Revision
				decision := snapshot.Decide(ArtifactLease, SignerIdentity{KeyID: "root", Generation: 1}, fixedNow)
				if decision.Allowed || decision.Reason != ReasonSignerRevoked {
					errorsFound <- fmt.Errorf("partial decision at revision %d: %#v", snapshot.Revision, decision)
					return
				}
			}
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		for revision := initial.Revision + 1; revision <= 96; revision++ {
			next := cloneSnapshot(initial)
			next.Revision = revision
			next.AcceptedAt = initial.AcceptedAt.Add(time.Duration(revision) * time.Microsecond)
			if err := runtime.Replace(next); err != nil {
				errorsFound <- err
				return
			}
		}
	}()
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
}

func TestSnapshotDecideRejectsUnknownArtifactClass(t *testing.T) {
	lower, _ := runtimeHardeningSnapshots(t)
	for _, class := range []ArtifactClass{"", "unknown"} {
		decision := lower.Decide(class, SignerIdentity{KeyID: "root", Generation: 1}, fixedNow)
		if decision.Allowed || decision.Reason != ReasonArtifactClassUntrusted {
			t.Fatalf("class %q decision = %#v", class, decision)
		}
	}
}

func runtimeHardeningSnapshots(t *testing.T) (Snapshot, Snapshot) {
	t.Helper()
	fixture := makeTrustFixture(t, "root", "current")
	lower := fixture.snapshot(t)
	lower.Revision = 2
	manifest := testManifest(1, nil, nil, "root", 1)
	encoded := signManifest(t, manifest, AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2},
		fixture.privateKeys["current"])
	verified, err := verifyManifest(t.Context(), encoded, lower, fixture, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	higher := withRevocation(withHead(lower, verified), verified, encoded)
	higher.Revision = 3
	higher.AcceptedAt = fixedNow.Add(time.Minute)
	return lower, higher
}
