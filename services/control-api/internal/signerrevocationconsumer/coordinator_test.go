package signerrevocationconsumer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocation"
	"github.com/google/uuid"
)

type coordinatorStore struct {
	mu        sync.Mutex
	current   signerrevocation.CheckpointLKG
	accept    signerrevocation.CheckpointLKG
	acceptErr error
	accepted  int
	outages   []string
	outageErr error
}

func (store *coordinatorStore) RestoreV2(context.Context) (signerrevocation.CheckpointLKG, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.Checkpoint.Revision == 0 {
		return signerrevocation.CheckpointLKG{}, signerrevocation.ErrNoSnapshot
	}
	return store.current, nil
}

func (store *coordinatorStore) AcceptV2(context.Context, uuid.UUID, []byte, string, time.Time) (signerrevocation.CheckpointLKG, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.accepted++
	if store.acceptErr != nil {
		return signerrevocation.CheckpointLKG{}, store.acceptErr
	}
	store.current = store.accept
	return store.accept, nil
}

func (store *coordinatorStore) RecordCheckpointOutage(_ context.Context, _ uuid.UUID, reason string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.outageErr != nil {
		return store.outageErr
	}
	store.outages = append(store.outages, reason)
	return nil
}

type coordinatorRuntime struct {
	mu       sync.Mutex
	replaced []uint64
	failOnce map[uint64]error
}

func (runtime *coordinatorRuntime) Replace(snapshot signerrevocation.Snapshot) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.replaced = append(runtime.replaced, snapshot.Revision)
	if err := runtime.failOnce[snapshot.Revision]; err != nil {
		delete(runtime.failOnce, snapshot.Revision)
		return err
	}
	return nil
}

type coordinatorFetcher struct {
	mu      sync.Mutex
	results []FetchResult
	errors  []error
	entered chan struct{}
	release chan struct{}
	active  int
	max     int
	known   []KnownCheckpoint
}

func (fetcher *coordinatorFetcher) Fetch(ctx context.Context, known KnownCheckpoint) (FetchResult, error) {
	fetcher.mu.Lock()
	fetcher.known = append(fetcher.known, known)
	fetcher.active++
	if fetcher.active > fetcher.max {
		fetcher.max = fetcher.active
	}
	if fetcher.entered != nil {
		select {
		case fetcher.entered <- struct{}{}:
		default:
		}
	}
	fetcher.mu.Unlock()
	var waitErr error
	if fetcher.release != nil {
		select {
		case <-ctx.Done():
			waitErr = ctx.Err()
		case <-fetcher.release:
		}
	}
	fetcher.mu.Lock()
	if waitErr == nil && len(fetcher.errors) == 0 && len(fetcher.results) == 0 {
		fetcher.mu.Unlock()
		<-ctx.Done()
		fetcher.mu.Lock()
		waitErr = ctx.Err()
	}
	defer fetcher.mu.Unlock()
	fetcher.active--
	if waitErr != nil {
		return FetchResult{}, waitErr
	}
	if len(fetcher.errors) > 0 {
		err := fetcher.errors[0]
		fetcher.errors = fetcher.errors[1:]
		return FetchResult{}, err
	}
	result := fetcher.results[0]
	fetcher.results = fetcher.results[1:]
	return result, nil
}

func TestCoordinatorRunCancelsInflightFetch(t *testing.T) {
	store := &coordinatorStore{current: checkpointLKG(1)}
	runtime := &coordinatorRuntime{failOnce: map[uint64]error{}}
	fetcher := &coordinatorFetcher{entered: make(chan struct{}, 1), release: make(chan struct{}),
		results: []FetchResult{{NotModified: true, OperationID: uuid.New(), ObservedAt: time.Now()}}}
	coordinator, err := NewCoordinator(store, fetcher, runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- coordinator.Run(ctx, time.Hour) }()
	<-fetcher.entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
	if fetcher.max != 1 {
		t.Fatalf("max concurrent fetches = %d", fetcher.max)
	}
}

func TestCoordinatorStartupCommitThenReplaceAndRecovery(t *testing.T) {
	one, two := checkpointLKG(1), checkpointLKG(2)
	store := &coordinatorStore{current: one, accept: two}
	runtime := &coordinatorRuntime{failOnce: map[uint64]error{2: errors.New("replace failed")}}
	now := time.Unix(1_800_000_000, 0).UTC()
	fetcher := &coordinatorFetcher{results: []FetchResult{
		{Body: []byte("checkpoint-2"), ETag: `"` + two.Checkpoint.CheckpointSHA256 + `"`, OperationID: uuid.New(), ObservedAt: now},
		{NotModified: true, ETag: `"` + two.Checkpoint.CheckpointSHA256 + `"`, OperationID: uuid.New(), ObservedAt: now.Add(time.Minute)},
	}}
	coordinator, err := NewCoordinator(store, fetcher, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Startup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Refresh(t.Context()); err == nil {
		t.Fatal("replace failure was hidden")
	}
	if store.accepted != 1 || store.current.Checkpoint.Revision != 2 {
		t.Fatalf("committed state = %#v, accepts=%d", store.current, store.accepted)
	}
	if err := coordinator.Refresh(t.Context()); err != nil {
		t.Fatalf("recovery refresh = %v", err)
	}
	if len(runtime.replaced) != 4 || runtime.replaced[0] != 1 || runtime.replaced[1] != 1 ||
		runtime.replaced[2] != 2 || runtime.replaced[3] != 2 {
		t.Fatalf("replace revisions = %v", runtime.replaced)
	}
	if len(store.outages) != 1 || store.outages[0] != ReasonNotModified {
		t.Fatalf("outages = %v", store.outages)
	}
}

func TestCoordinatorRunRecoversReplaceFailureOnNextRound(t *testing.T) {
	one, two := checkpointLKG(1), checkpointLKG(2)
	store := &coordinatorStore{current: one, accept: two}
	runtime := &coordinatorRuntime{failOnce: map[uint64]error{2: errors.New("replace failed")}}
	now := time.Unix(1_800_000_000, 0).UTC()
	fetcher := &coordinatorFetcher{results: []FetchResult{
		{Body: []byte("checkpoint-2"), ETag: `"` + two.Checkpoint.CheckpointSHA256 + `"`,
			OperationID: uuid.New(), ObservedAt: now},
		{NotModified: true, ETag: `"` + two.Checkpoint.CheckpointSHA256 + `"`,
			OperationID: uuid.New(), ObservedAt: now.Add(time.Minute)},
	}}
	coordinator, err := NewCoordinator(store, fetcher, runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- coordinator.Run(ctx, time.Millisecond) }()
	deadline := time.Now().Add(time.Second)
	for {
		store.mu.Lock()
		recovered := len(store.outages) == 1
		store.mu.Unlock()
		if recovered {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("Run did not retry after post-commit Replace failure")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run cancellation after recovery = %v", err)
	}
	if store.accepted != 1 || store.current.Checkpoint.Revision != 2 {
		t.Fatalf("committed state = %#v, accepts=%d", store.current, store.accepted)
	}
	if len(runtime.replaced) < 4 || runtime.replaced[0] != 1 || runtime.replaced[1] != 1 ||
		runtime.replaced[2] != 2 || runtime.replaced[3] != 2 {
		t.Fatalf("replace revisions = %v", runtime.replaced)
	}
	for _, revision := range runtime.replaced[4:] {
		if revision != 2 {
			t.Fatalf("replace revisions regressed = %v", runtime.replaced)
		}
	}
}

func TestCoordinatorRunReturnsOutagePersistenceFailure(t *testing.T) {
	auditErr := errors.New("outage audit unavailable")
	store := &coordinatorStore{current: checkpointLKG(1), outageErr: auditErr}
	runtime := &coordinatorRuntime{failOnce: map[uint64]error{}}
	fetcher := &coordinatorFetcher{errors: []error{&FetchError{Reason: ReasonServerOutage,
		OperationID: uuid.New(), ObservedAt: time.Now(), Err: errors.New("503")}}}
	coordinator, err := NewCoordinator(store, fetcher, runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- coordinator.Run(ctx, time.Hour) }()
	select {
	case err := <-done:
		if !errors.Is(err, auditErr) {
			t.Fatalf("Run outage audit error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		cancel()
		if err := <-done; !errors.Is(err, auditErr) {
			t.Fatalf("Run swallowed outage audit failure: %v", err)
		}
	}
}

func TestCoordinatorFailClosedOutageAndSerializedCancellation(t *testing.T) {
	store := &coordinatorStore{}
	runtime := &coordinatorRuntime{failOnce: map[uint64]error{}}
	fetcher := &coordinatorFetcher{}
	coordinator, err := NewCoordinator(store, fetcher, runtime)
	if err != nil {
		t.Fatal(err)
	}
	// An empty LKG (fresh install, center never imported a checkpoint) must not
	// block control-plane startup; nothing is installed and the gate allows.
	if err := coordinator.Startup(t.Context()); err != nil || len(runtime.replaced) != 0 {
		t.Fatalf("empty-LKG startup = %v, replacements=%v", err, runtime.replaced)
	}

	store.current = checkpointLKG(1)
	fetcher.errors = []error{&FetchError{Reason: ReasonServerOutage, OperationID: uuid.New(),
		ObservedAt: time.Now(), Err: errors.New("503")}}
	if err := coordinator.Refresh(t.Context()); err == nil || len(store.outages) != 1 || store.outages[0] != ReasonServerOutage {
		t.Fatalf("outage refresh = %v, outages=%v", err, store.outages)
	}
	if store.current.Checkpoint.Revision != 1 {
		t.Fatal("outage changed LKG")
	}

	fetcher.entered = make(chan struct{}, 1)
	fetcher.release = make(chan struct{})
	fetcher.results = []FetchResult{{NotModified: true, OperationID: uuid.New(), ObservedAt: time.Now()}}
	first := make(chan error, 1)
	go func() { first <- coordinator.Refresh(context.Background()) }()
	<-fetcher.entered
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := coordinator.Refresh(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting cancellation = %v", err)
	}
	close(fetcher.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if fetcher.max != 1 {
		t.Fatalf("max concurrent fetches = %d", fetcher.max)
	}
}

func checkpointLKG(revision uint64) signerrevocation.CheckpointLKG {
	digest := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	return signerrevocation.CheckpointLKG{
		Checkpoint: signercheckpoint.Snapshot{Revision: revision, CheckpointSHA256: digest},
		Runtime:    signerrevocation.Snapshot{Revision: revision}, ETag: `"` + digest + `"`,
	}
}

func TestCoordinatorBootstrapsFromEmptyLKG(t *testing.T) {
	store := &coordinatorStore{accept: checkpointLKG(1)}
	runtime := &coordinatorRuntime{failOnce: map[uint64]error{}}
	fetcher := &coordinatorFetcher{errors: []error{&FetchError{Reason: ReasonInvalidResponse,
		OperationID: uuid.New(), ObservedAt: time.Now(), Err: ErrInvalidResponse}},
		results: []FetchResult{{Body: []byte("{}"), ETag: `"x"`, OperationID: uuid.New(), ObservedAt: time.Now()}}}
	coordinator, err := NewCoordinator(store, fetcher, runtime)
	if err != nil {
		t.Fatal(err)
	}
	// Older authorization centers answer 404 (invalid response): retryable, no LKG installed.
	var retryable *retryableRefreshError
	if err := coordinator.Refresh(t.Context()); !errors.As(err, &retryable) || len(runtime.replaced) != 0 {
		t.Fatalf("empty-LKG outage refresh = %v, replacements=%v", err, runtime.replaced)
	}
	if len(store.outages) != 1 || store.outages[0] != ReasonInvalidResponse {
		t.Fatalf("outage audit = %v", store.outages)
	}
	if err := coordinator.Refresh(t.Context()); err != nil {
		t.Fatalf("first checkpoint refresh = %v", err)
	}
	if len(runtime.replaced) != 1 || runtime.replaced[0] != 1 {
		t.Fatalf("replacements = %v", runtime.replaced)
	}
	for _, known := range fetcher.known {
		if known != (KnownCheckpoint{}) {
			t.Fatalf("empty LKG must fetch from revision 0, got %#v", known)
		}
	}
}

func TestCoordinatorRejectedCheckpointKeepsLKGAndIsRetryable(t *testing.T) {
	for name, rejection := range map[string]error{
		"signature": signercheckpoint.ErrInvalidSignature,
		"rollback":  signercheckpoint.ErrRevisionRollback,
		"fork":      signercheckpoint.ErrPrefixFork,
		"clock":     signerrevocation.ErrObservedAtOutOfRange,
	} {
		t.Run(name, func(t *testing.T) {
			store := &coordinatorStore{current: checkpointLKG(2), acceptErr: rejection}
			runtime := &coordinatorRuntime{failOnce: map[uint64]error{}}
			fetcher := &coordinatorFetcher{results: []FetchResult{{Body: []byte("{}"), ETag: `"x"`,
				OperationID: uuid.New(), ObservedAt: time.Now()}}}
			coordinator, err := NewCoordinator(store, fetcher, runtime)
			if err != nil {
				t.Fatal(err)
			}
			var retryable *retryableRefreshError
			if err := coordinator.Refresh(t.Context()); !errors.As(err, &retryable) || !errors.Is(err, rejection) {
				t.Fatalf("rejected checkpoint refresh = %v", err)
			}
			if store.current.Checkpoint.Revision != 2 || len(store.outages) != 1 || store.outages[0] != ReasonInvalidResponse {
				t.Fatalf("LKG=%d outages=%v", store.current.Checkpoint.Revision, store.outages)
			}
		})
	}
	t.Run("storage stays terminal", func(t *testing.T) {
		store := &coordinatorStore{current: checkpointLKG(2), acceptErr: signerrevocation.ErrInvalidStoredState}
		fetcher := &coordinatorFetcher{results: []FetchResult{{Body: []byte("{}"), ETag: `"x"`,
			OperationID: uuid.New(), ObservedAt: time.Now()}}}
		coordinator, err := NewCoordinator(store, fetcher, &coordinatorRuntime{failOnce: map[uint64]error{}})
		if err != nil {
			t.Fatal(err)
		}
		var retryable *retryableRefreshError
		if err := coordinator.Refresh(t.Context()); errors.As(err, &retryable) || !errors.Is(err, signerrevocation.ErrInvalidStoredState) {
			t.Fatalf("storage failure must be terminal, got %v", err)
		}
	})
}
