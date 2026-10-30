package signerrevocationconsumer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocation"
	"github.com/google/uuid"
)

func TestOpenProductionRuntimeDisabledDoesNotTouchDependencies(t *testing.T) {
	runtime, err := OpenProductionRuntime(nil, Config{}, ProductionDependencies{})
	if err != nil || runtime != nil {
		t.Fatalf("disabled runtime = (%#v, %v)", runtime, err)
	}
}

func TestProductionConfigValidationIsFailClosed(t *testing.T) {
	valid := Config{
		RefreshInterval: time.Minute, RequestTimeout: time.Second,
		StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	if !validProductionConfig(valid) {
		t.Fatal("valid production durations were rejected")
	}
	for name, mutate := range map[string]func(*Config){
		"refresh low":   func(config *Config) { config.RefreshInterval = time.Minute - 1 },
		"refresh high":  func(config *Config) { config.RefreshInterval = 24*time.Hour + 1 },
		"request low":   func(config *Config) { config.RequestTimeout = time.Second - 1 },
		"request high":  func(config *Config) { config.RequestTimeout = 30*time.Second + 1 },
		"startup low":   func(config *Config) { config.StartupTimeout = time.Second - 1 },
		"startup high":  func(config *Config) { config.StartupTimeout = 30*time.Second + 1 },
		"shutdown low":  func(config *Config) { config.ShutdownTimeout = time.Second - 1 },
		"shutdown high": func(config *Config) { config.ShutdownTimeout = 30*time.Second + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if validProductionConfig(candidate) {
				t.Fatalf("invalid production durations were accepted: %#v", candidate)
			}
		})
	}
}

func TestProductionRuntimeRunsImmediateRefreshAndIsSingleUse(t *testing.T) {
	store := &productionStore{current: productionLKG(3)}
	fetcher := &productionFetcher{results: []FetchResult{{
		NotModified: true, ETag: store.current.ETag, OperationID: uuid.New(), ObservedAt: time.Now(),
	}}}
	runtime := newTestProductionRuntime(t, store, fetcher, &productionSnapshotRuntime{}, time.Hour)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	waitForProduction(t, func() bool { return fetcher.callCount() == 1 && store.outageCount() == 1 })
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready while Run is active = %v", err)
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrProductionAlreadyRun) {
		t.Fatalf("second Run error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run after Close = %v", err)
	}
	if got := store.outageReasons(); len(got) != 1 || got[0] != ReasonNotModified {
		t.Fatalf("outage reasons = %v", got)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrProductionClosed) {
		t.Fatalf("Ready after Close = %v", err)
	}
}

func TestProductionRuntimeKeepsReadyAcrossAuditedOutages(t *testing.T) {
	now := time.Now()
	store := &productionStore{current: productionLKG(5)}
	fetcher := &productionFetcher{errors: []error{
		&FetchError{Reason: ReasonNetworkOutage, OperationID: uuid.New(), ObservedAt: now, Err: errors.New("network down")},
		&FetchError{Reason: ReasonServerOutage, OperationID: uuid.New(), ObservedAt: now.Add(time.Second), Err: errors.New("503")},
	}}
	runtime := newTestProductionRuntime(t, store, fetcher, &productionSnapshotRuntime{}, time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	waitForProduction(t, func() bool { return store.outageCount() >= 2 })
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready after audited outages = %v", err)
	}
	if store.currentRevision() != 5 {
		t.Fatalf("outage changed durable revision to %d", store.currentRevision())
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run after outage Close = %v", err)
	}
	got := store.outageReasons()
	if len(got) < 2 || got[0] != ReasonNetworkOutage || got[1] != ReasonServerOutage {
		t.Fatalf("outage reasons = %v", got)
	}
}

func TestProductionRuntimeOutageAuditAndRestoreFailuresAreTerminal(t *testing.T) {
	t.Run("outage audit", func(t *testing.T) {
		auditErr := errors.New("audit unavailable")
		store := &productionStore{current: productionLKG(1), outageErr: auditErr}
		fetcher := &productionFetcher{errors: []error{&FetchError{
			Reason: ReasonRateLimited, OperationID: uuid.New(), ObservedAt: time.Now(), Err: errors.New("429"),
		}}}
		runtime := newTestProductionRuntime(t, store, fetcher, &productionSnapshotRuntime{}, time.Hour)
		if err := runtime.Run(t.Context()); !errors.Is(err, auditErr) {
			t.Fatalf("Run error = %v", err)
		}
		if err := runtime.Ready(); !errors.Is(err, auditErr) {
			t.Fatalf("Ready terminal error = %v", err)
		}
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("restore", func(t *testing.T) {
		restoreErr := errors.New("stored checkpoint invalid")
		store := &productionStore{restoreErr: restoreErr}
		runtime := newTestProductionRuntime(t, store, &productionFetcher{}, &productionSnapshotRuntime{}, time.Hour)
		if err := runtime.Run(t.Context()); !errors.Is(err, restoreErr) {
			t.Fatalf("Run error = %v", err)
		}
		if err := runtime.Ready(); !errors.Is(err, restoreErr) {
			t.Fatalf("Ready terminal error = %v", err)
		}
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestProductionRuntimeRepairsPostCommitReplaceFailure(t *testing.T) {
	one, two := productionLKG(1), productionLKG(2)
	store := &productionStore{current: one, accepted: two}
	replaceErr := errors.New("replace failed")
	snapshotRuntime := &productionSnapshotRuntime{failRevision: 2, failErr: replaceErr}
	fetcher := &productionFetcher{results: []FetchResult{
		{Body: []byte("checkpoint-2"), ETag: two.ETag, OperationID: uuid.New(), ObservedAt: time.Now()},
		{NotModified: true, ETag: two.ETag, OperationID: uuid.New(), ObservedAt: time.Now().Add(time.Second)},
	}}
	runtime := newTestProductionRuntime(t, store, fetcher, snapshotRuntime, time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	waitForProduction(t, func() bool { return store.outageCount() == 1 })
	if store.acceptCount() != 1 || store.currentRevision() != 2 {
		t.Fatalf("durable state accepts=%d revision=%d", store.acceptCount(), store.currentRevision())
	}
	if got := snapshotRuntime.revisions(); len(got) < 3 || got[0] != 1 || got[1] != 2 || got[2] != 2 {
		t.Fatalf("runtime replacements = %v", got)
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready after repair = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProductionRuntimeCloseCancelsFetchAndClearsSecret(t *testing.T) {
	store := &productionStore{current: productionLKG(1)}
	fetcher := &productionFetcher{entered: make(chan struct{}), waitForCancel: true}
	runtime := newTestProductionRuntime(t, store, fetcher, &productionSnapshotRuntime{}, time.Hour)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	select {
	case <-fetcher.entered:
	case <-time.After(time.Second):
		t.Fatal("immediate fetch did not start")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run after Close = %v", err)
	}
	assertProductionPrivateKeyCleared(t, runtime)
	if err := runtime.Close(); err != nil {
		t.Fatalf("repeated Close = %v", err)
	}
}

func TestProductionRuntimeCloseCancelsBlockedStore(t *testing.T) {
	store := &productionStore{entered: make(chan struct{}), waitForCancel: true}
	runtime := newTestProductionRuntime(t, store, &productionFetcher{}, &productionSnapshotRuntime{}, time.Hour)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("store restore did not start")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run after blocked store Close = %v", err)
	}
	assertProductionPrivateKeyCleared(t, runtime)
}

func TestProductionRuntimeNeverRunAndParentCancellation(t *testing.T) {
	t.Run("never run", func(t *testing.T) {
		runtime := newTestProductionRuntime(t, &productionStore{}, &productionFetcher{}, &productionSnapshotRuntime{}, time.Hour)
		if err := runtime.Ready(); !errors.Is(err, ErrProductionNotReady) {
			t.Fatalf("Ready before Run = %v", err)
		}
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
		assertProductionPrivateKeyCleared(t, runtime)
	})

	t.Run("parent cancel", func(t *testing.T) {
		store := &productionStore{current: productionLKG(1)}
		fetcher := &productionFetcher{entered: make(chan struct{}), waitForCancel: true}
		runtime := newTestProductionRuntime(t, store, fetcher, &productionSnapshotRuntime{}, time.Hour)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runtime.Run(ctx) }()
		<-fetcher.entered
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run cancellation error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Run did not honor parent cancellation")
		}
		if err := runtime.Ready(); !errors.Is(err, context.Canceled) {
			t.Fatalf("Ready after parent cancellation = %v", err)
		}
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestProductionRuntimeCloseTimeoutIsBounded(t *testing.T) {
	release := make(chan struct{})
	store := &productionStore{current: productionLKG(1)}
	fetcher := &productionFetcher{entered: make(chan struct{}), release: release}
	runtime := newTestProductionRuntime(t, store, fetcher, &productionSnapshotRuntime{}, time.Hour)
	runtime.config.ShutdownTimeout = 20 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	<-fetcher.entered
	started := time.Now()
	if err := runtime.Close(); !errors.Is(err, ErrProductionShutdownTimed) {
		t.Fatalf("Close timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Close timeout took %s", elapsed)
	}
	assertProductionPrivateKeyCleared(t, runtime)
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after timeout release = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after releasing fetch")
	}
	if err := runtime.Close(); !errors.Is(err, ErrProductionShutdownTimed) {
		t.Fatalf("repeated timed-out Close = %v", err)
	}
}

type productionStore struct {
	mu            sync.Mutex
	current       signerrevocation.CheckpointLKG
	accepted      signerrevocation.CheckpointLKG
	restoreErr    error
	outageErr     error
	acceptedCount int
	outages       []string
	entered       chan struct{}
	waitForCancel bool
}

func (store *productionStore) RestoreV2(ctx context.Context) (signerrevocation.CheckpointLKG, error) {
	store.mu.Lock()
	entered, waitForCancel := store.entered, store.waitForCancel
	current, err := store.current, store.restoreErr
	store.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if waitForCancel {
		<-ctx.Done()
		return signerrevocation.CheckpointLKG{}, ctx.Err()
	}
	return current, err
}

func (store *productionStore) AcceptV2(context.Context, uuid.UUID, []byte, string, time.Time) (signerrevocation.CheckpointLKG, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.acceptedCount++
	store.current = store.accepted
	return store.accepted, nil
}

func (store *productionStore) RecordCheckpointOutage(_ context.Context, _ uuid.UUID, reason string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.outageErr != nil {
		return store.outageErr
	}
	store.outages = append(store.outages, reason)
	return nil
}

func (store *productionStore) outageCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.outages)
}

func (store *productionStore) outageReasons() []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]string(nil), store.outages...)
}

func (store *productionStore) currentRevision() uint64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.current.Checkpoint.Revision
}

func (store *productionStore) acceptCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.acceptedCount
}

type productionFetcher struct {
	mu            sync.Mutex
	results       []FetchResult
	errors        []error
	calls         int
	entered       chan struct{}
	release       chan struct{}
	waitForCancel bool
}

func (fetcher *productionFetcher) Fetch(ctx context.Context, _ KnownCheckpoint) (FetchResult, error) {
	fetcher.mu.Lock()
	index := fetcher.calls
	fetcher.calls++
	var result FetchResult
	var err error
	if index < len(fetcher.results) {
		result = fetcher.results[index]
	}
	if index < len(fetcher.errors) {
		err = fetcher.errors[index]
	}
	entered, release, waitForCancel := fetcher.entered, fetcher.release, fetcher.waitForCancel
	fetcher.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if waitForCancel {
		<-ctx.Done()
		return FetchResult{}, ctx.Err()
	}
	if release != nil {
		<-release
	}
	if index >= len(fetcher.results) && index >= len(fetcher.errors) {
		<-ctx.Done()
		return FetchResult{}, ctx.Err()
	}
	return result, err
}

func (fetcher *productionFetcher) callCount() int {
	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	return fetcher.calls
}

type productionSnapshotRuntime struct {
	mu           sync.Mutex
	replaced     []uint64
	failRevision uint64
	failErr      error
}

func (runtime *productionSnapshotRuntime) Replace(snapshot signerrevocation.Snapshot) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.replaced = append(runtime.replaced, snapshot.Revision)
	if runtime.failRevision == snapshot.Revision && runtime.failErr != nil {
		err := runtime.failErr
		runtime.failErr = nil
		return err
	}
	return nil
}

func (runtime *productionSnapshotRuntime) revisions() []uint64 {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]uint64(nil), runtime.replaced...)
}

func newTestProductionRuntime(t *testing.T, store Store, fetcher Fetcher, snapshotRuntime Runtime,
	interval time.Duration) *ProductionRuntime {
	t.Helper()
	coordinator, err := NewCoordinator(store, fetcher, snapshotRuntime)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for index := range privateKey {
		privateKey[index] = 0xa5
	}
	return &ProductionRuntime{
		config:      Config{Enabled: true, RefreshInterval: interval, ShutdownTimeout: 250 * time.Millisecond},
		coordinator: coordinator,
		client:      &Client{http: &http.Client{}, privateKey: privateKey},
		runDone:     make(chan struct{}),
	}
}

func productionLKG(revision uint64) signerrevocation.CheckpointLKG {
	digest := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	return signerrevocation.CheckpointLKG{
		Checkpoint: signercheckpoint.Snapshot{Revision: revision, CheckpointSHA256: digest},
		Runtime:    signerrevocation.Snapshot{Revision: revision},
		ETag:       `"` + digest + `"`,
	}
}

func assertProductionPrivateKeyCleared(t *testing.T, runtime *ProductionRuntime) {
	t.Helper()
	for index, value := range runtime.client.privateKey {
		if value != 0 {
			t.Fatalf("private key byte %d was not cleared", index)
		}
	}
}

func waitForProduction(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for production runtime state")
		}
		time.Sleep(time.Millisecond)
	}
}
