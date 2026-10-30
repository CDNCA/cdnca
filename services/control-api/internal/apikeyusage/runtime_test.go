package apikeyusage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

var testNow = time.Date(2026, time.July, 28, 10, 0, 0, 0, time.UTC)

func TestConfigValidation(t *testing.T) {
	runtime, err := newRuntime(newFakeStore(), Config{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("close default runtime: %v", err)
	}
	valid := DefaultConfig()
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"negative queue", func(c *Config) { c.QueueCapacity = -1 }},
		{"queue too large", func(c *Config) { c.QueueCapacity = maxQueueCapacity + 1 }},
		{"negative batch", func(c *Config) { c.BatchSize = -1 }},
		{"batch too large", func(c *Config) { c.BatchSize = maxBatchSize + 1 }},
		{"batch exceeds queue", func(c *Config) { c.BatchSize = c.QueueCapacity + 1 }},
		{"negative flush", func(c *Config) { c.FlushInterval = -time.Second }},
		{"flush too large", func(c *Config) { c.FlushInterval = maxFlushInterval + time.Second }},
		{"negative retry", func(c *Config) { c.RetryInterval = -time.Second }},
		{"retry too large", func(c *Config) { c.RetryInterval = maxRetryInterval + time.Second }},
		{"negative operation", func(c *Config) { c.OperationTimeout = -time.Second }},
		{"operation too large", func(c *Config) { c.OperationTimeout = maxOperationTimeout + time.Second }},
		{"negative shutdown", func(c *Config) { c.ShutdownTimeout = -time.Second }},
		{"shutdown too large", func(c *Config) { c.ShutdownTimeout = maxShutdownTimeout + time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := newRuntime(newFakeStore(), config, func() time.Time { return testNow }); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestRecordRejectsInvalidAndNeverBlocksWhenFull(t *testing.T) {
	store := newFakeStore()
	store.block = make(chan struct{})
	runtime := mustTestRuntime(t, store, Config{
		QueueCapacity: 1, BatchSize: 1, FlushInterval: maxFlushInterval,
		RetryInterval:    time.Millisecond,
		OperationTimeout: time.Second, ShutdownTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	if runtime.TryRecord(uuid.Nil, testNow) || runtime.TryRecord(uuid.New(), time.Time{}) ||
		runtime.TryRecord(uuid.New(), testNow.Add(time.Nanosecond)) {
		t.Fatal("invalid observation was accepted")
	}
	firstID := uuid.New()
	if !runtime.TryRecord(firstID, testNow.In(time.FixedZone("offset", 8*60*60))) {
		t.Fatal("first observation rejected")
	}
	<-store.started
	if !runtime.TryRecord(uuid.New(), testNow) {
		t.Fatal("queue slot was not accepted")
	}
	started := time.Now()
	if runtime.TryRecord(uuid.New(), testNow) {
		t.Fatal("saturated queue accepted an observation")
	}
	if time.Since(started) > 50*time.Millisecond {
		t.Fatal("saturated Record blocked")
	}
	snapshot := runtime.Counters()
	if snapshot.Accepted != 2 || snapshot.Invalid != 3 || snapshot.Dropped != 1 {
		t.Fatalf("counters = %#v", snapshot)
	}
	close(store.block)
	store.mu.Lock()
	store.block = nil
	store.mu.Unlock()
	waitFor(t, time.Second, func() bool { return runtime.Counters().Updated == 2 })
	store.mu.Lock()
	observed := store.calls[0][firstID]
	store.mu.Unlock()
	if observed.Location() != time.UTC || !observed.Equal(testNow) {
		t.Fatalf("stored observation = %v", observed)
	}
}

func TestWorkerCoalescesMaximumAndBoundsBatches(t *testing.T) {
	store := newFakeStore()
	runtime := mustTestRuntime(t, store, Config{
		QueueCapacity: 8, BatchSize: 2, FlushInterval: 5 * time.Millisecond,
		RetryInterval:    time.Millisecond,
		OperationTimeout: time.Second, ShutdownTimeout: time.Second,
	})
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	one, two, three := uuid.New(), uuid.New(), uuid.New()
	for _, observation := range []struct {
		id uuid.UUID
		at time.Time
	}{
		{one, testNow.Add(-time.Minute)}, {one, testNow.Add(-3 * time.Minute)},
		{one, testNow.Add(-30 * time.Second)}, {two, testNow.Add(-time.Minute)},
		{three, testNow.Add(-time.Minute)},
	} {
		if !runtime.TryRecord(observation.id, observation.at) {
			t.Fatal("observation rejected")
		}
	}
	waitFor(t, time.Second, func() bool { return runtime.Counters().Updated == 3 })
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, call := range store.calls {
		if len(call) > 2 {
			t.Fatalf("batch size = %d", len(call))
		}
	}
	found := false
	for _, call := range store.calls {
		if observed, ok := call[one]; ok {
			found = true
			if !observed.Equal(testNow.Add(-30 * time.Second)) {
				t.Fatalf("coalesced maximum = %v", observed)
			}
		}
	}
	if !found {
		t.Fatal("coalesced key missing")
	}
}

func TestFailureRetainsBatchAndRecovers(t *testing.T) {
	store := newFakeStore()
	store.failures = 2
	runtime := mustTestRuntime(t, store, Config{
		QueueCapacity: 2, BatchSize: 1, FlushInterval: time.Millisecond,
		RetryInterval:    time.Millisecond,
		OperationTimeout: time.Second, ShutdownTimeout: time.Second,
	})
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	id := uuid.New()
	if !runtime.TryRecord(id, testNow.Add(-time.Second)) {
		t.Fatal("record rejected")
	}
	waitFor(t, time.Second, func() bool { return runtime.Counters().DBFailures >= 1 })
	if !errors.Is(runtime.Failure(), ErrDatabaseUnavailable) || !errors.Is(runtime.Ready(), ErrDatabaseUnavailable) {
		t.Fatalf("failure=%v ready=%v", runtime.Failure(), runtime.Ready())
	}
	waitFor(t, time.Second, func() bool { return runtime.Counters().Updated == 1 })
	if runtime.Failure() != nil || runtime.Ready() != nil {
		t.Fatalf("recovered failure=%v ready=%v", runtime.Failure(), runtime.Ready())
	}
	snapshot := runtime.Counters()
	if snapshot.Accepted != 1 || snapshot.DBFailures != 2 || snapshot.Batches != 1 || snapshot.Updated != 1 {
		t.Fatalf("counters = %#v", snapshot)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.calls) != 3 || len(store.calls[0]) != 1 || len(store.calls[1]) != 1 || len(store.calls[2]) != 1 {
		t.Fatalf("retry calls = %#v", store.calls)
	}
}

func TestCloseIsIdempotentDrainsAndRejectsNewRecords(t *testing.T) {
	store := newFakeStore()
	runtime := mustTestRuntime(t, store, Config{
		QueueCapacity: 4, BatchSize: 4, FlushInterval: maxFlushInterval,
		RetryInterval:    time.Millisecond,
		OperationTimeout: time.Second, ShutdownTimeout: time.Second,
	})
	for range 3 {
		if !runtime.TryRecord(uuid.New(), testNow.Add(-time.Second)) {
			t.Fatal("record rejected")
		}
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if runtime.TryRecord(uuid.New(), testNow) {
		t.Fatal("closed runtime accepted record")
	}
	if !errors.Is(runtime.Ready(), ErrRuntimeClosed) || runtime.Failure() != nil {
		t.Fatalf("ready=%v failure=%v", runtime.Ready(), runtime.Failure())
	}
	snapshot := runtime.Counters()
	if snapshot.Accepted != 3 || snapshot.Updated != 3 || snapshot.Dropped != 1 {
		t.Fatalf("counters = %#v", snapshot)
	}
}

func TestCloseTimeoutIsStableAndBounded(t *testing.T) {
	store := newFakeStore()
	store.block = make(chan struct{})
	runtime := mustTestRuntime(t, store, Config{
		QueueCapacity: 1, BatchSize: 1, FlushInterval: maxFlushInterval,
		RetryInterval:    time.Millisecond,
		OperationTimeout: time.Second, ShutdownTimeout: 20 * time.Millisecond,
	})
	if !runtime.TryRecord(uuid.New(), testNow) {
		t.Fatal("record rejected")
	}
	<-store.started
	started := time.Now()
	if err := runtime.Close(context.Background()); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("close error = %v", err)
	}
	if time.Since(started) > 200*time.Millisecond {
		t.Fatal("Close exceeded its configured bound")
	}
	close(store.block)
	waitFor(t, time.Second, func() bool { return errors.Is(runtime.Ready(), ErrRuntimeClosed) })
}

func TestPermanentFailureShutdownAndReplacementRuntime(t *testing.T) {
	store := newFakeStore()
	store.alwaysFail = true
	runtime := mustTestRuntime(t, store, Config{
		QueueCapacity: 2, BatchSize: 1, FlushInterval: time.Millisecond,
		RetryInterval: time.Millisecond, OperationTimeout: 5 * time.Millisecond,
		ShutdownTimeout: 20 * time.Millisecond,
	})
	firstID, secondID := uuid.New(), uuid.New()
	if !runtime.TryRecord(firstID, testNow.Add(-2*time.Second)) {
		t.Fatal("initial record rejected")
	}
	waitFor(t, time.Second, func() bool { return runtime.Counters().DBFailures > 0 })
	for _, value := range []observation{
		{keyID: firstID, observedAt: testNow.Add(-time.Second)},
		{keyID: secondID, observedAt: testNow.Add(-time.Second)},
	} {
		if !runtime.TryRecord(value.keyID, value.observedAt) {
			t.Fatal("queued record rejected")
		}
	}
	if err := runtime.Close(context.Background()); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("first close error = %v", err)
	}
	waitFor(t, time.Second, func() bool { return errors.Is(runtime.Ready(), ErrRuntimeClosed) })
	if err := runtime.Close(context.Background()); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("second close error = %v", err)
	}
	if snapshot := runtime.Counters(); snapshot.ShutdownDropped != 2 || snapshot.Accepted != 3 {
		t.Fatalf("permanent failure counters = %#v", snapshot)
	}

	replacement := mustTestRuntime(t, newFakeStore(), Config{
		QueueCapacity: 1, BatchSize: 1, FlushInterval: time.Millisecond,
		RetryInterval: time.Millisecond, OperationTimeout: time.Second,
		ShutdownTimeout: time.Second,
	})
	if !replacement.TryRecord(uuid.New(), testNow.Add(-time.Second)) {
		t.Fatal("replacement runtime rejected record")
	}
	waitFor(t, time.Second, func() bool { return replacement.Counters().Updated == 1 })
	if err := replacement.Close(context.Background()); err != nil {
		t.Fatalf("close replacement runtime: %v", err)
	}
}

func TestCloseWriterBarrierPersistsAllAcceptedUniqueIdentities(t *testing.T) {
	store := newFakeStore()
	runtime := mustTestRuntime(t, store, Config{
		QueueCapacity: 64, BatchSize: 64, FlushInterval: maxFlushInterval,
		RetryInterval: time.Millisecond, OperationTimeout: time.Second,
		ShutdownTimeout: time.Second,
	})

	accepted := make(map[uuid.UUID]time.Time)
	acceptedCalls := 0
	recordAccepted := func(value observation) bool {
		if !runtime.TryRecord(value.keyID, value.observedAt) {
			return false
		}
		acceptedCalls++
		if previous, exists := accepted[value.keyID]; !exists || value.observedAt.After(previous) {
			accepted[value.keyID] = value.observedAt
		}
		return true
	}

	one, two, three := uuid.New(), uuid.New(), uuid.New()
	baseline := []observation{
		{keyID: one, observedAt: testNow.Add(-3 * time.Minute)},
		{keyID: two, observedAt: testNow.Add(-2 * time.Minute)},
		{keyID: one, observedAt: testNow.Add(-time.Minute)},
		{keyID: three, observedAt: testNow.Add(-time.Minute)},
	}
	for _, value := range baseline {
		if !recordAccepted(value) {
			t.Fatal("record rejected before Close")
		}
	}

	inFlight := []observation{
		{keyID: uuid.New(), observedAt: testNow.Add(-4 * time.Second)},
		{keyID: one, observedAt: testNow.Add(-30 * time.Second)},
		{keyID: uuid.New(), observedAt: testNow.Add(-2 * time.Second)},
	}
	// Fix the interleaving after TryRecord's second state check but before enqueue.
	for range inFlight {
		if runtime.state.Load() != stateRunning {
			t.Fatal("runtime closed before writer acquired its lease")
		}
		runtime.writers.Add(1)
		if runtime.state.Load() != stateRunning {
			t.Fatal("writer did not pass the second state check")
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- runtime.Close(context.Background()) }()
	waitFor(t, time.Second, func() bool { return runtime.state.Load() == stateClosing })
	for _, value := range inFlight {
		runtime.events <- value
		runtime.counts.accepted.Add(1)
		acceptedCalls++
		if previous, exists := accepted[value.keyID]; !exists || value.observedAt.After(previous) {
			accepted[value.keyID] = value.observedAt
		}
		runtime.finishRecord()
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	written := make(map[uuid.UUID]time.Time)
	store.mu.Lock()
	for _, call := range store.calls {
		for keyID, observedAt := range call {
			if previous, exists := written[keyID]; !exists || observedAt.After(previous) {
				written[keyID] = observedAt
			}
		}
	}
	store.mu.Unlock()
	if len(written) != len(accepted) {
		t.Fatalf("persisted identity count = %d, want %d", len(written), len(accepted))
	}
	for keyID, observedAt := range accepted {
		if !written[keyID].Equal(observedAt) {
			t.Fatalf("persisted observation for %s = %v, want %v", keyID, written[keyID], observedAt)
		}
	}
	if snapshot := runtime.Counters(); snapshot.Accepted != uint64(acceptedCalls) || snapshot.Updated != uint64(len(accepted)) || snapshot.ShutdownDropped != 0 {
		t.Fatalf("close counters = %#v", snapshot)
	}
}

func TestCloseBoundIncludesInFlightRecorder(t *testing.T) {
	runtime := mustTestRuntime(t, newFakeStore(), Config{
		QueueCapacity: 1, BatchSize: 1, FlushInterval: maxFlushInterval,
		RetryInterval:    time.Millisecond,
		OperationTimeout: time.Second, ShutdownTimeout: 20 * time.Millisecond,
	})
	runtime.writers.Add(1)
	started := time.Now()
	if err := runtime.Close(context.Background()); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("close error = %v", err)
	}
	if time.Since(started) > 200*time.Millisecond {
		t.Fatal("Close blocked outside its configured bound")
	}
	runtime.finishRecord()
	waitFor(t, time.Second, func() bool { return errors.Is(runtime.Ready(), ErrRuntimeClosed) })
}

func TestTryRecordCloseRace(t *testing.T) {
	for range 20 {
		runtime := mustTestRuntime(t, newFakeStore(), Config{
			QueueCapacity: 32, BatchSize: 16, FlushInterval: time.Millisecond,
			RetryInterval:    time.Millisecond,
			OperationTimeout: time.Second, ShutdownTimeout: time.Second,
		})
		var group sync.WaitGroup
		for range 16 {
			group.Add(1)
			go func() {
				defer group.Done()
				for runtime.TryRecord(uuid.New(), testNow) {
				}
			}()
		}
		if err := runtime.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		group.Wait()
		if !errors.Is(runtime.Ready(), ErrRuntimeClosed) {
			t.Fatalf("ready = %v", runtime.Ready())
		}
	}
}

func mustTestRuntime(t *testing.T, store usageStore, config Config) *Runtime {
	t.Helper()
	runtime, err := newRuntime(store, config, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

type fakeStore struct {
	mu         sync.Mutex
	calls      []map[uuid.UUID]time.Time
	failures   int
	alwaysFail bool
	started    chan struct{}
	block      chan struct{}
}

func newFakeStore() *fakeStore { return &fakeStore{started: make(chan struct{}, 32)} }

func (s *fakeStore) update(_ context.Context, observations map[uuid.UUID]time.Time) (int, int, error) {
	copyOfBatch := make(map[uuid.UUID]time.Time, len(observations))
	for id, observedAt := range observations {
		copyOfBatch[id] = observedAt
	}
	s.mu.Lock()
	s.calls = append(s.calls, copyOfBatch)
	fail := s.alwaysFail || s.failures > 0
	if fail {
		s.failures--
	}
	block := s.block
	s.mu.Unlock()
	s.started <- struct{}{}
	if block != nil {
		<-block
	}
	if fail {
		return 0, 0, errors.New("sensitive database failure")
	}
	return len(observations), 0, nil
}
