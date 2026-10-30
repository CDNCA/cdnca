package apikeyusage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxQueueCapacity    = 65_536
	maxBatchSize        = 1_000
	maxFlushInterval    = 5 * time.Minute
	maxRetryInterval    = time.Minute
	maxOperationTimeout = 30 * time.Second
	maxShutdownTimeout  = 5 * time.Minute
	mergeWindow         = 5 * time.Minute
)

var (
	ErrInvalidConfig       = errors.New("invalid API key usage runtime configuration")
	ErrDatabaseUnavailable = errors.New("API key usage database unavailable")
	ErrRuntimeClosed       = errors.New("API key usage runtime closed")
	ErrShutdownTimeout     = errors.New("API key usage runtime shutdown timeout")
)

type Config struct {
	QueueCapacity    int
	BatchSize        int
	FlushInterval    time.Duration
	RetryInterval    time.Duration
	OperationTimeout time.Duration
	ShutdownTimeout  time.Duration
}

func DefaultConfig() Config {
	return Config{
		QueueCapacity:    1_024,
		BatchSize:        100,
		FlushInterval:    time.Second,
		RetryInterval:    time.Second,
		OperationTimeout: 2 * time.Second,
		ShutdownTimeout:  10 * time.Second,
	}
}

type Snapshot struct {
	Accepted        uint64
	Dropped         uint64
	ShutdownDropped uint64
	Invalid         uint64
	DBFailures      uint64
	Batches         uint64
	Updated         uint64
	Filtered        uint64
}

type usageStore interface {
	update(context.Context, map[uuid.UUID]time.Time) (updated int, filtered int, err error)
}

type observation struct {
	keyID      uuid.UUID
	observedAt time.Time
}

type counters struct {
	accepted        atomic.Uint64
	dropped         atomic.Uint64
	shutdownDropped atomic.Uint64
	invalid         atomic.Uint64
	dbFailures      atomic.Uint64
	batches         atomic.Uint64
	updated         atomic.Uint64
	filtered        atomic.Uint64
}

type Runtime struct {
	store  usageStore
	config Config
	now    func() time.Time

	state      atomic.Uint32
	writers    atomic.Int64
	writerDone chan struct{}
	events     chan observation
	stop       chan struct{}
	done       chan struct{}

	failing  atomic.Bool
	counts   counters
	closeMu  sync.RWMutex
	closeErr error
}

const (
	stateRunning uint32 = iota + 1
	stateClosing
	stateClosed
)

func NewRuntime(pool *pgxpool.Pool, config Config) (*Runtime, error) {
	if pool == nil {
		return nil, invalidConfig("database pool is required")
	}
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return newRuntimeWithConfig(newPostgresStore(pool, normalized.OperationTimeout), normalized, time.Now), nil
}

func newRuntime(store usageStore, config Config, now func() time.Time) (*Runtime, error) {
	if store == nil {
		return nil, invalidConfig("usage store is required")
	}
	if now == nil {
		return nil, invalidConfig("clock is required")
	}
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return newRuntimeWithConfig(store, normalized, now), nil
}

func newRuntimeWithConfig(store usageStore, config Config, now func() time.Time) *Runtime {
	runtime := &Runtime{
		store: store, config: config, now: now,
		writerDone: make(chan struct{}, 1), events: make(chan observation, config.QueueCapacity),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	runtime.state.Store(stateRunning)
	go runtime.run()
	return runtime
}

func (r *Runtime) TryRecord(keyID uuid.UUID, observedAt time.Time) bool {
	if keyID == uuid.Nil || observedAt.IsZero() || observedAt.After(r.now()) {
		r.counts.invalid.Add(1)
		return false
	}
	value := observation{keyID: keyID, observedAt: observedAt.UTC()}
	if r.state.Load() != stateRunning {
		r.counts.dropped.Add(1)
		return false
	}
	r.writers.Add(1)
	defer r.finishRecord()
	if r.state.Load() != stateRunning {
		r.counts.dropped.Add(1)
		return false
	}
	select {
	case r.events <- value:
		r.counts.accepted.Add(1)
		return true
	default:
		r.counts.dropped.Add(1)
		return false
	}
}

func (r *Runtime) Ready() error {
	if r.state.Load() != stateRunning {
		return ErrRuntimeClosed
	}
	return r.Failure()
}

func (r *Runtime) Failure() error {
	if r.failing.Load() {
		return ErrDatabaseUnavailable
	}
	return nil
}

func (r *Runtime) Counters() Snapshot {
	return Snapshot{
		Accepted: r.counts.accepted.Load(), Dropped: r.counts.dropped.Load(),
		ShutdownDropped: r.counts.shutdownDropped.Load(), Invalid: r.counts.invalid.Load(),
		DBFailures: r.counts.dbFailures.Load(), Batches: r.counts.batches.Load(),
		Updated: r.counts.updated.Load(), Filtered: r.counts.filtered.Load(),
	}
}

func (r *Runtime) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if r.state.CompareAndSwap(stateRunning, stateClosing) {
		go r.stopAfterWriters()
	}

	timer := time.NewTimer(r.config.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-r.done:
		r.closeMu.RLock()
		err := r.closeErr
		r.closeMu.RUnlock()
		return err
	case <-ctx.Done():
		return ErrShutdownTimeout
	case <-timer.C:
		return ErrShutdownTimeout
	}
}

func (r *Runtime) finishRecord() {
	if r.writers.Add(-1) == 0 && r.state.Load() != stateRunning {
		select {
		case r.writerDone <- struct{}{}:
		default:
		}
	}
}

func (r *Runtime) stopAfterWriters() {
	if r.writers.Load() != 0 {
		<-r.writerDone
	}
	close(r.stop)
}

func (r *Runtime) run() {
	defer func() {
		r.state.Store(stateClosed)
		close(r.done)
	}()
	ticker := time.NewTicker(r.config.FlushInterval)
	defer ticker.Stop()
	pending := make(map[uuid.UUID]time.Time, r.config.BatchSize)
	failed := false
	var retry <-chan time.Time

	for {
		if failed {
			select {
			case <-retry:
				failed = !r.flush(context.Background(), pending)
				if failed {
					retry = time.After(r.config.RetryInterval)
				}
			case <-r.stop:
				r.finish(pending)
				return
			}
			continue
		}

		select {
		case value := <-r.events:
			addObservation(pending, value)
			if len(pending) >= r.config.BatchSize {
				failed = !r.flush(context.Background(), pending)
				if failed {
					retry = time.After(r.config.RetryInterval)
				}
			}
		case <-ticker.C:
			if len(pending) > 0 {
				failed = !r.flush(context.Background(), pending)
				if failed {
					retry = time.After(r.config.RetryInterval)
				}
			}
		case <-r.stop:
			r.finish(pending)
			return
		}
	}
}

func (r *Runtime) finish(pending map[uuid.UUID]time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.ShutdownTimeout)
	defer cancel()
	for {
		for len(pending) < r.config.BatchSize {
			select {
			case value := <-r.events:
				addObservation(pending, value)
			default:
				goto drained
			}
		}
	drained:
		if len(pending) > 0 {
			if !r.flush(ctx, pending) {
				select {
				case <-ctx.Done():
					r.counts.shutdownDropped.Add(uint64(r.discardPending(pending)))
					r.setCloseError(ErrShutdownTimeout)
					return
				case <-time.After(r.config.RetryInterval):
					continue
				}
			}
		}
		if len(r.events) == 0 {
			return
		}
	}
}

func (r *Runtime) discardPending(pending map[uuid.UUID]time.Time) int {
	lost := make(map[uuid.UUID]struct{}, len(pending)+len(r.events))
	for keyID := range pending {
		lost[keyID] = struct{}{}
	}
	clear(pending)
	for {
		select {
		case value := <-r.events:
			lost[value.keyID] = struct{}{}
		default:
			return len(lost)
		}
	}
}

func (r *Runtime) flush(parent context.Context, pending map[uuid.UUID]time.Time) bool {
	if len(pending) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(parent, r.config.OperationTimeout)
	defer cancel()
	updated, filtered, err := r.store.update(ctx, pending)
	if err != nil {
		r.counts.dbFailures.Add(1)
		r.failing.Store(true)
		return false
	}
	r.counts.batches.Add(1)
	r.counts.updated.Add(uint64(updated))
	r.counts.filtered.Add(uint64(filtered))
	r.failing.Store(false)
	clear(pending)
	return true
}

func (r *Runtime) setCloseError(err error) {
	r.closeMu.Lock()
	r.closeErr = err
	r.closeMu.Unlock()
}

func addObservation(pending map[uuid.UUID]time.Time, value observation) {
	if previous, exists := pending[value.keyID]; !exists || value.observedAt.After(previous) {
		pending[value.keyID] = value.observedAt
	}
}

func normalizeConfig(config Config) (Config, error) {
	defaults := DefaultConfig()
	if config.QueueCapacity == 0 {
		config.QueueCapacity = defaults.QueueCapacity
	}
	if config.BatchSize == 0 {
		config.BatchSize = defaults.BatchSize
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = defaults.FlushInterval
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = defaults.RetryInterval
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = defaults.OperationTimeout
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = defaults.ShutdownTimeout
	}
	if config.QueueCapacity < 1 || config.QueueCapacity > maxQueueCapacity {
		return Config{}, invalidConfig("queue capacity must be between 1 and 65536")
	}
	if config.BatchSize < 1 || config.BatchSize > maxBatchSize || config.BatchSize > config.QueueCapacity {
		return Config{}, invalidConfig("batch size must be positive, bounded, and not exceed queue capacity")
	}
	if config.FlushInterval < time.Millisecond || config.FlushInterval > maxFlushInterval {
		return Config{}, invalidConfig("flush interval must be between 1 millisecond and 5 minutes")
	}
	if config.RetryInterval < time.Millisecond || config.RetryInterval > maxRetryInterval {
		return Config{}, invalidConfig("retry interval must be between 1 millisecond and 1 minute")
	}
	if config.OperationTimeout < time.Millisecond || config.OperationTimeout > maxOperationTimeout {
		return Config{}, invalidConfig("operation timeout must be between 1 millisecond and 30 seconds")
	}
	if config.ShutdownTimeout < time.Millisecond || config.ShutdownTimeout > maxShutdownTimeout {
		return Config{}, invalidConfig("shutdown timeout must be between 1 millisecond and 5 minutes")
	}
	return config, nil
}

func invalidConfig(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, detail)
}
